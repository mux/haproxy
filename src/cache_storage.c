/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The HTTP cache storage engine: a log-structured segment store, loosely based
 * on Segcache (NSDI '21) and, more precisely, on its maintained Rust
 * implementation (the cache-rs crate), whose readers are fully lock-free. The
 * basic structure is theirs; we diverge wherever the HTTP use case differs
 * from the small-object key-value cache they target. The design and the
 * reasoning behind each choice are documented in
 * doc/design-thoughts/cache-storage-design.md, which is authoritative; this
 * comment is only a map of the main departures:
 *
 * - An entry larger than one segment is not declined but stored as a chain of
 *   segments private to that single entry ("jumbo" entry). Both Segcache
 *   implementations simply refuse to cache an over-sized object, which is not
 *   acceptable for HTTP, where object sizes vary enormously.
 * - Entries cannot be copied in with a single memcpy(): they are streamed in
 *   as they arrive from the origin server, and streamed back out to what may
 *   be a slow client, so a segment can stay pinned for seconds. Nothing here
 *   may busy-loop or wait on such a pin, so the reclaim and store paths fail
 *   and retry later instead.
 * - Merge-based eviction falls back to evicting whole segments when no
 *   sequence of segments can be merged or no destination is available. While
 *   another merge is producing space, the reservation is declined instead.
 * - The paper does not concern itself with adversarial traffic, but we do:
 *   the hash is seeded, so an attacker cannot predict placement in the
 *   hashtable, nor forge a key colliding with a victim's.
 * - The TTL bucket lock is coarser than the Rust version's: it also covers
 *   byte reservation, which they make lock-free.
 */

#include <sys/mman.h>
#include <sys/types.h>

#include <haproxy/atomic.h>
#include <haproxy/bug.h>
#include <haproxy/cache_storage.h>
#include <haproxy/clock.h>
#include <haproxy/time.h>
#include <haproxy/tools.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* We define convenience wrappers for sequentially consistent loads/stores. The
 * atomic.h header only provides macros for acquire loads and release stores,
 * plus underscore-prefixed relaxed variants of both.
 */
#define HA_ATOMIC_LOAD_SEQ_CST(ptr)       __atomic_load_n(ptr, __ATOMIC_SEQ_CST)
#define HA_ATOMIC_STORE_SEQ_CST(ptr, val) __atomic_store_n(ptr, val, __ATOMIC_SEQ_CST)

/* Definitions related to the array of TTL buckets. Note that the way this works
 * means that out of the 1024 buckets, a few are wasted between the different
 * groups. This is neither a correctness nor a resolution issue.
 */
#define CACHE_TTL_GROUP_BITS    8
#define CACHE_TTL_FACTOR_BITS   4
#define CACHE_TTL_GROUPS        4
#define CACHE_TTL_N_BUCKETS     (CACHE_TTL_GROUPS << CACHE_TTL_GROUP_BITS)

BUG_ON_STATIC(CACHE_TTL_N_BUCKETS != 1024);
/* CACHE_TTL_MAX is public API (cache_storage.h); make sure it still matches
 * the bucket geometry in case either side is changed.
 */
BUG_ON_STATIC(CACHE_TTL_MAX !=
	(1 << (CACHE_TTL_GROUP_BITS + CACHE_TTL_FACTOR_BITS * (CACHE_TTL_GROUPS - 1))));

/* Mean size of a stored entry (record header + HTTP headers + body), used
 * to size the hash index. The index provisions four slots per expected
 * object (see cache_index_init()), so store failures stay negligible until
 * the actual mean falls below about a third of this value. The default sits
 * at the small end of real-world means (~35 KB measured: a ~2.6 MB median
 * page over ~71 requests, HTTP Archive 2024) so that even small-object
 * workloads fit without tuning; the index then costs about 1% of the cache
 * size.
 *
 * Can be overridden in cache_config.
 */
#define CACHE_IDX_MEAN_SIZE     (4 * 1024)

/* Maximum number of times seg_read_pin() re-validates after losing a race
 * with a rewrite of its slot. Each retry requires a store or delete of the
 * same key to have rewritten the slot within the few nanoseconds between
 * the slot read and its post-pin re-read, so only a sustained storm of
 * same-key rewrites can exhaust the cap; this should never happen in
 * practice (exhaustions are counted in the read_pin_fails statistic), and the
 * resulting miss is harmless since the entry is being replaced anyway.
 */
#define CACHE_READ_PIN_TRIES    3

/* Auto segment sizing (cfg.seg_size == 0): the largest power of two yielding at
 * least CACHE_SEG_AUTO_TARGET segments, capped at CACHE_SEG_AUTO_MAX and at
 * cfg.seg_max_entries mean-sized objects. The latter limits the records walked
 * per reclaimed segment, but is an estimate, not a record count.
 * Smaller segments waste less in per-TTL-class open segments (~seg/2 each) and
 * evict at finer grain; larger segments shorten the chains of oversized entries
 * and amortize reclaim better. At the measured ~35 KB mean web response, a 2 MB
 * segment already holds ~60 entries, so growing past that buys little while
 * coarsening eviction. The hard ceiling is nevertheless the largest segment the
 * slot layout can address, so an operator asking for it with a large
 * segment-max-entries gets it.
 *
 * A segment must also hold several mean objects, or most entries span segments
 * and a small cache degrades sharply (measured: segments under ~4x the mean
 * cost half the hit ratio; ~14x and above is flat). So the segment size is
 * floored at CACHE_SEG_AUTO_MIN_OBJS mean objects, while always keeping at
 * least CACHE_SEG_AUTO_MIN_SEGS segments as eviction and expiry units. The
 * floor only engages when the cache holds fewer than TARGET * MIN_OBJS mean
 * objects. The 4096-byte minimum and representable segment count take
 * precedence over the expected-entry ceiling.
 */
#define CACHE_SEG_AUTO_MAX      CACHE_SEG_MAX_SIZE
#define CACHE_SEG_AUTO_TARGET   2048
#define CACHE_SEG_AUTO_MIN_OBJS CACHE_SEG_MIN_ENTRIES
#define CACHE_SEG_AUTO_MIN_SEGS 16

/* Number of slots in a hash bucket */
#define CACHE_BUCKET_N_SLOT     8

/* Offsets are encoded in units of 8 bytes */
#define CACHE_OFF_SHIFT         3
#define CACHE_OFF_ALIGN         (1ULL << CACHE_OFF_SHIFT)
/* Round a length up to a whole number of offset-encoding units. */
#define CACHE_OFF_ALIGN_UP(len) (((len) + CACHE_OFF_ALIGN - 1) & ~(CACHE_OFF_ALIGN - 1))

/* Masks/shifts for the 64-bit slot value */
#define CACHE_SLOT_OFF_BITS     20
#define CACHE_SLOT_SEG_BITS     24
#define CACHE_SLOT_FREQ_BITS    7
#define CACHE_SLOT_TAG_BITS     12

#define CACHE_SLOT_OFF_SHIFT    0
#define CACHE_SLOT_SEG_SHIFT    (CACHE_SLOT_OFF_SHIFT  + CACHE_SLOT_OFF_BITS)
#define CACHE_SLOT_FREQ_SHIFT   (CACHE_SLOT_SEG_SHIFT  + CACHE_SLOT_SEG_BITS)
#define CACHE_SLOT_TAG_SHIFT    (64 - CACHE_SLOT_TAG_BITS)

#define CACHE_SLOT_OFF_MASK     (((1ULL << CACHE_SLOT_OFF_BITS)  - 1) << CACHE_SLOT_OFF_SHIFT)
#define CACHE_SLOT_SEG_MASK     (((1ULL << CACHE_SLOT_SEG_BITS)  - 1) << CACHE_SLOT_SEG_SHIFT)
#define CACHE_SLOT_FREQ_MASK    (((1ULL << CACHE_SLOT_FREQ_BITS) - 1) << CACHE_SLOT_FREQ_SHIFT)
#define CACHE_SLOT_TAG_MASK     (((1ULL << CACHE_SLOT_TAG_BITS)  - 1) << CACHE_SLOT_TAG_SHIFT)

/* The counter saturates at the field's maximum. The pending bit marks an
 * entry still being written: only its writer may change or clear such a slot,
 * and every other index user skips it.
 */
#define CACHE_SLOT_FREQ_MAX     ((1U << CACHE_SLOT_FREQ_BITS) - 1)
#define CACHE_SLOT_PENDING      (1ULL << (CACHE_SLOT_FREQ_SHIFT + CACHE_SLOT_FREQ_BITS))

BUG_ON_STATIC(CACHE_SLOT_FREQ_SHIFT + CACHE_SLOT_FREQ_BITS + 1 != CACHE_SLOT_TAG_SHIFT);

/* A used slot must never encode as all zeroes, the empty value, although its
 * tag, segment and counter may each be 0. So the offset field is one-based: it
 * holds the record's offset in CACHE_OFF_ALIGN units plus one, and is never 0
 * in a used slot. This costs no range. A record header must fit in the segment
 * where its record starts, so no record starts in a segment's last unit, and
 * the largest real start still fits the field once counted from one.
 */
#define CACHE_SLOT_OFF(slot)    \
	(((((slot) & CACHE_SLOT_OFF_MASK) >> CACHE_SLOT_OFF_SHIFT) - 1) << CACHE_OFF_SHIFT)
#define CACHE_SLOT_SEG(slot)    \
	((((slot) & CACHE_SLOT_SEG_MASK)  >> CACHE_SLOT_SEG_SHIFT))
#define CACHE_SLOT_FREQ(slot)   \
	((((slot) & CACHE_SLOT_FREQ_MASK) >> CACHE_SLOT_FREQ_SHIFT))
#define CACHE_SLOT_TAG(slot)    \
	((((slot) & CACHE_SLOT_TAG_MASK)  >> CACHE_SLOT_TAG_SHIFT))

/* Creation macro. The frequency counter counts hits, so a fresh slot
 * carries 0.
 */
#define CACHE_SLOT_MAKE(tag, seg, off, freq)                                    \
	(((uint64_t)(tag)                           << CACHE_SLOT_TAG_SHIFT)  | \
	( (uint64_t)(freq)                          << CACHE_SLOT_FREQ_SHIFT) | \
	( (uint64_t)(seg)                           << CACHE_SLOT_SEG_SHIFT)  | \
	((((uint64_t)(off) >> CACHE_OFF_SHIFT) + 1) << CACHE_SLOT_OFF_SHIFT))

/* CACHE_MAX_TOTAL_SIZE is public API (cache_storage.h); it must stay equal to
 * what a slot's location can address: 2^(SEG_BITS + OFF_BITS) offset units of
 * CACHE_OFF_ALIGN bytes.
 */
BUG_ON_STATIC(CACHE_MAX_TOTAL_SIZE !=
	(1ULL << (CACHE_SLOT_SEG_BITS + CACHE_SLOT_OFF_BITS + CACHE_OFF_SHIFT)));

/* CACHE_SEG_MAX_SIZE is public API (cache_storage.h); it must stay equal to
 * what a slot's offset field can address: 2^OFF_BITS offset units of
 * CACHE_OFF_ALIGN bytes.
 */
BUG_ON_STATIC(CACHE_SEG_MAX_SIZE !=
	(1ULL << (CACHE_SLOT_OFF_BITS + CACHE_OFF_SHIFT)));

#define CACHE_MAX_N_SEGS        (1ULL << CACHE_SLOT_SEG_BITS)

/* The tag is the top CACHE_SLOT_TAG_BITS bits of the hash, cached in the hash
 * table slot itself. On lookup we compare it first and only confirm against the
 * full 128-bit hash when it matches. This avoids pinning the segment and
 * reading the record's (separate, usually cold) cacheline in the arena for
 * every candidate.
 */
#define CACHE_HASH_TAG(hash)    ((hash).high64 >> (64 - CACHE_SLOT_TAG_BITS))

/* Pointer to the beginning of the data in a record */
#define CACHE_REC_DATA(rec)     ((char *)(rec) + sizeof(struct cache_record))
/* Data capacity of a record */
#define CACHE_REC_CAPACITY(rec) ((rec)->rec_len - sizeof(struct cache_record))

/* Arena offset given a segment ID and an offset */
#define CACHE_ARENA_OFF(c, seg_id, off) ((size_t)(seg_id) * (c)->cfg.seg_size + (off))
/* Cache record the handle references */
#define CACHE_HANDLE_REC(c, h)  ((struct cache_record *)((char *)((c)->arena) + \
                                 CACHE_ARENA_OFF(c, (h)->seg_id, (h)->seg_off)))

#define CACHE_RHANDLE_NULL      ((struct cache_rhandle){ .seg_id = CACHE_SEG_NONE })
#define CACHE_WHANDLE_NULL      ((struct cache_whandle){ .seg_id = CACHE_SEG_NONE })

#define BUG_ON_BAD_HANDLE(cache, h)    BUG_ON((h)->seg_id >= (cache)->n_segs ||        \
                                              (h)->seg_off >= (cache)->cfg.seg_size || \
                                              (h)->seg_off & (CACHE_OFF_ALIGN - 1))

/* Segment states */
#define SEG_S_FREE              (1 << 0)
#define SEG_S_LIVE              (1 << 1)
#define SEG_S_DRAINING          (1 << 2)
#define SEG_S_CONDEMNED         (1 << 3)

/* The segment state is packed with a generation in a single atomic word:
 * bits 7..0 hold the SEG_S_* state, bits 31..8 a generation bumped each
 * time the segment is reinitialized for reuse. The CONDEMNED -> FREE
 * handoff CAS carries the word it observed, so a thread that stalled
 * across a full free/reuse/re-condemn cycle of the segment fails its CAS
 * instead of freeing the segment under the new generation's readers. The
 * generation wraps at 2^24: being fooled would take a stall spanning an
 * exact multiple of 2^24 reuses of the same segment.
 */
#define SEG_STATE(w)            ((uint8_t)((w) & 0xFF))
#define SEG_STATE_GEN(w)        ((w) >> 8)
#define SEG_STATE_MAKE(gen, st) (((gen) << 8) | (st))

/* Segment flags */
#define SEG_F_PRIVATE           (1 << 0)
#define SEG_F_NO_LEN            (1 << 1)

/* Segment descriptors, chained in TTL buckets or in the free pool. */
struct seg {
	uint32_t write_off;      /* Current write offset */
	uint32_t n_chain;        /* Chain length, recorded in the head segment */
	uint32_t live_bytes;     /* Indexed bytes (shared segments only) */
	uint32_t n_live;         /* Indexed entries (shared segments only) */
	uint32_t create_ts;      /* Creation timestamp */
	uint16_t ttl_bucket;     /* TTL bucket index */
	uint32_t r_refcount;     /* Read refcounts */
	uint32_t w_refcount;     /* Write refcounts */
	seg_id_t next_seg_id;    /* Linkage for next entry in seg_list */
	seg_id_t prev_seg_id;    /* Linkage for previous entry in seg_list */
	seg_id_t next_chain_id;  /* Jumbo entries & free-list linkage */
	uint32_t state_gen;      /* SEG_S_* state + generation */
	uint8_t flags;           /* SEG_F_* */
	uint8_t merge_claimed;   /* Protected by the owning TTL bucket's lock */
};

/* A list of segments. The owning TTL bucket's lock protects its counters. */
struct seg_list {
	seg_id_t first_seg_id;
	seg_id_t last_seg_id;
	uint32_t n_segs;         /* Segments held, every one of a chain counted */
	uint32_t rate_ts;        /* Second that rate_acc counts */
	uint32_t rate_acc;       /* Segments appended during rate_ts */
	double rate;             /* Segments appended per second, averaged */
	double rate_period;      /* Seconds that rate is averaged over */
};

struct ttl_bucket {
	struct seg_list segs;
	struct seg_list prv_segs;
	uint32_t ttl_approx;
	seg_id_t merge_next;     /* Where the next merge resumes, or CACHE_SEG_NONE */
	uint32_t merge_next_gen; /* Generation of merge_next when it was set */
	seg_id_t prv_next;       /* Where the next private eviction resumes, or CACHE_SEG_NONE */
	uint32_t prv_next_gen;   /* Generation of prv_next when it was set */
	__decl_thread(HA_SPINLOCK_T lock);
	unsigned int merges_inflight; /* Zero or one owner, under the TTL lock */
};

struct ht_bucket {
	uint64_t slot[CACHE_BUCKET_N_SLOT];
} ALIGNED(64);

BUG_ON_STATIC(sizeof(struct ht_bucket) != 64);

/* Reclaim budget of one reservation or growth step, in records: those walked
 * by expiration, eviction and merging, plus what scanning the TTL buckets
 * costs. Reclaim works in units that are never interrupted: expiring or
 * evicting a segment, or a whole merge. The first unit always starts, so that
 * every reservation can make progress; later ones start only while the budget
 * lasts.
 */
#define CACHE_RECLAIM_BUDGET      1024
/* A scan of the TTL buckets costs CACHE_SCAN_COST records for reading every
 * bucket head, plus one per CACHE_SCAN_LOCKED_PER_REC buckets it locks and
 * searches. Measured on x86, where unindexing costs 40 to 200 ns per record.
 */
#define CACHE_SCAN_COST           16
#define CACHE_SCAN_LOCKED_PER_REC 4

enum cache_reclaim_status {
	CACHE_RECLAIM_PROGRESS,
	CACHE_RECLAIM_RETRY,
	CACHE_RECLAIM_MERGING,
	CACHE_RECLAIM_GIVEUP
};

/* Outcome of reclaiming one segment. Only SEG_RECLAIM_FREED means the segment
 * reached the free-list; CONDEMNED means it was removed from the index and its
 * TTL chain but the free-list push is deferred to its last reader.
 */
enum seg_reclaim_status {
	SEG_RECLAIM_FREED,
	SEG_RECLAIM_CONDEMNED,
	SEG_RECLAIM_BLOCKED
};

struct cache_record {
	XXH128_hash_t hash;
	uint32_t expire;      /* Absolute expiry; wall-clock seconds */
	size_t rec_len;       /* Exact record size; the arena footprint is
	                       * CACHE_OFF_ALIGN_UP(rec_len) */
};

/* The one-based slot offset relies on no record starting in a segment's last
 * offset unit, which holds as long as a record header fills a whole unit.
 */
BUG_ON_STATIC(sizeof(struct cache_record) < CACHE_OFF_ALIGN);

struct cache {
	uint32_t flags;                 /* CACHE_F_* flags */
	struct cache_config cfg;        /* Configuration tunables */
	uint64_t seed;                  /* Seeds the hashing of the keys */

	/* Hash table index for reads */
	struct {
		struct ht_bucket *buckets;
		uint32_t n_buckets;
	} index;

	uint32_t n_segs;                /* Number of segments */
	uint8_t *arena;                 /* Storage buffer */
	size_t arena_len;               /* And its size */

	struct seg *segments;           /* Segment descriptor table */
	struct ttl_bucket *ttl_buckets; /* TTL buckets for writes */
	unsigned long ttl_used[CACHE_TTL_N_BUCKETS / LONGBITS]; /* TTL buckets holding segments */
	__decl_thread(HA_SPINLOCK_T pool_lock); /* Lock for the pool of free segments */
	seg_id_t free_seg_id;           /* Free-list of segments */
	unsigned int n_free;            /* Number of free segments in the pool */
	uint64_t merge_empty;           /* Merges that retained nothing */
	uint64_t merge_success;         /* Merges that retained something */
	unsigned int merges_inflight;   /* Merges holding a destination segment */
	unsigned int segs_condemned;    /* Segment/chain heads waiting on readers */

	struct cache_stats stats;       /* Activity counters */
};

/* Next power of 2 */
static uint32_t pow2_up(uint32_t x)
{
	return x <= 1 ? 1 : 1U << (32 - __builtin_clz(x - 1));
}

/* Previous power of 2 */
static uint32_t pow2_down(uint32_t x)
{
	return x <= 1 ? 1 : 1U << (31 - __builtin_clz(x));
}

/* Number of segments <len> bytes span. */
static inline unsigned int cache_seg_count(const struct cache *cache, size_t len)
{
	return len / cache->cfg.seg_size + !!(len % cache->cfg.seg_size);
}

/* Pick an automatic segment size, before rounding the arena down to whole
 * segments. <max_entries> is nonzero and at least CACHE_SEG_MIN_ENTRIES.
 */
static uint32_t cache_auto_segment_size(size_t total_size, size_t mean_obj_size,
                                      uint32_t max_entries)
{
	uint64_t sz = total_size / CACHE_SEG_AUTO_TARGET;
	uint64_t cap = total_size / CACHE_SEG_AUTO_MIN_SEGS;
	/* A larger mean already hits the byte ceiling. Clamping it here also
	 * keeps both products representable, including for a UINT32_MAX cap.
	 */
	uint64_t mean = MIN(mean_obj_size, (size_t)CACHE_SEG_AUTO_MAX);

	if (sz < mean * CACHE_SEG_AUTO_MIN_OBJS)
		sz = mean * CACHE_SEG_AUTO_MIN_OBJS;
	if (sz > mean * max_entries)
		sz = mean * max_entries;
	if (sz > cap)
		sz = cap;
	if (sz > CACHE_SEG_AUTO_MAX)
		sz = CACHE_SEG_AUTO_MAX;
	if (sz < 4096)
		sz = 4096;
	sz = pow2_down(sz);

	/* Do not make a previously representable arena fail solely because the
	 * entry ceiling selected more segments than the slot can address. Keep
	 * the auto byte ceiling; the caller rejects any still-oversized arena.
	 */
	while (total_size / sz > CACHE_MAX_N_SEGS && sz < CACHE_SEG_AUTO_MAX)
		sz <<= 1;
	return sz;
}

/* A small iterator API to abstract away the hash table addressing scheme */
struct ht_iter {
	const struct cache *cache;
	uint8_t bucket_idx;    /* 0 or 1 */
	uint8_t slot_idx;      /* 0..7 */
};

static inline void ht_iter_init(struct ht_iter *it, const struct cache *cache)
{
	it->cache = cache;
	it->bucket_idx = 0;
	it->slot_idx = 0;
}

/* Return a pointer to the next slot in the buckets corresponding to <hash>.
 * Returns NULL when there are no more slots to consider.
 */
static inline uint64_t *ht_iter_next(struct ht_iter *it, const XXH128_hash_t *hash)
{
	struct ht_bucket *buckets, *bucket;
	uint32_t mask;

	if (it->slot_idx >= CACHE_BUCKET_N_SLOT) {
		if (it->bucket_idx > 0)
			return NULL;

		/* Now scan the second bucket. */
		it->bucket_idx++;
		it->slot_idx = 0;
	}

	buckets = it->cache->index.buckets;
	mask = it->cache->index.n_buckets - 1;
	if (it->bucket_idx == 0) {
		bucket = &buckets[hash->high64 & mask];
	} else {
		bucket = &buckets[hash->low64 & mask];
	}
	return &bucket->slot[it->slot_idx++];
}

/* Similar to ht_iter_next(), except that we only return pointers to slots that
 * match the tag in <hash>, skipping pending ones. Useful for lookups. This also
 * sets the slot's value in <val>, so the caller does not need to duplicate the
 * atomic load. Note that this only matches the tag and not the full hash, so
 * the slot we return is only a candidate for the hash; the caller needs to
 * check the full hash to ensure this is the correct slot.
 */
static inline uint64_t *ht_iter_next_tag(struct ht_iter *it, const XXH128_hash_t *hash, uint64_t *val)
{
	uint64_t *slotp, slot;

	while ((slotp = ht_iter_next(it, hash)) != NULL) {
		slot = HA_ATOMIC_LOAD(slotp);
		if (slot == 0 || (slot & CACHE_SLOT_PENDING))
			continue;

		if (CACHE_HASH_TAG(*hash) != CACHE_SLOT_TAG(slot))
			continue;

		*val = slot;
		return slotp;
	}
	return NULL;
}

/* Return the pending slot of the entry being written at <h>. Only its writer
 * may change or clear it, so it is always found.
 */
static uint64_t *ht_find_pending(const struct cache *cache, const struct cache_whandle *h)
{
	const struct cache_record *rec = CACHE_HANDLE_REC(cache, h);
	struct ht_iter it;
	uint64_t *slotp, slot;

	ht_iter_init(&it, cache);
	while ((slotp = ht_iter_next(&it, &rec->hash)) != NULL) {
		slot = _HA_ATOMIC_LOAD(slotp);
		if ((slot & CACHE_SLOT_PENDING) &&
		    CACHE_SLOT_SEG(slot) == h->seg_id &&
		    CACHE_SLOT_OFF(slot) == h->seg_off)
			return slotp;
	}
	/* A write handle always has a pending slot naming its record. */
	ABORT_NOW();
	return NULL;
}

/* Store <slot> in a free slot of one of <hash>'s two buckets, and return it, or
 * NULL if both are full. Prefer the bucket with more free slots: two-choice
 * hashing only delivers its load-factor benefit when inserts favor the emptier
 * bucket, and a more balanced fill defers the day both buckets are full. The
 * counts are racy, but they only steer the scan order; the CAS decides.
 */
static uint64_t *ht_insert(struct cache *cache, const XXH128_hash_t *hash, uint64_t slot)
{
	struct ht_bucket *b[2];
	uint32_t mask;
	int nfree[2];
	int i, j;

	mask = cache->index.n_buckets - 1;
	b[0] = &cache->index.buckets[hash->high64 & mask];
	b[1] = &cache->index.buckets[hash->low64 & mask];
	nfree[0] = nfree[1] = 0;
	for (i = 0; i < 2; i++)
		for (j = 0; j < CACHE_BUCKET_N_SLOT; j++)
			if (_HA_ATOMIC_LOAD(&b[i]->slot[j]) == 0)
				nfree[i]++;

	/* Put the buckets in scan order, emptiest first. */
	if (nfree[1] > nfree[0]) {
		struct ht_bucket *tmp = b[0];

		b[0] = b[1];
		b[1] = tmp;
	}

	for (i = 0; i < 2; i++) {
		struct ht_bucket *bkt = b[i];

		for (j = 0; j < CACHE_BUCKET_N_SLOT; j++) {
			uint64_t slot2;

			slot2 = HA_ATOMIC_LOAD(&bkt->slot[j]);
			if (slot2 != 0)
				continue;

			if (HA_ATOMIC_CAS(&bkt->slot[j], &slot2, slot))
				return &bkt->slot[j];
		}
	}
	return NULL;
}

/* A list's append rate is averaged over its retention time, as computed by
 * seg_list_elect_age(): CACHE_RATE_PERIOD_INIT seconds until one is known,
 * CACHE_RATE_PERIOD_MAX at most.
 */
#define CACHE_RATE_PERIOD_INIT 60
#define CACHE_RATE_PERIOD_MAX  4096

/* Small segment list API - avoids code duplication with the shared and private
 * segment lists in TTL buckets.
 */
static inline void seg_list_init(struct seg_list *l)
{
	l->first_seg_id = CACHE_SEG_NONE;
	l->last_seg_id = CACHE_SEG_NONE;
	l->n_segs = 0;
	l->rate_ts = 0;
	l->rate_acc = 0;
	l->rate = 0.0;
	l->rate_period = CACHE_RATE_PERIOD_INIT;
}

/* Bring <l>'s append rate up to the current second: the last second counted
 * enters the average, and the seconds without an append since then decay it.
 * Seconds are counted on the date all threads share, which only moves
 * forward: under the bucket lock, a caller never sees it go back.
 */
static inline void seg_list_rate_update(struct seg_list *l)
{
	uint32_t now = ns_to_sec(HA_ATOMIC_LOAD(global_now_ns));
	uint32_t elapsed = now - l->rate_ts;
	double keep = 1.0 - 1.0 / l->rate_period;
	uint32_t idle;

	if (elapsed == 0)
		return;
	l->rate = keep * l->rate + (1.0 - keep) * l->rate_acc;
	l->rate_acc = 0;
	/* Decay by <keep> to the power of the idle seconds. */
	for (idle = elapsed - 1; idle; idle >>= 1) {
		if (idle & 1)
			l->rate *= keep;
		keep *= keep;
	}
	l->rate_ts = now;
}

/* One bit per TTL bucket, set while the bucket holds at least one segment.
 * Bits change under the bucket's lock and are read without it.
 */
static inline void ttl_used_set(struct cache *cache, unsigned int id)
{
	_HA_ATOMIC_OR(&cache->ttl_used[id / LONGBITS], 1UL << (id % LONGBITS));
}

static inline void ttl_used_clear(struct cache *cache, unsigned int id)
{
	_HA_ATOMIC_AND(&cache->ttl_used[id / LONGBITS], ~(1UL << (id % LONGBITS)));
}

/* Return the first TTL bucket in use from <from> on, or CACHE_TTL_N_BUCKETS
 * if there is none.
 */
static inline unsigned int ttl_used_next(const struct cache *cache, unsigned int from)
{
	unsigned int w = from / LONGBITS;
	unsigned long bits;

	if (from >= CACHE_TTL_N_BUCKETS)
		return CACHE_TTL_N_BUCKETS;
	bits = _HA_ATOMIC_LOAD(&cache->ttl_used[w]) & (~0UL << (from % LONGBITS));
	while (!bits) {
		if (++w == CACHE_TTL_N_BUCKETS / LONGBITS)
			return CACHE_TTL_N_BUCKETS;
		bits = _HA_ATOMIC_LOAD(&cache->ttl_used[w]);
	}
	return w * LONGBITS + my_ffsl(bits) - 1;
}

/* A scan visits the TTL buckets from <off> on and wraps, so that the bucket
 * of rank <i> is (<off> + <i>) modulo CACHE_TTL_N_BUCKETS. Return the rank of
 * the first bucket in use from rank <i> on, or CACHE_TTL_N_BUCKETS if there
 * is none.
 */
static inline unsigned int ttl_used_first(const struct cache *cache, unsigned int off,
                                         unsigned int i)
{
	unsigned int id;

	if (i < CACHE_TTL_N_BUCKETS - off) {
		id = ttl_used_next(cache, off + i);
		if (id < CACHE_TTL_N_BUCKETS)
			return id - off;
		i = CACHE_TTL_N_BUCKETS - off;
	}
	id = ttl_used_next(cache, i - (CACHE_TTL_N_BUCKETS - off));
	if (id < off)
		return id + CACHE_TTL_N_BUCKETS - off;
	return CACHE_TTL_N_BUCKETS;
}

static inline void seg_list_append(struct cache *cache, struct seg_list *l,
                                   seg_id_t seg_id)
{
	struct seg *seg, *prev;

	if (l->last_seg_id != CACHE_SEG_NONE) {
		prev = &cache->segments[l->last_seg_id];
		prev->next_seg_id = seg_id;
	}
	seg = &cache->segments[seg_id];
	seg->prev_seg_id = l->last_seg_id;
	seg->next_seg_id = CACHE_SEG_NONE;
	l->last_seg_id = seg_id;
	if (l->first_seg_id == CACHE_SEG_NONE) {
		l->first_seg_id = seg_id;
		ttl_used_set(cache, seg->ttl_bucket);
	}

	l->n_segs += seg->n_chain;
	seg_list_rate_update(l);
	l->rate_acc += seg->n_chain;
}

static inline void seg_list_splice(struct cache *cache, struct seg_list *l,
                                   seg_id_t first_id, seg_id_t last_id, seg_id_t new_id)
{
	struct seg *first, *last, *new;
	seg_id_t prev_id, next_id, id;
	seg_id_t after_prev, before_next;

	first = &cache->segments[first_id];
	last = &cache->segments[last_id];
	prev_id = first->prev_seg_id;
	next_id = last->next_seg_id;

	for (id = first_id; ; id = cache->segments[id].next_seg_id) {
		l->n_segs -= cache->segments[id].n_chain;
		if (id == last_id)
			break;
	}

	if (new_id != CACHE_SEG_NONE) {
		new = &cache->segments[new_id];
		new->prev_seg_id = first->prev_seg_id;
		new->next_seg_id = last->next_seg_id;
		l->n_segs += new->n_chain;
		after_prev = new_id;
		before_next = new_id;
	} else {
		after_prev = next_id;
		before_next = prev_id;
	}

	if (prev_id != CACHE_SEG_NONE)
		cache->segments[prev_id].next_seg_id = after_prev;
	else {
		const struct ttl_bucket *ttlb = &cache->ttl_buckets[first->ttl_bucket];

		l->first_seg_id = after_prev;
		if (ttlb->segs.first_seg_id == CACHE_SEG_NONE &&
		    ttlb->prv_segs.first_seg_id == CACHE_SEG_NONE)
			ttl_used_clear(cache, first->ttl_bucket);
	}

	if (next_id != CACHE_SEG_NONE)
		cache->segments[next_id].prev_seg_id = before_next;
	else
		l->last_seg_id = before_next;
}

static inline seg_id_t seg_list_first(struct seg_list *l)
{
	return l->first_seg_id;
}

static inline seg_id_t seg_list_last(struct seg_list *l)
{
	return l->last_seg_id;
}

/* Internal segment API */

static inline seg_id_t seg_get_id(const struct cache *cache, const struct seg *seg)
{
	return seg - cache->segments;
}

/* Find the segment at position <seg_idx> in a chain. This is only used for
 * jumbo entries, and only for the functions reading at arbitrary offsets such
 * as cache_read_at() and cache_peek_at(), and also when moving the offset with
 * cache_seek() - although for cache_seek(), it will only walk the chain from
 * the current segment if possible. Other functions can just use the cached
 * current segment in the handle.
 */
static inline seg_id_t seg_chain_nth(const struct cache *cache, seg_id_t seg_id,
                                     unsigned int seg_idx)
{
	struct seg *seg;

	while (seg_idx > 0) {
		BUG_ON(seg_id == CACHE_SEG_NONE);
		seg = &cache->segments[seg_id];
		seg_id = seg->next_chain_id;
		seg_idx--;
	}

	return seg_id;
}

static inline void seg_reinit(struct seg *seg)
{
	uint32_t gen = SEG_STATE_GEN(_HA_ATOMIC_LOAD(&seg->state_gen));

	seg->write_off = 0;
	seg->n_chain = 1;
	seg->create_ts = date.tv_sec;
	seg->flags = 0;
	seg->merge_claimed = 0;
	_HA_ATOMIC_STORE(&seg->live_bytes, 0);
	_HA_ATOMIC_STORE(&seg->n_live, 0);
	_HA_ATOMIC_STORE(&seg->state_gen, SEG_STATE_MAKE(gen + 1, SEG_S_LIVE));
}

/* Grab up to <n_segs> segments from the free-list, linked as a chain. The pool
 * may supply fewer. Only a caller setting <reserve> may take the reserved
 * segments.
 */
static inline seg_id_t seg_free_pop(struct cache *cache, unsigned int n_segs, int reserve)
{
	seg_id_t first_seg_id, seg_id;
	unsigned int n_avail, n_left;
	struct seg *seg;

	BUG_ON(n_segs == 0);

	HA_SPIN_LOCK(CACHE_LOCK, &cache->pool_lock);
	n_avail = _HA_ATOMIC_LOAD(&cache->n_free);
	if (!reserve)
		n_avail -= MIN(n_avail, cache->cfg.n_reserved);
	if (n_segs > n_avail)
		n_segs = n_avail;
	if (n_segs == 0) {
		HA_SPIN_UNLOCK(CACHE_LOCK, &cache->pool_lock);
		return CACHE_SEG_NONE;
	}
	first_seg_id = cache->free_seg_id;
	seg_id = first_seg_id;
	n_left = n_segs;
	while (n_left > 0) {
		seg = &cache->segments[seg_id];
		seg_id = seg->next_chain_id;
		n_left--;
	}
	_HA_ATOMIC_SUB(&cache->n_free, n_segs);
	cache->free_seg_id = seg->next_chain_id;
	HA_SPIN_UNLOCK(CACHE_LOCK, &cache->pool_lock);
	seg->next_chain_id = CACHE_SEG_NONE;

	return first_seg_id;
}

/* Put a segment back on the free-list (which can be a chain). */
static inline void seg_free_push(struct cache *cache, seg_id_t seg_id)
{
	seg_id_t first_seg_id, last_seg_id;
	unsigned int n_segs;
	struct seg *last;

	BUG_ON(seg_id == CACHE_SEG_NONE);

	n_segs = 0;
	first_seg_id = seg_id;
	do {
		struct seg *seg = &cache->segments[seg_id];
		uint32_t gen = SEG_STATE_GEN(_HA_ATOMIC_LOAD(&seg->state_gen));

		n_segs++;
		/* It's not actually required to set the state back to
		 * SEG_S_FREE for correctness, but it is useful for debugging.
		 */
		_HA_ATOMIC_STORE(&seg->state_gen, SEG_STATE_MAKE(gen, SEG_S_FREE));
		last_seg_id = seg_id;
		seg_id = seg->next_chain_id;
	} while (seg_id != CACHE_SEG_NONE);

	last = &cache->segments[last_seg_id];

	HA_SPIN_LOCK(CACHE_LOCK, &cache->pool_lock);
	last->next_chain_id = cache->free_seg_id;
	cache->free_seg_id = first_seg_id;
	_HA_ATOMIC_ADD(&cache->n_free, n_segs);
	HA_SPIN_UNLOCK(CACHE_LOCK, &cache->pool_lock);
}

/* Given <data_off>, which is an offset into a record's data, set <seg_idx> to
 * be the index of the segment holding this data in the segment chain and return
 * the offset of the data in this segment. Note that <seg_idx> is the index in
 * the chain, as in, 0 is the first segment in the chain, 1 is the second, and
 * so on. The segment chain must then be walked using the next_chain_id linkage
 * field to locate the actual segment. <seg_idx> will only be set if non-NULL,
 * and is only useful when dealing with jumbo entries, and for cache_read_at()
 * and cache_peek_at() where we don't have a known current segment ID.
 */
static uint32_t seg_data_off(const struct cache *cache, uint32_t seg_off,
                             size_t data_off, unsigned int *seg_idx)
{
	/* Capacity of the first segment */
	size_t first_len = cache->cfg.seg_size - seg_off - sizeof(struct cache_record);
	size_t left;

	if (data_off < first_len) {
		if (seg_idx != NULL)
			*seg_idx = 0;
		return seg_off + sizeof(struct cache_record) + data_off;
	}

	left = data_off - first_len;
	if (seg_idx != NULL)
		*seg_idx = left / cache->cfg.seg_size + 1;
	return left % cache->cfg.seg_size;
}

/* Tell whether segment <seg> has expired. */
static inline int seg_expired(struct ttl_bucket *ttlb, const struct seg *seg)
{
	return (int64_t)date.tv_sec - seg->create_ts >= ttlb->ttl_approx;
}

/* Unpin a segment that was pinned for reads. */
static inline void seg_read_unpin(struct cache *cache, struct seg *seg)
{
	uint32_t prev, expected;

	prev = HA_ATOMIC_FETCH_SUB(&seg->r_refcount, 1);
	if (prev != 1)
		return;

	expected = HA_ATOMIC_LOAD_SEQ_CST(&seg->state_gen);
	if (SEG_STATE(expected) == SEG_S_CONDEMNED &&
	    HA_ATOMIC_LOAD_SEQ_CST(&seg->r_refcount) == 0) {
		/* We took the reader count to zero on a condemned segment:
		 * freeing it is our responsibility. The CONDEMNED -> FREE
		 * CAS can race seg_drain()'s own attempt and guarantees
		 * that exactly one of us pushes.
		 *
		 * The r_refcount recheck is required: <prev> == 1 only says
		 * we were the last reader at the instant of our decrement.
		 * If we stall before the state load, another reader can pin
		 * the still-live segment and the reclaimer can condemn it on
		 * that reader's behalf - acting on <prev> alone would free
		 * the segment under its pin. Seeing 0 here is decisive: this
		 * load is seq_cst-after the CONDEMNED store, which is
		 * seq_cst-after any pin the reclaimer observed, so a
		 * surviving reader's increment cannot be missed. Nor can the
		 * push be lost: every reader we defer to runs this same
		 * protocol when unpinning, and the segment is unindexed, so
		 * no new pin can settle - the final decrement finds 0.
		 *
		 * The CAS carries the generation we observed above: if we
		 * stalled across a complete free/reuse/re-condemn cycle of
		 * this segment, the r_refcount we rechecked belonged to the
		 * previous generation and says nothing about the current
		 * one's readers - the generation mismatch makes such a stale
		 * CAS fail instead of freeing the segment under them.
		 */
		if (HA_ATOMIC_CAS(&seg->state_gen, &expected,
		                  SEG_STATE_MAKE(SEG_STATE_GEN(expected), SEG_S_FREE))) {
			_HA_ATOMIC_DEC(&cache->segs_condemned);
			seg_free_push(cache, seg_get_id(cache, seg));
		}
	}
}

/* Pin a segment for reads. Returns a cache handle that can be safely used for
 * reading, because the segment has been validated and is now pinned. Returns
 * an error handle in case of failure.
 *
 * The <slotp> parameter is a pointer to the slot in the hash table, whereas
 * the <val> parameter is a pointer to the slot value that has already been
 * read atomically; the latter is both an input and output parameter that will
 * be set to the validated slot value on success.
 *
 * The hash pointer can be NULL, in which case identity is not verified and is
 * left to the caller. This is useful for enumeration.
 *
 * When <check_state> is zero, segments being reclaimed are not refused; see
 * the comment before the state check below.
 */
static inline struct cache_rhandle seg_read_pin(struct cache *cache,
                                                const XXH128_hash_t *hash,
                                                uint64_t *slotp, uint64_t *val,
                                                int check_state)
{
	struct cache_rhandle h;
	struct cache_record *rec;
	struct seg *seg;
	uint64_t slot, slot2;
	int tries = 0;

	slot = *val;

retry:
	h.seg_id = CACHE_SLOT_SEG(slot);
	h.cur_seg_id = h.seg_id;
	h.seg_off = CACHE_SLOT_OFF(slot);
	h.data_off = 0;
	seg = &cache->segments[h.seg_id];

	HA_ATOMIC_INC(&seg->r_refcount);

	/* Ensure that nothing changed out from under us. The load must be
	 * sequentially consistent, like the r_refcount increment above and
	 * seg_unindex()'s slot-clearing CAS: it is the other half of the
	 * Dekker pairing with seg_drain()'s r_refcount check. A change
	 * confined to the frequency counter is a concurrent hit, not a
	 * different slot; an emptied slot always is.
	 */
	slot2 = HA_ATOMIC_LOAD_SEQ_CST(slotp);
	if (slot2 == 0 || ((slot2 ^ slot) & ~CACHE_SLOT_FREQ_MASK)) {
		seg_read_unpin(cache, seg);
		slot = slot2;

		/* We need to validate again that this slot still
		 * matches our tag and is neither empty nor pending, since
		 * it changed.
		 */
		if (slot != 0 && !(slot & CACHE_SLOT_PENDING) &&
		    likely(hash != NULL) &&
		    CACHE_SLOT_TAG(slot) == CACHE_HASH_TAG(*hash)) {
			if (++tries < CACHE_READ_PIN_TRIES)
				goto retry;
			_HA_ATOMIC_INC(&cache->stats.read_pin_fails);
		}

		return CACHE_RHANDLE_NULL;
	}
	slot = slot2;

	/* Refuse the pin if the segment is no longer live. The load must be
	 * sequentially consistent: with the reference count increment above
	 * it forms a Dekker pair against seg_drain(), which stores
	 * SEG_S_DRAINING and then reads that count. One side always observes
	 * the other, so no reader serves from a segment reclaim goes on to
	 * recycle.
	 *
	 * Declining here is a serve decision, not what keeps the record
	 * alive: the pin and the slot revalidation above already force
	 * reclaim to condemn the segment and hand it to its last reader
	 * rather than free it. Callers that need to find an entry rather
	 * than serve it opt out - a purge, or a store superseding an older
	 * copy. Eviction marks a segment SEG_S_DRAINING while it decides,
	 * and puts it back if a writer holds it; an entry missed in that
	 * window would stay indexed.
	 */
	if (check_state &&
	    SEG_STATE(HA_ATOMIC_LOAD_SEQ_CST(&seg->state_gen)) != SEG_S_LIVE) {
		seg_read_unpin(cache, seg);
		return CACHE_RHANDLE_NULL;
	}

	rec = CACHE_HANDLE_REC(cache, &h);
	if (likely(hash != NULL) &&
	    memcmp(&rec->hash, hash, sizeof(rec->hash)) != 0) {
		seg_read_unpin(cache, seg);
		return CACHE_RHANDLE_NULL;
	}

	*val = slot;
	return h;
}

/* Pin a segment for writes. */
static inline void seg_write_pin(struct seg *seg)
{
	HA_ATOMIC_INC(&seg->w_refcount);
}

/* Unpin a segment that was pinned for writes. */
static inline void seg_write_unpin(struct seg *seg)
{
	HA_ATOMIC_DEC(&seg->w_refcount);
}

/* Account for a record of a shared segment gaining or losing its index slot. */
static inline void seg_live_add(struct seg *seg, const struct cache_record *rec)
{
	_HA_ATOMIC_ADD(&seg->live_bytes, CACHE_OFF_ALIGN_UP(rec->rec_len));
	_HA_ATOMIC_INC(&seg->n_live);
}

static inline void seg_live_sub(struct seg *seg, const struct cache_record *rec)
{
	_HA_ATOMIC_SUB(&seg->live_bytes, CACHE_OFF_ALIGN_UP(rec->rec_len));
	_HA_ATOMIC_DEC(&seg->n_live);
}

/* Clear a segment's index slots and return the number of records examined. */
static unsigned int seg_unindex(const struct cache *cache, struct seg *seg)
{
	struct cache_whandle h = { .seg_id = seg_get_id(cache, seg) };
	struct ht_iter it;
	struct cache_record *rec;
	uint64_t *slotp, slot;
	size_t off = 0;
	unsigned int records = 0;

	BUG_ON_HOT(seg->write_off > cache->cfg.seg_size);

	/* A jumbo record's stride is the whole entry length and may exceed 4 GB,
	 * so the cursor is a size_t: a uint32 would wrap back below the bound and
	 * parse payload as a record header. h.seg_off stays below write_off,
	 * hence below seg_size.
	 */
	while (off < seg->write_off) {
		h.seg_off = off;
		rec = CACHE_HANDLE_REC(cache, &h);

		BUG_ON_HOT(rec->rec_len <= sizeof(struct cache_record));

		ht_iter_init(&it, cache);
		while ((slotp = ht_iter_next_tag(&it, &rec->hash, &slot)) != NULL) {
			int success = 0;

			/* Retry a CAS lost to a counter bump; stop if the slot
			 * was replaced.
			 */
			do {
				if (CACHE_SLOT_SEG(slot) != h.seg_id ||
				    CACHE_SLOT_OFF(slot) != h.seg_off)
					break;
				success = HA_ATOMIC_CAS(slotp, &slot, 0);
			} while (!success);

			if (success)
				break;
		}

		off += CACHE_OFF_ALIGN_UP(rec->rec_len);
		records++;
	}
	return records;
}

/* Merge tuning, after Segcache. A merge needs a sequence of at least
 * CACHE_MERGE_MIN evictable segments and takes up to CACHE_MERGE_MAX; sources
 * must be more than CACHE_MERGE_EXPIRY_GUARD seconds from expiry. A search
 * examines at most CACHE_MERGE_SCAN_MAX segments. Retain about
 * 1/CACHE_MERGE_TARGET of each source's bytes, and stop taking sources once
 * the destination is CACHE_MERGE_STOP_PCT percent full.
 */
#define CACHE_MERGE_MIN           3
#define CACHE_MERGE_MAX           8
#define CACHE_MERGE_SCAN_MAX      32
#define CACHE_MERGE_EXPIRY_GUARD  20
#define CACHE_MERGE_TARGET        4
#define CACHE_MERGE_STOP_PCT      90

/* Outcome of a merge, in bytes of source records unless stated otherwise. */
struct seg_merge_res {
	unsigned int merged; /* Sources consumed, from the head onwards */
	unsigned int records; /* Source records walked */
	size_t copied;   /* Retained: copied to the destination and re-indexed */
	size_t dropped;  /* Below the cutoff, or no room left in the destination */
	size_t dead;     /* Had no index slot */
	size_t expired;
	size_t lost;     /* Copied, but re-indexed elsewhere concurrently */
};

/* Merge the claimed shared segments in <srcs>, in list order, into <dst>:
 * one-pass merge-based eviction. Records worth keeping are copied to the
 * destination and their slots repointed to it; every other slot into a consumed
 * source is cleared, so consumed sources come out unindexed. Sources are
 * consumed in list order until the destination is nearly full or <n_srcs> is
 * reached, but at least two, so that a merge always frees one segment net of
 * its destination: a second source met with a full destination is thinned to
 * what still fits. res->merged says how many were consumed, the rest are
 * untouched. Sources have no writer; the destination is a fresh segment linked
 * in no list. The descriptors are protected by merge_claimed while the bucket
 * lock is released. Links may change meanwhile: follow only the captured source
 * IDs, never their list linkage.
 *
 * A record is retained when its hit count, scaled by its size relative to the
 * mean live record of its segment, exceeds the cutoff. The cutoff aims at
 * keeping 1/CACHE_MERGE_TARGET of each source's scanned bytes, dead ones
 * included: after every tenth of a segment it moves by the relative error on
 * that target whenever it exceeds 50%, and each source starts from the midpoint
 * between 1 and the previous source's final value. A source whose incoming
 * cutoff is zero, the first one under <copy_all> or any one after a source
 * whose cutoff collapsed to zero, is copied whole. Once the destination is past
 * its stop mark and so is the scan of the current source, the remainder of that
 * source is kept whole rather than thinned for a next source that will not
 * come; only a full destination drops a record then.
 */
static void seg_merge(struct cache *cache, seg_id_t dst_id, const seg_id_t *srcs,
                      unsigned int n_srcs, int copy_all, struct seg_merge_res *res)
{
	struct seg *dst = &cache->segments[dst_id];
	uint32_t stop = (uint64_t)cache->cfg.seg_size * CACHE_MERGE_STOP_PCT / 100;
	uint32_t intvl = cache->cfg.seg_size / 10;
	double target = 1.0 / MIN(n_srcs, CACHE_MERGE_TARGET);
	double cutoff = 1.0;
	seg_id_t src_id;
	struct seg *src;

	memset(res, 0, sizeof(*res));
	/* The destination expires with its oldest source. */
	dst->create_ts = cache->segments[srcs[0]].create_ts;
	dst->ttl_bucket = cache->segments[srcs[0]].ttl_bucket;
	if (copy_all)
		cutoff = 0.0;

	while (res->merged < n_srcs) {
		struct cache_whandle h = { .seg_id = srcs[res->merged] };
		size_t scanned = 0, copied = 0, checkpoint = intvl;
		uint32_t n_live, off = 0;
		double mean_size;
		int keep_rest;

		src_id = h.seg_id;
		BUG_ON_HOT(src_id == CACHE_SEG_NONE);
		src = &cache->segments[src_id];
		BUG_ON_HOT(src->flags & SEG_F_PRIVATE);
		BUG_ON_HOT(src->write_off > cache->cfg.seg_size);

		n_live = _HA_ATOMIC_LOAD(&src->n_live);
		mean_size = 1.0;
		if (n_live)
			mean_size = (double)_HA_ATOMIC_LOAD(&src->live_bytes) / n_live;
		keep_rest = cutoff < 0.0001;
		cutoff = (1.0 + cutoff) / 2.0;

		while (off < src->write_off) {
			struct cache_record *rec;
			struct ht_iter it;
			uint64_t *slotp, slot, newval;
			uint32_t stride;
			int expired, retain, relinked;

			h.seg_off = off;
			rec = CACHE_HANDLE_REC(cache, &h);
			BUG_ON_HOT(rec->rec_len <= sizeof(struct cache_record));
			stride = CACHE_OFF_ALIGN_UP(rec->rec_len);
			off += stride;
			scanned += stride;
			res->records++;

			if (scanned >= checkpoint) {
				double t = ((double)copied / scanned - target) / target;

				if (t > 0.5 || t < -0.5)
					cutoff *= 1.0 + t;
				checkpoint += intvl;
			}
			if (!keep_rest && dst->write_off >= stop && off - stride > stop)
				keep_rest = 1;

			ht_iter_init(&it, cache);
			while ((slotp = ht_iter_next_tag(&it, &rec->hash, &slot)) != NULL) {
				if (CACHE_SLOT_SEG(slot) == h.seg_id &&
				    CACHE_SLOT_OFF(slot) == h.seg_off)
					break;
			}
			if (slotp == NULL) {
				res->dead += stride;
				continue;
			}

			expired = date.tv_sec >= rec->expire;
			retain = 0;
			if (!expired) {
				double hits = (double)CACHE_SLOT_FREQ(slot);
				double score = hits / ((double)stride / mean_size);

				retain = (keep_rest || score > cutoff) &&
				         dst->write_off + stride <= cache->cfg.seg_size;
			}

			if (retain) {
				memcpy((char *)cache->arena +
				       CACHE_ARENA_OFF(cache, dst_id, dst->write_off),
				       rec, stride);
				/* The counter starts over, so that a record that was
				 * once hot does not outlive its popularity.
				 */
				newval = CACHE_SLOT_MAKE(CACHE_HASH_TAG(rec->hash),
				                         dst_id, dst->write_off, 0);
			}
			else
				newval = 0;

			/* Clear or repoint the slot, retrying a CAS lost to a
			 * counter bump; stop if it no longer names this record.
			 */
			relinked = 1;
			do {
				if (slot == 0 ||
				    CACHE_SLOT_SEG(slot) != h.seg_id ||
				    CACHE_SLOT_OFF(slot) != h.seg_off) {
					relinked = 0;
					break;
				}
			} while (!HA_ATOMIC_CAS(slotp, &slot, newval));

			if (expired)
				res->expired += stride;
			else if (!retain)
				res->dropped += stride;
			else if (relinked) {
				seg_live_add(dst, rec);
				dst->write_off += stride;
				res->copied += stride;
				copied += stride;
			}
			else
				res->lost += stride;
		}

		res->merged++;
		if (res->merged >= 2 && dst->write_off >= stop)
			break;
	}
}

/* Tell whether <seg> of bucket <ttlb> expires within CACHE_MERGE_EXPIRY_GUARD
 * seconds: too soon for a merge to be worth its copy.
 */
static inline int seg_expiring(const struct ttl_bucket *ttlb, const struct seg *seg)
{
	int64_t age = (int64_t)date.tv_sec - seg->create_ts;

	return age + CACHE_MERGE_EXPIRY_GUARD >= ttlb->ttl_approx;
}

/* Tell whether <seg>, in <ttlb>'s shared list, can be merged: it has a
 * successor, no writer and more than CACHE_MERGE_EXPIRY_GUARD seconds
 * until expiry. The caller holds the bucket's lock.
 */
static inline int seg_evictable(const struct ttl_bucket *ttlb, const struct seg *seg)
{
	return !seg->merge_claimed && seg->next_seg_id != CACHE_SEG_NONE &&
	       HA_ATOMIC_LOAD(&seg->w_refcount) == 0 &&
	       !seg_expiring(ttlb, seg);
}

/* Search up to <max> segments for CACHE_MERGE_MIN consecutive evictable ones.
 * At <stop>, only finish a run already in progress, rechecking at most
 * CACHE_MERGE_MIN - 1 segments. Returns its start or CACHE_SEG_NONE.
 * The caller holds <ttlb>'s lock.
 */
static seg_id_t seg_merge_find(const struct cache *cache,
                               const struct ttl_bucket *ttlb, seg_id_t seg_id,
                               seg_id_t stop, unsigned int max)
{
	const struct seg *seg;
	seg_id_t start = seg_id;
	unsigned int n = 0;
	int past = 0;

	while (seg_id != CACHE_SEG_NONE) {
		if (seg_id == stop) {
			if (!n)
				break;
			past = 1;
		}
		if (!past) {
			if (!max)
				break;
			max--;
		}
		seg = &cache->segments[seg_id];
		if (seg_evictable(ttlb, seg)) {
			n++;
			if (n == CACHE_MERGE_MIN)
				return start;
		}
		else {
			if (past)
				break;
			n = 0;
			start = seg->next_seg_id;
		}
		seg_id = seg->next_seg_id;
	}
	return CACHE_SEG_NONE;
}

/* Claim the sequence starting at <head_id> and the evictable segments that
 * follow it, up to CACHE_MERGE_MAX in all; returns how many and captures their
 * IDs. The merge_claimed marker excludes reclamation and append admission even
 * if removing successors makes a source the structural tail. The destination
 * needs the same protection: its published records can be deleted before the
 * merge links it into the list.
 */
static unsigned int seg_merge_claim(const struct cache *cache, const struct ttl_bucket *ttlb,
                                    seg_id_t head_id, seg_id_t *srcs)
{
	seg_id_t seg_id = head_id;
	unsigned int n = 0;

	while (n < CACHE_MERGE_MAX && seg_id != CACHE_SEG_NONE &&
	       seg_evictable(ttlb, &cache->segments[seg_id])) {
		srcs[n++] = seg_id;
		cache->segments[seg_id].merge_claimed = 1;
		seg_id = cache->segments[seg_id].next_seg_id;
	}
	BUG_ON_HOT(n < CACHE_MERGE_MIN);
	return n;
}

/* A bucket's resume point <next> of generation <gen>, for its next merge or
 * private eviction, or CACHE_SEG_NONE when unset or when the segment it named
 * has been reclaimed since (its generation moved on, or it is no longer live).
 * The caller holds the bucket's lock.
 */
static inline seg_id_t seg_cursor(const struct cache *cache, seg_id_t *next, uint32_t gen)
{
	uint32_t w;

	if (*next == CACHE_SEG_NONE)
		return CACHE_SEG_NONE;
	w = _HA_ATOMIC_LOAD(&cache->segments[*next].state_gen);
	if (SEG_STATE(w) != SEG_S_LIVE || SEG_STATE_GEN(w) != gen)
		*next = CACHE_SEG_NONE;
	return *next;
}

static inline void seg_cursor_set(const struct cache *cache, seg_id_t *next, uint32_t *gen,
                                  seg_id_t seg_id)
{
	*next = seg_id;
	if (seg_id != CACHE_SEG_NONE) {
		uint32_t w = _HA_ATOMIC_LOAD(&cache->segments[seg_id].state_gen);

		*gen = SEG_STATE_GEN(w);
	}
}

/* Free the unindexed, unlinked segment <seg_id>, or condemn it to be freed by
 * its last reader. The segment has no writer and was unlinked under the lock
 * of the TTL bucket it came from, which need not be held any more. Returns
 * SEG_RECLAIM_FREED or SEG_RECLAIM_CONDEMNED.
 */
static inline enum seg_reclaim_status seg_drain(struct cache *cache, seg_id_t seg_id)
{
	struct seg *seg = &cache->segments[seg_id];
	uint32_t expected, gen;

	/* Stop new readers from keeping a pin: they bump r_refcount first and
	 * only then check the state, so every reader that got past this store
	 * is counted by the loads below. No CAS is needed since only code
	 * holding the bucket lock leaves SEG_S_LIVE, and an unlinked segment
	 * has a single owner; a caller that already stored SEG_S_DRAINING
	 * loses nothing by our storing it again.
	 */
	gen = SEG_STATE_GEN(_HA_ATOMIC_LOAD(&seg->state_gen));
	HA_ATOMIC_STORE_SEQ_CST(&seg->state_gen,
	                        SEG_STATE_MAKE(gen, SEG_S_DRAINING));

	/* At this point, there are no writers, no new writers or code trying to
	 * expire/evict this segment can come because it has been unlinked from
	 * the TTL bucket, no new readers can come because the hashtable index
	 * slots have been cleared, but there might still be pre-existing
	 * readers, and in-flight readers who have located this segment from the
	 * hash table before its slots were cleared, but have yet to increment
	 * the read refcount.
	 */
	if (HA_ATOMIC_LOAD_SEQ_CST(&seg->r_refcount) == 0) {
		/* Relaxed store is fine because of the free-list lock. */
		_HA_ATOMIC_STORE(&seg->state_gen,
		                 SEG_STATE_MAKE(gen, SEG_S_FREE));
		/* We saw that r_refcount is 0 here, so we know that there are
		 * no pre-existing readers. Only those in-flight readers can get
		 * to the struct seg, and they will promptly bail because the
		 * state is not SEG_S_LIVE anymore. However, as soon as we call
		 * seg_free_push(), it is possible for another writer in another
		 * TTL bucket to pick it up and reuse it, in which case the
		 * state will be SEG_S_LIVE again.
		 *
		 * Any in-flight readers incrementing r_refcount then verify
		 * that the hashtable slot they read has not changed. In all
		 * likelihood, if the segment has been picked up again, it will
		 * have changed. However, if a new entry was stored, and its tag
		 * and offset equal the previous ones, the readers will go on.
		 * They will then check the full hash in the record. This is
		 * safe, because if the slot has been published, the entry is
		 * complete and therefore so is the record header. In all
		 * likelihood, again, the full hash will not match the value the
		 * readers expect, but it is technically possible. If that
		 * happens, we are in one of two cases: either this new entry is
		 * legitimately a fresher version of the entry the readers
		 * wanted to read - which is fine - or we have a hash collision
		 * and it is an unrelated entry. That is of course fantastically
		 * unlikely, but it is possible and something we have already
		 * accepted by using hash comparison as our identity check.
		 * However, importantly, it won't cause any sort of corruption;
		 * the cache remains in a valid state.
		 */
		seg_free_push(cache, seg_id);
		return SEG_RECLAIM_FREED;
	}

	/* We do not need a CAS here either, for the exact same reason as the
	 * transition to SEG_S_DRAINING above. The segment is counted as
	 * condemned before the store: whoever wins the CONDEMNED -> FREE CAS
	 * uncounts it, and no reader can observe CONDEMNED before the counter
	 * is bumped.
	 */
	HA_ATOMIC_UPDATE_MAX(&cache->stats.segs_condemned_max,
	                     _HA_ATOMIC_ADD_FETCH(&cache->segs_condemned, 1));
	HA_ATOMIC_STORE_SEQ_CST(&seg->state_gen,
	                        SEG_STATE_MAKE(gen, SEG_S_CONDEMNED));

	/* We compare r_refcount to 0 again here, to exclude pre-existing
	 * readers, exactly like the check before transitioning to CONDEMNED.
	 * This is necessary because since we did that transition, all the
	 * pre-existing readers may have terminated and we don't know if there
	 * are in-flight readers or not, but we still need someone to handle
	 * that push back to the free-list. It can either be us, or the last
	 * reader calling seg_read_unpin() - it cannot miss the CONDEMNED
	 * state, by the same SEQ_CST ordering the earlier checks rely on, and
	 * the CONDEMNED -> FREE CAS guarantees that exactly one of us
	 * performs the push. Therefore, if we see that r_refcount is 0 here,
	 * we need to attempt to do the push ourselves.
	 */
	if (HA_ATOMIC_LOAD_SEQ_CST(&seg->r_refcount) == 0) {
		/* And because we still have no way to know if there are
		 * in-flight readers or not, we need to use a CAS. It carries
		 * the word we stored above: if we stall here across a full
		 * free/reuse/re-condemn cycle of this segment, the generation
		 * mismatch makes our stale CAS fail instead of freeing the
		 * segment under the new generation's readers.
		 */
		expected = SEG_STATE_MAKE(gen, SEG_S_CONDEMNED);
		if (HA_ATOMIC_CAS(&seg->state_gen, &expected,
		                  SEG_STATE_MAKE(gen, SEG_S_FREE))) {
			_HA_ATOMIC_DEC(&cache->segs_condemned);
			seg_free_push(cache, seg_id);
		}
		/* Won or lost, the push is done or imminent: the segment is
		 * freed.
		 */
		return SEG_RECLAIM_FREED;
	}

	/* Pre-existing readers still hold the segment; the last one to unpin
	 * will free it. It is gone from the index and the TTL chain, but it
	 * is not supply the caller can pop yet.
	 */
	return SEG_RECLAIM_CONDEMNED;
}

/* Take segment <seg_id> out of segment list <l> to reclaim it, the part of
 * reclaiming that needs the TTL bucket lock, which the caller holds. The whole
 * segment chain goes with its head; the number of segments it counts is stored
 * in <n_segs>. Returns 0, leaving the segment untouched, if a merge claimed it
 * or a writer pins it. Otherwise the segment is SEG_S_DRAINING and in no list:
 * nothing that takes the bucket lock can reach it any more, and seg_unindex()
 * then seg_drain() finish the job without the lock.
 */
static inline int seg_unlink(struct cache *cache, struct seg_list *l,
                             seg_id_t seg_id, uint32_t *n_segs)
{
	struct seg *seg = &cache->segments[seg_id];
	uint32_t gen;

	/* The merge owner still parses these bytes or appends copied records to an
	 * unlinked destination. Leave its state and linkage untouched.
	 */
	if (seg->merge_claimed)
		return 0;

	/* Setting the state to something other than SEG_S_LIVE stops any new
	 * reader from keeping a pin - but crucially, they still bump r_refcount
	 * first and only then check the state, so they do touch this seg's
	 * struct before backing out.
	 *
	 * We do not need to use a CAS here because this LIVE -> DRAINING
	 * transition can only be performed by code trying to expire or evict
	 * this segment, and those code paths require the TTL bucket lock that
	 * we are holding.
	 */
	gen = SEG_STATE_GEN(_HA_ATOMIC_LOAD(&seg->state_gen));
	HA_ATOMIC_STORE_SEQ_CST(&seg->state_gen,
	                        SEG_STATE_MAKE(gen, SEG_S_DRAINING));

	/* Now we check for writer pins. Increments to w_refcount happen under
	 * the TTL bucket lock we hold, so no new writer can appear. The load
	 * still needs to be acquire: proceeding on zero means we observed the
	 * last writer's lock-free decrement, and seg_unindex() later parses
	 * record headers (rec_len, hash) that this writer wrote AFTER
	 * releasing the bucket lock - for a never-published record, this
	 * acquire pairing with the decrement (an RMW, hence release) is the
	 * only thing ordering those header writes before our parse. A relaxed
	 * load could hand seg_unindex stale header bytes on weakly-ordered
	 * machines. If we see that writes are still happening, we cannot go
	 * on and have to bail.
	 */
	if (HA_ATOMIC_LOAD(&seg->w_refcount) > 0) {
		/* Relaxed store because we don't have anything to publish. */
		_HA_ATOMIC_STORE(&seg->state_gen,
		                 SEG_STATE_MAKE(gen, SEG_S_LIVE));
		return 0;
	}

	/* The head segment records the length of its chain. */
	*n_segs = seg->n_chain;

	/* Unlink the segment from the TTL bucket. This means it won't be a
	 * candidate for expiration or eviction anymore. If this segment was
	 * also the active one, no new writers will be able to find it as well.
	 */
	seg_list_splice(cache, l, seg_id, seg_id, CACHE_SEG_NONE);
	return 1;
}

/* Reclaim segment <seg_id> of segment list <l> entirely under the TTL bucket
 * lock, which the caller holds: see seg_unlink(). Examined records are added to
 * <records> when non-NULL.
 */
static inline enum seg_reclaim_status seg_reclaim(struct cache *cache,
                                                  struct seg_list *l,
                                                  seg_id_t seg_id,
                                                  uint32_t *n_segs,
                                                  unsigned int *records)
{
	unsigned int n_records;

	if (!seg_unlink(cache, l, seg_id, n_segs))
		return SEG_RECLAIM_BLOCKED;

	/* Now we unindex, which guarantees no new lookups will get to the seg
	 * structure anymore, since it won't be found in the hashtable.
	 */
	n_records = seg_unindex(cache, &cache->segments[seg_id]);
	if (records)
		*records += n_records;

	return seg_drain(cache, seg_id);
}

/* Reclaim shared segment <seg_id> of bucket <ttlb> if no writer and no indexed
 * record are left in it: nothing can reach it any more. The writer count is
 * read first, since a publish bumps n_live before dropping its pin. The caller
 * holds the bucket lock.
 */
static void seg_reclaim_dead(struct cache *cache, struct ttl_bucket *ttlb, seg_id_t seg_id)
{
	struct seg *seg = &cache->segments[seg_id];
	uint32_t n_segs;

	if (HA_ATOMIC_LOAD(&seg->w_refcount) != 0 || HA_ATOMIC_LOAD(&seg->n_live) != 0)
		return;
	if (seg_reclaim(cache, &ttlb->segs, seg_id,
	                &n_segs, NULL) != SEG_RECLAIM_BLOCKED)
		_HA_ATOMIC_ADD(&cache->stats.segs_emptied, n_segs);
}

/* Reclaim shared segment <seg_id> at once if an abort, delete or supersede
 * just left it dead, unless it is its bucket's tail, which still takes new
 * reservations. <ttl_bucket> and <state_gen> were read while the caller still
 * pinned the segment: a different state or generation under the lock means it
 * was reclaimed, and possibly reused, meanwhile.
 */
static void seg_check_dead(struct cache *cache, seg_id_t seg_id,
                           unsigned int ttl_bucket, uint32_t state_gen)
{
	struct seg *seg = &cache->segments[seg_id];
	struct ttl_bucket *ttlb = &cache->ttl_buckets[ttl_bucket];

	if (SEG_STATE(state_gen) != SEG_S_LIVE || HA_ATOMIC_LOAD(&seg->n_live) != 0)
		return;

	HA_SPIN_LOCK(CACHE_TTLB_LOCK, &ttlb->lock);
	if (_HA_ATOMIC_LOAD(&seg->state_gen) == state_gen &&
	    seg_list_last(&ttlb->segs) != seg_id)
		seg_reclaim_dead(cache, ttlb, seg_id);
	HA_SPIN_UNLOCK(CACHE_TTLB_LOCK, &ttlb->lock);
}

/* One reservation or growth operation shares this state across its reclaim
 * passes. <reserving> is its segment count. Each pass tries to free
 * <shortfall> segments and counts in <freed> those that reached the pool.
 * <last> is the previous pass's result. <spent> counts the budget used and
 * <units> the reclaim units started.
 */
struct cache_reclaim_ctx {
	unsigned int reserving;
	unsigned int shortfall;
	unsigned int freed;
	enum cache_reclaim_status last;
	unsigned int spent;
	unsigned int units;
};

/* Tell whether <rc> may start another reclaim unit: its first one, or one
 * within the budget.
 */
static inline int cache_reclaim_may_act(const struct cache_reclaim_ctx *rc)
{
	return !rc->units || rc->spent < CACHE_RECLAIM_BUDGET;
}

/* Account for a reclaim unit of <rc> that walked <records> records. */
static inline void cache_reclaim_unit(struct cache_reclaim_ctx *rc,
                                      unsigned int records)
{
	rc->units++;
	rc->spent += records;
}

static inline void cache_reclaim_init(struct cache_reclaim_ctx *rc,
                                      unsigned int reserving)
{
	*rc = (struct cache_reclaim_ctx){
		.reserving = reserving,
		.last = CACHE_RECLAIM_RETRY,
	};
}

/* Tell whether the pool can already serve <rc>'s reservation. */
static inline int cache_pool_covers(struct cache *cache,
                                    const struct cache_reclaim_ctx *rc)
{
	return _HA_ATOMIC_LOAD(&cache->n_free) >= cache->cfg.n_reserved + rc->reserving;
}

/* Tell whether expiration on behalf of <rc> may reclaim another segment; NULL
 * leaves the expired prefix unbounded, as in cache_expire(). Past the
 * shortfall, expiring early still pays: the records are unindexed once either
 * way, and each segment freed now spares a later reservation a scan.
 */
static inline int cache_expire_more(const struct cache_reclaim_ctx *rc)
{
	return !rc || cache_reclaim_may_act(rc);
}

/* Reclaim an expired prefix until <rc> stops it, adding the segments freed to
 * its count. Writer pins are skipped; condemned segments consume records but
 * supply no free segments. Whole segments/chains may overrun the record limit.
 * The caller holds <ttlb>'s lock, which is dropped while each victim is
 * unindexed and held again on return.
 */
static void seg_list_expire(struct cache *cache, struct ttl_bucket *ttlb,
                            struct seg_list *l, struct cache_reclaim_ctx *rc)
{
	enum seg_reclaim_status status;
	struct seg *seg;
	seg_id_t seg_id, next_id;
	uint32_t n_segs, next_gen = 0;
	unsigned int n_records;

	seg_id = seg_list_first(l);
	while (seg_id != CACHE_SEG_NONE) {
		seg = &cache->segments[seg_id];
		next_id = seg->next_seg_id;
		if (!seg_expired(ttlb, seg) || !cache_expire_more(rc))
			break;
		if (!seg_unlink(cache, l, seg_id, &n_segs)) {
			seg_id = next_id;
			continue;
		}
		if (next_id != CACHE_SEG_NONE)
			next_gen = _HA_ATOMIC_LOAD(&cache->segments[next_id].state_gen);

		HA_SPIN_UNLOCK(CACHE_TTLB_LOCK, &ttlb->lock);
		n_records = seg_unindex(cache, seg);
		if (rc)
			cache_reclaim_unit(rc, n_records);
		status = seg_drain(cache, seg_id);
		HA_SPIN_LOCK(CACHE_TTLB_LOCK, &ttlb->lock);

		if (status == SEG_RECLAIM_FREED && rc)
			rc->freed += n_segs;
		_HA_ATOMIC_ADD(&cache->stats.segs_expired, n_segs);

		/* A segment leaves a list only by changing state, so a successor
		 * still live in the same generation is still linked here. If it
		 * went away meanwhile, start over from the head.
		 */
		if (next_id != CACHE_SEG_NONE &&
		    _HA_ATOMIC_LOAD(&cache->segments[next_id].state_gen) != next_gen)
			next_id = seg_list_first(l);
		seg_id = next_id;
	}
}

/* Internal TTL bucket API */

/* The TTL bucket for a TTL of <ttl> seconds. */
static inline struct ttl_bucket *ttl_bucket_get(struct cache *cache, uint32_t ttl)
{
	unsigned int h, g, idx;

	if (ttl == 0)
		idx = 0;
	else if (ttl >= CACHE_TTL_MAX)
		idx = CACHE_TTL_N_BUCKETS - 1;
	else {
		h = 31 - __builtin_clz(ttl);        /* highest set bit; ttl >= 1 */
		g = h / CACHE_TTL_FACTOR_BITS;
		if (g)
			g--;                        /* group = max(0, h/4 - 1);  */
		idx = (g << CACHE_TTL_GROUP_BITS) + (ttl >> (g * CACHE_TTL_FACTOR_BITS));
	}
	return &cache->ttl_buckets[idx];
}

/* The index of a TTL bucket. */
static inline uint16_t ttl_bucket_get_id(const struct cache *cache, const struct ttl_bucket *ttlb)
{
	return ttlb - cache->ttl_buckets;
}

/* Reserve <size> bytes in a TTL bucket's tail segment, or in a fresh segment
 * from the free pool. An entry larger than a segment gets only its first one
 * here; cache_make_room() grows its chain. Returns a null handle
 * when no segment is available; the caller decides whether to reclaim and
 * retry.
 */
static struct cache_whandle ttl_bucket_reserve(struct cache *cache, struct ttl_bucket *ttlb, size_t size)
{
	struct cache_whandle h;
	struct seg *seg;
	seg_id_t seg_id;
	uint32_t off;
	int private;

	private = (size == 0 || size > cache->cfg.seg_size);

	/* The size here must be the complete size, including the metadata
	 * header, and be properly aligned to 8 bytes.
	 */
	BUG_ON((size > 0 && size <= sizeof(struct cache_record)) ||
	       size & (CACHE_OFF_ALIGN - 1));

	HA_SPIN_LOCK(CACHE_TTLB_LOCK, &ttlb->lock);
	if (!private)
		seg_id = seg_list_last(&ttlb->segs);
	else
		/* When size is 0 or we need more than one segment, we have
		 * to use private segments for the reservation.
		 */
		seg_id = CACHE_SEG_NONE;

	/* Check if the tail segment exists and has enough room. */
	if (seg_id == CACHE_SEG_NONE || cache->segments[seg_id].merge_claimed ||
	    cache->segments[seg_id].write_off + size > cache->cfg.seg_size) {
		/* A dead tail is recycled rather than left to eviction: the
		 * pool hands it straight back.
		 */
		if (seg_id != CACHE_SEG_NONE)
			seg_reclaim_dead(cache, ttlb, seg_id);

		/* Get a free segment if possible. */
		seg_id = seg_free_pop(cache, 1, 0);
		if (seg_id == CACHE_SEG_NONE) {
			HA_SPIN_UNLOCK(CACHE_TTLB_LOCK, &ttlb->lock);
			return CACHE_WHANDLE_NULL;
		}

		/* Link the new segment in the TTL bucket. */
		seg = &cache->segments[seg_id];
		seg_reinit(seg);
		seg->ttl_bucket = ttl_bucket_get_id(cache, ttlb);
		if (private) {
			/* Private chains join the bucket's list at publish
			 * time. Until then the writer owns them alone, and
			 * failure paths return them whole to the pool.
			 */
			seg->flags |= SEG_F_PRIVATE;
		} else
			seg_list_append(cache, &ttlb->segs, seg_id);
		if (size == 0)
			seg->flags |= SEG_F_NO_LEN;
	} else {
		seg = &cache->segments[seg_id];
	}

	off = seg->write_off;
	seg->write_off += MIN(cache->cfg.seg_size - off, size);
	seg_write_pin(seg);
	HA_SPIN_UNLOCK(CACHE_TTLB_LOCK, &ttlb->lock);

	h.seg_id = seg_id;
	h.cur_seg_id = seg_id;
	h.seg_off = off;
	h.data_off = 0;
	return h;
}

/* External (and internal) cache API */
static int cache_index_init(struct cache *cache, uint64_t total_size)
{
	uint32_t n_buckets;
	size_t size;

	/* Two expected objects per bucket, which holds eight slots. Insert
	 * failures stay below noise up to ~60% slot load on this two-choice
	 * index and cross 1% at ~75%; publish_fails counts the refusals.
	 *
	 * The count is clamped before pow2_up(), whose uint32 domain overflows
	 * well within the 128 TB of arena that CACHE_MAX_TOTAL_SIZE permits:
	 * from 16 TB at the default mean, 512 GB at the 128-byte minimum. 2^26
	 * buckets is 4 GB of index, and well below the 2^52 that two-choice
	 * hashing tops out at here.
	 */
	n_buckets = pow2_up(MIN(1U << 26, MAX(1024, (total_size / cache->cfg.mean_obj_size) / 2)));
	cache->index.n_buckets = n_buckets;
	size = n_buckets * sizeof(struct ht_bucket);
	if (size / sizeof(struct ht_bucket) != n_buckets)
		return -1;
	cache->index.buckets = ha_aligned_alloc(64, size);
	if (!cache->index.buckets)
		return -1;
	memset(cache->index.buckets, 0, size);
	return 0;
}

void cache_destroy(struct cache *cache)
{
	if (cache == NULL)
		return;

	ha_aligned_free(cache->index.buckets);
	if (cache->arena != NULL && cache->arena != MAP_FAILED)
		munmap(cache->arena, cache->arena_len);
	free(cache->segments);
	free(cache->ttl_buckets);
	free(cache);
}

struct cache *cache_new(const struct cache_config *ucfg, uint flags,
                        size_t total_size, uint64_t seed, const char *name)
{
	struct cache *cache;
	struct cache_config *cfg;
	struct seg *seg;
	seg_id_t seg_id;
	unsigned int cap;
	int mapflags, i;

	/* Validate the parameters and deduce n_segs. */
	BUG_ON(total_size == 0);
#if SIZE_MAX > CACHE_MAX_TOTAL_SIZE
	BUG_ON(total_size > CACHE_MAX_TOTAL_SIZE);
#endif

	cache = calloc(1, sizeof(*cache));
	if (cache == NULL)
		goto out;
	cache->seed = seed;

	if (ucfg != NULL)
		memcpy(&cache->cfg, ucfg, sizeof(cache->cfg));
	cfg = &cache->cfg;

	if (cfg->mean_obj_size == 0)
		cfg->mean_obj_size = CACHE_IDX_MEAN_SIZE;
	if (cfg->seg_max_entries == 0)
		cfg->seg_max_entries = CACHE_SEG_DEFAULT_MAX_ENTRIES;
	if (cfg->seg_max_entries < CACHE_SEG_MIN_ENTRIES)
		goto out;

	if (cfg->seg_size == 0) {
		cfg->seg_size = cache_auto_segment_size(total_size, cfg->mean_obj_size,
		                                       cfg->seg_max_entries);
		/* We picked the size ourselves, so don't demand exact
		 * divisibility: use as many whole segments as fit.
		 */
		total_size = (total_size / cfg->seg_size) * (uint64_t)cfg->seg_size;
		if (total_size == 0)
			goto out;
	}

	if (cfg->seg_size <= sizeof(struct cache_record) || cfg->seg_size > CACHE_SEG_MAX_SIZE)
		goto out;
	if (cfg->seg_size & (CACHE_OFF_ALIGN - 1))
		goto out;
	if (total_size % cfg->seg_size != 0)
		goto out;

	cache->flags = flags;

	if (total_size / cfg->seg_size > CACHE_MAX_N_SEGS)
		goto out;
	cache->n_segs = total_size / cfg->seg_size;

	/* Merging off means no reserve is used, whatever cfg held. */
	if (flags & CACHE_F_NO_MERGE)
		cache->cfg.n_reserved = 0;

	/* Keep the reserve small: a 64th of the segments, but at least one. */
	cap = cache->n_segs / 64;
	if (cap < 1)
		cap = 1;
	if (cache->cfg.n_reserved > cap)
		cache->cfg.n_reserved = cap;

	/* Initialize the hashtable index. */
	if (cache_index_init(cache, total_size) != 0)
		goto out;

	/* Allocate the main storage area. We attempt to use MAP_HUGETLB if
	 * available, so the entire arena is allocated with huge pages. If that
	 * fails, we use a plain mmap() and try madvise(MADV_HUGEPAGE) when
	 * available: this gets us transparent huge pages, which are more likely
	 * to be enabled on most Linux systems, and should give us about the
	 * same benefits.
	 */
	mapflags = MAP_PRIVATE | MAP_ANON;
#ifdef MAP_HUGETLB
	mapflags |= MAP_HUGETLB;
#endif
	cache->arena_len = total_size;
	cache->arena = mmap(NULL, total_size, PROT_READ | PROT_WRITE, mapflags, -1, 0);
#ifdef MAP_HUGETLB
	if (cache->arena == MAP_FAILED) {
		mapflags &= ~MAP_HUGETLB;
		cache->arena = mmap(NULL, total_size, PROT_READ | PROT_WRITE, mapflags, -1, 0);
#ifdef MADV_HUGEPAGE
		if (cache->arena != MAP_FAILED)
			madvise(cache->arena, total_size, MADV_HUGEPAGE);
#endif
	}
#endif
	if (cache->arena == MAP_FAILED)
		goto out;
	if (name != NULL)
		vma_set_name(cache->arena, total_size, "cache_storage", name);

	/* Allocate segment descriptors and initialize them and the free-list. */
	cache->segments = calloc(cache->n_segs, sizeof(struct seg));
	if (cache->segments == NULL)
		goto out;
	for (seg_id = 0; seg_id < cache->n_segs; seg_id++) {
		seg = &cache->segments[seg_id];
		if (seg_id == cache->n_segs - 1)
			seg->next_chain_id = CACHE_SEG_NONE;
		else
			seg->next_chain_id = seg_id + 1;
		seg->state_gen = SEG_STATE_MAKE(0, SEG_S_FREE);
	}
	cache->free_seg_id = 0;
	cache->n_free = cache->n_segs;
	HA_SPIN_INIT(&cache->pool_lock);

	/* Allocate and initialize the TTL buckets. */
	cache->ttl_buckets = calloc(CACHE_TTL_N_BUCKETS, sizeof(struct ttl_bucket));
	if (cache->ttl_buckets == NULL)
		goto out;
	for (i = 0; i < CACHE_TTL_N_BUCKETS; i++) {
		struct ttl_bucket *ttlb = &cache->ttl_buckets[i];
		unsigned int grp = i >> CACHE_TTL_GROUP_BITS;
		unsigned int off = i & ((1 << CACHE_TTL_GROUP_BITS) - 1);

		ttlb->ttl_approx = off << (grp * CACHE_TTL_FACTOR_BITS);
		seg_list_init(&ttlb->segs);
		seg_list_init(&ttlb->prv_segs);
		ttlb->merge_next = CACHE_SEG_NONE;
		ttlb->prv_next = CACHE_SEG_NONE;
		HA_SPIN_INIT(&ttlb->lock);
	}

	return cache;

out:
	cache_destroy(cache);
	return NULL;
}

void cache_expire(struct cache *cache)
{
	struct ttl_bucket *ttlb;
	int i;

	for (i = 0; i < CACHE_TTL_N_BUCKETS; i++) {
		ttlb = &cache->ttl_buckets[i];

		HA_SPIN_LOCK(CACHE_TTLB_LOCK, &ttlb->lock);
		seg_list_expire(cache, ttlb, &ttlb->prv_segs, NULL);
		seg_list_expire(cache, ttlb, &ttlb->segs, NULL);
		HA_SPIN_UNLOCK(CACHE_TTLB_LOCK, &ttlb->lock);
	}
}

/* Evict segment <seg_id> of list <l> of bucket <ttlb> whole and account for
 * it: segments that reached the free pool are added to <freed>. The caller
 * holds the bucket's lock, which is dropped while the victim is unindexed and
 * held again on return. Returns the status of the reclaim pass. Unlike a
 * merge, this does not consult seg_evictable(): it is the fallback when merging
 * cannot run.
 */
static enum cache_reclaim_status seg_evict(struct cache *cache, struct ttl_bucket *ttlb,
                                           struct seg_list *l, seg_id_t seg_id,
                                           struct cache_reclaim_ctx *rc)
{
	enum seg_reclaim_status status;
	uint32_t n_segs;

	if (!seg_unlink(cache, l, seg_id, &n_segs)) {
		_HA_ATOMIC_INC(&cache->stats.reclaim_blocked);
		return CACHE_RECLAIM_RETRY;
	}
	HA_SPIN_UNLOCK(CACHE_TTLB_LOCK, &ttlb->lock);
	cache_reclaim_unit(rc, seg_unindex(cache, &cache->segments[seg_id]));
	status = seg_drain(cache, seg_id);
	HA_SPIN_LOCK(CACHE_TTLB_LOCK, &ttlb->lock);

	_HA_ATOMIC_ADD(&cache->stats.segs_evicted, n_segs);
	if (status == SEG_RECLAIM_FREED) {
		rc->freed += n_segs;
		return CACHE_RECLAIM_PROGRESS;
	}
	return CACHE_RECLAIM_RETRY;
}

/* Bound descriptor searching separately from the physical record walk of the
 * one FIFO victim. A merge can protect eight sources; 64 examinations leave
 * room for claims and writer pins without an unbounded list scan.
 */
#define CACHE_FIFO_SCAN_MAX 64

/* Tell whether segment <seg> can be evicted whole: not claimed by a merge, not
 * being written, and still live. The caller holds its TTL lock.
 */
static inline int seg_fifo_safe(struct seg *seg)
{
	return !seg->merge_claimed && !HA_ATOMIC_LOAD(&seg->w_refcount) &&
	       SEG_STATE(_HA_ATOMIC_LOAD(&seg->state_gen)) == SEG_S_LIVE;
}

/* Find the first safe victim in list order from <id>. The caller holds its TTL
 * lock. Do not mistake a claimed or writer-pinned head for an empty victim set.
 */
static seg_id_t seg_fifo_find(struct cache *cache, seg_id_t id)
{
	seg_id_t found = CACHE_SEG_NONE;
	unsigned int steps = 0;

	while (id != CACHE_SEG_NONE && steps < CACHE_FIFO_SCAN_MAX) {
		struct seg *seg = &cache->segments[id];

		steps++;
		if (seg_fifo_safe(seg)) {
			found = id;
			break;
		}
		id = seg->next_seg_id;
	}
	return found;
}

/* At most this many private chains are spared by one eviction. */
#define CACHE_PRV_SPARE_MAX 8

/* Return the index slot of the record held by private chain <seg_id>, with its
 * value in <slot>, or NULL if that record is no longer indexed.
 */
static uint64_t *seg_chain_slot(const struct cache *cache, seg_id_t seg_id, uint64_t *slot)
{
	const struct cache_record *rec;
	struct ht_iter it;
	uint64_t *slotp;

	rec = (const struct cache_record *)((char *)cache->arena +
	                                    CACHE_ARENA_OFF(cache, seg_id, 0));
	ht_iter_init(&it, cache);
	while ((slotp = ht_iter_next_tag(&it, &rec->hash, slot)) != NULL) {
		if (CACHE_SLOT_SEG(*slot) == seg_id && CACHE_SLOT_OFF(*slot) == 0)
			return slotp;
	}
	return NULL;
}

/* The chain an eviction in <l>, the private list of <ttlb>, examines first: the
 * first safe one from the bucket's resume point, else from the head. The caller
 * holds the bucket's lock.
 */
static seg_id_t seg_prv_candidate(struct cache *cache, struct ttl_bucket *ttlb,
                                  struct seg_list *l)
{
	seg_id_t id;

	id = seg_cursor(cache, &ttlb->prv_next, ttlb->prv_next_gen);
	id = seg_fifo_find(cache, id);
	if (id == CACHE_SEG_NONE)
		id = seg_fifo_find(cache, seg_list_first(l));
	return id;
}

/* Choose the victim of an eviction in <l>, the private list of <ttlb>, whose
 * lock the caller holds. Chains are examined from seg_prv_candidate() on,
 * wrapping to the head, each costing <rc> one record. The first chain not hit
 * since it was last examined is the victim. A chain that was hit is spared: its
 * counter restarts and it stays in place. After CACHE_PRV_SPARE_MAX spared
 * chains, or when all were hit, the least-hit one is the victim.
 */
static seg_id_t seg_prv_victim(struct cache *cache, struct ttl_bucket *ttlb,
                               struct seg_list *l, struct cache_reclaim_ctx *rc)
{
	seg_id_t id, next, first, least = CACHE_SEG_NONE;
	unsigned int spared = 0, steps = 0, hits, least_hits = UINT_MAX;
	uint64_t *slotp, slot;

	id = first = seg_prv_candidate(cache, ttlb, l);
	while (id != CACHE_SEG_NONE && steps < CACHE_FIFO_SCAN_MAX) {
		struct seg *seg = &cache->segments[id];

		steps++;
		next = seg->next_seg_id;
		if (next == CACHE_SEG_NONE)
			next = seg_list_first(l);
		if (!seg_fifo_safe(seg)) {
			id = next;
			if (id == first)
				break;
			continue;
		}

		rc->spent++;
		hits = 0;
		slotp = seg_chain_slot(cache, id, &slot);
		if (slotp)
			hits = CACHE_SLOT_FREQ(slot);
		if (!hits) {
			if (next == id)
				next = CACHE_SEG_NONE;
			seg_cursor_set(cache, &ttlb->prv_next, &ttlb->prv_next_gen, next);
			return id;
		}

		if (hits < least_hits) {
			least_hits = hits;
			least = id;
		}
		/* A lost race with a hit is harmless: the counter is approximate. */
		HA_ATOMIC_CAS(slotp, &slot, slot & ~CACHE_SLOT_FREQ_MASK);
		seg_cursor_set(cache, &ttlb->prv_next, &ttlb->prv_next_gen, next);
		if (++spared == CACHE_PRV_SPARE_MAX)
			break;
		id = next;
		if (id == first)
			break;
	}
	return least;
}

/* A shared list's retention time is divided by this before lists are compared,
 * so shared lists keep their content that many times longer than private ones.
 * Shared lists hold the objects that fit in a segment, private lists the larger
 * ones. A larger value moves memory to small objects, which raises the hit
 * ratio and can lower the byte hit ratio. A smaller value does the opposite. At
 * 1, small and large objects are kept equally long.
 */
#define CACHE_SHARED_AGE_DIV 2

/* Return what <l> competes with when a list is elected for eviction, the
 * largest winning: the list's retention time in seconds. That is how long a
 * segment stays in <l> on average: the segments held divided by those appended
 * per second. Unlike the age of the head, it does not depend on which segments
 * a merge retains or an eviction spares. <shared> tells a shared list from a
 * private one. Without a measurable rate, the age of candidate <seg> stands
 * in. The caller holds the lock of the list's bucket.
 */
static double seg_list_elect_age(struct seg_list *l, int shared, const struct seg *seg)
{
	double age;

	seg_list_rate_update(l);
	if (l->rate < 1e-9)
		return (int64_t)date.tv_sec - seg->create_ts;

	age = l->n_segs / l->rate;
	l->rate_period = MIN(MAX(age, 1.0), (double)CACHE_RATE_PERIOD_MAX);
	if (shared)
		age /= CACHE_SHARED_AGE_DIV;
	return age;
}

/* Report whether an arena merger is about to return space to the shared pool.
 * This is a snapshot, not a wait condition. PROGRESS means space appeared;
 * MERGING asks the caller to try one more reservation before the store is
 * declined; RETRY means no merger is active, so the caller may fall back to
 * whole-segment FIFO.
 */
static enum cache_reclaim_status cache_merge_pending(struct cache *cache,
                                                    const struct cache_reclaim_ctx *rc)
{
	if (cache_pool_covers(cache, rc))
		return CACHE_RECLAIM_PROGRESS;
	if (!_HA_ATOMIC_LOAD(&cache->merges_inflight))
		return CACHE_RECLAIM_RETRY;
	return CACHE_RECLAIM_MERGING;
}

/* Evict one whole segment from <l>, a list of bucket <ttlb>, the fallback when
 * that bucket cannot merge. The index clearing runs without the bucket lock,
 * once the victim is unlinked. Pool supply is rechecked first because another
 * bucket's merger may have refilled it, and a merger about to return space
 * defers to the caller rather than discarding a live segment, unless the victim
 * is about to expire: it could not be merged and has little left to give.
 * Finding no safe victim within the descriptor bound fails the pass rather
 * than waiting for the merger.
 */
static enum cache_reclaim_status ttl_bucket_evict(struct cache *cache,
                                                 struct ttl_bucket *ttlb,
                                                 struct seg_list *l,
                                                 struct cache_reclaim_ctx *rc)
{
	seg_id_t id;
	enum cache_reclaim_status status;

	status = cache_merge_pending(cache, rc);
	if (status == CACHE_RECLAIM_PROGRESS)
		return status;
	if (l == &ttlb->prv_segs)
		id = seg_prv_victim(cache, ttlb, l, rc);
	else
		id = seg_fifo_find(cache, seg_list_first(l));
	if (id == CACHE_SEG_NONE) {
		if (status == CACHE_RECLAIM_MERGING)
			return status;
		return rc->freed ? CACHE_RECLAIM_PROGRESS : CACHE_RECLAIM_RETRY;
	}
	if (status == CACHE_RECLAIM_MERGING &&
	    !seg_expiring(ttlb, &cache->segments[id]))
		return status;
	_HA_ATOMIC_INC(&cache->stats.fifo_fallbacks);
	return seg_evict(cache, ttlb, l, id, rc);
}

/* Merge-based eviction in the shared list of <ttlb>, whose lock the caller
 * holds. Descriptor claims protect one active merger per bucket without a
 * second lock. Different buckets may merge concurrently. The bucket lock is
 * dropped during bulk work and reacquired before returning. Segments that
 * reached the free pool are added to <rc>'s count. Returns the status of the
 * reclaim pass.
 *
 * Expire first within the caller's reclaim budget. Otherwise a sequence of
 * evictable segments is searched from the bucket's cursor, then from its head,
 * and merged into a destination taken from the reserve, which takes the
 * sequence's place in the list; the consumed sources are drained. A merge that
 * retained nothing returns its destination to the pool, and once such merges
 * outnumber the successful ones, later merges start out copying every live
 * record. Without a run or destination, use safe FIFO only if no arena merger
 * is active or the victim is about to expire; otherwise decline the store
 * after a final retry of the reservation.
 */
static enum cache_reclaim_status ttl_bucket_merge(struct cache *cache,
                                                  struct ttl_bucket *ttlb,
                                                  struct cache_reclaim_ctx *rc)
{
	struct seg_list *l = &ttlb->segs;
	seg_id_t srcs[CACHE_MERGE_MAX];
	struct seg_merge_res res;
	seg_id_t head_id, dst_id, seg_id;
	uint64_t empty, success;
	unsigned int n, i, dead = 0;
	int supply;

	seg_list_expire(cache, ttlb, l, rc);
	if (rc->freed >= rc->shortfall)
		return CACHE_RECLAIM_PROGRESS;
	if (seg_list_first(l) == CACHE_SEG_NONE || !cache_reclaim_may_act(rc))
		return CACHE_RECLAIM_RETRY;
	if (cache_pool_covers(cache, rc))
		return CACHE_RECLAIM_PROGRESS;
	/* A TTL within the expiry guard leaves no segment evictable. */
	if (ttlb->merges_inflight || ttlb->ttl_approx <= CACHE_MERGE_EXPIRY_GUARD)
		return ttl_bucket_evict(cache, ttlb, l, rc);

	/* Split the budget between cursor and head, finishing runs across the
	 * cursor. Without a distinct cursor, search only from the head.
	 */
	seg_id = seg_cursor(cache, &ttlb->merge_next, ttlb->merge_next_gen);
	if (seg_id != CACHE_SEG_NONE && seg_id != seg_list_first(l)) {
		head_id = seg_merge_find(cache, ttlb, seg_id, CACHE_SEG_NONE,
		                         CACHE_MERGE_SCAN_MAX / 2);
		if (head_id == CACHE_SEG_NONE)
			head_id = seg_merge_find(cache, ttlb,
			                         seg_list_first(l), seg_id,
			                         CACHE_MERGE_SCAN_MAX / 2);
	}
	else
		head_id = seg_merge_find(cache, ttlb, seg_list_first(l),
		                         CACHE_SEG_NONE, CACHE_MERGE_SCAN_MAX);
	if (head_id == CACHE_SEG_NONE) {
		seg_cursor_set(cache, &ttlb->merge_next, &ttlb->merge_next_gen,
		               CACHE_SEG_NONE);
		return ttl_bucket_evict(cache, ttlb, l, rc);
	}

	if (cache_pool_covers(cache, rc))
		return CACHE_RECLAIM_PROGRESS;
	dst_id = seg_free_pop(cache, 1, 1);
	if (dst_id == CACHE_SEG_NONE) {
		_HA_ATOMIC_INC(&cache->stats.merges_no_dst);
		return ttl_bucket_evict(cache, ttlb, l, rc);
	}
	HA_ATOMIC_UPDATE_MAX(&cache->stats.merges_inflight_max,
	                     _HA_ATOMIC_ADD_FETCH(&cache->merges_inflight, 1));
	seg_reinit(&cache->segments[dst_id]);

	n = seg_merge_claim(cache, ttlb, head_id, srcs);
	empty = _HA_ATOMIC_LOAD(&cache->merge_empty);
	success = _HA_ATOMIC_LOAD(&cache->merge_success);
	ttlb->merges_inflight = 1;
	cache->segments[dst_id].merge_claimed = 1;
	HA_SPIN_UNLOCK(CACHE_TTLB_LOCK, &ttlb->lock);
	seg_merge(cache, dst_id, srcs, n, empty > 2 && empty > success, &res);
	cache_reclaim_unit(rc, res.records);
	HA_SPIN_LOCK(CACHE_TTLB_LOCK, &ttlb->lock);

	/* A purge may have emptied an unused source or the destination, and its eager
	 * cleanup was deferred by our claim. Unindex those outside the bucket lock
	 * too. With no writers or further destination copies, each candidate can
	 * become empty only once: at most n + 1 passes. A purge that has not yet
	 * checked the claim under this lock will perform its normal cleanup after we
	 * release it.
	 */
	{
		unsigned int pending;

		do {
			pending = 0;
			for (i = res.merged; i < n; i++)
				if (!(dead & (1U << i)) &&
				    HA_ATOMIC_LOAD(&cache->segments[srcs[i]].n_live) == 0)
					pending |= 1U << i;
			if (res.copied && !(dead & (1U << n)) &&
			    HA_ATOMIC_LOAD(&cache->segments[dst_id].n_live) == 0)
				pending |= 1U << n;
			if (!pending)
				break;
			HA_SPIN_UNLOCK(CACHE_TTLB_LOCK, &ttlb->lock);
			for (i = res.merged; i <= n; i++)
				if (pending & (1U << i))
					seg_unindex(cache, &cache->segments[i == n ? dst_id : srcs[i]]);
			HA_SPIN_LOCK(CACHE_TTLB_LOCK, &ttlb->lock);
			dead |= pending;
		} while (1);
	}

	/* Unclaimed neighbours may have disappeared, and reservations may have
	 * appended a tail. Read current boundary links only after locking. Release
	 * unused claims too; their contents were never modified.
	 */
	seg_id = cache->segments[srcs[res.merged - 1]].next_seg_id;
	for (i = 0; i < n; i++)
		cache->segments[srcs[i]].merge_claimed = 0;
	cache->segments[dst_id].merge_claimed = 0;

	if (res.copied > 0) {
		seg_list_splice(cache, l, head_id, srcs[res.merged - 1], dst_id);
		_HA_ATOMIC_INC(&cache->merge_success);
		supply = -1;
	}
	else {
		seg_list_splice(cache, l, head_id, srcs[res.merged - 1], CACHE_SEG_NONE);
		seg_free_push(cache, dst_id);
		_HA_ATOMIC_INC(&cache->merge_empty);
		supply = 0;
	}
	seg_cursor_set(cache, &ttlb->merge_next, &ttlb->merge_next_gen, seg_id);

	for (i = 0; i < res.merged; i++) {
		if (seg_drain(cache, srcs[i]) == SEG_RECLAIM_FREED)
			supply++;
	}
	/* The empty claims were already unindexed above, so only short list changes
	 * and the normal reader-drain handoff remain under the lock.
	 */
	for (i = res.merged; i <= n; i++) {
		if (dead & (1U << i)) {
			seg_id_t id = i == n ? dst_id : srcs[i];

			seg_list_splice(cache, l, id, id, CACHE_SEG_NONE);
			if (seg_drain(cache, id) == SEG_RECLAIM_FREED)
				supply++;
			_HA_ATOMIC_INC(&cache->stats.segs_emptied);
		}
	}
	BUG_ON_HOT(ttlb->merges_inflight != 1);
	ttlb->merges_inflight = 0;
	_HA_ATOMIC_DEC(&cache->merges_inflight);
	_HA_ATOMIC_ADD(&cache->stats.segs_evicted, res.merged);

	/* The destination came out of the pool: only what the sources put back
	 * beyond it is supply the caller can pop, and with none put back the
	 * pool is one short of what the scan's expiries counted.
	 */
	if (supply <= 0) {
		if (supply < 0 && rc->freed > 0)
			rc->freed--;
		return CACHE_RECLAIM_RETRY;
	}
	rc->freed += supply;
	return CACHE_RECLAIM_PROGRESS;
}

/* Attempt to reclaim a segment for a new reservation. We always attempt to
 * reclaim an expired segment before evicting a live one.
 *
 * The scan locks each non-empty TTL bucket and may repeat after a
 * write-pinned victim. The expiration record budget does not bound bucket
 * scans, skipped writer pins or time spent waiting for locks.
 *
 * <rc>'s shortfall is the number of segments the caller is waiting for:
 * expired segments freed during the scan count towards it. Expiration
 * continues past it while <rc>'s budget lasts. At most one eviction or merge
 * runs per call, and only within the budget unless it is the reservation's
 * first unit. Once the victim is locked, a pool that can already serve <rc>'s
 * reservation ends the pass. The number of segments that measurably reached
 * the free pool is returned in <rc>'s freed count; it can exceed the shortfall
 * since segments are freed whole chains at a time.
 *
 * If we observed no in-use segment, return CACHE_RECLAIM_GIVEUP. This should
 * hardly ever happen in practice. If a segment actually reached the free
 * pool - we freed one, or another thread demonstrably made some progress - we
 * return CACHE_RECLAIM_PROGRESS to let the caller know that retrying the
 * reservation can succeed. A segment we could only condemn (removed, but its
 * free-list push deferred to its last reader) is not supply; when nothing at
 * all reached the free pool, the call counts as CACHE_RECLAIM_RETRY, exactly
 * like victims blocked by write pins.
 */
static enum cache_reclaim_status cache_reclaim(struct cache *cache,
                                               struct cache_reclaim_ctx *rc)
{
	struct ttl_bucket *ttlb, *best;
	struct seg_list *best_list;
	struct seg *seg;
	enum cache_reclaim_status status;
	double longest, age;
	seg_id_t seg_id;
	uint32_t scan_off;
	unsigned int locked = 0;
	int i, j, seen;

	/* Every pass is charged a scan, even one finding the pool covered:
	 * another reservation then takes the space first, and retrying is not
	 * free either.
	 */
	rc->freed = 0;
	rc->spent += CACHE_SCAN_COST;
	_HA_ATOMIC_INC(&cache->stats.reclaim_calls);
	if (!rc->shortfall)
		return CACHE_RECLAIM_PROGRESS;

	/* Locate the list that keeps its segments longest. While here, see if
	 * any segments can be expired.
	 */
	longest = 0;
	best = NULL;
	best_list = NULL;		/* Quiet GCC */
	seen = 0;

	/* Start the scan at a random offset. This is mostly useful when
	 * several lists are tied. Concurrent reclaimers then elect
	 * different victims instead of all racing for the first-scanned
	 * one.
	 */
	scan_off = statistical_prng() & (CACHE_TTL_N_BUCKETS - 1);
	for (i = ttl_used_first(cache, scan_off, 0); i < CACHE_TTL_N_BUCKETS;
	     i = ttl_used_first(cache, scan_off, i + 1)) {
		struct seg_list *lists[2];

		ttlb = &cache->ttl_buckets[(scan_off + i) & (CACHE_TTL_N_BUCKETS - 1)];
		lists[0] = &ttlb->prv_segs;
		lists[1] = &ttlb->segs;

		seen = 1;
		if (++locked % CACHE_SCAN_LOCKED_PER_REC == 0)
			rc->spent++;
		HA_SPIN_LOCK(CACHE_TTLB_LOCK, &ttlb->lock);
		for (j = 0; j < 2; j++) {
			seg_id = seg_list_first(lists[j]);
			if (seg_id == CACHE_SEG_NONE)
				continue;

			seg_list_expire(cache, ttlb, lists[j], rc);
			if (rc->freed >= rc->shortfall && !cache_expire_more(rc)) {
				HA_SPIN_UNLOCK(CACHE_TTLB_LOCK, &ttlb->lock);
				return CACHE_RECLAIM_PROGRESS;
			}

			/* Read the head again after expiration. */
			if (cache->flags & CACHE_F_NO_MERGE)
				seg_id = seg_list_first(lists[j]);
			else if (lists[j] == &ttlb->prv_segs)
				seg_id = seg_prv_candidate(cache, ttlb, lists[j]);
			else
				seg_id = seg_fifo_find(cache, seg_list_first(lists[j]));

			/* The head is fresh, or expired but writer-pinned:
			 * evaluate it as an eviction candidate below (a
			 * pinned one fails the check, which is the point).
			 */
			if (seg_id != CACHE_SEG_NONE) {
				seg = &cache->segments[seg_id];
				age = seg_list_elect_age(lists[j], j == 1, seg);
				if (_HA_ATOMIC_LOAD(&seg->w_refcount) == 0 &&
				    (best == NULL || age > longest)) {
					longest = age;
					best_list = lists[j];
					best = ttlb;
				}
			}
		}
		HA_SPIN_UNLOCK(CACHE_TTLB_LOCK, &ttlb->lock);
	}

	/* Other reclaimers may have supplied the pool during this scan. */
	if (rc->freed >= rc->shortfall || cache_pool_covers(cache, rc))
		return CACHE_RECLAIM_PROGRESS;

	/* We did not see a single segment in use, or all of them were pinned
	 * for writes. In the former case, we need to give up. This should not
	 * really happen in practice unless this thread has been stuck for a
	 * very long time or this function was called at an inappropriate time.
	 * A scan that freed some expired segments reports progress, even short
	 * of the need.
	 */
	if (best == NULL) {
		if (rc->freed > 0)
			return CACHE_RECLAIM_PROGRESS;
		if (!(cache->flags & CACHE_F_NO_MERGE)) {
			status = cache_merge_pending(cache, rc);
			if (status != CACHE_RECLAIM_RETRY)
				return status;
		}
		if (seen) {
			_HA_ATOMIC_INC(&cache->stats.reclaim_no_candidate);
			return CACHE_RECLAIM_RETRY;
		}
		return CACHE_RECLAIM_GIVEUP;
	}

	/* The budget allows no other unit: what expiration freed is all. */
	if (!cache_reclaim_may_act(rc)) {
		if (rc->freed > 0)
			return CACHE_RECLAIM_PROGRESS;
		return CACHE_RECLAIM_RETRY;
	}

	/* Expiration did not cover the need: merge or evict in the elected bucket
	 * rather than throw away the scan we paid for: claim the bucket, use
	 * safe FIFO, or decline admission while another merger is producing
	 * supply.
	 */

	HA_SPIN_LOCK(CACHE_TTLB_LOCK, &best->lock);

	/* Another reclaimer may have refilled the pool since the election. */
	if (cache_pool_covers(cache, rc)) {
		HA_SPIN_UNLOCK(CACHE_TTLB_LOCK, &best->lock);

		return CACHE_RECLAIM_PROGRESS;
	}

	if (best_list == &best->segs && !(cache->flags & CACHE_F_NO_MERGE))
		status = ttl_bucket_merge(cache, best, rc);
	else if (!(cache->flags & CACHE_F_NO_MERGE))
		status = ttl_bucket_evict(cache, best, best_list, rc);
	else {
		/* Without merging, the victim is the head of the list. Other
		 * reclaimers may have emptied the list since the election.
		 */
		seg_id = seg_list_first(best_list);
		if (seg_id == CACHE_SEG_NONE)
			status = CACHE_RECLAIM_PROGRESS;
		else
			status = seg_evict(cache, best, best_list, seg_id, rc);
	}
	HA_SPIN_UNLOCK(CACHE_TTLB_LOCK, &best->lock);

	if (status == CACHE_RECLAIM_PROGRESS || status == CACHE_RECLAIM_MERGING)
		return status;

	/* The victims were only condemned (their free deferred to their last
	 * reader) or blocked by a writer - not supply. Expired segments
	 * freed during the scan still are.
	 */
	if (rc->freed > 0)
		return CACHE_RECLAIM_PROGRESS;
	return CACHE_RECLAIM_RETRY;
}

/* Reclaim after a failed reservation. A MERGING last pass means the caller
 * just retried the reservation before refusal. Return GIVEUP on refusal or a
 * spent budget, otherwise the new result.
 */
static enum cache_reclaim_status cache_reclaim_try(struct cache *cache,
                                                  struct cache_reclaim_ctx *rc)
{
	enum cache_reclaim_status status;
	unsigned int n_free;

	if (rc->last == CACHE_RECLAIM_MERGING) {
		if (_HA_ATOMIC_LOAD(&cache->merges_inflight)) {
			_HA_ATOMIC_INC(&cache->stats.reserve_fail_merging);
			goto fail;
		}
	}
	if (rc->spent >= CACHE_RECLAIM_BUDGET) {
		_HA_ATOMIC_INC(&cache->stats.reserve_fail_budget);
		goto fail;
	}

	/* Only currently available supply reduces the shortfall: earlier
	 * frees may already have been consumed by another reservation.
	 */
	n_free = _HA_ATOMIC_LOAD(&cache->n_free);
	rc->shortfall = cache->cfg.n_reserved + rc->reserving;
	rc->shortfall = rc->shortfall > n_free ? rc->shortfall - n_free : 0;
	status = cache_reclaim(cache, rc);
	if (status == CACHE_RECLAIM_GIVEUP) {
		_HA_ATOMIC_INC(&cache->stats.reserve_fail_giveup);
		goto fail;
	}
	rc->last = status;
	return status;

fail:
	_HA_ATOMIC_INC(&cache->stats.reserve_fails);
	return CACHE_RECLAIM_GIVEUP;
}

/* Account for a reservation that succeeded after the passes of <rc>. */
static inline void cache_reclaim_done(struct cache *cache,
                                      const struct cache_reclaim_ctx *rc)
{
	if (rc->last == CACHE_RECLAIM_MERGING)
		_HA_ATOMIC_INC(&cache->stats.reserve_merging_rescued);
}

/* Move a finished unknown-length entry that fits in one segment, <h>, out of
 * its private segment and into the shared list of its TTL bucket. When the
 * record fits in the free space of the shared tail it is copied there and the
 * private segment goes back to the pool; otherwise the private segment itself
 * becomes the new tail, its free space open to the stores that follow, and the
 * old tail is closed as a rollover would close it. Neither case takes a segment
 * from the pool. Entries spanning several segments stay private, see
 * cache_publish_private(). Returns the handle to publish. A copied record's
 * private segment stays write-pinned: the caller frees it once the entry's slot
 * no longer names it.
 */
static struct cache_whandle seg_relocate(struct cache *cache, const struct cache_whandle *h)
{
	struct cache_record *rec = CACHE_HANDLE_REC(cache, h);
	struct seg *seg = &cache->segments[h->seg_id];
	struct ttl_bucket *ttlb = &cache->ttl_buckets[seg->ttl_bucket];
	size_t total_len = CACHE_OFF_ALIGN_UP(rec->rec_len);
	struct cache_whandle nh;
	seg_id_t tail_id;
	struct seg *tail;

	HA_SPIN_LOCK(CACHE_TTLB_LOCK, &ttlb->lock);
	tail_id = seg_list_last(&ttlb->segs);
	if (tail_id != CACHE_SEG_NONE) {
		tail = &cache->segments[tail_id];
		if (!tail->merge_claimed &&
		    tail->write_off + total_len <= cache->cfg.seg_size) {
			nh.seg_id = tail_id;
			nh.cur_seg_id = tail_id;
			nh.seg_off = tail->write_off;
			nh.data_off = h->data_off;
			tail->write_off += total_len;
			seg_write_pin(tail);
			HA_SPIN_UNLOCK(CACHE_TTLB_LOCK, &ttlb->lock);

			memcpy(CACHE_HANDLE_REC(cache, &nh), rec, rec->rec_len);
			return nh;
		}
	}

	seg->flags &= ~(SEG_F_PRIVATE | SEG_F_NO_LEN);
	seg_list_append(cache, &ttlb->segs, h->seg_id);
	if (tail_id != CACHE_SEG_NONE)
		seg_reclaim_dead(cache, ttlb, tail_id);
	HA_SPIN_UNLOCK(CACHE_TTLB_LOCK, &ttlb->lock);
	return *h;
}

void cache_hash(const struct cache *cache, const void *key, uint32_t key_len,
                struct cache_key *key_hash)
{
	key_hash->hash = XXH128(key, key_len, cache->seed);
}

/* Lookup a record in the cache. */
struct cache_rhandle cache_lookup(struct cache *cache, struct cache_key *k)
{
	struct ht_iter it;
	struct cache_rhandle h;
	struct cache_record *rec;
	uint64_t *slotp, slot, slot2;
	unsigned int count;

	ht_iter_init(&it, cache);
	while ((slotp = ht_iter_next_tag(&it, &k->hash, &slot)) != NULL) {
		h = seg_read_pin(cache, &k->hash, slotp, &slot, 1);
		if (CACHE_HANDLE_ERR(h))
			continue;

		/* Freshness: an entry at or past its expiry is a miss. Physical
		 * removal is left to the expiration/reclaim path; we just don't
		 * serve it.
		 */
		rec = CACHE_HANDLE_REC(cache, &h);
		if (date.tv_sec >= rec->expire) {
			seg_read_unpin(cache, &cache->segments[h.seg_id]);
			/* Keep scanning: a fresher copy of this key may sit
			 * in a later slot (duplicates are possible when two
			 * first-time stores of the same key race), and an
			 * expired copy must not shadow it.
			 */
			continue;
		}

		/* Bump the frequency counter: exactly up to 16, then with
		 * probability 1/count so hot entries stop rewriting their
		 * slot. A lost CAS is not retried; the counter is approximate.
		 */
		count = CACHE_SLOT_FREQ(slot);
		if (count < CACHE_SLOT_FREQ_MAX &&
		    (count <= 16 || statistical_prng() % count == 0)) {
			slot2 = (slot & ~CACHE_SLOT_FREQ_MASK) |
			        ((uint64_t)(count + 1) << CACHE_SLOT_FREQ_SHIFT);
			HA_ATOMIC_CAS(slotp, &slot, slot2);
		}

		return h;
	}

	return CACHE_RHANDLE_NULL;
}

/* Copy <len> bytes out of an entry, starting at offset <off> within segment
 * <*seg_id> and following the chain across segment boundaries. <len> must
 * already be clamped to the entry's remaining capacity. <*seg_id> is updated
 * eagerly past every exhausted segment, so on return it names the segment
 * holding the byte after the last one copied (possibly CACHE_SEG_NONE when
 * the entry ends exactly on a segment boundary).
 */
static void cache_copyout(const struct cache *cache, seg_id_t *seg_id,
                           uint32_t off, void *buf, size_t len)
{
	uint32_t max;
	char *data;

	while (len > 0) {
		BUG_ON(*seg_id == CACHE_SEG_NONE);

		max = MIN(cache->cfg.seg_size - off, len);
		data = (char *)cache->arena + CACHE_ARENA_OFF(cache, *seg_id, off);
		memcpy(buf, data, max);
		buf = (char *)buf + max;
		len -= max;

		if (off + max == cache->cfg.seg_size) {
			*seg_id = cache->segments[*seg_id].next_chain_id;
			off = 0;
		}
	}
}

size_t cache_read(const struct cache *cache, struct cache_rhandle *h, void *buf, size_t size)
{
	struct cache_record *rec;
	size_t n_read, off;

	BUG_ON_BAD_HANDLE(cache, h);

	rec = CACHE_HANDLE_REC(cache, h);

	n_read = MIN(CACHE_REC_CAPACITY(rec) - h->data_off, size);
	off = seg_data_off(cache, h->seg_off, h->data_off, NULL);
	cache_copyout(cache, &h->cur_seg_id, off, buf, n_read);
	h->data_off += n_read;

	return n_read;
}

size_t cache_read_at(const struct cache *cache, const struct cache_rhandle *h,
                     size_t off, void *buf, size_t size)
{
	struct cache_record *rec;
	unsigned int seg_idx;
	seg_id_t seg_id;
	uint32_t seg_off;
	size_t n_read;

	BUG_ON_BAD_HANDLE(cache, h);

	rec = CACHE_HANDLE_REC(cache, h);
	if (off >= CACHE_REC_CAPACITY(rec))
		return 0;

	n_read = MIN(CACHE_REC_CAPACITY(rec) - off, size);
	seg_off = seg_data_off(cache, h->seg_off, off, &seg_idx);
	seg_id = seg_chain_nth(cache, h->seg_id, seg_idx);
	cache_copyout(cache, &seg_id, seg_off, buf, n_read);

	return n_read;
}

size_t cache_seek(const struct cache *cache, struct cache_rhandle *h,
                  ssize_t off, int whence)
{
	struct cache_record *rec;
	unsigned int old_idx, new_idx;
	seg_id_t seg_id;
	ssize_t base, cap;

	BUG_ON_BAD_HANDLE(cache, h);

	rec = CACHE_HANDLE_REC(cache, h);
	cap = CACHE_REC_CAPACITY(rec);
	switch (whence) {
	case SEEK_SET:
		base = 0;
		break;
	case SEEK_CUR:
		base = h->data_off;
		break;
	case SEEK_END:
		base = cap;
		break;
	default:
		return h->data_off;
	}

	BUG_ON(off < -base || off > cap - base);

	/* Bring cur_seg_id along. It always designates the segment holding
	 * data_off (readers and writers move it whenever they cross a segment
	 * boundary), so a seek within the current segment costs nothing and a
	 * forward seek only walks the difference; only a backward seek across
	 * a segment boundary has to restart from the first segment.
	 */
	seg_data_off(cache, h->seg_off, h->data_off, &old_idx);
	h->data_off = base + off;
	seg_data_off(cache, h->seg_off, h->data_off, &new_idx);

	if (new_idx >= old_idx) {
		seg_id = h->cur_seg_id;
		new_idx -= old_idx;
	} else {
		seg_id = h->seg_id;
	}
	h->cur_seg_id = seg_chain_nth(cache, seg_id, new_idx);

	return h->data_off;
}

const void *cache_peek_at(const struct cache *cache, const struct cache_rhandle *h,
                          size_t off, size_t *len)
{
	struct cache_record *rec;
	unsigned int seg_idx;
	seg_id_t seg_id;
	uint32_t seg_off;

	BUG_ON_BAD_HANDLE(cache, h);

	rec = CACHE_HANDLE_REC(cache, h);
	if (off >= CACHE_REC_CAPACITY(rec)) {
		*len = 0;
		return NULL;
	}

	seg_off = seg_data_off(cache, h->seg_off, off, &seg_idx);
	seg_id = seg_chain_nth(cache, h->seg_id, seg_idx);

	/* The run is contiguous only to the end of the current segment. */
	*len = MIN(CACHE_REC_CAPACITY(rec) - off,
	           (size_t)(cache->cfg.seg_size - seg_off));
	return (char *)cache->arena + CACHE_ARENA_OFF(cache, seg_id, seg_off);
}

/* This one doesn't call into cache_peek_at() to avoid walking the segment
 * chain with seg_chain_nth() when dealing with jumbo entries.
 */
const void *cache_peek(const struct cache *cache, const struct cache_rhandle *h,
                       size_t *len)
{
	struct cache_record *rec;
	uint32_t seg_off;

	BUG_ON_BAD_HANDLE(cache, h);

	rec = CACHE_HANDLE_REC(cache, h);
	if (h->data_off >= CACHE_REC_CAPACITY(rec)) {
		*len = 0;
		return NULL;
	}

	seg_off = seg_data_off(cache, h->seg_off, h->data_off, NULL);

	*len = MIN(CACHE_REC_CAPACITY(rec) - h->data_off,
	           (size_t)(cache->cfg.seg_size - seg_off));
	return (char *)cache->arena + CACHE_ARENA_OFF(cache, h->cur_seg_id, seg_off);
}

void cache_release(struct cache *cache, const struct cache_rhandle *h)
{
	BUG_ON_BAD_HANDLE(cache, h);

	seg_read_unpin(cache, &cache->segments[h->seg_id]);
}

void cache_delete(struct cache *cache, const struct cache_key *key)
{
	struct ht_iter it;
	struct cache_rhandle h;
	uint64_t *slotp, slot;
	int removed;

	ht_iter_init(&it, cache);
	while ((slotp = ht_iter_next_tag(&it, &key->hash, &slot)) != NULL) {
		/* A slot that changed under us to another location of the same
		 * key was moved by a merge or superseded by a concurrent store:
		 * pin the new location and purge it too. Stop on an emptied slot
		 * or another key.
		 */
		do {
			h = seg_read_pin(cache, &key->hash, slotp, &slot, 0);
			if (CACHE_HANDLE_ERR(h))
				break;

			/* Retry a CAS lost to a counter bump; stop if the slot
			 * no longer names this record.
			 */
			while (!(removed = HA_ATOMIC_CAS(slotp, &slot, 0))) {
				if (slot == 0 ||
				    CACHE_SLOT_SEG(slot) != h.seg_id ||
				    CACHE_SLOT_OFF(slot) != h.seg_off)
					break;
				__ha_cpu_relax();
			}
			if (removed && !(cache->segments[h.seg_id].flags & SEG_F_PRIVATE)) {
				struct seg *seg = &cache->segments[h.seg_id];
				unsigned int ttl_bucket = seg->ttl_bucket;
				uint32_t state_gen = _HA_ATOMIC_LOAD(&seg->state_gen);

				seg_live_sub(seg, CACHE_HANDLE_REC(cache, &h));
				seg_read_unpin(cache, seg);
				seg_check_dead(cache, h.seg_id, ttl_bucket, state_gen);
			}
			else
				seg_read_unpin(cache, &cache->segments[h.seg_id]);
		} while (!removed && slot != 0 && !(slot & CACHE_SLOT_PENDING) &&
		         CACHE_SLOT_TAG(slot) == CACHE_HASH_TAG(key->hash));

		/* Keep scanning: racing first-time stores of the same key can
		 * leave more than one live slot for it, and a purge must be
		 * deterministic - remove every copy.
		 */
	}
}

/* Give up on the entry being written at <h>, after clearing its pending slot
 * <slotp> if it has one. A private chain has no reader and sits in no list yet:
 * it goes straight back to the pool. Bytes reserved in a shared segment lie
 * dead until it is reclaimed.
 */
static void cache_drop(struct cache *cache, const struct cache_whandle *h,
                       uint64_t *slotp)
{
	struct seg *seg = &cache->segments[h->seg_id];
	unsigned int ttl_bucket;
	uint32_t state_gen;

	if (slotp != NULL)
		HA_ATOMIC_STORE(slotp, 0);

	if (seg->flags & SEG_F_PRIVATE) {
		seg_write_unpin(seg);
		seg_free_push(cache, h->seg_id);
		return;
	}

	_HA_ATOMIC_ADD(&cache->stats.dead_bytes_cum,
	               CACHE_OFF_ALIGN_UP(CACHE_HANDLE_REC(cache, h)->rec_len));
	ttl_bucket = seg->ttl_bucket;
	state_gen = _HA_ATOMIC_LOAD(&seg->state_gen);
	seg_write_unpin(seg);
	seg_check_dead(cache, h->seg_id, ttl_bucket, state_gen);
}

/* Make room for <len> more bytes at <h>, within the limits set on entries. A
 * private chain holds the record from the start of its first segment, and
 * grows when these bytes go past its end: an unknown-length record grows with
 * it, a known-length one already had its full length. The pool may supply the
 * missing segments in several steps: they join the chain once all are there.
 * Returns 0 on success, or -1 with the reservation unchanged.
 */
static int cache_make_room(struct cache *cache, struct cache_whandle *h, size_t len)
{
	struct cache_record *rec = CACHE_HANDLE_REC(cache, h);
	struct seg *head = &cache->segments[h->seg_id];
	struct seg *tail, *last;
	struct cache_reclaim_ctx rc;
	seg_id_t seg_id, first_id;
	unsigned int n_segs, n_left;
	size_t chain_cap;

	if (len > cache->arena_len - sizeof(*rec) ||
	    h->data_off > cache->arena_len - sizeof(*rec) - len)
		return -1;

	if (cache->cfg.max_obj_size > 0 &&
	    (len > cache->cfg.max_obj_size ||
	     h->data_off > cache->cfg.max_obj_size - len))
		return -1;

	if (len > CACHE_REC_CAPACITY(rec) - h->data_off &&
	    (cache->flags & CACHE_F_NO_JUMBO || !(head->flags & SEG_F_NO_LEN)))
		return -1;

	chain_cap = (size_t)head->n_chain * cache->cfg.seg_size - sizeof(*rec);
	if (!(head->flags & SEG_F_PRIVATE) || len <= chain_cap - h->data_off)
		return 0;

	/* Get the missing segments, evicting or expiring our way to them when
	 * the pool has none to supply, with the same accounting as
	 * cache_reserve(). Reclaim can never free the entry being grown: its
	 * head is write-pinned, so at worst it elects it and comes back
	 * empty-handed.
	 */
	n_segs = cache_seg_count(cache, len - (chain_cap - h->data_off));
	first_id = CACHE_SEG_NONE;
	last = NULL;
	n_left = n_segs;
	while (n_left > 0) {
		cache_reclaim_init(&rc, 1);
		while ((seg_id = seg_free_pop(cache, n_left, 0)) == CACHE_SEG_NONE) {
			if (cache_reclaim_try(cache, &rc) == CACHE_RECLAIM_GIVEUP) {
				if (first_id != CACHE_SEG_NONE)
					seg_free_push(cache, first_id);
				return -1;
			}
		}
		cache_reclaim_done(cache, &rc);
		if (last)
			last->next_chain_id = seg_id;
		else
			first_id = seg_id;

		/* Count each segment the pool supplied. */
		do {
			last = &cache->segments[seg_id];
			seg_id = last->next_chain_id;
			n_left--;
		} while (seg_id != CACHE_SEG_NONE);
	}

	/* If the last write completely filled the chain, h->cur_seg_id is
	 * CACHE_SEG_NONE, so we walk the chain to find back its last segment.
	 */
	if (h->cur_seg_id == CACHE_SEG_NONE) {
		seg_id = seg_chain_nth(cache, h->seg_id, head->n_chain - 1);
		h->cur_seg_id = first_id;
	} else
		seg_id = h->cur_seg_id;
	tail = &cache->segments[seg_id];

	/* This loop only iterates for a misbehaving writer: one that got room
	 * from cache_reserve_with() and did not write the bytes it announced
	 * before a larger write. Otherwise the segment being written is
	 * already the last one.
	 */
	while (tail->next_chain_id != CACHE_SEG_NONE)
		tail = &cache->segments[tail->next_chain_id];
	tail->next_chain_id = first_id;

	if (head->flags & SEG_F_NO_LEN)
		rec->rec_len += (size_t)n_segs * cache->cfg.seg_size;
	head->n_chain += n_segs;
	return 0;
}

struct cache_whandle cache_reserve_with(struct cache *cache, const struct cache_key *key,
                                        size_t data_len, size_t ready_len, time_t expire)
{
	struct cache_whandle h;
	struct cache_record *rec;
	struct cache_reclaim_ctx rc;
	struct ttl_bucket *ttlb;
	struct ht_iter it;
	uint64_t *slotp, slot;
	size_t total_len;
	unsigned int n_free;
	uint32_t ttl;

	if (expire <= date.tv_sec)
		return CACHE_WHANDLE_NULL;

	if (data_len == 0) {
		if (cache->flags & CACHE_F_REQUIRE_LEN)
			return CACHE_WHANDLE_NULL;
		data_len = cache->cfg.seg_size;
		total_len = 0;
	}
	else {
		if ((cache->flags & CACHE_F_NO_JUMBO) &&
		    data_len > cache->cfg.seg_size - sizeof(struct cache_record))
			return CACHE_WHANDLE_NULL;

		if (data_len > cache->arena_len - sizeof(struct cache_record) ||
		    (cache->cfg.max_obj_size > 0 && data_len > cache->cfg.max_obj_size))
			return CACHE_WHANDLE_NULL;

		/* Add enough bytes to store the metadata. */
		data_len += sizeof(struct cache_record);
		/* Reserve whole 8-byte units, since offsets are encoded in units of 8
		 * bytes. The record itself keeps its exact length, so readers get a
		 * byte-exact entry size rather than one rounded up to the reservation
		 * granularity. Safe to compute without overflow checks since the
		 * previous size checks make overflow impossible at this point.
		 */
		total_len = CACHE_OFF_ALIGN_UP(data_len);
	}

	/* Check the key's buckets before reserving anything: a store of the
	 * same key in flight makes this one redundant, and without a free
	 * slot the entry could not be indexed. A tag match is enough, a false
	 * one only skips a store. Both checks are racy: two stores of a key
	 * starting together may both proceed, and the insertion below decides
	 * whether a slot is left.
	 */
	n_free = 0;
	ht_iter_init(&it, cache);
	while ((slotp = ht_iter_next(&it, &key->hash)) != NULL) {
		slot = HA_ATOMIC_LOAD(slotp);
		if (slot == 0)
			n_free++;
		else if ((slot & CACHE_SLOT_PENDING) &&
		         CACHE_SLOT_TAG(slot) == CACHE_HASH_TAG(key->hash)) {
			_HA_ATOMIC_INC(&cache->stats.reserve_inflight);
			return CACHE_WHANDLE_NULL;
		}
	}
	if (n_free == 0) {
		_HA_ATOMIC_INC(&cache->stats.publish_fails);
		return CACHE_WHANDLE_NULL;
	}

	ttl = expire - date.tv_sec;
	if (ttl > CACHE_TTL_MAX)
		ttl = CACHE_TTL_MAX;
	ttlb = ttl_bucket_get(cache, ttl);

	cache_reclaim_init(&rc, 1);
	while (1) {
		h = ttl_bucket_reserve(cache, ttlb, total_len);
		if (!CACHE_HANDLE_ERR(h))
			break;

		/* The bucket had no segment to give: try to reclaim. */
		if (cache_reclaim_try(cache, &rc) == CACHE_RECLAIM_GIVEUP)
			return CACHE_WHANDLE_NULL;
	}
	cache_reclaim_done(cache, &rc);

	rec = CACHE_HANDLE_REC(cache, &h);
	rec->rec_len = data_len;
	rec->expire = expire;
	rec->hash = key->hash;

	/* Index the entry right away, pending: lookups skip it until it is
	 * published, while stores of the same key see it in flight.
	 */
	slot = CACHE_SLOT_MAKE(CACHE_HASH_TAG(key->hash), h.seg_id, h.seg_off, 0);
	if (!ht_insert(cache, &key->hash, slot | CACHE_SLOT_PENDING)) {
		_HA_ATOMIC_INC(&cache->stats.publish_fails);
		cache_drop(cache, &h, NULL);
		return CACHE_WHANDLE_NULL;
	}

	/* The caller writes <ready_len> bytes next: their room is made now. */
	if (cache_make_room(cache, &h, ready_len) < 0) {
		cache_drop(cache, &h, ht_find_pending(cache, &h));
		return CACHE_WHANDLE_NULL;
	}

	return h;
}

struct cache_whandle cache_reserve(struct cache *cache, const struct cache_key *key,
                                   size_t data_len, time_t expire)
{
	return cache_reserve_with(cache, key, data_len, 0, expire);
}

int cache_write(struct cache *cache, struct cache_whandle *h,
                const void *data, size_t len)
{
	struct seg *seg;

	BUG_ON_BAD_HANDLE(cache, h);

	if (cache_make_room(cache, h, len) < 0)
		return -1;

	while (len > 0) {
		size_t off;
		uint32_t max;
		char *buf;

		BUG_ON(h->cur_seg_id == CACHE_SEG_NONE);

		off = seg_data_off(cache, h->seg_off, h->data_off, NULL);
		max = MIN(cache->cfg.seg_size - off, len);
		buf = (char *)(cache->arena) + CACHE_ARENA_OFF(cache, h->cur_seg_id, off);
		memcpy(buf, data, max);
		len -= max;
		h->data_off += max;
		data = (const char *)data + max;

		if (off + max == cache->cfg.seg_size) {
			seg = &cache->segments[h->cur_seg_id];
			h->cur_seg_id = seg->next_chain_id;
		}
	}
	return 0;
}

/* Abort a write. */
void cache_abort(struct cache *cache, const struct cache_whandle *h)
{
	BUG_ON_BAD_HANDLE(cache, h);

	_HA_ATOMIC_INC(&cache->stats.aborts);
	cache_drop(cache, h, ht_find_pending(cache, h));
}

/* Link a just-published private chain into its bucket's list, where expiry
 * and eviction can see it. The list is publish-ordered, so a slow write
 * delays its entry's expiry by up to the write duration - imprecision of
 * the same order as the one-second TTL granularity.
 */
static void cache_publish_private(struct cache *cache, seg_id_t seg_id)
{
	struct seg *seg = &cache->segments[seg_id];
	struct ttl_bucket *ttlb;

	BUG_ON_HOT(!(seg->flags & SEG_F_PRIVATE));

	ttlb = &cache->ttl_buckets[seg->ttl_bucket];
	HA_SPIN_LOCK(CACHE_TTLB_LOCK, &ttlb->lock);
	seg_list_append(cache, &ttlb->prv_segs, seg_id);
	HA_SPIN_UNLOCK(CACHE_TTLB_LOCK, &ttlb->lock);
}

/* Finalize a write by publishing it. */
int cache_publish(struct cache *cache, const struct cache_whandle *h)
{
	struct ht_iter it;
	struct cache_rhandle rh;
	struct cache_whandle moved;
	struct cache_record *rec;
	struct seg *seg;
	uint64_t *slotp, *oldp, slot, old;
	uint32_t state_gen;
	unsigned int ttl_bucket;
	seg_id_t reserved_id;
	uint16_t tag;

	BUG_ON_BAD_HANDLE(cache, h);

	rec = CACHE_HANDLE_REC(cache, h);
	seg = &cache->segments[h->seg_id];
	slotp = ht_find_pending(cache, h);
	reserved_id = h->seg_id;

	if (seg->flags & SEG_F_NO_LEN) {
		BUG_ON(h->seg_off != 0);
		if (h->data_off == 0)
			goto fail;
		rec->rec_len = sizeof(struct cache_record) + h->data_off;
		/* Shrink write_off to the end of what was written so
		 * seg_unindex() stops there, clamped because a grown entry
		 * spans several segments while write_off is a within-segment
		 * offset. Such a segment holds one record, so any non-zero
		 * bound visits it.
		 */
		seg->write_off = MIN(CACHE_OFF_ALIGN_UP(rec->rec_len),
		                     cache->cfg.seg_size);

		/* A single segment does not stay private to this one entry:
		 * the record joins the shared list, see seg_relocate().
		 */
		if (seg->n_chain == 1) {
			moved = seg_relocate(cache, h);
			h = &moved;
			rec = CACHE_HANDLE_REC(cache, h);
			seg = &cache->segments[h->seg_id];
		}
	}

	/* Since cache_write() correctly protects against out-of-bounds writes,
	 * seeing data_off larger than the record's capacity is definitely an
	 * internal bug, or data corruption in the handle.
	 */
	BUG_ON(h->data_off > CACHE_REC_CAPACITY(rec));

	if (h->data_off < CACHE_REC_CAPACITY(rec)) {
		/* If the caller wrote less than the expected number of bytes,
		 * we have no choice but to abort. This is because rec->rec_len
		 * is used both as the size of the data entry, and as the stride
		 * to know where to look for the next entry. If we tried to fix
		 * it up here, seg_unindex() could end up reading garbage
		 * instead of the next entries. There are edge cases where it
		 * would be possible to fix up rec_len, for instance if the
		 * stride ends up unchanged because of the alignment bytes, or
		 * if nothing has been written after this entry in this segment
		 * yet, but these aren't worth the extra complexity nor the loss
		 * in strictness.
		 */
		goto fail;
	}

	tag = CACHE_HASH_TAG(rec->hash);
	slot = CACHE_SLOT_MAKE(tag, h->seg_id, h->seg_off, 0);

	/* Clear the published copies of the key before exposing this one, so
	 * that a re-store (e.g. refreshing an expired entry) supersedes the old
	 * copy instead of staying indexed next to it. If we lose a clearing
	 * CAS, we retry the same slot: the value can only have changed to the
	 * same entry with a bumped frequency counter, to another copy of this
	 * key, which we clear too, or to something we skip. Two stores of a key
	 * publishing at once may each miss the other's copy and leave both
	 * indexed; lookups and deletes handle duplicates.
	 */
	ht_iter_init(&it, cache);
	while ((oldp = ht_iter_next_tag(&it, &rec->hash, &old)) != NULL) {
		do {
			rh = seg_read_pin(cache, &rec->hash, oldp, &old, 0);
			if (CACHE_HANDLE_ERR(rh))
				break;
			/* Same key, verified: supersede it. A replaced live
			 * copy is a concurrent store's loser, counted as dead
			 * bytes; a replaced expired one is a plain refresh.
			 */
			if (HA_ATOMIC_CAS(oldp, &old, 0)) {
				struct cache_record *oldrec = CACHE_HANDLE_REC(cache, &rh);
				struct seg *oldseg = &cache->segments[rh.seg_id];
				/* Read while pinned: once unpinned the segment may
				 * be recycled under a new life.
				 */
				int old_private = oldseg->flags & SEG_F_PRIVATE;

				if (!old_private)
					seg_live_sub(oldseg, oldrec);
				if (date.tv_sec < oldrec->expire) {
					_HA_ATOMIC_INC(&cache->stats.publish_supersedes);
					_HA_ATOMIC_ADD(&cache->stats.dead_bytes_cum,
					               CACHE_OFF_ALIGN_UP(oldrec->rec_len));
				}
				ttl_bucket = oldseg->ttl_bucket;
				state_gen = _HA_ATOMIC_LOAD(&oldseg->state_gen);
				seg_read_unpin(cache, oldseg);
				if (!old_private)
					seg_check_dead(cache, rh.seg_id, ttl_bucket, state_gen);
				break;
			}
			seg_read_unpin(cache, &cache->segments[rh.seg_id]);
		} while (old != 0 && !(old & CACHE_SLOT_PENDING) &&
		         CACHE_SLOT_TAG(old) == tag);
	}

	/* The release store orders the record's contents before the slot that
	 * exposes them.
	 */
	HA_ATOMIC_STORE(slotp, slot);
	if (seg->flags & SEG_F_PRIVATE)
		cache_publish_private(cache, h->seg_id);
	else
		seg_live_add(seg, rec);
	seg_write_unpin(seg);

	if (h->seg_id != reserved_id) {
		seg_write_unpin(&cache->segments[reserved_id]);
		seg_free_push(cache, reserved_id);
	}
	return 0;

fail:
	_HA_ATOMIC_INC(&cache->stats.publish_fails);
	cache_drop(cache, h, slotp);
	return -1;
}

void cache_get_stats(const struct cache *cache, struct cache_stats *stats)
{
	stats->reserve_fails = _HA_ATOMIC_LOAD(&cache->stats.reserve_fails);
	stats->reserve_fail_giveup = _HA_ATOMIC_LOAD(&cache->stats.reserve_fail_giveup);
	stats->reserve_fail_budget = _HA_ATOMIC_LOAD(&cache->stats.reserve_fail_budget);
	stats->reclaim_calls = _HA_ATOMIC_LOAD(&cache->stats.reclaim_calls);
	stats->reclaim_blocked = _HA_ATOMIC_LOAD(&cache->stats.reclaim_blocked);
	stats->reclaim_no_candidate = _HA_ATOMIC_LOAD(&cache->stats.reclaim_no_candidate);
	stats->publish_fails = _HA_ATOMIC_LOAD(&cache->stats.publish_fails);
	stats->read_pin_fails = _HA_ATOMIC_LOAD(&cache->stats.read_pin_fails);
	stats->segs_expired = _HA_ATOMIC_LOAD(&cache->stats.segs_expired);
	stats->segs_evicted = _HA_ATOMIC_LOAD(&cache->stats.segs_evicted);
	stats->publish_supersedes = _HA_ATOMIC_LOAD(&cache->stats.publish_supersedes);
	stats->aborts = _HA_ATOMIC_LOAD(&cache->stats.aborts);
	stats->reserve_inflight = _HA_ATOMIC_LOAD(&cache->stats.reserve_inflight);
	stats->dead_bytes_cum = _HA_ATOMIC_LOAD(&cache->stats.dead_bytes_cum);
	stats->segs_emptied = _HA_ATOMIC_LOAD(&cache->stats.segs_emptied);
	stats->merges = _HA_ATOMIC_LOAD(&cache->merge_success);
	stats->merges_empty = _HA_ATOMIC_LOAD(&cache->merge_empty);
	stats->merges_no_dst = _HA_ATOMIC_LOAD(&cache->stats.merges_no_dst);
	stats->merges_inflight_max = _HA_ATOMIC_LOAD(&cache->stats.merges_inflight_max);
	stats->reserve_fail_merging = _HA_ATOMIC_LOAD(&cache->stats.reserve_fail_merging);
	stats->reserve_merging_rescued = _HA_ATOMIC_LOAD(&cache->stats.reserve_merging_rescued);
	stats->fifo_fallbacks = _HA_ATOMIC_LOAD(&cache->stats.fifo_fallbacks);
	stats->segs_condemned = _HA_ATOMIC_LOAD(&cache->segs_condemned);
	stats->segs_condemned_max = _HA_ATOMIC_LOAD(&cache->stats.segs_condemned_max);
	stats->n_segs = cache->n_segs;
	stats->n_reserved = cache->cfg.n_reserved;
	stats->n_free = _HA_ATOMIC_LOAD(&cache->n_free);
}

size_t cache_entry_size(const struct cache *cache, const struct cache_rhandle *h)
{
	struct cache_record *rec;

	BUG_ON_BAD_HANDLE(cache, h);

	rec = CACHE_HANDLE_REC(cache, h);
	return CACHE_REC_CAPACITY(rec);
}

uint32_t cache_entry_expire(const struct cache *cache, const struct cache_rhandle *h)
{
	struct cache_record *rec;

	BUG_ON_BAD_HANDLE(cache, h);

	rec = CACHE_HANDLE_REC(cache, h);
	return rec->expire;
}

const struct cache_key *cache_entry_key(const struct cache *cache, const struct cache_rhandle *h)
{
	struct cache_record *rec;

	BUG_ON_BAD_HANDLE(cache, h);

	rec = CACHE_HANDLE_REC(cache, h);
	return (struct cache_key *)&rec->hash;
}

int cache_foreach(struct cache *cache, struct cache_iter *it,
                  cache_foreach_cb_t cb, void *data)
{
	struct seg *seg;
	struct cache_rhandle h;
	uint64_t *slotp, slot;
	int bucket_idx, slot_idx, yield;

	while (it->idx < cache->index.n_buckets * CACHE_BUCKET_N_SLOT) {
		bucket_idx = it->idx / CACHE_BUCKET_N_SLOT;
		slot_idx = it->idx % CACHE_BUCKET_N_SLOT;

		slotp = &cache->index.buckets[bucket_idx].slot[slot_idx];
		slot = _HA_ATOMIC_LOAD(slotp);
		if (slot != 0 && !(slot & CACHE_SLOT_PENDING)) {
			h = seg_read_pin(cache, NULL, slotp, &slot, 1);
			if (!CACHE_HANDLE_ERR(h)) {
				yield = cb(cache, &h, data);
				seg = &cache->segments[h.seg_id];
				seg_read_unpin(cache, seg);
				if (yield)
					return yield;
			}
		}
		it->idx++;
	}

	return 0;
}
