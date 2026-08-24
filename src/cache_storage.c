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
 * - Eviction is plain FIFO over whole segments, with no per-item frequency
 *   counter and no merging of live entries into compacted segments. An
 *   admission filter that only caches an object on its second sighting keeps
 *   one-hit wonders out of the store instead.
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

/* Admission filter sizing: ~0.05% false positives per full generation. */
#define CACHE_ADMIT_BITS_PER_KEY 16
#define CACHE_ADMIT_PROBES       8

/* Entries smaller than this many mean objects bypass the admission filter:
 * what a never-reused entry wastes is its size, so only entries far above
 * the workload's typical size must prove reuse before being stored.
 */
#define CACHE_ADMIT_MIN_OBJS     16

/* The filter is addressed with a bit mask, so its size must be a power of two.
 * The key count is one already, leaving the per-key bits to check.
 */
BUG_ON_STATIC(CACHE_ADMIT_BITS_PER_KEY & (CACHE_ADMIT_BITS_PER_KEY - 1));

/* Maximum number of times seg_read_pin() re-validates after losing a race
 * with a rewrite of its slot. Each retry requires a store or delete of the
 * same key to have rewritten the slot within the few nanoseconds between
 * the slot read and its post-pin re-read, so only a sustained storm of
 * same-key rewrites can exhaust the cap; this should never happen in
 * practice (exhaustions are counted in the read_pin_fails statistic), and the
 * resulting miss is harmless since the entry is being replaced anyway. The
 * cap is also what makes the read path wait-free.
 */
#define CACHE_READ_PIN_TRIES    3

/* Auto segment sizing (cfg.seg_size == 0): the largest power of two yielding at
 * least CACHE_SEG_AUTO_TARGET segments, capped at CACHE_SEG_AUTO_MAX. Smaller
 * segments waste less in per-TTL-class open segments (~seg/2 each) and evict at
 * finer grain; larger segments shorten the chains of oversized entries and
 * amortize reclaim better. At the measured ~35 KB mean web response, a 2 MB
 * segment already holds ~60 entries, so growing past the cap buys little while
 * coarsening eviction.
 *
 * A segment must also hold several mean objects, or most entries span segments
 * and a small cache degrades sharply (measured: segments under ~4x the mean
 * cost half the hit ratio; ~14x and above is flat). So the segment size is
 * floored at CACHE_SEG_AUTO_MIN_OBJS mean objects, while always keeping at
 * least CACHE_SEG_AUTO_MIN_SEGS segments as eviction and expiry units. The
 * floor only engages when the cache holds fewer than TARGET * MIN_OBJS mean
 * objects; larger caches are unaffected by it.
 */
#define CACHE_SEG_AUTO_MAX      (2 * 1024 * 1024)
#define CACHE_SEG_AUTO_TARGET   64
#define CACHE_SEG_AUTO_MIN_OBJS 16
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
#define CACHE_SLOT_TAG_BITS     12

#define CACHE_SLOT_OFF_SHIFT    0
#define CACHE_SLOT_SEG_SHIFT    (CACHE_SLOT_OFF_SHIFT  + CACHE_SLOT_OFF_BITS)
#define CACHE_SLOT_TAG_SHIFT    (64 - CACHE_SLOT_TAG_BITS)

#define CACHE_SLOT_OFF_MASK     (((1ULL << CACHE_SLOT_OFF_BITS)  - 1) << CACHE_SLOT_OFF_SHIFT)
#define CACHE_SLOT_SEG_MASK     (((1ULL << CACHE_SLOT_SEG_BITS)  - 1) << CACHE_SLOT_SEG_SHIFT)
#define CACHE_SLOT_TAG_MASK     (((1ULL << CACHE_SLOT_TAG_BITS)  - 1) << CACHE_SLOT_TAG_SHIFT)

/* One always-set bit in the unused space between the location bits and the
 * tag: it keeps a live slot from ever encoding as all zeroes (the empty
 * value), since tag, seg and off can all legitimately be 0.
 */
#define CACHE_SLOT_LIVE         (1ULL << (CACHE_SLOT_SEG_SHIFT + CACHE_SLOT_SEG_BITS))

/* Accessor macros */
#define CACHE_SLOT_OFF(slot)    \
	((((slot) & CACHE_SLOT_OFF_MASK)  >> CACHE_SLOT_OFF_SHIFT) << CACHE_OFF_SHIFT)
#define CACHE_SLOT_SEG(slot)    \
	((((slot) & CACHE_SLOT_SEG_MASK)  >> CACHE_SLOT_SEG_SHIFT))
#define CACHE_SLOT_TAG(slot)    \
	((((slot) & CACHE_SLOT_TAG_MASK)  >> CACHE_SLOT_TAG_SHIFT))

/* Creation macro */
#define CACHE_SLOT_MAKE(tag, seg, off)                                    \
	(((uint64_t)(tag)                     << CACHE_SLOT_TAG_SHIFT)  | \
	CACHE_SLOT_LIVE                                                 | \
	( (uint64_t)(seg)                     << CACHE_SLOT_SEG_SHIFT)  | \
	(((uint64_t)(off) >> CACHE_OFF_SHIFT) << CACHE_SLOT_OFF_SHIFT))

/* CACHE_MAX_TOTAL_SIZE is public API (cache_storage.h); it must stay equal to
 * what a slot's location can address: SEG_BITS + OFF_BITS offset-units, each
 * CACHE_OFF_SHIFT bytes wide.
 */
BUG_ON_STATIC(CACHE_MAX_TOTAL_SIZE !=
	(1ULL << (CACHE_SLOT_SEG_BITS + CACHE_SLOT_OFF_BITS + CACHE_OFF_SHIFT)));

/* CACHE_SEG_MAX_SIZE is public API (cache_storage.h); it must stay equal to
 * what a slot's offset field can address: OFF_BITS offset-units, each
 * CACHE_OFF_SHIFT bytes wide.
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

#define CACHE_LOCK_FREE         0
#define CACHE_LOCK_TAKEN        1

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

/* A simple XCHG-based spinlock implementation. */
typedef uint8_t spinlock_t;

static inline void cache_lock(spinlock_t *lock)
{
	while (HA_ATOMIC_XCHG(lock, CACHE_LOCK_TAKEN) != CACHE_LOCK_FREE) {
		__ha_cpu_relax();
		while (_HA_ATOMIC_LOAD(lock) != CACHE_LOCK_FREE)
			__ha_cpu_relax_for_read();
	}
}

static inline void cache_unlock(spinlock_t *lock)
{
	HA_ATOMIC_STORE(lock, CACHE_LOCK_FREE);
}

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
	uint32_t create_ts;      /* Creation timestamp */
	uint16_t ttl_bucket;     /* TTL bucket index */
	uint32_t r_refcount;     /* Read refcounts */
	uint32_t w_refcount;     /* Write refcounts */
	seg_id_t next_seg_id;    /* TTL bucket list linkage (seg_list) */
	seg_id_t next_chain_id;  /* Jumbo entries & free-list linkage */
	uint32_t state_gen;      /* SEG_S_* state + generation */
	uint8_t flags;           /* SEG_F_* */
};

struct seg_list {
	seg_id_t first_seg_id;
	seg_id_t last_seg_id;
};

struct ttl_bucket {
	struct seg_list segs;
	struct seg_list prv_segs;
	uint32_t ttl_approx;
	uint8_t lock;
};

struct ht_bucket {
	uint64_t slot[CACHE_BUCKET_N_SLOT];
} ALIGNED(64);

BUG_ON_STATIC(sizeof(struct ht_bucket) != 64);

/* Maximum total number of reclaim rounds when trying to reserve segments. */
#define CACHE_RESERVE_ATTEMPTS  8
/* Maximum number of reclaim rounds in a row that made no progress, e.g.
 * because the victim segment was busy (pinned for writes).
 */
#define CACHE_RESERVE_MAX_BUSY  4

enum cache_reclaim_status {
	CACHE_RECLAIM_PROGRESS,
	CACHE_RECLAIM_RETRY,
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

struct cache {
	uint32_t flags;                 /* CACHE_F_* flags */
	struct cache_config cfg;        /* Configuration tunables */
	uint64_t seed;                  /* Seeds the hashing of the keys */

	/* Hash table index for reads */
	struct {
		struct ht_bucket *buckets;
		uint32_t n_buckets;

		/* Admission filtering (see cache_admit) */
		ulong *admit_bloom;     /* Both generations, halves of one allocation */
		uint64_t admit_mask;    /* Bits per generation - 1 */
		uint32_t admit_cap;     /* Keys per generation before rotation */
		uint32_t admit_count;   /* Keys recorded in the current generation */
		uint32_t admit_phase;   /* Low bit selects the current half */
	} index;

	uint32_t n_segs;                /* Number of segments */
	uint8_t *arena;                 /* Storage buffer */
	size_t arena_len;               /* And its size */

	struct seg *segments;           /* Segment descriptor table */
	struct ttl_bucket *ttl_buckets; /* TTL buckets for writes */
	spinlock_t pool_lock;           /* Lock for the pool of free segments */
	seg_id_t free_seg_id;           /* Free-list of segments */

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
 * match the tag in <hash>. Useful for lookups. This also sets the slot's value
 * in <val>, so the caller does not need to duplicate the atomic load. Note that
 * this only matches the tag and not the full hash, so the slot we return is
 * only a candidate for the hash; the caller needs to check the full hash to
 * ensure this is the correct slot.
 */
static inline uint64_t *ht_iter_next_tag(struct ht_iter *it, const XXH128_hash_t *hash, uint64_t *val)
{
	uint64_t *slotp, slot;

	while ((slotp = ht_iter_next(it, hash)) != NULL) {
		slot = HA_ATOMIC_LOAD(slotp);
		if (slot == 0)
			continue;

		if (CACHE_HASH_TAG(*hash) != CACHE_SLOT_TAG(slot))
			continue;

		*val = slot;
		return slotp;
	}
	return NULL;
}

/* Small segment list API - avoids code duplication with the shared and private
 * segment lists in TTL buckets. The relaxed atomic stores and loads on
 * first_seg_id only exist because of an optimization in cache_reclaim() where
 * this field is read without a lock.
 */
static inline void seg_list_init(struct seg_list *l)
{
	l->first_seg_id = CACHE_SEG_NONE;
	l->last_seg_id = CACHE_SEG_NONE;
}

static inline void seg_list_append(const struct cache *cache, struct seg_list *l,
                                   seg_id_t seg_id)
{
	struct seg *seg, *prev;

	if (l->last_seg_id != CACHE_SEG_NONE) {
		prev = &cache->segments[l->last_seg_id];
		prev->next_seg_id = seg_id;
	}
	seg = &cache->segments[seg_id];
	seg->next_seg_id = CACHE_SEG_NONE;
	l->last_seg_id = seg_id;
	if (l->first_seg_id == CACHE_SEG_NONE)
		_HA_ATOMIC_STORE(&l->first_seg_id, seg_id);
}

static inline seg_id_t seg_list_pop(const struct cache *cache, struct seg_list *l)
{
	struct seg *seg;
	seg_id_t seg_id;

	seg_id = l->first_seg_id;
	if (seg_id != CACHE_SEG_NONE) {
		seg = &cache->segments[seg_id];
		_HA_ATOMIC_STORE(&l->first_seg_id, seg->next_seg_id);
	}
	if (l->last_seg_id == seg_id)
		l->last_seg_id = CACHE_SEG_NONE;

	return seg_id;
}

static inline seg_id_t seg_list_first(struct seg_list *l)
{
	return _HA_ATOMIC_LOAD(&l->first_seg_id);
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
 * as cache_read_at(), cache_peek_at(), cache_peek_at_mut() and also when moving
 * the offset with cache_seek() - although for cache_seek(), it will only walk
 * the chain from the current segment if possible. Other functions can just use
 * the cached current segment in the handle.
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
	_HA_ATOMIC_STORE(&seg->state_gen, SEG_STATE_MAKE(gen + 1, SEG_S_LIVE));
	seg->flags = 0;
}

/* Grab <n_segs> segments from the free-list. */
static inline seg_id_t seg_free_pop(struct cache *cache, unsigned int n_segs)
{
	seg_id_t first_seg_id, seg_id;
	struct seg *seg;

	BUG_ON(n_segs == 0);

	cache_lock(&cache->pool_lock);
	first_seg_id = cache->free_seg_id;
	seg_id = first_seg_id;
	while (seg_id != CACHE_SEG_NONE && n_segs > 0) {
		seg = &cache->segments[seg_id];
		seg_id = seg->next_chain_id;
		n_segs--;
	}
	if (n_segs > 0) {
		cache_unlock(&cache->pool_lock);
		return CACHE_SEG_NONE;
	}
	cache->free_seg_id = seg->next_chain_id;
	cache_unlock(&cache->pool_lock);
	seg->next_chain_id = CACHE_SEG_NONE;

	return first_seg_id;
}

/* Put a segment back on the free-list (which can be a chain). */
static inline void seg_free_push(struct cache *cache, seg_id_t seg_id)
{
	seg_id_t first_seg_id, last_seg_id;
	struct seg *last;

	BUG_ON(seg_id == CACHE_SEG_NONE);

	first_seg_id = seg_id;
	do {
		struct seg *seg = &cache->segments[seg_id];
		uint32_t gen = SEG_STATE_GEN(_HA_ATOMIC_LOAD(&seg->state_gen));

		/* It's not actually required to set the state back to
		 * SEG_S_FREE for correctness, but it is useful for debugging.
		 */
		_HA_ATOMIC_STORE(&seg->state_gen, SEG_STATE_MAKE(gen, SEG_S_FREE));
		last_seg_id = seg_id;
		seg_id = seg->next_chain_id;
	} while (seg_id != CACHE_SEG_NONE);

	last = &cache->segments[last_seg_id];

	cache_lock(&cache->pool_lock);
	last->next_chain_id = cache->free_seg_id;
	cache->free_seg_id = first_seg_id;
	cache_unlock(&cache->pool_lock);
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
	return (date.tv_sec - seg->create_ts) >= ttlb->ttl_approx;
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
		 * CAS can race seg_reclaim()'s own attempt and guarantees
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
		                  SEG_STATE_MAKE(SEG_STATE_GEN(expected), SEG_S_FREE)))
			seg_free_push(cache, seg_get_id(cache, seg));
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
	 * Dekker pairing with seg_reclaim()'s r_refcount check.
	 */
	slot2 = HA_ATOMIC_LOAD_SEQ_CST(slotp);
	if (slot2 != slot) {
		seg_read_unpin(cache, seg);
		slot = slot2;

		/* We need to validate again that this slot still
		 * matches our tag and is not empty, since it changed.
		 */
		if (slot != 0 && likely(hash != NULL) &&
		    CACHE_SLOT_TAG(slot) == CACHE_HASH_TAG(*hash)) {
			if (++tries < CACHE_READ_PIN_TRIES)
				goto retry;
			_HA_ATOMIC_INC(&cache->stats.read_pin_fails);
		}

		return CACHE_RHANDLE_NULL;
	}

	/* Refuse the pin if the segment is no longer live. The load must be
	 * sequentially consistent: with the reference count increment above
	 * it forms a Dekker pair against seg_reclaim(), which stores
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

/* Unlink all the entries in a segment from the hashtable. */
static void seg_unindex(const struct cache *cache, struct seg *seg)
{
	struct cache_whandle h = { .seg_id = seg_get_id(cache, seg) };
	struct ht_iter it;
	struct cache_record *rec;
	uint64_t *slotp, slot;
	size_t off = 0;

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
			if (CACHE_SLOT_SEG(slot) != h.seg_id ||
			    CACHE_SLOT_OFF(slot) != h.seg_off)
				continue;

			HA_ATOMIC_CAS(slotp, &slot, 0);
			break;
		}

		off += CACHE_OFF_ALIGN_UP(rec->rec_len);
	}
}

/* Reclaim the head segment <seg> of a segment list: unindex it, unlink it from
 * the list, then either free it or condemn it to be freed by its last reader.
 * The whole segment chain is reclaimed with its head; the number of segments
 * it counts is stored in <n_segs> (except when blocked). The caller needs to
 * hold the TTL bucket lock where the segment list lives.
 */
static inline enum seg_reclaim_status seg_reclaim(struct cache *cache, struct seg_list *l,
                                                  uint32_t *n_segs)
{
	seg_id_t seg_id = seg_list_first(l);
	struct seg *seg = &cache->segments[seg_id];
	uint32_t expected, gen;

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
	 * last writer's lock-free decrement, and seg_unindex() below parses
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
		return SEG_RECLAIM_BLOCKED;
	}

	/* The head segment records the length of its chain. */
	*n_segs = seg->n_chain;

	/* Now we unindex, which guarantees no new lookups will get to the seg
	 * structure anymore, since it won't be found in the hashtable.
	 */
	seg_unindex(cache, seg);

	/* Unlink the segment from the TTL bucket. This means it won't be a
	 * candidate for expiration or eviction anymore. If this segment was
	 * also the active one, no new writers will be able to find it as well.
	 */
	seg_list_pop(cache, l);

	/* At this point, there are no writers, no new writers or code trying to
	 * expire/evict this segment can come because it has been unlinked from
	 * the TTL bucket and we still hold the lock, no new readers can come
	 * because the hashtable index slots have been cleared, but there might
	 * still be pre-existing readers, and in-flight readers who have located
	 * this segment from the hash table before we called seg_unindex(), but
	 * have yet to increment the read refcount.
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
		 * state will be SEG_S_LIVE again. It is not obvious why this
		 * ABA situation isn't a problem, so it's worth explaining in
		 * detail.
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
	 * LIVE -> DRAINING transition at the beginning of this function.
	 */
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
		                  SEG_STATE_MAKE(gen, SEG_S_FREE)))
			seg_free_push(cache, seg_id);
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

/* Attempt to reclaim all the expired segments at the head of a TTL bucket
 * segment list. Returns the number of segments that were successfully freed.
 */
static inline int seg_list_expire(struct cache *cache, struct ttl_bucket *ttlb, struct seg_list *l)
{
	enum seg_reclaim_status status;
	struct seg *seg;
	seg_id_t seg_id;
	uint32_t n_segs;
	int freed = 0;

	while ((seg_id = seg_list_first(l)) != CACHE_SEG_NONE) {
		seg = &cache->segments[seg_id];
		if (!seg_expired(ttlb, seg))
			break;
		status = seg_reclaim(cache, l, &n_segs);
		if (status == SEG_RECLAIM_BLOCKED)
			break;
		if (status == SEG_RECLAIM_FREED)
			freed += n_segs;
		_HA_ATOMIC_ADD(&cache->stats.segs_expired, n_segs);
	}

	return freed;
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
 * from the free pool. Returns a null handle when no segment is available; the
 * caller decides whether to reclaim and retry.
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

	cache_lock(&ttlb->lock);
	if (!private)
		seg_id = seg_list_last(&ttlb->segs);
	else
		/* When size is 0 or we need more than one segment, we have
		 * to use private segments for the reservation.
		 */
		seg_id = CACHE_SEG_NONE;

	/* Check if the tail segment exists and has enough room. */
	if (seg_id == CACHE_SEG_NONE ||
	    cache->segments[seg_id].write_off + size > cache->cfg.seg_size) {
		unsigned int n_segs;

		/* See if this entry requires more than one segment. */
		if (size > cache->cfg.seg_size)
			n_segs = (size + cache->cfg.seg_size - 1) / cache->cfg.seg_size;
		else
			n_segs = 1;

		/* Get free segments if possible. */
		seg_id = seg_free_pop(cache, n_segs);
		if (seg_id == CACHE_SEG_NONE) {
			cache_unlock(&ttlb->lock);
			return CACHE_WHANDLE_NULL;
		}

		/* Link the new segments in the TTL bucket. */
		seg = &cache->segments[seg_id];
		seg_reinit(seg);
		seg->n_chain = n_segs;
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
	cache_unlock(&ttlb->lock);

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

	/* Two expected objects per bucket, which is four slots each. Insert
	 * failures stay below noise up to ~60% slot load on this two-choice
	 * index and cross 1% at ~75%; publish_fails counts the refusals.
	 *
	 * The count is clamped before pow2_up(), whose uint32 domain overflows
	 * past the ~32 TB of arena that CACHE_MAX_TOTAL_SIZE permits. 2^26
	 * buckets is 4 GB of index, and well below the 2^52 that two-choice
	 * hashing tops out at here.
	 */
	n_buckets = pow2_up(MIN(1U << 26, MAX(1024, (total_size / cache->cfg.mean_obj_size) / 2)));
	cache->index.n_buckets = n_buckets;
	size = n_buckets * sizeof(struct ht_bucket);
	cache->index.buckets = ha_aligned_alloc(64, size);
	if (!cache->index.buckets)
		return -1;
	memset(cache->index.buckets, 0, size);

	if (!(cache->flags & CACHE_F_NO_ADM_FILTER)) {
		uint64_t bits;

		/* Twice the expected object count: the filter also absorbs
		 * sightings of objects that are never stored.
		 */
		cache->index.admit_cap = n_buckets * 4;
		bits = (uint64_t)cache->index.admit_cap * CACHE_ADMIT_BITS_PER_KEY;
		cache->index.admit_bloom = calloc(2, bits / 8);
		if (cache->index.admit_bloom == NULL)
			return -1;
		cache->index.admit_mask = bits - 1;
	}
	return 0;
}

void cache_destroy(struct cache *cache)
{
	if (cache == NULL)
		return;

	ha_aligned_free(cache->index.buckets);
	free(cache->index.admit_bloom);
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

	if (cfg->admit_min_size == 0) {
		uint64_t sz = (uint64_t)cfg->mean_obj_size * CACHE_ADMIT_MIN_OBJS;

		cfg->admit_min_size = sz > SIZE_MAX ? SIZE_MAX : sz;
	}

	if (cfg->seg_size == 0) {
		uint64_t sz = total_size / CACHE_SEG_AUTO_TARGET;
		uint64_t cap = total_size / CACHE_SEG_AUTO_MIN_SEGS;

		if (sz < (uint64_t)cfg->mean_obj_size * CACHE_SEG_AUTO_MIN_OBJS)
			sz = (uint64_t)cfg->mean_obj_size * CACHE_SEG_AUTO_MIN_OBJS;
		if (sz > cap)
			sz = cap;
		if (sz > CACHE_SEG_AUTO_MAX)
			sz = CACHE_SEG_AUTO_MAX;
		if (sz < 4096)
			sz = 4096;
		cfg->seg_size = pow2_down(sz);
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
	cache->pool_lock = CACHE_LOCK_FREE;

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
		ttlb->lock = CACHE_LOCK_FREE;
	}

	return cache;

out:
	cache_destroy(cache);
	return NULL;
}

/* The admission filter is a pair of Bloom filter generations queried as a
 * union and rotated by insertion count, so a first sighting is remembered for
 * the next <admit_cap> to 2*<admit_cap> recorded keys. See the design
 * document for more information.
 */
static inline int admit_bits_test(const ulong *gen, uint64_t mask, uint64_t h1, uint64_t h2)
{
	uint64_t pos;
	int i;

	for (i = 0; i < CACHE_ADMIT_PROBES; i++) {
		pos = (h1 + i * h2) & mask;
		if (!(_HA_ATOMIC_LOAD(&gen[pos / (8 * sizeof(ulong))]) &
		      ((ulong)1 << (pos % (8 * sizeof(ulong))))))
			return 0;
	}
	return 1;
}

static inline void admit_bits_set(ulong *gen, uint64_t mask, uint64_t h1, uint64_t h2)
{
	uint64_t pos;
	int i;

	for (i = 0; i < CACHE_ADMIT_PROBES; i++) {
		pos = (h1 + i * h2) & mask;
		_HA_ATOMIC_OR(&gen[pos / (8 * sizeof(ulong))],
		              (ulong)1 << (pos % (8 * sizeof(ulong))));
	}
}

/* Rotate the generations: clear the previous one and make it current. Only
 * the single thread whose key made the count reach <admit_cap> gets here, so
 * rotations cannot double-fire and wipe both generations. Probes and records
 * racing the clear cost at most a bounded number of extra rejects.
 */
static void admit_rotate(struct cache *cache)
{
	size_t words = (cache->index.admit_mask + 1) / (8 * sizeof(ulong));
	uint32_t phase = _HA_ATOMIC_LOAD(&cache->index.admit_phase);
	ulong *stale = cache->index.admit_bloom + ((phase & 1) ^ 1) * words;
	size_t i;

	/* Word-wide atomic stores: concurrent probes read these words. */
	for (i = 0; i < words; i++)
		_HA_ATOMIC_STORE(&stale[i], 0);

	/* The count reset must be a release store: the next winner's
	 * fetch-and-add acquires it, ordering this rotation before the next.
	 */
	HA_ATOMIC_STORE(&cache->index.admit_phase, phase ^ 1);
	HA_ATOMIC_STORE(&cache->index.admit_count, 0);
	_HA_ATOMIC_INC(&cache->stats.admit_rotations);
}

/* Record a key. The fetch-and-add hands out unique counts, so exactly one
 * thread observes the cap and rotates.
 */
static void admit_record(struct cache *cache, ulong *cur, uint64_t h1, uint64_t h2)
{
	admit_bits_set(cur, cache->index.admit_mask, h1, h2);
	_HA_ATOMIC_INC(&cache->stats.admit_inserts);
	if (HA_ATOMIC_ADD_FETCH(&cache->index.admit_count, 1) == cache->index.admit_cap)
		admit_rotate(cache);
}

/* Decide whether to admit entry: only a key seen before is admitted. */
static int cache_admit(struct cache *cache, const struct cache_key *k)
{
	size_t words;
	uint64_t h1 = k->hash.low64;
	uint64_t h2 = k->hash.high64 | 1;   /* odd probe stride */
	ulong *cur, *prev;
	uint32_t phase;

	if (cache->index.admit_bloom == NULL)
		return 1;

	words = (cache->index.admit_mask + 1) / (8 * sizeof(ulong));

	/* A single phase load keeps the current/previous pair coherent. */
	phase = _HA_ATOMIC_LOAD(&cache->index.admit_phase);
	cur  = cache->index.admit_bloom + (phase & 1) * words;
	prev = cache->index.admit_bloom + ((phase & 1) ^ 1) * words;

	if (admit_bits_test(cur, cache->index.admit_mask, h1, h2))
		return 1;

	if (admit_bits_test(prev, cache->index.admit_mask, h1, h2)) {
		/* Re-record so the key survives the next rotation even if
		 * the store it just earned fails.
		 */
		admit_record(cache, cur, h1, h2);
		return 1;
	}

	admit_record(cache, cur, h1, h2);
	return 0;
}

void cache_expire(struct cache *cache)
{
	struct ttl_bucket *ttlb;
	int i;

	for (i = 0; i < CACHE_TTL_N_BUCKETS; i++) {
		ttlb = &cache->ttl_buckets[i];

		cache_lock(&ttlb->lock);
		seg_list_expire(cache, ttlb, &ttlb->segs);
		seg_list_expire(cache, ttlb, &ttlb->prv_segs);
		cache_unlock(&ttlb->lock);
	}
}

/* Attempt to reclaim a segment for a new reservation. We always attempt to
 * reclaim an expired segment before evicting a live one.
 *
 * This function is costly: it scans all the TTL buckets, locking every
 * non-empty one, and it may have to run again when the victim was blocked
 * by writers. Benchmarks showed that this cost is not a problem in
 * practice: even under adversarial in-process load, reservations virtually
 * never fail. The reserve_fail_* counters would reveal it if real traffic
 * proved this wrong. The one known weak spot is when nearly all entries
 * share a single TTL bucket; writers then queue behind evictions on that
 * bucket's lock, which inflates the write tail latency.
 *
 * <needed> is the number of segments the caller is waiting for: expired
 * segments freed during the scan count towards it and the scan stops as soon
 * as it is covered, while at most one victim is evicted per call. The number
 * of segments that measurably reached the free pool is returned in <freed>;
 * it can exceed <needed> since segments are freed whole chains at a time.
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
                                               unsigned int needed,
                                               unsigned int *freed)
{
	struct ttl_bucket *ttlb, *best;
	struct seg_list *best_list;
	struct seg *seg;
	enum seg_reclaim_status status;
	uint32_t oldest_ts, best_gen;
	seg_id_t seg_id, best_seg_id;
	uint32_t n_segs, scan_off;
	int i, j, seen, vanished;

	*freed = 0;
	_HA_ATOMIC_INC(&cache->stats.reclaim_calls);

	/* Locate the oldest segment which is our best candidate for eviction.
	 * While here, see if any segments can be expired. Note that the oldest
	 * segment is not necessarily expirable.
	 */
	oldest_ts = UINT32_MAX;
	best = NULL;
	best_seg_id = CACHE_SEG_NONE;	/* Quiet old GCC versions */
	seen = vanished = 0;

	/* Start the scan at a random offset. This is mostly useful when
	 * several segments are tied for the oldest creation timestamp - an
	 * easy occurrence at one-second granularity. Concurrent reclaimers
	 * then elect different victims instead of all racing for the
	 * first-scanned one.
	 */
	scan_off = statistical_prng() & (CACHE_TTL_N_BUCKETS - 1);
	for (i = 0; i < CACHE_TTL_N_BUCKETS; i++) {
		struct seg_list *lists[2];
		seg_id_t head[2];

		ttlb = &cache->ttl_buckets[(scan_off + i) & (CACHE_TTL_N_BUCKETS - 1)];
		lists[0] = &ttlb->segs;
		lists[1] = &ttlb->prv_segs;

		/* Unlocked read first to avoid taking the lock if possible. */
		for (j = 0; j < 2; j++)
			head[j] = seg_list_first(lists[j]);
		if (head[0] == CACHE_SEG_NONE && head[1] == CACHE_SEG_NONE)
			continue;

		seen = 1;
		cache_lock(&ttlb->lock);
		for (j = 0; j < 2; j++) {
			/* Now that we hold the TTL bucket lock, we need to
			 * re-read segment ID and validate it.
			 */
			seg_id = seg_list_first(lists[j]);
			if (head[j] != CACHE_SEG_NONE && head[j] != seg_id)
				vanished = 1;

			if (seg_id == CACHE_SEG_NONE)
				continue;

			/* The chain ages head-first, so consecutive expired
			 * segments all sit at the head: drain the whole
			 * expired prefix while we hold the lock, not just one
			 * segment - the extra ones feed other reservers, which
			 * then pop free segments without paying for a scan of
			 * their own. An unlucky reservation can thus absorb a
			 * large expired backlog, but capping the drain would
			 * only spread the same work over many more scans, so
			 * the trade-off is deliberate. Should the latency ever
			 * become a problem, the better fix is to call
			 * cache_expire() pro-actively so that big backlogs
			 * never build up in the first place.
			 */
			*freed += seg_list_expire(cache, ttlb, lists[j]);

			/* Expired segments that reached the free pool are
			 * real supply: stop scanning as soon as it covers
			 * what the caller needs.
			 */
			if (*freed >= needed) {
				cache_unlock(&ttlb->lock);
				return CACHE_RECLAIM_PROGRESS;
			}

			/* Read the head again after expiration. */
			seg_id = seg_list_first(lists[j]);

			/* The head is fresh, or expired but writer-pinned:
			 * evaluate it as an eviction candidate below (a
			 * pinned one fails the check, which is the point).
			 */
			if (seg_id != CACHE_SEG_NONE) {
				seg = &cache->segments[seg_id];
				if (_HA_ATOMIC_LOAD(&seg->w_refcount) == 0 &&
				    (best == NULL || seg->create_ts < oldest_ts)) {
					uint32_t sw = _HA_ATOMIC_LOAD(&seg->state_gen);

					oldest_ts = seg->create_ts;
					best_gen = SEG_STATE_GEN(sw);
					best_seg_id = seg_id;
					best_list = lists[j];
					best = ttlb;
				}
			}
		}
		cache_unlock(&ttlb->lock);
	}

	/* We did not see a single segment in use, or all of them were pinned
	 * for writes. In the former case, we need to give up. This should not
	 * really happen in practice unless this thread has been stuck for a
	 * very long time or this function was called at an inappropriate time.
	 * In the edge case where we saw a segment with the unlocked load of
	 * first_seg_id but it was gone when we read again, it means a segment
	 * was reclaimed, so we return CACHE_RECLAIM_PROGRESS in this case,
	 * just like when the scan freed some expired segments, even short of
	 * the need.
	 */
	if (best == NULL) {
		if (*freed > 0 || vanished)
			return CACHE_RECLAIM_PROGRESS;
		if (seen) {
			_HA_ATOMIC_INC(&cache->stats.reclaim_no_candidate);
			return CACHE_RECLAIM_RETRY;
		}
		return CACHE_RECLAIM_GIVEUP;
	}

	/* Expiration did not cover the need: evict the elected victim rather
	 * than throw away the scan we paid for.
	 */
	cache_lock(&best->lock);
	seg_id = seg_list_first(best_list);
	if (seg_id != best_seg_id) {
		/* If the head segment changed, someone successfully
		 * reclaimed it, so we need to retry.
		 */
		cache_unlock(&best->lock);
		_HA_ATOMIC_INC(&cache->stats.reclaim_elect_losses);
		return CACHE_RECLAIM_PROGRESS;
	}

	seg = &cache->segments[best_seg_id];
	if (SEG_STATE_GEN(_HA_ATOMIC_LOAD(&seg->state_gen)) != best_gen) {
		/* Like above, there was some kind of progress: the segment
		 * was reclaimed and reused since we elected it.
		 */
		cache_unlock(&best->lock);
		_HA_ATOMIC_INC(&cache->stats.reclaim_elect_losses);
		return CACHE_RECLAIM_PROGRESS;
	}

	status = seg_reclaim(cache, best_list, &n_segs);
	if (status == SEG_RECLAIM_BLOCKED)
		_HA_ATOMIC_INC(&cache->stats.reclaim_blocked);
	else
		_HA_ATOMIC_ADD(&cache->stats.segs_evicted, n_segs);
	if (status == SEG_RECLAIM_FREED) {
		*freed += n_segs;
		cache_unlock(&best->lock);
		return CACHE_RECLAIM_PROGRESS;
	}

	cache_unlock(&best->lock);

	/* The victim was only condemned (its free deferred to its last
	 * reader) or blocked by a writer - not supply. Expired segments
	 * freed during the scan still are.
	 */
	if (*freed > 0)
		return CACHE_RECLAIM_PROGRESS;
	return CACHE_RECLAIM_RETRY;
}

/* Retry budget for the reclaim rounds of one reservation: <needed> is the
 * number of segments the reservation is waiting for, <freed> accumulates the
 * segments the rounds measurably sent to the free pool, <attempts> counts
 * every round and <busy> the consecutive rounds that made no progress.
 */
struct cache_reclaim_budget {
	unsigned int needed;
	unsigned int freed;
	int attempts;
	int busy;
};

static inline void cache_reclaim_budget_init(struct cache_reclaim_budget *b,
                                             unsigned int needed)
{
	b->needed = needed;
	b->freed = 0;
	b->attempts = 0;
	b->busy = 0;
}

/* Make one cache_reclaim() attempt on behalf of a reservation that found no
 * free segment, and account for it in budget <b>. Returns 0 if the caller
 * should retry the reservation, or -1, with reserve_fails bumped, when there
 * is nothing left to reclaim or the budget is exhausted.
 *
 * The budget is spent on three conditions. A few consecutive attempts with
 * no progress at all mean reclaim cannot help right now. The total number of
 * attempts is capped to bound the time spent on a single reservation. And an
 * attempt must remain plausible to be worth continuing: eviction supplies
 * segments roughly one victim per attempt, so when the shortfall exceeds the
 * attempts remaining, the reservation cannot be satisfied in time and going
 * on would only evict entries for nothing.
 */
static int cache_reclaim_try(struct cache *cache, struct cache_reclaim_budget *b)
{
	enum cache_reclaim_status status;
	unsigned int shortfall, freed;

	/* Freed segments can be consumed by other reservations before ours
	 * succeeds, so the accumulated total may cover the need while the
	 * reservation still fails: keep asking for at least one segment and
	 * let the attempts cap bound the losses.
	 */
	shortfall = b->needed > b->freed ? b->needed - b->freed : 1;
	status = cache_reclaim(cache, shortfall, &freed);
	if (status == CACHE_RECLAIM_GIVEUP) {
		_HA_ATOMIC_INC(&cache->stats.reserve_fail_giveup);
		goto fail;
	}

	b->freed += freed;
	b->attempts++;
	if (status == CACHE_RECLAIM_PROGRESS)
		b->busy = 0;
	else
		b->busy++;
	if (b->attempts >= CACHE_RESERVE_ATTEMPTS) {
		_HA_ATOMIC_INC(&cache->stats.reserve_fail_attempts);
		goto fail;
	}
	if (b->busy >= CACHE_RESERVE_MAX_BUSY) {
		_HA_ATOMIC_INC(&cache->stats.reserve_fail_busy);
		goto fail;
	}
	if (b->needed > b->freed + (CACHE_RESERVE_ATTEMPTS - b->attempts)) {
		_HA_ATOMIC_INC(&cache->stats.reserve_fail_infeasible);
		goto fail;
	}
	return 0;

fail:
	_HA_ATOMIC_INC(&cache->stats.reserve_fails);
	return -1;
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
	uint64_t *slotp, slot;

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

void *cache_peek_at_mut(const struct cache *cache, const struct cache_rhandle *h,
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

/* This one doesn't call into cache_peek_at_mut() to avoid walking the segment
 * chain with seg_chain_nth() when dealing with jumbo entries.
 */
void *cache_peek_mut(const struct cache *cache, const struct cache_rhandle *h,
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

const void *cache_peek_at(const struct cache *cache, const struct cache_rhandle *h,
                          size_t off, size_t *len)
{
	return cache_peek_at_mut(cache, h, off, len);
}

const void *cache_peek(const struct cache *cache, const struct cache_rhandle *h,
                       size_t *len)
{
	return cache_peek_mut(cache, h, len);
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

	ht_iter_init(&it, cache);
	while ((slotp = ht_iter_next_tag(&it, &key->hash, &slot)) != NULL) {
		h = seg_read_pin(cache, &key->hash, slotp, &slot, 0);
		if (CACHE_HANDLE_ERR(h))
			continue;

		HA_ATOMIC_CAS(slotp, &slot, 0);

		seg_read_unpin(cache, &cache->segments[h.seg_id]);

		/* Keep scanning: racing first-time stores of the same key can
		 * leave more than one live slot for it, and a purge must be
		 * deterministic - remove every copy.
		 */
	}
}

struct cache_whandle cache_reserve(struct cache *cache, const struct cache_key *key,
                                   size_t data_len, time_t expire, uint flags)
{
	struct cache_whandle h;
	struct cache_record *rec;
	struct cache_reclaim_budget budget;
	struct ttl_bucket *ttlb;
	size_t total_len;
	size_t req_len = data_len;
	unsigned int n_segs;
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

		if (data_len > cache->arena_len ||
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

	/* Small entries are always admitted, and never enter the filter, whose
	 * window then covers only the keys it arbitrates. Unknown-length
	 * entries cost at least a private segment, so they face it too.
	 */
	if (!(flags & CACHE_RESERVE_ALWAYS) &&
	    (req_len == 0 || req_len >= cache->cfg.admit_min_size) &&
	    !cache_admit(cache, key)) {
		_HA_ATOMIC_INC(&cache->stats.admit_rejects);
		return CACHE_WHANDLE_NULL;
	}

	ttl = expire - date.tv_sec;
	if (ttl > CACHE_TTL_MAX)
		ttl = CACHE_TTL_MAX;
	ttlb = ttl_bucket_get(cache, ttl);

	/* Mirror ttl_bucket_reserve()'s segment count so the retry budget
	 * knows how many segments this reservation is waiting for.
	 */
	if (total_len > cache->cfg.seg_size)
		n_segs = (total_len + cache->cfg.seg_size - 1) / cache->cfg.seg_size;
	else
		n_segs = 1;

	cache_reclaim_budget_init(&budget, n_segs);
	while (1) {
		h = ttl_bucket_reserve(cache, ttlb, total_len);
		if (!CACHE_HANDLE_ERR(h))
			break;

		/* The bucket had no segment to give: try to reclaim. */
		if (cache_reclaim_try(cache, &budget) != 0)
			return CACHE_WHANDLE_NULL;
	}

	rec = CACHE_HANDLE_REC(cache, &h);
	rec->rec_len = data_len;
	rec->expire = expire;
	rec->hash = key->hash;

	return h;
}

int cache_write(struct cache *cache, struct cache_whandle *h,
                const void *data, size_t len)
{
	struct cache_record *rec;
	struct seg *seg, *head, *tail;
	struct cache_reclaim_budget budget;
	unsigned int n_segs;
	seg_id_t seg_id;
	size_t need;

	BUG_ON_BAD_HANDLE(cache, h);

	rec = CACHE_HANDLE_REC(cache, h);

	if (cache->cfg.max_obj_size > 0 &&
	    (len > cache->cfg.max_obj_size ||
	     h->data_off > cache->cfg.max_obj_size - len))
		return -1;

	if (len > CACHE_REC_CAPACITY(rec) - h->data_off) {
		head = &cache->segments[h->seg_id];
		if (cache->flags & CACHE_F_NO_JUMBO || !(head->flags & SEG_F_NO_LEN))
			return -1;

		if (len > cache->arena_len)
			return -1;

		/* If we are trying to write past the bounds of a record in the
		 * case of an unknown length reservation and if jumbo entries
		 * are allowed, we need to attempt to grow the reservation by
		 * acquiring one or more segments.
		 */
		need = len - (CACHE_REC_CAPACITY(rec) - h->data_off);
		n_segs = (need + cache->cfg.seg_size - 1) / cache->cfg.seg_size;

		/* If the last write completely filled the last segment, then
		 * h->cur_seg_id would be CACHE_SEG_NONE, so we walk the chain
		 * to find back the last valid segment.
		 */
		if (h->cur_seg_id == CACHE_SEG_NONE)
			seg_id = seg_chain_nth(cache, h->seg_id, head->n_chain - 1);
		else
			seg_id = h->cur_seg_id;
		tail = &cache->segments[seg_id];

		/* Get the segments, evicting or expiring our way to enough
		 * room when the pool cannot supply them, with the same
		 * accounting as cache_reserve(). Reclaim can never free the
		 * entry being grown: its head is write-pinned, so at worst
		 * it elects it and comes back empty-handed.
		 */
		cache_reclaim_budget_init(&budget, n_segs);
		while ((seg_id = seg_free_pop(cache, n_segs)) == CACHE_SEG_NONE) {
			if (cache_reclaim_try(cache, &budget) != 0)
				return -1;
		}
		rec->rec_len += (size_t)n_segs * cache->cfg.seg_size;
		tail->next_chain_id = seg_id;
		head->n_chain += n_segs;

		if (h->cur_seg_id == CACHE_SEG_NONE)
			h->cur_seg_id = seg_id;
	}

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

/* Abort a write. A private chain has no reader and sits in no list yet:
 * it goes straight back to the pool. Bytes reserved in a shared segment
 * lie dead until it is reclaimed.
 */
void cache_abort(struct cache *cache, const struct cache_whandle *h)
{
	struct seg *seg = &cache->segments[h->seg_id];

	BUG_ON_BAD_HANDLE(cache, h);

	_HA_ATOMIC_INC(&cache->stats.aborts);

	if (seg->flags & SEG_F_PRIVATE) {
		seg_write_unpin(seg);
		seg_free_push(cache, h->seg_id);
		return;
	}

	_HA_ATOMIC_ADD(&cache->stats.dead_bytes,
	               CACHE_OFF_ALIGN_UP(CACHE_HANDLE_REC(cache, h)->rec_len));
	seg_write_unpin(seg);
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
	cache_lock(&ttlb->lock);
	seg_list_append(cache, &ttlb->prv_segs, seg_id);
	cache_unlock(&ttlb->lock);
}

/* Finalize a write by publishing it. */
int cache_publish(struct cache *cache, const struct cache_whandle *h)
{
	struct ht_iter it;
	struct cache_rhandle rh;
	struct cache_record *rec;
	struct ht_bucket *b[2];
	struct seg *seg;
	uint64_t *slotp, slot;
	uint64_t old;
	uint32_t mask;
	uint16_t tag;
	int nfree[2];
	int i, j;

	BUG_ON_BAD_HANDLE(cache, h);

	rec = CACHE_HANDLE_REC(cache, h);
	seg = &cache->segments[h->seg_id];

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
	slot = CACHE_SLOT_MAKE(tag, h->seg_id, h->seg_off);

	/* First look for an existing entry with the same key and replace it
	 * in place, so that a key only ever has one live slot: a re-store of
	 * a known key (e.g. refreshing an expired entry) must supersede the
	 * old copy, not leave it indexed next to the new one. If we lose the
	 * replacement CAS, we retry the same slot rather than falling through:
	 * the value can only have changed to a concurrent store of this very
	 * key (which we must supersede too, one winner), to empty, or to an
	 * unrelated tag - the latter two let us resume the scan.
	 */
	ht_iter_init(&it, cache);
	while ((slotp = ht_iter_next_tag(&it, &rec->hash, &old)) != NULL) {
		do {
			rh = seg_read_pin(cache, &rec->hash, slotp, &old, 0);
			if (CACHE_HANDLE_ERR(rh))
				break;
			/* Same key, verified: supersede it. A replaced live
			 * copy is a concurrent store's loser, counted as dead
			 * bytes; a replaced expired one is a plain refresh.
			 */
			if (HA_ATOMIC_CAS(slotp, &old, slot)) {
				struct cache_record *oldrec = CACHE_HANDLE_REC(cache, &rh);

				if (seg->flags & SEG_F_PRIVATE)
					cache_publish_private(cache, h->seg_id);
				if (date.tv_sec < oldrec->expire) {
					_HA_ATOMIC_INC(&cache->stats.publish_supersedes);
					_HA_ATOMIC_ADD(&cache->stats.dead_bytes,
					               CACHE_OFF_ALIGN_UP(oldrec->rec_len));
				}
				seg_read_unpin(cache, &cache->segments[rh.seg_id]);
				seg_write_unpin(seg);
				return 0;
			}
			seg_read_unpin(cache, &cache->segments[rh.seg_id]);
		} while (old != 0 && CACHE_SLOT_TAG(old) == tag);
	}

	/* Find a free item slot. Between the two candidate buckets, prefer the
	 * one with more free slots: two-choice hashing only delivers its
	 * load-factor benefit when inserts favor the emptier bucket, and a
	 * more balanced fill defers the day both buckets are full - a failed
	 * publish permanently wastes the reserved bytes. The counts are racy,
	 * but they only steer the scan order; the CAS decides.
	 */
	mask = cache->index.n_buckets - 1;
	b[0] = &cache->index.buckets[rec->hash.high64 & mask];
	b[1] = &cache->index.buckets[rec->hash.low64 & mask];
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

			/* We found a free slot, try to claim it. */
			if (!HA_ATOMIC_CAS(&bkt->slot[j], &slot2, slot))
				continue;

			if (seg->flags & SEG_F_PRIVATE)
				cache_publish_private(cache, h->seg_id);
			seg_write_unpin(seg);
			return 0;
		}
	}

	/* We didn't find a free slot. A private chain, in no list yet, goes
	 * back to the pool; bytes reserved in a shared segment are dead space,
	 * as data may already sit past them.
	 */
fail:
	_HA_ATOMIC_INC(&cache->stats.publish_fails);

	if (seg->flags & SEG_F_PRIVATE) {
		seg_write_unpin(seg);
		seg_free_push(cache, h->seg_id);
		return -1;
	}
	_HA_ATOMIC_ADD(&cache->stats.dead_bytes,
	               CACHE_OFF_ALIGN_UP(rec->rec_len));
	seg_write_unpin(seg);
	return -1;
}

void cache_get_stats(const struct cache *cache, struct cache_stats *stats)
{
	stats->admit_rejects = _HA_ATOMIC_LOAD(&cache->stats.admit_rejects);
	stats->admit_inserts = _HA_ATOMIC_LOAD(&cache->stats.admit_inserts);
	stats->admit_rotations = _HA_ATOMIC_LOAD(&cache->stats.admit_rotations);
	stats->reserve_fails = _HA_ATOMIC_LOAD(&cache->stats.reserve_fails);
	stats->reserve_fail_giveup = _HA_ATOMIC_LOAD(&cache->stats.reserve_fail_giveup);
	stats->reserve_fail_attempts = _HA_ATOMIC_LOAD(&cache->stats.reserve_fail_attempts);
	stats->reserve_fail_busy = _HA_ATOMIC_LOAD(&cache->stats.reserve_fail_busy);
	stats->reserve_fail_infeasible = _HA_ATOMIC_LOAD(&cache->stats.reserve_fail_infeasible);
	stats->reclaim_calls = _HA_ATOMIC_LOAD(&cache->stats.reclaim_calls);
	stats->reclaim_elect_losses = _HA_ATOMIC_LOAD(&cache->stats.reclaim_elect_losses);
	stats->reclaim_blocked = _HA_ATOMIC_LOAD(&cache->stats.reclaim_blocked);
	stats->reclaim_no_candidate = _HA_ATOMIC_LOAD(&cache->stats.reclaim_no_candidate);
	stats->publish_fails = _HA_ATOMIC_LOAD(&cache->stats.publish_fails);
	stats->read_pin_fails = _HA_ATOMIC_LOAD(&cache->stats.read_pin_fails);
	stats->segs_expired = _HA_ATOMIC_LOAD(&cache->stats.segs_expired);
	stats->segs_evicted = _HA_ATOMIC_LOAD(&cache->stats.segs_evicted);
	stats->publish_supersedes = _HA_ATOMIC_LOAD(&cache->stats.publish_supersedes);
	stats->aborts = _HA_ATOMIC_LOAD(&cache->stats.aborts);
	stats->dead_bytes = _HA_ATOMIC_LOAD(&cache->stats.dead_bytes);
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
		if (slot != 0) {
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
