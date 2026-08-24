/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef _CACHE_STORAGE_H
#define _CACHE_STORAGE_H

#include <haproxy/xxhash.h>

/* Cache configuration flags */
#define CACHE_F_NO_JUMBO        (1 << 0)	/* Disable jumbo entries */
#define CACHE_F_REQUIRE_LEN     (1 << 1)	/* Require length for reservations */
#define CACHE_F_NO_ADM_FILTER   (1 << 2)	/* No admission filter */

/* Upper bound on entry TTLs: the engine clamps larger TTLs down to this
 * (about 12 days). Reserving with an expire this far ahead means the entry
 * lives until capacity reclaims it.
 */
#define CACHE_TTL_MAX           (1 << 20)

/* Largest cache a slot's location can address. */
#define CACHE_MAX_TOTAL_SIZE    (1ULL << 47)

/* Largest segment a slot's offset field can address. */
#define CACHE_SEG_MAX_SIZE      (8ULL * 1024 * 1024)

/* Flags for cache_reserve() */

/* Bypass admission filter, only meaningful if the cache was created without the
 * CACHE_F_NO_ADM_FILTER flag, in which case it allows us to decide whether to
 * use the admission filter on a per-entry basis.
 */
#define CACHE_RESERVE_ALWAYS    (1 << 0)

/* These are only defined here for the sake of the handle definitions. */
#define CACHE_SEG_NONE          (-1)

typedef int32_t seg_id_t;

/* Macros to deal with handles generically. */
#define CACHE_HANDLE_INIT(h)    do { (h).seg_id = CACHE_SEG_NONE; } while(0)
#define CACHE_HANDLE_ERR(h)     ((h).seg_id == CACHE_SEG_NONE)

/* These 4 structures are defined publicly only to avoid unnecessary memory
 * allocations. They must be treated as opaque and never modified directly.
 *
 * There are two identical handle structures for reads and writes; this is not
 * an oversight. The set of functions expecting or returning read/write handles
 * is disjoint, so having two different types allows the compiler to prevent
 * using them with the wrong functions at compile-time.
 */
struct cache_rhandle {
	size_t data_off;
	seg_id_t seg_id;
	seg_id_t cur_seg_id;
	uint32_t seg_off;
};

struct cache_whandle {
	size_t data_off;
	seg_id_t seg_id;
	seg_id_t cur_seg_id;
	uint32_t seg_off;
};

struct cache_iter {
	uint32_t idx;
};

struct cache_key {
	XXH128_hash_t hash;
};

/* Optional configuration tunables. 0 means default. */
struct cache_config {
	size_t max_obj_size;
	size_t mean_obj_size;
	uint32_t seg_size;
	size_t admit_min_size;
};

/* Cache activity counters, all monotonic. Read with cache_get_stats(). */
struct cache_stats {
	uint64_t admit_rejects;   /* Stores refused by the admission filter */
	uint64_t admit_inserts;   /* Keys recorded by the admission filter */
	uint64_t admit_rotations; /* Admission filter generation rotations */
	uint64_t reserve_fails;   /* Reservations abandoned: reclaim found no room in time */
	uint64_t reserve_fail_giveup;     /* ... because no listed segment was left:
	                                   * all free, unpublished or condemned */
	uint64_t reserve_fail_attempts;   /* ... because the attempts cap was reached */
	uint64_t reserve_fail_busy;       /* ... because consecutive rounds made no progress */
	uint64_t reserve_fail_infeasible; /* ... because the shortfall exceeded the rounds left */
	uint64_t reclaim_calls;       /* Reclaim scans started */
	uint64_t reclaim_elect_losses;/* Elected victims lost to a concurrent reclaimer */
	uint64_t reclaim_blocked;     /* Elected victims skipped: pinned by a writer */
	uint64_t reclaim_no_candidate;/* Scans that found segments but no electable victim */
	uint64_t publish_fails;   /* Publishes refused: index full or entry incomplete */
	uint64_t read_pin_fails;  /* Read pins abandoned: the entry's slot kept being
	                           * rewritten by same-key stores or deletes */
	uint64_t publish_supersedes; /* Publishes that replaced a live entry of the same key */
	uint64_t aborts;             /* Reservations abandoned unpublished */
	uint64_t dead_bytes;         /* Bytes left dead in segments until reclaim */
	uint64_t segs_expired;    /* Segments reclaimed at expiry */
	uint64_t segs_evicted;    /* Live segments evicted to make room */
};

struct cache;

/* Create a cache instance of <total_size> bytes. The <cfg> and <name>
 * parameters can be NULL. If <cfg> is NULL, default configuration values will
 * be used. If <name> is NULL, the memory region allocated for the cache won't
 * be named. <seed> seeds the hashing of the keys it is addressed with:
 * instances a key is shared across must be created with the same one. Returns
 * NULL if a parameter is invalid or if an allocation fails.
 */
struct cache *cache_new(const struct cache_config *cfg, uint flags,
                        size_t total_size, uint64_t seed, const char *name);

/* Destroy a cache instance. */
void cache_destroy(struct cache *c);

/* Hash a key using <c>'s hashing function. This function exists because the
 * choice of the hashing function is private to this implementation.
 *
 * The computed hash (cache_key) can then be used to reference entries.
 */
void cache_hash(const struct cache *c, const void *key,
                uint32_t key_len, struct cache_key *key_hash);

/* Lookup an entry in the cache. Returns a cache handle that can be used to read
 * that entry with cache_read() and/or cache_peek() if found. If the entry is
 * not found, this function returns an error cache handle. The handle should be
 * checked using the CACHE_HANDLE_ERR macro to determine whether the entry has
 * been found.
 *
 * If the entry was found, the handle must be released with cache_release(),
 * regardless of whether it was read or not. This ensures it does not remain
 * pinned in the storage, permanently wasting space.
 */
struct cache_rhandle cache_lookup(struct cache *c, struct cache_key *key);

/* Copy up to <len> bytes of an entry's data into <buf>, starting at the
 * handle's current read position, and advance that position. Returns the number
 * of bytes copied. Short reads only happen at the end of the entry, so a return
 * value smaller than <len>, including 0, means the end was reached.
 */
size_t cache_read(const struct cache *c, struct cache_rhandle *h,
                  void *buf, size_t len);

/* Copy up to <len> bytes of an entry's data into <buf>, starting at the
 * absolute offset <off>, without using or moving the handle's read position.
 * Returns the number of bytes copied; as with cache_read(), a short return
 * means the end of the entry was reached.
 */
size_t cache_read_at(const struct cache *c, const struct cache_rhandle *h,
                     size_t off, void *buf, size_t len);

/* Adjust the handle's read position, as used by cache_read(). <off> and
 * <whence> work like fseek()'s, relative to the entry's data: SEEK_SET,
 * SEEK_CUR and SEEK_END are all supported. Returns the resulting absolute
 * position, so cache_seek(c, h, 0, SEEK_CUR) reads the current one. Seeking
 * outside of the entry's data is a bug (BUG_ON); an unknown <whence> leaves
 * the position unchanged and returns it.
 */
size_t cache_seek(const struct cache *c, struct cache_rhandle *h,
                  ssize_t off, int whence);

/* Zero-copy read interface: return a pointer to the entry's data at the current
 * read position, and store the length of the contiguous bytes available there
 * in <len>. Returns NULL with a zero <len> when we're at or past the end of the
 * entry's data. The pointer stays valid until the handle is released with
 * cache_release().
 */
const void *cache_peek(const struct cache *c, const struct cache_rhandle *h,
                       size_t *len);

/* Like cache_peek(), except that we read at the absolute offset <off> into the
 * entry's data instead of the current read position.
 */
const void *cache_peek_at(const struct cache *c, const struct cache_rhandle *h,
                          size_t off, size_t *len);

/* Variants of the cache_peek functions that return a non-const pointer. These
 * exist for the rare cases where the caller needs to change the contents of
 * live entries. Callers are entirely responsible for thread-safety when using
 * these functions, since there can be multiple concurrent readers. Misusing
 * these functions can also easily cause corruption, for instance if data is
 * written out of the bounds of the entry. Do not use these unless you are
 * absolutely sure you need them.
 */
void *cache_peek_mut(const struct cache *c, const struct cache_rhandle *h,
                     size_t *len);
void *cache_peek_at_mut(const struct cache *c, const struct cache_rhandle *h,
                        size_t off, size_t *len);

/* Release the handle once done reading an entry. The handle is not valid
 * anymore once this function has been called, and should not be reused.
 */
void cache_release(struct cache *c, const struct cache_rhandle *h);


/* Attempt to reserve <data_len> bytes from the cache to store an entry. This
 * returns a cache handle that must be checked with CACHE_HANDLE_ERR to tell
 * whether the reservation succeeded or not. Upon completion of the write, the
 * entry must be either abandoned with cache_abort() or published with
 * cache_publish(). As with cache_lookup(), failure to do so will permanently
 * leak data from the cache.
 *
 * It is possible to pass a length of 0, for cases where the length isn't known
 * in advance, unless the cache was created with the CACHE_F_REQUIRE_LEN flag.
 *
 * <expire> is the entry's absolute expiry in wall-clock seconds and must be in
 * the future. <flags> accepts CACHE_RESERVE_ALWAYS to bypass the admission
 * filter, without which a key is only admitted on its second sighting.
 */
struct cache_whandle cache_reserve(struct cache *c, const struct cache_key *key,
                                   size_t data_len, time_t expire, uint flags);

/* Write (append) data to an entry after a successful reservation. Returns 0 on
 * success, or -1 in case of an out-of-bounds write. The error is mostly useful
 * when a reservation's size was not known in advance (cache_reserve() was
 * called with a size of 0): in that case, the caller shouldn't be expected to
 * keep track of the length itself. A failed write leaves the reservation
 * unchanged; the caller remains responsible for completing or aborting it.
 */
int cache_write(struct cache *c, struct cache_whandle *h,
                const void *data, size_t len);

/* Publish an entry once we are done writing it. Publishing supersedes any
 * previously published entry with the same key, so a re-store refreshes it;
 * concurrent publishes of the same key are safe, one copy wins and any stray is
 * eventually reclaimed. Returns 0 on success, -1 otherwise. Failure can happen
 * if no index slot could be claimed, or if trying to publish an entry that has
 * not been completely written. In all cases, the handle is not valid anymore
 * once this function has been called, and should not be reused.
 */
int cache_publish(struct cache *c, const struct cache_whandle *h);

/* Abandon an entry. The handle is not valid anymore once this function has been
 * called, and should not be reused.
 */
void cache_abort(struct cache *c, const struct cache_whandle *h);

/* Remove an entry from the cache. */
void cache_delete(struct cache *c, const struct cache_key *key);

/* Proactively reclaim space held by expired entries. This is never required
 * for correct operation: entries are expired or evicted on demand as
 * reservations need room. It is offered so a caller can trigger reclamation at
 * a convenient time (for instance, when the system is idle), so that future
 * reservations have less work to do. Reclamation is best-effort and not
 * guaranteed to remove every expired entry.
 */
void cache_expire(struct cache *c);

/* Retrieve a snapshot of the cache's activity counters. */
void cache_get_stats(const struct cache *c, struct cache_stats *stats);

/* Return the exact length of the entry's data. */
size_t cache_entry_size(const struct cache *c, const struct cache_rhandle *h);

/* Return the entry's expiration date in wall clock time. */
uint32_t cache_entry_expire(const struct cache *c, const struct cache_rhandle *h);

/* Return the key of an entry. */
const struct cache_key *cache_entry_key(const struct cache *c, const struct cache_rhandle *h);

/* Iterate over all the entries in the cache, and invoke <cb> for each one. The
 * <it> iterator must be zeroed before the first call. The callback can yield
 * and stop the iteration by returning a non-zero value. The operation can then
 * be resumed by calling this function again, passing the same iterator. If the
 * callback yields, the current entry is not considered consumed and iteration
 * will resume on that same entry. Returns 0 when all entries have been seen, or
 * the return value of the callback if it yielded.
 *
 * The <data> pointer can be used to relay state to the callback.
 *
 * The handle passed to the callback is pinned, and can be safely used for any
 * read operation, or for calling the cache_entry accessors. It will be unpinned
 * automatically after the callback returns. Most other functions are not safe
 * to be called from the callback. Generally speaking, because of the const
 * qualifier on the cache pointer, it should not be possible to call any unsafe
 * function from there, unless a non-const pointer is smuggled through the data
 * pointer, or accessible another way. However, that should not be understood as
 * any kind of guarantee.
 */
typedef int (*cache_foreach_cb_t)(const struct cache *c, const struct cache_rhandle *h, void *data);

int cache_foreach(struct cache *c, struct cache_iter *it, cache_foreach_cb_t cb, void *data);

#endif /* _CACHE_STORAGE_H */
