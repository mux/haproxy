# 2026-08-18 - HTTP cache storage design

This document explains and justifies the design of the HTTP cache's storage
engine (`src/cache_storage.c`). It is written for developers working on the
cache: it records *why* each choice was made, not just what the code does. It is
also the authoritative description: the comment at the top of the source file is
only a short map of the main departures.

The engine is a ground-up rewrite of the HTTP cache's storage layer, driven by
performance and, above all, scalability: as core and thread counts keep
climbing, the previous shctx-based storage -- with its process-wide write lock
-- became the bottleneck. The new engine is loosely modelled on [Segcache][seg]
(NSDI '21) and, more precisely, on its maintained implementation, the cache-rs
Rust crate, whose readers are fully lock-free. The basic structure is theirs; we
diverge from both wherever the HTTP use case differs from the small-object
key-value cache they target, and those divergences are the interesting part --
they are called out throughout.

## Goals and constraints

- **Scalability.** The primary driver. Serving cached content must scale with
  HAProxy's thread count, which means reads must not contend on a shared lock.
- **Performance.** The common paths (lookup, reserve, publish) are cheap, and
  the hot path avoids needless atomics and cold-cacheline touches.
- **Bounded memory.** The cache lives within a fixed, operator-configured budget
  and stays inside it by construction: a fixed arena, bounded index and
  metadata, and eviction to hold the line. Per-entry overhead is a small,
  predictable fraction, and the segment size is auto-tuned (below) to keep
  internal waste low.
- **Constraint: never block the event loop.** HAProxy is event-driven, so
  stalling a thread -- even briefly on a spinlock waiting for slow I/O -- stalls
  every connection it owns.

## A log-structured segment store

The arena is divided into fixed-size **segments**. A segment is an append-only
run of records: a write advances a cursor, and individual records are never
moved or freed in place. Reclamation happens one whole segment at a time, which
is what keeps it cheap -- there is no per-record free list, no compaction, and
no fragmentation within a segment's live region.

An entry normally lives entirely inside one segment. Entries whose size is not
yet known when their space is reserved, and entries too large for a single
segment, instead get segments of their own; both cases are covered under
*Private segments* below.

Two different limits bound the segment size. The hard ceiling is 8 MB, set by
the slot layout: a slot encodes a record's offset within its segment in 20 bits
of 8-byte units. Below that the engine sizes segments from the configured
capacity, and `segment-size` overrides it.

This log-structured shape is the core idea taken from Segcache. Its consequences
-- no in-place mutation, segment-granularity reclaim, and no relocation of live
data -- drive most of the decisions below, so they are worth keeping in mind
throughout.

## Keys: digest identity and the hash function

The paper does not concern itself with adversarial traffic. We have to: a cache
in front of the open Internet answers to clients nobody controls, and this
section is where that shows.

An entry is identified by a seeded 128-bit XXH3 digest of its key (the URL --
and, for the variants of a varying resource, a derivation of it described under
*Vary* below). The full key is never stored: by the time a response is cached
the request buffer that held the URL is usually gone, so keeping it would mean
holding a variable-length copy per in-flight entry, where the digest is a flat
sixteen bytes. A match is confirmed by comparing digests, not keys, as the old
cache did with SHA-1.

The digest has three jobs, each asking something different of the hash. As
identity it must make a false match -- two keys landing on the same bits --
vanishingly rare; 128 bits, spread evenly by XXH3's avalanche, sit far below any
rate worth a thought. As a placement key it need only furnish two bucket indices
-- bits it has in abundance. And it must resist prediction, which is the one
property a fast hash cannot supply by itself, and the subject of the rest of
this section.

The old cache had the same three jobs and met them with SHA-1, identifying
entries by a 160-bit digest rather than by the key itself. Those extra 32 bits
bought nothing in practice: 128 is already far past the collision rate worth a
thought. What SHA-1 quietly did do was the third job, since, having no seed, the
design leaned on the hash's one-wayness to keep its digests both unpredictable
and unforgeable.

That unpredictability now comes from a per-process random seed rather than from
the strength of the hash -- the same guarantee at a fraction of the cost, and
never a matter of correctness: without a seed -- or any other secret to keep the
hash unpredictable -- the cache would serve every request exactly the same. Its
only job is to blunt two attacks that matter once the cache faces clients you
don't control. Placement is the lesser, and needs nothing privileged: query
strings alone mint endless distinct keys, so any client can aim as many as they
like at a single bucket. The damage is bounded, though -- even a full pair of
candidate buckets is only sixteen slots to scan, two cachelines, so the pile-up
never becomes a slow walk. Poisoning is the graver, and the real point of the
seed: predict the digest and you can forge a key colliding with a victim's, then
-- given some way to plant your own entry, which a multi-tenant cache affords --
have your content served under their URL, something nothing else here would
catch.

The engine takes the seed when an instance is created, so instances need not
share one. HAProxy gives all of its caches the same seed, because a request
hashes its key once and may use it against several of them -- two `cache-use`
rules can match one transaction, and a configured cache is itself two engine
instances, the store and the early-hints store -- long after the URL it came
from is gone.

## The hash index: two-choice, tagged slots

Lookups go through a hash table of 64-byte buckets, each holding eight 64-bit
slots -- one bucket to a cacheline. A slot is a packed reference to a record:
its segment id and offset, plus a **tag** -- the top bits of the digest, cached
in the slot itself.

- **Two-choice hashing.** A key maps to two candidate buckets, one from each
  half of the digest. This spreads load and tolerates hot buckets far better
  than a single choice, at the cost of probing two buckets on a miss. cache-rs
  makes the count configurable up to eight, defaulting to two; here the two
  halves of the digest give two for free.
- **A full bucket pair fails the insert.** With all sixteen slots taken the
  publish fails and the entry is not cached, which keeps the index a flat, fixed
  array with no pointer-chasing. Full pairs are rare with two choices, and the
  failure costs the bytes already reserved for the record, which stay dead until
  their segment is reclaimed.
- **The tag.** Before touching a record, a lookup compares the slot's tag to the
  key's. Only on a tag match does it pin the segment -- an atomic increment of
  the segment's reference count plus a sequentially consistent load -- and read
  the record's (cold, separate) cacheline to confirm the full digest. A tag
  mismatch skips *all* of that: not just the cacheline miss, but the costly
  atomics of pinning. Since most candidates in a well-distributed table do not
  match, this is a large saving.

An all-zero slot means "empty", so a live slot is kept non-zero by construction
-- one always-set bit outside the tag and location fields. This lets the empty
check be a single comparison against zero.

## Concurrency & scalability

The index itself is lock-free: slots are accessed only with atomics -- a lookup
loads a slot atomically, and publish, delete, and expiry update slots with a
compare-and-swap. The spinlocks in the engine guard segment bookkeeping (the
TTL-bucket segment lists, byte reservation, the free-segment pool), never the
index and, with the one exception below, never reads.

Reads take no lock at all. A reader pins the target segment (a reference count),
re-reads the index slot to confirm nothing changed under it, then checks that
the segment's `state` is still `SEG_S_LIVE` before trusting the record.

Safety rests on a Dekker-style pairing -- two variables, each side setting its
own and then reading the other's. The reader increments the read reference
count, then re-reads the slot; reclamation clears the index slots, then reads
the reference count. Either the reader observes the cleared slot and treats the
entry as gone, or the reclaimer observes the pin, so a record is never recycled
under a reader. Both sides must use sequentially consistent atomics: the
ordering relies on a store followed by a load on each side being globally
ordered, which acquire/release does not give. HAProxy's `HA_ATOMIC_*` load and
store macros are only acquire/release, so this code adds `_SEQ_CST` variants of
them -- thin local wrappers over the raw `__atomic` builtins.

The `SEG_S_LIVE` check that follows is serve policy rather than safety: once the
pin is taken and the slot re-checked, reclamation is guaranteed to observe the
pin and condemn the segment rather than recycle it, so the check only decides
whether to serve from a segment on its way out. `cache_delete()` skips it, so
that a purge cannot miss an entry whose segment is transiently draining.

Segcache keeps a per-item frequency counter in the hash slot, which its eviction
consults to score entries (below). Eviction here never looks at per-item
frequency, so the counter is gone from the slot entirely: a read is a pure
sequence of loads, with no write to shared slot state on the hot path and no
reader-versus-reader contention.

One narrow exception keeps the no-lock claim honest: a segment reclaimed while
readers still hold pins is *condemned* and handed to its last reader, whose
release then completes the reclaim -- including a brief, bounded acquisition of
the free-pool spinlock. This is the only lock any read path can ever touch; it
is taken at most once per condemned segment, by one reader, and never makes a
reader wait on other readers.

Writing an entry's content is lock-free as well; the only locked step in a store
is reserving its space. Reserving holds the TTL-bucket spinlock just long enough
to link a segment if needed and advance the write offset, then releases it. The
byte copy that follows runs with no lock held, into a reserved, non-overlapping
range guarded by a write pin -- a reference count, the write-side mirror of a
reader's pin -- and the publish is a compare-and-swap into the index. So the
lock carves out the space and is never held while the payload is copied in --
the never-block-the-event-loop constraint applied to the write path.

That lock is deliberately coarser than the Rust implementation's, where it
protects only the list links and the byte reservation itself is lock-free. That
is a lot of complexity for parallelism on a couple of loads and stores. It pays
at the scale they run, where thousands of small entries fit in one segment and
reservations are constant; it does not for an HTTP cache, where a segment holds
tens of entries and every reservation is followed by a comparatively enormous
streamed copy that takes no lock at all.

## TTL buckets and expiration

Segments are grouped into **TTL buckets** by the remaining lifetime of the
entries written to them. Within a bucket, segments are filled in creation order,
so the oldest segment is always at the head and -- since all entries in a bucket
share roughly the same TTL -- is also the first to expire. Expiry is therefore a
cheap walk from the head: reclaim expired head segments and stop at the first
fresh one.

The bucket array is a fixed 1024 entries, and a TTL in seconds maps to one with
a find-last-set and a shift -- no per-object state. Those 1024 buckets form four
tiers of 256. Buckets within a tier are evenly spaced, and each tier is 16 times
coarser than the one below it, so with the same 256 buckets a tier spans 16x the
time range of its predecessor:

- tier 0 -- 1s per bucket, TTLs up to ~4 min;
- tier 1 -- 16s per bucket, up to ~1 h;
- tier 2 -- ~4 min per bucket, up to ~18 h;
- tier 3 -- ~68 min per bucket, up to the ~12-day ceiling.

A TTL is rounded *down* to its bucket's class, so the class is never later than
any entry filed under it and bulk expiry errs early, never late; TTLs past the
ceiling clamp to the last bucket. The fine low tier gives short-lived entries
precise expiry where it matters most, while long-lived entries coalesce into the
coarse high tiers -- keeping the number of segments held open for writing small
even under TTL-diverse traffic. That number is one per active bucket for the
shared queue, plus whatever private segments the bucket's unknown-length and
jumbo entries own.

Expiry is not required for correctness, on two counts. A stale entry is never
*served* regardless, because lookup checks freshness on the record and treats an
expired entry as a miss. And the *space* is reclaimed even without expiry:
eviction (next section) reclaims segments under pressure whether or not their
entries have expired.

So why expire at all? Not to spare live data: a reservation that must free space
already tries expiry before it evicts anything (see below), so a background
sweep changes nothing there. Its value is cost, and it lands on future
reservations: an expired segment returned to the free pool ahead of demand is
one the next writer takes directly, instead of paying inline for the scan that
on-demand reclamation runs. Expiry is thus a throughput optimization --
opportunistic background work that keeps that scan off the hot path -- not a
correctness mechanism, which is why it can be lazy and needs no per-object
timers (there would be far too many). The engine exposes it as `cache_expire()`
for a caller that wants to spend an idle moment on it.

## Eviction: FIFO over whole segments

When the cache is full and nothing has expired, eviction reclaims a live segment
to make room. The policy is plain FIFO -- reclaim in creation order -- chosen
deliberately over cleverer schemes.

The justification is the [S3-FIFO][s3] result (SOSP '23): across thousands of
production traces, including the web and CDN workloads closest to ours, the
decisive factor in eviction quality is not a smart recency or frequency policy
but the prompt removal of **one-hit wonders** -- objects requested once and
never again. A plain FIFO paired with a small admission filter (next section)
matches far more elaborate policies at this. FIFO's blindness to per-item value
costs little once the one-hit wonders are kept out, and it buys a reclaim path
that amounts to clearing a segment's index slots and dropping it.

We deliberately do **not** use Segcache's merge-based eviction, nor an
S3-FIFO-style promotion between queues -- Segcache scores entries with a
per-item frequency counter (the ASFC) and merges the hot ones into compacted
segments, dropping the cold. Both relocate live items between segments,
reintroducing exactly the copying and drain-and-wait coordination this design
avoids -- and their benefit is concentrated in the many-tiny-items-per-segment
regime, the opposite of HTTP's large, variable objects. Whole-segment FIFO is
also what production HTTP caches converge on (for example Apache Traffic
Server's circular storage), so this is a well-trodden path, not a shortcut.

A reservation that finds no free segment frees one in two steps, tried in order:

- **Expire first.** Reclaiming an expired segment is free -- its data is already
  dead -- whereas evicting a live one destroys useful content, so the reserve
  path first walks the chain heads for expired segments to reclaim, draining a
  chain's whole expired prefix when it finds one so the extra segments feed
  other reservations.
- **Then evict the oldest.** With nothing expired, a live segment goes. Because
  each chain ages head-first, the globally oldest segment is always one of the
  chain heads -- 2048 of them, a shared and a private queue for each of the 1024
  TTL buckets. The scan takes the oldest head that is not write-pinned:
  unindexing has to parse a segment's record headers to walk it, and a write pin
  means one of those headers is still being written. Read pins are no obstacle
  at all; a segment reclaimed under them is condemned and handed to its last
  reader. We pick the true oldest rather than sampling a few candidates for an
  approximate one.

## Admission: keeping one-hit wonders out

The filter's rule is simple: an object is not cached on its first sighting, only
on its second, so one-hit wonders never occupy a segment at all.

This is standard practice for HTTP and CDN caches, not an invention:

- [Akamai][ak] caches an object only on its second request, detecting the repeat
  with a Bloom filter; they report that about three-quarters of objects are
  one-hit wonders and that filtering them freed a comparable fraction of cache.
- [nginx][ng] exposes exactly this as `proxy_cache_min_uses` -- cache only after
  N requests -- commonly set to 2.
- [TinyLFU][tlfu] is the sophisticated end of the same idea: a frequency sketch
  admits a newcomer only if it looks more valuable than the entry it would
  evict.

We use the simple Akamai/nginx form: a binary "seen once before".

### A pair of rotating Bloom filters

The filter is a classic Bloom filter in two generations, the same construction
[Akamai][ak] describes. A cacheable miss probes both: found in either, the key
is admitted; found in neither, it is recorded in the current generation and
rejected. The generations rotate by insertion count -- when the current one has
absorbed its capacity of keys, the stale one is cleared and the roles swap --
so a first sighting is remembered for at least one and at most two generations'
worth of subsequent recordings, and the filter never saturates. A key found
only in the previous generation is re-recorded into the current one, so a key
that keeps being seen keeps being remembered.

Each generation is sized for twice the cache's expected object count, since the
filter also absorbs sightings of objects that are never stored, at 16 bits and
eight derived probe positions per key -- a false-positive rate of about 0.06%
per generation at capacity, and a false positive only admits an object one
sighting early. The two generations are the halves of a single allocation,
about 0.1% of the arena.

The structure is monotone between rotations, which makes concurrency cheap:
probes are relaxed loads, recordings relaxed atomic bit-ORs, and a race costs
at most an occasional extra reject. Rotation elects a single winner -- the
thread whose recording reaches the capacity count -- so it cannot double-fire
and wipe both generations; the ordering details live with the code.

### Validation on real traces

We measured end-to-end FIFO-cache hit ratio on a synthetic Zipfian
(skewed-popularity) workload and two real traces: a Twitter key-value trace
from [libCacheSim][lcs] (see also the [Twitter cache
traces][tw]) and a Wikipedia CDN trace from the [LRB dataset][lrb]. The table
reports the two real traces.

| Trace (cache size)   | no filter | with filter |
| -------------------- | --------- | ----------- |
| Wikipedia CDN (10%)  | 48.2%     | 52.9%       |
| Twitter KV (5%)      | 72.9%     | 67.0%       |

Two findings:

- **Admission is workload-dependent.** On the Wikipedia CDN trace (one-hit
  wonders were 21% of requests) it lifts hit ratio by three to five points; on
  the Twitter key-value trace (one-hit wonders only 6.5% of requests) it *hurts*
  by about six points, because there the cost of delaying every object's caching
  outweighs the little junk there is to filter. HTTP and CDN traffic is the
  former case, which is why the filter is on by default -- but it is a config
  flag precisely because the value depends on the workload.
- **Cache-on-second is the hit-ratio optimum.** Sweeping "cache on the Nth
  request" showed N of 2 best; higher N only helps reduce disk writes, which is
  irrelevant for an in-memory cache.

Caveats worth knowing: the simulation counts objects, not bytes, so size-aware
admission would likely help more on CDN traffic than these numbers suggest; the
real traces are single prefixes.

## Private segments: unknown sizes and jumbo entries

Not every entry's size is known when its space must be reserved: an HTTP
response without a Content-Length header starts arriving before its total size
is knowable, and buffering it in full just to measure it would defeat streaming.
Such an entry is reserved with a size of zero and receives a **private
segment**: a segment owned by that single entry, whose record grows as chunks
are written and whose true length is fixed only when the entry is published.
Records in shared segments are laid out back-to-back at reservation time and
have no such freedom, which is why the two kinds do not mix: each TTL bucket
keeps two segment queues, shared and private, and reclamation visits both in
creation order.

Private segments are also what makes entries larger than a segment possible.
When a write runs past the end of a private entry's reservation, the engine
takes more segments from the free pool and splices them onto the tail of the
entry's chain. A **jumbo** entry is one that has grown this way, or one whose
known length exceeded a segment and was reserved as a chain in one step: either
way, a chain of segments private to that single entry.

That is a deliberate departure from both Segcache implementations, which simply
refuse to cache an object larger than a segment. HTTP object sizes vary
enormously -- from tiny API responses to large media -- so refusing the large
ones is not acceptable. A store is refused only when the entry would exceed
`max-object-size`, when jumbo entries are disabled on the instance, or when
reclaim cannot supply the segments.

A chain costs contiguity: a jumbo entry's payload is no longer one contiguous
run, so serving it means gathering across segments. A cache large enough to
store jumbo entries also has large segments, so that cost is mostly amortized.
The other cost is space, the tail of the last segment in the chain, treated
under *Arena utilization* below.

Reading across a chain needs no validation of its own: a chain is reclaimed and
freed as a unit through its head, so the reader's pin on the head covers every
link in it.

## The API: an HTTP-agnostic engine

The engine stores and returns opaque byte records keyed by a digest, and knows
nothing about HTTP. All HTTP logic -- cacheability rules, freshness, the
response filter, the serving applet, Vary -- stays in `src/cache.c`, which
drives the engine in place of shctx. This layering was not required by anything;
it is a structural choice that paid off: the HTTP glue in `cache.c` is reused
untouched, the engine can be tested in isolation, and swapping the storage is
mostly a matter of replacing shctx calls with engine calls.

Entries stream in over time -- a response can take a while to arrive from origin
-- so a store is not a single copy but a sequence: **reserve** space, **write**
chunks into it, then **publish** it into the index. Reads similarly stream out
to what may be a slow client, over seconds. Each side is driven by an opaque
handle returned by the engine.

The read and write handles are distinct types even though they carry the same
fields (a record location plus a `data_off` cursor into the record's payload).
Keeping them separate lets the compiler reject, say, publishing a read handle --
a cheap guard on a protocol that is otherwise easy to get subtly wrong. The
cursor lives in the handle so the caller streams chunks without tracking an
offset itself.

## Vary: anchors, generations, and variant selection

When a response varies on request headers, one URL maps to several cached
variants. The engine needed almost nothing for this -- the design lives in
`cache.c`, as the layering intended -- but it is recorded here because it solves
two problems a flat digest index seems to preclude: invalidating every variant
of a URL at once, and serving a variant to any client able to accept it, not
only to clients who ask exactly alike.

A varying URL's digest maps to an **anchor** entry instead of a response. The
anchor records which headers the resource varies on and a random 64-bit
**generation**; each variant is an ordinary, independent entry under a key
derived from the primary digest, the vary signature, the generation, and a
normalized digest of the request's varying headers. Whole-URL invalidation is
then one operation: delete or supersede the anchor and every derived key becomes
unreachable together -- the orphaned variants age out with their segments, which
the log-structured shape treats as routine. The generation must be random per
anchor incarnation, never a counter: the anchor itself is a cache entry and can
be evicted, and a counter reborn at the same value would resurrect the orphaned
variants of a previous life -- stale content reappearing after an invalidation.
(This is the namespace-versioning idiom from the memcached world; the randomness
requirement is what an evictable anchor adds to it.)

Accept-Encoding needs one more idea. A stored variant is keyed by the response's
actual content coding, but a request offers a *set* of accepted codings, and a
hash lookup answers only exact questions. Most peers duck this: Varnish, nginx
and Squid key variants by the operator-normalized request header -- exact match,
no sharing across differently-phrased requests. The old cache did better,
walking the URL's variants and serving any whose codings the client could
decode. To keep that containment matching over an exact-match index, the anchor
carries a small, fixed **directory** of the coding masks of the variants stored
so far (its occupancy bounded by `max-secondary-entries`), and a lookup probes
one derived key per directory mask the client fully accepts -- one or two probes
in practice. Directory slots are written once and claimed by CAS inside the
*published* anchor: the single place the design relaxes entry immutability, done
through an explicitly writable accessor so the exception stays visible in the
code. Apache Traffic Server's per-URL alternate vectors are the one peer
precedent for this shape.

The engine's entire contribution to all of the above: a per-reservation flag to
bypass the admission filter -- an anchor must never be turned away, since no
variant can be stored without it -- and the writable peek. Everything else is
composition.

## Early hints

103 Early Hints live in a *separate, smaller* cache instance dedicated to hints,
sized by `early-hints <on|off|only> [ratio N]` as N percent of the configured
total, 25 by default. The hints instance is created with no admission filter
at all: a hint is created deliberately by the store path, never admitted from
request traffic, so the instance-level opt-out also spares the filter's
memory. When a response carrying `Link` hints is cached, a hints-only entry is
written under the request's primary key; on a miss for the main entry the
hints are replayed as a 103 while the origin is queried, and a hit needs none.
Hint entries are reserved with the engine's maximum TTL rather than the
response's expiry, so
they deliberately outlive its freshness: a 103 is most valuable exactly when
the response has expired and an origin round-trip is coming, and a stale hint
is harmless -- RFC 8297 makes hints advisory.

This matches how CDNs (Cloudflare, Fastly, Akamai) handle cached early hints,
and gives hints a direct memory budget instead of the old cache's ratio-based
demotion of full entries. That in-place demotion is not portable here anyway: it
is an entry-granularity shrink, which the no-relocation design cannot do
cheaply. The one downside is that the `Link` data is duplicated (once in the
main entry, once in the hints store); hints are tiny, so this is an accepted,
negligible cost.

## Memory usage

Two things are worth weighing separately: the overhead of the auxiliary
structures, and how efficiently the arena itself is filled.
### Auxiliary structures

The old cache threads its index through the arena: each object is prefixed by a
`cache_entry` -- on the order of 150-200 bytes -- holding the eb-tree node (one
of 256 sharded trees), two list links for LRU and cleanup, a secondary key, and
assorted timing and ETag fields. Apart from 256 empty tree roots there is no
separate index memory; the tree lives inside the objects.

Our per-object overhead splits across the two layers and is far leaner: the
engine's `cache_record` -- digest, expiry, length; about thirty bytes -- plus
the HTTP layer's `cache_entry` prefix stored as ordinary payload (the Vary key,
validators, and ETag location; about fifty more). A FIFO cache needs no recency
links, and the index node is not embedded here. The index is instead a separate
hash table (the counterpart of those 256 trees), sized as described above,
alongside the admission filter and one small descriptor per segment; the
three together come to well under one percent of the arena. The free-space
bookkeeping -- shctx's list of available blocks versus our free pool and
per-bucket segment chains -- is negligible on both sides.

Most of the index now sits outside the arena in compact fixed arrays rather than
competing with payload for block space.

### Arena utilization

shctx hands out storage in fixed 1 KB blocks, and an object is a private chain
of them. It therefore pays a ~44-byte header on every block, and -- since
objects never share a block -- loses the unused tail of its last block, up to
nearly a full kilobyte. That rounding loss is a large fraction of a small object
and a negligible one of a large object.

An object that fits in a single segment packs contiguously with no per-object
rounding; its only slack is the dead tail left when the next object will not fit
and a segment rolls over, which amortized across a multi-megabyte segment is a
fraction of a percent. (Expired or superseded records also sit dead until their
segment is reclaimed, one whole segment at a time.) Here utilization runs well
above shctx's, most of all for small objects that shctx would round up to a
whole block.

Jumbo objects are the exception, and the design's weak spot. A jumbo entry owns
a private chain of segments, so the tail of its last segment -- up to almost a
whole segment, potentially megabytes -- is wasted and cannot be reused. It is
the same rounding shctx suffers, but at segment rather than block granularity,
so for an object only just past a segment boundary it can waste considerably
more than shctx's 1 KB blocks would. The loss is bounded by the segment size and
shrinks the more segments an object spans.

Segment size is where all of this meets: larger segments waste proportionally
less in every tail, smaller ones make reclaim finer-grained and chained reads
less fragmented. The auto-derived default aims for a low waste fraction at the
expected object size.

## Future work

Three items are known and deliberately deferred.

- **Reclaim scanning.** `cache_reclaim()` scans all 1024 TTL buckets, locking
  every non-empty one, to find a segment to expire or the best eviction
  candidate, and may run again when its victim was blocked by writers.
  Measured under adversarial in-process load this is not the bottleneck it
  looks like: reservations essentially never fail, even with objects arriving
  back-to-back from memory with no network to pace them. The margin is
  structural: unindexing costs a few memory accesses per record, while
  storing that record cost at least the object's copy and a round of request
  processing -- far more. Both scale with the same memory system, so a
  machine runs out of capacity to store objects long before it can congest
  the scan that reclaims their space. The `reserve_fail_*` counters are
  there to prove it either way in production; if they ever climb, this can
  be addressed by replacing the scan with a reclaim list to which segments
  are appended as they fill.

- **The write tail under a single TTL class.** When nearly all entries share
  one TTL bucket, writers queue behind evictions on that bucket's lock:
  unindexing a full segment holds it for a few microseconds up to a few
  hundred, in proportion to its record count, which inflates write tail
  latency without failing anything. The hold is bounded by the segment size,
  so `segment-size` already caps it. The fix is to unindex outside the lock,
  after the victim is unlinked from its bucket list: the orderings that
  protect readers never depended on the lock, unlinking replaces it as the
  barrier against new writers, and the condemned handoff keeps its two-phase
  check.

- **Scheduled expiry.** Nothing calls `cache_expire()` yet: expired segments
  are reclaimed inline, by the reservation that needs their space. A periodic
  call from a housekeeping task would keep the free pool stocked ahead of
  demand, taking the reclaim scan and its bucket-lock holds off the store
  path whenever traffic expires faster than it evicts. It would also release
  the index slots of expired entries earlier, since slots are only freed when
  their segment is reclaimed, lowering index pressure near capacity. The walk
  costs tens of microseconds, so even a one-second period is negligible.

## References

- Segcache (NSDI '21): [usenix.org][seg]
- S3-FIFO (SOSP '23): [dl.acm.org][s3], overview at [s3fifo.com][s3o]
- Akamai one-hit-wonder filtering (ACM CCR '15): [dl.acm.org][ak]
- nginx `proxy_cache_min_uses`: [nginx.org][ng]
- TinyLFU (ACM ToS '17): [dl.acm.org][tlfu]
- Twitter cache traces: [github.com][tw]
- libCacheSim: [github.com][lcs]
- LRB / Wikipedia trace: [github.com][lrb]

[seg]: https://www.usenix.org/conference/nsdi21/presentation/yang-juncheng
[s3]: https://dl.acm.org/doi/10.1145/3600006.3613147
[s3o]: https://s3fifo.com/
[ak]: https://dl.acm.org/doi/10.1145/2805789.2805800
[ng]: https://nginx.org/en/docs/http/ngx_http_proxy_module.html
[tlfu]: https://dl.acm.org/doi/10.1145/3149371
[tw]: https://github.com/twitter/cache-trace
[lcs]: https://github.com/1a1a11a/libCacheSim
[lrb]: https://github.com/sunnyszy/lrb
