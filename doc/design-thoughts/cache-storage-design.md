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
is what keeps it cheap -- there is no per-record free list or in-place
compaction. Dead records stay in the log until their segment is reclaimed.

An entry normally lives entirely inside one segment. Entries whose size is not
yet known when their space is reserved, and entries too large for a single
segment, instead get segments of their own; both cases are covered under
*Private segments* below.

The segment size is derived, not configured directly: `mean-object-size`,
`segment-max-entries` and `total-max-size` determine it, and the product of the
first two is what selects the upper bound. Sizing targets 2048 segments, with a
lower target of 16 mean-sized objects per segment and at least 16 segments when
possible. It caps size at `segment-max-entries` (256 by default) times
`mean-object-size`, then rounds down to a power of two. Sizes that would leave a
segment below 4096 bytes, or below the size needed to fit the index's segment-ID
field, are raised instead. The hard ceiling is 8 MB, set by the slot layout: a
slot encodes a record's offset within its segment in 20 bits of 8-byte units, so
a larger `segment-max-entries` can reach it but no setting can exceed it.

This entry target limits segment-granularity work, not the actual number of
physical records: the configured mean is only an estimate, dead records still
cost work, and merging can traverse several source segments. Expiration,
eviction and merging all walk records without the bucket lock. A conservative
index estimate can also select smaller-than-desirable segments for large
responses. Raising `mean-object-size` or `segment-max-entries` widens that
ceiling; changing the entry target leaves index sizing alone.

This log-structured shape is the core idea taken from Segcache. Its consequences
-- no in-place mutation and segment-granularity reclaim and relocation -- drive
most of the decisions below, so they are worth keeping in mind throughout.

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

The previous cache likewise used digest identity, with 160-bit SHA-1 digests. It
also prefixed SHA-1 input with a per-process random seed. The new engine passes
that seed to XXH3 instead; seeding itself is not new to this conversion.

As before, the seed is intended to make digests and placement difficult to
predict. XXH3 is not a cryptographic hash, and a seed does not turn it into a
cryptographic MAC. Ordinary cache identity still rests on digest comparison;
seeding does not replace that check. The seed's only job is to blunt two attacks
that matter once the cache faces clients you don't control. Placement is the
lesser, and needs nothing privileged: query strings alone mint endless distinct
keys, so any client can aim as many as they like at a single bucket. The damage
is bounded, though -- even a full pair of candidate buckets is only sixteen
slots to scan, two cachelines, so the pile-up never becomes a slow walk.
Poisoning is the graver, and the real point of the seed: predict the digest and
you can forge a key colliding with a victim's, then -- given some way to plant
your own entry, which a multi-tenant cache affords -- have your content served
under their URL, something nothing else here would catch.

The engine takes the seed when an instance is created, so instances need not
share one. HAProxy gives all of its caches the same seed, because a request
hashes its key once and may use it against several of them -- two `cache-use`
rules can match one transaction, and a configured cache may have response,
Vary-anchor and early-hints instances -- long after the URL it came from is
gone.

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
  reservation fails and the entry is not cached, which keeps the index a flat,
  fixed array with no pointer-chasing. Full pairs are rare with two choices.
  The reservation checks for a free slot before taking any space, so only a
  slot taken in between costs reserved bytes, which stay dead until their
  segment is reclaimed.
- **The tag.** Before touching a record, a lookup compares the slot's tag to the
  key's. Only on a tag match does it pin the segment -- an atomic increment of
  the segment's reference count plus a sequentially consistent load -- and read
  the record's (cold, separate) cacheline to confirm the full digest. A tag
  mismatch skips *all* of that: not just the cacheline miss, but the costly
  atomics of pinning. Since most candidates in a well-distributed table do not
  match, this is a large saving.

An all-zero slot means "empty", so the offset field counts 8-byte units from one
rather than zero, and is never 0 in a used slot. No record starts in a segment's
last unit, its header would not fit, so this costs no range. The empty check is
then a single comparison against zero.

An entry is indexed when its space is reserved, with a pending bit set until
it is published. Lookups, purges and listings skip pending slots, and only the
entry's writer changes or clears one: publishing clears the bit, aborting
clears the slot. A pending slot always names a segment its writer pins, so
reclamation never meets one. A reservation that finds a pending slot with its
key's tag declines, so concurrent misses on one URL store it once instead of
each reserving a full copy. A tag match is enough there, as a false one only
skips a store.

## Concurrency & scalability

The index itself is lock-free: slots are accessed only with atomics -- a lookup
loads a slot atomically, and publish, delete, and expiry update slots with a
compare-and-swap. The spinlocks in the engine guard segment bookkeeping: the
TTL-bucket segment lists, byte reservation and free-segment pool. Index access
requires no index lock. Reclamation unlinks a victim from its bucket list under
the bucket lock, which keeps new writers out, then clears its slots without the
lock: the orderings that protect readers below never depended on it. With the
one exception below, reads never take a lock.

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

The slot also carries Segcache's per-item frequency counter (the ASFC) in seven
bits between the location and the pending bit. It counts hits, so it starts at 0
when a record is published or relocated by a merge: the records of a merged
segment then compete on the hits they gather from that point, and a record that
stopped being hot cannot outlive its popularity by several merges. A served hit
bumps it with a single compare-and-swap -- exactly for the first sixteen hits,
then with probability 1/count, so a hot entry soon stops rewriting its slot --
and a lost bump is dropped: the counter is approximate. A reader revalidating
its pin ignores the counter bits, and the compare-and-swaps that clear or
replace a slot retry while it still names the same record.

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

Reclamation also releases the bucket lock during a merge. Under that lock it
claims the source IDs and a destination, then scores, copies and updates index
slots without holding it. Claims prevent source reuse and appending even when an
expired successor makes a source the new tail; they also protect the published
but not yet linked destination. Finalization reacquires the lock, uses current
boundary links, releases unused claims and performs the normal
reader-condemnation handoff. Purges that empty claimed segments defer their
cleanup until the owner can safely finalize them.

Only one merger owns a TTL bucket at a time. Different buckets may merge
concurrently, but there is no maintenance mutex or waiting queue for a merger.
This does not make reclaim free: the caller still performs the merge's CPU work
synchronously, and reservations and finalization can still contend on the bucket
lock.

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

## Eviction: merging segments by frequency

When the cache is full and nothing has expired, eviction must free live
segments. The engine does what [Segcache][seg] does: it merges a run of
neighbouring segments into one, copying the records worth keeping and dropping
the rest. Space is still freed a whole segment at a time, but the choice of what
survives is made per record.

Each record carries the hit counter kept in its index slot (see *The hash
index*). Its score is its hits divided by its size relative to the segment's
mean record size: a record earns its place by being read again, and a large one
must be read more often than a small one to earn the same. A merge takes from
two to eight consecutive segments, walks their records in order and copies into
the destination those whose score exceeds a cutoff, adjusted as the copy
proceeds so that a quarter to a third of each source's bytes survive, until the
destination is nine-tenths full. A record that was never read again scores zero
and goes first. That is what keeps **one-hit wonders** -- objects requested once
and never again -- out of the cache, and the [S3-FIFO][s3] study of thousands of
production traces found their prompt removal to be the decisive factor in
eviction quality, ahead of any recency or frequency subtlety. The destination
takes the sources' place in the bucket's list and inherits their age, and each
copied record's counter starts again from zero, so the next merge judges it on
what it earns from now on. Carrying part of the count forward keeps records that
stopped being popular ahead of newcomers, and retained less on production
traces.

A reservation, or a growth step of a private entry, needs one segment, and
reclaims in units that are never interrupted: expiring or evicting a segment or
a private chain, or a whole merge. A reclaim budget of 1024 records bounds how
many units it runs. It counts the physical records those units examine,
including dead and aborted ones, and the scans of the TTL buckets: a scan reads
every bucket head, which costs about as much as 16 records on x86, plus a record
for every four buckets it locks and searches. The first unit always starts, so
that every reservation can make progress; later ones start only while the
budget lasts, and the last one may overrun it. A reservation therefore walks at
most the budget plus one unit, the largest being a merge. Lock waiting is not
bounded. `cache_expire()` still walks full expired prefixes.

A reservation short of free segments reclaims space in two steps:

- **Expire first.** Within each TTL bucket, visit private chains before shared
  segments. Once demand is satisfied, keep expiring while the budget lasts: the
  records are unindexed once either way, and each segment freed early spares a
  later reservation a scan. Writer-pinned segments are skipped. Reader-pinned
  segments are unindexed and condemned: they cost their records but do not
  supply free segments yet. No live data is evicted to free segments early.
- **Then evict from one queue.** If expiration falls short, budget allowing,
  elect a queue and a safe victim in it. Each bucket has a shared and a private
  queue. Within a bounded 64-descriptor search of each queue, skip claimed and
  write-pinned segments, then elect one queue across buckets: see *Which queue
  gives up space* and *What leaves the elected queue* below. Unindexing parses
  record headers, so a write pin means a candidate cannot be reclaimed safely. A
  private candidate is a chain owned by one entry and can only be evicted whole.
  A shared candidate hands its bucket to the merge, which examines up to sixteen
  segments from where the previous merge stopped, then, if needed, up to sixteen
  from the head towards that resume point. A run already in progress may finish
  across it, rechecking at most two segments. Without a distinct resume point,
  it examines up to 32 from the head. A run needs at least three consecutive
  eligible segments: neither the write tail nor being written, and more than
  twenty seconds from expiry. They are merged into a destination taken from a
  small reserve of `reserved-segments` segments, defaulting to min(nbthread, 4)
  further capped at a 64th of the segment count (floored at one), that ordinary
  reservations leave alone so a merge can always run. The destination keeps its
  oldest source's creation time, so that it expires no later than any record it
  holds. The sources return to the pool, unless a reader still pins them, in
  which case they are condemned and their return is delayed until that reader
  unpins -- which is why a burst of merges can want more destinations than there
  are concurrent merges, and why `merges_no_dst` and `segs_condemned` are
  reported. Without a run or destination, use a bounded safe FIFO victim only
  when no merger is active in the arena. If any bucket's merger is producing
  supply, decline storage instead of evicting useful content or waiting for it,
  unless the victim expires within twenty seconds: it could not be merged and
  has little left to give. Read pins do not block reclamation; a victim held by
  readers is condemned and handed to its last reader. With `reserved-segments
  0`, ordinary reservations may consume the entire pool: no destination is held
  aside. Merging is still attempted, and succeeds whenever a segment happens to
  be free when the merge needs one; it is just more likely to find none and fall
  back to whole-segment eviction. The separate `CACHE_F_NO_MERGE` flag disables
  merging explicitly.

Refusal is a capacity decision, not a popularity filter. It applies only after a
reservation and bounded expiration fail to provide usable space and the elected
bucket cannot start a useful merge. Before declining, try reserving space once
more: a new shared tail or free segment may already satisfy the request. If that
reservation fails and mergers remain active, abandon only the cache copy; the
HTTP response continues normally. If all mergers ended, resume ordinary bounded
reclamation. Free means available beyond the merge reserve for this request, not
merely a nonzero free-list count. No timer, completion-counter polling or retry
burst waits for supply to appear.

This preserves existing content at the cost of declining some new stores and can
slow learning after a working-set change. Hit-rate measurements must count
refused stores as misses, rather than divide only by hits and successful stores.

A merge that retains nothing hands its destination back, and once such merges
outnumber the successful ones, later merges copy every live record: on a cache
whose segments are mostly dead, scoring would only drop the little that is still
alive.

Dead segments do not wait for either step. A shared segment whose stores were
all aborted, or whose last indexed object was deleted or replaced, can never be
read again, so it is reclaimed as soon as it is neither the bucket's tail nor
being written or claimed: at the abort, delete or supersede that emptied it, or,
for a full tail, when the next reservation rolls over to a new one, which then
gets the same segment straight back from the pool. Without this, a client that
keeps aborting a large download -- a health check fetching a big file every
second is the real-world case -- fills the cache with dead segments at its own
pace and pushes live ones out ahead of them.

A reservation scans again when contention left it short: another reservation
took the freed segment, the victim was pinned, or an election was lost. Every
scan is charged to the budget, so a reservation that keeps losing segments to
others gives up once it is spent. A merge is a single unit: stopping it early
would leave its destination half empty, so the budget never cuts it short. Each
retry uses the pool's current supply rather than a cumulative count that other
reservations may already have consumed.

### Which queue gives up space

Each eviction takes a segment from one queue, so the choice of queue, repeated
at every eviction, is what divides the cache's memory between the queues: the
shared and the private one of every TTL bucket.

The aim is to give every object the same time in the cache, whichever queue
holds it. That is what a single queue over the whole cache would do, and it
favours no size or TTL over another. Memcached at [Facebook][fb] pursues the
same aim between its slab classes: it moves memory to a class whose next victim
was used more recently than the others', so that the oldest items have the same
age in every class.

That method reads the age of the item a queue is about to evict, which tells how
long the queue keeps its content only if the queue evicts in order of age.
Neither kind of queue does here. A merge leaves the records it keeps in their
sources' place, under the oldest source's creation time, and a private eviction
leaves in place the chains it spares. The head of a queue can therefore be far
older than what the queue is giving up. Ranked by it, a queue would lose memory
for keeping its popular content.

The time a queue gives its content can be computed instead of read. A queue that
holds 1000 segments and receives ten per second keeps a segment for 100 seconds
on average. This is [Little's law][ll], and it holds whatever order the segments
leave in. The election compares this **retention time**: the segments a queue
holds, divided by the segments stored in it per second. The queue with the
longest one gives up space.

The count is in segments, not in bytes of live records. Memory is what the
election divides, and a queue holds memory by the segment: a segment costs its
full size whatever is still alive in it. Counted in live bytes, a queue whose
records were deleted or replaced in place would look smaller than the memory it
occupies, and would be spared for wasting it. A byte count would also have to
follow every record indexed or unindexed, which happens outside the bucket's
lock. The segment count only changes when a segment joins or leaves a queue,
under that lock.

The retention time has three properties that the age of a segment lacks:

- **It gives every object the same time.** Taking space from the queue with the
  longest retention time shortens it, so all queues settle at the same one. Each
  then holds its store rate times that time: a queue receiving a third of what
  is written to the cache gets a third of its memory.
- **It keeps the two choices apart.** The records a merge retains and the chains
  an eviction spares change neither a queue's size nor its store rate. What a
  queue keeps is decided within its share of memory and takes nothing from the
  other queues.
- **It moves smoothly.** An eviction changes a queue's size by a few segments.
  The age of a head jumps whenever the head changes, and an election ranked by
  it swings between queues in long runs.

A shared queue's retention time is halved before the comparison, so shared
queues settle at twice the retention time of private ones. Shared queues hold
the objects that fit in a segment and private queues the larger ones, so this
moves memory from large objects to small ones: more objects are kept, which
raises the hit ratio and can lower the byte hit ratio. The divisor,
`CACHE_SHARED_AGE_DIV`, sets that balance. At one, small and large objects are
kept equally long; below one, large objects are kept longer.

The store rate is counted per second and averaged exponentially over a window as
long as the retention time itself, bounded between one second and 4096, and of
sixty seconds until a retention time is known. A chain counts for every segment
in it. A merge destination is not a store: it replaces its sources. A second
without a store counts as zero: the rate of an idle queue decays, its retention
time grows, and it gives its memory up to the queues still being written. A
queue without a measurable rate is ranked as if its retention time were the age
of its candidate.

### What leaves the elected queue

Neither kind of queue simply gives up its head.

A shared queue is merged, as described above. Each merge resumes where the
bucket's previous one stopped, so successive merges sweep the queue from oldest
to newest and start over. Age only decides when a segment comes up; the score of
each record decides whether it survives.

A private queue holds chains, and a chain is owned by a single entry: it is kept
whole or evicted whole, and there is nothing to merge. The queue is swept the
same way, by a hand that resumes where the previous eviction stopped and wraps
from the newest chain to the oldest. For each chain, the hand reads the hit
counter of its entry:

- **Not hit** since the hand last passed, or since it was stored: the chain is
  evicted, and the hand stops there.
- **Hit**: the chain is spared. Its counter restarts from zero, it stays where
  it is, and the hand moves on. It must be hit again before the hand comes back
  to be spared again.

After eight chains spared in a row, or when every chain was hit, the least-hit
chain examined is evicted, the first on ties, so that an eviction stays bounded.
Each chain examined costs the reclaim budget one record. This is [SIEVE][sieve]
applied to chains. A single hit is enough to be spared: requiring more did worse
on the traces tried. A spared chain is not moved to the newest end either: the
queue stays in the order expiration walks it.

With `CACHE_F_NO_MERGE`, neither choice applies: every queue is a plain FIFO,
elected by the age of its head and evicted from it.

### Why not a popularity admission filter

Caching an object only on its second request is common practice for HTTP caches:
[Akamai][ak] does it with a Bloom filter and reports three-quarters of its
objects as one-hit wonders, and [nginx][ng] exposes it as
`proxy_cache_min_uses`. A FIFO cache needs it, having no other way to tell a
one-hit wonder from a popular object. Here the merge already drops a record that
was never read again at the first merge that reaches its segment, so a one-hit
wonder costs its space only until then. What a filter would add is its cost:
every object that does come back pays one extra origin fetch. Under FIFO that
cost was worth paying on a Wikipedia CDN trace ([LRB][lrb]), where the filter
gained three to five points of hit ratio, and already a loss of six points on a
[Twitter][tw] key-value trace with few one-hit wonders. With the frequency
signal inside the cache, the filter would only spare the space one-hit wonders
occupy until their first merge, and that does not buy back the delay.

## Private segments: unknown sizes and jumbo entries

Not every entry's size is known when its space must be reserved: an HTTP
response without a Content-Length header starts arriving before its total size
is knowable, and buffering it in full just to measure it would defeat streaming.
Such an entry is reserved with a size of zero and receives a **private
segment**: a segment owned by that single entry, whose record grows as chunks
are written and whose true length is fixed only when the entry is published.
Records in shared segments are laid out back-to-back at reservation time and
have no such freedom, which is why the two kinds do not mix: each TTL bucket
keeps two segment queues, shared and private, and expiration visits both in
creation order.

Most such entries turn out small once complete -- compressed pages and API
responses are the typical case -- and leaving each in a segment of its own would
cap the cache at one such entry per segment. So an entry that fits one segment
does not keep it once published. If its record fits in the free space of the
bucket's shared tail, it is copied there and its segment returns to the pool at
once; otherwise the segment itself becomes the new tail, its free space open to
the stores that follow, and the old tail is closed exactly as a rollover would
have closed it. Neither case takes a segment from the pool or evicts anything,
and the copy, when it happens, is a single memcpy on the writer's thread of
bytes written once already. Only chains stay private.

Private segments are also what makes entries larger than a segment possible.
When a write runs past the end of a private entry's chain, the engine takes more
segments from the free pool and splices them onto its tail. A **jumbo** entry is
one that has grown this way: of unknown length, or of a known length exceeding a
segment, which is reserved with its first segment only and grows the same way as
its data arrives. Either way, it is a chain of segments private to that single
entry. Growing one segment at a time gives each step the same budget, whatever
the entry's size, at the cost of a store that may fail partway, its data already
written.

That is a deliberate departure from both Segcache implementations, which simply
refuse to cache an object larger than a segment. HTTP object sizes vary
enormously -- from tiny API responses to large media -- so refusing the large
ones is not acceptable. A store is refused only when the entry would exceed
`max-object-size`, when jumbo entries are disabled on the instance, or when
reclaim cannot supply the segments, including temporary refusal while another
merger is producing space.

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

A varying URL's digest maps to an **anchor** entry in a separate metadata cache
instance. The response arena contains only plain responses and variants. Plain
hits use the primary digest directly; on a miss, lookup consults the anchor
store and derives candidate variant keys. The anchor records which headers the
resource varies on and a random 64-bit **generation**; each variant is an
ordinary, independent entry under a key derived from the primary digest, the
vary signature, the generation, and a normalized digest of the request's varying
headers. Whole-URL invalidation is then one operation: delete or supersede the
anchor and every derived key becomes unreachable together -- the orphaned
variants age out with their segments, which the log-structured shape treats as
routine. The generation must be random per anchor incarnation, never a counter:
the anchor itself is a cache entry and can be evicted, and a counter reborn at
the same value would resurrect the orphaned variants of a previous life -- stale
content reappearing after an invalidation. (This is the namespace-versioning
idiom from the memcached world; the randomness requirement is what an evictable
anchor adds to it.)

The metadata arena is sized by `vary-cache-size`, defaulting to one percent of
the response arena with a 64 KiB minimum. Fixed 4 KiB segments limit the number
of URL families lost through one eviction. Anchors contain only a generation,
Vary signature and coding-mask array, with no HTTP response header. The index
uses a small-object mean of at least 128 bytes to allow for storage metadata
rather than sizing from the compact payload alone. Merging is disabled in this
instance. Neither response pressure nor response segment sizing consumes its
capacity. Metadata still has a bounded budget and can evict families of its own.

Anchors start with the response's absolute expiry. Storing a longer-lived
variant extends the anchor by publishing a replacement with the same generation
and the maximum expiry. Reservation puts that copy in the appropriate
remaining-TTL bucket; no expiry or routing payload is mutated in place.

Accept-Encoding needs one more idea. A stored variant is keyed by the response's
actual content coding, but a request offers a *set* of accepted codings, and a
hash lookup answers only exact questions. The old cache walked the URL's
variants and served any whose codings the client could decode. To keep that
containment matching over an exact-match index, the anchor carries a small,
fixed **directory** of the coding masks of the variants stored so far (its
occupancy bounded by `max-secondary-entries`), and a lookup probes one derived
key per directory mask the client fully accepts -- one or two probes in
practice. A published anchor is never modified: a new mask is added by
publishing a copy of the anchor with the mask appended, which supersedes the
original under the primary key and keeps its generation, so the variants already
stored stay reachable. A per-cache writer lock in `cache.c` serializes anchor
lookup/update/publication against explicit invalidation and plain-response
publication. It prevents an old copy from reinstating an invalidated generation
and avoids lost concurrent mask additions. Readers never acquire it, and no
origin or client streaming is performed under it. Plain-to-Vary creation removes
the primary-key response; plain publication retires the Vary anchor. This is
metadata-operation coordination, not a request-start invalidation epoch: a GET
whose response arrives after an unsafe request can still establish a new family.
Apache Traffic Server's per-URL alternate vectors are a peer precedent for this
shape.

None of the above needs anything from the engine: it is all composition.

## Early hints

103 Early Hints live in a *separate, smaller* cache instance dedicated to hints,
sized by `early-hints <on|off|only> [size <bytes>]`, defaulting to a tenth of
the configured total -- or all of it in `only` mode, where nothing else is
stored. When a response carrying `Link` hints is cached, a hints-only entry is
written under the request's primary key; on a miss for the main entry the hints
are replayed as a 103 while the origin is queried, and a hit needs none. Hint
entries are reserved with the engine's maximum TTL rather than the response's
expiry, so they deliberately outlive its freshness: a 103 is most valuable
exactly when the response has expired and an origin round-trip is coming, and a
stale hint is harmless -- RFC 8297 makes hints advisory.

This matches how CDNs (Cloudflare, Fastly, Akamai) handle cached early hints,
and gives hints a direct memory budget instead of the old cache's ratio-based
demotion of full entries. That in-place demotion is not portable here anyway: it
is an entry-granularity shrink, which the segment-based design cannot do
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
validators, and ETag location; about fifty more). The store needs no recency
links, and the index node is not embedded here. The index is instead a separate
hash table (the counterpart of those 256 trees), sized as described above,
alongside one small descriptor per segment; the two together come to well under
one percent of the arena. The free-space bookkeeping -- shctx's list of
available blocks versus our free pool and per-bucket segment chains -- is
negligible on both sides.

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

Two items are known and deliberately deferred.

- **Reclaim scanning.** `cache_reclaim()` scans all 1024 TTL buckets, locking
  every non-empty one, to find a segment to expire or the best eviction
  candidate, and may run again when its victim was blocked by writers. This
  traversal and its acquisitions still cost foreground time even though bulk
  merging is unlocked. A reclaim list or expiration coalescing could avoid some
  scans. The `reserve_fail_*` counters distinguish deliberate active-merge
  admission refusal from other failures; a rising refusal count alone does not
  establish an insufficient cache size or a slow scan.

- **Scheduled expiry.** Nothing calls `cache_expire()` yet: expired segments are
  reclaimed inline, by the reservation that needs their space. A periodic call
  from a housekeeping task would keep the free pool stocked ahead of demand,
  taking the reclaim scan and its bucket-lock holds off the store path whenever
  traffic expires faster than it evicts. It would also release the index slots
  of expired entries earlier, since slots are only freed when their segment is
  reclaimed, lowering index pressure near capacity. The walk costs tens of
  microseconds, so even a one-second period is negligible.

## References

- Segcache (NSDI '21): [usenix.org][seg]
- S3-FIFO (SOSP '23): [dl.acm.org][s3], overview at [s3fifo.com][s3o]
- SIEVE (NSDI '24): [usenix.org][sieve]
- Scaling Memcache at Facebook (NSDI '13): [usenix.org][fb]
- Little's law (Operations Research '61): [doi.org][ll]
- Akamai one-hit-wonder filtering (ACM CCR '15): [dl.acm.org][ak]
- nginx `proxy_cache_min_uses`: [nginx.org][ng]
- Twitter cache traces: [github.com][tw]
- LRB / Wikipedia trace: [github.com][lrb]

[seg]: https://www.usenix.org/conference/nsdi21/presentation/yang-juncheng
[s3]: https://dl.acm.org/doi/10.1145/3600006.3613147
[s3o]: https://s3fifo.com/
[sieve]: https://www.usenix.org/conference/nsdi24/presentation/zhang-yazhuo
[fb]: https://www.usenix.org/conference/nsdi13/technical-sessions/presentation/nishtala
[ll]: https://doi.org/10.1287/opre.9.3.383
[ak]: https://dl.acm.org/doi/10.1145/2805789.2805800
[ng]: https://nginx.org/en/docs/http/ngx_http_proxy_module.html
[tw]: https://github.com/twitter/cache-trace
[lrb]: https://github.com/sunnyszy/lrb
