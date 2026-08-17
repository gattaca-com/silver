# Hash-result caching — exploration notes

Status: **exploratory**, branch `bronek/hash_caching_experiments`. Not a merge candidate;
the deliverable is lessons for the team about whether/where/how to cache cryptographic
hash results in silver.

Working method: every claim below is tagged **[verified]** (checked against code, a
measurement, or a primary source) or **[guess]** (plausible, unverified — do not build on
it without promoting it).

## The core motivation (confirmed by Bronek at kickoff)

Attestation traffic has extreme *value sharing*: tens of thousands of messages per slot
carry only a handful of distinct `AttestationData` values (one per committee per vote
variant). Every derived hash — tree root for pool keying, signing root for verification —
is therefore computed with **identical inputs thousands of times**. A cache keyed by a fast
hash of the input turns those repeats into lookups. This is the same structural fact
CL-112's same-message MSM fast path exploits for the pairing; here we ask what it buys for
the *hashing* around the pairing, and what data structure serves it at 50k msgs / 1–2 s on
≤ 16 cores.

## Motivating guesses (from kickoff)

1. ~~"A single cryptographic hashing call may cost ~1 ms" (per CL-112)~~ — **[verified: false as stated]**.
   CL-112's ~1 ms figure is the **BLS pairing verification** per attestation signature
   (`SigBatch` / blst multi-pairing territory), not a hash function call. SHA-256 of small
   inputs is expected in the hundreds-of-nanoseconds range — measurement in progress to pin
   the real numbers. The *conclusion* Bronek drew (lookup is 3–4 orders cheaper than the
   1 ms operation) still holds for the pairing, which is what CL-112 attacks via batching —
   a different tool than caching.
2. "Hashing happens all over the place" — **[guess]**, inventory in progress.
3. "`Immutable` is both a misnomer and design tension" — **[verified]**. See below.
4. "High performance requires hash caching" — **[guess]**; depends on (2) and on measured
   per-call costs. May be true for tree-hashing of large/repeated structures even if false
   for single small SHA-256 calls.
5. "We have cheap & fast hashing for table lookups" — **[verified]**: `fxhash` and
   `rustc-hash` are workspace deps used across crates (gossip, common, peer, columns,
   network, storage, engine, discovery, metrics).

## The `Immutable` finding (kickoff observation by colleague)

`crates/beacon_state/data/src/types.rs:182`. The struct mixes:

- **Truly immutable** data: `genesis_time`, `genesis_validators_root`, fork versions,
  `historical_roots` (frozen since Capella) + its precomputed `historical_roots_hash`.
- **A hand-rolled 5-entry cache**: `fork_data_roots: [(Version, B256); 5]`, refreshed by
  `refresh_fork_data_roots(&mut self, prev, cur)` on fork transitions
  (`decompose/common.rs:271`, `encode.rs:661`). Lookup (`fork_data_root`, types.rs:213) is
  a linear scan over 5 entries with a **recompute-on-miss fallback** (logged at debug).

So: both a misnomer and a design tension, exactly as guessed. The precompute itself was the
`compute_domain_roots` optimization (commit 38db1ff, PR #172). The tension is that the type
name promises frozen data but one field is epoch/fork-varying derived state — i.e. we used
the nearest convenient home as a cache rather than having a designated caching layer.

Lesson candidate #1: *the codebase already caches hash results ad hoc (fork_data_roots,
historical_roots_hash); the design question is whether ad-hoc precompute-at-known-refresh-
points is the right pattern (it is O(1), contention-free, and refresh points are known!) or
whether a general concurrent cache buys anything beyond it.*

## Context that bounds the design (from CL-112, verified against the ticket)

- Load target: ~50k attestations arriving in 1–2 s; ≤ 16 cores.
- The verify count is already minimized by seen-sets (one verify per attester/epoch);
  CL-111 shed aggregate-topic redundancy.
- CL-112's plan for the 1 ms pairing cost is **randomized batch verification + same-message
  MSM fast path** (singles for one committee share one `AttestationData` ⇒ one signing
  root ⇒ one pairing per data_root group). Note the implication for *hash* caching: the
  same sharing (few distinct `AttestationData` per slot vs. tens of thousands of messages)
  is what would give a signing-root/tree-root cache its hit rate.

## Back-of-envelope: what winning looks like — [guess, being measured]

Suppose per-message hashing is a few µs (tree root of `AttestationData` ≈ 10–15 SHA-256
compressions, signing root 2 more, gossip message-id one pass over ~240 B). Then 50k
messages ≈ 150–250 ms of single-thread hashing per burst — *material* against a 1–2 s
budget, but not the wall; the wall is the pairing (CL-112). A hash cache at ~99% hit rate
recovers most of that. Whether that's "significant obstacle removed" or "nice-to-have"
depends entirely on the measured per-call numbers — hence the measurement agent.

## Cache = the batcher's group index — [guess, to verify in design phase]

CL-112's same-message MSM fast path must **group pending tuples by signing/data root**
anyway. A map keyed by (fast hash of) `AttestationData` bytes with the tree root / signing
root as value is simultaneously (a) the hash-result cache and (b) the grouping index the
batch verifier needs. If so, the cache isn't a separate optimization competing with CL-112 —
it's a shared substrate, and its API should be designed for both consumers. This may be the
strongest argument for building it.

## Lesson candidate #2: the cache shape follows the sharing pattern

Q (Bronek): BLS verify is the single most expensive operation — does that make this
optimization specific to `AttestationData`?

A: BLS verify itself is **uncacheable** — the tuple (pubkey, signature, signing_root) is
unique per attester even when the message is shared, so no key ever repeats. Sharing is
exploited there by *batching/aggregation* (CL-112), not caching. Within hash caching, at
least three distinct sharing patterns exist, each wanting a different cache shape:

| domain | sharing pattern | natural cache shape | status |
| --- | --- | --- | --- |
| `AttestationData` tree/signing root | 50k msgs share ~10²–10³ distinct values within a slot | concurrent fast-hash-keyed map, slot-based eviction (the kickoff sketch) | the burst-problem customer; doubles as MSM group index |
| epoch committee shuffling | whole validator set re-shuffled per epoch (~90 SHA-256 rounds over the set); same output needed by many lookups all epoch | per-epoch snapshot, swapped at boundary (no concurrent mutation needed) | [guess] — does silver cache shufflings at all? inventory will tell |
| state tree-hashing | most state bytes unchanged slot-to-slot; same subtrees rehashed | incremental/memoized tree with dirty tracking | [guess] — state-hashing agent reporting |
| pubkey decompression (BLS-adjacent) | same validators verify msgs all epoch; G1 decompress ≈ tens of µs | decompressed-registry snapshot | [guess] — CL-112 hints it may already exist |

Sync-committee messages (hundreds of signers over one block root) would share the
`AttestationData` pattern — whether silver processes them yet is unverified.

## Research findings (map phase complete, 4 agents; measurements still in flight)

### Where the SHA-256 actually goes — ranked [verified against code]

1. **Full-state re-merkleization** — `hash_tree_root_state`
   (`crates/beacon_state/tile/src/ssz_hash.rs:58`), measured **~7.6 ms** per call
   (perf-harness ceiling `max_hash_tree_root_state_avg`), runs **once per process_slot +
   once per applied block** (post-state check). ~90k compressions per call, of which
   **~84k are the four merged rings** (randao_mixes 65536 + block_roots 8192 +
   state_roots 8192 + slashings 2048 chunks) rehashed from scratch although ≤1–2 buckets
   per ring change between calls (>99.99% identical leaves). Acknowledged `TODO(perf)` in
   the code ("milhouse-style persistent trees"). Bonus redundancy: the post-block hash and
   the next `process_slot`'s prev-state-root hash are computed over **byte-identical
   state** — 2 full hashes where 1 would do.
2. **Swap-or-not shuffling** — ~390k sha256/shuffle at ~1.1M validators (~15–40 ms), but
   **already cached** (`ShufflingCache`, 4 entries keyed `(epoch, randao_mix)`).
3. **Block-body hashing** (transactions dominate) — per block, largely irreducible content
   hashing, but issued as single-pair hashtree calls (see "batching" below).
4. **Gossipsub message-id** — one SHA-256 per unique message (~10–25 ms of one core per
   50k burst); duplicates already shed pre-decompression by an FxHash fast-dedup
   (`DedupCache.fast_sets`). Per-message-unique ⇒ **uncacheable**, already optimal shape.
5. **Attestation signing-root hashing** — see next section. Small per call.

### The attestation path per message [verified]

Per single attestation: ~5 compressions message-id (unique input) + **9 compressions
`hash_attestation_data`** + 1 compression signing root + **one hash-to-G2 hidden inside
`Signature::verify`** (expand_message_xmd ≈ 19 compressions + SSWU + cofactor clearing ≈
tens of µs). Domain: zero hashing (Immutable precompute). All dedup/pool keys are fast
hashes or bitmaps already.

**Sharper than the kickoff guess:** since Electra (EIP-7549) the committee index lives
*outside* `AttestationData` (`data.index` forced to 0 — `tile/gossip.rs:55-62`), so all
~50k attesters voting the same head sign **the identical 128-byte AttestationData — 1–3
distinct values per slot, not ~64**. Hit rate of any cache keyed on it: >99.99%.

Consequences, ranked by CPU recovered per 50k burst:
- **hash-to-G2 of the signing root: ~50k identical evaluations ≈ ~2 CPU-seconds/slot** at
  ~40 µs each — the largest non-pairing win on the whole path. Cacheable as
  `signing_root → blst_p2_affine` (2–8 entries/slot). Cost: requires dropping below blst's
  safe API (prehashed-point verify) — unsafe FFI where a DST mismatch silently verifies
  the wrong message. High value, high care.
- **data_root + signing_root memo: ~460k compressions ≈ 25–50 ms CPU/burst** — the simple
  win. Key: raw 128 AttestationData bytes → `(data_root, signing_root)`; 2–4 entries/slot.
- **Aggregate path re-hashes the inner AttestationData twice** (`gossip.rs:224` then again
  inside `hash_tree_root_aggregate_and_proof`, `ssz/src/ssz_hash/attestation.rs:49`) —
  no cache needed, just thread the root through as a parameter.
- Selection-proof signing root is slot-constant across all ~1k aggregates — 1-entry memo.

### Architecture facts that reshape the design [verified]

- **6 tiles = 6 pinned busy-polling threads** (cores 1–6, flux `park` off). Attestation
  hashing happens **only in the single-threaded beacon_state tile**; message-id hashing
  only in the control tile. **No hash workload is computed on two threads today ⇒ a
  shared concurrent cache adds synchronization without adding hits.** The kickoff sketch
  (concurrent mostly-non-blocking map, promoted writer, CAS LRU) solves a problem this
  architecture doesn't have — per-tile single-threaded maps need no locks at all.
- Cross-thread sharing that *does* exist: BeaconState via Seqlock (single writer +
  optimistic readers), parking_lot on cold paths. No dashmap/arc-swap/crossbeam/lru crates
  anywhere in the workspace.
- **Eviction idiom of the house: slot/epoch-keyed rotation, not LRU.** Rotating bucket
  wheels (`Wheel<K,V,N>`), cap + slot-floor `retain`, epoch-parity bitmap lanes,
  direct-mapped overwrite tables. The only LRU is protocol-mandated (Kademlia k-buckets).
  A per-slot 2–4-entry memo fits the house style; a general LRU does not.
- **Batching gap, not a cache:** the bulk merkleization path (`MerkleStack`,
  `merkleize_padded`) issues ~84k hashtree calls **of batch size 1**, forfeiting
  hashtree's SIMD multi-block throughput (~2–8×). A pure reordering rewrite could take the
  7.6 ms state root toward ~2–3 ms *without any caching*, and composes with incremental
  trees.
- Measurement infra: 222 `#[timed]` frames, `just perf-local` with `thresholds.json`
  ceilings (state-root avg is a tracked ceiling), criterion benches in 3 crates
  (`bls_verify` bench covers attestation hashing), multithreaded bench precedent in quic.

### Lesson candidates #3–#5

3. **"The expensive element" ≠ "the most repeated element."** AttestationData tree-rooting
   is the most *repeated* hash (50k×/slot) but cheap per call (~0.5–1 µs); full-state
   re-merkleization is the most *expensive* (7.6 ms) but runs ~2×/slot. The biggest
   attestation-path win (hash-to-G2, ~2 s CPU) was hidden inside "signature verification"
   where nobody had itemized it as hashing.
4. **The concurrency machinery in the kickoff sketch is unnecessary here** — tile
   architecture already partitions the hash workloads to single threads. If sharding
   (CL-112's `subnet % tile_count`) lands later, per-shard caches replicate trivially
   (2–8 entries each) rather than needing a shared structure.
5. **Root cause is one pattern in many places: recompute-from-scratch over inputs that
   barely change** — the 4 state rings (>99.99% identical), sync-committee roots (rotate
   every 256 epochs, rehashed 2×/state-hash), eth1 votes, historical summaries, the
   duplicate aggregate hash, hash-to-G2 on an input identical 50k times. The *shape* of
   the fix differs (incremental tree / stored-root-with-invalidation / parameter threading
   / tiny per-slot memo) but the diagnosis is uniform.

## Measured numbers [verified — AMD Ryzen 9 9950X, SHA-NI + AVX-512, rustc 1.91, --release, pinned core]

Bench crate: scratchpad `hashbench`, calling the repo's own `silver_ssz` functions via
path-dep (repo untouched). Medians of 15 trials, spread <2%.

| operation | ns/op |
| --- | --- |
| sha256 32 B / 64 B / 128 B / 1 KiB (sha2, SHA-NI) | 37.8 / 51.5 / 74.5 / 395.8 |
| `hash_attestation_data` (repo, real 128 B AttestationData) | **338.7** |
| `hash_tree_root_fork_data` (what `Immutable` caches) | 55.4 |
| `hash_concat` 2×32 B (hashtree, single) | 29.7 |
| hashtree batched N=1000, per hash | 27.7 (**batching gains only ~7% on SHA-NI hardware**) |
| FxHashMap hit, 128 B key (incl. hash + memcmp) | **8.1** |
| FxHashMap hit, 32 B key | 3.1 |
| blst min_pk verify, 1 attestation-shaped sig | **604,321 (0.60 ms)** |

### What the numbers decide

- **Kickoff guess #1 refuted by ~4 orders of magnitude**: a crypto hash call is 38–340 ns,
  not ~1 ms. One BLS verify = ~1,780 AttestationData tree roots.
- **Kickoff guess #4 ("no high performance without hash caching") refuted for the burst
  path**: recomputing roots for all 50k attestations costs **~17 ms single-core total**
  (+ ~3 ms signing roots, ~10–25 ms message-ids) — ~0.1% of the 16-core × 1–2 s budget.
  Hash caching cannot be the load-shedding lever for the attestation burst.
- **The wall, quantified**: 50k naive BLS verifies ≈ 30 s single-core ≈ 1.9 s across 16
  cores — the *entire* budget. CL-112's batching/aggregation is the load-bearing work;
  an 8 ns map hit makes dedup-by-key essentially free relative to every crypto operation
  it can avoid, which is exactly the group-index role.
- **The batching-rewrite guess demoted**: earlier estimate "hashtree multi-block SIMD
  ⇒ 2–8×" measured at ~7% on this CPU (SHA-NI single-stream is already near-optimal).
  Arithmetic check: 84k compressions × 29.7 ns ≈ **2.5 ms of pure hashing** inside the
  measured 7.6 ms state root — the other ~5 ms is copies (~2.6 MB/call), tree-walk and
  scratch management. So the state-hash win comes from *not doing the work* (incremental
  trees kill both halves), not from batching the same work. Re-measure batching on target
  production hardware before dismissing entirely.
- The `Immutable.fork_data_roots` precompute saves 55 ns/call — right direction,
  negligible magnitude; its real value is API shape (domain derivation with zero hashing).

## Lesson candidate #6 — the headline

**We came looking for a concurrent hash cache and found the premise was numerically wrong
in every load-bearing spot.** The measured story: (a) per-call crypto hashing is ns-scale,
(b) the burst's repeated hashing totals tens of ms, (c) the only ms-scale repeated hash
work is the full-state re-merkleization (7.6 ms ≥2×/slot — 84k/90k compressions over
>99.99%-unchanged ring leaves + a byte-identical double hash per block), and (d) the burst
wall is BLS, where the fix is aggregation (CL-112), not caching. The valuable descendants
of this exploration, ranked:

1. **Incremental trees for the 4 state rings + stored roots for slow-changing fields +
   eliminate the double full-state hash** — the real hashing win (~7.6 ms → ~O(log) per
   slot), fork-aware/rebase-aware, measurable in `just perf-local` against a committed
   ceiling. This is state-hashing work, unrelated to the kickoff's concurrent-LRU shape.
2. **Signing-root → G2-point cache** (~2 CPU-s/slot inline) — but largely *subsumed* by
   CL-112's same-message batch path, which computes hash-to-G2 once per group anyway.
   Belongs to CL-112's design, not a standalone cache.
3. **Per-slot `AttestationData → (data_root, signing_root)` memo** — ~20 ms/burst; worth
   having only because it doubles as the batcher's group index (its CL-112 role), and as
   parameter-threading fixes (the aggregate path's duplicate hash). Not worth a
   general-purpose cache abstraction.

## Lesson candidate #7 — cutting hash-to-G2 without leaving the safe API

Q (Bronek): how do we cut ~99.99% of hash-to-G2 without dropping below blst's safe API —
cache at the layer we control, above Signature::verify?

A: don't cache the G2 point across calls — **restructure so repeated inputs meet inside
one safe-API call**; the cache becomes a loop variable (no lifetime, no eviction, no
unsafe):

1. Group by signing root + aggregate + one `fast_aggregate_verify` per group: 1 internal
   hash-to-G2 per group, zero unsafe — but unsound alone (unweighted sums admit the
   crafted-pair false-success attack CL-112 rules out). Only fits protocol-aggregated
   signer sets (sync-committee style).
2. **Group + weighted MSM through the existing `Pairing` pattern (the answer).**
   `blst::Pairing` binds the DST once at construction; `mul_n_aggregate` hashes the
   message internally. Feed it the *Pippenger-weighted aggregated* pk and sig once per
   group ⇒ one correctly-domain-separated hash-to-G2 per group + soundness from random
   weights. Only unsafe: the affine casts `SigBatch` (bls.rs:167) already contains — no
   new unsafe class, we never touch a DST or raw hashed point ourselves.
3. A true cross-call cache, if ever needed, must own (domain, DST, point) as one unit so
   stale-domain hits are unexpressible — but the CL-112 deferral window makes it moot:
   repeated roots co-arrive within a batch window, so cache-across-time degenerates into
   loop-within-one-call. The only cross-call residue is the slot-constant selection-proof
   *root* — 32 bytes, not a curve point, harmless to memo.

General form: **prefer caching inputs awaiting a shared computation (a grouped queue) over
caching outputs of a library-internal step.** The former stays inside the library's
correctness envelope; the latter is where DST-mismatch dragons live.

Caveat, now quantified (blsbench): per-signature G2 subgroup checks survive grouping and
are indeed the floor — 28.2 µs each, 63% of per-tuple cost at K=128; at 50k that is
~1.4 s CPU ≈ 88 ms across 16 cores. Comfortably within budget.

## Cache-strategy shootout [verified — burstbench, 50k msgs × D distinct × T pinned cores]

Seven strategies behind one trait, all collision-safe (full 128-byte key equality), real
repo hash functions, cold-burst and steady-state (warm) phases, 15-trial medians.

Burst wall-time (ms) for the 50k-message burst, D=2 (realistic post-Electra):

| strategy | T=1 | T=4 | T=16 |
| --- | --- | --- | --- |
| no-cache (recompute) | 19.6 | 5.0 | **1.3** |
| single-owner per-thread FxHashMap | 0.31 | 0.12 | **0.04** |
| global Mutex | 0.54 | 1.5 | **43.0** (2.2× slower than ONE uncached core) |
| global RwLock read-promote (the kickoff sketch) | 0.54 | 1.1 | 2.0 (worse than no-cache) |
| 16-shard RwLock | 0.75 | 1.1 | 2.2 |
| dashmap | 0.55 | 1.2 | 2.5 |
| lock-free 8-slot direct-mapped | 0.73 | 0.33 | 0.75 |

Verdicts:

- **Single-owner (per-tile / per-shard private memo) wins 17 of 18 cells** — zero
  synchronization, and it's what silver's tile model already gives for free.
- **The kickoff sketch (RwLock read-promote) never beats the private memo in any cell**
  and at T=16 loses even to plain recompute at every D. Root cause measured: a read-lock
  acquisition is still a CAS on one shared line — at T=16 the *pure-hit* path costs
  ~576 ns/thread-msg of ping-pong, i.e. **taking a read lock is more expensive than
  recomputing the SHA-256**. Under miss traffic (D=5000, T=16) writer promotions
  serialize 16 readers: 11.5× worse than no-cache.
- dashmap is the only robust *shared* cache (cross-thread compute dedup wins at
  adversarial D=5000), but at realistic D=2 it loses to no-cache at T=16 (2 keys pin 2
  shard locks). The house-style 8-slot atomic table is the best shared option at D=2
  (read-only hits replicate cache lines, no ping-pong) but cliffs into overwrite thrash
  the moment D > slots.
- **Perspective**: even with NO cache, 16 cores hash the whole burst in 1.3 ms of a
  1000–2000 ms budget. No strategy is justified by wall time; a private memo is justified
  only as CPU freed for BLS (19.6 → 0.3 single-core ms/burst). Any shared lock-based cache
  can only *burn* budget. Cap the memo's size: an unbounded memo under adversarial
  distinct-value spray is a memory-DoS vector.

## BLS verify split & batch table [verified — blsbench; the numbers CL-112 said "to be benchmarked, not assumed"]

One inline min_pk verify = **608 µs** = hash-to-G2 **96.9 µs (15.9%)** + pairing
**481.8 µs (79.2%)** + sig subgroup check **28.2 µs (4.6%)**. (Correction to the map-phase
estimate of "tens of µs" for hash-to-G2: it's ~97 µs, i.e. ~4.8 s CPU per 50k burst — but
caching it alone buys at most 1.19×; the pairing dominates, so grouping is what matters,
and grouping gets the hash-to-G2 collapse for free.)

Same-message weighted batch (Pippenger MSM on both sides + 1 hash-to-G2 + 1 pairing),
per-tuple **including** the surviving per-sig subgroup check:

| K same-data tuples | µs/tuple | speedup vs 608 µs inline |
| --- | --- | --- |
| 8 | 130.8 | 4.7× |
| 32 | 64.8 | 9.4× |
| 128 | 45.1 | 13.5× (→ asymptote ~40.5: the 28.2 µs subgroup check is 63% of the floor) |

Budget check: 50k inline = 30.4 s CPU = **1.90 s on 16 perfect cores — nominally inside
2 s with zero headroom, effectively does not fit**. Batch at K=128 = 2.25 s CPU = **141 ms
on 16 cores — fits with >10× headroom** (202 ms at K=32). Post-Electra concentration
(1–3 distinct AttestationData/slot) makes K ≥ 128 the realistic regime. CL-112's "expected
10–20× at K=32–128" is confirmed at 9.4–13.5× with subgroup checks (16.6–36× without).
Curiosity: the one-shot FFI `blst_core_verify_pk_in_g1` is reproducibly ~9% *slower* than
the Rust `Pairing`-based `min_pk::verify` — prefer the Pairing path. Also: the
"prehashed-message verify" (481.8 µs) was reachable via the *public* `Pairing::raw_aggregate`
— the unsafe surface for a G2 cache is smaller than assumed, though grouping still makes
it unnecessary.

## Consolidated lessons for the team

1. **Verify magnitudes before designing.** The founding guess ("a hash call ≈ 1 ms") was
   off by 4 orders; a day of measurement redirected the whole effort from "build a
   concurrent hash cache" to "batch BLS + incrementalize state hashing".
2. **The cache shape must follow the sharing pattern** (lesson #2 table): burst-shared
   values → per-owner memo; per-epoch values → snapshot swap; slowly-mutating aggregates →
   incremental trees. There is no one cache to rule them all.
3. **In a pinned-tile architecture, private-per-owner beats shared-anything**: read locks
   cost more than the SHA-256 they guard; every shared strategy lost to a per-thread
   FxHashMap in every realistic cell.
4. **Prefer grouping inputs over caching intermediate crypto outputs** (lesson #7): the
   pending-queue-grouped-by-signing-root turns "cache hash-to-G2 across calls" into "one
   safe-API call per group", eliminating staleness, eviction, and unsafe DST plumbing.
5. **The real hashing money is in the state root, not the gossip path**: 84k/90k
   compressions per 7.6 ms state hash cover >99.99%-unchanged ring leaves, plus a
   byte-identical double hash per block — incremental ring trees + stored slow-field roots
   + double-hash elimination is the follow-up with measurable perf-harness impact.
6. **`Immutable` should be split honestly**: truly-frozen genesis data vs fork-varying
   derived roots. The precompute pattern is right; the naming/ownership is the tension.
7. **CL-112's batch design is quantitatively confirmed and necessary**: inline verification
   does not fit the 50k budget (1.90 s of 2 s, zero headroom); batching fits with >10×
   headroom. The AttestationData memo's real role there is the batcher's group index.

## Design outcome (agreed with Bronek)

**Per-owner private FxHashMap memo — a plain field on the tile struct** (the tile owns its
thread; no TLS, no locks, no `Sync`). Key: the full 128-byte `AttestationData` (fast-hash
prefilter, full equality on hit) → `(data_root, signing_root)`. Capped entries +
slot-floor rotation, matching the `AttestationPool` idiom; a capped memo under adversarial
spray degrades to recompute, which costs 1.3–20 ms/burst — harmless. Measured headroom:
one core absorbs the 50k burst in **0.31 ms** cold (6.25 ns/msg warm, ~160M lookups/s);
even D=5000 spray is 2.4 ms.

Scope: this closes the *hashing* question. The tile's real capacity limit is the BLS batch
itself — 45.1 µs/tuple × 50k = 2.25 s CPU does not fit 1–2 s on one core — which is
CL-112's surviving motivation for `subnet % tile_count` shard tiles; the memo replicates
per shard as another private field, no sharing, exactly the regime where the shootout says
single-owner wins. With compute fitted, the remaining engineering moves to **not dropping
messages**: pending-queue sizing (240 B × 50k ≈ 12 MB), verdict latency under the batch
window, backpressure through the gossip rings — queueing design, not cryptography.

Benchmark crates (scratchpad, re-runnable): `hashbench` (primitives), `burstbench`
(strategy grid, results.tsv), `blsbench` (BLS split + MSM table).
