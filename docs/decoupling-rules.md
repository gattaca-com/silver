# Decoupling rules

What may cross a boundary in silver, and how. Companion:
[cohesion-rules.md](cohesion-rules.md) — what belongs together. Topology:
[spine-message-flow.md](spine-message-flow.md); vocabulary:
[CONTEXT.md](../CONTEXT.md).

Read the *enforced by* line on every rule: the spine hands every tile a
producer and a consumer for every queue, and Cargo rejects only cycles, so the
compiler catches almost none of this. When code contradicts a rule, check
[Known departures](#known-departures) before flagging it.

## 1. Crates form tiers, and depend only downward

| tier | crates | silver deps |
|------|--------|-------------|
| 0 — leaves | `ssz`, `metrics`, `chain_spec` | none |
| 1 — state data | `beacon_state_data` | `chain_spec`, `ssz` |
| 2 — vocabulary | `common` | tiers 0–1 |
| 3 — config | `config` | `chain_spec`, `common` |
| 4 — hosted | `gossip`, `peer`, `discovery` | tiers 0–3 |
| 5 — tiles | `network`, `control`, `beacon_state`, `storage`, `columns`, `engine` | tiers 0–4 |
| 6 — processes | `silver` (bin), `surfer`, `telemetry`, `e2e` | anything |

`silver_common` is tier 2 because it owns the spine — the queue declarations
(`crates/common/src/spine.rs`), the message types, the tcache handles — and
every tile and hosted crate needs it.

A commit that adds a `silver_*` crate places it in this table. Check the graph
with:

```
cargo metadata --no-deps --format-version 1 \
  | jq -r '.packages[] | .name as $p | .dependencies[] | select(.name|startswith("silver_")) | "\($p) -> \(.name) [\(.kind // "normal")]"'
```

The lists are what a reviewer checks a new crate against; the recipe above is
what checks the lists.

Tiers constrain vocabulary, not only Cargo edges: a tier-1 struct naming a
tier-5 concept is an upward edge with no manifest line to show it (rule 9).

**Enforced by:** Cargo, cycles only. An upward edge inside the DAG compiles.

## 2. Tile crates are leaves

Only tier 6 depends on a tile crate. A tile crate holds a hot loop pinned to a
core; depending on one drags that loop's transitive world into your build and
invites calling into its internals instead of messaging it. Two tiles needing
the same type is rule 3 — or [cohesion](cohesion-rules.md) rule 3, for shared
state — instead.

**Enforced by:** nothing.

## 3. A type two tiles both name lives in `silver_common::spine`

Message types go in `crates/common/src/spine/messages.rs`, next to the queue
that carries them; wire-adjacent vocabulary (`GossipTopic`, `PeerId`,
`StreamProtocol`, `TCacheRead`) elsewhere in `silver_common`. Shared *state*
goes in a data crate instead (rule 8).

**Enforced by:** rule 2 — a type defined in one tile crate is unnameable in
another.

## 4. Spine messages are `Copy` and `#[repr(C)]`

A queue slot is a fixed-size cell in a preallocated ring: no heap, no `Drop`.
Bulk bytes go into a tcache and the message carries a `TCacheRead` into it.
Every slot pays for the largest variant (`PeerControl::P2pDial`'s ~200 B
`Enr`); boxing one down is rejected because it would cost the enum its `Copy`.

**Enforced by:** the compiler. `SpineQueue<T>` requires `T: Copy`.

## 5. The message type is the route

One Rust type maps to exactly one queue: `adapter.produce(msg)` and
`adapter.consume(|msg: T, _| …)` resolve the queue from `T`. A new message
means a new queue field in `SilverSpine`; a type cannot ride two queues.

Inside a `consume` closure, produce through the `&mut SilverSpineProducers`
the closure receives — `producers.p2p_send.produce(&msg)`; the enclosing
`consume` already called `mark_work`.

**Enforced by:** the compiler.

## 6. The producer/consumer table is the contract

Every tile holds producers and consumers for every queue, so producing a
message another tile owns compiles, links, and runs. The table in
[spine-message-flow.md](spine-message-flow.md) is the only statement of who
may produce what; a topology change updates it in the same commit.

**Enforced by:** review.

## 7. A tile does not consume a type it produces

Queues are broadcast with no self-filtering: the producer would read its own
message back. A message with both an in-tile and a cross-tile consumer is
applied in-tile first, then produced — `handle_peer_control` in
`crates/control/src/tile.rs`. (Test harnesses consuming through an `Injector`
adapter — storage's `ReplayBlock`, beacon-state's `SyncNeed` — are not
breaches.)

**Enforced by:** nothing.

## 8. One shared-memory read path crosses tiles

`BeaconStateReader` (`crates/beacon_state/data/src/view.rs`) is the only tile
state another tile reads by reference: single writer (`BeaconStateOwner`, not
`Clone`, mutating behind `&mut self`), N optimistic seqlock readers, handed
out by `main.rs` at construction. Everything else crosses as a spine message
or a tcache payload.

**Enforced by:** `BeaconStateOwner` is not `Clone` — the write handle cannot
leave the tile. See
[beacon-state-architecture.md](beacon-state-architecture.md) and
[delta-rebase-invariant.md](delta-rebase-invariant.md).

## 9. That read path carries state, not conclusions

`BeaconStateReader` publishes what the beacon state *is*. A value some tile
concluded — a head, a verdict — crosses as a spine message (rules 3–4), never
through the reader. The control word is the tempting spot: a reader gets the
value paired with a consistent snapshot for free, nothing looks wrong at the
call site, and the value has taken a tier it did not earn — an upward edge no
manifest shows.

**Test:** can the owning crate compute the value from the data it holds? If it
can, the value is state and the reader may carry it. If some other component
has to push it in, the value is that component's conclusion, and the push is
the boundary being crossed. Greppable: a setter on a shared data type whose
value that type cannot derive. The owner publishing the word's own fields
(`state_id`, the finalize counter) is not the tell — the tell is a new value
pushed in beside them.

**Enforced by:** nothing.

## 10. A `read()` closure pulls every input and computes nothing

The closure body is the reader-blocking budget — `read` spins while a finalize
window is open, and a torn read retries. Pull every scalar, root and pubkey
the caller needs in one pass and return them; anything slow runs outside.
`crates/columns/src/validate.rs` is the shape. Only the fixed-size bases are
safe lock-free; the pending and longtail bases are realloc-prone `Vec`s and
need the lock-guarded path.

**Enforced by:** nothing.

## 11. A tile is constructed from values and handles

`Tile::new` takes tcache producers and consumers, an `Arc<SpecConfig>`, plain
config values, and its own hosted components — never another tile, never a
whole `Config`. That keeps a tile steppable alone: tests drive `loop_body`
against an `Injector` marker tile owning the other end of each queue
(`crates/e2e/src/stack.rs`, `crates/beacon_state/tile/tests/common.rs`).

**Enforced by:** nothing.

## 12. Hosted crates emit; the host tile produces

A hosted crate owns protocol state and hands events out through
`emit: &mut impl FnMut(PeerControl)` callbacks — naming spine message types,
never touching the spine itself (`silver_peer`, `silver_discovery`).

**Enforced by:** nothing.

## 13. Observers are separate processes, and read-only

`silver_surfer` and `silver_telemetry` are their own binaries: they attach to
a running silver's spine as extra consumers and read the counter shmem, and
produce nothing onto it. A queue with no in-process consumer is therefore
live, not dead — `engine_health` and `peer_stats` are read out of process.

**Enforced by:** nothing.

## 14. Test-only visibility is feature-gated

Widening a surface for a test harness is gated, not unconditional —
`silver_beacon_state` exports its fork-choice store types only under
`ef_tests`, `SlotTicker::set_current_slot` only under
`silver_common/test-util`. Gated code is invisible to a plain
`cargo check --all-targets`: verify with `--all-features` (`just clippy`,
`just test`).

**Enforced by:** the compiler.

## Known departures

Code that contradicts a rule above and stands anyway. A departure is not
precedent: a new one needs its own row here and review.

| where | what | why it stands |
|-------|------|---------------|
| `silver_common` → `silver_beacon_state_data` | `crates/common/src/column_util.rs` imports `SLOTS_PER_EPOCH`, defined in `crates/beacon_state/data/src/types.rs`, and `crates/common/src/lib.rs` re-exports it. It also takes `SpecConfig` through that crate's re-export rather than from `silver_chain_spec`. | One constant, but the re-export puts it on `silver_common`'s public surface, so callers of `silver_common::SLOTS_PER_EPOCH` inherit the edge. Moving the preset to `silver_chain_spec` would drop it. |
| `silver_gossip` | Consumes `GossipMsgIn` off the spine (rule 12). | The handler runs inside the controller tile (#140) and reads the `incoming_gossip` tcache by random access. |
| `silver_peer` | `pub use silver_config::SyncingConfig` at its crate root. | Gives `silver_control` a config type without a `silver_config` dependency of its own. |
| `silver_beacon_state` dev-deps `silver_storage` | Rule 2 — a tile crate as a dependency. | Dev-only: the EF PeerDAS fork-choice vectors need storage's real column-sidecar verification. Storage depends only on `beacon_state_data`, so there is no cycle. |
