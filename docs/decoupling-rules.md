# Decoupling rules

What may cross a boundary in silver, and how. The companion is
[cohesion-rules.md](cohesion-rules.md) — what belongs together. The topology
these rules produce is tabulated in
[spine-message-flow.md](spine-message-flow.md); vocabulary is in
[CONTEXT.md](../CONTEXT.md).

Read the *enforced by* column. The spine hands every tile a producer and a
consumer for every queue, and Cargo rejects only cycles, so the compiler catches
almost none of this. Most of these rules are convention that a reviewer has to
hold.

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

`silver_common` is tier 2 because it owns the spine: the queue declarations
(`crates/common/src/spine.rs`), the message types, and the tcache handles. Every
tile and every hosted crate needs it, so nothing it depends on can sit above it.

Check the graph with:

```
cargo metadata --no-deps --format-version 1 \
  | jq -r '.packages[] | .name as $p | .dependencies[] | select(.name|startswith("silver_")) | "\($p) -> \(.name) [\(.kind // "normal")]"'
```

A commit that adds a `silver_*` crate places it in this table. The lists are
what a reviewer checks a new crate against; the recipe above is what checks the
lists.

Tiers constrain vocabulary, not only Cargo edges. A tier-1 struct that names a
tier-5 concept is an upward edge whether or not the manifest shows one, and
rule 9 is where that happens most easily.

**Enforced by:** Cargo, cycles only. An upward edge inside the DAG compiles.

## 2. Tile crates are leaves

No tile crate is a dependency of another tile crate or of a hosted crate. Only
tier 6 — the three binaries and the `e2e` harness — depends on a tile crate.

A tile crate holds a hot loop pinned to a core. Depending on one drags that
loop's transitive world into your build and invites calling into its internals
directly rather than sending it a message. When two tiles need the same type,
rule 3 or rule 4 of [cohesion-rules.md](cohesion-rules.md) applies instead.

**Enforced by:** nothing. One dev-dependency exception:
`silver_beacon_state` dev-deps `silver_storage`, because column-sidecar
verification lives in storage and the EF PeerDAS fork-choice vectors exercise
it. Storage depends only on `beacon_state_data`, so there is no cycle.

## 3. A type two tiles both name lives in `silver_common::spine`

Message types go in `crates/common/src/spine/messages.rs`, next to the queue
that carries them. Wire-adjacent shared vocabulary — `GossipTopic`, `PeerId`,
`StreamProtocol`, `TCacheRead` — lives elsewhere in `silver_common`. Shared
*state* is the one exception and goes in a data crate (rule 8).

**Enforced by:** rule 2. With tile crates unreachable from each other, a type
defined in one is unnameable in another.

## 4. Spine messages are `Copy` and `#[repr(C)]`

A queue slot is a fixed-size cell in a preallocated ring, so a message carries
no heap and no `Drop`. Bulk bytes go into a tcache and the message carries a
`TCacheRead` into it. A large cold variant is paid for by every slot in the
queue — `PeerControl::P2pDial` carries a ~200 B `Enr` against ~60 B for the
rest, and boxing it is rejected because it would cost the enum its `Copy`.

**Enforced by:** the compiler. `SpineQueue<T>` requires `T: Copy`.

## 5. The message type is the route

`adapter.produce(msg)` and `adapter.consume(|msg: T, _| …)` resolve the queue
from `T` through `AsRef<SpineProducer<T>>`, generated per queue field by
`#[from_spine]`. One Rust type maps to exactly one queue: a new message means a
new queue field in `SilverSpine`, and a type cannot ride two queues.

Inside a `consume` closure the adapter is already borrowed, so production goes
through the `&mut SilverSpineProducers` the closure receives, naming the queue:
`producers.p2p_send.produce(&msg)`. That path does not call `mark_work` — the
enclosing `consume` already did.

**Enforced by:** the compiler.

## 6. The producer/consumer table is the contract

Every tile holds producers and consumers for every queue. Producing a message
another tile owns compiles, links, and runs.

The table in [spine-message-flow.md](spine-message-flow.md) is therefore the
only statement of who may produce what. A change to the topology updates that
table in the same commit.

**Enforced by:** review.

## 7. A tile does not consume a type it produces

Queues are broadcast and there is no self-filtering: a tile that produces a
type it also consumes reads its own message back. Where a message has both an
in-tile and a cross-tile consumer, the producing tile applies it in-tile first
and then produces it — `handle_peer_control` in `crates/control/src/tile.rs`
hands each `PeerControl` to the gossip handler and then puts it on the spine.

The invariant holds across every tile today. Two apparent breaches are test
harnesses consuming through an `Injector` adapter: storage's `ReplayBlock` and
the beacon-state tile's `SyncNeed`.

**Enforced by:** nothing.

## 8. One shared-memory read path crosses tiles

`BeaconStateReader` (`crates/beacon_state/data/src/view.rs`) is the only piece
of tile state another tile reads by reference. Single writer — the
`BeaconStateOwner` inside the beacon-state tile, not `Clone`, mutating behind
`&mut self`; N optimistic readers validating a seqlock. `main.rs` hands
`beacon_state_tile.reader()` to storage and to data-columns at construction.

No other tile state is shared. Everything else crosses as a spine message or a
tcache payload.

**Enforced by:** `BeaconStateOwner` is not `Clone`, so the write handle cannot
leave the tile. See [beacon-state-architecture.md](beacon-state-architecture.md)
and [delta-rebase-invariant.md](delta-rebase-invariant.md).

## 9. That read path carries state, not conclusions

`BeaconStateReader` publishes what the beacon state *is*. A value that a tile
concluded, rather than one the state holds, is not state and does not travel
this way. It crosses as a spine message like any other cross-tile datum
(rules 3 and 4).

The control word is where such a value wants to go, because a reader already
gets it paired with a consistent snapshot for free. That is the trap: the
pairing is genuine, so nothing reads as wrong at the call site, and meanwhile
the value has taken on a tier it did not earn. `crates/beacon_state/data` is
tier 1; a conclusion drawn inside a tile is tier 5. Carrying one in the other
is an upward edge that no manifest shows and rule 1's `cargo metadata` check
cannot see.

**Test:** can the owning crate compute the value from the data it holds? If it
can, the value is state and the reader may carry it. If it cannot — if some
other component has to push the value in — then it is that component's
conclusion, and the push is the boundary being crossed.

**Enforced by:** nothing. The test is greppable, though: a setter on a shared
data type whose value that type cannot derive.

## 10. A `read()` closure pulls every input and computes nothing

`BeaconStateReader::read` spins while a finalize window is open, and a torn read
is retried, so the closure body is the reader-blocking budget. Pull all the
scalars, roots and pubkeys the caller needs in one pass and return them;
anything slow runs outside. `crates/columns/src/validate.rs` takes exactly this
shape — one closure returning a tuple of checks, BLS verification after it.

Only the fixed-size bases are safe on the lock-free path. The pending and
longtail bases are realloc-prone `Vec`s; reading their contents needs the
lock-guarded path.

**Enforced by:** nothing.

## 11. A tile is constructed from values and handles

`Tile::new` takes tcache producers and consumers, an `Arc<SpecConfig>`, plain
config values, and its own hosted components. It never takes another tile, and
never a whole `Config`.

The payoff is that a tile is constructible and steppable alone: tests call
`loop_body` by hand against an `Injector` marker tile that owns the other end of
each queue — `crates/e2e/src/stack.rs` builds partial stacks this way, and
`crates/beacon_state/tile/tests/common.rs` drives the beacon-state tile with no
neighbours at all. A constructor that reaches for a neighbour costs that.

**Enforced by:** nothing.

## 12. Hosted crates emit; the host tile produces

A hosted crate owns protocol state and hands events out through
`emit: &mut impl FnMut(PeerControl)` callbacks, naming spine message types
without touching the spine. `silver_peer` and `silver_discovery` hold this:
neither mentions `flux::spine`.

`silver_gossip` does not. `GossipHandler::spin` takes the `SpineAdapter` and
consumes `GossipMsgIn` itself.

**Enforced by:** nothing.

## 13. Observers are separate processes, and read-only

`silver_surfer` and `silver_telemetry` are their own binaries. They attach to a
running silver's spine as extra consumers and read the counter shmem; they
produce nothing onto it (outside their own tests). A queue with no in-process
consumer is therefore live, not dead: `engine_health` and `peer_stats` are read
out of process.

**Enforced by:** nothing.

## 14. Test-only visibility is feature-gated

Widening a surface for a test harness is gated, not unconditional:
`silver_beacon_state` exports its fork-choice store types only under
`ef_tests`, and `SlotTicker::set_current_slot` only under
`silver_common/test-util`.

Because those gates hide code from a plain `cargo check --all-targets`, verify
with `--all-features` (`just clippy`, `just test`).

**Enforced by:** the compiler.

## Known departures

| where | what | why it stands |
|-------|------|---------------|
| `silver_common` → `silver_beacon_state_data` | `crates/common/src/column_util.rs` imports `SLOTS_PER_EPOCH`, defined in `crates/beacon_state/data/src/types.rs`, and `crates/common/src/lib.rs` re-exports it. It also takes `SpecConfig` through that crate's re-export rather than from `silver_chain_spec`. | One constant, but the re-export puts it on `silver_common`'s public surface, so callers of `silver_common::SLOTS_PER_EPOCH` inherit the edge. Moving the preset to `silver_chain_spec` would drop it. |
| `silver_gossip` | Consumes `GossipMsgIn` off the spine (rule 12). | The handler runs inside the controller tile (#140) and reads the `incoming_gossip` tcache by random access. |
| `silver_peer` | `pub use silver_config::SyncingConfig` at its crate root. | Gives `silver_control` a config type without a `silver_config` dependency of its own. |
| `silver_beacon_state` dev-deps `silver_storage` | Rule 2. | EF PeerDAS DA vectors need the real column-sidecar verification. |
