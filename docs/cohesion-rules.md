# Cohesion rules

What belongs together in silver, at each scale above the function: tile,
crate, file, type. Companion: [decoupling-rules.md](decoupling-rules.md) —
what may cross a boundary. CLAUDE.md's *Encapsulation* section covers the
scale below this one. When code contradicts a rule, check
[Where this is not uniform](#where-this-is-not-uniform) before flagging it.

## 1. A tile is a cadence, not a subsystem

Six tiles, one pinned OS thread each, one `loop_body` each. A boundary is
decided by *does this work block that work*, not *is this a different topic*:
split when one workload's latency shows up in another's (data-column
validation left the storage tile, #162), merge when two tiles only shuffle
messages between themselves (gossipsub decode/encode moved into the
controller, #140).

**Test:** name the two cadences and say what each blocks. If you cannot, it
is one tile.

## 2. A hosted crate is one protocol, entire

A hosted crate is a transport-free library hardcoded into the tile that owns
the loop — not a plugin. Each holds one protocol whole; the host tile keeps
no protocol state of its own, consuming the spine on the crate's behalf and
routing between its hosted components.

| crate | holds | host |
|-------|-------|------|
| `silver_gossip` | gossipsub — mesh, mcache, dedup, control frames | `Controller` |
| `silver_peer` | peer lifecycle, scoring, ban DB, sync issuance | `Controller` |
| `silver_discovery` | discv5 | `NetworkTile` |

## 3. Data that two tiles read earns its own crate

When a second tile needs to read a structure you own, the structure moves
down a tier with its methods and the loop stays where it is — widening `pub`
cannot work, because the blocker is the Cargo edge, not visibility: nothing
may depend on a tile crate. The worked shape is
`crates/beacon_state`: `data/` holds `BeaconState`, its groups, the codecs,
and the `BeaconStateOwner`/`BeaconStateReader` pair; `tile/` holds the loop,
the state transition, fork choice, BLS, the pools. Storage and data-columns
depend on `data/` only, so neither can call into state-transition code.

## 4. A group is a write cadence

`BeaconState` is a bag of groups split by *when the tier is written*:
per-block tiers (validators, balances, participation, …) roll every block;
boundary tiers (epoch, longtail) roll only on their boundary event. Fields
that change together live in one group. Every group has the same shape —
finalized base plus a ring of per-fork deltas
([beacon-state-architecture.md](beacon-state-architecture.md)).

The seqlock control word is the smallest cadence: one writer, two write
paths, each rewriting the whole word — a publish sets `state_id` and carries
the finalize counter unchanged; the finalize window brackets its writes with
that counter and may republish a remapped `state_id` at close. A field added
beside them is republished by writes that know nothing about it, so it must
be derivable at every write of both paths. The tell: a field whose doc
comment explains which of its struct's writes skip it. Decoupling rule 9 is
the same boundary seen from the other side.

## 5. `tile.rs` is the tile struct and its loop

`src/tile.rs` holds the tile struct, its constructor, its `Tile` impl, and
the loop's dispatch — nothing else. The tile's private sub-components go one
per file under `src/tile/` (`attestation_pool.rs`, `orphan_pool.rs`, …);
domain logic that is not the loop goes in sibling top-level modules (`stf/`,
`fork_choice/`, `validate.rs`, `bls/`). A pool or cache reached only from the
loop belongs under `tile/`; one reached from `stf/` as well moves up beside
it.

## 6. The crate root is a flat re-export list

`mod x; pub use x::Type;` — modules private, the one primary type re-exported
at the root, the file named for that type. `pub mod` only where the module
*is* the surface (`tile`, `stf`, `counters`, `sync_engine`).
`crates/engine/src/lib.rs` is the shape: eight private modules plus
`pub mod tile`, four names out.

## 7. One counter set per crate, namespaced by the crate

```rust
silver_common::declare_counters! {
    pub StorageCounters => "storage" { … }
}
```

One `declare_counters!` per crate, the string naming the crate, because it
names the shmem file surfer reads — in `counters.rs` where the set is long,
at the crate root where it is short. Gossip has no namespace of its own: its
counters are `PeerCounters`, because peer scoring consumes them.

## 8. Events leave through a callback, into a reused buffer

A component hands events out as `emit: &mut impl FnMut(Event)`, never a
returned `Vec` — nothing allocates per call (`PeerManager::tick`,
`peer_scores`, `activate_topics` all take one). Where the caller cannot act
re-entrantly, the buffer is a field, taken and restored:
`GossipHandler::spin` does `std::mem::take(&mut self.events)`, fills it, puts
it back — capacity survives the loop.

## 9. Fan out in-tile before the spine

A message with both an in-tile and a cross-tile consumer goes through one
fan-out function in the host tile: hand it in-tile first, then produce the
cross-tile variants — `handle_peer_control` (`crates/control/src/tile.rs`).
One function is what keeps decoupling rule 7 checkable: a single place where
an in-tile hand-off could be mistaken for a spine round trip.

## Where this is not uniform

| pattern | variation |
|---------|-----------|
| counter declaration site | `counters.rs` in storage, columns, beacon_state, control; crate root in network, peer |
| counter namespace | gossip's counters live under `"peer"` |
| hosted crate and the spine | `silver_gossip` consumes `GossipMsgIn` directly; `silver_peer` and `silver_discovery` never mention the spine |
| config reach | `beacon_state`, `engine`, `peer`, `discovery`, `telemetry` depend on `silver_config`; `control`, `network`, `storage`, `columns` take plain values instead |
