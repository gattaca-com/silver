# Cohesion rules

What belongs together in silver, at each scale above the function: tile, crate,
file, type. The companion is [decoupling-rules.md](decoupling-rules.md) — what
may cross a boundary.

CLAUDE.md's *Encapsulation* section covers the scale below this one: data owns
its methods, a banner comment is an unwritten function name, a cohesive field
subset wants its own type. This document is about the units those rules sit
inside.

## 1. A tile is a cadence, not a subsystem

Six tiles, one OS thread each, pinned to a core, each running one `loop_body`.
The question that decides a boundary is *does this work block that work* — not
*is this a different topic*.

Split when one workload's latency shows up in another's. Data-column validation
and DA tracking left the storage tile (#162) because a column batch stalled
disk writes.

Merge when two tiles only shuffle messages between themselves. Gossipsub
decode/encode runs inside the controller (#140): every message it produced was
consumed by the peer manager sitting one queue away, so the queue was pure
latency.

**Test:** name the two cadences and say what each blocks. If you cannot, it is
one tile.

## 2. A hosted crate is one protocol, entire

A hosted crate is a transport-free library living inside the tile that owns the
loop, hardcoded into it — not a plugin. Each holds one protocol whole:

| crate | holds | host |
|-------|-------|------|
| `silver_gossip` | gossipsub — mesh, mcache, dedup, control frames | `Controller` |
| `silver_peer` | peer lifecycle, scoring, ban DB, sync issuance | `Controller` |
| `silver_discovery` | discv5 | `NetworkTile` |

The host tile keeps no protocol state of its own. `Controller` holds a
`PeerManager` and a `GossipHandler`, consumes the spine on their behalf, and
routes between them; the mesh state and the score table live in their own
crates.

## 3. Data that two tiles read earns its own crate

`crates/beacon_state` is two crates, and the split is the reason storage and
data-columns can read beacon state at all:

- `data/` — `BeaconState`, its groups, the encode/decode paths, and the
  `BeaconStateOwner` / `BeaconStateReader` pair.
- `tile/` — the loop, the state transition, fork choice, BLS, the pools.

Storage and data-columns depend on `silver_beacon_state_data`. Neither depends
on `silver_beacon_state`, so rule 2 of
[decoupling-rules.md](decoupling-rules.md) holds and neither can call into the
state-transition code.

This is the general remedy: when a second tile needs to read a structure you
own, the structure moves down a tier with its methods, and the loop stays where
it is. Widening `pub` in the tile crate would not have worked — nothing may
depend on a tile crate.

## 4. A group is a write cadence

Inside `beacon_state_data` the same principle repeats one scale down.
`BeaconState` is not a monolith; it is a bag of groups split by *when the tier
is written* — per-block tiers (validators, balances, participation, …) rolled
for every block, boundary tiers (epoch, longtail) rolled only when their
boundary event fires. Fields that change together live in one group; fields on
different cadences do not.

Every group then has the same shape — finalized base plus a ring of per-fork
deltas — so one set of rules covers all of them. See
[beacon-state-architecture.md](beacon-state-architecture.md).

The seqlock control word is a cadence too, and the smallest one. One writer,
two write paths, and each rewrites the whole word: a publish sets `state_id`
and carries the finalize counter unchanged, while the finalize window brackets
its writes with that counter and may stage a remapped `state_id` to land at
close — finalization re-anchors survivor bundles, so the head's refreshed
bundle has to publish inside the same seqlock window. A field added beside them
is therefore republished on both cadences whether or not either has anything to
say about it, and has to be derivable at every one of those writes. When a
field's doc comment has to explain which of its struct's writes skip it, that
is the tell. Rule 9 of [decoupling-rules.md](decoupling-rules.md) is the same
boundary seen from the other side.

## 5. `tile.rs` is the tile struct and its loop

Each tile crate has `src/tile.rs`: the tile struct, its constructor, its `Tile`
impl, and the dispatch the loop performs. Nothing else.

The tile's private sub-components go one per file under `src/tile/` —
`attestation_pool.rs`, `orphan_pool.rs`, `shuffling_cache.rs`,
`seen_validators.rs`, `attestation_root_memo.rs`. Domain logic that is not the
loop goes in sibling top-level modules: `stf/`, `fork_choice/`, `validate.rs`,
`bls/`.

A pool or cache reached only from the loop belongs under `tile/`. One reached
from `stf/` as well is not a tile detail, and moves up beside it.

## 6. The crate root is a flat re-export list

`mod x; pub use x::Type;` — modules private, the one primary type re-exported at
the root, the file named for that type. `pub mod` only where the module *is* the
surface: `tile`, `stf`, `counters`, `sync_engine`.

`crates/engine/src/lib.rs` is the shape: eight private modules plus `pub mod
tile`, four names out.

## 7. One counter set per crate, namespaced by the crate

```rust
silver_common::declare_counters! {
    pub StorageCounters => "storage" { … }
}
```

One `declare_counters!` per crate, the string naming the crate, because it names
the shmem file surfer reads. In `counters.rs` where the set is long (storage,
columns, beacon_state); at the crate root where it is short (network, peer).

Gossip has no namespace of its own: `GossipInvalidFrame`,
`GossipInvalidControl` and `GossipInvalidMsg` are `PeerCounters`, because peer
scoring is what consumes them. Check before adding a `"gossip"` file.

## 8. Events leave through a callback, into a reused buffer

A component hands events out as `emit: &mut impl FnMut(Event)`, not as a
returned `Vec` — `PeerManager::tick`, `activate_topics`, `redial_known_peers`,
`peer_scores` all take one. Nothing allocates per call.

Where the caller cannot act re-entrantly, the buffer is a field, taken and
restored rather than created: `GossipHandler::spin` does
`std::mem::take(&mut self.events)`, fills it through the emit closure, and puts
it back. Capacity survives the loop.

## 9. Fan out in-tile before the spine

When a message has both an in-tile and a cross-tile consumer, one function in
the host tile is the fan-out point. `handle_peer_control`
(`crates/control/src/tile.rs`) takes each `PeerControl`, gives it to the gossip
handler, then produces the variants the network and storage tiles need.

Keeping that in one function is what makes rule 7 of
[decoupling-rules.md](decoupling-rules.md) checkable: the tile has a single
place where an in-tile hand-off could be mistaken for a spine round trip.

## Where this is not uniform

| pattern | variation |
|---------|-----------|
| counter declaration site | `counters.rs` in storage, columns, beacon_state; crate root in network, peer |
| counter namespace | gossip's counters live under `"peer"` |
| hosted crate and the spine | `silver_gossip` consumes `GossipMsgIn` directly; `silver_peer` and `silver_discovery` never mention the spine |
| config reach | `beacon_state`, `engine`, `peer`, `discovery`, `telemetry` depend on `silver_config`; `control`, `network`, `storage`, `columns` take plain values instead |
