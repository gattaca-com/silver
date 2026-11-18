# Beacon state: groups, forks, and the read/write model

How `silver_beacon_state_data` stores the beacon state.
It also covers how one writer and many lock-free readers share it.
The writer is the beacon-state tile.
Readers include the storage, columns and beacon API tiles.

## 1. The state is a set of independent groups

There is no monolithic state object.
`BeaconState` is a bag of per-tier **groups**, plus the `immutable` block.

| cadence | groups |
|---|---|
| every block | `validators`, `balances`, `eth1`, `pending`, `previous_participation`, `current_participation`, `inactivity`, `slashings`, `block_roots`, `state_roots`, `randao_mixes`, `slot_states`, `builders` |
| boundary only | `epoch` (epoch transition), `longtail` (sync-committee rotation, historical summaries) |

`builders` stays empty until the Gloas fork.
The `epoch` tier also carries the Gloas PTC window.

Each group holds a finalized base and per-fork entries addressed by a typed `Id`.
A fork's value is the base overlaid with its entry.
Groups come in two shapes:

- **Tree groups** (`TreeGroup<C>`: balances, participation, inactivity, slashings, roots, randao mixes).
  One flat writer tree takes all writes.
  A commit stores the fork as a page-table snapshot in a shared `PagePool`.
  The hash columns of `validators` and `builders` are tree groups too.
- **Ring groups** (validators, builders, eth1, pending queues, slot, epoch, longtail).
  Each fork owns a delta in a `Ring` slot.
  Validators and builders keep sparse `Edits` plus an appended tail.
  Eth1 and pending keep append logs.
  Slot, epoch and longtail keep a full working copy.

A **fork** (a block's post-state) is named by a `StateId`.
It is a `Copy` bundle of one id per tier.
`epoch_idx` and `longtail_idx` are `Option`: a fork that never crossed that boundary reads the base.

Every `StateId` holder is re-based at finalization (section 5).
Holders are the fork-choice nodes, `last_applied`, precomputed epochs, held blocks, and block production.
The published head's `StateId` lives inline in the control word (section 4).

## 2. Append-only writes and `commit`

- A **writer exists only by rolling** a new slot: fresh, or derived from a parent id.
  There is no way to re-open a committed slot for writing.
- An **id exists only by committing**: `Slot::commit(self)` and `TreeWriteView::commit(self)` consume the writer.
- A committed slot is **never mutated again**.
  It is promoted into the base at finalization, or freed after it.

This gives the central invariant: *everything reachable from a published `StateId` is immutable*.
That is what lets readers run without locks.

`StateId` follows the same rule.
It has no `Default`, and only `StateWriterView::commit` assembles one.

Rings grow by doubling under non-finality.
A grow publishes a new buffer and retains the old one until the `Ring` drops.
Growing per-fork collections use `silver_state_memory::RetainedVec` for the same reason.
A racing reader therefore never dereferences freed memory.

## 3. The write path (one block)

```
parent: StateId
   │
   ▼
owner.apply_block_view(parent) -> ForkWriter      rolls every per-block tier, holds the writers
   │
   ├─ stf::process_slots(cfg, &mut fork, ..)       epoch boundary: rolls and commits the epoch
   │     └─ process_epoch(..)                      entry; longtail only if its gate fires
   ├─ stf::process_block_body(cfg, &mut fork, ..)
   ▼
fork.commit()                                     consumes the writers, assembles the child StateId
   │
   ▼
owner.publish_state_id(child)                     one seqlock write: the only cross-thread sync
```

`ForkWriter` holds the `StateWriterView` plus `&mut EpochGroup` and `&mut LongtailGroup`.
Boundary tiers travel as ids, not resolved views.
A resolved view shared-borrows the group that a later roll needs `&mut` on.

Rolls never touch the seqlock.
A block in progress is invisible to readers until its publish.

## 4. The read paths

| view | who | sees |
|---|---|---|
| `StateReadView` | any thread, via `BeaconStateReader::read` / `read_pinned` | tiers safe to read during a concurrent write |
| `StateView` | writer thread, via `owner.read_view` / `ForkWriter::read` | adds eth1 votes, pending queues, effective increments, historical summaries |

`StateView` dereferences to `StateReadView`.
The split is enforced by `compile_fail` doctests on `StateReadView`.

The cross-thread read is an optimistic seqlock read over the control word `{state_id, finalize_version}`:

```
reader loop:
  ctrl = read_copy()            spin while finalize_version is odd
  fence(Acquire)
  run the closure on state_read_view(ctrl.state_id)
  fence(Acquire)
  finalize_version unchanged? → accept, else retry
```

A publish rewrites `state_id` but keeps the finalize counter.
Tiers are append-only between finalizations, so a publish never invalidates an in-flight read.
Only the finalize window bumps the counter.

`pin` + `read_pinned` reuse one head across many reads until the next finalize.
Checkpoint encoding (`begin_checkpoint` / `checkpoint_chunk`) restarts when a finalize lands.
It also takes the groups' `with_finalized_locked` for pending queues and historical summaries.

The state allocation is shared as `Arc<StateCell>`, the seqlock's one `unsafe`.
A reader handle can never dangle, whatever the teardown order.

## 5. Finalization: the only reader-blocking window

`BeaconStateTile::finalize` runs when fork-choice finality advances past node 0:

```
fork_choice.prune(), drop outdated held/precomputed state ids      readers: unaffected
┌─ state.write(): finalize_version goes odd ─────────────────────┐ readers: spin
│  BeaconState::finalize(winner, every live StateId):            │
│    ring groups: re-anchor survivors into fresh slots,          │
│                 then promote the winner delta into the base    │
│    tree groups: adopt the winner's page table as the base;     │
│                 survivor ids stay valid unchanged              │
│  set_state_id(last_applied)                                    │
└─ guard drop: control word + even counter in one write ─────────┘
prune operation pools against the new finalized state             readers: unaffected
```

Re-anchoring gives survivors new ids, so published slots are never re-opened.
The sparse re-base rule is `Edits::rebase_and_prune_from`.
It runs before promotion, because it reads the old base.

The window must block readers.
Their views borrow directly into the base allocations that promotion rewrites in place.

`write()` is for finalization only (plus EF-test hooks).
Rolls never take it.

## 6. Lifecycle: no state before the snapshot

- `BeaconState::decompose(ssz, cfg, pubkeys)` builds a state from real SSZ.
  It picks the Fulu or Gloas decoder from `fork.current_version`.
  `from_checkpoint` adds the decompressed-pubkeys sidecar.
  The test constructors are `#[doc(hidden)]`.
- The tile is built only once a checkpoint state exists (`CheckpointState`).
  Before the first `publish_state_id`, the control seqlock is unwritten and `reader.read(..)` returns `None`.
- `fresh_fork_writer` rolls the anchor fork off the bases.
  The tile commits it, seeds fork choice, and publishes it.

## 7. Rules and what enforces them

| rule | enforced by |
|---|---|
| writer only from a roll | ring and tree API surface |
| id only from `commit` | `commit(self)` consumes the writer |
| published slots immutable | no re-open API exists |
| bundle only from committed ids | `StateId` has no `Default` |
| shared readers cannot reach freeable collections | `StateReadView` type, `compile_fail` doctests |
| nothing readable before publish | unwritten control seqlock |
