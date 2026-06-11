# Beacon state: groups, forks, and the read/write model

How `silver_beacon_state_data` stores the beacon state and how the single
writer (the beacon-state tile) and lock-free readers (e.g. the storage tile)
share it.

## 1. The state is a set of independent groups

There is no monolithic state object. `BeaconState` is a bag of per-tier
**groups**, split by write cadence, plus one immutable block:

```
BeaconState
├── immutable: Immutable            // genesis data, fork schedule — never changes
│
│   per-block tiers (rolled for every block)
├── validators        ─┐
├── balances           │  Group = finalized base + Ring of per-fork deltas
├── eth1               │
├── pending            │
├── previous_participation
├── current_participation
├── inactivity         │
├── slot_states       ─┘
│
│   boundary tiers (rolled only when their boundary event fires)
├── epoch                           // epoch transition
└── longtail                        // sync-committee rotation / historical summaries
```

Every group has the same shape:

```
          Group
┌───────────────────────┐    finalized = the canonical FINALIZED state of this
│ finalized: Finalized* │                tier (mutated only during finalization)
│                       │
│ deltas: Ring<G,Δ,N>   │    ring      = N reusable slots holding per-fork
│  ┌───┬───┬───┬───┐    │                DELTAS (what a fork changed vs the
│  │ Δ │ Δ │ Δ │ Δ │…   │                finalized state)
│  └───┴───┴───┴───┘    │
└───────────────────────┘    a fork's effective value = finalized ⊕ its delta
```

A **fork** (a block's post-state) is identified by a `StateId` — a ~72-byte
`Copy` bundle of one typed ring id per tier:

```
StateId { validators_idx, balances_idx, eth1_idx, pending_idx, …, slot_idx,
          epoch_idx: Option<EpochId>, longtail_idx: Option<LongtailId> }
```

The boundary tiers are `Option` because a fork that never crossed an epoch
boundary simply reads the base. Fork-choice nodes own their fork's `StateId`
by value; the published head's `StateId` lives inline in the control word
(section 4).

## 2. Append-only writes and `commit`

The ring API is deliberately tiny — `get(id)`, `roll_fresh`, `roll_from`,
`roll_fresh_deriving`, `free`/`free_outdated`:

* a **writer exists only by rolling** a new slot (fresh, or copy-on-write
  from a parent id). There is no way to re-open a slot by id for writing.
* an **id exists only by committing**: `Slot::commit(self) -> Id` consumes
  the writer. While a writer is live, nobody can name (or read) its slot.
* a committed slot is **never mutated again** — it is either promoted into
  the base at finalization or reclaimed (`free`) after it.

This gives the central invariant: *everything reachable from a published
`StateId` is immutable*. That is what lets readers run without locks.

`StateId` itself follows the same rule: it has no `Default` and is only
assembled by `StateWriterView::commit`, from the held writers' ids — a bundle
cannot exist before its entries do.

## 3. The write path (one block)

```
parent: StateId
   │
   ▼
apply_block_view(parent)              owner rolls the 8 per-block tiers
   │   roll_from(parent.X_idx) ×8     and HOLDS the writers
   ▼
StateWriterView { validators, balances, eth1, pending, …, slot }  ← held writers
   │
   ├─ process_slots(...)              epoch boundary? roll + HOLD the epoch
   │     └─ process_epoch(...)        writer; longtail iff its gate fires;
   │                                  their ids return as plain data
   ├─ process_block_body(...)         leaves take &mut view (the holder) or
   │                                  the single tier they touch
   ▼
view.commit(epoch_idx, longtail_idx)  consumes the writers, assembles the
   │                                  child StateId
   ▼
publish_state_id(child)               ONE small seqlock write — the only
                                      cross-thread synchronization on the
                                      block path
```

Notes:

* The holder (`StateWriterView`) is a **methodless field bundle**. Leaves
  touching one tier take that tier's writer/view; leaves touching many take
  `&mut view` and bind fields locally. There are no whole-state delegator
  methods.
* The boundary groups (`EpochGroup`, `LongtailGroup`) travel as separate
  `&mut` args next to the holder. Their *ids* — not resolved views — cross
  any call that may still roll, because a resolved view shared-borrows the
  group the roll needs `&mut` on.
* Rolls never touch the seqlock. Readers are unaffected by a block being
  processed (its slots are unreachable until publish).

## 4. The read paths

One read currency: `StateReadView`, a `Copy`-field bundle of all ten tier
read views (plus `imm`), resolved from a `StateId` by the single resolver
`BeaconState::read_view`. Consumers read tier fields directly
(`rv.validators.pubkey(i)`, `rv.epoch.proposer_at(idx)`, …).

```
writer thread (tile's own reads):          cross-thread (lock-free):
  owner.read_view(state_id)                  reader.read(|rv| { … })
  view.read(epoch_v, longtail_v)
       │                                          │
       ▼                                          ▼
  resolve StateId ─────────────► StateReadView ◄─── resolve published StateId
```

The cross-thread protocol (`BeaconStateReader::read`) is an optimistic
seqlock read:

```
            writer                              reader
              │                                   │
 publish ───► │ control = Seqlock<{StateId,       │ loop:
              │           finalize_version}>      │   ctrl = read_copy()
              │   counter odd = finalize window   │     ── spins while the counter is odd
              │                                   │   fence(Acquire)
              │                                   │   rv = state.read_view(ctrl.state_id)
              │                                   │   … read tier data …
              │                                   │   fence(Acquire)
              │                                   │   finalize_version unchanged? → accept
              │                                   │   else                        → retry
```

A publish rewrites `state_id` but carries the finalize counter unchanged —
tiers are append-only between finalizations, so a publish never invalidates
an in-flight read. Only the finalize window (which rebases and frees tier
slots) bumps the counter.

The state allocation is shared as `Arc<StateCell>` (an `UnsafeCell` newtype,
the seqlock's one irreducible `unsafe`): a reader handle can never dangle,
whatever the teardown order. Reads cost a pointer deref — the `Arc` refcount
is touched only at clone/drop.

Caveat: the lock-free path must not read the *contents* of realloc-prone
`Vec` bases (pending queues, longtail historical summaries) — a finalize
realloc can race them; those reads go through the groups' promote barriers
(`with_finalized_locked`). The fixed-size bases — including the inline
fixed-capacity eth1 vote list — are safe to read optimistically.

## 5. Finalization — the only reader-blocking window

When fork choice finalizes a block, its deltas are folded into the bases and
every surviving fork is re-anchored:

```
maybe_finalize:
  fork-choice prune, survivor collection            readers: unaffected
  ┌─ write() ── version goes ODD ──────────────┐
  │  for each group:                            │    readers: spin
  │    finalize(winner, survivors):             │
  │      free forks older than the winner       │
  │      reanchor survivors → FRESH slots       │   (append-only: survivors
  │      promote winner delta into base         │    get new ids, published
  │      free the survivors' old slots          │    slots are not re-opened)
  │  rewrite survivor StateIds (locals)         │
  │  stage the head's rewritten StateId         │
  └─ guard drop ── control word + version even ─┘
  write rewritten StateIds back to fork-choice nodes  readers: unaffected
```

The window must block readers: their views borrow directly into the base
allocations being rewritten in place. Budget: a few milliseconds of base
promotion once per finalization — everything else on the read side is
wait-free (plus one ≤80-byte retry per publish).

`write()` is for **finalization and bootstrap only**. Rolls never take it.

## 6. Lifecycle: no state before the snapshot

* `BeaconState::decompose(ssz, cfg, pubkeys) -> Result<Self>` is the only public
  constructor — a state exists only from real data.
* Before the snapshot arrives (checkpoint file or network sync), the owner
  holds a writer-private stub and the control seqlock is **unwritten**:
  `reader.read(..)` returns `None`. Nothing is observable until `bootstrap`
  decomposes the snapshot (replacing the stub under the write window) and
  publishes the anchor `StateId`.
* `BeaconState::roll_fresh()` rolls one fresh fork per per-block tier and
  assembles the anchor bundle — used at bootstrap and as the pre-bootstrap
  placeholder head.

## 7. Cheat sheet

| operation            | who          | reader impact            |
|----------------------|--------------|---------------------------|
| roll / STF / commit  | block path   | none (unpublished slots)  |
| `publish_state_id`   | block path   | none (in-flight reads stand) |
| `write()` window     | finalize, bootstrap | spin for the window |
| reading              | anyone       | wait-free, no refcounts   |

| rule | enforced by |
|------|-------------|
| writer only from a roll          | ring API surface              |
| id only from `commit`            | `Slot::commit(self)`          |
| published slots immutable        | no re-open API exists         |
| bundle only from committed ids   | `StateId` has no `Default`    |
| nothing readable before publish  | unwritten control seqlock     |
| state only from real data        | `decompose` is the only ctor  |
