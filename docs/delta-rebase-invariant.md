# Delta rebase invariant

Finalization moves the base under every surviving fork.
This note states what keeps each survivor's state unchanged across that move.
Read `beacon-state-architecture.md` first for groups, forks and the finalize window.

## Where it applies

Only ring groups with sparse `Edits` need a rebase:

| group | delta | rebase call |
|---|---|---|
| `validators` | seven `Edits` columns + `appended` | `ValidatorsDelta::rebase_and_prune_from` |
| `builders` | one `Edits<Builder>` + `appended` | `BuildersDelta::rebase_and_prune_from` |

Both delegate each column to `Edits::rebase_and_prune_from`.

The other groups do not rebase:

- Tree groups, including the `validators` and `builders` hash columns, finalize by page-table adoption.
  Survivor ids stay valid unchanged.
- Eth1 and pending drop the promoted prefix of their append logs.
- Slot, epoch and longtail copy the whole working copy into a fresh slot.

## Model

A fork's delta has a `base_count`, an `appended` tail, and sparse `Edits` keyed by absolute index.
Indices below `base_count` read through to the base `B` unless edited.
Indices at or above `base_count` read from `appended`, then any edit on top.

`S` is the fork's true state, what its blocks produced.
The delta is valid when every read returns `S`.
For indices below `base_count`, that splits into two halves:

```
(a)    D[i] = S[i]   for every edited i          every edit is correct
(INV)  dom(D) ⊇ { i < base_count : S[i] ≠ B[i] }  carry an edit wherever you differ from B
```

Edits stay correct on their own.
INV is the half at risk: moving `B` can make an unedited index differ from the new base.

## The re-anchor pass

Finalizing winner `W` moves the base from `B` (count `n`) to `B'` (count `n' = W.base_count + W.appended.len()`).
Each survivor is re-anchored into a fresh slot by one sorted merge of its edits with `W`'s edits.

`old(i)` is the value at `i` before `W`'s edits.
It reads `B[i]` for `i < n`, else `W`'s appended record (`winner.unedited`).
Then `B'[i]` is `W[i]` where `W` has an edit, else `old(i)`.

| survivor at `i` | winner at `i` | output edit |
|---|---|---|
| edit `s` | edit `w` | `s` if `s ≠ w` |
| edit `s` | none, `i < n'` | `s` if `s ≠ old(i)` |
| edit `s` | none, `i ≥ n'` | `s`, always |
| none | edit `w` | `old(i)` if `old(i) ≠ w` (the pin) |
| none | none | none |

The survivor also drops up to `n' − n` leading records of `appended`, which `W` promoted.
Its new `base_count` is `n'`.

The pass reads `old(i)` from the finalized base.
So it must run before `promote_into_base` overwrites that base.

## Proof sketch

Take a survivor valid over `B`.
Check each row reads the same value before and after:

- **Survivor edit.**
  Before, the read is `s`.
  After, `s` is kept unless it equals `B'[i]`, which then reads `s` anyway.
  Indices `≥ n'` have no new base, so their edits are always kept.
- **Gap, winner edit (the pin).**
  Before, the gap reads `old(i)`.
  After, `B'[i] = w` would leak the winner's value.
  The pin restores `old(i)`, unless it already equals `w`.
- **Gap, no winner edit.**
  Before, the gap reads `old(i)`; after, it reads `B'[i] = old(i)`.

The result also satisfies INV over `B'`: every kept edit differs from `B'`, and every gap equals it.
So the next finalization starts from a valid delta again.

Two gap reads above rely on **descent**: survivors descend from `W`.
For `n ≤ i < n'`, the survivor's gap reads its own `appended` record.
That equals `W`'s record only because the survivor inherited `W`'s appended prefix.
The prefix drop relies on the same fact.
`appended` records are never mutated; changes go through `Edits` for this reason.

## Why winner-only indices exist

A survivor rolled from `W` inherits all of `W`'s edits.
So a winner-only index appears only after an earlier pass pruned a reverted edit:

```
base 0 <- D1 (a) <- D2 (b) <- D3 (a)
```

| step | base | `D3` edit | `D3` read |
|---|---|---|---|
| finalize `D1` | `a` | pruned (`a = B'`) | `a` |
| finalize `D2`, no pin | `b` | none | **`b`, wrong** |
| finalize `D2`, with pin | `b` | `a` (from `old`) | `a` |

Without the pin, `D3` reads `b`, a value it never set.
The pin captures `a` from the old base before promotion moves it.

## Tests

| test | pins |
|---|---|
| `sparse::tests::rebase_and_prune_pins_injects_overrides_and_drops_redundant` (`sparse/tests.rs:12`) | every row; idx 0 and 6 are the pin, idx 2 a skipped pin, idx 3 and 4 the prunes |
| `sparse::tests::rebase_and_prune_keeps_survivor_appended_indices` (`sparse/tests.rs:36`) | edits at or above `new_count` are kept |
| `validators::tests::descendant_view_survives_finalize` | a re-anchored child keeps its reads and root |
| `builders::tests::descendant_survives_finalize`, `survivor_edit_past_base_capacity` | the same for builders, including an edit on a promoted appended index |

No ring-group test runs the full two-finalization `a → b → a` sequence.
`tree::tests::aba_finalize_keeps_reverted_value` covers it for tree groups, which need no pin.
