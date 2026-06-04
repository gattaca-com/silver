# Delta rebase invariant

## Setup

One large list of values (e.g. validator balances) evolves as blocks arrive. The
chain forks: several candidate "latest states" coexist, one per branch. A full
list per fork would be wasteful — forks mostly agree — so we keep one shared
**base** `B` (the last agreed state) plus, per fork, a sparse **delta** `D` of the
indices it changed. Untouched indices read through to `B`.

When a fork **finalizes** it folds into the base, *becoming* the new base; forks
not descended from it are discarded, and the rest are **survivors**. Finalization
moves `B` out from under every survivor. This note states the invariant that keeps
each survivor's state unchanged across that move, the operations that maintain it,
and why they do.

(Each field also carries a parallel Merkle overlay used for hashing. It obeys this
same invariant and moves in lockstep, so we reason about one delta.)

## Model

`B` is **total**: the finalized values, padded with spec-defaults out to capacity.
Every index therefore has a base value, and appending past the finalized count is
just a `set` on a default slot — no separate case.

`D` is a partial map; `dom(D)` is the set of indices it covers.

```
view(i) = D[i]   if i ∈ dom(D)      (an edit)
        = B[i]   otherwise           (read through to base)
```

`S` is the fork's **true state** — what its blocks produced. `D` is **valid** when
it reproduces `S` over `B`:

```
(VAL)   view(i) = S[i]   for every i
```

Splitting VAL by case gives two halves:

```
(a)   D[i] = S[i]   for i ∈ dom(D)      every edit is correct
(b)   B[i] = S[i]   for i ∉ dom(D)      every gap already matches the base
```

Half (b), stated as its contrapositive, is the **invariant**:

```
(INV)   dom(D) ⊇ { i : S[i] ≠ B[i] }     "carry an edit wherever you differ from B"
```

so

```
VAL  ⟺  (a) ∧ INV.
```

Keeping a delta valid is exactly keeping its edits correct *and* maintaining INV.
INV is the half at risk: when finalization moves `B`, an index that matched the old
base can differ from the new one, demanding an edit that may not be there. (INV is
required only **at rest**, between finalizations — the sequence below breaks it
mid-flight on purpose.)

## Operations

`B ⊕ W` is `B` overwritten at the winner's indices: `(B ⊕ W)[i] = W[i]` if
`i ∈ dom(W)`, else `B[i]`.

| op | effect | role |
|---|---|---|
| `set(i, v)` | `D[i] := v` — how a fork's blocks define `S` | builds a valid delta |
| `rebase(W)` | for each `i ∈ dom(W)\dom(D)`: `D[i] := B[i]`, using the **old** `B` | re-pins gaps the move would expose |
| `promote(W)` | `B := B ⊕ W` | advances the base for everyone else |
| `prune` | drop every `i` with `D[i] = B[i]` (against the current base) | removes slack, keeps `D` sparse |

They run in exactly one order per finalization, and the order is the whole point:

```
rebase survivors (old B)  →  promote winner (B → B')  →  prune survivors (new B')
```

`rebase` must run first: it captures the old base value before `promote` overwrites
it.

## Proof

Fix a survivor `D`, valid over `B`. Let `B' = B ⊕ W`. `S` does not change.

**rebase + promote preserve VAL.** rebase adds, for each `i ∈ dom(W)\dom(D)`, the
edit `D[i] := B[i]`. Such an `i` was a gap, so (b) gives `B[i] = S[i]`: the new edit
is correct. Old edits and remaining gaps are untouched, so VAL still holds over `B`
— and now `dom(D) ⊇ dom(W)`.

Now promote to `B'`. Take any gap `i ∉ dom(D)`. Since `dom(D) ⊇ dom(W)`, also
`i ∉ dom(W)`, so `B'[i] = B[i]`; and `i` was a gap, so `B[i] = S[i]`. Hence
`B'[i] = S[i]` — half (b) holds over `B'`. Edits are unchanged, so (a) holds.
Therefore VAL holds over `B'`. ∎

**prune preserves VAL.** It drops `i` only when `D[i] = B'[i]`. By (a) `D[i] = S[i]`,
so `S[i] = B'[i]`: after dropping, the gap reads `B'[i] = S[i]`, satisfying (b); and
`i ∉ { S ≠ B' }`, so INV survives too.

**Induction.** A fork's `set`s build a valid delta. Each finalization is
rebase → promote → prune, each step preserving VAL, so every survivor stays valid
after any number of finalizations — provided rebase precedes prune.

Descent is not needed for correctness; it only shows rebase is *usually* a no-op. A
survivor descends from the winner, so it already carries the winner's edits:
`dom(D) ⊇ dom(W)`, and rebase's loop is empty. rebase has work only where `prune`
once dropped a reverted edit — the case below.

## The one case rebase fires

One index, base `0`, three forks each built on the previous — each arrow sets the
index to a new value:

```
base <- a (D1) <- b (D2) <- a (D3)
```

so `D3`'s true value is `a` again. When `D1` finalizes (base `→ a`), `D3`'s edit equals the
base, so `prune` drops it — leaving `D3` a gap exactly where the next winner `D2`
holds an edit: the `dom(W)\dom(D)` case. Now finalize `D2` (base `a → b`):

| `D3`'s index | base | `D3` edit | `D3` view |
|---|---|---|---|
| after `D1` finalizes | `a` | — (pruned) | `a` |
| **no rebase**, then promote `D2` | `b` | — | **`b` ✗** |
| **rebase** (old base) | `a` | `a` | `a` |
| then promote `D2` | `b` | `a` | **`a` ✓** |

Without rebase, `D3` silently flips `a → b` — a value it never set. rebase re-pins
`a` from the old base before promote moves it, which is exactly the
`rebase + promote` step of the proof.
