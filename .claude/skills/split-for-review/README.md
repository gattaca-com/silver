# split-for-review

Type `/split-for-review` on a big uncommitted change.
Claude cuts it into small units and stages one at a time; you review and commit each.

Why:

- **Small chunks to review, full context kept.** You read one unit; the agent still holds the whole change.
- **Rework while you review.** Ask for a design, architecture, implementation or simplification change on the current unit.
  The scope is small, so the agent does it well, and it carries the change into the later units.
- **Every commit stands alone.** Each unit passes `just fmt-check`, `just clippy` and `just nextest` in an isolated checkout.
- **Parallel PRs, fewer rebases.** The default is one PR. When you ask for more, independent PRs branch off `main`.
  A PR stacks only on one whose symbols it uses.

## Example

A perf branch, simplified. Claude proposes this plan before staging anything:

| PR | Unit | What | Depends on | Lines |
|---|---|---|---|---|
| **1. Faster dev loop** (`main`) | 1 | `buf.yaml` per proto crate: stop needless rebuilds | — | +3 |
| | 2 | `perf-local` pubkey cache | — | ~80 |
| **2. Attestation path** (`main`) | 3 | Interned votes: `Vote` 96 B → 8 B | — | ~180 |
| | 4 | Finalize after the head is published | — | ~15 |
| | 5 | `BlockAttestations` bundle: one rehash per body | — | ~200 |
| | 6 | Effective-balance increments read by `apply_flags` | unit 5's `apply_flags` | ~70 |
| **3. Page pool** (`main`) | 7 | Pages in fixed segments: fixes a racing-reader segfault | — | ~120 |

All three PRs branch from `main`, so none waits on another.
Unit 4 went through four design rounds in review before it was committed.

## Reviewing a unit

The unit is what's in the index. Open **Staged Changes** in your IDE's source control panel and click through the files.
Or use `git diff --cached`. Unstaged changes are the later units, so ignore them.
Ask Claude for any edit rather than typing it in, so the later units stay in sync.

## Driving it

| you say | Claude does |
|---|---|
| `unit 1` / `next unit` | stages the unit, verifies it alone, reports what to look at |
| *you commit* | — |
| "simplify this" / "redesign X" / "rename Y" | changes the unit and later units, re-verifies |
| "regroup into two PRs" | re-cuts the plan |
| `status` | which units landed, which is staged, which remain |

Claude never commits or pushes. It suggests a branch per PR, and creates one only when you say so.
