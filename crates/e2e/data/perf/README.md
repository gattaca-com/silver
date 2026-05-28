# Perf-regression fixtures

Mainnet fixtures consumed by `crates/e2e/tests/sync_pm_bs_perf.rs`:

- `finalized_state.ssz` — finalized BeaconState (~300 MB, **git-lfs**).
- `next_block_<slot>.ssz` — one SSZ block per following slot (**git-lfs**).
- `expected.json` — `{finalized_slot, final_slot, head_state_root}` — the
  authoritative post-replay state root, generated from the canonical
  mainnet archive by the updater. The test asserts hermetically against
  this; no network is touched at test time.
- `thresholds.json` — `{max_ns_per_block, max_hash_validators_ns_per_validator}`
  — regression ceilings the harness enforces. Either field can be `null`
  to disable. Same file is used by `just perf-local` and CI so they gate
  on the exact same numbers; there are no env overrides on purpose —
  tune by editing this file in a PR.

## Run

```
just perf-local
```

Needs `git lfs install && git lfs pull` on a fresh clone. Regression
ceilings come from `thresholds.json` and gate local + CI identically
(see `.github/workflows/perf.yaml`).

## Refresh

```
just perf-update-fixtures                              # 128 blocks (default)
just perf-update-fixtures --blocks 32                  # fewer for a quick smoke
just perf-update-fixtures --continue                   # resume after a network blip
just perf-update-fixtures --blocks 256 --continue      # both
```

Each run fetches a fresh finalized state and `--blocks N` blocks on top of
it; existing fixtures in the directory are overwritten.

`--continue` keeps the on-disk `finalized_state.ssz` and any already-fetched
`next_block_<slot>.ssz` files, filling only the missing slots up to N —
useful when a long fetch is interrupted mid-run. Errors out if no
`finalized_state.ssz` is present.

### Commit via git-lfs

The fixtures live in this directory but are stored in git-lfs (see
`.gitattributes` at the repo root). After a refresh:

```
git lfs install                                        # once per clone
git add crates/e2e/data/perf/finalized_state.ssz \
        crates/e2e/data/perf/next_block_*.ssz \
        crates/e2e/data/perf/expected.json
git lfs ls-files | grep next_block_ | head             # verify pointers, not raw blobs
git commit -m "Refresh perf fixtures"
```

If `git lfs ls-files` does not list the SSZ files, the LFS filter did not
run — `git lfs install` is missing or `.gitattributes` was bypassed. Fix
that before committing; raw SSZ blobs would balloon the git pack.
