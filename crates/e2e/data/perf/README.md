# Perf-regression fixtures

Mainnet fixtures consumed by `crates/e2e/tests/sync_pm_bs_perf.rs`:

- `finalized_state.ssz` — finalized BeaconState (~300 MB, **git-lfs**).
- `next_block_<slot>.ssz` — one SSZ block per following slot (**git-lfs**).
- `expected.json` — `{finalized_slot, final_slot, head_state_root}` — the
  authoritative post-replay state root, generated from the canonical
  mainnet archive by the updater. The test asserts hermetically against
  this; no network is touched at test time.

## Run

```
just perf-local
```

Needs `git lfs pull` on a fresh clone.

## Refresh

```
just perf-update-fixtures                              # 128 blocks (default)
just perf-update-fixtures --blocks 32                  # fewer for a quick smoke
just perf-update-fixtures --continue                   # resume after a network blip
just perf-update-fixtures --blocks 256 --continue      # both
```

Then `git add` and `git commit` — the LFS filter handles the SSZ files.

Each run fetches a fresh finalized state and `--blocks N` blocks on top of
it; existing fixtures in the directory are overwritten.

`--continue` keeps the on-disk `finalized_state.ssz` and any already-fetched
`next_block_<slot>.ssz` files, filling only the missing slots up to N —
useful when a long fetch is interrupted mid-run. Errors out if no
`finalized_state.ssz` is present.
