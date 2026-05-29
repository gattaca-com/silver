# Perf-regression test

Replays committed mainnet fixtures through `process_block` and fails if
per-block / per-validator hashing time exceeds `thresholds.json`. Same path
local and CI: `just perf-local`, driven by `sync_pm_bs_perf.rs`.

## Setup

Fixtures are large SSZ blobs in [git-lfs], so a plain clone gives only
pointers. Install the tools, then pull the data:

```sh
sudo apt-get install -y git-lfs just   # Debian/Ubuntu
git lfs install                        # once per machine
git lfs pull                           # download fixture blobs into this checkout
```

## Run

```sh
just perf-local
```

Ceilings live in `crates/e2e/data/perf/thresholds.json` (either field `null`
to disable) — no env overrides; tune by editing it in a PR.

## Refresh

```sh
just perf-update-fixtures              # 128 blocks; --blocks N / --continue to adjust
```

Fetches a fresh finalized state + N blocks, overwriting existing fixtures.
`--continue` keeps what's on disk and fills only missing slots. Then commit
via git-lfs:

```sh
git add crates/e2e/data/perf/{finalized_state.ssz,next_block_*.ssz,expected.json}
git lfs ls-files | grep next_block_    # must list them — else lfs filter didn't run
git commit -m "Refresh perf fixtures"
```

[git-lfs]: https://git-lfs.com
