# Perf-regression test

Two replay tests run on fixtures committed to this repo: `perf-local` for the
state transition, `da-local` for the data-column path. Both call the same entry
points production calls, so a change you measure here is a real change.

## Setup

Fixtures are large SSZ blobs in [git-lfs], so a plain clone gives only
pointers. Install the tools, then pull the data:

```sh
sudo apt-get install -y git-lfs just   # Debian/Ubuntu
git lfs install                        # once per machine
git lfs pull                           # download fixture blobs into this checkout
```

## Block replay

Replays committed mainnet fixtures through `process_block` and fails if
per-block / per-validator hashing time exceeds `thresholds.json`. Same path
local and CI: `just perf-local`, driven by `sync_pm_bs_perf.rs`.

```sh
just perf-local
```

Ceilings live in `crates/e2e/data/perf/thresholds.json` (either field `null`
to disable) — no env overrides; tune by editing it in a PR.

### Refresh

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

## Data-column replay

Replays column gossip recorded from a production node through a real
`DataColumnsTile`, each sidecar at the offset the node received it: `just
da-local`, driven by `da_replay.rs`.

```sh
just da-local                          # 9 slots, full 128-column custody
just da-local --slots 3 --columns 8    # 3 slots as a node custodying 8 columns
```

`recv_*` and `proc_*` are ms into the slot: `recv_*` the replayed arrival curve
(when that share of the custody set landed), `proc_*` when the tile had
validated it, `proc_last` custody-complete. The tile's own cost is
`recv -> proc max`, the longest any one column waited between arriving and
being validated, plus `cpu`, tile CPU on the turns carrying a sidecar.

### Refresh

```sh
CH_URL=<telemetry clickhouse> just da-fixtures <user>@<beacon-host>
```

It always takes the slots right after the node's newest checkpoint. You cannot
pick other slots: the replay checks each sidecar's proposer against the
checkpoint state, and that only works for slots close to it.

The node must be ready in three ways:

- you can ssh in as `user@host` (the login user is required);
- its telemetry daemon runs and reports this same hostname;
- it still stores the sidecars for those slots (old ones are deleted).

```sh
git add crates/e2e/data/da
git lfs ls-files | grep data/da    # must list them — else lfs filter didn't run
git commit -m "Refresh DA capture"
```

[git-lfs]: https://git-lfs.com
