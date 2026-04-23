# silver_beacon_state

## EF-based tests

Two test suites read vectors published by the Ethereum Foundation at
[`consensus-spec-tests`](https://github.com/ethereum/consensus-specs/releases)
(mainnet, Fulu fork):

- `tests/sync_scenarios.rs` — YAML-driven scenarios that drive
  `BeaconStateTile` through a real `SilverSpine` adapter. Each scenario
  loads a `*.ssz_snappy` checkpoint/block and asserts observable state
  (mode, head slot).
- `tests/ssz_view_fixtures.rs` — field-level verification of every
  `silver_common::ssz_view` accessor against `ssz_static/<Container>/ssz_random`
  fixtures.

Both suites expect the vectors to be present and fail if they
aren't — run `make` first. `ssz_view_fixtures` asserts each container
directory is non-empty; `sync_scenarios` panics when `snappy_decode`
can't open the referenced file. CI runs `make` before `cargo test`.

### Fetch vectors

```sh
make -C crates/beacon_state
```

Downloads `mainnet.tar.gz` (pinned in the `Makefile`) and extracts to
`crates/beacon_state/consensus-spec-tests/`. The directory is gitignored.

### Run

```sh
# all tests
cargo test -p silver_beacon_state

# only scenarios
cargo test -p silver_beacon_state --test sync_scenarios

# only ssz_view field checks
cargo test -p silver_beacon_state --test ssz_view_fixtures
```
