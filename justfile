toolchain := "nightly-2025-06-01"

fmt:
  rustup toolchain install {{toolchain}} --component rustfmt > /dev/null 2>&1 && \
  cargo +{{toolchain}} fmt

fmt-check:
  rustup toolchain install {{toolchain}} --component rustfmt > /dev/null 2>&1 && \
  cargo +{{toolchain}} fmt --check

clippy:
	cargo clippy --all-features --no-deps -- -D warnings -A clippy::collapsible_if

clippy-fix:
	cargo clippy --fix --all-features --no-deps --allow-dirty -- -D warnings -A clippy::collapsible_if

machete:
  cargo install cargo-machete && \
  cargo machete

ef-tests-download:
  make -C crates/beacon_state/tile

# Fetches the mainnet finalized state + the next N canonical blocks used
# by `checkpoint_load` and `sync_pm_bs`. Idempotent — already-cached
# fixtures are skipped.
checkpoint-fixtures:
  make -C crates/e2e checkpoint-fixtures

# Same features/crates as CI, but optimised (opt-level 3) with debug-assertions
# on so invariant checks run. Run `just ef-tests-download` + `just
# checkpoint-fixtures` first if you don't have the fixtures locally.
test:
  cargo test --workspace --features "silver_beacon_state/ef_tests,silver_e2e/lh-client" --profile release-with-debug --no-fail-fast 2>&1

# As above but using `nextest`
nextest:
  cargo install --locked cargo-nextest && \
  cargo nextest r --features "silver_beacon_state/ef_tests,silver_e2e/lh-client" --cargo-profile release-with-debug --no-fail-fast --status-level skip

# Run the perf-regression harness on the committed mainnet fixtures.
# Release-only (no debug-assertions — they skew the counters); reads crates/e2e/data/perf (git-lfs). CI runs this too.
perf-local events="instructions,cycles,l1d-misses,l2-misses,l3-misses":
  PERF_EVENTS="{{events}}" cargo test --release -p silver_e2e --features perf-counters,alloc-profile --test sync_pm_bs_perf -- --ignored --nocapture

# Run surfer (the metrics TUI). It folds the watched silver's `#[timed]` perf
# counters into the flamegraph whenever that silver published them (the producer
# opts into counters via its own `perf` feature); otherwise it shows timing
# only. Counter labels come from the silver's published schema, so no event list
# is needed here. Extra args pass through as `[BASE_DIR] [APP_NAME]`.
surfer *args='':
  cargo run --release -p silver_surfer -- {{args}}

# Refresh crates/e2e/data/perf from mainnet (~13 min for the default 128
# blocks at lodestar's ~1 req / 6 s cap). Commit the result via git-lfs.
# Pass `--continue` (and/or `--blocks N`) to resume after a network blip.
perf-update-fixtures *args='--blocks 128':
  cargo run --release -p silver_e2e --bin perf_update_fixtures -- {{args}}
