# rustfmt.toml relies on nightly-only options, and min-publish-age is a nightly
# cargo feature. Everything else runs on the stable pin in rust-toolchain.toml,
# so lints and tests always match the shipped compiler.
nightly := "nightly-2026-06-21"

# Update dependencies under the publish-age cooldown (.cargo/config.toml):
# versions published less than 14 days ago are excluded from resolution.
# Resolution done on stable (cargo add, plain cargo update) is NOT covered;
# this recipe is the intended path for routine updates. Git dependencies are
# outside the cooldown entirely — no publish age exists for them. Ours are
# rev-pinned, so review the rev when you bump it by hand.
update *args:
  rustup toolchain install {{nightly}} --profile minimal > /dev/null 2>&1 && \
  cargo +{{nightly}} update -Z min-publish-age {{args}}

# Escape hatch for an urgent update to a version younger than the cooldown,
# e.g. `just update-allow h2 0.4.16`. The bypass applies to the WHOLE
# resolution of this invocation (transitive picks included), so review the
# full Cargo.lock diff, not just the target package.
update-allow package version:
  @echo "NOTE: the cooldown bypass is invocation-global; review the full Cargo.lock diff."
  rustup toolchain install {{nightly}} --profile minimal > /dev/null 2>&1 && \
  CARGO_RESOLVER_INCOMPATIBLE_PUBLISH_AGE=allow \
  cargo +{{nightly}} update -Z min-publish-age -p {{package}} --precise {{version}}

# Warn when the committed Cargo.lock pins crates younger than the cooldown.
cooldown-check:
  @rustup toolchain install {{nightly}} --profile minimal > /dev/null 2>&1 || \
  { echo "SKIPPED: could not install {{nightly}}"; exit 0; }; \
  out=$(cargo +{{nightly}} update --dry-run -Z min-publish-age 2>&1 | grep -E "Downgrading|is too new" || true); \
  if [ -n "$out" ]; then echo "WARNING: lockfile pins crates younger than the publish-age cooldown:"; echo "$out"; fi

fmt:
  rustup toolchain install {{nightly}} --component rustfmt > /dev/null 2>&1 && \
  cargo +{{nightly}} fmt

fmt-check:
  rustup toolchain install {{nightly}} --component rustfmt > /dev/null 2>&1 && \
  cargo +{{nightly}} fmt --check

clippy:
	cargo clippy --locked --all-features --no-deps -- -D warnings -A clippy::collapsible_if

clippy-fix:
	cargo clippy --fix --locked --all-features --no-deps --allow-dirty -- -D warnings -A clippy::collapsible_if

machete:
  cargo install --locked cargo-machete && \
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
  cargo test --locked --workspace --features "silver_beacon_state/ef_tests,silver_e2e/lh-client" --profile release-with-debug --no-fail-fast 2>&1

# As above but using `nextest`
nextest:
  cargo install --locked cargo-nextest && \
  cargo nextest r --locked --features "silver_beacon_state/ef_tests,silver_e2e/lh-client" --cargo-profile release-with-debug --no-fail-fast --status-level skip

# Run the perf-regression harness on the committed mainnet fixtures.
# Release-only (no debug-assertions — they skew the counters); reads crates/e2e/data/perf (git-lfs). CI runs this too.
# Pass a path to also dump the raw #[timed] FXT trace (Perfetto/magic-trace), e.g. `just perf-local perf-local.fxt`.
perf-local file="" events="instructions,cycles,l1d-misses,l2-misses,l3-misses":
  PERF_FXT="{{file}}" PERF_EVENTS="{{events}}" cargo test --locked --release -p silver_e2e --features perf-counters,alloc-profile --test sync_pm_bs_perf -- --ignored --nocapture

# Refresh data/da from a running beacon node: state, blocks, sidecars and the
# arrival order (the latter from its telemetry, so its daemon must be up and
# CH_URL must point at it). Always the window after the node's newest checkpoint.
da-fixtures host:
  cargo run --release -p silver_e2e --bin da_fixtures -- {{host}}

# Replay prod-captured column gossip through the real DataColumnsTile, reporting
# each slot's custody-complete time and the `#[timed]` call tree. `--slots N`
# caps the slots replayed (default 9); `--columns N` is the custody set (default
# 128)
da-local *args='':
  cargo run --release -p silver_e2e --features alloc-profile --bin da_replay -- {{args}}

# Run surfer (the metrics TUI). It folds the watched silver's `#[timed]` perf
# counters into the flamegraph whenever that silver published them (the producer
# opts into counters via its own `perf` feature); otherwise it shows timing
# only. Counter labels come from the silver's published schema, so no event list
# is needed here. Extra args pass through as `[BASE_DIR] [APP_NAME]`.
surfer *args='':
  cargo run --locked --release -p silver_surfer -- {{args}}

# Refresh crates/e2e/data/perf from mainnet (~13 min for the default 128
# blocks at lodestar's ~1 req / 6 s cap). Commit the result via git-lfs.
# Pass `--continue` (and/or `--blocks N`) to resume after a network blip.
perf-update-fixtures *args='--blocks 128':
  cargo run --locked --release -p silver_e2e --bin perf_update_fixtures -- {{args}}
