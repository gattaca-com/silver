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
  make -C crates/beacon_state

# Fetches the mainnet finalized state + the next N canonical blocks used
# by `checkpoint_load` and `sync_pm_bs`. Idempotent — already-cached
# fixtures are skipped.
checkpoint-fixtures:
  make -C crates/e2e checkpoint-fixtures

# Mirrors CI's test invocation: every crate, EF spec tests on, lh-client
# e2e suite on. Run `just ef-tests-download` + `just checkpoint-fixtures`
# first if you don't have the fixtures locally.
test:
  cargo test --workspace --features "silver_beacon_state/ef_tests,silver_e2e/lh-client" --release --no-fail-fast 2>&1
