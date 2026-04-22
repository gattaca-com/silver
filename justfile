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

test:
  cargo test -p silver_beacon_state --features ef_tests --release 2>&1
