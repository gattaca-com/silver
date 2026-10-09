#!/usr/bin/env bash
# Regenerates LeanBlsSimd/Extracted/Types.lean and Funs.lean from crates/bls_simd/src with Charon
# and Aeneas. The hand-written TypesExternal.lean and FunsExternal.lean are left alone, so
# `git diff` shows how the extraction drifted from the committed one.
#
# AENEAS_DIR must be an Aeneas checkout at the revision lake-manifest.json pins for `aeneas`,
# with Aeneas built (`make`) and Charon built at its pin (`make setup-charon`). Charon needs
# rustup and the nightly in $AENEAS_DIR/charon/rust-toolchain.
set -euo pipefail

: "${AENEAS_DIR:?set AENEAS_DIR to an Aeneas checkout with Charon and Aeneas built}"

lean_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
crate_dir=$(cd "$lean_dir/../.." && pwd)

AENEAS_DIR=$(cd "$AENEAS_DIR" && pwd)
aeneas="$AENEAS_DIR/bin/aeneas"
charon="$AENEAS_DIR/charon/bin/charon"

pinned=$(python3 -I -c 'import json, sys
print(next(p["rev"] for p in json.load(open(sys.argv[1]))["packages"] if p["name"] == "aeneas"))' \
  "$lean_dir/lake-manifest.json")
actual=$(git -C "$AENEAS_DIR" rev-parse HEAD)
if [[ $actual != "$pinned" ]]; then
  echo "AENEAS_DIR is at $actual; lake-manifest.json pins aeneas at $pinned" >&2
  exit 1
fi
# The binaries may predate the checkout: Aeneas reports its commit, Charon only its crate version.
aeneas_built=$("$aeneas" -version | awk '{print $2}')
if [[ -z $aeneas_built || $pinned != "$aeneas_built"* ]]; then
  echo "$aeneas was built from $aeneas_built, not $pinned; rebuild it" >&2
  exit 1
fi
charon_pinned=$(tail -n 1 "$AENEAS_DIR/charon-pin")
charon_actual=$(git -C "$AENEAS_DIR/charon" rev-parse HEAD)
if [[ $charon_actual != "$charon_pinned" ]]; then
  echo "AENEAS_DIR/charon is at $charon_actual; AENEAS_DIR/charon-pin says $charon_pinned" >&2
  exit 1
fi
charon_version=$(sed -n 's/^version = "\(.*\)"/\1/p' "$AENEAS_DIR/charon/charon/Cargo.toml" | head -n 1)
if [[ $("$charon" version) != "$charon_version" ]]; then
  echo "$charon reports $("$charon" version), not the checkout's $charon_version; rebuild it" >&2
  exit 1
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# A separate target directory keeps Charon's nightly build out of the workspace's `target/`.
# `fp8::lanes` is a `transmute`, which Aeneas cannot translate; FunsExternal.lean defines it.
(cd "$crate_dir" &&
  CARGO_TARGET_DIR="$work/target" "$charon" cargo --preset aeneas \
    --start-from crate::decompress_g2::decompress --opaque crate::fp8::lanes \
    --dest-file "$work/silver_bls_simd.llbc")

"$aeneas" -backend lean -split-files -subdir LeanBlsSimd/Extracted \
  -dest "$work/lean" "$work/silver_bls_simd.llbc"

cp "$work/lean/LeanBlsSimd/Extracted/Types.lean" "$work/lean/LeanBlsSimd/Extracted/Funs.lean" \
  "$lean_dir/LeanBlsSimd/Extracted/"
