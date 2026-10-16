#!/usr/bin/env bash
# Usage: extract.sh [--check]
#
# Regenerate LeanBlsSimd/Extracted/{Types,Funs}.lean from crates/crypto_simd/src/bls using Charon
# and Aeneas, then print the diff. By default, replace the checked-in files with the result.
# With --check, leave them unchanged and exit 1 if the comparison finds a difference.
# The handwritten TypesExternal.lean and FunsExternal.lean are left unchanged.
#
# Aeneas records where each item comes from in a `Source: '<file>', lines <span>` comment.
# To ignore changes in source locations, replace each span's numbers with `L` before comparing.
# Everything else, including comment delimiters, must match exactly. Rust formatting or comment
# changes are therefore ignored only when their sole effect on the extraction is a moved span.
#
# AENEAS_DIR must be an Aeneas checkout at the revision lake-manifest.json pins for `aeneas`,
# with Aeneas built (`make`) and Charon built at its pin (`make setup-charon`). Charon needs
# rustup and the nightly in $AENEAS_DIR/charon/rust-toolchain.
set -euo pipefail

check=false
case "${1-}" in
  "") ;;
  --check) check=true ;;
  *)
    echo "usage: $0 [--check]" >&2
    exit 2
    ;;
esac

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
    --start-from crate::bls::decompress_g2::decompress --start-from crate::bls::uncompress_in_g1 \
    --start-from crate::bls::uncompress_in_g2 \
    --opaque crate::bls::fp8::lanes --opaque crate::bls::simd_available \
    --opaque crate::bls::uncompress_in_g1_blst --opaque crate::bls::uncompress_in_g2_blst \
    --dest-file "$work/silver_crypto_simd.llbc")

"$aeneas" -backend lean -split-files -subdir LeanBlsSimd/Extracted \
  -dest "$work/lean" "$work/silver_crypto_simd.llbc"

# Abstract feature detection and both total scalar externals. Lean adds this instance
# parameter only to generated definitions whose bodies use it; the kernels stay unchanged.
python3 -I - "$work/lean/LeanBlsSimd/Extracted/Funs.lean" <<'PY'
from pathlib import Path
import re
import sys
path = Path(sys.argv[1])
source = path.read_text()
anchor = "namespace silver_crypto_simd\n"
if source.count(anchor) != 1:
    raise SystemExit("expected exactly one silver_crypto_simd namespace")
source = source.replace(anchor, anchor + "\nvariable [bls.BlsExternals]\n", 1)
# `full` is a keyword in the imported Lean environment. Quoting preserves its name.
source, full_count = re.subn(r"\bfull\b", "«full»", source)
if full_count != 6:
    raise SystemExit(f"expected six generated full identifiers, found {full_count}")
path.write_text(source)
PY

for f in Types.lean Funs.lean; do
  for side in "$lean_dir/LeanBlsSimd/Extracted/$f" "$work/lean/LeanBlsSimd/Extracted/$f"; do
    if [[ ! -f $side ]]; then
      echo "missing $side" >&2
      exit 2
    fi
  done
done

# Only the numbers of a `lines <start>-<end>` span are masked, wherever the span sits on the line.
mask_spans() {
  sed -E "s/(Source: '[^']*', lines )[0-9]+:[0-9]+-[0-9]+:[0-9]+/\1L/" "$1"
}

drift=false
for f in Types.lean Funs.lean; do
  mkdir -p "$work/committed" "$work/regenerated"
  mask_spans "$lean_dir/LeanBlsSimd/Extracted/$f" >"$work/committed/$f"
  mask_spans "$work/lean/LeanBlsSimd/Extracted/$f" >"$work/regenerated/$f"
  status=0
  git --no-pager diff --no-index --exit-code "$work/committed/$f" "$work/regenerated/$f" ||
    status=$?
  case $status in
    0) ;;
    1) drift=true ;;
    *) exit "$status" ;;
  esac
done

if $drift; then
  echo "The extraction drifted from LeanBlsSimd/Extracted/ beyond its Source spans." >&2
else
  echo "No drift from LeanBlsSimd/Extracted/ beyond its Source spans."
fi

if $check; then
  if $drift; then exit 1; fi
  exit 0
fi

cp "$work/lean/LeanBlsSimd/Extracted/Types.lean" "$work/lean/LeanBlsSimd/Extracted/Funs.lean" \
  "$lean_dir/LeanBlsSimd/Extracted/"
