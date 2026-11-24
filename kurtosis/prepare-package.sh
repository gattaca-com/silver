#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REVISION=90d0f4e795cd4c3298753b428bb588ed7999d4da
ARCHIVE_SHA256=744efa21bb05f0a94388ddf240967fd12de35ebd6417a3909487204b4272d33d
TEST="$HERE/gloas-proposals.yaml"

for bin in curl tar sha256sum; do
  command -v "$bin" >/dev/null || { echo "missing dependency: $bin" >&2; exit 1; }
done

read -r CHANGES_SHA256 _ < <(sha256sum "$TEST")
CACHE="$HERE/.cache"
PACKAGE="$CACHE/ethereum-package-$REVISION-${CHANGES_SHA256:0:12}"

if [ ! -d "$PACKAGE" ]; then
  mkdir -p "$CACHE"
  STAGING="$(mktemp -d "$CACHE/prepare.XXXXXX")"
  trap 'rm -rf "$STAGING"' EXIT
  curl -fsSL --retry 3 \
    "https://codeload.github.com/ethpandaops/ethereum-package/tar.gz/$REVISION" \
    -o "$STAGING/package.tar.gz"
  printf '%s  %s\n' "$ARCHIVE_SHA256" "$STAGING/package.tar.gz" | sha256sum --check --status
  mkdir "$STAGING/package"
  tar -xzf "$STAGING/package.tar.gz" --strip-components=1 -C "$STAGING/package"
  cp "$TEST" "$STAGING/package/static_files/assertoor-config/tests/silver-gloas.yaml"
  mv "$STAGING/package" "$PACKAGE"
fi

printf '%s\n' "$PACKAGE"
