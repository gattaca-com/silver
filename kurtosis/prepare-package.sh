#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REVISION=19d6bd99ac14c69ff7aa63b53f75fc3701940de1
ARCHIVE_SHA256=69852b6298ae1128b3e6e0665653279f74ddf8d67ae038e7476762f8f11a6e83
PATCH="$HERE/ethereum-package.patch"
TEST="$HERE/gloas-proposals.yaml"

for bin in curl tar patch sha256sum; do
  command -v "$bin" >/dev/null || { echo "missing dependency: $bin" >&2; exit 1; }
done

read -r CHANGES_SHA256 _ < <(cat "$PATCH" "$TEST" | sha256sum)
CACHE="$HERE/.cache"
PACKAGE="$CACHE/ethereum-package-$REVISION-${CHANGES_SHA256:0:12}"

if [ ! -d "$PACKAGE" ]; then
  mkdir -p "$CACHE"
  STAGING="$(mktemp -d "$CACHE/prepare.XXXXXX")"
  trap 'rm -rf "$STAGING"' EXIT
  curl -fsSL --retry 3 \
    "https://codeload.github.com/ninaiiad/ethereum-package/tar.gz/$REVISION" \
    -o "$STAGING/package.tar.gz"
  printf '%s  %s\n' "$ARCHIVE_SHA256" "$STAGING/package.tar.gz" | sha256sum --check --status
  mkdir "$STAGING/package"
  tar -xzf "$STAGING/package.tar.gz" --strip-components=1 -C "$STAGING/package"
  patch --directory "$STAGING/package" --strip=1 --batch --fuzz=0 < "$PATCH" >&2
  cp "$TEST" "$STAGING/package/static_files/assertoor-config/tests/silver-gloas.yaml"
  mv "$STAGING/package" "$PACKAGE"
fi

printf '%s\n' "$PACKAGE"
