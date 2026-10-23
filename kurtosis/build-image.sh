#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE="${1:-silver:proposing}"
export BUILDX_CONFIG="$HERE/.cache/buildx-state"

if docker buildx version >/dev/null 2>&1; then
  BUILDER=(docker buildx)
else
  VERSION=v0.38.1
  case "$(uname -sm)" in
    'Linux x86_64')
      ARCH=amd64
      SHA256=e25d5cd675092bb5d1d03632fdc46cdf3fede7b514dc5f023a105e00d3ce5ad4
      ;;
    'Linux aarch64')
      ARCH=arm64
      SHA256=3b83b3731916ba433feccaaa689fe5bcdc81c641d92c8e6c2ea865dfa141c97a
      ;;
    *) echo "install Docker Buildx for this platform" >&2; exit 1 ;;
  esac
  mkdir -p "$HERE/.cache"
  BUILDX="$HERE/.cache/buildx-$VERSION-$ARCH"
  if [ ! -f "$BUILDX" ]; then
    DOWNLOAD="$(mktemp "$HERE/.cache/buildx.XXXXXX")"
    trap 'rm -f "$DOWNLOAD"' EXIT
    curl -fsSL --retry 3 \
      "https://github.com/docker/buildx/releases/download/$VERSION/buildx-$VERSION.linux-$ARCH" \
      -o "$DOWNLOAD"
    printf '%s  %s\n' "$SHA256" "$DOWNLOAD" | sha256sum --check --status
    chmod +x "$DOWNLOAD"
    mv "$DOWNLOAD" "$BUILDX"
  fi
  printf '%s  %s\n' "$SHA256" "$BUILDX" | sha256sum --check --status
  BUILDER=("$BUILDX")
fi

COMMIT="$(git -C "$HERE/.." rev-parse --short HEAD)"
if [ -n "$(git -C "$HERE/.." status --porcelain)" ]; then
  COMMIT="$COMMIT-dirty"
fi
exec "${BUILDER[@]}" build --load --progress=plain --tag "$IMAGE" \
  --build-arg "SILVER_BUILD_COMMIT=$COMMIT" "$HERE/.."
