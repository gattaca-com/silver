#!/usr/bin/env bash
# Fetches and builds the libraries the bench compares against blst:
# mcl (AVX-512 IFMA G1 arithmetic and MSM) and avxbls (AVX-512 pairing).
# Needs clang/clang++ and python3; no gmp.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p libs
cd libs

fetch() {
  local name=$1 url=$2
  [ -d "$name" ] && return
  curl -sL "$url" -o "$name.tgz"
  mkdir -p "$name"
  tar xzf "$name.tgz" --strip-components=1 -C "$name"
  rm "$name.tgz"
}

fetch mcl https://github.com/herumi/mcl/archive/refs/heads/master.tar.gz
fetch avxbls https://github.com/hchengv/avxbls/archive/refs/heads/main.tar.gz

# libmcl.a with the AVX-512 MSM object; the bench builds its own copy of
# msm_avx.cpp (with the prototypes appended), so a second archive drops it.
(cd mcl && make -j"$(nproc)" CXX=clang++ CC=clang lib/libmcl.a)
cp mcl/lib/libmcl.a mcl/lib/libmcl_nomsm.a
ar d mcl/lib/libmcl_nomsm.a msm_avx.o

(cd avxbls && make)
echo "avxbls: run libs/avxbls/bin/bench for its own cycle counts"
