#!/usr/bin/env bash
# Compiles proto_tail.cpp into mcl's msm_avx.cpp and runs libbench.c against the
# blst static library cargo built for this workspace. Run fetch_and_build.sh first.
set -euo pipefail
cd "$(dirname "$0")"
root=$(git rev-parse --show-toplevel)
blst_a=$(find "$root/target/release/build" -name libblst.a | head -1)
blst_h=$(find ~/.cargo/registry/src -path '*/blst-*/blst/bindings/blst.h' | head -1)
[ -n "$blst_a" ] || { echo "no libblst.a under target/release/build; cargo build --release first"; exit 1; }

cat libs/mcl/src/msm_avx.cpp proto_tail.cpp > libs/proto.cpp
clang++ -c libs/proto.cpp -o libs/proto.o -m64 -I libs/mcl/include -I libs/mcl/test -I libs/mcl/src \
  -fomit-frame-pointer -DNDEBUG -fno-stack-protector -O3 -fpic \
  -DMCL_FP_BIT=384 -DMCL_FR_BIT=256 -DMCL_USE_LLVM=1 -DMCL_BINT_ASM=1 -DMCL_MSM=1 \
  -mavx512f -mavx512ifma -std=c++11
clang -O2 -march=native -o libs/libbench libbench.c libs/proto.o \
  -I libs/mcl/include -I "$(dirname "$blst_h")" \
  libs/mcl/lib/libmcl_nomsm.a "$blst_a" -lstdc++ -lm -lpthread
libs/libbench
