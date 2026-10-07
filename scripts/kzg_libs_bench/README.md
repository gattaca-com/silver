# KZG verification: blst vs AVX-512 IFMA libraries

Measures the operations that dominate `verify_cell_kzg_proof_batch` on 1152
G1 points (64 columns of an 18-blob block) with blst and with mcl's AVX-512
IFMA code, plus two 16-way prototypes appended to mcl's `msm_avx.cpp`:
Scott's G1 membership test and the Fp square root behind point decompression.

```
./fetch_and_build.sh   # mcl + avxbls, clang, no gmp
./bench.sh             # needs a cargo release build for libblst.a
libs/avxbls/bin/bench  # avxbls's own cycle counts
```

Results on a Ryzen 9950X (Zen 5), 2026-09-03, best of 5:

| operation, 1152 points | blst | AVX-512 IFMA | speedup |
|---|---|---|---|
| subgroup check `[-z^2]P == sigma^2(P)` | 23.3 us/pt | 4.65 us/pt (16-way prototype) | 5.0x |
| decompression sqrt `x^((p+1)/4)` | 7.24 us | 1.79 us/pt (16-way prototype) | 4.0x |
| MSM, 255-bit scalars | 8.8 ms | 5.95 ms (mcl `mulVec`) | 1.5x |
| MSM, 128-bit scalars | 2.65 ms | 5.94 ms (mcl, no gain) | blst wins |
| per-point scalar mult, any width | 23.3 us (in_g1) | 7.8 us (mcl `mulEach`, GLV) | 3.0x |
| one Fp Montgomery mul | 22 ns | ~20 cycles/element at 8-way (avxbls) | ~5x |
| pairing | 0.48 ms | 0.31 ms (avxbls, earlier measurement) | 1.56x |

Both prototypes verify: sigma^2 matches all 1152 members (sigma matches none),
and all 1152 roots square back to their inputs. mcl and blst agree bit for bit
on the 255-bit MSM.

Projection for one 64-column call, today 62.6 ms: membership 27.0 -> 5.4,
decompression 8.6 -> 2.3, the two proof MSMs 18.0 -> 8.6 (128-bit random
weights on blst for one, mcl for the 255-bit weighted one), field aggregation
4.2 -> 2.8, fixed per-call 3.0 -> 1.5. About 21 ms, 3x, on one thread.

Everything here needs a runtime `avx512ifma` gate with the blst path as the
fallback; the IFMA code is x86-only.

## Without a library: `crates/bls_simd`

The same two kernels in Rust on `std::arch` IFMA intrinsics, no C or C++:
eight lanes of 52-bit-limb Montgomery arithmetic (R = 2^416, values lazily
in [0, 2p)), Jacobian point ops, Scott's test, and decompression with the
sign rule. Checked against blst on every proof and commitment in the capture:

```
cargo run --release -p silver_e2e --example kzg_simd_check    # 20174 encodings, 0 mismatches
cargo run --release -p silver_e2e --example kzg_simd_phases   # per-phase cost
```

| per point, 2304 real proofs | blst | `silver_bls_simd` | speedup |
|---|---|---|---|
| Fp Montgomery multiply | 22 ns | 4.8 ns (38 ns per 8-wide op) | 4.6x |
| square root exponentiation | 7.2 us | 2.2 us | 3.3x |
| Scott membership test | 23.3 us | 6.0 us | 3.9x |
| decompress + membership | 30.4 us | 8.3 us | 3.65x |

Two independent multiply chains run at 30 ns per 8-wide op against 38 for
one, so 16 lanes in lockstep and a dedicated squaring are the next ~30%.
