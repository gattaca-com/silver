# silver_crypto_simd

BLS12-381 and KZG primitives for Ethereum consensus, with machine-checked proofs covering the x86-64 implementation.

## Why this crate exists

Every consensus client verifies KZG proofs and BLS signatures on its hot path. PeerDAS is peer-to-peer data availability sampling, introduced in the Fulu fork. It multiplies the KZG work: cells must be verified and extended for every blob.

On CPUs with AVX-512 IFMA, this crate's arithmetic kernels process eight field elements at once. Other CPUs use portable Rust arithmetic and MSM. They use blst for point decoding and pairing. Charon and Aeneas translate its x86-64 code to Lean 4. The proofs relate that translation to the executable specification in [EthLib](https://github.com/ethereum/EthLib), under the external-operation assumptions described below. EthLib formalises Ethereum's consensus cryptography in Lean.

## Using the crate

The main APIs are:

- `kzg::CellBatchVerifier`: create one with `new()`, then call `verify(commitments, cell_indices, cells, proofs)` per batch. It returns true exactly when the spec's `verify_cell_kzg_proof_batch` does. Reuse the verifier to retain its allocated buffers between calls.
- `kzg::CellExtender`: create one with `new()`, then call `compute(blob, cells)` per blob. It fills all 128 cells, or returns false and leaves `cells` unchanged when the spec rejects the blob.
- `bls::uncompress_in_g1` and `bls::uncompress_in_g2`: batch decoding of compressed points with subgroup checks, one `Option` per input.

`ifma_available()` reports whether this process uses the AVX-512 IFMA kernels. The other public modules, including the `#[doc(hidden)]` kernels, are internals.

### CPU features

The crate selects code at run time based on CPU features. It reads no environment variables or configuration.

- The `simd` Cargo feature, enabled by default, selects the AVX-512 IFMA kernels on CPUs with AVX-512F and AVX-512 IFMA. If it is disabled or the CPU lacks either feature, point decoding and KZG pairing use blst. MSM and field arithmetic then use portable Rust. The silver binary enables it through its `crypto_simd` feature.
- Two older x86-64 features are used whether or not `simd` is enabled:
  - SHA-NI with SSE4.1 hashes the KZG challenge when the CPU supports both. Otherwise SHA-256 runs in plain Rust.
  - BMI2 selects `mulx` builds of the portable field products. The baseline build uses `_addcarry_u64`, supported by every x86-64 CPU.
- Other architectures, such as aarch64, use the same non-IFMA combination of portable arithmetic and blst.

### Uses of blst

- The `bls` API returns blst's point types, `blst_p1_affine` and `blst_p2_affine`, re-exported from `bls`.
- G2 decoding falls back to blst for lanes the IFMA kernel leaves undecided and for batches too short for the kernel. It also uses blst on every CPU without the IFMA route. `bls::uncompress_in_g2_blst` exposes that decoder.
- G1 decoding uses blst on CPUs without IFMA. Undecided IFMA lanes and short tails use the portable Rust decoder. `bls::uncompress_in_g1_blst` exposes the blst decoder.
- KZG pairing uses blst without IFMA, filtering pairs with either point at infinity. Its MSM uses portable Rust. KZG extension and SHA-256 do not call blst.

## Reusing the project

The crate is not currently published on crates.io. Other projects can use it as a git dependency pinned to a commit:

```toml
[dependencies]
silver_crypto_simd = { git = "https://github.com/gattaca-com/silver", rev = "<commit>" }
```

- blst is the only runtime dependency. Cargo resolves it to the newest compatible 0.3 release; silver's lockfile pins 0.3.16.
- The minimum Rust version is 1.91.
- Outside silver, the default features enable `simd`. Add `default-features = false` to disable IFMA.
- The proofs cover the committed code. They do not cover a modified copy until you regenerate its extraction and rebuild the proofs; see [`proof/README.md`](proof/README.md).

## What is proved

- KZG cell batch verification (`kzg::CellBatchVerifier`), under scoped blst laws for the general theorem.
- KZG cell extension (`kzg::CellExtender`).
- BLS12-381 G1 batch point decoding with subgroup checks, under a non-IFMA blst decoder law.
- G2 batch point decoding, except the blst fallback for lanes the kernel cannot decide, which stays an explicit premise.

The IFMA KZG verifier theorem has no blst correctness premises. The general theorem assumes a CPU-conditioned G1 decoder law and a pairing law for each scalar workspace. G1 batch decoding has the same decoder assumption without IFMA. The extender uses neither operation. It has no component premises on either route. [`proof/README.md`](proof/README.md) gives the exact statements and the proved arithmetic beneath them. It lists the trust placed in the Charon/Aeneas translation, CPU intrinsic models and EthLib. The aarch64 build is not proved.

## Reusing the proofs

The Lean project in [`proof/lean/`](proof/lean/) is public domain (CC0). Other client teams and EthLib can reuse any part without attribution. That includes the field tower, the pairing and final-exponentiation results, and the method itself. We want these proofs to be reused rather than rewritten.

## License

The crate is licensed under [MIT](LICENSE), with one exception. [`proof/lean/`](proof/lean/) and everything under it are dedicated to the public domain under [CC0 1.0](proof/lean/LICENSE).
