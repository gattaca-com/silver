# silver_crypto_simd

BLS12-381 and KZG for Ethereum consensus, optimized for x86-64 CPUs with AVX-512 IFMA.

## Why this crate exists

Ethereum consensus clients spend much of their verification time decoding BLS signatures, checking subgroup membership and verifying KZG proofs. PeerDAS adds cell verification and blob extension to that workload. These operations involve repeated field arithmetic, which can process several independent inputs together.

This crate uses AVX-512 IFMA to work on eight field elements at once. It combines point decoding and subgroup checks in batches, and uses the same arithmetic for KZG verification, cell extension and pairing products. It is used in [Silver](https://github.com/gattaca-com/silver), an Ethereum consensus client, and is available separately for other clients and applications that need these operations. CPUs without IFMA use portable Rust arithmetic and blst, with the same public APIs.

The x86-64 implementation also has machine-checked Lean proofs relating it to Ethereum's cryptographic specification. The proofs live in the [GitHub repository](https://github.com/gattaca-com/silver/tree/main/crates/crypto_simd/proof), outside the crates.io package. [Proof coverage](#proof-coverage) below explains what they establish and what remains trusted.

## Getting started

Add the crate to your `Cargo.toml`:

```toml
[dependencies]
silver_crypto_simd = "0.1"
```

The minimum Rust version is 1.91, and blst is the only runtime dependency. The default `simd` feature enables runtime selection of the IFMA implementation; no CPU-specific build flags are needed. Set `default-features = false` to disable IFMA.

The 0.1 API may change in subsequent releases before 1.0.

## Using the crate

### BLS points and pairing products

The BLS API provides point decoding, subgroup checks and pairing products for signature verification. The following example combines them to verify a single signature with Ethereum's BLS ciphersuite:

```rust
use silver_crypto_simd::bls::{
    COMPRESSED_LEN, G1Point, G2_COMPRESSED_LEN, G2Point, PairingProduct, uncompress_in_g1,
    uncompress_in_g2,
};

const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

fn verify(
    public_key: &[u8; COMPRESSED_LEN],
    message: &[u8],
    signature: &[u8; G2_COMPRESSED_LEN],
) -> bool {
    let mut pk = [None];
    let mut sig = [None];
    uncompress_in_g1(&[*public_key], &mut pk);
    uncompress_in_g2(&[*signature], &mut sig);
    let ([Some(pk)], [Some(sig)]) = (pk, sig) else { return false };
    if pk.is_infinity() {
        return false;
    }
    let hash = G2Point::hash_to_curve(message, DST);
    PairingProduct::two_pairs_are_one((&G1Point::negative_generator(), &sig), (&pk, &hash))
}
```

The example rejects infinity public keys because an infinity key and signature satisfy the pairing equation for every message. Applications supply the message to verify and enforce their protocol's rules, including domain separation and any random weights used for batch verification.

`bls::uncompress_in_g1` and `bls::uncompress_in_g2` decode batches of compressed points and check subgroup membership. Each takes an input slice and an equally sized output slice of `Option<G1Point>` or `Option<G2Point>`. An accepted point produces `Some`; an invalid encoding or a point outside the subgroup produces `None`.

G1 encodings are 48 bytes (`bls::COMPRESSED_LEN`), and G2 encodings are 96 bytes (`bls::G2_COMPRESSED_LEN`). Both batch decoders panic if the input and output lengths differ.

`G1Point` and `G2Point` hold canonical, on-curve points in the prime-order subgroup. Infinity is allowed, so applications must reject it wherever their protocol requires a nonzero point. Both types provide `from_blst` for checked conversion from blst's affine representation. `G1Point::from_trusted` skips validation: its caller must ensure the coordinates are canonical and the point lies on the curve and in the prime-order subgroup. This is useful when reusing cached keys that were validated earlier.

These point types feed `bls::PairingProduct`, which checks whether a product of pairings is one. Create it with `with_capacity`, add pairs with `push`, and call `is_one()` for the verdict. Pairs containing infinity contribute the identity and are dropped; an empty product returns `true`. Call `clear()` before reusing it for a new product, or use `two_pairs_are_one` for an allocation-free two-pair check.

The point types also provide the operations used in the example: `G2Point::hash_to_curve(message, dst)` hashes to G2 with a caller-supplied domain, and `G1Point` supplies `negative_generator()` and `is_infinity()`.

For point aggregation, both types provide `weighted_sum`, taking one 64-bit little-endian scalar per point. Scalars are supplied as consecutive bytes; a length mismatch panics. Both types also expose `as_blst` and `into_blst` for interoperability with blst.

### KZG for PeerDAS

`kzg::CellBatchVerifier` verifies batches of PeerDAS cells. Supply each cell with its blob's KZG commitment, its index within the extended blob and its KZG proof:

```rust
use silver_crypto_simd::kzg::CellBatchVerifier;

let mut verifier = CellBatchVerifier::new();
let valid = verifier.verify(&commitments, &cell_indices, &cells, &proofs);
```

The four input slices must have equal lengths, with corresponding entries in the same position. Commitments and proofs are 48-byte arrays, indices are `u64` values, and cells are `[u8; kzg::BYTES_PER_CELL]` arrays. `verify` returns the verdict of the specification's `verify_cell_kzg_proof_batch`, treating inputs rejected with an error as `false`.

The verifier includes Ethereum's trusted setup, so callers do not need to load a setup file. Keep the verifier between batches to reuse its allocated buffers.

To extend a blob into the full set of PeerDAS cells, use `kzg::CellExtender`:

```rust
use silver_crypto_simd::kzg::{BYTES_PER_CELL, CELLS_PER_EXT_BLOB, CellExtender};

let mut extender = CellExtender::new();
let mut cells = Box::new([[0u8; BYTES_PER_CELL]; CELLS_PER_EXT_BLOB]);
let valid = extender.compute(&blob, &mut cells);
```

The input blob is a `[u8; kzg::BYTES_PER_BLOB]` array. The example uses a `Box` for the 256 KiB output, which holds all 128 cells. On success, `compute` fills the cells and returns `true`. If the blob contains an invalid field element, it returns `false` and leaves the output unchanged. Keep the extender and output buffer between calls to reuse their allocations.

## CPU support

The default `simd` feature enables runtime detection of AVX-512F and AVX-512 IFMA. The crate uses these instructions on supported CPUs, including AMD Zen 4 and Zen 5 and recent Intel Xeon families. Other CPUs, including aarch64, use portable Rust arithmetic and blst through the same public APIs. `ifma_available()` reports whether the IFMA implementation is active.

The performance benefit depends on the CPU, operation and batch size. Batching gives the vector arithmetic more independent work, so applications should submit available inputs together and reuse the verifier's buffers between calls.

blst is also used for point operations and some fallbacks on IFMA CPUs. The crate is not a replacement for every blst API; its focus is the consensus operations described above. Modules marked `#[doc(hidden)]` expose implementation details rather than supported application APIs.

## Proof coverage

The [proof guide](https://github.com/gattaca-com/silver/blob/main/crates/crypto_simd/proof/README.md) gives the theorem statements, assumptions and reproduction instructions. The [Lean project](https://github.com/gattaca-com/silver/tree/main/crates/crypto_simd/proof/lean) contains the proofs and pins their dependencies. Both are available in the repository and omitted from the crates.io package.

Charon and Aeneas translate the x86-64 Rust implementation into Lean 4. The proofs relate that translation to the executable specification in [EthLib](https://github.com/ethereum/EthLib), which formalizes Ethereum's consensus cryptography:

- **KZG cell batch verification:** the IFMA theorem has no blst correctness premises. The general theorem assumes a CPU-conditioned G1 decoder law and a law for blst pairing.
- **KZG cell extension:** the theorem has no external-operation correctness premises on either route.
- **G1 batch decoding and subgroup checks:** the IFMA route, including its portable fallback, is proved. Without IFMA, correctness assumes a blst decoder law.
- **G2 batch decoding and subgroup checks:** the IFMA implementation is proved; agreement of the blst fallback with the specification remains an explicit premise.
- **Pairing products:** the IFMA lane implementation is proved. The public API theorem retains a separate correctness law for its blst fallback.

These results rely on the translation, CPU intrinsic models and specification described in the proof guide's [trust list](https://github.com/gattaca-com/silver/blob/main/crates/crypto_simd/proof/README.md#what-a-reader-must-trust). They do not prove full BLS signature verification, hash-to-G2 correctness or the aarch64 build. They cover the committed code; a modified implementation needs fresh extraction and proof builds.

The Lean project is dedicated to the public domain under CC0. Other client teams and EthLib can reuse its field tower, pairing results and other proofs without attribution.

## License

The crates.io package is licensed under [MIT](https://github.com/gattaca-com/silver/blob/main/crates/crypto_simd/LICENSE). The repository additionally contains the Lean proof project, dedicated to the public domain under [CC0 1.0](https://github.com/gattaca-com/silver/blob/main/crates/crypto_simd/proof/lean/LICENSE); that project is not included in the package.
