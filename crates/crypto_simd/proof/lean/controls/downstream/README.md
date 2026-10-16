This independent Lake package imports `lean_bls_simd` by path and inherits its dependency pins. It checks that the public interface of `silver_crypto_simd::bls` is useful to its consumers. Each file models a consumer extracted separately, which declares its own copies of blst's structs and its own externals class, and uses the published theorems across that boundary. It does not model calls between sibling `bls` and `kzg` modules extracted together in one crate, where the extraction can share the blst structs directly.

Each file follows the same pattern for one public wrapper:

- It declares the consumer's own blst structs. A `#guard_msgs` control checks that redeclaring the upstream wrapper at its root name is rejected.
- `Bridge.uncompress_eq_spec_list` transports the upstream list result across the copied structs.
- The facade `silver_crypto_simd.bls.uncompress_in_g1` or `uncompress_in_g2`, inside the consumer's namespace, reads the function field of the downstream-owned `Fixed.Externals`.
- `caller` calls the wrapper in the generated spelling. Its only instance parameter is `Fixed.Externals`, and `caller_eq_spec_list` proves its list result.
- `Fixed.externalsOf upstream` fixes an explicit upstream `BlsExternals` instance inside the adapter. `Fixed.externalsOf_matches_spec` discharges the downstream premise `Fixed.UncompressMatchesSpec` from the upstream `BlstMatchesSpec`.
- A concrete instance implementing the spec witnesses that the premises are consistent.

These are interoperability demonstrations, not changes to any consumer's extraction.

## `G1Smoke.lean`

The G1 consumer is silver_kzg, under the `silver_kzg` namespace. It copies `blst_fp` and `blst_p1_affine`, and imports `LeanBlsSimd.Refines.UncompressG1`.

## `G2Smoke.lean`

A G2 consumer checks signatures. This file models one, extracted separately under the example namespace `silver_bls`. It copies `blst_fp`, `blst_fp2` and `blst_p2_affine`, so its bridge also converts each Fp2 coordinate. It imports `LeanBlsSimd.Refines.UncompressG2`.

## Running

The normal package commands, run from this directory, are:

```sh
lake update
lake build
```

`lake build` builds both files, which are the package's default targets. Lake resolves the `lean_bls_simd` path requirement to `../..` and builds its imported modules as dependencies. For development with an already-built parent library, the ignored package-cache symlink below optionally reuses its installed dependencies without copying them:

```sh
mkdir -p .lake
ln -s ../../../.lake/packages .lake/packages
lake update
lake env lean G1Smoke.lean
lake env lean G2Smoke.lean
```

Create the symlink only when `.lake/packages` does not already exist. Each adapter and caller axiom check is wrapped in `#guard_msgs`; the build fails if its list differs from `propext`, `Classical.choice`, and `Quot.sound`.
