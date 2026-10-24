# Independent consumers

This Lake package imports `lean_bls_simd` by path and inherits its dependency
pins. Its three default targets check the public BLS and KZG proof interfaces.

## BLS adapters

`G1Smoke.lean` models a separately extracted G1 consumer under `silver_kzg`.
`G2Smoke.lean` models a G2 consumer under `silver_bls`. Each declares its own
blst-shaped data types and a downstream `Fixed.Externals` function field.
These are consumer adapters, not replacement dictionaries for the generated
KZG implementation.

Both files transport specification verdicts across the copied structures.
The facade retains the generated call spelling, and `caller_eq_spec_list`
proves the caller's result from the downstream agreement premise.
A `#guard_msgs` control rejects redeclaration of the upstream wrapper at its
root name. Adapter and caller axiom checks admit only `propext`,
`Classical.choice` and `Quot.sound`.

G1's `Fixed.externalsOf` captures `RuntimeFeatures` and calls the actual
generated wrapper. Its agreement proof requires `G1DecoderCorrect` for the
portable singleton and pair decoders. The IFMA component is already proved.
The consumer examples are conditional applications; they do not prove that
the generated portable implementation satisfies its contract.

G2's adapter captures `RuntimeFeatures` and a separate upstream
`BlsExternals` containing only the opaque G2 decoder. Its agreement proof
requires `UncompressG2.BlstMatchesSpec`. A specification-backed G2 external
still supplies a concrete witness for that external-function premise.

## KZG consumers

`KzgSmoke.lean` checks scalar cell decoding, kernel interpolation and pairing
composition with the four remaining component contracts: `PortableFpCorrect`,
`G1DecoderCorrect`, `PortableMsmCorrect` and `PairingCorrect`. SHA and scalar
laws are discharged inside the imported results. It retains the canonical
cell relation and the conditional scalar-scratch premise. It also checks
arbitrary-length proved MSM8, lane-only linear combination and preservation
of stored interpolation/curve-work routes.

These examples use the shared data types from the same-crate extraction.
They do not model a second copy of the verifier or prove its pending
generated-component contracts.

## Running

From this directory:

```sh
lake update
lake build
```

Lake resolves `lean_bls_simd` to `../..` and builds imported modules as
dependencies. An ignored cache symlink can reuse the parent's dependency
checkouts when `.lake/packages` does not already exist:

```sh
mkdir -p .lake
ln -s ../../../.lake/packages .lake/packages
lake update
lake build
```
