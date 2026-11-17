# Independent consumers

This Lake package imports `lean_bls_simd` by path and inherits its dependency pins. Its four default targets check public BLS, KZG and pairing-product results. The examples apply the generated-code correctness results; separate field-algebra interfaces are outside their scope. The package is a template for a Rust caller extracted separately with Aeneas: such a caller can prove its own code from these results, as the BLS adapters below do.

## BLS adapters

`G1Smoke.lean` models a separately extracted G1 consumer under `silver_kzg`. `G2Smoke.lean` models a G2 consumer under `silver_bls`. Each declares its own blst-shaped data types and a downstream `Fixed.Externals` function field. These are consumer adapters, not replacement dictionaries for the generated KZG implementation.

Both files transport specification verdicts across the copied structures. The facade retains the generated call spelling, and `caller_eq_spec_list` proves the caller's result from the downstream agreement premise. A `#guard_msgs` control rejects redeclaration of the upstream wrapper at its root name. Adapter and caller axiom checks admit only `propext`, `Classical.choice` and `Quot.sound`.

G1's `Fixed.externalsOf` captures `RuntimeFeatures` and `KzgExternals`. Its general agreement proof uses `UncompressG1.FallbackCorrect`. The IFMA example discharges that conditional law without an external agreement premise. Portable singleton and pair decoding are proved internally for IFMA tails and undecided lanes.

G2's adapter captures `RuntimeFeatures` and a separate upstream `BlsExternals` containing only the opaque G2 decoder. Its agreement proof requires `UncompressG2.BlstMatchesSpec`. A specification-backed G2 external still supplies a concrete witness for that external-function premise.

## KZG consumers

`KzgSmoke.lean` checks the general verifier under the scoped decoder and pairing laws. Cell decoding, interpolation, MSM, SHA and scalar/base-field arithmetic are proved internally. Extender consumers need no blst laws. The examples retain the canonical-cell relation and conditional scalar-scratch premise. They also check preservation of stored routes.

These examples use the shared data types from the same-crate extraction. The imported library proves the generated-component contracts; these examples check their public consumer interfaces.

## Pairing-product consumer

`PairingSmoke.lean` applies the public owner and fixed-two-pair headlines with explicit point-validity premises and an agreement premise for the blst route. An empty-owner example composes clearing with the empty-product result.

## Running

From this directory:

```sh
lake update
lake build --wfail
```

Lake resolves `lean_bls_simd` to `../..` and builds imported modules as dependencies. An ignored cache symlink can reuse the parent's dependency checkouts when `.lake/packages` does not already exist:

```sh
mkdir -p .lake
ln -s ../../../.lake/packages .lake/packages
lake update
lake build --wfail
```
