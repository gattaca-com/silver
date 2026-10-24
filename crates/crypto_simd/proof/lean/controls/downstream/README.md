# Independent consumers

This Lake package imports `lean_bls_simd` by path and inherits its dependency
pins. Its four default targets check the public BLS, KZG and pairing-field interfaces.

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
generated wrapper. Its agreement proof uses the proved portable singleton,
pair and IFMA decoders internally. The consumer examples require no
`G1DecoderCorrect` premise.

G2's adapter captures `RuntimeFeatures` and a separate upstream
`BlsExternals` containing only the opaque G2 decoder. Its agreement proof
requires `UncompressG2.BlstMatchesSpec`. A specification-backed G2 external
still supplies a concrete witness for that external-function premise.

## KZG consumers

`KzgSmoke.lean` checks scalar cell decoding, kernel interpolation and pairing
composition with the remaining component contract, `PairingCorrect`. SHA, scalar and base-field laws, and G1 decoding are
discharged inside the imported results. It retains the canonical
cell relation and the conditional scalar-scratch premise. It also checks
arbitrary-length proved MSM8, lane-only linear combination and preservation
of stored interpolation/curve-work routes.

These examples use the shared data types from the same-crate extraction.
They do not model a second copy of the verifier or prove its pending
generated-component contracts.

## Pairing-field consumer

`TowerSmoke.lean` imports the field and cyclotomic interfaces independently.
It checks multiplication, total inverse, the coordinate formula, Frobenius,
conjugation, easy-part membership and the target-group exponent.
It assumes no generated pairing correctness.

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

`TowerSmoke.lean` also consumes portable multiplication, total inverse, cyclotomic squaring and Frobenius refinements, plus the decoded table-entry theorem.

The lane examples consume the multiplication field identity and generated one, conjugation, square, multiplication, sparse line multiplication and Frobenius refinements under `LaneTower.Rep`. Both portable and lane table entries are connected to the field basis. The lane cyclotomic-square consumer permits zero as well as Φ12 membership.
