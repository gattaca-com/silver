This independent Lake package imports `lean_bls_simd` by path and inherits its dependency pins. `Smoke.lean` reproduces silver_kzg's generated blst structs and the rejected root external declaration. Its `#guard_msgs` control requires the name collision to remain visible.

Two adapters prove the list result on the copied structs:

- `silver_kzg.caller_eq_spec_list` uses a namespaced adapter and threads the upstream `G1Externals` instance.
- `silver_kzg.Fixed.externalsOf_matches_spec` fixes an explicit upstream instance inside a downstream-owned external. The downstream caller takes only `Fixed.Externals`; its named assumption is `Fixed.UncompressMatchesSpec`.

Both assumptions are discharged from `LeanBlsSimd.UncompressG1.BlstMatchesSpec`. A concrete instance implementing the spec witnesses consistency. These are interoperability demonstrations, not changes to silver_kzg's extraction.

The normal package commands, run from this directory, are:

```sh
lake update
lake build
```

Lake resolves the `lean_bls_simd` path requirement to `../..` and builds its imported modules as dependencies. For development with an already-built parent library, the ignored package-cache symlink below optionally reuses its installed dependencies without copying them:

```sh
mkdir -p .lake
ln -s ../../../.lake/packages .lake/packages
lake update
lake env lean Smoke.lean
```

Create the symlink only when `.lake/packages` does not already exist. The final command prints the axiom lists of both adapter proofs and the downstream caller theorem; each must contain only `propext`, `Classical.choice`, and `Quot.sound`.
