This independent Lake package imports `lean_bls_simd` by path and inherits its dependency pins. `Smoke.lean` reproduces silver_kzg's generated blst structs and the rejected root external declaration. Its `#guard_msgs` control requires the name collision to remain visible.

The downstream facade follows silver_kzg's chosen external interface:

- `silver_kzg.silver_crypto_simd.bls.uncompress_in_g1` reads the function field of `Fixed.Externals`.
- `silver_kzg.caller` calls `silver_crypto_simd.bls.uncompress_in_g1 inputs out` in the generated spelling. Its only instance parameter is `Fixed.Externals`.
- `Fixed.externalsOf upstream` fixes an explicit upstream `BlsExternals` instance inside the adapter. `Fixed.externalsOf_matches_spec` discharges the named downstream premise `Fixed.UncompressMatchesSpec` from `BlstMatchesSpec`.

`Bridge.uncompress_eq_spec_list` transports the upstream result across the copied structs; `caller_eq_spec_list` proves the downstream caller's list result. A concrete instance implementing the spec witnesses consistency. These are interoperability demonstrations, not changes to silver_kzg's extraction.

The package models a separately extracted consumer of `silver_crypto_simd::bls`. It remains useful for checking that boundary and the transport between independent struct declarations. It does not model calls between sibling `bls` and `kzg` modules extracted together in one crate, where the extraction can share the blst structs directly.

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

Create the symlink only when `.lake/packages` does not already exist. Each adapter and caller axiom check is wrapped in `#guard_msgs`; the build fails if its list differs from `propext`, `Classical.choice`, and `Quot.sound`.
