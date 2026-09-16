# Lighthouse partial-column fixtures

Generated with the actual Lighthouse types, not Silver's encoders or handwritten SSZ layouts.

- Lighthouse revision: `e423a66763bb1bd780492d635123f208d80c3538`.
- SSZ definitions: `consensus/types/src/data/partial_data_column_sidecar.rs`.
- Encoder: `ethereum_ssz` 0.10.4 and `ethereum_ssz_derive` 0.10.4.
- Collection types: `ssz_types` 0.14.1.
- Lighthouse pins libp2p revision `c774d4e71357d7cd2f792c4767d616d2dd369ee3`.

These fixtures cover Fulu SSZ. They do not claim Gloas interoperability or capture a live libp2p exchange.
Gloas remains covered by the separate pinned-spec fixtures.

The nine-row bitmap crosses a byte boundary. Sparse messages contain rows 0, 3, and 8.
Header-only, header-plus-cells, cells-only, and replacement metadata are included.
Cells, commitments, proofs, and roots contain deterministic markers. They are codec fixtures, not valid cryptographic proofs.

## Reproduction

Use `generate_lighthouse.rs` as a standalone Cargo binary outside the Silver workspace.
Point these path dependencies at the pinned Lighthouse checkout:

```toml
[dependencies]
types = { path = "/path/to/lighthouse/consensus/types" }
kzg = { path = "/path/to/lighthouse/crypto/kzg" }
bls = { path = "/path/to/lighthouse/crypto/bls" }
ssz = { package = "ethereum_ssz", version = "=0.10.4" }
ethereum_ssz_derive = "=0.10.4"
ssz_types = "=0.14.1"
```

Run the binary and split its `name=hex` output into the corresponding `.hex` files.
Whitespace is ignored by the tests. No Lighthouse dependency is added to Silver's build.
