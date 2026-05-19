# silver_e2e

End-to-end tests that exercise multiple silver tiles together, plus optional
rust-libp2p interop tests behind the `lh-client` feature.

## Fixtures (`make`)

Pulls the mainnet checkpoint + a few following blocks into
`tests/example_checkpoints/` (gitignored). Idempotent — already-cached files
are skipped.

| target | what it does |
| --- | --- |
| `make checkpoint-fixtures` | `finalized-state` + `next-blocks` (the usual entry point). |
| `make checkpoint-fixtures-large` | `finalized` anchor + 128 following blocks. Used by `sync_pm_bs_one_batch`. ~13 min wall-clock. |
| `make next-blocks-large` | Fetches 128 blocks past whatever `finalized_state.ssz` is currently on disk — doesn't touch the state file. |
| _override_ | `make checkpoint-fixtures ANCHOR_SLOT=<slot> NEXT_BLOCKS_COUNT=<n>` pins to any archive-reachable slot. Default `ANCHOR_SLOT=finalized` rotates with each fetch. |
| `make finalized-state` | Download `finalized_state.ssz` from chainsafe's beaconstate archive. |
| `make next-blocks` | Probe lodestar for up to `NEXT_BLOCKS_COUNT` (= 4) canonical blocks past the anchor slot, scanning `NEXT_BLOCKS_LOOKAHEAD` (= 12) slots ahead to skip empty ones. Writes `next_block_<slot>.ssz`. |
| `make clean` | Remove the `.ssz` fixtures. |

## Tests

| file | what it covers |
| --- | --- |
| `gossip_oneway.rs` | Two silver stacks; publisher → echo gossip; asserts zero invalid deliveries. |
| `rpc_multipart.rs` | Silver ↔ silver multi-MB `BlocksByRange` response: chunk encoding + decoding + synthetic `Complete`. |
| `checkpoint_load.rs` | Boot `BeaconStateTile` from `finalized_state.ssz`, apply the `next_block_*.ssz` blocks in order, cross-check post-state root against lodestar. |
| `sync_pm_bs.rs` | PM + BS on one spine, synthetic peer; PM issues two `BlocksByRange` batches (`max_batch=2`) covering 4 blocks; final `head_state_root` cross-checked against lodestar. |
| `sync_pm_bs_one_batch.rs` | Same wiring, one big batch over all fetched blocks. Skips unless ≥ 64 blocks on disk (`make checkpoint-fixtures-large`). Stresses sustained STF + body parser. |
| `lh_handshake.rs` | QUIC handshake silver ↔ rust-libp2p (both directions). `lh-client`. |
| `lh_identify.rs` | `/ipfs/id/1.0.0` round-trip vs rust-libp2p. `lh-client`. |
| `lh_rpc.rs` | Eth2 RPC round-trips (Ping / StatusV2 / MetaData) vs rust-libp2p. `lh-client`. |

Fixture-dependent tests skip cleanly when files are missing — run
`make checkpoint-fixtures` first.

## Running

```sh
cargo test -p silver_e2e --tests                       # everything except lh-*
cargo test -p silver_e2e --features lh-client          # adds rust-libp2p interop tests
```

The `gossip_oneway` example can also be run standalone:

```sh
cargo run -p silver_e2e --example gossip_oneway -- --duration 2 --rate 300 --payload-size 512 --dup-pct 20
# silver ↔ libp2p variants (require lh-client):
cargo run -p silver_e2e --features lh-client --example gossip_oneway_lh   -- --duration 2 --rate 300 --payload-size 512
cargo run -p silver_e2e --features lh-client --example gossip_oneway_lh_b -- --duration 2 --rate 300 --payload-size 512
cargo run -p silver_e2e --features lh-client --example gossip_oneway_lh_c -- --duration 2 --rate 300 --payload-size 512
```
