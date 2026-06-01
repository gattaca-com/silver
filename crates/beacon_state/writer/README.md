# silver_beacon_state

The beacon state tile.

Responsibilities:
- State transition driven by `SlotTicker` ticks and gossip-arriving blocks.
- Fork choice + finalization.
- Bootstrap from an SSZ checkpoint, sync via `BlocksByRange` RPC.
- Emit `Status` / `Synced` events and `PersistBlock` /
  `RequestBlocksByRange` control messages.

The tiered in-memory state storage and checkpoint `decompose` (SSZ →
tiers) live in `silver_common::beacon_state`; this crate drives the
transition over the `StateDeltaView` it exposes.

```
crates/beacon_state/
├── src/
│   ├── lib.rs                 Crate root, module wiring, box_zeroed
│   ├── tile.rs                BeaconStateTile, gossip/RPC handlers, ticker driver
│   ├── ticker.rs              SlotTicker
│   ├── state_transition.rs    Two-pass apply_block (validate-all, batch-verify, apply)
│   ├── epoch_transition.rs    process_epoch
│   ├── fork_choice.rs         LMD-GHOST tree
│   ├── bls.rs                 BLS primitives + SigBatch (collect-then-batch-verify)
│   ├── shuffling.rs           Committee shuffling
│   ├── ssz_hash.rs            hash_tree_root for every container
│   ├── validate.rs            Stateless data-validation helpers
│   ├── error.rs               Error / PrecheckError / Result
│   └── test_signing.rs        Test-only block/attestation signing helpers
├── benches/
│   ├── bls_verify.rs          Signature batch-verification
│   └── hash_tree_build.rs     Finalized hash-tree construction
└── tests/
    ├── common.rs              Shared test helpers
    ├── sync_scenarios.rs      Drives the tile through SilverSpine (steps in sync_scenarios/)
    ├── ssz_view_fixtures.rs   Field-level checks of ssz_view accessors
    ├── ef_common.rs           EF test harness (load + compare states)
    └── ef_*.rs                EF consensus-spec-tests (gated on --features ef_tests)
```

To test run `cargo test -p silver_beacon_state`.

For EF test vectors run `make` to fetch them first (published at [`consensus-spec-tests`](https://github.com/ethereum/consensus-specs/releases)) and then `cargo test -p silver_beacon_state --features ef_tests`.
