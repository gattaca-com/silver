# silver_beacon_state

The beacon state tile.

Responsibilities:
- State transition driven by `SlotTicker` ticks and gossip-arriving blocks.
- Fork choice + finalisation.
- Bootstrap from an SSZ checkpoint, sync via `BlocksByRange` RPC.
- Emit `Status` / `Synced` events and `PersistBlock` /
  `RequestBlocksByRange` control messages.

```
crates/beacon_state/
├── src/
│   ├── tile.rs                BeaconStateTile, gossip/RPC handlers, ticker driver
│   ├── state_transition.rs    Two-pass apply_block (validate-all, batch-verify, apply)
│   ├── bls.rs                 BLS primitives + SigBatch (collect-then-batch-verify)
│   ├── epoch_transition.rs    process_epoch
│   ├── fork_choice.rs         LMD-GHOST tree
│   ├── shuffling.rs           Committee shuffling
│   ├── ssz_hash.rs            hash_tree_root for every container
│   ├── decompose.rs           Checkpoint SSZ → tiered storage
│   ├── validate.rs            Stateless data-validation helpers
│   └── types.rs               Types for tiered in-memory state storage
└── tests/
    ├── sync_scenarios.rs      Drives the tile through SilverSpine
    ├── ssz_view_fixtures.rs   Field-level checks of ssz_view accessors
    └── ef_*.rs                EF consensus-spec-tests (gated on --features ef_tests)
```

To test run `cargo test -p silver_beacon_state`.

For EF test vectors run `make` to fetch them first (published at [`consensus-spec-tests`](https://github.com/ethereum/consensus-specs/releases)) and then `cargo test -p silver_beacon_state --features ef_tests`.
