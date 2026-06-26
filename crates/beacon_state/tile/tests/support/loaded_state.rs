//! Shared EF harness state: per-tier finalized bases decoded from SSZ + the
//! working fork bundle (`state_id`) anchored on top. `#[path]`-included by
//! the ef_* tests (via `ef_common`) and the `bls_verify` bench.
#![allow(dead_code)]

use std::{fs, path::Path};

use silver_beacon_state_data::{
    BeaconState, EpochGroup, LongtailGroup, SpecConfig, StateId, StateWriterView,
};

/// Snappy-decompress a file.
pub fn snappy_decode(path: &Path) -> Vec<u8> {
    let compressed = fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    snap::Decoder::new()
        .decompress_vec(&compressed)
        .unwrap_or_else(|e| panic!("{}: snappy: {e}", path.display()))
}

/// State-transition runs mutate a rolled fork; post-state comparison hashes
/// via `hash_tree_root_state` over a `StateWriterView`.
pub struct LoadedState {
    pub bs: Box<BeaconState>,
    pub state_id: StateId,
}

impl LoadedState {
    /// Roll a fresh fork off the bundle and hand back its writer view, with
    /// the epoch/longtail groups alongside for boundary reads + rolls — the
    /// production `apply_block_view` shape. Mutations persist only via
    /// `s.state_id = view.commit(epoch_idx, longtail_idx)` writeback.
    pub fn view(&mut self) -> (StateWriterView<'_>, &mut EpochGroup, &mut LongtailGroup) {
        let sid = self.state_id;
        let bs = &mut self.bs;
        let view = StateWriterView {
            imm: &bs.immutable,
            balances: bs.balances.roll_from(sid.balances_idx),
            eth1: bs.eth1.roll_from(sid.eth1_idx),
            pending: bs.pending.roll_from(sid.pending_idx),
            previous_participation: bs
                .previous_participation
                .roll_from(sid.previous_participation_idx),
            current_participation: bs
                .current_participation
                .roll_from(sid.current_participation_idx),
            inactivity: bs.inactivity.roll_from(sid.inactivity_idx),
            slot: bs.slot_states.roll_from(sid.slot_idx),
            validators: bs.validators.roll_from(sid.validators_idx),
            builders: bs.builders.roll_from(sid.builders_idx),
        };
        (view, &mut bs.epoch, &mut bs.longtail)
    }
}

pub fn load_state(path: &Path) -> LoadedState {
    let ssz = snappy_decode(path);
    let mut bs = Box::new(
        BeaconState::decompose(&ssz, &SpecConfig::mainnet(), None)
            .unwrap_or_else(|e| panic!("{}: decompose failed: {e}", path.display())),
    );
    // Anchor each working fork at the decoded base; epoch/longtail stay
    // unrolled (lazy — `None` idx reads the base).
    let state_id = bs.roll_fresh();
    LoadedState { bs, state_id }
}
