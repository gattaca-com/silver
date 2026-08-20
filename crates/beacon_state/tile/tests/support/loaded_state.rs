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
        self.bs.roll_from(self.state_id)
    }
}

pub fn load_state(path: &Path) -> LoadedState {
    anchor(
        BeaconState::decompose(&snappy_decode(path), &SpecConfig::mainnet(), None)
            .unwrap_or_else(|e| panic!("{}: decompose failed: {e}", path.display())),
    )
}

/// Force the Gloas decoder. EF Gloas suites contain vectors that mutate
/// `fork.current_version` (signature testing), which defeats the version
/// routing in `BeaconState::decompose`; the harness knows the layout is Gloas.
pub fn load_state_gloas(path: &Path) -> LoadedState {
    anchor(
        BeaconState::decompose_gloas(&snappy_decode(path), &SpecConfig::mainnet(), None)
            .unwrap_or_else(|e| panic!("{}: decompose_gloas failed: {e}", path.display())),
    )
}

fn anchor(bs: BeaconState) -> LoadedState {
    let mut bs = Box::new(bs);
    // Anchor each working fork at the decoded base; epoch/longtail stay
    // unrolled (lazy — `None` idx reads the base).
    let state_id = bs.roll_fresh();
    LoadedState { bs, state_id }
}
