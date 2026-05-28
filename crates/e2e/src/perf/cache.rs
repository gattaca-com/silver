//! On-disk fixture layout for the perf harness: one anchor_state.ssz + one
//! next_block_<slot>.ssz per following block.

use std::path::{Path, PathBuf};

const STATE_SLOT_OFFSET: usize = 8 + 32; // genesis_time(u64) + genesis_validators_root(B256)

pub struct FixtureCacheDir<'a>(pub &'a Path);

impl<'a> FixtureCacheDir<'a> {
    pub fn anchor_state_path(&self) -> PathBuf {
        self.0.join("anchor_state.ssz")
    }

    pub fn block_path(&self, slot: u64) -> PathBuf {
        self.0.join(format!("next_block_{slot}.ssz"))
    }

    /// Remove every `next_block_*.ssz` from the cache dir. Called when a fresh
    /// anchor invalidates the previously-cached chain.
    pub fn clear_next_blocks(&self) {
        if let Ok(rd) = std::fs::read_dir(self.0) {
            for e in rd.flatten() {
                if e.file_name().to_string_lossy().starts_with("next_block_") {
                    let _ = std::fs::remove_file(e.path());
                }
            }
        }
    }

    /// Number of `next_block_<anchor+p>.ssz` files present for `p` in
    /// `1..=lookahead` — i.e. blocks already cached for this anchor.
    pub fn count_cached_blocks(&self, anchor: u64, lookahead: u64) -> usize {
        (1..=lookahead).filter(|p| self.block_path(anchor + p).exists()).count()
    }

    /// All `next_block_<slot>.ssz` files in the cache dir, parsed and sorted by
    /// slot. Used by perf (post-anchor) and by
    /// `utils::scan_checkpoint_fixtures` (make-managed
    /// `example_checkpoints/`).
    pub fn read_sorted_next_blocks(&self) -> Vec<(u64, Vec<u8>)> {
        let mut found: Vec<(u64, Vec<u8>)> = std::fs::read_dir(self.0)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| {
                let name = e.file_name().into_string().ok()?;
                let slot: u64 =
                    name.strip_prefix("next_block_")?.strip_suffix(".ssz")?.parse().ok()?;
                Some((slot, std::fs::read(e.path()).ok()?))
            })
            .collect();
        found.sort_by_key(|(s, _)| *s);
        found
    }

    /// Load up to `n_blocks` cached next-blocks strictly after `anchor`,
    /// slot-ascending.
    pub fn load_next_blocks(&self, anchor: u64, n_blocks: usize) -> Vec<Vec<u8>> {
        let mut found = self.read_sorted_next_blocks();
        found.retain(|(slot, _)| *slot > anchor);
        found.truncate(n_blocks);
        found.into_iter().map(|(_, b)| b).collect()
    }
}

/// Parse the slot field from a BeaconState SSZ buffer.
pub fn read_state_slot(ssz: &[u8]) -> Result<u64, String> {
    ssz.get(STATE_SLOT_OFFSET..STATE_SLOT_OFFSET + 8)
        .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
        .ok_or_else(|| "state SSZ shorter than slot offset".to_string())
}
