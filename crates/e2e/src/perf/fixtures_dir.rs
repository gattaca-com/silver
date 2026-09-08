//! On-disk fixture layout for the perf harness.

use std::{fs, path::PathBuf};

use crate::{fixtures::FixtureRoot, perf::thresholds::Threshold};

#[derive(serde::Serialize, serde::Deserialize)]
struct ExpectedJson {
    finalized_slot: u64,
    final_slot: u64,
    #[serde(with = "hex::serde")]
    head_state_root: [u8; 32],
}

pub struct BlockFixtures(FixtureRoot);

impl BlockFixtures {
    pub fn perf() -> Self {
        Self(FixtureRoot::new("PERF_FIXTURES", "data/perf"))
    }

    pub fn checkpoints() -> Self {
        Self(FixtureRoot::new("CHECKPOINT_FIXTURES", "tests/example_checkpoints"))
    }

    pub fn root(&self) -> &FixtureRoot {
        &self.0
    }

    pub fn block_path(&self, slot: u64) -> PathBuf {
        self.0.join(&format!("next_block_{slot}.ssz"))
    }

    pub fn expected_path(&self) -> PathBuf {
        self.0.join("expected.json")
    }

    pub fn thresholds_path(&self) -> PathBuf {
        self.0.join("thresholds.json")
    }

    /// Missing file → no gauges.
    pub fn read_thresholds(&self) -> Result<Vec<Threshold>, String> {
        let path = self.thresholds_path();
        let body = match fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(format!("read {}: {e}", path.display())),
        };
        serde_json::from_str(&body).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// Slot-sorted `next_block_<slot>.ssz` contents.
    pub fn read_sorted_next_blocks(&self) -> Vec<(u64, Vec<u8>)> {
        let mut found: Vec<(u64, Vec<u8>)> = fs::read_dir(self.0.path())
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| {
                let name = e.file_name().into_string().ok()?;
                let slot: u64 =
                    name.strip_prefix("next_block_")?.strip_suffix(".ssz")?.parse().ok()?;
                Some((slot, fs::read(e.path()).ok()?))
            })
            .collect();
        found.sort_by_key(|(s, _)| *s);
        found
    }

    pub fn clear_next_blocks(&self) {
        if let Ok(rd) = fs::read_dir(self.0.path()) {
            for e in rd.flatten() {
                if e.file_name().to_string_lossy().starts_with("next_block_") {
                    let _ = fs::remove_file(e.path());
                }
            }
        }
    }

    pub fn read_expected(&self) -> Result<[u8; 32], String> {
        let path = self.expected_path();
        let body =
            fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let parsed: ExpectedJson =
            serde_json::from_str(&body).map_err(|e| format!("expected.json: {e}"))?;
        Ok(parsed.head_state_root)
    }

    pub fn write_expected(
        &self,
        finalized_slot: u64,
        final_slot: u64,
        root: &[u8; 32],
    ) -> Result<(), String> {
        let json = serde_json::to_string_pretty(&ExpectedJson {
            finalized_slot,
            final_slot,
            head_state_root: *root,
        })
        .map_err(|e| format!("serialize expected.json: {e}"))?;
        let path = self.expected_path();
        fs::write(&path, json).map_err(|e| format!("write {}: {e}", path.display()))
    }
}
