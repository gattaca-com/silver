//! On-disk fixture layout for the perf harness.

use std::{
    fs,
    path::{Path, PathBuf},
};

const STATE_SLOT_OFFSET: usize = 8 + 32; // genesis_time(u64) + genesis_validators_root(B256)

#[derive(serde::Serialize, serde::Deserialize)]
struct ExpectedJson {
    finalized_slot: u64,
    final_slot: u64,
    #[serde(with = "hex::serde")]
    head_state_root: [u8; 32],
}

/// Perf-regression ceilings; `None` disables that ceiling.
#[derive(Default, Clone, Copy, serde::Deserialize)]
#[serde(default)]
pub struct Thresholds {
    pub max_ns_per_block: Option<u64>,
    pub max_hash_validators_ns_per_validator: Option<u64>,
}

pub struct FixturesDir<'a>(pub &'a Path);

impl<'a> FixturesDir<'a> {
    pub fn finalized_state_path(&self) -> PathBuf {
        self.0.join("finalized_state.ssz")
    }

    pub fn block_path(&self, slot: u64) -> PathBuf {
        self.0.join(format!("next_block_{slot}.ssz"))
    }

    pub fn expected_path(&self) -> PathBuf {
        self.0.join("expected.json")
    }

    pub fn thresholds_path(&self) -> PathBuf {
        self.0.join("thresholds.json")
    }

    /// Missing file → `Thresholds::default()` (all ceilings disabled).
    pub fn read_thresholds(&self) -> Result<Thresholds, String> {
        let path = self.thresholds_path();
        let body = match fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Thresholds::default()),
            Err(e) => return Err(format!("read {}: {e}", path.display())),
        };
        serde_json::from_str(&body).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// Slot-sorted `next_block_<slot>.ssz` contents.
    pub fn read_sorted_next_blocks(&self) -> Vec<(u64, Vec<u8>)> {
        let mut found: Vec<(u64, Vec<u8>)> = fs::read_dir(self.0)
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

    pub fn read_finalized_state(&self) -> Result<(Vec<u8>, u64), String> {
        let path = self.finalized_state_path();
        let bytes = fs::read(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let slot = read_state_slot(&bytes)?;
        Ok((bytes, slot))
    }

    /// Avoids the ~300 MB read of `read_finalized_state` — used by
    /// `--continue`.
    pub fn read_finalized_slot(&self) -> Result<u64, String> {
        use std::io::{Read, Seek, SeekFrom};
        let path = self.finalized_state_path();
        let mut f = fs::File::open(&path).map_err(|e| format!("open {}: {e}", path.display()))?;
        f.seek(SeekFrom::Start(STATE_SLOT_OFFSET as u64))
            .map_err(|e| format!("seek {}: {e}", path.display()))?;
        let mut buf = [0u8; 8];
        f.read_exact(&mut buf).map_err(|e| format!("read slot {}: {e}", path.display()))?;
        Ok(u64::from_le_bytes(buf))
    }

    pub fn clear_next_blocks(&self) {
        if let Ok(rd) = fs::read_dir(self.0) {
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

fn read_state_slot(ssz: &[u8]) -> Result<u64, String> {
    ssz.get(STATE_SLOT_OFFSET..STATE_SLOT_OFFSET + 8)
        .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
        .ok_or_else(|| "state SSZ shorter than slot offset".to_string())
}
