//! On-disk fixture layout for the perf harness.

use std::{
    fs,
    path::{Path, PathBuf},
};

use silver_common::Nanos;

const STATE_SLOT_OFFSET: usize = 8 + 32; // genesis_time(u64) + genesis_validators_root(B256)

#[derive(serde::Serialize, serde::Deserialize)]
struct ExpectedJson {
    finalized_slot: u64,
    final_slot: u64,
    #[serde(with = "hex::serde")]
    head_state_root: [u8; 32],
}

/// Per-frame perf thresholds; field names match `#[timed]` frame labels,
/// `_avg` = average across all calls of that frame in the run.
#[derive(Default, Clone, Copy, serde::Deserialize)]
#[serde(default)]
pub struct Thresholds {
    /// One-shot cost of `decompose` at harness boot.
    #[serde(deserialize_with = "de_duration")]
    pub max_decompose: Option<Nanos>,
    /// Median (p50) `apply_block` call — typical per-block latency, robust to
    /// the epoch-boundary outliers that skew the average.
    #[serde(deserialize_with = "de_duration")]
    pub max_apply_block_p50: Option<Nanos>,
    /// Slowest single `apply_block` call in the run — guards worst-case
    /// latency, not just the typical block.
    #[serde(deserialize_with = "de_duration")]
    pub max_apply_block_max: Option<Nanos>,
    /// Average wall time of one `process_epoch` (epoch-transition) call.
    #[serde(deserialize_with = "de_duration")]
    pub max_process_epoch_avg: Option<Nanos>,
    /// Average wall time of one `hash_tree_root_state` call (sum across all
    /// call sites — `process_slots` and direct).
    #[serde(deserialize_with = "de_duration")]
    pub max_hash_tree_root_state_avg: Option<Nanos>,
}

/// Accepts `"2.5s" | "500ms" | "100us" | "100µs" | "100ns"` (or `null`).
/// Rejects bare numbers — the unit is mandatory so the file stays
/// self-documenting (`Nanos`' own deserializer would silently read a bare
/// number as nanoseconds, so we keep this stricter parser).
fn de_duration<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Nanos>, D::Error> {
    use serde::Deserialize;
    let s: Option<String> = Option::deserialize(d)?;
    s.map(|s| parse_duration_ns(s.as_str()).map(Nanos).map_err(serde::de::Error::custom))
        .transpose()
}

fn parse_duration_ns(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let split = s
        .find(|c: char| c.is_alphabetic() || c == 'µ')
        .filter(|&i| i > 0)
        .ok_or_else(|| format!("missing unit in {s:?} (expected e.g. \"2.5s\")"))?;
    let n: f64 = s[..split].trim().parse().map_err(|e| format!("number in {s:?}: {e}"))?;
    let mult: f64 = match s[split..].trim() {
        "ns" => 1.0,
        "us" | "µs" => 1_000.0,
        "ms" => 1_000_000.0,
        "s" => 1_000_000_000.0,
        u => return Err(format!("unknown unit {u:?} in {s:?} (expected ns|us|ms|s)")),
    };
    Ok((n * mult).round() as u64)
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
