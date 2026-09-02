//! The directory every fixture set is rooted at, and the one file they all
//! hold. Layout past that point belongs to `perf::fixtures_dir::BlockFixtures`
//! and `da_capture::ColumnFixtures`.

use std::{
    fs,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};

const STATE_SLOT_OFFSET: usize = 8 + 32; // genesis_time(u64) + genesis_validators_root(B256)

pub struct FixtureRoot(PathBuf);

impl FixtureRoot {
    /// `env_override` points a run at a capture outside the repo. The default
    /// is resolved against this crate at compile time, so a binary carried to
    /// another machine has only the override.
    pub(crate) fn new(env_override: &str, default_subdir: &str) -> Self {
        Self(
            std::env::var_os(env_override)
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(default_subdir)),
        )
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    pub fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    pub fn finalized_state(&self) -> PathBuf {
        self.0.join("finalized_state.ssz")
    }

    pub fn read_finalized_state(&self) -> Result<(Vec<u8>, u64), String> {
        let path = self.finalized_state();
        let bytes = fs::read(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let slot = bytes
            .get(STATE_SLOT_OFFSET..STATE_SLOT_OFFSET + 8)
            .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
            .ok_or_else(|| "state SSZ shorter than slot offset".to_string())?;
        Ok((bytes, slot))
    }

    /// Avoids the ~300 MB read of `read_finalized_state`.
    pub fn read_finalized_slot(&self) -> Result<u64, String> {
        let path = self.finalized_state();
        let mut f = fs::File::open(&path).map_err(|e| format!("open {}: {e}", path.display()))?;
        f.seek(SeekFrom::Start(STATE_SLOT_OFFSET as u64))
            .map_err(|e| format!("seek {}: {e}", path.display()))?;
        let mut buf = [0u8; 8];
        f.read_exact(&mut buf).map_err(|e| format!("read slot {}: {e}", path.display()))?;
        Ok(u64::from_le_bytes(buf))
    }
}
