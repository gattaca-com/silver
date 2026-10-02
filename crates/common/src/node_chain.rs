use std::{fs, io, path::PathBuf};

use flux::utils::directories::shmem_dir_queues;

use crate::APP_NAME;

/// The chain a booted node times its slots in, as it publishes it for the
/// processes reading its rings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeChain {
    pub genesis_unix_secs: u64,
    pub slot_ms: u64,
    pub network: String,
}

impl NodeChain {
    pub fn publish(&self) -> io::Result<()> {
        let path = Self::path();
        fs::create_dir_all(path.parent().expect("queue dir has a parent"))?;
        fs::write(path, format!("{} {} {}", self.genesis_unix_secs, self.slot_ms, self.network))
    }

    /// `None` until a node has published one.
    pub fn read() -> Option<Self> {
        let text = fs::read_to_string(Self::path()).ok()?;
        let mut fields = text.split_whitespace();
        Some(Self {
            genesis_unix_secs: fields.next()?.parse().ok()?,
            slot_ms: fields.next()?.parse().ok()?,
            network: fields.next()?.to_owned(),
        })
    }

    fn path() -> PathBuf {
        shmem_dir_queues(APP_NAME).join("chain")
    }
}
