use std::fs;

use flux::utils::directories::shmem_dir_queues;
use silver_common::APP_NAME;
use silver_config::ChainConfig;
use silver_stages::SlotClock;

/// The per-node values joined onto every row.
pub struct NodeMeta {
    /// `meta_client_name`: rows from every machine land in one table.
    pub node: String,
    pub network: String,
    pub clock: SlotClock,
    /// Commit the running node was built from; empty until a node has
    /// published one.
    pub version: String,
}

impl NodeMeta {
    pub fn new(chain: &ChainConfig) -> Self {
        let slot_ms = chain.slot_duration().as_millis() as u64;
        Self {
            node: Self::hostname(),
            network: chain.spec.network_name(),
            clock: SlotClock::new(chain.genesis_unix_secs, slot_ms),
            version: String::new(),
        }
    }

    fn hostname() -> String {
        let mut buf = [0u8; 256];
        if unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) } != 0 {
            return "unknown".to_owned();
        }
        let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        String::from_utf8_lossy(&buf[..len]).into_owned()
    }

    /// A restarted node may run a different build.
    pub fn refresh_version(&mut self) {
        if let Ok(info) = fs::read_to_string(shmem_dir_queues(APP_NAME).join("build-info")) {
            let commit = info.split(" · ").next().unwrap_or_default();
            if commit != self.version {
                commit.clone_into(&mut self.version);
            }
        }
    }
}
