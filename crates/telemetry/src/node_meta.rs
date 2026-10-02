use std::{fs, thread, time::Duration};

use flux::utils::directories::shmem_dir_queues;
use flux_profiler::published_pid;
use silver_common::{APP_NAME, NodeChain};
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

/// The chain node `pid` booted into, since slot times mean nothing without
/// it. `None` once that node is gone: one that dies while loading its
/// checkpoint never publishes.
pub fn wait_for_node_chain(pid: u32) -> Option<NodeChain> {
    silver_log::info!("waiting for the node to publish its chain");
    loop {
        if let Some(chain) = NodeChain::read() {
            return Some(chain);
        }
        if published_pid(APP_NAME) != Some(pid) {
            return None;
        }
        thread::sleep(Duration::from_millis(100));
    }
}

impl NodeMeta {
    pub fn new(chain: &NodeChain) -> Self {
        Self {
            node: Self::hostname(),
            network: chain.network.clone(),
            clock: SlotClock::new(chain.genesis_unix_secs, chain.slot_ms),
            version: String::new(),
        }
    }

    pub fn hostname() -> String {
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
