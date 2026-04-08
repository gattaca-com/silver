use std::{path::PathBuf, time::Duration};

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct DiscoveryConfig {
    #[serde(default = "default_u64::<1000>")]
    pub lookup_interval_ms: u64,
    #[serde(default = "default_usize::<6>")]
    pub lookup_distances: usize,
    #[serde(default = "default_usize::<128>")]
    pub target_sessions: usize,
    #[serde(default = "default_u64::<5>")]
    pub ping_frequency_s: u64,
    #[serde(default = "default_usize::<5>")]
    pub probes_per_lookup: usize,
    #[serde(default = "default_usize::<10>")]
    pub pings_per_poll: usize,
    #[serde(default = "default_u64::<5000>")]
    pub cleanup_interval_ms: u64,
    #[serde(default = "default_u64::<1200>")]
    pub session_timeout_s: u64,
    #[serde(default = "default_u64::<1>")]
    pub challenge_ttl_s: u64,
    #[serde(default = "default_u64::<500>")]
    pub request_timeout_ms: u64,
    #[serde(default = "default_u32::<3>")]
    pub ip_vote_threshold: u32,
    #[serde(default = "default_u64::<60>")]
    pub kbucket_pending_timeout_s: u64,
    #[serde(default = "default_u32::<5>")]
    pub whoareyou_per_ip_limit: u32,
    #[serde(default = "default_u32::<100>")]
    pub whoareyou_global_limit: u32,
    #[serde(default = "default_u64::<1000>")]
    pub whoareyou_window_ms: u64,
    pub persisted_routing_table_path: Option<PathBuf>,
}

impl DiscoveryConfig {
    pub fn lookup_interval(&self) -> Duration {
        Duration::from_millis(self.lookup_interval_ms)
    }

    pub fn ping_frequency(&self) -> Duration {
        Duration::from_secs(self.ping_frequency_s)
    }

    pub fn cleanup_interval(&self) -> Duration {
        Duration::from_millis(self.cleanup_interval_ms)
    }

    pub fn session_timeout(&self) -> Duration {
        Duration::from_secs(self.session_timeout_s)
    }

    pub fn challenge_ttl(&self) -> Duration {
        Duration::from_secs(self.challenge_ttl_s)
    }

    pub fn request_timeout(&self) -> Duration {
        Duration::from_millis(self.request_timeout_ms)
    }

    pub fn kbucket_pending_timeout(&self) -> Duration {
        Duration::from_secs(self.kbucket_pending_timeout_s)
    }

    pub fn whoareyou_window(&self) -> Duration {
        Duration::from_millis(self.whoareyou_window_ms)
    }
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            lookup_interval_ms: 3_600_000,
            lookup_distances: 6,
            target_sessions: 128,
            ping_frequency_s: 5,
            probes_per_lookup: 5,
            pings_per_poll: 10,
            cleanup_interval_ms: 5000,
            session_timeout_s: 1200,
            challenge_ttl_s: 1,
            request_timeout_ms: 500,
            ip_vote_threshold: 3,
            kbucket_pending_timeout_s: 60,
            whoareyou_per_ip_limit: 5,
            whoareyou_global_limit: 100,
            whoareyou_window_ms: 1000,
            persisted_routing_table_path: None,
        }
    }
}

pub const fn default_u32<const V: u32>() -> u32 {
    V
}

pub const fn default_u64<const V: u64>() -> u64 {
    V
}

pub const fn default_usize<const V: usize>() -> usize {
    V
}
