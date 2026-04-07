use std::time::Duration;

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct DiscoveryConfig {
    pub lookup_interval_ms: u64,
    #[serde(default = "default_usize::<6>")]
    pub lookup_distances: usize,
    pub target_sessions: usize,
    pub ping_frequency_s: u64,
    #[serde(default = "default_usize::<10>")]
    pub pings_per_poll: usize,
    #[serde(default = "default_u64::<5000>")]
    pub cleanup_interval_ms: u64,
    #[serde(default = "default_u32::<5>")]
    pub whoareyou_per_ip_limit: u32,
    #[serde(default = "default_u32::<100>")]
    pub whoareyou_global_limit: u32,
    #[serde(default = "default_u64::<1000>")]
    pub whoareyou_window_ms: u64,
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

    pub fn whoareyou_window(&self) -> Duration {
        Duration::from_millis(self.whoareyou_window_ms)
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
