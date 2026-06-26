//! Filesystem discovery of metrics sources under flux's canonical
//! shmem-queues directory: `{base_dir}/{app_name}/shmem/queues/`.
//! silver's counters macro writes here too, so one walk picks up
//! every source.
//!
//! Files of interest:
//! - `counters-{name}` — shmem-mapped `[AtomicU64; N]` (read-only).
//! - `latency-{name}` — flux MPMC `TimingMessage` queue (tcache consumer
//!   latency).
//! - `tilemetrics-{name}` — flux SPMC `TileSample` queue.

use std::{fs, io, path::PathBuf};

pub struct DiscoveredSources {
    pub counters: Vec<CounterFile>,
    pub tcaches: Vec<CounterFile>,
    pub timings: Vec<TimingFile>,
    pub tilemetrics: Vec<TileMetricsFile>,
}

pub struct CounterFile {
    /// The `{name}` suffix from `counters-{name}` — used as both the
    /// display label and the schema lookup key.
    pub name: String,
    pub path: PathBuf,
    /// File size in bytes. Divided by 8 gives the slot count.
    pub size_bytes: u64,
}

pub struct TimingFile {
    /// The `{name}` suffix from `latency-{name}`.
    pub name: String,
    pub path: PathBuf,
}

pub struct TileMetricsFile {
    /// The `{name}` suffix from `tilemetrics-{name}`.
    pub name: String,
    pub path: PathBuf,
}

pub fn discover(base_dir: &std::path::Path, app_name: &str) -> io::Result<DiscoveredSources> {
    let mut counters = Vec::new();
    let mut tcaches = Vec::new();
    let mut timings = Vec::new();
    let mut tilemetrics = Vec::new();

    let dir = flux::utils::directories::shmem_dir_queues_with_base(base_dir, app_name);
    if let Ok(entries) = fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(fname) = path.file_name().and_then(|n| n.to_str()) else { continue };
            if let Some(name) = fname.strip_prefix("counters-") {
                let size_bytes = entry.metadata().map(|m| m.len()).unwrap_or(0);
                let file = CounterFile { name: name.to_string(), path, size_bytes };
                if file.name.starts_with("tcache-") {
                    tcaches.push(file);
                } else {
                    counters.push(file);
                }
            } else if let Some(name) = fname.strip_prefix("latency-") {
                timings.push(TimingFile { name: name.to_string(), path });
            } else if let Some(name) = fname.strip_prefix("tilemetrics-") {
                tilemetrics.push(TileMetricsFile { name: name.to_string(), path });
            }
        }
    }

    counters.sort_by(|a, b| a.name.cmp(&b.name));
    tcaches.sort_by(|a, b| a.name.cmp(&b.name));
    timings.sort_by(|a, b| a.name.cmp(&b.name));
    tilemetrics.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(DiscoveredSources { counters, tcaches, timings, tilemetrics })
}
