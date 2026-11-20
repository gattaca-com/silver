//! Filesystem discovery of metrics sources under flux's canonical
//! shmem-queues directory: `{base_dir}/{app_name}/shmem/queues/`.
//! silver's counters macro writes here too, so one walk picks up
//! every source.
//!
//! Files of interest:
//! - `counters-{name}` — shmem-mapped `[AtomicU64; N]` (read-only).
//! - `latency-{name}` — flux MPMC `TimingMessage` queue (tcache consumer
//!   latency / spine consumer ingestion→consume gap).
//! - `timing-{name}` — the same Timer's processing side (consume handler
//!   duration). Created eagerly for every Timer; only spine consumers emit.
//! - `tilemetrics-{name}` — flux SPMC `TileSample` queue.
//! - `build-info` — the producer's build stamp, plain text.

use std::{collections::HashMap, fs, io, path::PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceKind {
    Counters,
    Latency,
    Processing,
    Tile,
    Build,
}

impl SourceKind {
    pub fn parse(filename: &str) -> Option<(Self, &str)> {
        if filename == "build-info" {
            return Some((Self::Build, filename));
        }
        let (kind, name) = filename.split_once('-')?;
        Some((
            match kind {
                "counters" => Self::Counters,
                "latency" => Self::Latency,
                "timing" => Self::Processing,
                "tilemetrics" => Self::Tile,
                _ => return None,
            },
            name,
        ))
    }
}

pub struct DiscoveredSources {
    pub counters: Vec<CounterFile>,
    pub tcaches: Vec<CounterFile>,
    pub timings: Vec<TimingFile>,
    pub tilemetrics: Vec<TileMetricsFile>,
    pub build_info: Option<String>,
}

pub struct CounterFile {
    /// The `{name}` suffix from `counters-{name}` — used as both the
    /// display label and the schema lookup key.
    pub name: String,
    pub path: PathBuf,
}

pub struct TimingFile {
    /// The `{name}` suffix from `latency-{name}`.
    pub name: String,
    pub path: PathBuf,
    /// Sibling `timing-{name}` queue (processing duration), when present.
    pub processing_path: Option<PathBuf>,
}

pub struct TileMetricsFile {
    /// The `{name}` suffix from `tilemetrics-{name}`.
    pub name: String,
    pub path: PathBuf,
}

pub fn discover(base_dir: &std::path::Path, app_name: &str) -> io::Result<DiscoveredSources> {
    let mut counters = Vec::new();
    let mut tcaches = Vec::new();
    let mut timings: Vec<TimingFile> = Vec::new();
    let mut processing: HashMap<String, PathBuf> = HashMap::new();
    let mut tilemetrics = Vec::new();
    let mut build_info = None;

    let dir = flux::utils::directories::shmem_dir_queues_with_base(base_dir, app_name);
    if let Ok(entries) = fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(fname) = path.file_name().and_then(|n| n.to_str()) else { continue };
            match SourceKind::parse(fname) {
                Some((SourceKind::Counters, name)) => {
                    let file = CounterFile { name: name.to_string(), path };
                    if file.name.starts_with("tcache-") {
                        tcaches.push(file);
                    } else {
                        counters.push(file);
                    }
                }
                Some((SourceKind::Latency, name)) => {
                    timings.push(TimingFile { name: name.to_string(), path, processing_path: None })
                }
                Some((SourceKind::Processing, name)) => {
                    processing.insert(name.to_string(), path);
                }
                Some((SourceKind::Tile, name)) => {
                    tilemetrics.push(TileMetricsFile { name: name.to_string(), path })
                }
                Some((SourceKind::Build, _)) => build_info = fs::read_to_string(path).ok(),
                None => {}
            }
        }
    }

    for t in &mut timings {
        t.processing_path = processing.remove(&t.name);
    }

    counters
        .sort_by(|a, b| crate::schema::sort_key(&a.name).cmp(&crate::schema::sort_key(&b.name)));
    tcaches.sort_by(|a, b| a.name.cmp(&b.name));
    timings.sort_by(|a, b| a.name.cmp(&b.name));
    tilemetrics.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(DiscoveredSources { counters, tcaches, timings, tilemetrics, build_info })
}
