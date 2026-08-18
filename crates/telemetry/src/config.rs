//! The daemon's CLI flags, plus the two things it reads out of the node's own
//! config file: the slot clock block-event rows are timed against and the
//! ClickHouse endpoint they go to.

use std::{fs, path::PathBuf, time::Duration};

use bytesize::ByteSize;
use clap::Parser;
use silver_config::ChainConfig;

#[derive(Parser)]
#[command(about = "Rotate silver's #[timed] marks into .fxt.gz segment files")]
pub struct Args {
    /// Directory the profiler trace segments are written to.
    #[arg(long, default_value = "profiler-traces")]
    pub dir: PathBuf,
    /// How much of a run one segment file holds, e.g. `5m`, `1h`. Rotations
    /// land on wall-clock multiples of it, so `1h` opens a file at every
    /// `hh:00:00`.
    #[arg(long, default_value = "1h", value_parser = humantime::parse_duration)]
    pub period: Duration,
    /// Discard a completed top-level frame spanning less than this — throws
    /// away idle polls so segments hold only real work, and `0s` keeps
    /// everything. The default clears an empty transmit poll (~100ns) but
    /// not the cheapest frame worth seeing (a QUIC stream event, ~2us).
    #[arg(long, default_value = "1us", value_parser = humantime::parse_duration)]
    pub filter_short_frames: Duration,
    /// Disk the segments may occupy, e.g. `512MB`, `20GB`. Every cut drops the
    /// oldest ones until the directory fits.
    #[arg(long, default_value = "20GB")]
    pub retain: ByteSize,
    /// The node's own config file: `[chain_config]` gives the slot clock the
    /// rows are timed against, and a `[telemetry] clickhouse_url = "..."`
    /// endpoint turns on block-event inserts. Unknown keys are ignored;
    /// without the file, mainnet timings apply and nothing is inserted.
    #[arg(long)]
    config: Option<PathBuf>,
}

impl Args {
    pub fn file_config(&self) -> Result<FileConfig, String> {
        let Some(path) = &self.config else {
            return Ok(FileConfig::default());
        };
        let raw = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        toml::from_str(&raw).map_err(|e| format!("{}: {e}", path.display()))
    }
}

#[derive(serde::Deserialize, Default)]
pub struct FileConfig {
    #[serde(default)]
    pub telemetry: TelemetrySection,
    #[serde(default)]
    pub chain_config: ChainConfig,
}

#[derive(serde::Deserialize, Default)]
pub struct TelemetrySection {
    pub clickhouse_url: Option<String>,
    /// Tags every row's `meta_network_name`, which is what keeps a devnet's
    /// rows from being compared against mainnet's. Unset records `unknown`.
    pub network: Option<String>,
}
