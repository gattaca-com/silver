use clap::Parser;
use silver_config::{Config, Network, Overrides};

use crate::BUILD_INFO;

/// High-performance Ethereum consensus client. Flags override the config file.
#[derive(Parser)]
#[command(version, long_version = BUILD_INFO)]
pub struct Args {
    /// TOML config file. Every key is optional; without one, silver runs a
    /// mainnet node.
    #[arg(long)]
    config: Option<String>,
    /// `mainnet` (default), `hoodi`, `sepolia`, or a devnet's metadata
    /// directory holding its `config.yaml` and, optionally,
    /// `bootstrap_nodes.yaml`.
    #[arg(long)]
    network: Option<Network>,
    /// Engine API URL of the execution client, e.g. `http://localhost:8551`.
    #[arg(long)]
    execution_endpoint: Option<String>,
    /// The execution client's hex JWT secret file.
    #[arg(long)]
    jwt_secret: Option<String>,
    /// Run without an execution client: every payload counts as valid. For
    /// testing only.
    #[arg(long)]
    unsafe_no_el: bool,
}

impl Args {
    pub fn config(self) -> Result<Config, silver_common::Error> {
        let overrides = Overrides {
            network: self.network,
            execution_endpoint: self.execution_endpoint,
            jwt_secret: self.jwt_secret,
            unsafe_no_el: self.unsafe_no_el,
        };
        let config = Config::load(self.config.as_deref(), overrides)?;

        silver_log::info!("loaded config: {config:#?}");

        Ok(config)
    }
}
