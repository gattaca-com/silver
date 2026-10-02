use clap::Parser;
use silver_config::Config;

use crate::BUILD_INFO;

/// High-performance Ethereum consensus client. Flags override the config file.
#[derive(Parser)]
#[command(version, long_version = BUILD_INFO)]
pub struct Args {
    /// TOML config file. Every key is optional; without one, silver runs a
    /// mainnet node.
    #[arg(long)]
    config: Option<String>,
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
    pub fn config(&self) -> Result<Config, silver_common::Error> {
        let mut config = match &self.config {
            Some(path) => Config::from_file(path)?,
            None => Config::mainnet()?,
        };
        if let Some(url) = &self.execution_endpoint {
            config = config.with_execution_endpoint(url.clone());
        }
        if let Some(path) = &self.jwt_secret {
            config = config.with_jwt_secret(path.clone());
        }
        if self.unsafe_no_el {
            config = config.with_unsafe_no_el(true);
        }

        silver_log::info!("loaded config: {config:#?}");

        Ok(config)
    }
}
