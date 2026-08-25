//! Telemetry daemon: one background tile on the node's spine that drains its
//! `#[timed]` rings and rotates the retained marks into compressed fxt segment
//! files, so any spike on a long run leaves a trace on disk. With a ClickHouse
//! endpoint configured, the same loop also streams per-stage block events.
//!
//! It outlives the node it attached to: on a restart the tile rebinds to the
//! new rings rather than exiting.

use std::{error::Error, time::Duration};

use clap::Parser;
use flux::tile::{TileConfig, tile_runner};
use silver_common::{SilverSpine, tracing::initialise_tracing_log};

use crate::{collector::TraceCollector, config::Args};

mod block_events;
mod clickhouse;
mod collector;
mod config;

fn main() -> Result<(), Box<dyn Error>> {
    let _tracing = initialise_tracing_log("telemetry", 10, None, false);
    let collector = TraceCollector::attach_to_node(Args::parse())?;

    let spine = SilverSpine::new(None);
    spine.start_no_persist(None, None, |scoped_spine| {
        let config =
            TileConfig::background(None, Some(Duration::from_millis(10).into())).without_metrics();
        tile_runner(collector, scoped_spine, config)();
    });
    Ok(())
}
