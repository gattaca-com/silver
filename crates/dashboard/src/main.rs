//! Relays exporter datagrams to browsers. Each instance's datagrams land in a
//! bounded raw ring; every WebSocket client is a cursor into those rings and
//! replays them from the oldest entry on connect. The server reads only the
//! header — decoding is the page's job.

use std::{io, net::SocketAddr};

use bytesize::ByteSize;
use clap::Parser;
use tracing_subscriber::EnvFilter;

use crate::relay::Relay;

mod conn;
mod relay;
mod ring;

#[derive(Parser)]
#[command(about = "Live dashboard for silver instances")]
struct Args {
    /// Where exporters send their datagrams.
    #[arg(long, default_value = "0.0.0.0:9870")]
    udp: SocketAddr,
    /// Serves the page and its WebSocket.
    #[arg(long, default_value = "0.0.0.0:8080")]
    http: SocketAddr,
    /// Raw history kept per instance, e.g. `64MB`. The replay window is this
    /// over the instance's ingest rate, logged every 10 s as `retained_s`.
    #[arg(long, default_value = "64MB")]
    ring: ByteSize,
}

fn main() -> io::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    let args = Args::parse();
    Relay::bind(args.udp, args.http, args.ring.as_u64() as usize)?.run()
}
