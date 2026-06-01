// Run the engine tile standalone against a local EL node.
//
// A separate feeder process can write EngineReq messages over the shared
// memory spine and large SSZ payloads into the shmem TCache segments.
//
// Usage:
//   cargo run -p silver_engine --example engine_tile_relay -- \
//     --endpoint http://127.0.0.1:8551 \
//     --jwt-secret /path/to/jwtsecret
//
// Press Ctrl-C to stop.

use std::sync::atomic::Ordering;

use flux::tile::{TileConfig, attach_tile};
use silver_common::{SilverSpine, TCache};
use silver_engine::{EngineClient, EngineTile, JwtSecret};
use tracing_subscriber::EnvFilter;

const ENGINE_TCACHE_SIZE: usize = 1 << 24; // 16 MiB

const REQ_SHMEM_NAME: &str = "/silver-engine-req";
const RESP_SHMEM_NAME: &str = "/silver-engine-resp";

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive(tracing::Level::INFO.into()))
        .init();

    let (endpoint, jwt) = parse_args();
    tracing::info!(%endpoint, "starting engine tile");

    // Shmem-backed TCache pair. The req segment is written by the feeder
    // process; the resp segment is written here and read by the feeder.
    let req_consumer =
        TCache::shm_consumer(REQ_SHMEM_NAME, ENGINE_TCACHE_SIZE).expect("req shmem consumer");
    let resp_producer = TCache::shm_producer(RESP_SHMEM_NAME, ENGINE_TCACHE_SIZE);

    let tile = EngineTile::new(EngineClient::new(endpoint, jwt), req_consumer, resp_producer);

    let spine = SilverSpine::new(None);
    spine.start(None, None, |scoped| {
        let stop = std::sync::Arc::clone(&scoped.stop_flag);
        attach_tile(tile, scoped, TileConfig::background(None, None));

        while stop.load(Ordering::Relaxed) == 0 {
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    });
}

fn parse_args() -> (String, JwtSecret) {
    let args: Vec<String> = std::env::args().collect();
    let mut endpoint = "http://127.0.0.1:8551".to_string();
    let mut jwt_arg: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--endpoint" => {
                i += 1;
                endpoint = args[i].clone();
            }
            "--jwt-secret" => {
                i += 1;
                jwt_arg = Some(args[i].clone());
            }
            _ => {}
        }
        i += 1;
    }

    let jwt = match jwt_arg {
        Some(s) if std::path::Path::new(&s).exists() => {
            JwtSecret::from_file(std::path::Path::new(&s))
                .unwrap_or_else(|e| panic!("invalid jwt file {s}: {e}"))
        }
        Some(s) => JwtSecret::from_hex(&s).unwrap_or_else(|e| panic!("invalid jwt hex: {e}")),
        _ => {
            eprintln!("--jwt-secret <path|hex> required");
            std::process::exit(1);
        }
    };

    (endpoint, jwt)
}
