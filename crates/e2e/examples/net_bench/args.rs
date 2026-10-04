use std::{env, net::SocketAddr, path::PathBuf, process, time::Duration};

use serde::Serialize;
use silver_config::NetworkConfig;
#[cfg(all(target_os = "linux", feature = "io-uring"))]
use silver_config::UringConfig;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Sender,
    Echo,
}

#[derive(Debug, Serialize)]
pub struct Args {
    pub role: Role,
    pub listen: SocketAddr,
    pub peer: Option<SocketAddr>,
    #[serde(skip)]
    pub network: NetworkConfig,
    pub backend: &'static str,
    pub sqpoll_cpu: Option<u32>,
    pub send_zc_min_size: Option<usize>,
    pub connections: usize,
    pub rate_hz: u64,
    pub payload_size: usize,
    #[serde(with = "seconds")]
    pub warmup: Duration,
    #[serde(with = "seconds")]
    pub duration: Duration,
    #[serde(with = "seconds")]
    pub idle_exit: Duration,
    #[serde(skip)]
    pub json: Option<PathBuf>,
}

const USAGE: &str = "\
usage: net_bench --role sender|echo --listen ADDR [--peer ADDR]
                 [--backend mio|io-uring] [--sqpoll-cpu N] [--zc-min BYTES]
                 [--connections N] [--rate HZ] [--payload-size BYTES]
                 [--warmup S] [--duration S] [--idle-exit S] [--json PATH]
The discovery socket binds the --listen port + 1. --rate is the total across
--connections; the sender sends probe n on connection n % N.";

impl Args {
    pub fn parse() -> Self {
        let mut role = None;
        let mut listen = None;
        let mut peer = None;
        let mut backend = "mio";
        let mut sqpoll_cpu = None;
        let mut send_zc_min_size = None;
        let mut connections = 1;
        let mut rate_hz = 1000;
        let mut payload_size = 1024;
        let mut warmup = Duration::from_secs(2);
        let mut duration = Duration::from_secs(10);
        let mut idle_exit = Duration::from_secs(5);
        let mut json = None;

        let argv: Vec<String> = env::args().skip(1).collect();
        let mut pairs = argv.chunks(2);
        while let Some(pair) = pairs.next() {
            let [flag, value] = pair else { fail(&format!("{} needs a value", pair[0])) };
            match flag.as_str() {
                "--role" => {
                    role = Some(match value.as_str() {
                        "sender" => Role::Sender,
                        "echo" => Role::Echo,
                        _ => fail("--role expects sender or echo"),
                    })
                }
                "--listen" => listen = Some(parse(flag, value)),
                "--peer" => peer = Some(parse(flag, value)),
                "--backend" => {
                    backend = match value.as_str() {
                        "mio" => "mio",
                        "io-uring" => "io-uring",
                        _ => fail("--backend expects mio or io-uring"),
                    }
                }
                "--sqpoll-cpu" => sqpoll_cpu = Some(parse(flag, value)),
                "--zc-min" => send_zc_min_size = Some(parse(flag, value)),
                "--connections" => connections = parse(flag, value),
                "--rate" => rate_hz = parse(flag, value),
                "--payload-size" => payload_size = parse(flag, value),
                "--warmup" => warmup = Duration::from_secs_f64(parse(flag, value)),
                "--duration" => duration = Duration::from_secs_f64(parse(flag, value)),
                "--idle-exit" => idle_exit = Duration::from_secs_f64(parse(flag, value)),
                "--json" => json = Some(PathBuf::from(value)),
                _ => fail(&format!("unknown flag {flag}")),
            }
        }

        let role = role.unwrap_or_else(|| fail("--role is required"));
        let listen = listen.unwrap_or_else(|| fail("--listen is required"));
        if role == Role::Sender && peer.is_none() {
            fail("--role sender needs --peer");
        }
        if rate_hz == 0 || connections == 0 {
            fail("--rate and --connections must be nonzero");
        }
        let network = network_config(backend, sqpoll_cpu, send_zc_min_size);
        Self {
            role,
            listen,
            peer,
            network,
            backend,
            sqpoll_cpu,
            send_zc_min_size,
            connections,
            rate_hz,
            payload_size,
            warmup,
            duration,
            idle_exit,
            json,
        }
    }
}

#[cfg(all(target_os = "linux", feature = "io-uring"))]
fn network_config(
    backend: &str,
    sqpoll_cpu: Option<u32>,
    send_zc_min_size: Option<usize>,
) -> NetworkConfig {
    if backend == "mio" {
        if sqpoll_cpu.is_some() || send_zc_min_size.is_some() {
            fail("--sqpoll-cpu and --zc-min need --backend io-uring");
        }
        return NetworkConfig::Mio;
    }
    let defaults = UringConfig::default();
    NetworkConfig::IoUring(UringConfig {
        sqpoll_cpu,
        send_zc_min_size: send_zc_min_size.unwrap_or(defaults.send_zc_min_size),
        ..defaults
    })
}

#[cfg(not(all(target_os = "linux", feature = "io-uring")))]
fn network_config(
    backend: &str,
    sqpoll_cpu: Option<u32>,
    send_zc_min_size: Option<usize>,
) -> NetworkConfig {
    if backend != "mio" || sqpoll_cpu.is_some() || send_zc_min_size.is_some() {
        fail("io-uring options need Linux and a build with --features io-uring");
    }
    NetworkConfig::Mio
}

fn parse<T: std::str::FromStr>(flag: &str, value: &str) -> T {
    value.parse().unwrap_or_else(|_| fail(&format!("{flag}: invalid value {value}")))
}

fn fail(message: &str) -> ! {
    eprintln!("{message}\n{USAGE}");
    process::exit(2);
}

mod seconds {
    use std::time::Duration;

    use serde::Serializer;

    pub fn serialize<S: Serializer>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_f64(duration.as_secs_f64())
    }
}
