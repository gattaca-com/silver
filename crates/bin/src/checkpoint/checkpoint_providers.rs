use std::{
    io::{self, Read},
    thread,
    time::{Duration, Instant},
};

use serde_json::Value;
use silver_beacon_state_data::Checkpoint;
use ureq::Agent;

/// Bounds each provider's answer; they are queried in parallel.
const FINALITY_TIMEOUT: Duration = Duration::from_secs(5);

/// A provider can announce a new finalized checkpoint before it serves that
/// block and state (Checkpointz fetches them only after finality moves), so a
/// miss right after a finality change is retried for about a minute.
const DOWNLOAD_ATTEMPTS: u32 = 6;
const DOWNLOAD_RETRY_DELAY: Duration = Duration::from_secs(12);

pub struct CheckpointProviders {
    agent: Agent,
    urls: Vec<String>,
    retry_delay: Duration,
}

impl CheckpointProviders {
    pub fn new(urls: &[String]) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(10))
            .timeout_read(Duration::from_secs(30))
            .build();
        let urls = urls.iter().map(|url| url.trim_end_matches('/').to_owned()).collect();
        Self { agent, urls, retry_delay: DOWNLOAD_RETRY_DELAY }
    }

    pub fn is_empty(&self) -> bool {
        self.urls.is_empty()
    }

    /// Needs a strict majority of the answers and at least `min(2, urls)`
    /// votes, so no single provider picks it; a provider lagging an epoch is
    /// outvoted. Keeps only the providers that voted for it, fastest first.
    pub fn agreed_finalized(&mut self) -> io::Result<Checkpoint> {
        let quorum = self.urls.len().min(2);
        let this = &*self;
        let queried: Vec<_> = thread::scope(|scope| {
            let queries: Vec<_> = (this.urls.iter())
                .map(|url| {
                    scope.spawn(move || {
                        let started = Instant::now();
                        (url, this.finalized(url), started.elapsed())
                    })
                })
                .collect();
            queries
                .into_iter()
                .map(|query| query.join().expect("finality query panicked"))
                .collect()
        });
        let mut answers = Vec::with_capacity(queried.len());
        for (url, finalized, latency) in queried {
            match finalized {
                Ok(c) => {
                    let root = hex::encode(c.root);
                    let epoch = c.epoch;
                    silver_log::info!(url = %url, epoch, %root, "checkpoint provider finalized");
                    answers.push((latency, url.clone(), c));
                }
                Err(e) => silver_log::warn!(url = %url, %e, "checkpoint provider unusable"),
            }
        }
        answers.sort_unstable_by_key(|(latency, ..)| *latency);

        let votes =
            |candidate: &Checkpoint| answers.iter().filter(|(.., c)| c == candidate).count();
        let Some(&(.., agreed)) = answers.iter().find(|(.., candidate)| {
            let count = votes(candidate);
            count >= quorum && 2 * count > answers.len()
        }) else {
            return Err(io::Error::other(format!(
                "no finalized checkpoint has a majority of {} provider answers",
                answers.len()
            )));
        };
        self.urls =
            answers.into_iter().filter(|(.., c)| *c == agreed).map(|(_, url, _)| url).collect();
        Ok(agreed)
    }

    /// By slot, not `finalized`: a provider finalizing again mid-boot still
    /// serves the agreed state. The block's slot, not the epoch's first: that
    /// one may be empty, and Checkpointz serves states only at block slots.
    pub fn download(&self, checkpoint: Checkpoint) -> io::Result<Vec<u8>> {
        let root = hex::encode(checkpoint.root);
        for attempt in 1..=DOWNLOAD_ATTEMPTS {
            if let Some(ssz) = self.download_once(&root) {
                return Ok(ssz);
            }
            if attempt < DOWNLOAD_ATTEMPTS {
                silver_log::info!(attempt, %root, "no provider served the checkpoint yet; retrying");
                thread::sleep(self.retry_delay);
            }
        }
        Err(io::Error::other(format!(
            "no checkpoint provider served the state of block {root} in {DOWNLOAD_ATTEMPTS} attempts"
        )))
    }

    fn download_once(&self, root: &str) -> Option<Vec<u8>> {
        for url in &self.urls {
            let started = Instant::now();
            let downloaded = self.block_slot(url, root).and_then(|slot| self.state(url, slot));
            match downloaded {
                Ok(ssz) => {
                    let bytes = ssz.len();
                    let elapsed_ms = started.elapsed().as_millis() as u64;
                    silver_log::info!(url = %url, bytes, elapsed_ms, "downloaded checkpoint state");
                    return Some(ssz);
                }
                Err(e) => {
                    silver_log::warn!(url = %url, %root, %e, "checkpoint state download failed")
                }
            }
        }
        None
    }

    /// Reads a whole block: Checkpointz serves neither `headers` nor
    /// `blinded_blocks`.
    fn block_slot(&self, url: &str, root: &str) -> io::Result<u64> {
        let body = self
            .agent
            .get(&format!("{url}/eth/v2/beacon/blocks/0x{root}"))
            .call()
            .map_err(io::Error::other)?
            .into_string()?;
        let json: Value = serde_json::from_str(&body)?;
        json["data"]["message"]["slot"]
            .as_str()
            .and_then(|slot| slot.parse().ok())
            .ok_or_else(|| io::Error::other(format!("block 0x{root} has no slot")))
    }

    fn state(&self, url: &str, slot: u64) -> io::Result<Vec<u8>> {
        let mut ssz = Vec::new();
        self.agent
            .get(&format!("{url}/eth/v2/debug/beacon/states/{slot}"))
            .set("Accept", "application/octet-stream")
            .call()
            .map_err(io::Error::other)?
            .into_reader()
            .read_to_end(&mut ssz)?;
        Ok(ssz)
    }

    /// Asks the head state: a beacon node answers `finalized` from the
    /// finalized state, whose own finalized checkpoint lags by an epoch or
    /// more.
    fn finalized(&self, url: &str) -> io::Result<Checkpoint> {
        let body = self
            .agent
            .get(&format!("{url}/eth/v1/beacon/states/head/finality_checkpoints"))
            .timeout(FINALITY_TIMEOUT)
            .call()
            .map_err(io::Error::other)?
            .into_string()?;
        let json: Value = serde_json::from_str(&body)?;
        let finalized = &json["data"]["finalized"];
        let parse = || {
            let epoch = finalized["epoch"].as_str()?.parse().ok()?;
            let mut root = [0u8; 32];
            hex::decode_to_slice(finalized["root"].as_str()?.strip_prefix("0x")?, &mut root)
                .ok()?;
            Some(Checkpoint { epoch, root })
        };
        parse().ok_or_else(|| {
            io::Error::other(format!("unexpected finality_checkpoints body: {body}"))
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{BufRead, BufReader, Write},
        net::{TcpListener, TcpStream},
    };

    use super::*;

    const ROOT: [u8; 32] = [0xab; 32];

    /// Answers 404 for the checkpoint block `misses` times, as a provider does
    /// between announcing finality and fetching the new checkpoint.
    fn provider(misses: usize) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        thread::spawn(move || {
            let mut block_requests = 0;
            for stream in listener.incoming() {
                let mut stream = stream.unwrap();
                let request_line = read_request(&stream);
                let (status, body) = if request_line.contains("/eth/v2/beacon/blocks/") {
                    block_requests += 1;
                    if block_requests <= misses {
                        ("404 Not Found", "")
                    } else {
                        ("200 OK", r#"{"data":{"message":{"slot":"7"}}}"#)
                    }
                } else if request_line.contains("/eth/v2/debug/beacon/states/7 ") {
                    ("200 OK", "ssz")
                } else {
                    ("404 Not Found", "")
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).unwrap();
            }
        });
        url
    }

    fn read_request(stream: &TcpStream) -> String {
        let mut lines = BufReader::new(stream).lines();
        let request_line = lines.next().unwrap().unwrap();
        for line in lines {
            if line.unwrap().is_empty() {
                break;
            }
        }
        request_line
    }

    fn providers(url: String) -> CheckpointProviders {
        let mut providers = CheckpointProviders::new(&[url]);
        providers.retry_delay = Duration::ZERO;
        providers
    }

    #[test]
    fn download_waits_for_a_provider_catching_up_with_finality() {
        let providers = providers(provider(2));
        let ssz = providers.download(Checkpoint { epoch: 1, root: ROOT }).unwrap();
        assert_eq!(ssz, b"ssz");
    }

    #[test]
    fn download_gives_up_on_a_provider_that_never_serves_it() {
        let providers = providers(provider(usize::MAX));
        let err = providers.download(Checkpoint { epoch: 1, root: ROOT }).unwrap_err();
        assert!(err.to_string().contains("attempts"), "{err}");
    }
}
