use std::{
    io::{self, Read},
    thread,
    time::{Duration, Instant},
};

use serde_json::Value;
use silver_beacon_state_data::{Checkpoint, SLOTS_PER_EPOCH};
use ureq::Agent;

/// Bounds each provider's answer; they are queried in parallel.
const FINALITY_TIMEOUT: Duration = Duration::from_secs(5);

pub struct CheckpointProviders {
    agent: Agent,
    urls: Vec<String>,
}

impl CheckpointProviders {
    pub fn new(urls: &[String]) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(10))
            .timeout_read(Duration::from_secs(30))
            .build();
        let urls = urls.iter().map(|url| url.trim_end_matches('/').to_owned()).collect();
        Self { agent, urls }
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
    /// serves the agreed state.
    pub fn download(&self, checkpoint: Checkpoint) -> io::Result<Vec<u8>> {
        let slot = checkpoint.epoch * SLOTS_PER_EPOCH;
        for url in &self.urls {
            let started = Instant::now();
            let mut ssz = Vec::new();
            let downloaded = self
                .agent
                .get(&format!("{url}/eth/v2/debug/beacon/states/{slot}"))
                .set("Accept", "application/octet-stream")
                .call()
                .map_err(io::Error::other)
                .and_then(|response| response.into_reader().read_to_end(&mut ssz));
            match downloaded {
                Ok(bytes) => {
                    let elapsed_ms = started.elapsed().as_millis() as u64;
                    silver_log::info!(url = %url, bytes, elapsed_ms, "downloaded checkpoint state");
                    return Ok(ssz);
                }
                Err(e) => {
                    silver_log::warn!(url = %url, slot, %e, "checkpoint state download failed")
                }
            }
        }
        Err(io::Error::other(format!("no checkpoint provider served the state at slot {slot}")))
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
