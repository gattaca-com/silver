use std::{
    fmt::Write,
    ops::Range,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use mio::{Events, Registry};
use silver_common::{BuilderBid, BuilderBidsRequest, BuilderTerms};
use silver_httpcore::{
    BufferCapacity, ClientRequest, ClientResponse, Endpoint, HttpPool, Method, TokenRange,
};
use silver_ssz::ssz_view::SignedExecutionPayloadBidView;

use crate::{CONSENSUS_VERSION, builder_config::BuilderConfig, header_fetch::write_hex};

/// `MAX_BUILDER_ENTRIES`: entries sharing a URL take a connection each.
const MAX_REQUESTS: usize = 64;
const SSZ: &str = "application/octet-stream";
/// Tags a block submission's request id; a bid request's is its round's.
const SUBMISSION: u64 = 1 << 63;

/// Bid requests to the builders a proposal names, one per `BuilderEntry`,
/// all in flight together, and the signed block to the winner. A pool per
/// builder URL outlives its requests, so the next slot's ask reuses the
/// connection.
pub struct BuilderBids {
    registry: Registry,
    tokens: TokenRange,
    timeout: Duration,
    pools: Vec<BuilderPool>,
    rounds: Vec<Round>,
    next_round: u64,
    next_submission: u64,
    path: String,
}

struct BuilderPool {
    url: Box<str>,
    pool: HttpPool,
}

/// One proposal's requests: answered once the last is.
struct Round {
    id: u64,
    request_id: u64,
    unanswered: usize,
    terms: Vec<EntryTerms>,
    pubkeys: Vec<u8>,
    bids: Vec<u8>,
}

struct EntryTerms {
    entry: u32,
    terms: BuilderTerms,
    pubkeys: Range<usize>,
}

impl BuilderBids {
    pub const MAX_SOCKETS: usize = MAX_REQUESTS;

    pub fn new(registry: &Registry, tokens: TokenRange, timeout: Duration) -> Self {
        Self {
            registry: registry.try_clone().expect("mio Registry::try_clone failed"),
            tokens,
            timeout,
            pools: Vec::new(),
            rounds: Vec::new(),
            next_round: 0,
            next_submission: 0,
            path: String::new(),
        }
    }

    /// Returns whether a request went out; `spin` then answers under
    /// `request.request_id`.
    pub fn request(&mut self, request: &BuilderBidsRequest, config: BuilderConfig<'_>) -> bool {
        let BuilderBidsRequest { request_id, slot, .. } = *request;
        let round_id = self.next_round;
        let mut round = Round {
            id: round_id,
            request_id,
            unanswered: 0,
            terms: Vec::new(),
            pubkeys: Vec::new(),
            bids: Vec::new(),
        };
        let sent_ms = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis();
        let (sent_ms, timeout_ms) = (sent_ms.to_string(), self.timeout.as_millis().to_string());
        let headers = [
            (CONSENSUS_VERSION, "gloas"),
            ("Date-Milliseconds", &sent_ms),
            ("X-Timeout-Ms", &timeout_ms),
        ];

        for (entry, builder) in config.entries().enumerate() {
            let entry = entry as u32;
            let Some(url) = str::from_utf8(builder.url()).ok().filter(|url| !url.is_empty()) else {
                silver_log::warn!(slot, entry, "builder url is not utf-8; no bid asked");
                continue;
            };
            if builder.auth_slot() != slot {
                silver_log::warn!(
                    slot,
                    entry,
                    auth_slot = builder.auth_slot(),
                    "builder auth names another slot; no bid asked"
                );
                continue;
            }
            let Some(at) = self.pool_for(url) else { continue };
            let pool = &mut self.pools[at].pool;
            if !pool.has_capacity() {
                silver_log::warn!(slot, entry, url, "builder connections all busy; no bid asked");
                continue;
            }
            write_bid_path(&mut self.path, url, request);
            let post = ClientRequest {
                method: Method::Post,
                path: &self.path,
                body: builder.auth(),
                authorization: None,
                accept: Some(SSZ),
                content_type: Some(SSZ),
                headers: &headers,
            };
            pool.enqueue(round_id << 8 | u64::from(entry), &post, &self.registry);

            let start = round.pubkeys.len();
            builder.builder_pubkeys().for_each(|key| round.pubkeys.extend_from_slice(key));
            round.terms.push(EntryTerms {
                entry,
                terms: BuilderTerms {
                    min_bid: builder.min_bid(),
                    builder_boost_factor: builder.builder_boost_factor(),
                    max_execution_payment: builder.max_execution_payment(),
                },
                pubkeys: start..round.pubkeys.len(),
            });
            round.unanswered += 1;
        }
        if round.unanswered == 0 {
            return false;
        }
        self.next_round += 1;
        self.rounds.push(round);
        true
    }

    /// `submitSignedBeaconBlock`: the builder learns its bid won without
    /// waiting for gossip. Its answer is only logged.
    pub fn submit_block(&mut self, url: &str, signed_block: &[u8]) {
        let Some(at) = self.pool_for(url) else { return };
        let pool = &mut self.pools[at].pool;
        if !pool.has_capacity() {
            silver_log::warn!(url, "builder connections all busy; block not forwarded");
            return;
        }
        write_base_path(&mut self.path, url);
        self.path.push_str("/eth/v1/builder/beacon_blocks");
        let post = ClientRequest {
            method: Method::Post,
            path: &self.path,
            body: signed_block,
            authorization: None,
            accept: None,
            content_type: Some(SSZ),
            headers: &[(CONSENSUS_VERSION, "gloas")],
        };
        pool.enqueue(SUBMISSION | self.next_submission, &post, &self.registry);
        self.next_submission += 1;
    }

    /// `on_answered` gets each finished round's request id and its framed
    /// [`BuilderBid`]s.
    pub fn spin(&mut self, events: &Events, on_answered: &mut impl FnMut(u64, &[u8])) {
        let Self { registry, pools, rounds, .. } = self;
        for BuilderPool { url, pool } in pools {
            pool.dispatch_events(events, registry, &mut |id, response| {
                if id & SUBMISSION != 0 {
                    return log_submission(url, response);
                }
                let (round_id, entry) = (id >> 8, (id & 0xff) as u32);
                let Some(at) = rounds.iter().position(|round| round.id == round_id) else {
                    return;
                };
                let round = &mut rounds[at];
                if let Some(signed_bid) = accepted_bid(url, entry, response) {
                    let terms =
                        round.terms.iter().find(|terms| terms.entry == entry).expect("asked");
                    BuilderBid {
                        entry,
                        terms: terms.terms,
                        builder_pubkeys: &round.pubkeys[terms.pubkeys.clone()],
                        signed_bid,
                    }
                    .write(&mut round.bids);
                }
                round.unanswered -= 1;
                if round.unanswered == 0 {
                    let round = rounds.swap_remove(at);
                    on_answered(round.request_id, &round.bids);
                }
            });
        }
    }

    fn pool_for(&mut self, url: &str) -> Option<usize> {
        if !url.starts_with("http://") {
            silver_log::warn!(url, "only http:// builder urls are served; no bid asked");
            return None;
        }
        if let Some(at) = self.pools.iter().position(|pool| *pool.url == *url) {
            return Some(at);
        }
        let at = if self.pools.len() < MAX_REQUESTS {
            self.pools.len()
        } else {
            let Some(at) = self.pools.iter().position(|pool| pool.pool.is_idle()) else {
                silver_log::warn!(url, "too many builder urls; no bid asked");
                return None;
            };
            at
        };
        let tokens = self.tokens.share_of(at, MAX_REQUESTS);
        let capacity = BufferCapacity { read: 16 << 10, write: 8 << 10 };
        let pool = HttpPool::new(
            Endpoint::Http(url.to_owned()),
            tokens,
            capacity,
            MAX_REQUESTS,
            self.timeout,
        );
        let builder = BuilderPool { url: url.into(), pool };
        if at == self.pools.len() {
            self.pools.push(builder);
        } else {
            self.pools[at] = builder;
        }
        Some(at)
    }
}

/// `url`'s own path, if any, which the builder API's paths follow.
fn write_base_path(path: &mut String, url: &str) {
    path.clear();
    let base = url.trim_start_matches("http://").split_once('/').map_or("", |(_, base)| base);
    let base = base.trim_end_matches('/');
    if !base.is_empty() {
        path.push('/');
        path.push_str(base);
    }
}

fn write_bid_path(path: &mut String, url: &str, request: &BuilderBidsRequest) {
    let BuilderBidsRequest { slot, parent_hash, parent_root, proposer_pubkey, .. } = request;
    write_base_path(path, url);
    write!(path, "/eth/v1/builder/execution_payload_bid/{slot}/").unwrap();
    write_hex(path, parent_hash);
    path.push('/');
    write_hex(path, parent_root);
    path.push('/');
    write_hex(path, proposer_pubkey);
}

/// A 202 is the only acceptance.
fn log_submission(url: &str, response: Result<ClientResponse<'_>, &str>) {
    match response {
        Ok(response) if response.status == 202 => {
            silver_log::info!(url, "builder accepted the signed block")
        }
        Ok(response) => {
            silver_log::warn!(url, status = response.status, "builder refused the signed block")
        }
        Err(error) => silver_log::warn!(url, error, "signed block did not reach builder"),
    }
}

/// The SSZ bid of a 200, framed; a 204 or a refusal is no bid.
fn accepted_bid<'a>(
    url: &str,
    entry: u32,
    response: Result<ClientResponse<'a>, &str>,
) -> Option<&'a [u8]> {
    match response {
        Ok(response) if response.status == 200 => {
            let body: &[u8] = response.body;
            if SignedExecutionPayloadBidView::check_size(body) {
                return Some(body);
            }
            silver_log::warn!(
                url,
                entry,
                len = body.len(),
                "builder bid is not an ssz SignedExecutionPayloadBid"
            );
        }
        Ok(response) if response.status == 204 => {
            silver_log::debug!(url, entry, "builder has no bid");
        }
        Ok(response) => {
            silver_log::warn!(url, entry, status = response.status, "builder refused bid request");
        }
        Err(error) => silver_log::warn!(url, entry, error, "bid request did not reach builder"),
    }
    None
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        sync::mpsc,
        thread,
        time::Instant,
    };

    use silver_httpcore::Readiness;
    use silver_ssz::ssz_view::SIGNED_EXECUTION_PAYLOAD_BID_MIN;

    use super::*;
    use crate::builder_config::tests::{Entry, config};

    const SLOT: u64 = 9;

    fn request() -> BuilderBidsRequest {
        BuilderBidsRequest {
            request_id: 77,
            slot: SLOT,
            parent_hash: [0x11; 32],
            parent_root: [0x22; 32],
            proposer_pubkey: [0x33; 48],
        }
    }

    fn signed_bid() -> Vec<u8> {
        let mut bid = vec![0x44; SIGNED_EXECUTION_PAYLOAD_BID_MIN];
        bid[..4].copy_from_slice(&100u32.to_le_bytes());
        bid
    }

    /// Answers each request on its own connection: a bid under `/relay`,
    /// no bid elsewhere. Requests go back as received; `silent` answers none.
    fn builder(silent: bool) -> (String, mpsc::Receiver<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let (sent, received) = mpsc::channel();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let sent = sent.clone();
                thread::spawn(move || serve(stream.unwrap(), silent, &sent));
            }
        });
        (url, received)
    }

    fn serve(mut stream: TcpStream, silent: bool, sent: &mpsc::Sender<Vec<u8>>) {
        let mut request = Vec::new();
        let mut buf = [0; 4096];
        loop {
            let Ok(n @ 1..) = stream.read(&mut buf) else { return };
            request.extend_from_slice(&buf[..n]);
            let Some(head) = request.windows(4).position(|w| w == b"\r\n\r\n") else { continue };
            let head_text = String::from_utf8_lossy(&request[..head]).to_lowercase();
            let len = head_text
                .lines()
                .find_map(|line| line.strip_prefix("content-length: "))
                .map_or(0, |len| len.parse().unwrap());
            if request.len() < head + 4 + len {
                continue;
            }
            let answer = request.starts_with(b"POST /relay/");
            sent.send(std::mem::take(&mut request)).unwrap();
            if silent {
                continue;
            }
            if answer {
                let bid = signed_bid();
                let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", bid.len());
                stream.write_all(&[head.as_bytes(), &bid].concat()).unwrap();
            } else {
                stream.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n").unwrap();
            }
        }
    }

    fn entry(url: &str, terms: [u64; 3]) -> Vec<u8> {
        Entry { url: url.as_bytes(), data: b"auth", slot: SLOT, pubkeys: &[[5; 48]], terms }.ssz()
    }

    /// Spins until the round is answered.
    fn answered(bids: &mut BuilderBids, readiness: &mut Readiness) -> (u64, Vec<u8>) {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut answer = None;
        while answer.is_none() {
            assert!(Instant::now() < deadline, "no answer");
            readiness.wait(Duration::from_millis(5));
            bids.spin(readiness.events(), &mut |id, frame| answer = Some((id, frame.to_vec())));
        }
        answer.unwrap()
    }

    #[test]
    fn every_entry_is_asked_and_only_bids_are_framed() {
        let (url, received) = builder(false);
        let relay = format!("{url}/relay/");
        let body = config(0, 100, &[entry(&url, [1, 2, 3]), entry(&relay, [4, 5, 6])]);
        let builder_config = BuilderConfig::parse(&body).unwrap();
        let mut readiness = Readiness::new(64);
        let mut bids =
            BuilderBids::new(readiness.registry(), TokenRange::whole(), Duration::from_secs(2));

        assert!(bids.request(&request(), builder_config));
        let (request_id, frame) = answered(&mut bids, &mut readiness);
        assert_eq!(request_id, 77);
        let framed: Vec<_> = BuilderBid::iter(&frame).collect();
        let terms = BuilderTerms { min_bid: 5, builder_boost_factor: 6, max_execution_payment: 4 };
        assert_eq!(framed, [BuilderBid {
            entry: 1,
            terms,
            builder_pubkeys: &[5; 48],
            signed_bid: &signed_bid()
        }]);

        let mut requests: Vec<_> = (0..2).map(|_| received.recv().unwrap()).collect();
        requests.sort();
        let path = format!(
            "/eth/v1/builder/execution_payload_bid/{SLOT}/0x{}/0x{}/0x{}",
            "11".repeat(32),
            "22".repeat(32),
            "33".repeat(48)
        );
        let auth = builder_config.entries().next().unwrap().auth();
        for (request, prefix) in requests.iter().zip(["", "/relay"]) {
            let text = String::from_utf8_lossy(request);
            assert!(text.starts_with(&format!("POST {prefix}{path} HTTP/1.1\r\n")), "{text}");
            for header in [
                "Eth-Consensus-Version: gloas",
                "X-Timeout-Ms: 2000",
                "Content-Type: application/octet-stream",
                "Accept: application/octet-stream",
                "Date-Milliseconds: ",
            ] {
                assert!(text.contains(header), "{header} in {text}");
            }
            assert!(request.ends_with(auth), "the auth is forwarded as sent");
        }
    }

    #[test]
    fn a_silent_builder_is_no_bid_once_the_timeout_lapses() {
        let (url, _received) = builder(true);
        let body = config(0, 100, &[entry(&url, [0, 0, 100])]);
        let mut readiness = Readiness::new(64);
        let timeout = Duration::from_millis(50);
        let mut bids = BuilderBids::new(readiness.registry(), TokenRange::whole(), timeout);

        let asked = Instant::now();
        assert!(bids.request(&request(), BuilderConfig::parse(&body).unwrap()));
        assert_eq!(answered(&mut bids, &mut readiness), (77, Vec::new()));
        assert!(asked.elapsed() >= timeout);
    }

    #[test]
    fn completed_pools_are_reused_for_new_builder_urls() {
        let (url, _received) = builder(false);
        let mut readiness = Readiness::new(64);
        let mut bids =
            BuilderBids::new(readiness.registry(), TokenRange::whole(), Duration::from_secs(2));

        for index in 0..MAX_REQUESTS + 2 {
            let body = config(0, 100, &[entry(&format!("{url}/relay/{index}"), [0, 0, 100])]);
            assert!(bids.request(&request(), BuilderConfig::parse(&body).unwrap()), "{index}");
            let (id, frame) = answered(&mut bids, &mut readiness);
            assert_eq!(id, 77);
            assert_eq!(BuilderBid::iter(&frame).count(), 1);
            assert!(bids.pools.len() <= MAX_REQUESTS);
        }
    }

    #[test]
    fn busy_pools_survive_until_all_requests_time_out() {
        let (url, _received) = builder(true);
        let mut readiness = Readiness::new(64);
        let mut bids =
            BuilderBids::new(readiness.registry(), TokenRange::whole(), Duration::from_millis(50));
        let mut request = request();
        for index in 0..MAX_REQUESTS {
            request.request_id = index as u64;
            let body = config(0, 100, &[entry(&format!("{url}/{index}"), [0, 0, 100])]);
            assert!(bids.request(&request, BuilderConfig::parse(&body).unwrap()));
        }
        let body = config(0, 100, &[entry(&format!("{url}/new"), [0, 0, 100])]);
        assert!(!bids.request(&request, BuilderConfig::parse(&body).unwrap()));

        let deadline = Instant::now() + Duration::from_secs(5);
        let mut answered = Vec::new();
        while !bids.rounds.is_empty() {
            assert!(Instant::now() < deadline, "requests did not time out");
            readiness.wait(Duration::from_millis(5));
            bids.spin(readiness.events(), &mut |id, frame| {
                assert!(frame.is_empty());
                answered.push(id);
            });
        }
        answered.sort_unstable();
        assert_eq!(answered, (0..MAX_REQUESTS as u64).collect::<Vec<_>>());
        assert!(bids.request(&request, BuilderConfig::parse(&body).unwrap()));
        assert_eq!(bids.pools.len(), MAX_REQUESTS);
    }

    #[test]
    fn signed_block_is_posted_as_ssz_under_the_url_s_path() {
        let (url, received) = builder(false);
        let mut readiness = Readiness::new(64);
        let mut bids =
            BuilderBids::new(readiness.registry(), TokenRange::whole(), Duration::from_secs(2));
        bids.submit_block(&format!("{url}/relay"), b"signed block");

        let deadline = Instant::now() + Duration::from_secs(5);
        let request = loop {
            assert!(Instant::now() < deadline, "no submission");
            readiness.wait(Duration::from_millis(5));
            bids.spin(readiness.events(), &mut |_, _| panic!("no bid round was asked"));
            if let Ok(request) = received.try_recv() {
                break request;
            }
        };
        let text = String::from_utf8_lossy(&request);
        assert!(
            text.starts_with("POST /relay/eth/v1/builder/beacon_blocks HTTP/1.1\r\n"),
            "{text}"
        );
        assert!(text.contains("Eth-Consensus-Version: gloas"), "{text}");
        assert!(text.contains("Content-Type: application/octet-stream"), "{text}");
        assert!(request.ends_with(b"signed block"));
        for _ in 0..10 {
            readiness.wait(Duration::from_millis(5));
            bids.spin(readiness.events(), &mut |_, _| panic!("no bid round was asked"));
        }
    }

    #[test]
    fn entries_that_cannot_be_asked_are_skipped() {
        let other_slot = Entry {
            url: b"http://127.0.0.1:1",
            data: b"auth",
            slot: SLOT + 1,
            pubkeys: &[],
            terms: [0; 3],
        }
        .ssz();
        let body = config(0, 100, &[entry("https://builder", [0; 3]), other_slot]);
        let readiness = Readiness::new(64);
        let mut bids =
            BuilderBids::new(readiness.registry(), TokenRange::whole(), Duration::from_secs(1));
        assert!(!bids.request(&request(), BuilderConfig::parse(&body).unwrap()));
    }
}
