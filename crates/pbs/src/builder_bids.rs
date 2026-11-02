use std::{
    borrow::Cow,
    fmt::{self, Write},
    mem,
    ops::Range,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use mio::{Events, Registry};
use serde::Deserialize;
use silver_common::{BuilderBid, BuilderBidsRequest, BuilderTerms};
use silver_httpcore::{ClientRequest, ClientResponse, Method, TokenRange};
use silver_ssz::ssz_view::SignedExecutionPayloadBidView;

use crate::{
    CONSENSUS_VERSION,
    builder_config::{BuilderConfig, MAX_BUILDER_ENTRIES, plain_http_url},
    builder_pools::{BuilderCall, BuilderPools, MAX_REQUESTS},
    builder_preferences::{
        BuilderPreferencesEntry, MAX_PREFERENCES, PreferenceFailures, PreferencesBody,
    },
    header_fetch::write_hex,
    json_payload_bid::JsonPayloadBid,
};

const SSZ: &str = "application/octet-stream";
const SSZ_OR_JSON: &str = "application/octet-stream;q=1.0,application/json;q=0.9";
/// A round's request ids end in the entry's index.
const INDEX_BITS: u32 = MAX_PREFERENCES.ilog2();
const _: () = assert!(MAX_PREFERENCES.is_power_of_two() && MAX_BUILDER_ENTRIES <= MAX_PREFERENCES);

pub enum BuilderEvent<'a> {
    /// A finished bid round's framed [`BuilderBid`]s.
    Bids { request_id: u64, bids: &'a [u8] },
    /// The entries a `builder_preferences` round could not submit.
    Preferences { request_id: u64, failures: PreferenceFailures<'a> },
}

/// Rounds of requests to the builders a VC names, one per entry, all in
/// flight together: bids for a proposal, and preferences ahead of one. Plus
/// the signed block to the bid's winner.
pub struct BuilderBids {
    registry: Registry,
    pools: BuilderPools,
    bid_rounds: Rounds<BidEntries>,
    preference_rounds: Rounds<PreferenceEntries>,
    next_submission: u64,
    /// The bid requests' `X-Timeout-Ms`.
    timeout_ms: String,
    buffers: RequestBuffers,
    json_entry: Vec<u8>,
    json_bid: JsonPayloadBid,
}

/// Finished rounds stay as spares, whose buffers the next ones reuse.
#[derive(Default)]
struct Rounds<E> {
    live: Vec<Round<E>>,
    spare: Vec<Round<E>>,
    next_id: u64,
}

/// One request's entries: answered once the last is.
#[derive(Default)]
struct Round<E> {
    id: u64,
    request_id: u64,
    unanswered: usize,
    entries: E,
    /// Framed [`BuilderBid`]s, or framed [`PreferenceFailures`].
    out: Vec<u8>,
}

trait RoundEntries: Default {
    fn clear(&mut self);
}

/// Each entry's terms and accepted builders.
#[derive(Default)]
struct BidEntries {
    terms: Vec<EntryTerms>,
    pubkeys: Vec<u8>,
}

/// Each entry's SSZ, to send again as JSON to a builder that refuses SSZ.
#[derive(Default)]
struct PreferenceEntries {
    bytes: Vec<u8>,
    starts: Vec<usize>,
    json_resends: Vec<usize>,
}

struct EntryTerms {
    entry: u32,
    terms: BuilderTerms,
    pubkeys: Range<usize>,
}

/// The path and bodies each request is framed from.
#[derive(Default)]
struct RequestBuffers {
    path: String,
    date_ms: String,
    ssz: Vec<u8>,
    json: String,
}

impl BuilderBids {
    pub const MAX_SOCKETS: usize = MAX_REQUESTS;

    pub fn new(registry: &Registry, tokens: TokenRange, bid_timeout: Duration) -> Self {
        Self {
            registry: registry.try_clone().expect("mio Registry::try_clone failed"),
            pools: BuilderPools::new(tokens, bid_timeout),
            bid_rounds: Rounds::default(),
            preference_rounds: Rounds::default(),
            next_submission: 0,
            timeout_ms: bid_timeout.as_millis().to_string(),
            buffers: RequestBuffers::default(),
            json_entry: Vec::new(),
            json_bid: JsonPayloadBid::new(),
        }
    }

    /// `spin` answers under `request.request_id`, with no bid when no entry
    /// could be asked.
    pub fn request(&mut self, request: &BuilderBidsRequest, config: BuilderConfig<'_>) {
        let BuilderBidsRequest { request_id, slot, .. } = *request;
        let mut round = self.bid_rounds.start(request_id);
        let sent_ms = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis();
        let RequestBuffers { path, date_ms, .. } = &mut self.buffers;
        date_ms.clear();
        write!(date_ms, "{sent_ms}").unwrap();
        let headers = [
            (CONSENSUS_VERSION, "gloas"),
            ("Date-Milliseconds", date_ms.as_str()),
            ("X-Timeout-Ms", &self.timeout_ms),
        ];

        for (entry, builder) in config.entries().enumerate() {
            let Some(url) = plain_http_url(builder.url()) else {
                silver_log::warn!(
                    slot,
                    entry,
                    "builder url is not a plain http(s) url; no bid asked"
                );
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
            write_bid_path(path, url, request);
            let post = ClientRequest {
                method: Method::Post,
                path,
                body: builder.auth(),
                authorization: None,
                accept: Some(SSZ_OR_JSON),
                content_type: Some(SSZ),
                headers: &headers,
            };
            let id = round.entry_id(entry);
            if let Err(unavailable) =
                self.pools.enqueue(url, BuilderCall::Bid, id, &post, &self.registry)
            {
                let reason = unavailable.reason();
                silver_log::warn!(slot, entry, url, reason, "no bid asked");
                continue;
            }

            let BidEntries { terms, pubkeys } = &mut round.entries;
            let start = pubkeys.len();
            builder.builder_pubkeys().for_each(|key| pubkeys.extend_from_slice(key));
            terms.push(EntryTerms {
                entry: entry as u32,
                terms: BuilderTerms {
                    min_bid: builder.min_bid(),
                    builder_boost_factor: builder.builder_boost_factor(),
                    max_execution_payment: builder.max_execution_payment(),
                },
                pubkeys: start..pubkeys.len(),
            });
            round.unanswered += 1;
        }
        self.bid_rounds.live.push(round);
    }

    /// `submitBuilderPreferences` for each entry, as SSZ, and again as JSON
    /// to a builder that refuses SSZ. `spin` answers under `request_id` once
    /// every builder has; an entry whose builder has no connection to spare
    /// fails, for the VC to send again.
    pub fn submit_preferences(&mut self, request_id: u64, body: PreferencesBody<'_>) {
        let mut round = self.preference_rounds.start(request_id);
        let Self { registry, pools, buffers, json_entry, .. } = self;
        body.for_each_entry(json_entry, |index, entry| {
            round.entries.push(entry);
            let id = round.entry_id(index);
            match buffers.send_preferences(pools, registry, BuilderCall::Preferences, id, entry) {
                Ok(()) => round.unanswered += 1,
                Err(reason) => round.fail(index, format_args!("{reason}")),
            }
        });
        self.preference_rounds.live.push(round);
    }

    /// `submitSignedBeaconBlock`: the builder learns its bid won without
    /// waiting for gossip. Its answer is only logged.
    pub fn submit_block(&mut self, url: &str, signed_block: &[u8]) {
        let path = &mut self.buffers.path;
        write_base_path(path, url);
        path.push_str("/eth/v1/builder/beacon_blocks");
        let post = ClientRequest {
            method: Method::Post,
            path,
            body: signed_block,
            authorization: None,
            accept: None,
            content_type: Some(SSZ),
            headers: &[(CONSENSUS_VERSION, "gloas")],
        };
        let id = self.next_submission;
        if let Err(unavailable) =
            self.pools.enqueue(url, BuilderCall::Block, id, &post, &self.registry)
        {
            return silver_log::warn!(url, reason = unavailable.reason(), "block not forwarded");
        }
        self.next_submission += 1;
    }

    pub fn spin(&mut self, events: &Events, on_event: &mut impl FnMut(BuilderEvent<'_>)) {
        let Self { registry, pools, bid_rounds, preference_rounds, buffers, json_bid, .. } = self;
        pools.dispatch_events(events, registry, &mut |url, call, id, response| match call {
            BuilderCall::Block => log_submission(url, response),
            BuilderCall::Bid => {
                if let Some((round, entry)) = bid_rounds.answered(id) {
                    round.record_bid(url, entry as u32, response, json_bid);
                }
            }
            BuilderCall::Preferences | BuilderCall::PreferencesJson => {
                if let Some((round, index)) = preference_rounds.answered(id) {
                    round.record_preferences(url, call, index, response);
                }
            }
        });
        for round in &mut preference_rounds.live {
            round.resend_as_json(buffers, pools, registry);
        }

        bid_rounds.finish(|round| {
            on_event(BuilderEvent::Bids { request_id: round.request_id, bids: &round.out })
        });
        preference_rounds.finish(|round| {
            let failures = PreferenceFailures::new(&round.out);
            on_event(BuilderEvent::Preferences { request_id: round.request_id, failures })
        });
    }
}

impl<E: RoundEntries> Rounds<E> {
    fn start(&mut self, request_id: u64) -> Round<E> {
        let mut round = self.spare.pop().unwrap_or_default();
        round.entries.clear();
        round.out.clear();
        let round = Round { id: self.next_id, request_id, unanswered: 0, ..round };
        self.next_id += 1;
        round
    }

    /// The round and entry index an answer's id names.
    fn answered(&mut self, id: u64) -> Option<(&mut Round<E>, usize)> {
        let (round_id, index) = (id >> INDEX_BITS, (id & ((1 << INDEX_BITS) - 1)) as usize);
        let round = self.live.iter_mut().find(|round| round.id == round_id)?;
        Some((round, index))
    }

    fn finish(&mut self, mut each: impl FnMut(&Round<E>)) {
        let Self { live, spare, .. } = self;
        for round in live.extract_if(.., |round| round.unanswered == 0) {
            each(&round);
            spare.push(round);
        }
    }
}

impl<E> Round<E> {
    fn entry_id(&self, index: usize) -> u64 {
        self.id << INDEX_BITS | index as u64
    }
}

impl RoundEntries for BidEntries {
    fn clear(&mut self) {
        self.terms.clear();
        self.pubkeys.clear();
    }
}

impl RoundEntries for PreferenceEntries {
    fn clear(&mut self) {
        self.bytes.clear();
        self.starts.clear();
        self.json_resends.clear();
    }
}

impl PreferenceEntries {
    fn push(&mut self, entry: BuilderPreferencesEntry<'_>) {
        self.starts.push(self.bytes.len());
        self.bytes.extend_from_slice(entry.bytes());
    }

    fn entry(&self, index: usize) -> BuilderPreferencesEntry<'_> {
        let end = self.starts.get(index + 1).copied().unwrap_or(self.bytes.len());
        BuilderPreferencesEntry::parse(&self.bytes[self.starts[index]..end])
            .expect("parsed when sent")
    }
}

impl RequestBuffers {
    /// SSZ under [`BuilderCall::Preferences`], JSON under
    /// [`BuilderCall::PreferencesJson`].
    fn send_preferences(
        &mut self,
        pools: &mut BuilderPools,
        registry: &Registry,
        call: BuilderCall,
        id: u64,
        entry: BuilderPreferencesEntry<'_>,
    ) -> Result<(), &'static str> {
        let url = plain_http_url(entry.url()).ok_or("url is not a plain http(s) url")?;
        write_base_path(&mut self.path, url);
        self.path.push_str("/eth/v1/builder/builder_preferences/");
        write_hex(&mut self.path, entry.proposer_pubkey());
        let (body, content_type) = if call == BuilderCall::Preferences {
            entry.write_request(&mut self.ssz);
            (&self.ssz[..], SSZ)
        } else {
            entry.write_request_json(&mut self.json);
            (self.json.as_bytes(), "application/json")
        };
        let post = ClientRequest {
            method: Method::Post,
            path: &self.path,
            body,
            authorization: None,
            accept: None,
            content_type: Some(content_type),
            headers: &[(CONSENSUS_VERSION, "gloas")],
        };
        pools.enqueue(url, call, id, &post, registry).map_err(|unavailable| unavailable.reason())
    }
}

impl Round<BidEntries> {
    fn record_bid(
        &mut self,
        url: &str,
        entry: u32,
        response: Result<ClientResponse<'_>, &str>,
        json_bid: &mut JsonPayloadBid,
    ) {
        self.unanswered -= 1;
        let Some(signed_bid) = accepted_bid(url, entry, response, json_bid) else { return };
        let BidEntries { terms, pubkeys } = &self.entries;
        let terms = terms.iter().find(|terms| terms.entry == entry).expect("asked");
        BuilderBid {
            entry,
            terms: terms.terms,
            builder_pubkeys: &pubkeys[terms.pubkeys.clone()],
            signed_bid,
        }
        .write(&mut self.out);
    }
}

impl Round<PreferenceEntries> {
    fn fail(&mut self, index: usize, message: fmt::Arguments<'_>) {
        PreferenceFailures::write(&mut self.out, index, message);
    }

    /// A 202 is the only acceptance. A 415 or 406 to SSZ holds the entry for
    /// [`Self::resend_as_json`].
    fn record_preferences(
        &mut self,
        url: &str,
        call: BuilderCall,
        index: usize,
        response: Result<ClientResponse<'_>, &str>,
    ) {
        #[derive(Deserialize)]
        struct ErrorMessage<'a> {
            #[serde(borrow)]
            message: Cow<'a, str>,
        }

        if call == BuilderCall::Preferences &&
            let Ok(response) = &response &&
            matches!(response.status, 406 | 415)
        {
            silver_log::info!(url, "builder refused ssz preferences; sending json");
            return self.entries.json_resends.push(index);
        }
        self.unanswered -= 1;
        let response = match response {
            Ok(response) if response.status == 202 => {
                return silver_log::debug!(url, "builder accepted preferences");
            }
            Ok(response) => response,
            Err(error) => {
                silver_log::warn!(url, error, "preferences did not reach builder");
                return self.fail(index, format_args!("builder unreachable: {error}"));
            }
        };
        let status = response.status;
        silver_log::warn!(url, status, "builder refused preferences");
        match serde_json::from_slice::<ErrorMessage<'_>>(response.body) {
            Ok(error) => self.fail(index, format_args!("{}", error.message)),
            Err(_) => self.fail(index, format_args!("builder answered {status}")),
        }
    }

    fn resend_as_json(
        &mut self,
        buffers: &mut RequestBuffers,
        pools: &mut BuilderPools,
        registry: &Registry,
    ) {
        let mut resends = mem::take(&mut self.entries.json_resends);
        for index in resends.drain(..) {
            let (id, entry) = (self.entry_id(index), self.entries.entry(index));
            let call = BuilderCall::PreferencesJson;
            if let Err(reason) = buffers.send_preferences(pools, registry, call, id, entry) {
                self.unanswered -= 1;
                self.fail(index, format_args!("{reason}"));
            }
        }
        self.entries.json_resends = resends;
    }
}

/// `url`'s own path, if any, which the builder API's paths follow.
fn write_base_path(path: &mut String, url: &str) {
    path.clear();
    let authority = url.split_once("://").map_or(url, |(_, authority)| authority);
    let base = authority.split_once('/').map_or("", |(_, base)| base);
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

/// The bid of a 200 as SSZ; a 204 or a refusal is no bid.
fn accepted_bid<'a>(
    url: &str,
    entry: u32,
    response: Result<ClientResponse<'a>, &str>,
    json_bid: &'a mut JsonPayloadBid,
) -> Option<&'a [u8]> {
    match response {
        Ok(response) if response.status == 200 => {
            let body = json_bid.ssz_bid(response);
            if SignedExecutionPayloadBidView::check_size(body) {
                return Some(body);
            }
            silver_log::warn!(
                url,
                entry,
                len = body.len(),
                "builder bid is not a SignedExecutionPayloadBid"
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
    use crate::{
        builder_config::tests::{Entry, auth_ssz, config},
        builder_pools::PREFERENCE_CONNECTIONS,
        builder_preferences::tests::{entry as preferences_entry, list},
        json_payload_bid::tests::{bid_json, hex_of},
    };

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

    /// Answers each request on its own connection: a bid under `/relay`, a
    /// JSON bid under `/json`, preferences accepted under `/prefs`, refused
    /// under `/refuse`, accepted only as JSON under `/json_only`, no bid
    /// elsewhere. Requests go back as received;
    /// `silent` answers none.
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
            let answer_json = request.starts_with(b"POST /json/");
            let is_json = head_text.contains("content-type: application/json");
            let json_only = request.starts_with(b"POST /json_only/");
            let accept_preferences = request.starts_with(b"POST /prefs/") || (json_only && is_json);
            let refuse_preferences = request.starts_with(b"POST /refuse/");
            sent.send(std::mem::take(&mut request)).unwrap();
            if silent {
                continue;
            }
            if json_only && !is_json {
                stream
                    .write_all(b"HTTP/1.1 415 Unsupported Media Type\r\nContent-Length: 0\r\n\r\n")
                    .unwrap();
            } else if accept_preferences {
                stream.write_all(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n").unwrap();
            } else if refuse_preferences {
                let error = r#"{"code":400,"message":"slot \"9\" has already passed"}"#;
                let head =
                    format!("HTTP/1.1 400 Bad Request\r\nContent-Length: {}\r\n\r\n", error.len());
                stream.write_all(&[head.as_bytes(), error.as_bytes()].concat()).unwrap();
            } else if answer_json {
                let bid = bid_json(&[hex_of(0xc0, 48)]);
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                    bid.len()
                );
                stream.write_all(&[head.as_bytes(), bid.as_bytes()].concat()).unwrap();
            } else if answer {
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
            bids.spin(readiness.events(), &mut |event| {
                let BuilderEvent::Bids { request_id, bids } = event else { panic!("bids only") };
                answer = Some((request_id, bids.to_vec()));
            });
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

        bids.request(&request(), builder_config);
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
    fn json_bids_are_framed_as_ssz() {
        let (url, _received) = builder(false);
        let body = config(0, 100, &[entry(&format!("{url}/json"), [0, 0, 100])]);
        let mut readiness = Readiness::new(64);
        let mut bids =
            BuilderBids::new(readiness.registry(), TokenRange::whole(), Duration::from_secs(2));

        bids.request(&request(), BuilderConfig::parse(&body).unwrap());
        let (_, frame) = answered(&mut bids, &mut readiness);
        let mut json_bid = JsonPayloadBid::new();
        let expected = json_bid.reencode(bid_json(&[hex_of(0xc0, 48)]).as_bytes()).unwrap();
        let [framed] = BuilderBid::iter(&frame).collect::<Vec<_>>()[..] else {
            panic!("one bid framed");
        };
        assert_eq!(framed.signed_bid, expected);
    }

    #[test]
    fn a_silent_builder_is_no_bid_once_the_timeout_lapses() {
        let (url, _received) = builder(true);
        let body = config(0, 100, &[entry(&url, [0, 0, 100])]);
        let mut readiness = Readiness::new(64);
        let timeout = Duration::from_millis(50);
        let mut bids = BuilderBids::new(readiness.registry(), TokenRange::whole(), timeout);

        let asked = Instant::now();
        bids.request(&request(), BuilderConfig::parse(&body).unwrap());
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
            bids.request(&request(), BuilderConfig::parse(&body).unwrap());
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
            bids.request(&request, BuilderConfig::parse(&body).unwrap());
        }
        let body = config(0, 100, &[entry(&format!("{url}/new"), [0, 0, 100])]);
        request.request_id = 999;
        bids.request(&request, BuilderConfig::parse(&body).unwrap());
        assert_eq!(
            bids.bid_rounds.live.last().unwrap().unanswered,
            0,
            "no pool is free for a new url"
        );

        let deadline = Instant::now() + Duration::from_secs(5);
        let mut answered = Vec::new();
        while !bids.bid_rounds.live.is_empty() {
            assert!(Instant::now() < deadline, "requests did not time out");
            readiness.wait(Duration::from_millis(5));
            bids.spin(readiness.events(), &mut |event| {
                let BuilderEvent::Bids { request_id, bids } = event else { panic!("bids only") };
                assert!(bids.is_empty());
                answered.push(request_id);
            });
        }
        answered.sort_unstable();
        let expected: Vec<_> = (0..MAX_REQUESTS as u64).chain([999]).collect();
        assert_eq!(answered, expected);
        bids.request(&request, BuilderConfig::parse(&body).unwrap());
        assert_eq!(
            bids.bid_rounds.live.last().unwrap().unanswered,
            1,
            "an idle pool is handed over"
        );
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
            bids.spin(readiness.events(), &mut |_| panic!("no bid round was asked"));
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
            bids.spin(readiness.events(), &mut |_| panic!("no bid round was asked"));
        }
    }

    /// Spins until the preferences request is answered.
    fn preference_failures(
        bids: &mut BuilderBids,
        readiness: &mut Readiness,
    ) -> (u64, Vec<(usize, String)>) {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut answer = None;
        while answer.is_none() {
            assert!(Instant::now() < deadline, "no answer");
            readiness.wait(Duration::from_millis(5));
            bids.spin(readiness.events(), &mut |event| {
                let BuilderEvent::Preferences { request_id, failures } = event else {
                    panic!("preferences only")
                };
                let failures = failures.iter().map(|(index, message)| (index, message.to_owned()));
                answer = Some((request_id, failures.collect()));
            });
        }
        answer.unwrap()
    }

    #[test]
    fn preferences_go_to_each_entry_s_builder_and_refusals_are_indexed() {
        let (url, received) = builder(false);
        let body = list(&[
            preferences_entry(1, &format!("{url}/prefs"), 7),
            preferences_entry(2, &format!("{url}/refuse"), 0),
            preferences_entry(3, "", 0),
            preferences_entry(4, "ftp://builder", 0),
        ]);
        let mut readiness = Readiness::new(64);
        let mut bids =
            BuilderBids::new(readiness.registry(), TokenRange::whole(), Duration::from_secs(2));

        bids.submit_preferences(55, PreferencesBody::parse(&body, false).unwrap());
        let (request_id, failures) = preference_failures(&mut bids, &mut readiness);
        assert_eq!(request_id, 55);
        let mut messages: Vec<_> =
            failures.iter().map(|(index, message)| (*index, message.as_str())).collect();
        messages.sort_unstable();
        assert_eq!(messages, [
            (1, r#"slot "9" has already passed"#),
            (2, "url is not a plain http(s) url"),
            (3, "url is not a plain http(s) url"),
        ]);

        let mut requests: Vec<_> = (0..2).map(|_| received.recv().unwrap()).collect();
        requests.sort();
        let text = String::from_utf8_lossy(&requests[0]);
        let path = format!("/eth/v1/builder/builder_preferences/0x{}", "01".repeat(48));
        assert!(text.starts_with(&format!("POST /prefs{path} HTTP/1.1\r\n")), "{text}");
        assert!(text.contains("Eth-Consensus-Version: gloas"), "{text}");
        assert!(text.contains("Content-Type: application/octet-stream"), "{text}");
        let auth = auth_ssz(b"builder.example", 9);
        let request = [&7u64.to_le_bytes()[..], &12u32.to_le_bytes(), &auth].concat();
        assert!(requests[0].ends_with(&request), "the auth goes out as the VC sent it");
    }

    #[test]
    fn preferences_without_a_plain_url_fail_unsent() {
        let (url, received) = builder(false);
        let body = list(&[
            preferences_entry(1, &format!("{url}/prefs x"), 0),
            preferences_entry(2, &format!("{url}/prefs\r\nX: 1"), 0),
            preferences_entry(3, "http://:1/prefs", 0),
            preferences_entry(4, &format!("{url}/prefs"), 0),
        ]);
        let mut readiness = Readiness::new(64);
        let mut bids =
            BuilderBids::new(readiness.registry(), TokenRange::whole(), Duration::from_secs(2));

        bids.submit_preferences(5, PreferencesBody::parse(&body, false).unwrap());
        let refused = "url is not a plain http(s) url".to_owned();
        let expected = (0..3).map(|index| (index, refused.clone())).collect();
        assert_eq!(preference_failures(&mut bids, &mut readiness), (5, expected));
        assert_eq!(received.try_iter().count(), 1);
    }

    /// Preferences take `PREFERENCE_CONNECTIONS` of a builder's connections at
    /// once; the rest fail, for the VC to send again.
    #[test]
    fn preferences_past_their_share_of_a_builder_fail() {
        let (url, received) = builder(false);
        let entries =
            vec![preferences_entry(1, &format!("{url}/prefs"), 0); PREFERENCE_CONNECTIONS + 2];
        let body = list(&entries);
        let mut readiness = Readiness::new(64);
        let mut bids =
            BuilderBids::new(readiness.registry(), TokenRange::whole(), Duration::from_secs(2));

        bids.submit_preferences(8, PreferencesBody::parse(&body, false).unwrap());
        let busy = "builder connections all busy".to_owned();
        let expected =
            vec![(PREFERENCE_CONNECTIONS, busy.clone()), (PREFERENCE_CONNECTIONS + 1, busy)];
        assert_eq!(preference_failures(&mut bids, &mut readiness), (8, expected));
        assert_eq!(received.try_iter().count(), PREFERENCE_CONNECTIONS);
    }

    /// A burst of preferences leaves bids the connections preferences may not
    /// take.
    #[test]
    fn preferences_leave_bids_their_share() {
        let (url, _received) = builder(true);
        let entries = vec![preferences_entry(1, &format!("{url}/relay"), 0); MAX_REQUESTS];
        let body = list(&entries);
        let readiness = Readiness::new(64);
        let mut bids =
            BuilderBids::new(readiness.registry(), TokenRange::whole(), Duration::from_secs(2));

        bids.submit_preferences(8, PreferencesBody::parse(&body, false).unwrap());
        let bid_entries = MAX_REQUESTS - PREFERENCE_CONNECTIONS;
        let config =
            config(0, 100, &vec![entry(&format!("{url}/relay"), [0, 0, 100]); bid_entries]);
        bids.request(&request(), BuilderConfig::parse(&config).unwrap());
        let bid_round = bids.bid_rounds.live.last().unwrap();
        assert_eq!(bid_round.unanswered, bid_entries, "every bid entry is asked");
    }

    /// SSZ goes first every time; a builder answering 415 gets the same entry
    /// again as JSON.
    #[test]
    fn preferences_fall_back_to_json_after_ssz_each_time() {
        let (url, received) = builder(false);
        let body = list(&[preferences_entry(1, &format!("{url}/json_only"), 7)]);
        let mut readiness = Readiness::new(64);
        let mut bids =
            BuilderBids::new(readiness.registry(), TokenRange::whole(), Duration::from_secs(2));

        for request_id in [1, 2] {
            bids.submit_preferences(request_id, PreferencesBody::parse(&body, false).unwrap());
            assert_eq!(preference_failures(&mut bids, &mut readiness), (request_id, Vec::new()));
        }
        let content_types: Vec<_> = received
            .try_iter()
            .map(|request| {
                let text = String::from_utf8_lossy(&request).to_lowercase();
                text.contains("content-type: application/json")
            })
            .collect();
        assert_eq!(content_types, [false, true, false, true]);
    }

    #[test]
    fn empty_preferences_are_answered_with_no_failures() {
        let mut readiness = Readiness::new(64);
        let mut bids =
            BuilderBids::new(readiness.registry(), TokenRange::whole(), Duration::from_secs(2));

        bids.submit_preferences(3, PreferencesBody::parse(&[], false).unwrap());
        assert_eq!(preference_failures(&mut bids, &mut readiness), (3, Vec::new()));
    }

    /// A finished round's buffers serve the next round of its kind.
    #[test]
    fn finished_rounds_are_reused() {
        let body = list(&[preferences_entry(1, "ftp://builder", 0)]);
        let mut readiness = Readiness::new(64);
        let mut bids =
            BuilderBids::new(readiness.registry(), TokenRange::whole(), Duration::from_secs(2));

        bids.submit_preferences(1, PreferencesBody::parse(&body, false).unwrap());
        preference_failures(&mut bids, &mut readiness);
        let out = bids.preference_rounds.spare[0].out.as_ptr();
        bids.submit_preferences(2, PreferencesBody::parse(&body, false).unwrap());
        assert!(bids.preference_rounds.spare.is_empty());
        assert_eq!(bids.preference_rounds.live[0].out.as_ptr(), out);
    }

    #[test]
    fn https_urls_keep_their_base_path() {
        let mut path = String::new();
        write_base_path(&mut path, "https://relay.example/builder/");
        assert_eq!(path, "/builder");
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
        let body = config(0, 100, &[entry("ftp://builder", [0; 3]), other_slot]);
        let mut readiness = Readiness::new(64);
        let mut bids =
            BuilderBids::new(readiness.registry(), TokenRange::whole(), Duration::from_secs(1));
        bids.request(&request(), BuilderConfig::parse(&body).unwrap());
        assert_eq!(answered(&mut bids, &mut readiness), (77, Vec::new()));
    }
}
