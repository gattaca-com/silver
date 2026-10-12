use std::{collections::VecDeque, ops::Range, time::Duration};

use mio::{Events, Registry};
use silver_beacon_state_data::{B256, Slot, SpecConfig};
use silver_common::SidecarBidRequest;
use silver_config::PbsConfig;
use silver_httpcore::{
    BufferCapacity, ClientRequest, ClientResponse, Endpoint, HttpPool, Method, TokenRange,
};

use crate::{
    block_submission::BlockSubmission, header_fetch::HeaderFetch, registrations::Registrations,
};

mod bid;
mod block_submission;
mod header_fetch;
mod registrations;

const CONSENSUS_VERSION: &str = "Eth-Consensus-Version";
/// The only fork whose bids and blinded blocks this client handles.
const FULU: &str = "fulu";

/// The builder-API calls the beacon API hands on to the sidecar.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SidecarCall {
    /// The VC's JSON registrations, forwarded as received.
    RegisterValidators,
    /// A Fulu `SignedBlindedBeaconBlock` as SSZ; the sidecar answers 202 with
    /// no body once a relay publishes the block.
    SubmitBlindedBlock,
}

impl SidecarCall {
    fn path(self) -> &'static str {
        match self {
            Self::RegisterValidators => "/eth/v1/builder/validators",
            Self::SubmitBlindedBlock => "/eth/v2/builder/blinded_blocks",
        }
    }

    /// A v2 blinded block is accepted with 202 only.
    pub fn is_success(self, status: u16) -> bool {
        match self {
            Self::RegisterValidators => matches!(status, 200 | 202 | 204),
            Self::SubmitBlindedBlock => status == 202,
        }
    }
}

pub enum SidecarEvent<'a> {
    Response { request_id: u64, response: Result<ClientResponse<'a>, &'a str> },
    Bid { slot: Slot, parent_hash: B256, signed_bid: Option<&'a [u8]> },
}

/// One second past Commit-Boost's `timeout_register_validator_ms` default,
/// which bounds every relay's retries together. A sidecar configured above
/// 3 s outlasts this.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(3 + 1);

/// Buffers grow past this for a large registration set.
const CONNECTION_CAPACITY: BufferCapacity = BufferCapacity { read: 64 << 10, write: 64 << 10 };

pub struct PbsClient {
    pool: HttpPool,
    registry: Registry,
    /// Registrations; the front one is in flight while the connection is
    /// busy.
    requests: VecDeque<Request>,
    bodies: Vec<u8>,
    registrations: Registrations,
    header_fetch: HeaderFetch,
    block_submission: BlockSubmission,
}

struct Request {
    id: u64,
    body: Range<usize>,
}

impl PbsClient {
    pub const MAX_SOCKETS: usize = 3;

    pub fn new(
        registry: &Registry,
        tokens: TokenRange,
        header_tokens: TokenRange,
        submission_tokens: TokenRange,
        config: &PbsConfig,
        spec: &SpecConfig,
        genesis_time: u64,
    ) -> Self {
        let endpoint = &config.endpoint;
        assert!(
            endpoint.starts_with("http://"),
            "unsupported pbs.endpoint scheme (only http:// is served): {endpoint}"
        );
        Self {
            pool: HttpPool::new(
                Endpoint::Http(endpoint.to_owned()),
                tokens,
                CONNECTION_CAPACITY,
                1,
                REQUEST_TIMEOUT,
            ),
            registry: registry.try_clone().expect("mio Registry::try_clone failed"),
            requests: VecDeque::new(),
            bodies: Vec::new(),
            registrations: Registrations::default(),
            header_fetch: HeaderFetch::new(header_tokens, config, spec, genesis_time),
            block_submission: BlockSubmission::new(submission_tokens, config),
        }
    }

    /// Registrations go out in order, one at a time; a blinded block takes
    /// its own connection. `spin` reports the answer under `id`.
    pub fn send(&mut self, id: u64, call_path: SidecarCall, body: &[u8]) {
        match call_path {
            SidecarCall::RegisterValidators => {
                let start = self.bodies.len();
                self.bodies.extend_from_slice(body);
                self.requests.push_back(Request { id, body: start..self.bodies.len() });
                self.post_next();
            }
            SidecarCall::SubmitBlindedBlock => self.block_submission.send(id, body, &self.registry),
        }
    }

    /// Returns whether a [`SidecarEvent::Bid`] will answer the request.
    pub fn request_bid(&mut self, request: &SidecarBidRequest) -> bool {
        let Some(registration) = self.registrations.get(&request.proposer_pubkey) else {
            silver_log::debug!(slot = request.slot, "proposer has no registration; no bid asked");
            return false;
        };
        self.header_fetch.fetch(request, registration, &self.registry)
    }

    pub fn spin(&mut self, events: &Events, on_event: &mut impl FnMut(SidecarEvent<'_>)) {
        self.header_fetch.spin(events, &self.registry, &mut |request, signed_bid| {
            on_event(SidecarEvent::Bid {
                slot: request.slot,
                parent_hash: request.parent_hash,
                signed_bid,
            })
        });

        self.block_submission.spin(events, &self.registry, &mut |id, response| {
            sidecar_accepted(SidecarCall::SubmitBlindedBlock, &response);
            on_event(SidecarEvent::Response { request_id: id, response });
        });

        let Self { pool, registry, requests, bodies, registrations, .. } = self;
        pool.dispatch_events(events, registry, &mut |id, response| {
            let request = requests.pop_front().expect("an answer follows a sent request");
            debug_assert_eq!(request.id, id);
            if sidecar_accepted(SidecarCall::RegisterValidators, &response) {
                registrations.store(&bodies[request.body]);
            }
            on_event(SidecarEvent::Response { request_id: id, response });
        });

        if self.requests.is_empty() {
            self.bodies.clear();
        }
        self.post_next();
    }

    fn post_next(&mut self) {
        if !self.pool.has_capacity() {
            return;
        }
        let Some(Request { id, body }) = self.requests.front() else { return };
        let registrations = &self.bodies[body.clone()];
        self.pool.enqueue(*id, &post_registrations(registrations), &self.registry);
    }
}

/// Logs a refusal.
fn sidecar_accepted(call_path: SidecarCall, response: &Result<ClientResponse<'_>, &str>) -> bool {
    let path = call_path.path();
    match response {
        Ok(response) if call_path.is_success(response.status) => return true,
        Ok(response) => {
            silver_log::warn!(path, status = response.status, "sidecar refused request")
        }
        Err(error) => silver_log::warn!(path, error, "request did not reach sidecar"),
    }
    false
}

fn post_registrations(body: &[u8]) -> ClientRequest<'_> {
    ClientRequest {
        method: Method::Post,
        path: SidecarCall::RegisterValidators.path(),
        body,
        authorization: None,
        accept: None,
        content_type: Some("application/json"),
        headers: &[],
    }
}
