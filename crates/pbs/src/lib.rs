use std::{collections::VecDeque, ops::Range, time::Duration};

use mio::{Events, Registry};
use silver_beacon_state_data::{B256, Slot, SpecConfig};
use silver_common::SidecarBidRequest;
use silver_config::PbsConfig;
use silver_httpcore::{
    BufferCapacity, ClientRequest, ClientResponse, Endpoint, HttpPool, Method, TokenRange,
};

use crate::{header_fetch::HeaderFetch, registrations::Registrations};

mod bid;
mod header_fetch;
mod registrations;

pub const REGISTER_VALIDATORS: &str = "/eth/v1/builder/validators";
const CONSENSUS_VERSION: &str = "Eth-Consensus-Version";
/// The only fork whose bids this client handles.
const FULU: &str = "fulu";
/// Takes a Fulu `SignedBlindedBeaconBlock` as SSZ; the sidecar answers 202
/// with no body once a relay publishes the block.
pub const SUBMIT_BLINDED_BLOCK: &str = "/eth/v2/builder/blinded_blocks";

/// 200, 202 and 204 all succeed, as Lighthouse's builder client counts them.
pub fn is_success(status: u16) -> bool {
    matches!(status, 200 | 202 | 204)
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
    /// The front request is in flight while the connection is busy.
    requests: VecDeque<Request>,
    bodies: Vec<u8>,
    registrations: Registrations,
    header_fetch: HeaderFetch,
}

struct Request {
    id: u64,
    path: &'static str,
    body: Range<usize>,
}

impl PbsClient {
    pub const MAX_SOCKETS: usize = 2;

    pub fn new(
        registry: &Registry,
        tokens: TokenRange,
        header_tokens: TokenRange,
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
        }
    }

    /// POSTs the JSON `body` to `path` at once when the connection is free,
    /// else after the requests ahead of it. `spin` reports the answer under
    /// `id`.
    pub fn send(&mut self, id: u64, path: &'static str, body: &[u8]) {
        let start = self.bodies.len();
        self.bodies.extend_from_slice(body);
        self.requests.push_back(Request { id, path, body: start..self.bodies.len() });
        self.post_next();
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

        let Self { pool, registry, requests, bodies, registrations, .. } = self;
        pool.dispatch_events(events, registry, &mut |id, response| {
            let request = requests.pop_front().expect("an answer follows a sent request");
            debug_assert_eq!(request.id, id);
            match &response {
                Ok(response) if is_success(response.status) => {
                    if request.path == REGISTER_VALIDATORS {
                        registrations.store(&bodies[request.body]);
                    }
                }
                Ok(response) => silver_log::warn!(
                    path = request.path,
                    status = response.status,
                    "sidecar refused request"
                ),
                Err(error) => {
                    silver_log::warn!(path = request.path, error, "request did not reach sidecar")
                }
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
        let Some(Request { id, path, body }) = self.requests.front() else { return };
        self.pool.enqueue(*id, &post(path, &self.bodies[body.clone()]), &self.registry);
    }
}

fn post<'a>(path: &'a str, body: &'a [u8]) -> ClientRequest<'a> {
    let (content_type, headers): (_, &[_]) = if path == SUBMIT_BLINDED_BLOCK {
        ("application/octet-stream", &[("Eth-Consensus-Version", "fulu")])
    } else {
        ("application/json", &[])
    };
    ClientRequest {
        method: Method::Post,
        path,
        body,
        authorization: None,
        accept: None,
        content_type: Some(content_type),
        headers,
    }
}
