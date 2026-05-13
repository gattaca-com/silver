use std::{
    collections::{HashMap, VecDeque},
    ops::Deref,
    time::{Duration, Instant},
};

use flux::tile::Tile;
use silver_common::{
    BeaconStateEvent, P2pSend, PeerControl, PeerEvent, PeerStatus, RpcInbound, RpcOutbound,
    RpcRequest, RpcRequestInbound, RpcRequestOutbound, RpcResponse, RpcResponseInbound,
    RpcResponseOutbound, RpcSeverity, SilverSpine, StreamProtocol,
    ssz_view::{
        BLOCKS_BY_RANGE_REQ_SIZE, BeaconBlocksByRangeRequestView, METADATA_SIZE, MetadataView,
        STATUS_V2_SIZE, StatusView,
    },
};
use silver_peer::PeerManager;

/// Per-peer cap on outstanding BlocksByRange requests. Bounds load on any
/// single peer and keeps fan-out useful when many ranges are pending.
const MAX_BLOCKS_BY_RANGE_IN_FLIGHT: u32 = 2;

/// Size of the `StreamProtocol` enum (incl. `Unset`). Used to allocate
/// the per-protocol outbound counter array; index via
/// `protocol.ordinal() as usize`.
const N_STREAM_PROTOCOLS: usize = 12;

/// Inbound rate-limit quota for a single protocol. Token-bucket
/// semantics: `max_tokens` tokens refilled continuously at rate
/// `max_tokens / period`. Mirrors lighthouse's
/// `lighthouse_network::rpc::config::RPCRateLimiterBuilder` defaults.
struct InboundQuota {
    max_tokens: u32,
    period: Duration,
}

impl InboundQuota {
    const fn new(max_tokens: u32, period_secs: u64) -> Self {
        Self { max_tokens, period: Duration::from_secs(period_secs) }
    }
}

/// Per-peer per-protocol inbound rate quotas. Indexed by
/// `protocol.ordinal() as usize`. `None` ⇒ no limit (gossip / identity /
/// the `Unset` sentinel). Defaults track
/// `lighthouse_network::rpc::config::RPCRateLimiterBuilder::DEFAULT_*_QUOTA`.
const INBOUND_QUOTAS: [Option<InboundQuota>; N_STREAM_PROTOCOLS] = [
    None,                               // GossipSub
    None,                               // Identity
    Some(InboundQuota::new(5, 15)),     // StatusV1
    Some(InboundQuota::new(5, 15)),     // StatusV2
    Some(InboundQuota::new(2, 10)),     // Ping
    Some(InboundQuota::new(1, 10)),     // Goodbye
    Some(InboundQuota::new(2, 5)),      // Metadata
    Some(InboundQuota::new(128, 10)),   // BeaconBlocksByRange
    Some(InboundQuota::new(128, 10)),   // BeaconBlocksByRoot
    Some(InboundQuota::new(16384, 10)), // DataColumnSidecarsByRange
    Some(InboundQuota::new(16384, 10)), // DataColumnSidecarsByRoot
    None,                               // Unset
];

/// Result-byte values for eth2 RPC error chunks. Per
/// `consensus-specs/p2p-interface.md`, only 0x01..=0x03 are spec-defined;
/// 0x14 is a lighthouse extension some clients emit and others tolerate.
const RPC_ERR_INVALID_REQUEST: u8 = 0x01;
const RPC_ERR_SERVER_ERROR: u8 = 0x02;
const RPC_ERR_RESOURCE_UNAVAILABLE: u8 = 0x03;
const RPC_ERR_RATE_LIMITED: u8 = 0x14;

/// Map a received `RpcResponse::Error` to an `RpcSeverity`. Returns `None`
/// when the error is informational and shouldn't impact peer score (notably
/// `ResourceUnavailable` for blob/column-by-root, where missing data is
/// expected). All RpcResponse::Error events at this layer are responses to
/// requests **we** initiated (the inbound branch handles request parsing
/// errors separately via the network tile), so direction is always
/// "outgoing-from-us" — the conditional ban on outbound BlocksByRange /
/// BlocksByRoot ResourceUnavailable is unconditional here.
fn severity_for_error_response(code: u8, protocol: StreamProtocol) -> Option<RpcSeverity> {
    match code {
        // Peer says our request was malformed. Either we're buggy or peer is
        // — LowTolerance gives a few strikes before disconnect.
        RPC_ERR_INVALID_REQUEST => Some(RpcSeverity::LowTolerance),
        // Peer's internal trouble. Not malicious — tolerate, but track.
        RPC_ERR_SERVER_ERROR => Some(RpcSeverity::MidTolerance),
        RPC_ERR_RESOURCE_UNAVAILABLE => match protocol {
            // Peer can't serve blocks they should have. Useless to keep
            // around — ban (mirrors lighthouse for outbound block sync).
            StreamProtocol::BeaconBlocksByRange | StreamProtocol::BeaconBlocksByRoot => {
                Some(RpcSeverity::Fatal)
            }
            // By-root is naturally sparse: many peers won't custody every
            // requested root. No penalty.
            StreamProtocol::DataColumnSidecarsByRoot => None,
            // By-range — peer should custody columns in their group;
            // missing column data is suspicious but not necessarily
            // malicious.
            StreamProtocol::DataColumnSidecarsByRange => Some(RpcSeverity::MidTolerance),
            // Status/Ping/Goodbye/MetaData/Identity/GossipSub — odd but
            // not abusive.
            _ => Some(RpcSeverity::HighTolerance),
        },
        // Lighthouse-emitted rate-limit signal. Means we're hammering them,
        // not that they're misbehaving — back off, don't ban.
        RPC_ERR_RATE_LIMITED => Some(RpcSeverity::MidTolerance),
        // Unknown / reserved code. Spec may add new codes — forward-compat
        // mild penalty rather than crash.
        _ => Some(RpcSeverity::HighTolerance),
    }
}

pub struct Controller {
    peer_manager: PeerManager,
    last_tick: Instant,
    last_ping: Instant,
    last_status: Instant,

    /// When false, the 17000ms heartbeat skips the per-peer Ping fan-out.
    /// Tests use this to keep the peer-state machine ticking without
    /// generating background Ping traffic that would interfere with
    /// targeted RPC assertions.
    auto_ping: bool,
    /// BlocksByRange requests that arrived with no eligible peer. Drained
    /// each `loop_body` once peers become available (or in-flight slots
    /// free up). A `PeerControl::DiscoverNodes` is emitted on each enqueue
    /// so discovery can backfill new candidates.
    pending_blocks_by_range: VecDeque<(u64, [u8; BLOCKS_BY_RANGE_REQ_SIZE])>,
    /// Outstanding outbound RPC requests per peer, broken down by
    /// protocol. Incremented when we send a request, decremented when the
    /// terminal response for that protocol arrives (single-chunk: the
    /// response itself; multi-chunk: `Complete` or `Error`). Cleared on
    /// peer disconnect. Indexed by `protocol.ordinal() as usize`.
    outbound_in_flight: HashMap<usize, [u32; N_STREAM_PROTOCOLS]>,
    /// Per-peer inbound rate-limit state — token bucket per protocol
    /// using lighthouse's defaults (`INBOUND_QUOTAS`). Refill is lazy:
    /// `try_admit_inbound` credits tokens on each access based on time
    /// elapsed since `last_refill`. Cleared on disconnect.
    inbound_buckets: HashMap<usize, PeerInboundState>,
}

#[derive(Default)]
struct PeerInboundState {
    /// Current token count per protocol (indexed by `ordinal()`).
    tokens: [u32; N_STREAM_PROTOCOLS],
    /// Last time the bucket was credited. `None` ⇒ never seen; the next
    /// `try_admit_inbound` call seeds it at `max_tokens`.
    last_refill: [Option<Instant>; N_STREAM_PROTOCOLS],
}

impl Controller {
    /// Build a Controller with a fresh `PeerManager`. `status` and
    /// `metadata` start empty — callers update them via `set_status` /
    /// `set_metadata` once chain state is available.
    pub fn new(peer_manager: PeerManager) -> Self {
        Self {
            peer_manager,
            last_tick: Instant::now(),
            last_ping: Instant::now(),
            last_status: Instant::now(),
            auto_ping: true,
            pending_blocks_by_range: VecDeque::new(),
            outbound_in_flight: HashMap::new(),
            inbound_buckets: HashMap::new(),
        }
    }

    pub fn set_status(&mut self, status: [u8; STATUS_V2_SIZE]) {
        self.peer_manager.set_status(status);
    }

    pub fn set_metadata(&mut self, metadata: [u8; METADATA_SIZE]) {
        self.peer_manager.set_metadata(metadata);
    }

    /// Toggle the heartbeat-driven outbound Ping fan-out. Default is on.
    pub fn set_auto_ping(&mut self, enabled: bool) {
        self.auto_ping = enabled;
    }

    pub fn peer_manager(&self) -> &PeerManager {
        &self.peer_manager
    }
}

type OutboundCounts = HashMap<usize, [u32; N_STREAM_PROTOCOLS]>;

fn outbound_count(counts: &OutboundCounts, peer: usize, protocol: StreamProtocol) -> u32 {
    counts.get(&peer).map_or(0, |c| c[protocol.ordinal() as usize])
}

fn record_outbound(counts: &mut OutboundCounts, peer: usize, protocol: StreamProtocol) {
    let entry = counts.entry(peer).or_insert([0; N_STREAM_PROTOCOLS]);
    entry[protocol.ordinal() as usize] += 1;
}

/// Decrement the outbound slot for `(peer, protocol)`; drop the peer's
/// entry when every protocol's count is zero so the map stays small in
/// steady state.
fn release_outbound(counts: &mut OutboundCounts, peer: usize, protocol: StreamProtocol) {
    if let Some(c) = counts.get_mut(&peer) {
        let slot = &mut c[protocol.ordinal() as usize];
        *slot = slot.saturating_sub(1);
        if c.iter().all(|&v| v == 0) {
            counts.remove(&peer);
        }
    }
}

/// Does this `response` terminate an outbound RPC stream we initiated?
/// Single-chunk protocols (Status/Ping/MetaData/Goodbye) have no `Complete`
/// sentinel — the one response chunk is the terminator. Multi-chunk
/// protocols (BlocksBy*, DataColumnSidecars*) terminate only on
/// `Complete` or `Error`; intermediate `BeaconBlock`/`DataColumnSidecar`
/// chunks are not terminal.
fn is_terminal_response(protocol: StreamProtocol, response: &RpcResponse) -> bool {
    !protocol.has_multipart_response() ||
        matches!(response, RpcResponse::Complete | RpcResponse::Error { .. })
}

/// Attempt to consume one inbound token for `(peer, protocol)`. Refills
/// the bucket lazily based on elapsed time since the last credit, then
/// decrements one token if available. Returns `true` if admitted,
/// `false` if the peer has exceeded their quota.
///
/// Protocols with no quota in `INBOUND_QUOTAS` (gossip/identity) are
/// always admitted. First contact seeds the bucket at `max_tokens`,
/// matching lighthouse's burst-allowed semantics.
fn try_admit_inbound(
    buckets: &mut HashMap<usize, PeerInboundState>,
    peer: usize,
    protocol: StreamProtocol,
    now: Instant,
) -> bool {
    let idx = protocol.ordinal() as usize;
    let Some(quota) = INBOUND_QUOTAS[idx].as_ref() else {
        return true;
    };
    let state = buckets.entry(peer).or_default();

    if state.last_refill[idx].is_none() {
        state.tokens[idx] = quota.max_tokens;
        state.last_refill[idx] = Some(now);
    }
    let last = state.last_refill[idx].expect("seeded above");

    // Continuous refill at rate `max_tokens / period`: credit whole
    // tokens, advance `last_refill` by the exact time they "cost" so
    // sub-token elapsed durations don't get lost.
    let per_token_ns = quota.period.as_nanos() as u64 / quota.max_tokens as u64;
    if per_token_ns > 0 {
        let elapsed_ns = now.saturating_duration_since(last).as_nanos() as u64;
        let new_tokens = (elapsed_ns / per_token_ns).min(quota.max_tokens as u64) as u32;
        if new_tokens > 0 {
            state.tokens[idx] = state.tokens[idx].saturating_add(new_tokens).min(quota.max_tokens);
            let advance_ns = per_token_ns.saturating_mul(new_tokens as u64);
            state.last_refill[idx] = Some(last + Duration::from_nanos(advance_ns));
        }
    }

    if state.tokens[idx] > 0 {
        state.tokens[idx] -= 1;
        true
    } else {
        false
    }
}

impl Tile<SilverSpine> for Controller {
    fn loop_body(&mut self, adapter: &mut flux::spine::SpineAdapter<SilverSpine>) {
        let now = Instant::now();
        adapter.consume(|event: PeerEvent, producers| {
            // Drop per-peer in-flight slots across every protocol when
            // the connection goes away — outstanding responses can never
            // arrive, so leaving counters pinned would lock the peer out
            // of future retries if it reconnects. The inbound bucket is
            // also dropped so a reconnecting peer starts fresh at full
            // tokens (matches lighthouse).
            if let PeerEvent::P2pDisconnect { p2p_peer } = &event {
                self.outbound_in_flight.remove(p2p_peer);
                self.inbound_buckets.remove(p2p_peer);
            }
            self.peer_manager.handle_event(event, now, &mut |pc| {
                match pc {
                    silver_common::PeerControl::P2pSend(send) => {
                        producers.p2p_send.produce(&send.into())
                    }
                    other => producers.peer_control.produce(&other.into()),
                };
            });
        });
        adapter.consume(|rpc: RpcInbound, producers| {
            let mut on_event = |pc| {
                match pc {
                    silver_common::PeerControl::P2pSend(send) => {
                        producers.p2p_send.produce(&send.into())
                    }
                    other => producers.peer_control.produce(&other.into()),
                };
            };

            tracing::info!(?rpc, "received rpc inbound");

            match rpc {
                RpcInbound::Request(RpcRequestInbound { stream_id, request }) => {
                    // Inbound rate-limit gate. The controller is the
                    // single chokepoint for all inbound RPC requests,
                    // including block/data-column requests that get
                    // forwarded to their owning tile downstream. Each
                    // protocol has a quota in `INBOUND_QUOTAS`; the gate
                    // returns admit=true unconditionally for the
                    // unquota'd protocols (gossip/identity).
                    let protocol = request.protocol();
                    if !try_admit_inbound(
                        &mut self.inbound_buckets,
                        stream_id.peer(),
                        protocol,
                        now,
                    ) {
                        // Goodbye expects no response — silently drop;
                        // anything else gets the standard rate-limit
                        // error chunk.
                        if protocol != StreamProtocol::Goodbye {
                            let mut msg = [0u8; 256];
                            let err = b"rate limit exceeded";
                            msg[..err.len()].copy_from_slice(err);
                            producers.p2p_send.produce(
                                &P2pSend::Rpc(RpcOutbound::Response(RpcResponseOutbound {
                                    stream_id,
                                    response: RpcResponse::Error {
                                        error: RPC_ERR_RATE_LIMITED,
                                        msg,
                                        len: err.len(),
                                    },
                                }))
                                .into(),
                            );
                        }
                        return;
                    }
                    match request {
                    RpcRequest::StatusV1(status_v1) => {
                        self.peer_manager.handle_event(
                            PeerEvent::P2pPeerStatus {
                                p2p_peer: stream_id.peer(),
                                status_ssz: PeerStatus::V1(status_v1),
                            },
                            now,
                            &mut on_event,
                        );
                        if let Some(status) = self.peer_manager.status() {
                            let status_v1 = StatusView::as_v1(status).try_into().unwrap();
                            producers.p2p_send.produce(
                                &P2pSend::Rpc(RpcOutbound::Response(RpcResponseOutbound {
                                    stream_id,
                                    response: RpcResponse::StatusV1(status_v1),
                                }))
                                .into(),
                            );
                        } else {
                            let mut msg = [0u8; 256];
                            let err_bytes = "peer not initialised".as_bytes();
                            msg[..err_bytes.len()].copy_from_slice(err_bytes);
                            producers.p2p_send.produce(
                                &P2pSend::Rpc(RpcOutbound::Response(RpcResponseOutbound {
                                    stream_id,
                                    response: RpcResponse::Error {
                                        error: 2,
                                        msg,
                                        len: err_bytes.len(),
                                    },
                                }))
                                .into(),
                            );
                        }
                    }
                    RpcRequest::StatusV2(status_v2) => {
                        self.peer_manager.handle_event(
                            PeerEvent::P2pPeerStatus {
                                p2p_peer: stream_id.peer(),
                                status_ssz: PeerStatus::V2(status_v2),
                            },
                            now,
                            &mut on_event,
                        );
                        if let Some(status) = self.peer_manager.status() {
                            producers.p2p_send.produce(
                                &P2pSend::Rpc(RpcOutbound::Response(RpcResponseOutbound {
                                    stream_id,
                                    response: RpcResponse::StatusV2(*status),
                                }))
                                .into(),
                            );
                        } else {
                            let mut msg = [0u8; 256];
                            let err_bytes = "peer not initialised".as_bytes();
                            msg[..err_bytes.len()].copy_from_slice(err_bytes);
                            producers.p2p_send.produce(
                                &P2pSend::Rpc(RpcOutbound::Response(RpcResponseOutbound {
                                    stream_id,
                                    response: RpcResponse::Error {
                                        error: 2,
                                        msg,
                                        len: err_bytes.len(),
                                    },
                                }))
                                .into(),
                            );
                        }
                    }
                    RpcRequest::Ping(ping) => {
                        let current_peer_metadata_seq =
                            self.peer_manager.peer_metadata_seq(stream_id.peer());
                        let metadata_seq = u64::from_le_bytes(ping);

                        let our_seq = self.peer_manager().metadata().map(|m| {
                            MetadataView::seq_number(m).to_le_bytes()
                        }).unwrap_or_default();

                        producers.p2p_send.produce(
                            &P2pSend::Rpc(RpcOutbound::Response(RpcResponseOutbound {
                                stream_id,
                                response: RpcResponse::Ping(our_seq),
                            }))
                            .into(),
                        );

                        if !matches!(current_peer_metadata_seq, Some(seq) if seq == metadata_seq) {
                            producers.p2p_send.produce(
                                &P2pSend::Rpc(RpcOutbound::Request(RpcRequestOutbound {
                                    application_id: 0,
                                    peer: stream_id.peer(),
                                    request: RpcRequest::MetaData,
                                }))
                                .into(),
                            );
                        }
                    }
                    RpcRequest::Goodbye(goodbye) => self.peer_manager.handle_event(
                        PeerEvent::P2pPeerGoodbye {
                            p2p_peer: stream_id.peer(),
                            status: u64::from_le_bytes(goodbye),
                        },
                        now,
                        &mut on_event,
                    ),
                    RpcRequest::MetaData => {
                        let metadata = self.peer_manager.metadata().unwrap_or(&[0u8;25]);
                        producers.p2p_send.produce(
                            &P2pSend::Rpc(RpcOutbound::Response(RpcResponseOutbound {
                                stream_id,
                                response: RpcResponse::MetaData(*metadata),
                            }))
                            .into(),
                        );
                    }
                    // TODO: forward admitted block/data-column requests
                    // to the owning tile. The rate-limit gate above has already accepted the
                    // request and credited the peer's bucket; the
                    // downstream tile owns response generation.
                    RpcRequest::BlocksByRange(_ssz) => {}
                    RpcRequest::BlockByRoot(_req) => {}
                    RpcRequest::DataColumnsByRange { ssz: _, len: _ } => {}
                    RpcRequest::DataColumnsByRoot(_req) => {}
                    }
                }
                RpcInbound::Response(RpcResponseInbound {
                    application_id,
                    stream_id,
                    response,
                }) => {
                    let terminal_protocol = is_terminal_response(stream_id.protocol(), &response)
                        .then_some(stream_id.protocol());
                    match response {
                        RpcResponse::StatusV1(status_v1) => self.peer_manager.handle_event(
                            PeerEvent::P2pPeerStatus {
                                p2p_peer: stream_id.peer(),
                                status_ssz: PeerStatus::V1(status_v1),
                            },
                            now,
                            &mut on_event,
                        ),
                        RpcResponse::StatusV2(status_v2) => self.peer_manager.handle_event(
                            PeerEvent::P2pPeerStatus {
                                p2p_peer: stream_id.peer(),
                                status_ssz: PeerStatus::V2(status_v2),
                            },
                            now,
                            &mut on_event,
                        ),
                        RpcResponse::Ping(ping) => {
                            let current_peer_metadata_seq =
                                self.peer_manager.peer_metadata_seq(stream_id.peer());
                            let metadata_seq = u64::from_le_bytes(ping);
                            if !matches!(current_peer_metadata_seq, Some(seq) if seq == metadata_seq)
                            {
                                record_outbound(
                                    &mut self.outbound_in_flight,
                                    stream_id.peer(),
                                    StreamProtocol::Metadata,
                                );
                                producers.p2p_send.produce(
                                    &P2pSend::Rpc(RpcOutbound::Request(RpcRequestOutbound {
                                        application_id: 0,
                                        peer: stream_id.peer(),
                                        request: RpcRequest::MetaData,
                                    }))
                                    .into(),
                                );
                            }
                        }
                        RpcResponse::MetaData(metadata_ssz) => self.peer_manager.handle_event(
                            PeerEvent::P2pPeerMetadata {
                                p2p_peer: stream_id.peer(),
                                metadata_ssz,
                            },
                            now,
                            &mut on_event,
                        ),
                        RpcResponse::Error { error, msg, len } => {
                            let err = String::from_utf8_lossy(&msg[..len]);
                            tracing::error!(
                                error,
                                err = err.deref(),
                                application_id,
                                ?stream_id,
                                "rpc error response"
                            );

                            if let Some(severity) =
                                severity_for_error_response(error, stream_id.protocol())
                            {
                                self.peer_manager.handle_event(
                                    PeerEvent::RpcMisbehaviour {
                                        p2p_peer: stream_id.peer(),
                                        severity,
                                    },
                                    now,
                                    &mut on_event,
                                );
                            }
                        }
                        _ => {}
                    }
                    if let Some(protocol) = terminal_protocol {
                        release_outbound(
                            &mut self.outbound_in_flight,
                            stream_id.peer(),
                            protocol,
                        );
                    }
                }
            };
        });

        adapter.consume(|beacon_event: BeaconStateEvent, producers| {
            match beacon_event {
                BeaconStateEvent::Synced(status) => {
                    // TODO trigger gossip subscriptions
                    self.peer_manager.set_synced(true);
                    self.peer_manager.set_status(status);
                }
                BeaconStateEvent::Status(status) => {
                    self.peer_manager.set_status(status);
                }
                BeaconStateEvent::RequestBlocksByRange { request_id, ssz } => {
                    // Pick the highest-scoring connected peer that
                    // advertises BeaconBlocksByRange AND has spare
                    // in-flight capacity. If none qualifies, cache the
                    // request and kick discovery — the retry pass at the
                    // bottom of `loop_body` drains the cache as soon as
                    // an eligible peer becomes available.
                    let peer = {
                        let pm = &self.peer_manager;
                        let counts = &self.outbound_in_flight;
                        pm.best_peer_for(StreamProtocol::BeaconBlocksByRange, |p| {
                            outbound_count(counts, p, StreamProtocol::BeaconBlocksByRange) <
                                MAX_BLOCKS_BY_RANGE_IN_FLIGHT
                        })
                    };
                    match peer {
                        Some(peer) => {
                            record_outbound(
                                &mut self.outbound_in_flight,
                                peer,
                                StreamProtocol::BeaconBlocksByRange,
                            );
                            producers.p2p_send.produce(
                                &P2pSend::Rpc(RpcOutbound::Request(RpcRequestOutbound {
                                    application_id: request_id,
                                    peer,
                                    request: RpcRequest::BlocksByRange(ssz),
                                }))
                                .into(),
                            );
                        }
                        None => {
                            self.pending_blocks_by_range.push_back((request_id, ssz));
                            producers.peer_control.produce(&PeerControl::DiscoverNodes.into());
                            tracing::debug!(
                                request_id,
                                from_slot = BeaconBlocksByRangeRequestView::start_slot(&ssz),
                                count = BeaconBlocksByRangeRequestView::count(&ssz),
                                pending = self.pending_blocks_by_range.len(),
                                "no eligible peer for BlocksByRange; cached + discovery kicked"
                            );
                        }
                    }
                }
                _ => {}
            }
        });

        // Drain pending BlocksByRange requests onto any peer that's
        // freshly available (new connection, in-flight slot freed). Loop
        // walks until either the cache is empty or no eligible peer
        // remains — natural ordering puts the highest-scoring peers first
        // (best_peer_for) and respects the per-peer cap.
        while !self.pending_blocks_by_range.is_empty() {
            let peer = {
                let pm = &self.peer_manager;
                let counts = &self.outbound_in_flight;
                pm.best_peer_for(StreamProtocol::BeaconBlocksByRange, |p| {
                    outbound_count(counts, p, StreamProtocol::BeaconBlocksByRange) <
                        MAX_BLOCKS_BY_RANGE_IN_FLIGHT
                })
            };
            let Some(peer) = peer else {
                break;
            };
            let (request_id, ssz) =
                self.pending_blocks_by_range.pop_front().expect("non-empty by loop guard");
            record_outbound(
                &mut self.outbound_in_flight,
                peer,
                StreamProtocol::BeaconBlocksByRange,
            );
            adapter.produce(P2pSend::Rpc(RpcOutbound::Request(RpcRequestOutbound {
                application_id: request_id,
                peer,
                request: RpcRequest::BlocksByRange(ssz),
            })));
        }

        if self.last_tick.elapsed() > Duration::from_millis(700) {
            self.last_tick = now;
            self.peer_manager.tick(now, &mut |event| {
                match event {
                    silver_common::PeerControl::P2pSend(send) => adapter.produce(send),
                    other => adapter.produce(other),
                };
            });

            // send pings
            if self.auto_ping &&
                self.last_ping.elapsed() > Duration::from_secs(17) &&
                let Some(metadata) = self.peer_manager.metadata()
            {
                self.last_ping = Instant::now();

                let ping = RpcRequest::Ping(MetadataView::seq_number(metadata).to_le_bytes());
                for peer in self.peer_manager.live_peers() {
                    record_outbound(&mut self.outbound_in_flight, peer, StreamProtocol::Ping);
                    adapter.produce(P2pSend::Rpc(RpcOutbound::Request(RpcRequestOutbound {
                        application_id: 0,
                        peer,
                        request: ping,
                    })));
                }
            }
        }

        if self.last_status.elapsed() > Duration::from_secs(300) &&
            let Some(status) = self.peer_manager.status()
        {
            let status = RpcRequest::StatusV2(*status);
            for peer in self.peer_manager.live_peers() {
                adapter.produce(P2pSend::Rpc(RpcOutbound::Request(RpcRequestOutbound {
                    application_id: 0,
                    peer,
                    request: status,
                })));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_request_is_low_tolerance() {
        // Same severity for any protocol — peer claims our request was bad.
        assert!(matches!(
            severity_for_error_response(RPC_ERR_INVALID_REQUEST, StreamProtocol::Ping),
            Some(RpcSeverity::LowTolerance)
        ));
        assert!(matches!(
            severity_for_error_response(
                RPC_ERR_INVALID_REQUEST,
                StreamProtocol::BeaconBlocksByRange
            ),
            Some(RpcSeverity::LowTolerance)
        ));
    }

    #[test]
    fn server_error_is_mid_tolerance() {
        assert!(matches!(
            severity_for_error_response(RPC_ERR_SERVER_ERROR, StreamProtocol::StatusV2),
            Some(RpcSeverity::MidTolerance)
        ));
    }

    #[test]
    fn resource_unavailable_blocks_outbound_is_fatal() {
        // Ban: peer admits they can't serve us blocks we expected.
        assert!(matches!(
            severity_for_error_response(
                RPC_ERR_RESOURCE_UNAVAILABLE,
                StreamProtocol::BeaconBlocksByRange
            ),
            Some(RpcSeverity::Fatal)
        ));
        assert!(matches!(
            severity_for_error_response(
                RPC_ERR_RESOURCE_UNAVAILABLE,
                StreamProtocol::BeaconBlocksByRoot
            ),
            Some(RpcSeverity::Fatal)
        ));
    }

    #[test]
    fn resource_unavailable_columns_by_root_is_silent() {
        // Sparse custody — no penalty.
        assert!(
            severity_for_error_response(
                RPC_ERR_RESOURCE_UNAVAILABLE,
                StreamProtocol::DataColumnSidecarsByRoot
            )
            .is_none()
        );
    }

    #[test]
    fn resource_unavailable_columns_by_range_is_mid() {
        assert!(matches!(
            severity_for_error_response(
                RPC_ERR_RESOURCE_UNAVAILABLE,
                StreamProtocol::DataColumnSidecarsByRange
            ),
            Some(RpcSeverity::MidTolerance)
        ));
    }

    #[test]
    fn resource_unavailable_other_is_high_tolerance() {
        // Status/Ping/Goodbye/MetaData/Identity/GossipSub all share this.
        assert!(matches!(
            severity_for_error_response(RPC_ERR_RESOURCE_UNAVAILABLE, StreamProtocol::Ping),
            Some(RpcSeverity::HighTolerance)
        ));
    }

    #[test]
    fn rate_limited_is_mid_tolerance() {
        // Self-throttle, don't ban.
        assert!(matches!(
            severity_for_error_response(RPC_ERR_RATE_LIMITED, StreamProtocol::BeaconBlocksByRange),
            Some(RpcSeverity::MidTolerance)
        ));
    }

    #[test]
    fn unknown_code_is_high_tolerance() {
        // Forward-compat: spec might add new codes — don't crash, don't ban.
        assert!(matches!(
            severity_for_error_response(0xff, StreamProtocol::Ping),
            Some(RpcSeverity::HighTolerance)
        ));
        assert!(matches!(
            severity_for_error_response(0x42, StreamProtocol::BeaconBlocksByRange),
            Some(RpcSeverity::HighTolerance)
        ));
    }

    // ---- Inbound rate limiter ----

    #[test]
    fn inbound_unlimited_protocols_always_admit() {
        // Gossip + Identity have no quota → permit unconditionally.
        let mut buckets = HashMap::new();
        let now = Instant::now();
        for _ in 0..1000 {
            assert!(try_admit_inbound(&mut buckets, 7, StreamProtocol::GossipSub, now));
            assert!(try_admit_inbound(&mut buckets, 7, StreamProtocol::Identity, now));
        }
        // No state should be allocated for unquota'd protocols.
        assert!(buckets.is_empty());
    }

    #[test]
    fn inbound_burst_up_to_max_then_denies() {
        let mut buckets = HashMap::new();
        let now = Instant::now();
        // Ping quota = 2 / 10 s. First two admits succeed, the third
        // hits an empty bucket (no time has passed → no refill).
        assert!(try_admit_inbound(&mut buckets, 1, StreamProtocol::Ping, now));
        assert!(try_admit_inbound(&mut buckets, 1, StreamProtocol::Ping, now));
        assert!(!try_admit_inbound(&mut buckets, 1, StreamProtocol::Ping, now));
        assert!(!try_admit_inbound(&mut buckets, 1, StreamProtocol::Ping, now));
    }

    #[test]
    fn inbound_refills_after_period() {
        let mut buckets = HashMap::new();
        let t0 = Instant::now();
        // Drain Ping bucket (2 tokens).
        assert!(try_admit_inbound(&mut buckets, 1, StreamProtocol::Ping, t0));
        assert!(try_admit_inbound(&mut buckets, 1, StreamProtocol::Ping, t0));
        assert!(!try_admit_inbound(&mut buckets, 1, StreamProtocol::Ping, t0));
        // After a full period (10 s) the bucket is full again.
        let t1 = t0 + Duration::from_secs(10);
        assert!(try_admit_inbound(&mut buckets, 1, StreamProtocol::Ping, t1));
        assert!(try_admit_inbound(&mut buckets, 1, StreamProtocol::Ping, t1));
        assert!(!try_admit_inbound(&mut buckets, 1, StreamProtocol::Ping, t1));
    }

    #[test]
    fn inbound_continuous_refill_partial() {
        // BlocksByRange = 128 / 10 s ⇒ one token per ~78 ms.
        // Drain then wait 200 ms — expect ~2 tokens to have been credited.
        let mut buckets = HashMap::new();
        let t0 = Instant::now();
        for _ in 0..128 {
            assert!(try_admit_inbound(&mut buckets, 5, StreamProtocol::BeaconBlocksByRange, t0));
        }
        assert!(!try_admit_inbound(&mut buckets, 5, StreamProtocol::BeaconBlocksByRange, t0));
        let t1 = t0 + Duration::from_millis(200);
        assert!(try_admit_inbound(&mut buckets, 5, StreamProtocol::BeaconBlocksByRange, t1));
        assert!(try_admit_inbound(&mut buckets, 5, StreamProtocol::BeaconBlocksByRange, t1));
        // ~2 tokens credited; the third call at the same instant should fail.
        assert!(!try_admit_inbound(&mut buckets, 5, StreamProtocol::BeaconBlocksByRange, t1));
    }

    #[test]
    fn inbound_per_peer_independent() {
        // Draining peer A's bucket must not affect peer B.
        let mut buckets = HashMap::new();
        let now = Instant::now();
        assert!(try_admit_inbound(&mut buckets, 1, StreamProtocol::Ping, now));
        assert!(try_admit_inbound(&mut buckets, 1, StreamProtocol::Ping, now));
        assert!(!try_admit_inbound(&mut buckets, 1, StreamProtocol::Ping, now));
        assert!(try_admit_inbound(&mut buckets, 2, StreamProtocol::Ping, now));
        assert!(try_admit_inbound(&mut buckets, 2, StreamProtocol::Ping, now));
    }
}
