use std::{ops::Deref, time::Instant};

use flux_profiler::timed;
use silver_common::{
    DataKind, Origin, P2pSend, PeerControl, PeerEvent, PeerStatus, RpcInbound, RpcOutbound,
    RpcRequest, RpcRequestInbound, RpcRequestOutbound, RpcResponse, RpcResponseInbound,
    RpcResponseOutbound, RpcSeverity, Scope, StreamProtocol, SyncRequest,
    rpc_rate_limit::{RPC_ERR_RATE_LIMITED, RpcRateLimit},
    ssz_view::{MetadataView, StatusView},
};

use crate::{PeerManager, manager::attempts::OutboundAttempt};

/// Per-peer cap on outstanding RPC requests per protocol. Bounds load on any
/// single peer and keeps fan-out useful when many ranges are pending.
const MAX_RPC_PROTOCOL_IN_FLIGHT: u32 = 2;

/// Cap on concurrent by-root column requests across all peers.
pub(crate) const MAX_COLUMN_ROOT_REQUESTS: usize = 4;

/// Result-byte values for eth2 RPC error chunks. Per
/// `consensus-specs/p2p-interface.md`, only 0x01..=0x03 are spec-defined and
/// [0x04, 0x7f] is RESERVED; codes >= 0x80 are client extensions. 0x8b is
/// lighthouse's `RateLimited`. Prysm overloads 0x01 (`InvalidRequest`) for
/// rate limiting, which is indistinguishable from a genuine malformed request.
const RPC_ERR_INVALID_REQUEST: u8 = 0x01;
const RPC_ERR_SERVER_ERROR: u8 = 0x02;
const RPC_ERR_RESOURCE_UNAVAILABLE: u8 = 0x03;
/// Map a received `RpcResponse::Error` to an `RpcSeverity`. Returns `None`
/// when the error is informational and shouldn't impact peer score (notably
/// `ResourceUnavailable` for blob/column-by-root, where missing data is
/// expected). All RpcResponse::Error events at this layer are responses to
/// requests **we** initiated (the inbound branch handles request parsing
/// errors separately via the network tile), so direction is always
/// "outgoing-from-us"; what stays conditional is `owed`, because backfill asks
/// for history a peer may lawfully have dropped.
fn severity_for_error_response(
    code: u8,
    protocol: StreamProtocol,
    owed: bool,
) -> Option<RpcSeverity> {
    match code {
        // Peer says our request was malformed. Either we're buggy or peer is
        // — LowTolerance gives a few strikes before disconnect.
        RPC_ERR_INVALID_REQUEST => Some(RpcSeverity::LowTolerance),
        // Peer's internal trouble. Not malicious — tolerate, but track.
        RPC_ERR_SERVER_ERROR => Some(RpcSeverity::MidTolerance),
        // Nothing was owed, so nothing was withheld: see `owed_the_request`.
        RPC_ERR_RESOURCE_UNAVAILABLE if !owed => None,
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
        // Lighthouse's rate-limit signal (0x8b). We're hammering them, not
        // misbehaviour — moderate, decaying penalty rotates us off this backer
        // without banning. Prysm's code-0x01 rate limit can't be told apart
        // from a real malformed request and lands on the arm above.
        RPC_ERR_RATE_LIMITED => Some(RpcSeverity::MidTolerance),
        // Unknown / reserved code. Spec may add new codes — forward-compat
        // mild penalty rather than crash.
        _ => Some(RpcSeverity::HighTolerance),
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

impl PeerManager {
    fn outbound_has_capacity(
        &self,
        peer: usize,
        protocol: StreamProtocol,
        tokens: u64,
        now: Instant,
        max_in_flight: u32,
    ) -> bool {
        let Some(peer_state) = self.peers.get(&peer) else {
            return false;
        };
        let idx = protocol.ordinal() as usize;
        if peer_state.outbound_in_flight[idx] >= max_in_flight {
            return false;
        }
        match peer_state.outbound_rpc_limits.peek_outbound(protocol, tokens, now) {
            RpcRateLimit::Allowed => true,
            denied => {
                tracing::debug!(
                    peer,
                    ?protocol,
                    tokens,
                    ?denied,
                    "outbound rpc request rate limited"
                );
                false
            }
        }
    }

    fn try_admit(
        &mut self,
        peer: usize,
        protocol: StreamProtocol,
        tokens: u64,
        now: Instant,
        claim_in_flight: bool,
    ) -> bool {
        let Some(peer_state) = self.peers.get_mut(&peer) else {
            return false;
        };
        match peer_state.outbound_rpc_limits.admit_outbound(protocol, tokens, now) {
            RpcRateLimit::Allowed => {
                if claim_in_flight {
                    peer_state.outbound_in_flight[protocol.ordinal() as usize] += 1;
                }
                true
            }
            denied => {
                tracing::debug!(peer, ?protocol, tokens, ?denied, "outbound rpc rate limited");
                false
            }
        }
    }

    fn holds_slots_from(&self, peer: usize, asking_for: u64) -> bool {
        match self.database.earliest_available_slot(peer) {
            Some(earliest) if asking_for < earliest => {
                tracing::trace!(peer, asking_for, earliest, "peer pruned the slots asked");
                false
            }
            _ => true,
        }
    }

    /// Whether `peer` was obliged to hold what request `request_id` asked it
    /// for.
    fn owed_the_request(&self, peer: usize, request_id: u64) -> bool {
        let Some(attempt) =
            self.outbound_attempts.iter().find(|a| a.request_id == request_id && a.peer_id == peer)
        else {
            return true;
        };
        if attempt.request.origin == Origin::Live {
            return true;
        }
        self.database
            .earliest_available_slot(peer)
            .is_some_and(|earliest| self.first_slot_asked(&attempt.request) >= earliest)
    }

    fn first_slot_asked(&self, request: &SyncRequest) -> u64 {
        match request.scope {
            Scope::Range { start, .. } => start,
            Scope::Root(_) => self.local_head_imported_slot,
        }
    }

    /// The peer covering the most of `remaining` for `request`, and the subset
    /// it can serve. Eligible peers advertise the protocol, custody some of
    /// `remaining`, hold the slots asked for, and have outbound capacity left.
    fn best_peer_for_data_columns(
        &self,
        request: &SyncRequest,
        remaining: u128,
        exclude: &[usize],
        now: Instant,
    ) -> Option<(usize, u128)> {
        let protocol = request.protocol();
        let max_in_flight = match request.origin {
            Origin::Backfill => MAX_RPC_PROTOCOL_IN_FLIGHT / 2,
            Origin::Live => MAX_RPC_PROTOCOL_IN_FLIGHT,
        };
        // By-range only: a peer whose claimed head is below the range start
        // could not cover one requested slot, so its `Complete` proves nothing.
        let min_head = match request.scope {
            Scope::Range { start, .. } => start,
            Scope::Root(_) => 0,
        };

        let asking_for = self.first_slot_asked(request);

        self.database
            .live_peers_supporting(protocol)
            .filter_map(|p| {
                if exclude.contains(&p) {
                    return None;
                }
                if min_head > 0 &&
                    self.database.peer_status_bytes(p).map(StatusView::head_slot).unwrap_or(0) <
                        min_head
                {
                    return None;
                }

                if !self.holds_slots_from(p, asking_for) {
                    return None;
                }

                let overlap = self.database.data_column_custody_groups_intersection(p, remaining);
                tracing::trace!(peer = p, overlap, remaining, "peer data columns overlap");
                if overlap == 0 {
                    return None;
                }

                let tokens = SyncRequest { columns: overlap, ..*request }.tokens();
                if !self.outbound_has_capacity(p, protocol, tokens, now, max_in_flight) {
                    tracing::trace!(
                        peer = p,
                        tokens,
                        max_in_flight,
                        origin = ?request.origin,
                        "data columns peer lacks outbound rpc capacity"
                    );
                    return None;
                }

                Some((p, overlap, self.peers.get(&p)?.cached_score))
            })
            .max_by(|a, b| {
                a.1.count_ones()
                    .cmp(&b.1.count_ones())
                    .then_with(|| a.2.partial_cmp(&b.2).unwrap_or(std::cmp::Ordering::Equal))
            })
            .map(|(p, overlap, _)| (p, overlap))
    }

    /// Dispatch an inbound RPC event. For requests this gates on the
    /// per-peer rate limit, then handles Status/Ping/Goodbye/MetaData
    /// inline (response on `emit`); block/column/envelope requests are
    /// ignored here — the storage tile consumes the same `RpcInbound`
    /// stream and serves them. For responses this maps errors to severity,
    /// updates peer database via `handle_event`, and releases the outbound
    /// in-flight slot on a terminal chunk.
    pub fn on_rpc_inbound(
        &mut self,
        rpc: RpcInbound,
        now: Instant,
        emit: &mut impl FnMut(PeerControl),
    ) {
        tracing::trace!(?rpc, "received rpc inbound");

        match rpc {
            RpcInbound::Request(RpcRequestInbound { stream_id, request }) => {
                tracing::debug!(?stream_id, "inbound rpc request");
                match request {
                    RpcRequest::StatusV1(status_v1) => {
                        self.handle_event(
                            PeerEvent::P2pPeerStatus {
                                p2p_peer: stream_id.peer(),
                                status_ssz: PeerStatus::V1(status_v1),
                            },
                            now,
                            emit,
                        );
                        if let Some(status) = self.status() {
                            let status_v1 = StatusView::as_v1(status).try_into().unwrap();
                            emit(PeerControl::P2pSend(P2pSend::Rpc(RpcOutbound::Response(
                                RpcResponseOutbound {
                                    stream_id,
                                    response: RpcResponse::StatusV1(status_v1),
                                },
                            ))));
                        } else {
                            let mut msg = [0u8; 256];
                            let err_bytes = "peer not initialised".as_bytes();
                            msg[..err_bytes.len()].copy_from_slice(err_bytes);
                            emit(PeerControl::P2pSend(P2pSend::Rpc(RpcOutbound::Response(
                                RpcResponseOutbound {
                                    stream_id,
                                    response: RpcResponse::Error {
                                        error: RPC_ERR_SERVER_ERROR,
                                        msg,
                                        len: err_bytes.len(),
                                    },
                                },
                            ))));
                        }
                    }
                    RpcRequest::StatusV2(status_v2) => {
                        self.handle_event(
                            PeerEvent::P2pPeerStatus {
                                p2p_peer: stream_id.peer(),
                                status_ssz: PeerStatus::V2(status_v2),
                            },
                            now,
                            emit,
                        );
                        if let Some(status) = self.status() {
                            emit(PeerControl::P2pSend(P2pSend::Rpc(RpcOutbound::Response(
                                RpcResponseOutbound {
                                    stream_id,
                                    response: RpcResponse::StatusV2(*status),
                                },
                            ))));
                        } else {
                            let mut msg = [0u8; 256];
                            let err_bytes = "peer not initialised".as_bytes();
                            msg[..err_bytes.len()].copy_from_slice(err_bytes);
                            emit(PeerControl::P2pSend(P2pSend::Rpc(RpcOutbound::Response(
                                RpcResponseOutbound {
                                    stream_id,
                                    response: RpcResponse::Error {
                                        error: RPC_ERR_SERVER_ERROR,
                                        msg,
                                        len: err_bytes.len(),
                                    },
                                },
                            ))));
                        }
                    }
                    RpcRequest::Ping(ping) => {
                        let current_peer_metadata_seq = self.peer_metadata_seq(stream_id.peer());
                        let metadata_seq = u64::from_le_bytes(ping);

                        let our_seq = MetadataView::seq_number(self.metadata()).to_le_bytes();

                        tracing::debug!(?stream_id, "P2pSend ping response");
                        emit(PeerControl::P2pSend(P2pSend::Rpc(RpcOutbound::Response(
                            RpcResponseOutbound { stream_id, response: RpcResponse::Ping(our_seq) },
                        ))));

                        if !matches!(current_peer_metadata_seq, Some(seq) if seq == metadata_seq) &&
                            self.try_admit(
                                stream_id.peer(),
                                StreamProtocol::Metadata,
                                1,
                                now,
                                true,
                            )
                        {
                            emit(PeerControl::P2pSend(P2pSend::Rpc(RpcOutbound::Request(
                                RpcRequestOutbound {
                                    application_id: 0,
                                    peer: stream_id.peer(),
                                    request: RpcRequest::MetaData,
                                },
                            ))));
                        }
                    }
                    RpcRequest::Goodbye(goodbye) => {
                        crate::PeerCounters::GoodbyeReceived.inc();
                        self.handle_event(
                            PeerEvent::P2pPeerGoodbye {
                                p2p_peer: stream_id.peer(),
                                status: u64::from_le_bytes(goodbye),
                            },
                            now,
                            emit,
                        )
                    }
                    RpcRequest::MetaData => {
                        let metadata = *self.metadata();
                        emit(PeerControl::P2pSend(P2pSend::Rpc(RpcOutbound::Response(
                            RpcResponseOutbound {
                                stream_id,
                                response: RpcResponse::MetaData(metadata),
                            },
                        ))));
                    }
                    RpcRequest::BlocksByRange(_) |
                    RpcRequest::BlockByRoot(_) |
                    RpcRequest::DataColumnsByRange { .. } |
                    RpcRequest::DataColumnsByRoot(_) |
                    RpcRequest::ExecutionPayloadEnvelopesByRange(_) |
                    RpcRequest::ExecutionPayloadEnvelopesByRoot(_) => {}
                }
            }
            RpcInbound::Response(RpcResponseInbound { application_id, stream_id, response }) => {
                let terminal_protocol = is_terminal_response(stream_id.protocol(), &response)
                    .then_some(stream_id.protocol());
                let completed_ok = matches!(response, RpcResponse::Complete);
                let progress_protocol = matches!(
                    response,
                    RpcResponse::BeaconBlock { .. } |
                        RpcResponse::DataColumnSidecar { .. } |
                        RpcResponse::ExecutionPayloadEnvelope { .. }
                )
                .then_some(stream_id.protocol());
                match response {
                    RpcResponse::StatusV1(status_v1) => self.handle_event(
                        PeerEvent::P2pPeerStatus {
                            p2p_peer: stream_id.peer(),
                            status_ssz: PeerStatus::V1(status_v1),
                        },
                        now,
                        emit,
                    ),
                    RpcResponse::StatusV2(status_v2) => self.handle_event(
                        PeerEvent::P2pPeerStatus {
                            p2p_peer: stream_id.peer(),
                            status_ssz: PeerStatus::V2(status_v2),
                        },
                        now,
                        emit,
                    ),
                    RpcResponse::Ping(ping) => {
                        let current_peer_metadata_seq = self.peer_metadata_seq(stream_id.peer());
                        let metadata_seq = u64::from_le_bytes(ping);
                        if !matches!(current_peer_metadata_seq, Some(seq) if seq == metadata_seq) &&
                            self.try_admit(
                                stream_id.peer(),
                                StreamProtocol::Metadata,
                                1,
                                now,
                                true,
                            )
                        {
                            emit(PeerControl::P2pSend(P2pSend::Rpc(RpcOutbound::Request(
                                RpcRequestOutbound {
                                    application_id: 0,
                                    peer: stream_id.peer(),
                                    request: RpcRequest::MetaData,
                                },
                            ))));
                        }
                    }
                    RpcResponse::MetaData(metadata_ssz) => self.handle_event(
                        PeerEvent::P2pPeerMetadata { p2p_peer: stream_id.peer(), metadata_ssz },
                        now,
                        emit,
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

                        if let Some(severity) = severity_for_error_response(
                            error,
                            stream_id.protocol(),
                            self.owed_the_request(stream_id.peer(), application_id),
                        ) {
                            self.handle_event(
                                PeerEvent::RpcMisbehaviour { p2p_peer: stream_id.peer(), severity },
                                now,
                                emit,
                            );
                        }
                    }
                    RpcResponse::Complete => {
                        tracing::debug!("complete for {stream_id:?}");
                    }
                    _ => {}
                }
                if let Some(protocol) = terminal_protocol {
                    if let Some(peer) = self.peers.get_mut(&stream_id.peer()) {
                        peer.outbound_in_flight[protocol.ordinal() as usize] =
                            peer.outbound_in_flight[protocol.ordinal() as usize].saturating_sub(1);

                        tracing::debug!(
                            ?stream_id,
                            "peer in-flight count is now: {}",
                            peer.outbound_in_flight[protocol.ordinal() as usize]
                        );
                    }
                    self.finish_attempt(application_id, stream_id.peer(), protocol, completed_ok);
                }
                if let Some(protocol) = progress_protocol {
                    self.progress_outbound_attempt(application_id, stream_id.peer(), protocol, now);
                }
            }
        }
    }

    fn control_event(request: SyncRequest, request_id: u64, peer: usize) -> PeerControl {
        let rpc = |req| {
            PeerControl::P2pSend(P2pSend::Rpc(RpcOutbound::Request(RpcRequestOutbound {
                application_id: request_id,
                peer,
                request: req,
            })))
        };
        match (request.kind, request.scope) {
            (DataKind::Block, Scope::Range { start, count }) => {
                rpc(RpcRequest::blocks_by_range(start, count))
            }
            (DataKind::Envelope, Scope::Range { start, count }) => {
                rpc(RpcRequest::envelopes_by_range(start, count))
            }
            (DataKind::Columns, Scope::Range { start, count }) => {
                rpc(RpcRequest::data_columns_by_range(start, count, request.columns))
            }
            (DataKind::Block, Scope::Root(block_root)) => {
                PeerControl::P2pBlockByRootRequest { app_id: request_id, peer, block_root }
            }
            (DataKind::Envelope, Scope::Root(block_root)) => {
                PeerControl::P2pEnvelopeByRootRequest { app_id: request_id, peer, block_root }
            }
            (DataKind::Columns, Scope::Root(block_root)) => PeerControl::P2pDataColumnsRequest {
                app_id: request_id,
                peer,
                block_root,
                columns: request.columns,
            },
        }
    }

    fn send(
        &mut self,
        peer: usize,
        request: SyncRequest,
        request_id: u64,
        now: Instant,
        emit: &mut impl FnMut(PeerControl),
    ) -> bool {
        let protocol = request.protocol();
        if !self.try_admit(peer, protocol, request.tokens(), now, true) {
            return false;
        }
        emit(Self::control_event(request, request_id, peer));
        self.track_outbound_attempt(OutboundAttempt {
            request_id,
            peer_id: peer,
            request,
            last_progress_at: now,
            siblings_clean: true,
        });
        true
    }

    #[timed]
    pub fn place(
        &mut self,
        request: SyncRequest,
        request_id: u64,
        now: Instant,
        emit: &mut impl FnMut(PeerControl),
    ) -> bool {
        if self.column_root_requests_saturated(&request) {
            return false;
        }
        match request.kind {
            DataKind::Columns => self.place_across_custody(request, request_id, now, emit),
            DataKind::Block | DataKind::Envelope => {
                self.place_with_one(request, request_id, now, emit)
            }
        }
    }

    fn column_root_requests_saturated(&self, request: &SyncRequest) -> bool {
        let Scope::Root(root) = request.scope else { return false };
        if request.kind != DataKind::Columns {
            return false;
        }

        let mut seen = [0u64; MAX_COLUMN_ROOT_REQUESTS];
        let mut distinct = 0;
        for attempt in &self.outbound_attempts {
            let held = &attempt.request;
            if held.kind != DataKind::Columns {
                continue;
            }
            let Scope::Root(held_root) = held.scope else { continue };
            if held_root == root {
                return true;
            }
            if seen[..distinct].contains(&attempt.request_id) {
                continue;
            }
            if distinct == MAX_COLUMN_ROOT_REQUESTS {
                return true;
            }
            seen[distinct] = attempt.request_id;
            distinct += 1;
        }
        false
    }

    fn place_with_one(
        &mut self,
        request: SyncRequest,
        request_id: u64,
        now: Instant,
        emit: &mut impl FnMut(PeerControl),
    ) -> bool {
        let (protocol, tokens) = (request.protocol(), request.tokens());
        let asking_for = self.first_slot_asked(&request);
        // A forward range has to come from a peer claiming the chain we are
        // chasing; backfill and by-root only need a peer that can serve it.
        let peer = match request.scope {
            Scope::Range { start, count } if request.origin == Origin::Live => {
                self.pick_sync_peer(start, count, now)
            }
            _ => self.best_peer_for(protocol, |i| {
                self.holds_slots_from(i, asking_for) &&
                    self.outbound_has_capacity(
                        i,
                        protocol,
                        tokens,
                        now,
                        MAX_RPC_PROTOCOL_IN_FLIGHT,
                    )
            }),
        };
        let Some(peer) = peer else {
            emit(PeerControl::DiscoverNodes);
            return false;
        };
        self.send(peer, request, request_id, now, emit)
    }

    fn place_across_custody(
        &mut self,
        request: SyncRequest,
        request_id: u64,
        now: Instant,
        emit: &mut impl FnMut(PeerControl),
    ) -> bool {
        let mut remaining = request.columns;
        let mut placed = false;
        self.column_fanout_tried.clear();

        while remaining != 0 {
            let Some((peer, overlap)) = self.best_peer_for_data_columns(
                &request,
                remaining,
                &self.column_fanout_tried,
                now,
            ) else {
                break;
            };
            placed |=
                self.send(peer, SyncRequest { columns: overlap, ..request }, request_id, now, emit);
            self.column_fanout_tried.push(peer);
            remaining &= !overlap;
        }

        if remaining != 0 {
            tracing::debug!(request_id, remaining, "no peer custodies the rest of the request");
            emit(PeerControl::DiscoverNodes);
        }
        placed
    }

    /// Highest-scoring connected peer that (a) backs the current sync
    /// target and (b) has BlocksByRange outbound capacity. `None` if no
    /// target is pinned or no eligible peer is connected.
    pub(crate) fn pick_sync_peer(&self, start: u64, count: u64, now: Instant) -> Option<usize> {
        let target = self.current_sync_target();
        if target.is_following() {
            return None;
        }

        let mut best: Option<(usize, f64)> = None;
        for (peer, ssz) in self.database.iter_live_status_bytes() {
            if !self.holds_slots_from(peer, start) {
                continue;
            }
            if !target.is_served_by(ssz) {
                tracing::debug!(
                    peer,
                    ?target,
                    peer_finalized_epoch = StatusView::finalized_epoch(ssz),
                    peer_head_slot = StatusView::head_slot(ssz),
                    "pick_sync_peer peer cannot serve sync target range"
                );
                continue;
            }
            let Some(peer_state) = self.peers.get(&peer) else {
                continue;
            };
            if !self.outbound_has_capacity(
                peer,
                StreamProtocol::BeaconBlocksByRange,
                count,
                now,
                MAX_RPC_PROTOCOL_IN_FLIGHT,
            ) {
                tracing::debug!(peer, "sync peer lacks BlocksByRange outbound capacity");
                continue;
            }
            let s = peer_state.cached_score;
            if best.is_none_or(|(_, bs)| s > bs) {
                best = Some((peer, s));
            }
        }
        best.map(|(p, _)| p)
    }

    /// Send a Ping to every connected peer using the current local
    /// metadata seq. No-op if local metadata hasn't been initialised.
    /// Each emission bumps the per-peer Ping in-flight counter; release
    /// happens in `on_rpc_inbound` on the response chunk.
    pub fn fan_out_ping(&mut self, now: Instant, emit: &mut impl FnMut(PeerControl)) {
        let metadata = self.metadata();
        let ping = RpcRequest::Ping(MetadataView::seq_number(metadata).to_le_bytes());
        let peers: Vec<usize> = self.live_peers().collect();
        for peer in peers {
            if !self.outbound_has_capacity(
                peer,
                StreamProtocol::Ping,
                1,
                now,
                MAX_RPC_PROTOCOL_IN_FLIGHT,
            ) || !self.try_admit(peer, StreamProtocol::Ping, 1, now, true)
            {
                continue;
            }
            emit(PeerControl::P2pSend(P2pSend::Rpc(RpcOutbound::Request(RpcRequestOutbound {
                application_id: 0,
                peer,
                request: ping,
            }))));
        }
    }

    /// Send a Status (V2) to every connected peer using the current local
    /// status. Runs while syncing too — peers use our advancing
    /// finalized/head to score us; suppressing would let their view rot.
    pub fn fan_out_status(&mut self, now: Instant, emit: &mut impl FnMut(PeerControl)) {
        let Some(status) = self.status().copied() else {
            return;
        };
        let request = RpcRequest::StatusV2(status);
        let peers: Vec<usize> = self.live_peers().collect();
        for peer in peers {
            if !self.try_admit(peer, StreamProtocol::StatusV2, 1, now, false) {
                continue;
            }
            emit(PeerControl::P2pSend(P2pSend::Rpc(RpcOutbound::Request(RpcRequestOutbound {
                application_id: 0,
                peer,
                request,
            }))));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use silver_common::{Enr, Identify, IpBytes, Keypair, P2pStreamId, RequestId};
    use silver_config::ScoreParams;

    use super::*;
    use crate::manager::{attempts::OutboundAttempt, fixture::*};

    #[test]
    fn invalid_request_is_low_tolerance() {
        // Same severity for any protocol — peer claims our request was bad.
        assert!(matches!(
            severity_for_error_response(RPC_ERR_INVALID_REQUEST, StreamProtocol::Ping, true),
            Some(RpcSeverity::LowTolerance)
        ));
        assert!(matches!(
            severity_for_error_response(
                RPC_ERR_INVALID_REQUEST,
                StreamProtocol::BeaconBlocksByRange,
                true
            ),
            Some(RpcSeverity::LowTolerance)
        ));
    }

    #[test]
    fn server_error_is_mid_tolerance() {
        assert!(matches!(
            severity_for_error_response(RPC_ERR_SERVER_ERROR, StreamProtocol::StatusV2, true),
            Some(RpcSeverity::MidTolerance)
        ));
    }

    #[test]
    fn resource_unavailable_blocks_outbound_is_fatal() {
        // Ban: peer admits they can't serve us blocks we expected.
        assert!(matches!(
            severity_for_error_response(
                RPC_ERR_RESOURCE_UNAVAILABLE,
                StreamProtocol::BeaconBlocksByRange,
                true
            ),
            Some(RpcSeverity::Fatal)
        ));
        assert!(matches!(
            severity_for_error_response(
                RPC_ERR_RESOURCE_UNAVAILABLE,
                StreamProtocol::BeaconBlocksByRoot,
                true
            ),
            Some(RpcSeverity::Fatal)
        ));
    }

    /// History nobody undertook to keep. Scoring the miss as `Fatal` bans a
    /// peer for pruning, and it lands on exactly the peers we backfill from.
    #[test]
    fn resource_unavailable_for_data_not_owed_is_never_a_penalty() {
        for protocol in [
            StreamProtocol::BeaconBlocksByRange,
            StreamProtocol::BeaconBlocksByRoot,
            StreamProtocol::DataColumnSidecarsByRange,
            StreamProtocol::ExecutionPayloadEnvelopesByRange,
        ] {
            assert!(
                severity_for_error_response(RPC_ERR_RESOURCE_UNAVAILABLE, protocol, false)
                    .is_none(),
                "{protocol:?}: unkept history is not misbehaviour"
            );
            assert!(
                severity_for_error_response(RPC_ERR_RESOURCE_UNAVAILABLE, protocol, true).is_some(),
                "{protocol:?}: what the peer undertook to serve still scores"
            );
        }
    }

    /// Only `ResourceUnavailable` reads as pruning. A request a peer calls
    /// malformed is our bug or theirs whatever span it named.
    #[test]
    fn data_not_owed_does_not_excuse_other_error_codes() {
        assert!(matches!(
            severity_for_error_response(
                RPC_ERR_INVALID_REQUEST,
                StreamProtocol::BeaconBlocksByRange,
                false
            ),
            Some(RpcSeverity::LowTolerance)
        ));
        assert!(matches!(
            severity_for_error_response(
                RPC_ERR_SERVER_ERROR,
                StreamProtocol::BeaconBlocksByRange,
                false
            ),
            Some(RpcSeverity::MidTolerance)
        ));
    }

    #[test]
    fn resource_unavailable_columns_by_root_is_silent() {
        // Sparse custody — no penalty.
        assert!(
            severity_for_error_response(
                RPC_ERR_RESOURCE_UNAVAILABLE,
                StreamProtocol::DataColumnSidecarsByRoot,
                true
            )
            .is_none()
        );
    }

    #[test]
    fn resource_unavailable_columns_by_range_is_mid() {
        assert!(matches!(
            severity_for_error_response(
                RPC_ERR_RESOURCE_UNAVAILABLE,
                StreamProtocol::DataColumnSidecarsByRange,
                true
            ),
            Some(RpcSeverity::MidTolerance)
        ));
    }

    #[test]
    fn resource_unavailable_other_is_high_tolerance() {
        // Status/Ping/Goodbye/MetaData/Identity/GossipSub all share this.
        assert!(matches!(
            severity_for_error_response(RPC_ERR_RESOURCE_UNAVAILABLE, StreamProtocol::Ping, true),
            Some(RpcSeverity::HighTolerance)
        ));
    }

    #[test]
    fn rate_limited_is_mid_tolerance() {
        // Self-throttle, don't ban. Assert the literal wire code (lighthouse
        // `RateLimited` = 139) so a regressed constant is caught here.
        assert_eq!(RPC_ERR_RATE_LIMITED, 139);
        assert!(matches!(
            severity_for_error_response(139, StreamProtocol::BeaconBlocksByRange, true),
            Some(RpcSeverity::MidTolerance)
        ));
        // Prysm overloads InvalidRequest (1) for rate limiting; by code alone
        // that is indistinguishable from a malformed request.
        assert!(matches!(
            severity_for_error_response(1, StreamProtocol::BeaconBlocksByRange, true),
            Some(RpcSeverity::LowTolerance)
        ));
    }

    #[test]
    fn unknown_code_is_high_tolerance() {
        // Forward-compat: spec might add new codes — don't crash, don't ban.
        assert!(matches!(
            severity_for_error_response(0xff, StreamProtocol::Ping, true),
            Some(RpcSeverity::HighTolerance)
        ));
        assert!(matches!(
            severity_for_error_response(0x42, StreamProtocol::BeaconBlocksByRange, true),
            Some(RpcSeverity::HighTolerance)
        ));
    }

    #[test]
    fn peer_data_columns_prioritization_and_slot_reservation() {
        let now = Instant::now();
        let (mut mgr, mut cap) = fixture(vec![], ScoreParams::default());

        // Connect and identify Peer 1
        let kp1 = Keypair::from_secret(&[1u8; 32]).unwrap();
        let enr1 = Enr::builder().cgc(4).build(kp1.secret_key()).unwrap();
        mgr.database.add_enr(enr1);
        mgr.handle_event(
            PeerEvent::P2pNewConnection {
                p2p_peer_id: 1,
                peer_id_full: kp1.peer_id(),
                ip: IpBytes::V4([10, 0, 0, 1]),
                port: 4001,
                local_dial: false,
            },
            now,
            &mut |c| cap.0.push(c),
        );
        let mut identify1 = Identify::default();
        identify1.protocols |= 1 << StreamProtocol::DataColumnSidecarsByRoot.ordinal();
        mgr.handle_event(
            PeerEvent::P2pPeerIdentity { p2p_peer: 1, identify: identify1 },
            now,
            &mut |c| cap.0.push(c),
        );

        // Connect and identify Peer 2
        let kp2 = Keypair::from_secret(&[2u8; 32]).unwrap();
        let enr2 = Enr::builder().cgc(4).build(kp2.secret_key()).unwrap();
        mgr.database.add_enr(enr2);
        mgr.handle_event(
            PeerEvent::P2pNewConnection {
                p2p_peer_id: 2,
                peer_id_full: kp2.peer_id(),
                ip: IpBytes::V4([10, 0, 0, 2]),
                port: 4002,
                local_dial: false,
            },
            now,
            &mut |c| cap.0.push(c),
        );
        let mut identify2 = Identify::default();
        identify2.protocols |= 1 << StreamProtocol::DataColumnSidecarsByRoot.ordinal();
        mgr.handle_event(
            PeerEvent::P2pPeerIdentity { p2p_peer: 2, identify: identify2 },
            now,
            &mut |c| cap.0.push(c),
        );

        let custody_mask1 = mgr.database.data_column_custody_groups_intersection(1, u128::MAX);
        let custody_mask2 = mgr.database.data_column_custody_groups_intersection(2, u128::MAX);
        assert!(custody_mask1 != 0);
        assert!(custody_mask2 != 0);

        // Peer-exclusive custody columns so a request can split cleanly: peer 1
        // covers `m1`, peer 2 covers `m2`, no overlap. A request for `m1 | m2`
        // sent while one peer is at capacity yields partial coverage: the
        // covered part is placed, while the unsent remainder is left for the
        // storage live/backfill wheels to retry.
        let m1 = custody_mask1 & !custody_mask2;
        let m2 = custody_mask2 & !custody_mask1;
        assert!(m1 != 0 && m2 != 0, "test needs peer-exclusive custody columns");
        let both = m1 | m2;
        let dcbr = StreamProtocol::DataColumnSidecarsByRoot.ordinal() as usize;

        // A distinct root per ask: PM refuses a second request for a root already
        // out there, and what this probes is the *per-peer* capacity — which
        // custody overlap makes root-independent, so the roots are free to vary.
        let mut seq = 0;
        let mut ask = |mgr: &mut PeerManager, cap: &mut Captured, origin, columns| {
            let request = SyncRequest {
                kind: DataKind::Columns,
                origin,
                scope: Scope::Root([seq as u8 + 1; 32]),
                columns,
            };
            let id = RequestId::next(DataKind::Columns, origin, &mut seq);
            mgr.place(request, id, now, &mut |c| cap.0.push(c));
        };
        let in_flight =
            |mgr: &PeerManager, peer| mgr.peers.get(&peer).unwrap().outbound_in_flight[dcbr];

        // Per-peer caps: backfill = MAX_RPC_PROTOCOL_IN_FLIGHT / 2 = 1, live = 2.

        // 1) Backfill `m1` → peer 1 (sole custodian), filling its one backfill slot.
        ask(&mut mgr, &mut cap, Origin::Backfill, m1);
        assert_eq!((in_flight(&mgr, 1), in_flight(&mgr, 2)), (1, 0));

        // 2) Backfill `both`: peer 1 is at its backfill cap, so only peer 2's `m2` is
        //    placed; peer 1's `m1` can't be sent and — being backfill — is dropped, not
        //    queued (storage's column backfill re-reports it).
        ask(&mut mgr, &mut cap, Origin::Backfill, both);
        assert_eq!((in_flight(&mgr, 1), in_flight(&mgr, 2)), (1, 1));

        // 3) Live `m1` → peer 1: backfill used 1 of its 2 live slots, so this fits.
        ask(&mut mgr, &mut cap, Origin::Live, m1);
        assert_eq!(in_flight(&mgr, 1), 2);

        // 4) Live `both`: peer 1 is at its live cap (2), so peer 2 takes `m2` and `m1`
        //    is left for the engine to re-offer.
        ask(&mut mgr, &mut cap, Origin::Live, both);
        assert_eq!((in_flight(&mgr, 1), in_flight(&mgr, 2)), (2, 2));
    }

    /// A by-root column request for `root`.
    fn column_root(root: [u8; 32]) -> SyncRequest {
        SyncRequest {
            kind: DataKind::Columns,
            origin: Origin::Live,
            scope: Scope::Root(root),
            columns: 0b1,
        }
    }

    /// Each by-root column request fans out across every peer custodying its
    /// mask, so a burst of needs would become a burst times the custody set. PM
    /// refuses past the cap; the engine re-offers after its own backoff.
    #[test]
    fn concurrent_by_root_column_requests_are_capped() {
        let now = Instant::now();
        let (mut mgr, mut cap) = fixture(vec![], ScoreParams::default());
        connect(&mut mgr, &mut cap, 1, 1, now);

        for seq in 0..crate::manager::rpc::MAX_COLUMN_ROOT_REQUESTS as u64 {
            let id = u64::from(RequestId { kind: DataKind::Columns, origin: Origin::Live, seq });
            mgr.track_outbound_attempt(OutboundAttempt {
                request_id: id,
                peer_id: 1,
                request: column_root([seq as u8; 32]),
                last_progress_at: now,
                siblings_clean: true,
            });
        }

        let id = u64::from(RequestId { kind: DataKind::Columns, origin: Origin::Live, seq: 99 });
        assert!(
            !mgr.place(column_root([0xEE; 32]), id, now, &mut |c| cap.0.push(c)),
            "refused at the cap, not queued"
        );
    }

    /// One root can be reported missing again before the first response lands —
    /// beacon state and the columns tile both re-declare per block. Asking
    /// twice at once would double the work for nothing.
    #[test]
    fn the_same_root_is_not_asked_for_twice_at_once() {
        let now = Instant::now();
        let (mut mgr, mut cap) = fixture(vec![], ScoreParams::default());
        connect(&mut mgr, &mut cap, 1, 1, now);

        const ROOT: [u8; 32] = [0xAB; 32];
        let first = u64::from(RequestId { kind: DataKind::Columns, origin: Origin::Live, seq: 1 });
        mgr.track_outbound_attempt(OutboundAttempt {
            request_id: first,
            peer_id: 1,
            request: column_root(ROOT),
            last_progress_at: now,
            siblings_clean: true,
        });

        let second = u64::from(RequestId { kind: DataKind::Columns, origin: Origin::Live, seq: 2 });
        assert!(
            !mgr.place(column_root(ROOT), second, now, &mut |c| cap.0.push(c)),
            "already out there"
        );
        assert!(
            mgr.place(column_root([0xCD; 32]), second, now, &mut |c| cap.0.push(c)) ||
                mgr.outbound_attempts.len() == 1,
            "another root is not blocked by it"
        );
    }

    /// One peer that serves column ranges, custodies every group, and has
    /// pruned its history below `earliest`. `head_slot` is far ahead, as a
    /// pruned-but-synced peer's is.
    fn connect_column_peer_pruned_below(
        mgr: &mut PeerManager,
        cap: &mut Captured,
        earliest: u64,
        now: Instant,
    ) {
        let kp = Keypair::from_secret(&[9u8; 32]).unwrap();
        mgr.database.add_enr(Enr::builder().cgc(128).build(kp.secret_key()).unwrap());
        mgr.handle_event(
            PeerEvent::P2pNewConnection {
                p2p_peer_id: 1,
                peer_id_full: kp.peer_id(),
                ip: IpBytes::V4([10, 0, 0, 9]),
                port: 4009,
                local_dial: false,
            },
            now,
            &mut |c| cap.0.push(c),
        );
        let mut identify = Identify::default();
        identify.protocols |= 1 << StreamProtocol::DataColumnSidecarsByRange.ordinal();
        mgr.handle_event(PeerEvent::P2pPeerIdentity { p2p_peer: 1, identify }, now, &mut |c| {
            cap.0.push(c)
        });

        let mut ssz = status_v2_ssz([0u8; 4], [0u8; 32], 0, [7u8; 32], 10_000);
        ssz[84..92].copy_from_slice(&earliest.to_le_bytes());
        send_status(mgr, cap, 1, PeerStatus::V2(ssz));
        assert_eq!(mgr.database.earliest_available_slot(1), Some(earliest));
    }

    fn backfill_column_range(start: u64) -> SyncRequest {
        SyncRequest {
            kind: DataKind::Columns,
            origin: Origin::Backfill,
            scope: Scope::Range { start, count: 64 },
            columns: 0b11,
        }
    }

    /// Backfill walks *down*, so a range's slots sit far below our head. Gating
    /// on our head instead of the range asks peers for history they have said
    /// they pruned — and their spec-compliant `ResourceUnavailable` is then
    /// scored as misbehaviour, driving our only backers negative for answering
    /// correctly.
    #[test]
    fn column_range_below_a_peers_earliest_slot_is_not_placed() {
        let now = Instant::now();
        let (mut mgr, mut cap) = fixture(vec![], ScoreParams::default());
        connect_column_peer_pruned_below(&mut mgr, &mut cap, 100, now);
        // Following at the tip while backfill walks the bottom of the chain.
        mgr.set_local_head_imported(9_000);
        cap.0.clear();

        assert!(
            !mgr.place(backfill_column_range(10), 1, now, &mut |c| cap.0.push(c)),
            "a peer that pruned slot 10 cannot serve it"
        );
        assert!(mgr.outbound_attempts.is_empty(), "and nothing goes out to be penalised for");
    }

    /// The other half: the gate must not swallow ranges the peer *can* serve,
    /// or column backfill never places at all.
    #[test]
    fn column_range_above_a_peers_earliest_slot_is_placed() {
        let now = Instant::now();
        let (mut mgr, mut cap) = fixture(vec![], ScoreParams::default());
        connect_column_peer_pruned_below(&mut mgr, &mut cap, 100, now);
        mgr.set_local_head_imported(9_000);
        cap.0.clear();

        assert!(
            mgr.place(backfill_column_range(200), 2, now, &mut |c| cap.0.push(c)),
            "slot 200 is above the peer's floor"
        );
        assert_eq!(mgr.outbound_attempts.len(), 1);
    }

    /// A column range, for tests that build attempts directly.
    fn column_range() -> SyncRequest {
        SyncRequest {
            kind: DataKind::Columns,
            origin: Origin::Live,
            scope: Scope::Range { start: 0, count: 1 },
            columns: 0b11,
        }
    }

    /// One identified peer and one placed by-root block chase.
    fn issue_by_root(mgr: &mut PeerManager, cap: &mut Captured, request_id: u64, now: Instant) {
        connect(mgr, cap, 1, 1, now);
        let mut identify = Identify::default();
        identify.protocols |= 1 << StreamProtocol::BeaconBlocksByRoot.ordinal();
        mgr.handle_event(PeerEvent::P2pPeerIdentity { p2p_peer: 1, identify }, now, &mut |c| {
            cap.0.push(c)
        });
        let request = SyncRequest {
            kind: DataKind::Block,
            origin: Origin::Live,
            scope: Scope::Root([3; 32]),
            columns: 0,
        };
        assert!(mgr.place(request, request_id, now, &mut |c| cap.0.push(c)), "chase placed");
        assert_eq!(mgr.outbound_attempts.len(), 1, "tracked like a range");
    }

    /// The engine holds an in-flight slot per by-root chase and releases it on
    /// the terminator. A peer that abandons the stream sends none — the
    /// network tile has no recv-EOF hook to synthesise one — so PM reporting
    /// the failure is the only thing that frees it.
    #[test]
    fn by_root_chase_is_reported_when_its_stream_dies() {
        let now = Instant::now();
        let (mut mgr, mut cap) = fixture(vec![], ScoreParams::default());
        let id = u64::from(RequestId { kind: DataKind::Block, origin: Origin::Live, seq: 5 });
        issue_by_root(&mut mgr, &mut cap, id, now);

        mgr.handle_event(
            PeerEvent::P2pStreamClosed {
                stream_id: P2pStreamId::new(1, 13, StreamProtocol::BeaconBlocksByRoot, false),
            },
            now,
            &mut |c| cap.0.push(c),
        );

        assert!(mgr.outbound_attempts.is_empty());
        assert_eq!(
            mgr.drain_finished_requests().next(),
            Some((id, 1, false)),
            "reported to the engine, and not as a delivery"
        );
    }

    /// Same for a peer that takes the request and simply never answers.
    #[test]
    fn stalled_by_root_chase_is_swept_and_reported() {
        let now = Instant::now();
        let (mut mgr, mut cap) = fixture(vec![], ScoreParams::default());
        let id = u64::from(RequestId { kind: DataKind::Block, origin: Origin::Live, seq: 6 });
        issue_by_root(&mut mgr, &mut cap, id, now);

        let later = now +
            Duration::from_millis(mgr.syncing.inflight_progress_timeout_ms) +
            Duration::from_millis(1);
        mgr.tick(later, &mut |c| cap.0.push(c));

        assert!(mgr.outbound_attempts.is_empty());
        assert_eq!(mgr.drain_finished_requests().next(), Some((id, 1, false)));
    }

    /// Setup shared by the backfill-range tests: one identified peer and one
    /// issued range.
    fn issue_backfill_range(
        mgr: &mut PeerManager,
        cap: &mut Captured,
        request_id: u64,
        start: u64,
        count: u64,
        now: Instant,
    ) {
        connect(mgr, cap, 1, 1, now);
        let mut identify = Identify::default();
        identify.protocols |= 1 << StreamProtocol::BeaconBlocksByRange.ordinal();
        mgr.handle_event(PeerEvent::P2pPeerIdentity { p2p_peer: 1, identify }, now, &mut |c| {
            cap.0.push(c)
        });
        let request = SyncRequest {
            kind: DataKind::Block,
            origin: Origin::Backfill,
            scope: Scope::Range { start, count },
            columns: 0,
        };
        assert!(mgr.place(request, request_id, now, &mut |c| cap.0.push(c)), "range placed");
        assert_eq!(mgr.outbound_attempts.len(), 1);
        assert_eq!(mgr.outbound_attempts[0].request_id, request_id);
    }

    #[test]
    fn block_backfill_range_attempt_is_tracked_until_complete() {
        let now = Instant::now();
        let (mut mgr, mut cap) = fixture(vec![], ScoreParams::default());
        let id = u64::from(RequestId { kind: DataKind::Block, origin: Origin::Backfill, seq: 7 });
        issue_backfill_range(&mut mgr, &mut cap, id, 20, 3, now);

        mgr.on_rpc_inbound(
            RpcInbound::Response(RpcResponseInbound {
                application_id: id,
                stream_id: P2pStreamId::new(1, 11, StreamProtocol::BeaconBlocksByRange, false),
                response: RpcResponse::Complete,
            }),
            now,
            &mut |c| cap.0.push(c),
        );

        assert!(mgr.outbound_attempts.is_empty());
        assert_eq!(
            mgr.drain_finished_requests().next(),
            Some((id, 1, true)),
            "reported as delivered — the engine reads that as emptiness evidence"
        );
    }

    /// The engine owns retry, so an error terminator releases the attempt and
    /// reports it as undelivered; PM no longer re-queues anything.
    #[test]
    fn block_backfill_range_error_is_reported_not_retried() {
        let now = Instant::now();
        let (mut mgr, mut cap) = fixture(vec![], ScoreParams::default());
        let id = u64::from(RequestId { kind: DataKind::Block, origin: Origin::Backfill, seq: 8 });
        issue_backfill_range(&mut mgr, &mut cap, id, 20, 3, now);

        mgr.on_rpc_inbound(
            RpcInbound::Response(RpcResponseInbound {
                application_id: id,
                stream_id: P2pStreamId::new(1, 12, StreamProtocol::BeaconBlocksByRange, false),
                response: RpcResponse::Error { error: 2, msg: [0; 256], len: 0 },
            }),
            now,
            &mut |c| cap.0.push(c),
        );

        assert!(mgr.outbound_attempts.is_empty());
        assert_eq!(mgr.drain_finished_requests().next(), Some((id, 1, false)));
    }

    /// A stall has no terminator, so this is the one PM has to report itself.
    /// Every kind is swept now, not just backfill.
    #[test]
    fn stalled_range_is_swept_and_reported() {
        let now = Instant::now();
        let (mut mgr, mut cap) = fixture(vec![], ScoreParams::default());
        let id = u64::from(RequestId { kind: DataKind::Block, origin: Origin::Backfill, seq: 9 });
        issue_backfill_range(&mut mgr, &mut cap, id, 30, 2, now);

        let later = now +
            Duration::from_millis(mgr.syncing.inflight_progress_timeout_ms) +
            Duration::from_millis(1);
        mgr.tick(later, &mut |c| cap.0.push(c));

        assert!(mgr.outbound_attempts.is_empty());
        assert_eq!(
            mgr.peers.get(&1).unwrap().outbound_in_flight
                [StreamProtocol::BeaconBlocksByRange.ordinal() as usize],
            0,
            "slot released"
        );
        assert_eq!(mgr.drain_finished_requests().collect::<Vec<_>>(), vec![(id, 1, false)]);
    }

    /// PM is the engine's only liveness signal, so a request fanned across
    /// peers must reach it exactly once — on the last attempt to end, not on
    /// each. Reporting early would free a range still streaming elsewhere.
    #[test]
    fn fanned_out_request_is_reported_once_on_its_last_attempt() {
        let now = Instant::now();
        let (mut mgr, mut cap) = fixture(vec![], ScoreParams::default());
        let id = u64::from(RequestId { kind: DataKind::Columns, origin: Origin::Live, seq: 11 });
        let request = column_range();
        let protocol = request.protocol();

        for peer in 1..=3usize {
            connect(&mut mgr, &mut cap, peer, peer as u8, now);
            mgr.track_outbound_attempt(OutboundAttempt {
                request_id: id,
                peer_id: peer,
                request,
                last_progress_at: now,
                siblings_clean: true,
            });
        }

        for peer in 1..=2usize {
            mgr.finish_attempt(id, peer, protocol, true);
            assert!(
                mgr.drain_finished_requests().next().is_none(),
                "attempt on peer {peer} ended, the rest still stream"
            );
        }
        mgr.finish_attempt(id, 3, protocol, true);
        assert_eq!(
            mgr.drain_finished_requests().collect::<Vec<_>>(),
            vec![(id, 3, true)],
            "the last attempt reports the whole request"
        );
    }

    /// One bad sub-request makes the logical request incomplete, so the report
    /// must not claim delivery however the remaining attempts end. The engine
    /// reads `delivered` as proof the unfilled slots were empty.
    #[test]
    fn one_failed_attempt_makes_the_whole_request_undelivered() {
        let now = Instant::now();
        let (mut mgr, mut cap) = fixture(vec![], ScoreParams::default());
        let id = u64::from(RequestId { kind: DataKind::Columns, origin: Origin::Live, seq: 12 });
        let request = column_range();
        let protocol = request.protocol();

        for peer in 1..=2usize {
            connect(&mut mgr, &mut cap, peer, peer as u8, now);
            mgr.track_outbound_attempt(OutboundAttempt {
                request_id: id,
                peer_id: peer,
                request,
                last_progress_at: now,
                siblings_clean: true,
            });
        }

        mgr.finish_attempt(id, 1, protocol, false);
        mgr.finish_attempt(id, 2, protocol, true);
        assert_eq!(
            mgr.drain_finished_requests().collect::<Vec<_>>(),
            vec![(id, 2, false)],
            "the failure carried through to the last attempt's report"
        );
    }

    /// A peer holding several requests must have every one of them reported on
    /// disconnect. The scan restarts after each removal: indexing a subslice
    /// and removing at that index from the whole vec used to report a foreign
    /// request and leak the real one.
    #[test]
    fn disconnect_reports_every_request_the_peer_held() {
        let now = Instant::now();
        let (mut mgr, mut cap) = fixture(vec![], ScoreParams::default());
        let mine = [
            u64::from(RequestId { kind: DataKind::Block, origin: Origin::Live, seq: 21 }),
            u64::from(RequestId { kind: DataKind::Columns, origin: Origin::Live, seq: 22 }),
        ];
        let theirs = u64::from(RequestId { kind: DataKind::Block, origin: Origin::Live, seq: 23 });

        connect(&mut mgr, &mut cap, 1, 1, now);
        connect(&mut mgr, &mut cap, 2, 2, now);
        // Interleaved so a wrong index lands on the other peer's attempt.
        for (request_id, peer_id) in [(mine[0], 1), (theirs, 2), (mine[1], 1)] {
            mgr.track_outbound_attempt(OutboundAttempt {
                request_id,
                peer_id,
                request: SyncRequest {
                    kind: DataKind::Block,
                    origin: Origin::Live,
                    scope: Scope::Range { start: 0, count: 1 },
                    columns: 0,
                },
                last_progress_at: now,
                siblings_clean: true,
            });
        }

        mgr.fail_attempts_on_disconnect(1);

        let mut reported: Vec<u64> = mgr.drain_finished_requests().map(|(id, ..)| id).collect();
        reported.sort_unstable();
        assert_eq!(reported, vec![mine[0], mine[1]], "both of the peer's requests, and only those");
        assert_eq!(mgr.outbound_attempts.len(), 1, "the other peer's attempt is untouched");
        assert_eq!(mgr.outbound_attempts[0].request_id, theirs);
    }
}
