use std::{
    ops::Deref,
    time::{Duration, Instant},
};

use flux_profiler::timed;
use silver_common::{
    DataKind, Origin, P2pSend, PeerControl, PeerEvent, PeerStatus, RpcInbound, RpcOutbound,
    RpcRequest, RpcRequestInbound, RpcRequestOutbound, RpcResponse, RpcResponseInbound,
    RpcResponseOutbound, RpcSeverity, Scope, StreamProtocol, SyncRequest,
    rpc_rate_limit::{RPC_ERR_RATE_LIMITED, RpcRateLimit},
    ssz_view::{MetadataView, StatusView},
};

use crate::{PeerManager, manager::OutboundAttempt};

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
    /// inline (response on `emit`); block/data-column requests are
    /// admitted but not yet forwarded (TODO). For responses this maps
    /// errors to severity, updates peer database via `handle_event`,
    /// and releases the outbound in-flight slot on a terminal chunk.
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

    pub(crate) fn track_outbound_attempt(&mut self, attempt: OutboundAttempt) {
        self.outbound_attempts.retain(|existing| {
            existing.request_id != attempt.request_id ||
                existing.peer_id != attempt.peer_id ||
                existing.request.protocol() != attempt.request.protocol()
        });
        self.outbound_attempts.push(attempt);
    }

    fn progress_outbound_attempt(
        &mut self,
        request_id: u64,
        peer_id: usize,
        protocol: StreamProtocol,
        now: Instant,
    ) {
        if let Some(attempt) = self.outbound_attempts.iter_mut().find(|attempt| {
            attempt.request_id == request_id &&
                attempt.peer_id == peer_id &&
                attempt.request.protocol() == protocol
        }) {
            attempt.last_progress_at = now;
        }
    }

    fn finish_attempt_at(&mut self, pos: usize, delivered: bool) {
        let attempt = self.outbound_attempts.swap_remove(pos);
        let clean = delivered && attempt.siblings_clean;

        let mut last = true;
        for sibling in &mut self.outbound_attempts {
            if sibling.request_id == attempt.request_id {
                sibling.siblings_clean &= clean;
                last = false;
            }
        }
        tracing::debug!(
            request_id = attempt.request_id,
            peer_id = attempt.peer_id,
            protocol = ?attempt.request.protocol(),
            delivered,
            last,
            "outbound attempt finished"
        );
        if last {
            self.finished_requests.push((attempt.request_id, attempt.peer_id, clean));
        }
    }

    fn finish_attempts_where(
        &mut self,
        delivered: bool,
        mut pred: impl FnMut(&OutboundAttempt) -> bool,
    ) {
        while let Some(pos) = self.outbound_attempts.iter().position(&mut pred) {
            self.finish_attempt_at(pos, delivered);
        }
    }

    pub(crate) fn finish_attempt(
        &mut self,
        request_id: u64,
        peer_id: usize,
        protocol: StreamProtocol,
        delivered: bool,
    ) {
        if let Some(pos) = self.outbound_attempts.iter().position(|attempt| {
            attempt.request_id == request_id &&
                attempt.peer_id == peer_id &&
                attempt.request.protocol() == protocol
        }) {
            self.finish_attempt_at(pos, delivered);
        }
    }

    pub(crate) fn fail_attempt_on_stream_close(
        &mut self,
        peer_id: usize,
        protocol: StreamProtocol,
    ) {
        if let Some(pos) = self.outbound_attempts.iter().position(|attempt| {
            attempt.peer_id == peer_id && attempt.request.protocol() == protocol
        }) {
            self.finish_attempt_at(pos, false);
        }
    }

    pub(crate) fn fail_attempts_on_disconnect(&mut self, peer_id: usize) {
        self.finish_attempts_where(false, |attempt| attempt.peer_id == peer_id);
    }

    pub(crate) fn sweep_stalled_attempts(&mut self, now: Instant) {
        let timeout = Duration::from_millis(self.syncing.inflight_progress_timeout_ms);
        while let Some(pos) = self
            .outbound_attempts
            .iter()
            .position(|attempt| now.saturating_duration_since(attempt.last_progress_at) >= timeout)
        {
            let (peer_id, protocol) = (
                self.outbound_attempts[pos].peer_id,
                self.outbound_attempts[pos].request.protocol(),
            );
            self.finish_attempt_at(pos, false);

            if let Some(peer) = self.peers.get_mut(&peer_id) {
                let ord = protocol.ordinal() as usize;
                peer.outbound_in_flight[ord] = peer.outbound_in_flight[ord].saturating_sub(1);
            }
            self.on_rpc_misbehaviour(
                peer_id,
                RpcSeverity::HighTolerance,
                "outbound request progress stall",
            );
        }
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
    use super::*;

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
}
