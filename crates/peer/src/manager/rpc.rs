//! RPC handling for `PeerManager`: per-protocol request handlers
//! (Status/Ping/Goodbye/MetaData replied here; block / data-column
//! requests are admitted by the network tile before reaching this manager),
//! outbound in-flight/rate-limit bookkeeping, PM-driven catchup
//! `BlocksByRange` issuance, and heartbeat-driven Ping/Status fan-out.
//!
//! All state lives on `PeerManager` so the controller tile that drives
//! the spine remains a thin shell.

use std::{
    ops::{Deref, Not},
    time::{Duration, Instant},
};

use fxhash::FxHashSet;
use silver_common::{
    BASE_REQUEST_ID, P2pSend, PeerControl, PeerEvent, PeerStatus, RequestCategory, RpcInbound,
    RpcOutbound, RpcRequest, RpcRequestInbound, RpcRequestOutbound, RpcResponse,
    RpcResponseInbound, RpcResponseOutbound, RpcSeverity, StreamProtocol, SyncUpdate, hex32,
    rpc_rate_limit::{RPC_ERR_RATE_LIMITED, RpcRateLimit},
    ssz_view::{
        BLOCKS_BY_RANGE_REQ_SIZE, BeaconBlocksByRangeRequestView, DC_BY_RANGE_REQ_MAX,
        DataColumnSidecarsByRangeRequestView, MetadataView, StatusView,
    },
};

use crate::{
    manager::{
        ColAttempt, ColSyncReq, OutboundRangeAttempt, PendingBlocksByRange,
        PendingDataColumnsByRange, PendingRangeRequest, SyncReq, SLOTS_PER_EPOCH,
    }, PeerManager
};

/// Per-peer cap on outstanding RPC requests per protocol. Bounds load on any
/// single peer and keeps fan-out useful when many ranges are pending.
const MAX_RPC_PROTOCOL_IN_FLIGHT: u32 = 2;

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

/// Human label for a Goodbye reason code (per eth2 spec).
fn goodbye_reason(code: u64) -> &'static str {
    match code {
        1 => "ClientShutdown",
        2 => "IrrelevantNetwork",
        3 => "Error",
        128 => "Banned",
        129 => "BannedIP",
        250 => "ScoreTooLow",
        251 => "Fault",
        _ => "Unknown",
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

    fn admit_outbound_request(
        &mut self,
        peer: usize,
        protocol: StreamProtocol,
        tokens: u64,
        now: Instant,
    ) -> bool {
        let Some(peer_state) = self.peers.get_mut(&peer) else {
            return false;
        };
        match peer_state.outbound_rpc_limits.admit_outbound(protocol, tokens, now) {
            RpcRateLimit::Allowed => {
                peer_state.outbound_in_flight[protocol.ordinal() as usize] += 1;
                true
            }
            denied => {
                tracing::debug!(
                    peer,
                    ?protocol,
                    tokens,
                    ?denied,
                    "outbound rpc admission raced with selection"
                );
                false
            }
        }
    }

    fn admit_outbound_rate(
        &mut self,
        peer: usize,
        protocol: StreamProtocol,
        tokens: u64,
        now: Instant,
    ) -> bool {
        let Some(peer_state) = self.peers.get_mut(&peer) else {
            return false;
        };
        match peer_state.outbound_rpc_limits.admit_outbound(protocol, tokens, now) {
            RpcRateLimit::Allowed => true,
            denied => {
                tracing::debug!(peer, ?protocol, tokens, ?denied, "outbound rpc rate limited");
                false
            }
        }
    }

    fn enqueue_pending_rpc_request(&mut self, request_id: u64, rpc: RpcRequest) {
        let category = RequestCategory::from_request_id(request_id);
        if category.is_backfill() {
            self.pending_rpc_request
                .retain(|(id, _)| RequestCategory::from_request_id(*id) != category);
        }
        self.pending_rpc_request.push_back((request_id, rpc));
    }

    fn enqueue_pending_range_request(&mut self, mut req: PendingRangeRequest) {
        let category = RequestCategory::from_request_id(req.request_id());
        if category.is_backfill() {
            self.pending_range_requests.retain(|pending| {
                if RequestCategory::from_request_id(pending.request_id()) == category &&
                    pending.protocol() == req.protocol()
                {
                    req = Self::coalesce_pending_range(*pending, req);
                    false
                } else {
                    true
                }
            });
        }
        self.pending_range_requests.push_back(req);
    }

    fn coalesce_pending_range(
        existing: PendingRangeRequest,
        incoming: PendingRangeRequest,
    ) -> PendingRangeRequest {
        match (existing, incoming) {
            (PendingRangeRequest::Blocks(a), PendingRangeRequest::Blocks(b))
                if a.step == b.step =>
            {
                let start_slot = a.start_slot.min(b.start_slot);
                let end_slot =
                    a.start_slot.saturating_add(a.count).max(b.start_slot.saturating_add(b.count));
                PendingRangeRequest::Blocks(PendingBlocksByRange {
                    request_id: b.request_id,
                    start_slot,
                    count: end_slot.saturating_sub(start_slot),
                    step: b.step,
                })
            }
            (PendingRangeRequest::DataColumns(a), PendingRangeRequest::DataColumns(b))
                if a.start_slot == b.start_slot && a.count == b.count =>
            {
                PendingRangeRequest::DataColumns(PendingDataColumnsByRange {
                    request_id: b.request_id,
                    start_slot: b.start_slot,
                    count: b.count,
                    columns: a.columns | b.columns,
                })
            }
            (_, incoming) => incoming,
        }
    }

    fn pending_range_from_rpc(request_id: u64, rpc: RpcRequest) -> Option<PendingRangeRequest> {
        match rpc {
            RpcRequest::BlocksByRange(ssz) => {
                Some(PendingRangeRequest::Blocks(PendingBlocksByRange {
                    request_id,
                    start_slot: BeaconBlocksByRangeRequestView::start_slot(&ssz),
                    count: BeaconBlocksByRangeRequestView::count(&ssz),
                    step: BeaconBlocksByRangeRequestView::step(&ssz),
                }))
            }
            RpcRequest::DataColumnsByRange { ssz, len } => {
                let buf = ssz.get(..len)?;
                if !DataColumnSidecarsByRangeRequestView::check_size(buf) {
                    return None;
                }
                Some(PendingRangeRequest::DataColumns(PendingDataColumnsByRange {
                    request_id,
                    start_slot: DataColumnSidecarsByRangeRequestView::start_slot(buf),
                    count: DataColumnSidecarsByRangeRequestView::count(buf),
                    columns: Self::data_columns_bitmask(buf)?,
                }))
            }
            _ => None,
        }
    }

    fn data_columns_bitmask(buf: &[u8]) -> Option<u128> {
        let mut columns = 0u128;
        for column in DataColumnSidecarsByRangeRequestView::columns(buf).chunks_exact(8) {
            let column = u64::from_le_bytes(column.try_into().ok()?);
            if column >= u128::BITS as u64 {
                return None;
            }
            columns |= 1u128 << column;
        }
        Some(columns)
    }

    /// Pick a peer for a `DataColumnsByRoot`/`ByRange` request that wants
    /// the columns in `columns`. Filters:
    /// - peer advertises `protocol`,
    /// - outbound in-flight on `protocol` is strictly below
    ///   `MAX_RPC_PROTOCOL_IN_FLIGHT`,
    /// - peer's custody set intersects `columns` (otherwise the peer has
    ///   nothing to serve),
    /// - `slot` is within the peer's 'earliest available slot'.
    ///
    /// Among eligible peers, ranks lexicographically by
    /// `(overlap_count desc, rpc_score desc)` — preferring peers that
    /// cover more of the request, breaking ties by score. Custody is
    /// deterministic from node_id+CGC so the overlap signal is
    /// immediately available even before scoring stabilises on a fresh
    /// connection.
    ///
    /// Returns `(peer, overlap)`. `overlap` is the subset of `columns`
    /// this peer can serve — callers may use it to trim the wire
    /// request (the responder will omit columns it doesn't have
    /// regardless, so this is just bandwidth optimisation).
    pub fn best_peer_for_data_columns(
        &self,
        protocol: StreamProtocol,
        columns: u128,
        request_id: u64,
        exclude: &FxHashSet<usize>,
        min_head: u64,
        slots: u64,
        now: Instant,
    ) -> Option<(usize, u128, u64)> {
        let is_backfill = RequestCategory::from_request_id(request_id).is_backfill();
        let max_in_flight =
            if is_backfill { MAX_RPC_PROTOCOL_IN_FLIGHT / 2 } else { MAX_RPC_PROTOCOL_IN_FLIGHT };
        self.database
            .live_peers_supporting(protocol)
            .filter_map(|p| {
                if exclude.contains(&p) {
                    return None;
                }
                // By-range only: skip peers whose claimed head is below the
                // range start (no status => head 0). Their `Complete` could
                // not cover a single requested slot.
                if min_head > 0 &&
                    self.database.peer_status_bytes(p).map(StatusView::head_slot).unwrap_or(0) <
                        min_head
                {
                    return None;
                }

                if let Some(earliest) = self.database.earliest_available_slot(p) &&
                    self.local_head_imported_slot < earliest
                {
                    tracing::warn!(
                        slot = self.local_head_imported_slot,
                        earliest,
                        "slot out of bounds"
                    );
                    return None;
                }

                let overlap = self.database.data_column_custody_groups_intersection(p, columns);
                tracing::trace!(peer = p, overlap, columns, "peer data columns overlap");
                if overlap == 0 {
                    return None;
                }

                let tokens = slots.max(1).saturating_mul(overlap.count_ones() as u64).max(1);
                if !self.outbound_has_capacity(p, protocol, tokens, now, max_in_flight) {
                    tracing::trace!(
                        peer = p,
                        tokens,
                        max_in_flight,
                        is_backfill,
                        "data columns peer lacks outbound rpc capacity"
                    );
                    return None;
                }

                let score = self.peers.get(&p)?.cached_score;
                Some((p, overlap, tokens, score))
            })
            .max_by(|a, b| {
                a.1.count_ones()
                    .cmp(&b.1.count_ones())
                    .then_with(|| a.3.partial_cmp(&b.3).unwrap_or(std::cmp::Ordering::Equal))
            })
            .map(|(p, overlap, tokens, _)| (p, overlap, tokens))
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
                            self.admit_outbound_request(
                                stream_id.peer(),
                                StreamProtocol::Metadata,
                                1,
                                now,
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
                        let code = u64::from_le_bytes(goodbye);
                        crate::PeerCounters::GoodbyeReceived.inc();
                        tracing::info!(
                            peer = stream_id.peer(),
                            code,
                            reason = goodbye_reason(code),
                            "received goodbye"
                        );
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
                    RpcRequest::BlocksByRange(_ssz) => {}
                    RpcRequest::BlockByRoot(_req) => {}
                    RpcRequest::DataColumnsByRange { ssz: _, len: _ } => {}
                    RpcRequest::DataColumnsByRoot(_req) => {}
                }
            }
            RpcInbound::Response(RpcResponseInbound { application_id, stream_id, response }) => {
                let terminal_protocol = is_terminal_response(stream_id.protocol(), &response)
                    .then_some(stream_id.protocol());
                let completed_ok = matches!(response, RpcResponse::Complete);
                let progress_protocol = match response {
                    RpcResponse::BeaconBlock { .. } => Some(StreamProtocol::BeaconBlocksByRange),
                    RpcResponse::DataColumnSidecar { .. } => {
                        Some(StreamProtocol::DataColumnSidecarsByRange)
                    }
                    _ => None,
                };
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
                            self.admit_outbound_request(
                                stream_id.peer(),
                                StreamProtocol::Metadata,
                                1,
                                now,
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

                        if let Some(severity) =
                            severity_for_error_response(error, stream_id.protocol())
                        {
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
                    self.complete_outbound_range_attempt(
                        application_id,
                        stream_id.peer(),
                        protocol,
                        completed_ok,
                        emit,
                    );
                    // Stamp `responded` so the progress-timeout can separate
                    // a peer stall from a local apply-lag.
                    if protocol == StreamProtocol::BeaconBlocksByRange &&
                        let Some(req) = self.inflight_syncreq.as_mut() &&
                        req.peer_id == stream_id.peer() &&
                        req.start_slot == application_id
                    {
                        req.responded = true;
                        req.delivered |= completed_ok;
                    }
                }
                // Column catch-up correlation: sidecar chunks bump progress,
                // terminators resolve the attempt (swept by
                // `maybe_issue_colreq`).
                if stream_id.protocol() == StreamProtocol::DataColumnSidecarsByRange &&
                    let Some(req) = self.col_syncreq.as_mut() &&
                    let Some(att) = req.attempt.as_mut() &&
                    att.peer_id == stream_id.peer() &&
                    application_id == (BASE_REQUEST_ID | req.start_slot)
                {
                    if terminal_protocol.is_some() {
                        att.responded = true;
                        att.delivered |= completed_ok;
                    } else {
                        att.last_progress_at = now;
                    }
                }
                if let Some(protocol) = progress_protocol {
                    self.progress_outbound_range_attempt(
                        application_id,
                        stream_id.peer(),
                        protocol,
                        now,
                    );
                }
            }
        }
    }

    /// Drive the PM-owned `BlocksByRange` request lifecycle.
    /// Called every loop body. Three phases, in order:
    ///
    /// 1. **Progress / completion**: if there's an inflight request, compare
    ///    current local head_slot to the request range. Bump `last_progress_at`
    ///    if head advanced; clear inflight if head has reached the end of the
    ///    requested range (fully delivered).
    /// 2. **Timeout sweep**: if inflight is older than
    ///    `inflight_progress_timeout_ms` with no observed advance, score the
    ///    peer (mid-tolerance) and clear; if it timed out *with* prior advance,
    ///    treat as a benign drain-end (empty slots) and clear without penalty.
    /// 3. **Issuance**: if inflight is `None` and `current_target` is a catchup
    ///    variant, pick the highest-scoring peer of the target that has
    ///    BlocksByRange capacity, build the SSZ request, emit it, and set
    ///    `inflight_syncreq`.
    pub fn maybe_issue_syncreq(&mut self, now: Instant, emit: &mut impl FnMut(PeerControl)) {
        if self.awaiting_local_replay {
            return;
        }

        if matches!(self.current_sync_target(), SyncUpdate::SyncingFinalized { .. }).not() {
            // Columns first: the early returns below (flow
            // control, target reached) must not starve the column driver —
            // with the DA check, missing columns are exactly what stalls the
            // applied head that those returns key off.
            self.maybe_issue_colreq(now, emit);
        }

        let head_slot = self.local_head_imported_slot;

        // Phase 1 + 2: completion (terminator-driven) / progress / timeout.
        if let Some(inflight) = self.inflight_syncreq {
            let end_inclusive = inflight.start_slot + inflight.count - 1;

            if inflight.delivered {
                // `Complete`: peer served `[start, min(end, peer_head)]`. Cap by
                // the serving peer's head — never claim slots past its tip /
                // trailing empty slots. Under-capping on a stale Status is safe
                // (re-fetch is idempotent); over-capping would skip real blocks.
                let peer_head = self
                    .database
                    .peer_status_bytes(inflight.peer_id)
                    .map(StatusView::head_slot)
                    .unwrap_or(0);
                self.synced_through = self.synced_through.max(end_inclusive.min(peer_head));
                self.inflight_syncreq = None;
            } else if inflight.responded {
                // `Error` terminator: peer aborted without serving the full
                // range. Retry; the served prefix is unknown so the watermark
                // is left untouched (re-issue falls back to the applied head).
                self.inflight_syncreq = None;
            } else if head_slot > inflight.last_observed_head_slot {
                let r = self.inflight_syncreq.as_mut().expect("checked above");
                r.last_observed_head_slot = head_slot;
                r.last_progress_at = now;
            } else {
                let timeout = Duration::from_millis(self.syncing.inflight_progress_timeout_ms);
                if now.saturating_duration_since(inflight.last_progress_at) >= timeout {
                    // No terminator and no progress. `head < start` ⇒ not a
                    // single block landed ⇒ peer stall (score). Otherwise the
                    // terminator was lost but the range applied (or apply-lag) —
                    // drop without penalty, advancing the watermark if our head
                    // already covered the range.
                    if head_slot < inflight.start_slot {
                        self.on_rpc_misbehaviour(
                            inflight.peer_id,
                            RpcSeverity::MidTolerance,
                            "blocks-by-range progress stall",
                        );
                    } else {
                        if head_slot >= end_inclusive {
                            self.synced_through = self.synced_through.max(end_inclusive);
                        }
                        self.inflight_syncreq = None;
                    }
                }
            }
        }

        // Phase 3: issuance.
        if self.inflight_syncreq.is_some() {
            return;
        }
        if self.status().is_none() {
            return;
        }
        // For SyncingFinalized, drive past `(target_epoch + 2) * SLOTS_PER_EPOCH`:
        // Casper FFG needs two more epochs of justification/finalization before
        // local `finalized_checkpoint.epoch` can reach `target_epoch`.
        let syncing_target = self.current_sync_target();
        let target_end_slot = match syncing_target {
            SyncUpdate::SyncingFinalized { target_epoch, .. } => {
                target_epoch.saturating_add(2).saturating_mul(SLOTS_PER_EPOCH)
            }
            SyncUpdate::SyncingHead { head_slot, .. } => head_slot,
            SyncUpdate::Following => return,
        };

        if head_slot >= target_end_slot {
            return;
        }
        // Continue past slots a peer already served this catch-up — never
        // rewind into the delivered range while the (async) apply head lags.
        let next_base = head_slot.max(self.synced_through);
        if next_base >= target_end_slot {
            return;
        }
        // Flow control: cap how far requests run ahead of the applied head so
        // in-flight + BS-buffered blocks stay bounded (~one batch ahead).
        if self.synced_through > head_slot + self.syncing.max_blocks_by_range_batch {
            return;
        }

        if matches!(syncing_target, SyncUpdate::SyncingFinalized { .. }).not() {
            // Couple block issuance to the column fetch.
            if self.custody_columns != 0 &&
                self.synced_through >
                    self.columns_synced_through + self.syncing.max_blocks_by_range_batch
            {
                if !self.col_stall_logged {
                    tracing::warn!(
                        synced_through = self.synced_through,
                        columns_synced_through = self.columns_synced_through,
                        "block sync stalled on data columns: column fetch is more than one \
                        batch behind; pausing block batches until it catches up"
                    );
                    self.col_stall_logged = true;
                }
                return;
            }

            self.col_stall_logged = false;
        }

        let start_slot = next_base + 1;
        let remaining = target_end_slot.saturating_sub(next_base);
        let count = match syncing_target {
            SyncUpdate::SyncingFinalized { target_epoch, target_root: _ } => {
                let target_slot = target_epoch.saturating_mul(self.syncing.slots_per_epoch) + 1;
                target_slot.saturating_sub(start_slot).min(remaining).min(self.syncing.max_blocks_by_range_batch)
            }
            _ => remaining.min(self.syncing.max_blocks_by_range_batch),
        };
        if count == 0 {
            return;
        }

        let Some(peer_id) = self.pick_sync_peer(count, now) else {
            // Keep the pin; self-heals when an in-flight slot frees or a backer drops.
            tracing::debug!(
                target = ?self.current_sync_target(),
                live_peers = self.database.iter_live_status_bytes().count(),
                "no issuable sync peer this iteration; keeping pin"
            );
            return;
        };

        // application_id is peer-local; use start_slot as a unique correlator.
        let application_id = start_slot;

        if !self.issue_blocks_by_range_request(
            peer_id,
            application_id,
            start_slot,
            count,
            1,
            now,
            emit,
        ) {
            return;
        }
        tracing::info!(
            peer_id,
            start_slot,
            count,
            head_slot,
            target = ?self.current_sync_target(),
            "issuing BlocksByRange"
        );
        self.inflight_syncreq = Some(SyncReq {
            peer_id,
            start_slot,
            count,
            last_observed_head_slot: head_slot,
            last_progress_at: now,
            responded: false,
            delivered: false,
        });
    }

    /// Drive the PM-owned catch-up `DataColumnsByRange` lifecycle: one
    /// range over our custody set, one peer attempt at a time. `remaining`
    /// shrinks as attempts deliver (`Complete` covers the claimed-custody
    /// overlap that was requested); an error terminator or progress
    /// timeout marks the peer tried and re-issues the remainder elsewhere.
    /// After `max_colreq_attempts` consecutive failures the remainder is
    /// conceded to storage's by-root straggler wheel. Paced to the block
    /// driver: never requests columns past
    /// `max(synced_through, inflight block range end)`.
    pub(crate) fn maybe_issue_colreq(&mut self, now: Instant, emit: &mut impl FnMut(PeerControl)) {
        if self.custody_columns == 0 {
            return;
        }
        self.resolve_colreq_attempt(now);
        self.open_colreq_range();
        self.issue_colreq_attempt(now, emit);
    }

    fn resolve_colreq_attempt(&mut self, now: Instant) {
        let Some(mut req) = self.col_syncreq else { return };
        let Some(att) = req.attempt else { return };

        if att.delivered {
            // `Complete` covers the overlap only up to the peer's claimed
            // head — never claim slots past its tip. Under-capping on a stale
            // Status is safe (re-fetch is idempotent); over-capping would skip
            // real columns and wedge the DA check.
            let peer_head = self
                .database
                .peer_status_bytes(att.peer_id)
                .map(StatusView::head_slot)
                .unwrap_or(0);
            req.served_through = req.served_through.min(peer_head);
            req.remaining &= !att.columns;
            req.attempts = 0;
            req.attempt = None;
            if req.remaining == 0 {
                let end = (req.start_slot + req.count - 1).min(req.served_through);
                self.columns_synced_through = self.columns_synced_through.max(end);
                self.col_tried_for_range.clear();
                self.col_syncreq = None;
            } else {
                self.col_syncreq = Some(req);
            }
        } else if att.responded {
            // Error terminator — peer already scored via
            // `severity_for_error_response`. Re-issue elsewhere.
            self.col_tried_for_range.insert(att.peer_id);
            req.attempt = None;
            self.col_syncreq = Some(req);
        } else if now.saturating_duration_since(att.last_progress_at) >=
            Duration::from_millis(self.syncing.inflight_progress_timeout_ms)
        {
            // No terminator and no sidecar chunk for a full timeout window:
            // peer stall.
            self.col_tried_for_range.insert(att.peer_id);
            req.attempt = None;
            self.col_syncreq = Some(req);
            self.on_rpc_misbehaviour(
                att.peer_id,
                RpcSeverity::MidTolerance,
                "columns-by-range progress stall",
            );
        }
    }

    fn open_colreq_range(&mut self) {
        if self.col_syncreq.is_some() {
            return;
        }
        let base = self.columns_synced_through.max(self.local_head_imported_slot);
        let block_end = self.inflight_syncreq.map_or(0, |r| r.start_slot + r.count - 1);
        let cap = self.synced_through.max(block_end);
        if base >= cap {
            return;
        }
        let count = (cap - base).min(self.syncing.max_blocks_by_range_batch);
        self.col_tried_for_range.clear();
        self.col_syncreq = Some(ColSyncReq {
            start_slot: base + 1,
            count,
            remaining: self.custody_columns,
            attempts: 0,
            served_through: u64::MAX,
            attempt: None,
        });
    }

    fn issue_colreq_attempt(&mut self, now: Instant, emit: &mut impl FnMut(PeerControl)) {
        let Some(mut req) = self.col_syncreq else { return };
        if req.attempt.is_some() {
            return;
        }
        if req.attempts >= self.syncing.max_colreq_attempts {
            // Concede: advance the watermark past the range; storage's by-root
            // wheel picks up the stragglers as blocks land.
            tracing::debug!(
                start_slot = req.start_slot,
                count = req.count,
                remaining = req.remaining,
                "colreq attempts exhausted; remainder conceded to by-root"
            );
            self.columns_synced_through =
                self.columns_synced_through.max(req.start_slot + req.count - 1);
            self.col_tried_for_range.clear();
            self.col_syncreq = None;
            return;
        }

        let app_id = BASE_REQUEST_ID | req.start_slot;
        match self.best_peer_for_data_columns(
            StreamProtocol::DataColumnSidecarsByRange,
            req.remaining,
            app_id,
            &self.col_tried_for_range,
            req.start_slot,
            req.count,
            now,
        ) {
            Some((peer, overlap, _tokens)) => {
                // Request only the overlap: the responder omits columns it
                // doesn't custody, so `Complete` then implies coverage of
                // exactly `overlap`.
                if !self.issue_data_columns_by_range_request(
                    peer,
                    app_id,
                    req.start_slot,
                    req.count,
                    overlap,
                    now,
                    emit,
                ) {
                    self.col_syncreq = Some(req);
                    return;
                }
                tracing::debug!(
                    peer,
                    start_slot = req.start_slot,
                    count = req.count,
                    overlap,
                    remaining = req.remaining,
                    attempts = req.attempts,
                    "issuing DataColumnsByRange"
                );
                req.attempts += 1;
                req.attempt = Some(ColAttempt {
                    peer_id: peer,
                    columns: overlap,
                    last_progress_at: now,
                    responded: false,
                    delivered: false,
                });
                self.col_syncreq = Some(req);
            }
            None => {
                // No eligible peer. If some were skipped as tried, allow
                // re-picks next tick; `attempts` still bounds the range.
                if !self.col_tried_for_range.is_empty() {
                    self.col_tried_for_range.clear();
                }
                tracing::trace!(
                    start_slot = req.start_slot,
                    remaining = req.remaining,
                    supporting = self
                        .database
                        .live_peers_supporting(StreamProtocol::DataColumnSidecarsByRange)
                        .count(),
                    "no peer for DataColumnsByRange; retrying next tick"
                );
            }
        }
    }

    /// `DataColumnsByRange` request body: `start_slot | count | offset(=20) |
    /// column indices (u64 LE each)`, expanding the custody bitmask to its set
    /// column indices.
    fn data_columns_by_range_ssz(
        start_slot: u64,
        count: u64,
        columns: u128,
    ) -> ([u8; DC_BY_RANGE_REQ_MAX], usize) {
        let mut ssz = [0u8; DC_BY_RANGE_REQ_MAX];
        ssz[0..8].copy_from_slice(&start_slot.to_le_bytes());
        ssz[8..16].copy_from_slice(&count.to_le_bytes());
        ssz[16..20].copy_from_slice(&20u32.to_le_bytes());
        let mut off = 20;
        for i in 0..u128::BITS {
            if columns & (1u128 << i) != 0 {
                ssz[off..off + 8].copy_from_slice(&(i as u64).to_le_bytes());
                off += 8;
            }
        }
        (ssz, off)
    }

    fn blocks_by_range_ssz(
        start_slot: u64,
        count: u64,
        step: u64,
    ) -> [u8; BLOCKS_BY_RANGE_REQ_SIZE] {
        let mut ssz = [0u8; BLOCKS_BY_RANGE_REQ_SIZE];
        ssz[0..8].copy_from_slice(&start_slot.to_le_bytes());
        ssz[8..16].copy_from_slice(&count.to_le_bytes());
        ssz[16..24].copy_from_slice(&step.to_le_bytes());
        ssz
    }

    fn issue_blocks_by_range_request(
        &mut self,
        peer: usize,
        request_id: u64,
        start_slot: u64,
        count: u64,
        step: u64,
        now: Instant,
        emit: &mut impl FnMut(PeerControl),
    ) -> bool {
        if !self.admit_outbound_request(peer, StreamProtocol::BeaconBlocksByRange, count, now) {
            return false;
        }
        let ssz = Self::blocks_by_range_ssz(start_slot, count, step);
        emit(PeerControl::P2pSend(P2pSend::Rpc(RpcOutbound::Request(RpcRequestOutbound {
            application_id: request_id,
            peer,
            request: RpcRequest::BlocksByRange(ssz),
        }))));
        self.track_outbound_range_attempt(OutboundRangeAttempt {
            request_id,
            peer_id: peer,
            protocol: StreamProtocol::BeaconBlocksByRange,
            start_slot,
            count,
            step,
            columns: 0,
            last_progress_at: now,
            responded: false,
            delivered: false,
        });
        true
    }

    fn issue_data_columns_by_range_request(
        &mut self,
        peer: usize,
        request_id: u64,
        start_slot: u64,
        count: u64,
        columns: u128,
        now: Instant,
        emit: &mut impl FnMut(PeerControl),
    ) -> bool {
        let tokens = count.max(1).saturating_mul(columns.count_ones() as u64).max(1);
        if !self.admit_outbound_request(
            peer,
            StreamProtocol::DataColumnSidecarsByRange,
            tokens,
            now,
        ) {
            return false;
        }
        let (ssz, len) = Self::data_columns_by_range_ssz(start_slot, count, columns);
        emit(PeerControl::P2pSend(P2pSend::Rpc(RpcOutbound::Request(RpcRequestOutbound {
            application_id: request_id,
            peer,
            request: RpcRequest::DataColumnsByRange { ssz, len },
        }))));
        self.track_outbound_range_attempt(OutboundRangeAttempt {
            request_id,
            peer_id: peer,
            protocol: StreamProtocol::DataColumnSidecarsByRange,
            start_slot,
            count,
            step: 0,
            columns,
            last_progress_at: now,
            responded: false,
            delivered: false,
        });
        true
    }

    fn track_outbound_range_attempt(&mut self, attempt: OutboundRangeAttempt) {
        self.outbound_range_attempts.retain(|existing| {
            existing.request_id != attempt.request_id ||
                existing.peer_id != attempt.peer_id ||
                existing.protocol != attempt.protocol
        });
        self.outbound_range_attempts.push(attempt);
    }

    fn progress_outbound_range_attempt(
        &mut self,
        request_id: u64,
        peer_id: usize,
        protocol: StreamProtocol,
        now: Instant,
    ) {
        if let Some(attempt) = self.outbound_range_attempts.iter_mut().find(|attempt| {
            attempt.request_id == request_id &&
                attempt.peer_id == peer_id &&
                attempt.protocol == protocol
        }) {
            attempt.last_progress_at = now;
        }
    }

    fn pending_range_from_attempt(attempt: OutboundRangeAttempt) -> PendingRangeRequest {
        match attempt.protocol {
            StreamProtocol::BeaconBlocksByRange => {
                PendingRangeRequest::Blocks(PendingBlocksByRange {
                    request_id: attempt.request_id,
                    start_slot: attempt.start_slot,
                    count: attempt.count,
                    step: attempt.step,
                })
            }
            StreamProtocol::DataColumnSidecarsByRange => {
                PendingRangeRequest::DataColumns(PendingDataColumnsByRange {
                    request_id: attempt.request_id,
                    start_slot: attempt.start_slot,
                    count: attempt.count,
                    columns: attempt.columns,
                })
            }
            _ => unreachable!("only range attempts are tracked"),
        }
    }

    fn is_retryable_backfill_attempt(attempt: OutboundRangeAttempt) -> bool {
        RequestCategory::from_request_id(attempt.request_id).is_backfill()
    }

    fn retry_backfill_range_attempt(
        &mut self,
        attempt: OutboundRangeAttempt,
        reason: &'static str,
        emit: &mut impl FnMut(PeerControl),
    ) {
        if !Self::is_retryable_backfill_attempt(attempt) {
            return;
        }
        tracing::debug!(
            request_id = attempt.request_id,
            peer = attempt.peer_id,
            protocol = ?attempt.protocol,
            start_slot = attempt.start_slot,
            count = attempt.count,
            columns = attempt.columns,
            reason,
            "queueing backfill range retry"
        );
        self.enqueue_pending_range_request(Self::pending_range_from_attempt(attempt));
        emit(PeerControl::DiscoverNodes);
    }

    pub(crate) fn on_range_stream_closed(
        &mut self,
        peer_id: usize,
        protocol: StreamProtocol,
        emit: &mut impl FnMut(PeerControl),
    ) {
        if let Some(pos) = self
            .outbound_range_attempts
            .iter()
            .position(|attempt| attempt.peer_id == peer_id && attempt.protocol == protocol)
        {
            let attempt = self.outbound_range_attempts.remove(pos);
            self.retry_backfill_range_attempt(attempt, "stream closed", emit);
        }
    }

    pub(crate) fn on_range_peer_disconnected(
        &mut self,
        peer_id: usize,
        emit: &mut impl FnMut(PeerControl),
    ) {
        let mut retry = Vec::new();
        self.outbound_range_attempts.retain(|attempt| {
            if attempt.peer_id == peer_id {
                retry.push(*attempt);
                false
            } else {
                true
            }
        });
        for attempt in retry {
            self.retry_backfill_range_attempt(attempt, "peer disconnected", emit);
        }
    }

    pub(crate) fn sweep_backfill_range_attempts(
        &mut self,
        now: Instant,
        emit: &mut impl FnMut(PeerControl),
    ) {
        let timeout = Duration::from_millis(self.syncing.inflight_progress_timeout_ms);
        let mut i = 0;
        while i < self.outbound_range_attempts.len() {
            let attempt = self.outbound_range_attempts[i];
            if !Self::is_retryable_backfill_attempt(attempt) ||
                now.saturating_duration_since(attempt.last_progress_at) < timeout
            {
                i += 1;
                continue;
            }

            let attempt = self.outbound_range_attempts.remove(i);
            if let Some(peer) = self.peers.get_mut(&attempt.peer_id) {
                peer.outbound_in_flight[attempt.protocol.ordinal() as usize] =
                    peer.outbound_in_flight[attempt.protocol.ordinal() as usize].saturating_sub(1);
            }
            self.on_rpc_misbehaviour(
                attempt.peer_id,
                RpcSeverity::MidTolerance,
                "backfill range progress stall",
            );
            self.retry_backfill_range_attempt(attempt, "timeout", emit);
        }
    }

    fn complete_outbound_range_attempt(
        &mut self,
        request_id: u64,
        peer_id: usize,
        protocol: StreamProtocol,
        completed_ok: bool,
        emit: &mut impl FnMut(PeerControl),
    ) {
        if let Some(pos) = self.outbound_range_attempts.iter().position(|attempt| {
            attempt.request_id == request_id &&
                attempt.peer_id == peer_id &&
                attempt.protocol == protocol
        }) {
            let mut attempt = self.outbound_range_attempts.remove(pos);
            attempt.responded = true;
            attempt.delivered = completed_ok;
            tracing::debug!(
                request_id,
                peer_id,
                ?protocol,
                start_slot = attempt.start_slot,
                count = attempt.count,
                columns = attempt.columns,
                delivered = attempt.delivered,
                "outbound range attempt completed"
            );
            if !completed_ok {
                self.retry_backfill_range_attempt(attempt, "terminal error", emit);
            }
        }
    }

    fn drain_pending_range_requests(&mut self, now: Instant, emit: &mut impl FnMut(PeerControl)) {
        let len = self.pending_range_requests.len();
        for _ in 0..len {
            let Some(req) = self.pending_range_requests.pop_front() else {
                break;
            };
            if !self.try_issue_pending_range_request(req, now, emit) {
                self.pending_range_requests.push_back(req);
                emit(PeerControl::DiscoverNodes);
            }
        }
    }

    fn try_issue_pending_range_request(
        &mut self,
        req: PendingRangeRequest,
        now: Instant,
        emit: &mut impl FnMut(PeerControl),
    ) -> bool {
        match req {
            PendingRangeRequest::Blocks(req) => {
                let protocol = StreamProtocol::BeaconBlocksByRange;
                let tokens = req.count.max(1);
                let has_capacity = |i: usize| {
                    self.outbound_has_capacity(i, protocol, tokens, now, MAX_RPC_PROTOCOL_IN_FLIGHT)
                };
                let Some(peer) = self.best_peer_for(protocol, has_capacity) else {
                    tracing::debug!(
                        request_id = req.request_id,
                        start_slot = req.start_slot,
                        count = req.count,
                        "no peer for pending BlocksByRange"
                    );
                    return false;
                };
                self.issue_blocks_by_range_request(
                    peer,
                    req.request_id,
                    req.start_slot,
                    req.count,
                    req.step,
                    now,
                    emit,
                )
            }
            PendingRangeRequest::DataColumns(req) => {
                if req.columns == 0 {
                    return true;
                }
                let Some((peer, overlap, _tokens)) = self.best_peer_for_data_columns(
                    StreamProtocol::DataColumnSidecarsByRange,
                    req.columns,
                    req.request_id,
                    &FxHashSet::default(),
                    req.start_slot,
                    req.count,
                    now,
                ) else {
                    tracing::debug!(
                        request_id = req.request_id,
                        start_slot = req.start_slot,
                        count = req.count,
                        columns = req.columns,
                        "no peer for pending DataColumnsByRange"
                    );
                    return false;
                };
                if !self.issue_data_columns_by_range_request(
                    peer,
                    req.request_id,
                    req.start_slot,
                    req.count,
                    overlap,
                    now,
                    emit,
                ) {
                    return false;
                }
                let remaining = req.columns & !overlap;
                if remaining != 0 {
                    self.enqueue_pending_range_request(PendingRangeRequest::DataColumns(
                        PendingDataColumnsByRange { columns: remaining, ..req },
                    ));
                }
                true
            }
        }
    }

    /// Drain pending RPC requests onto any peer that's freshly available
    /// (new connection, in-flight slot freed).
    pub fn drain_pending_outbound(&mut self, now: Instant, emit: &mut impl FnMut(PeerControl)) {
        self.drain_pending_range_requests(now, emit);

        // Drain pending blocks by root
        let len = self.pending_block_by_root.len();
        for _ in 0..len {
            if let Some((request_id, p2p_peer, block_root)) = self.pending_block_by_root.pop_front()
            {
                // requests that still cannot be sent will be re-added.
                self.on_request_blocks_by_root(request_id, p2p_peer, block_root, now, emit);
            }
        }

        // Drain other pending rpc requests.
        let len = self.pending_rpc_request.len();
        for _ in 0..len {
            if let Some((request_id, rpc)) = self.pending_rpc_request.pop_front() {
                // requests that still cannot be sent will be re-added.
                self.on_rpc_request(request_id, rpc, now, emit);
            }
        }
    }

    /// Dispatch a DataColumnsByRoot request to the highest-scoring connected
    /// peer that advertises the protocol AND has the data column group AND has
    /// spare outbound capacity.
    /// If no peer qualifies for some columns, kick discovery. Storage owns
    /// live/backfill DataColumnsByRoot retry timing via its outstanding
    /// request wheels.
    pub fn on_request_data_columns_by_root(
        &mut self,
        request_id: u64,
        columns: u128,
        block_root: [u8; 32],
        now: Instant,
        emit: &mut impl FnMut(PeerControl),
    ) {
        let mut remaining = columns;
        while remaining != 0 {
            let Some((peer, overlap, tokens)) = self.best_peer_for_data_columns(
                StreamProtocol::DataColumnSidecarsByRoot,
                remaining,
                request_id,
                &FxHashSet::default(),
                0,
                1,
                now,
            ) else {
                tracing::debug!("no peer has data columns: {remaining}");
                break;
            };
            if !self.admit_outbound_request(
                peer,
                StreamProtocol::DataColumnSidecarsByRoot,
                tokens,
                now,
            ) {
                break;
            }
            tracing::debug!(peer, overlap, "column request control event");
            emit(PeerControl::P2pDataColumnsRequest {
                app_id: request_id,
                peer,
                block_root,
                columns: overlap,
            });
            remaining &= !overlap;
            tracing::trace!(peer, overlap, remaining, "sent data columns request");
        }
        if remaining != 0 {
            emit(PeerControl::DiscoverNodes);
            tracing::debug!(
                request_id,
                remaining,
                "DataColumnsByRoot coverage incomplete; discovery kicked"
            );
        }
    }

    /// Dispatch a BlocksByRoot request to either the specified peer or the
    /// highest-scoring connected peer that advertises the protocol AND has
    /// spare outbound capacity.
    /// If no peer qualifies, cache the request and kick discovery — the
    /// retry pass in `drain_pending_outbound` drains the cache as soon
    /// as an eligible peer becomes available.
    pub fn on_request_blocks_by_root(
        &mut self,
        request_id: u64,
        p2p_peer: Option<usize>,
        block_root: [u8; 32],
        now: Instant,
        emit: &mut impl FnMut(PeerControl),
    ) {
        let protocol = StreamProtocol::BeaconBlocksByRoot;
        let tokens = 1;
        let has_capacity = |i: usize| {
            self.outbound_has_capacity(i, protocol, tokens, now, MAX_RPC_PROTOCOL_IN_FLIGHT)
        };

        tracing::debug!(?p2p_peer, "request blocks by root");

        let peer = match p2p_peer {
            Some(p) if has_capacity(p) => Some(p),
            _ => self.best_peer_for(protocol, has_capacity),
        };

        match peer {
            Some(peer) => {
                if !self.admit_outbound_request(peer, protocol, tokens, now) {
                    self.pending_block_by_root.push_back((request_id, Some(peer), block_root));
                    return;
                }
                tracing::debug!("sending blocks by root request to {peer}");
                emit(PeerControl::P2pBlockByRootRequest { app_id: request_id, peer, block_root });
            }
            None => {
                tracing::warn!("no peer for blocks by root");
                self.pending_block_by_root.push_back((request_id, p2p_peer, block_root));
                emit(PeerControl::DiscoverNodes);
            }
        }
    }

    pub fn on_rpc_request(
        &mut self,
        request_id: u64,
        rpc: RpcRequest,
        now: Instant,
        emit: &mut impl FnMut(PeerControl),
    ) {
        if let Some(req) = Self::pending_range_from_rpc(request_id, rpc) {
            self.enqueue_pending_range_request(req);
            self.drain_pending_range_requests(now, emit);
            return;
        }

        let protocol = rpc.protocol();
        let tokens = rpc.rate_limit_tokens().unwrap_or(1);
        let has_capacity = |i: usize| {
            self.outbound_has_capacity(i, protocol, tokens, now, MAX_RPC_PROTOCOL_IN_FLIGHT)
        };

        let peer = self.best_peer_for(protocol, has_capacity);

        match peer {
            Some(peer) => {
                if !self.admit_outbound_request(peer, protocol, tokens, now) {
                    self.enqueue_pending_rpc_request(request_id, rpc);
                    return;
                }
                tracing::debug!(?protocol, "sending rpc request to {peer}");
                emit(PeerControl::P2pSend(P2pSend::Rpc(RpcOutbound::Request(
                    RpcRequestOutbound { application_id: request_id, peer, request: rpc },
                ))));
            }
            None => {
                tracing::warn!(?protocol, "no peer for rpc request");
                self.enqueue_pending_rpc_request(request_id, rpc);
                emit(PeerControl::DiscoverNodes);
            }
        }
    }

    /// Highest-scoring connected peer that (a) backs the current sync
    /// target and (b) has BlocksByRange outbound capacity. `None` if no
    /// target is pinned or no eligible peer is connected.
    fn pick_sync_peer(&self, count: u64, now: Instant) -> Option<usize> {
        let target = self.current_sync_target();
        let mut best: Option<(usize, f64)> = None;
        for (peer, ssz) in self.database.iter_live_status_bytes() {
            if self.burnt_for_target.contains(&peer) {
                tracing::debug!(peer, ?target, "pick_sync_peer skipping burnt peer");
                continue;
            }
            let matches = match target {
                SyncUpdate::SyncingFinalized { target_epoch, target_root } => {
                    StatusView::finalized_epoch(ssz) == target_epoch &&
                        *StatusView::finalized_root(ssz) == target_root
                }
                SyncUpdate::SyncingHead { head_root, .. } => {
                    *StatusView::head_root(ssz) == head_root
                }
                SyncUpdate::Following => return None,
            };
            if !matches {
                tracing::debug!(
                    peer,
                    ?target,
                    peer_finalized_epoch = StatusView::finalized_epoch(ssz),
                    peer_finalized_root = hex32(StatusView::finalized_root(ssz)),
                    peer_head_slot = StatusView::head_slot(ssz),
                    peer_head_root = hex32(StatusView::head_root(ssz)),
                    "pick_sync_peer peer status does not match pinned target"
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
            ) || !self.admit_outbound_request(peer, StreamProtocol::Ping, 1, now)
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
    /// status. Runs during catch-up too — peers use our advancing
    /// finalized/head to score us; suppressing would let their view rot.
    /// Does **not** touch `outbound_in_flight` — Status is single-chunk and
    /// the terminal-response path uses saturating release for legacy paths.
    pub fn fan_out_status(&mut self, now: Instant, emit: &mut impl FnMut(PeerControl)) {
        let Some(status) = self.status().copied() else {
            return;
        };
        let request = RpcRequest::StatusV2(status);
        let peers: Vec<usize> = self.live_peers().collect();
        for peer in peers {
            if !self.admit_outbound_rate(peer, StreamProtocol::StatusV2, 1, now) {
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
    fn data_columns_by_range_ssz_layout() {
        // Custody columns {3, 7} over [42, 42+5).
        let columns = (1u128 << 3) | (1u128 << 7);
        let (ssz, len) = PeerManager::data_columns_by_range_ssz(42, 5, columns);

        // start_slot | count | offset(=20) | [3u64, 7u64]
        assert_eq!(len, 20 + 2 * 8);
        assert_eq!(u64::from_le_bytes(ssz[0..8].try_into().unwrap()), 42);
        assert_eq!(u64::from_le_bytes(ssz[8..16].try_into().unwrap()), 5);
        assert_eq!(u32::from_le_bytes(ssz[16..20].try_into().unwrap()), 20);
        assert_eq!(u64::from_le_bytes(ssz[20..28].try_into().unwrap()), 3);
        assert_eq!(u64::from_le_bytes(ssz[28..36].try_into().unwrap()), 7);

        // Empty custody set → header only, no column list.
        let (_, len) = PeerManager::data_columns_by_range_ssz(0, 1, 0);
        assert_eq!(len, 20);
    }

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
        // Self-throttle, don't ban. Assert the literal wire code (lighthouse
        // `RateLimited` = 139) so a regressed constant is caught here.
        assert_eq!(RPC_ERR_RATE_LIMITED, 139);
        assert!(matches!(
            severity_for_error_response(139, StreamProtocol::BeaconBlocksByRange),
            Some(RpcSeverity::MidTolerance)
        ));
        // Prysm overloads InvalidRequest (1) for rate limiting; by code alone
        // that is indistinguishable from a malformed request.
        assert!(matches!(
            severity_for_error_response(1, StreamProtocol::BeaconBlocksByRange),
            Some(RpcSeverity::LowTolerance)
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
}
