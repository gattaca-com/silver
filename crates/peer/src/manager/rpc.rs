//! RPC handling for `PeerManager`: inbound rate-limit gate, per-protocol
//! request handlers (Status/Ping/Goodbye/MetaData replied here; block /
//! data-column requests are admitted then forwarded by the caller),
//! outbound in-flight bookkeeping, PM-driven catchup `BlocksByRange`
//! issuance, and heartbeat-driven Ping/Status fan-out.
//!
//! All state lives on `PeerManager` (see fields `outbound_in_flight`,
//! `inbound_buckets`, `inflight_catchup` in `manager.rs`) so the
//! controller tile that drives the spine remains a thin shell.

use std::{
    collections::HashMap,
    ops::Deref,
    time::{Duration, Instant},
};

use silver_common::{
    P2pSend, PeerControl, PeerEvent, PeerStatus, RpcInbound, RpcOutbound, RpcRequest,
    RpcRequestInbound, RpcRequestOutbound, RpcResponse, RpcResponseInbound, RpcResponseOutbound,
    RpcSeverity, StreamProtocol, SyncUpdate,
    ssz_view::{BLOCKS_BY_RANGE_REQ_SIZE, MetadataView, StatusView},
};

use crate::{PeerManager, manager::SyncReq};

/// Per-peer cap on outstanding RPC requests per protocol. Bounds load on any
/// single peer and keeps fan-out useful when many ranges are pending.
const MAX_RPC_PROTOCOL_IN_FLIGHT: u32 = 2;

/// Size of the `StreamProtocol` enum (incl. `Unset`). Used to allocate
/// the per-protocol outbound counter array; index via
/// `protocol.ordinal() as usize`.
pub(crate) const N_STREAM_PROTOCOLS: usize = 12;

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

#[derive(Default)]
pub(crate) struct PeerInboundState {
    /// Current token count per protocol (indexed by `ordinal()`).
    tokens: [u32; N_STREAM_PROTOCOLS],
    /// Last time the bucket was credited. `None` ⇒ never seen; the next
    /// `try_admit_inbound` call seeds it at `max_tokens`.
    last_refill: [Option<Instant>; N_STREAM_PROTOCOLS],
}

pub(crate) type OutboundCounts = HashMap<usize, [u32; N_STREAM_PROTOCOLS]>;

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

impl PeerManager {
    /// Pick a peer for a `DataColumnsByRoot`/`ByRange` request that wants
    /// the columns in `columns`. Filters:
    /// - peer advertises `protocol`,
    /// - outbound in-flight on `protocol` is strictly below
    ///   `MAX_RPC_PROTOCOL_IN_FLIGHT`,
    /// - peer's custody set intersects `columns` (otherwise the peer has
    ///   nothing to serve).
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
    ) -> Option<(usize, u128)> {
        self.database
            .live_peers_supporting(protocol)
            .filter_map(|p| {
                if outbound_count(&self.outbound_in_flight, p, protocol) >=
                    MAX_RPC_PROTOCOL_IN_FLIGHT
                {
                    return None;
                }
                let overlap = self.database.data_column_custody_groups_intersection(p, columns);
                if overlap == 0 {
                    return None;
                }
                let score = self.score(p).unwrap_or(f64::NEG_INFINITY);
                Some((p, overlap, score))
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
                // Inbound rate-limit gate. PeerManager is the single
                // chokepoint for all inbound RPC requests, including
                // block/data-column requests that get forwarded
                // downstream. Each protocol has a quota in
                // `INBOUND_QUOTAS`; the gate returns admit=true
                // unconditionally for the unquota'd protocols
                // (gossip/identity).
                let protocol = request.protocol();
                if !try_admit_inbound(&mut self.inbound_buckets, stream_id.peer(), protocol, now) {
                    // Goodbye expects no response — silently drop;
                    // anything else gets the standard rate-limit
                    // error chunk.
                    if protocol != StreamProtocol::Goodbye {
                        let mut msg = [0u8; 256];
                        let err = b"rate limit exceeded";
                        msg[..err.len()].copy_from_slice(err);
                        emit(PeerControl::P2pSend(P2pSend::Rpc(RpcOutbound::Response(
                            RpcResponseOutbound {
                                stream_id,
                                response: RpcResponse::Error {
                                    error: RPC_ERR_RATE_LIMITED,
                                    msg,
                                    len: err.len(),
                                },
                            },
                        ))));
                    }
                    return;
                }
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

                        emit(PeerControl::P2pSend(P2pSend::Rpc(RpcOutbound::Response(
                            RpcResponseOutbound { stream_id, response: RpcResponse::Ping(our_seq) },
                        ))));

                        if !matches!(current_peer_metadata_seq, Some(seq) if seq == metadata_seq) {
                            emit(PeerControl::P2pSend(P2pSend::Rpc(RpcOutbound::Request(
                                RpcRequestOutbound {
                                    application_id: 0,
                                    peer: stream_id.peer(),
                                    request: RpcRequest::MetaData,
                                },
                            ))));
                        }
                    }
                    RpcRequest::Goodbye(goodbye) => self.handle_event(
                        PeerEvent::P2pPeerGoodbye {
                            p2p_peer: stream_id.peer(),
                            status: u64::from_le_bytes(goodbye),
                        },
                        now,
                        emit,
                    ),
                    RpcRequest::MetaData => {
                        let metadata = *self.metadata();
                        emit(PeerControl::P2pSend(P2pSend::Rpc(RpcOutbound::Response(
                            RpcResponseOutbound {
                                stream_id,
                                response: RpcResponse::MetaData(metadata),
                            },
                        ))));
                    }
                    // TODO: forward admitted block/data-column requests
                    // to the owning tile. The rate-limit gate above has
                    // already accepted the request and credited the
                    // peer's bucket; the downstream tile owns response
                    // generation.
                    RpcRequest::BlocksByRange(_ssz) => {}
                    RpcRequest::BlockByRoot(_req) => {}
                    RpcRequest::DataColumnsByRange { ssz: _, len: _ } => {}
                    RpcRequest::DataColumnsByRoot(_req) => {}
                }
            }
            RpcInbound::Response(RpcResponseInbound { application_id, stream_id, response }) => {
                let terminal_protocol = is_terminal_response(stream_id.protocol(), &response)
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
                        if !matches!(current_peer_metadata_seq, Some(seq) if seq == metadata_seq) {
                            record_outbound(
                                &mut self.outbound_in_flight,
                                stream_id.peer(),
                                StreamProtocol::Metadata,
                            );
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
                    _ => {}
                }
                if let Some(protocol) = terminal_protocol {
                    release_outbound(&mut self.outbound_in_flight, stream_id.peer(), protocol);
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
        let head_slot = self.status().map(|s| StatusView::head_slot(s)).unwrap_or(0);

        // Phase 1 + 2: observe progress / sweep timeout.
        if let Some(inflight) = self.inflight_syncreq {
            let end_inclusive = inflight.start_slot + inflight.count - 1;
            let advanced = head_slot > inflight.last_observed_head_slot;
            let reached_end = head_slot >= end_inclusive;

            if reached_end {
                self.inflight_syncreq = None;
            } else if advanced {
                let r = self.inflight_syncreq.as_mut().expect("checked above");
                r.last_observed_head_slot = head_slot;
                r.last_progress_at = now;
            } else {
                let timeout = Duration::from_millis(self.syncing.inflight_progress_timeout_ms);
                if now.saturating_duration_since(inflight.last_progress_at) >= timeout {
                    // Penalize only if no progress was ever made into the
                    // requested range; otherwise treat as benign drain-end.
                    if head_slot < inflight.start_slot {
                        self.on_rpc_misbehaviour(inflight.peer_id, RpcSeverity::MidTolerance);
                    }
                    self.inflight_syncreq = None;
                }
            }
        }

        // Phase 3: issuance.
        if self.inflight_syncreq.is_some() {
            return;
        }
        let Some(local) = self.status() else {
            return;
        };
        let local_head_slot = StatusView::head_slot(local);

        // For SyncingFinalised, drive past `(target_epoch + 2) * SLOTS_PER_EPOCH`:
        // Casper FFG needs two more epochs of justification/finalization before
        // local `finalized_checkpoint.epoch` can reach `target_epoch`.
        let target_end_slot = match self.current_sync_target() {
            SyncUpdate::SyncingFinalised { target_epoch, .. } => {
                target_epoch.saturating_add(2).saturating_mul(self.syncing.slots_per_epoch)
            }
            SyncUpdate::SyncingHead { head_slot, .. } => head_slot,
            SyncUpdate::Following => return,
        };

        if local_head_slot >= target_end_slot {
            return;
        }
        let start_slot = local_head_slot + 1;
        let remaining = target_end_slot.saturating_sub(local_head_slot);
        let count = remaining.min(self.syncing.max_blocks_by_range_batch);
        if count == 0 {
            return;
        }

        let Some(peer_id) = self.pick_sync_peer() else {
            tracing::warn!(
                target = ?self.current_sync_target(),
                live_peers = self.database.iter_live_status_bytes().count(),
                "no good sync peer for pinned target; dropping pin"
            );
            self.current_target = SyncUpdate::Following;
            self.target_dirty = true;
            return;
        };

        let mut ssz = [0u8; BLOCKS_BY_RANGE_REQ_SIZE];
        ssz[0..8].copy_from_slice(&start_slot.to_le_bytes());
        ssz[8..16].copy_from_slice(&count.to_le_bytes());
        ssz[16..24].copy_from_slice(&1u64.to_le_bytes()); // step = 1, deprecated but required

        // application_id is peer-local; use start_slot as a unique correlator.
        let application_id = start_slot;

        record_outbound(&mut self.outbound_in_flight, peer_id, StreamProtocol::BeaconBlocksByRange);
        tracing::info!(
            peer_id,
            start_slot,
            count,
            local_head_slot,
            target = ?self.current_sync_target(),
            "issuing BlocksByRange"
        );
        emit(PeerControl::P2pSend(P2pSend::Rpc(RpcOutbound::Request(RpcRequestOutbound {
            application_id,
            peer: peer_id,
            request: RpcRequest::BlocksByRange(ssz),
        }))));

        self.inflight_syncreq = Some(SyncReq {
            peer_id,
            start_slot,
            count,
            last_observed_head_slot: local_head_slot,
            last_progress_at: now,
        });
    }

    /// Drain pending BlocksByRange requests onto any peer that's freshly
    /// available (new connection, in-flight slot freed). Loop walks until
    /// either the cache is empty or no eligible peer remains —
    /// `best_peer_for` orders by cached score and respects the per-peer
    /// cap.
    pub fn drain_pending_outbound(&mut self, emit: &mut impl FnMut(PeerControl)) {
        // For each pending DataColumnsByRoot entry, fan out across as
        // many peers as needed to cover the remaining columns. If a
        // front entry can't make any forward progress (no peer overlaps
        // the remaining bits), stop draining — later peer events will
        // re-enter this loop. Newly-uncovered remainders are written
        // back in-place; fully-covered entries are popped.
        while let Some(&(request_id, remaining_at_entry, block_root)) =
            self.pending_data_columns_by_root.front()
        {
            let mut remaining = remaining_at_entry;
            let mut progressed = false;
            while remaining != 0 {
                let Some((peer, overlap)) = self.best_peer_for_data_columns(
                    StreamProtocol::DataColumnSidecarsByRoot,
                    remaining,
                ) else {
                    break;
                };
                record_outbound(
                    &mut self.outbound_in_flight,
                    peer,
                    StreamProtocol::DataColumnSidecarsByRoot,
                );
                emit(PeerControl::P2pDataColumnsRequest {
                    app_id: request_id,
                    peer,
                    block_root,
                    columns: overlap,
                });
                remaining &= !overlap;
                progressed = true;
            }
            if remaining == 0 {
                self.pending_data_columns_by_root.pop_front();
            } else {
                if progressed {
                    // Update the front entry in place with the
                    // narrowed remainder so the next drain pass picks
                    // up from the right spot.
                    self.pending_data_columns_by_root.front_mut().unwrap().1 = remaining;
                }
                // No further progress possible against the front this
                // pass — bail and let the next event re-enter.
                break;
            }
        }
    }

    /// Dispatch a DataColumnsByRoot request to the highest-scoring connected
    /// peer that advertises the protocol AND has the data column group AND has
    /// spare in-flight capacity.
    /// If no peer qualifies, cache the request and kick discovery — the
    /// retry pass in `drain_pending_outbound` drains the cache as soon
    /// as an eligible peer becomes available.
    pub fn on_request_data_columns_by_root(
        &mut self,
        request_id: u64,
        columns: u128,
        block_root: [u8; 32],
        emit: &mut impl FnMut(PeerControl),
    ) {
        let mut remaining = columns;
        while remaining != 0 {
            let Some((peer, overlap)) = self
                .best_peer_for_data_columns(StreamProtocol::DataColumnSidecarsByRoot, remaining)
            else {
                break;
            };
            record_outbound(
                &mut self.outbound_in_flight,
                peer,
                StreamProtocol::DataColumnSidecarsByRoot,
            );
            emit(PeerControl::P2pDataColumnsRequest {
                app_id: request_id,
                peer,
                block_root,
                columns: overlap,
            });
            remaining &= !overlap;
        }
        if remaining != 0 {
            self.pending_data_columns_by_root.push_back((request_id, remaining, block_root));
            emit(PeerControl::DiscoverNodes);
            tracing::debug!(
                request_id,
                remaining,
                pending = self.pending_data_columns_by_root.len(),
                "partial DataColumnsByRoot coverage; cached remainder + discovery kicked"
            );
        }
    }

    /// Highest-scoring connected peer that (a) backs the current sync
    /// target and (b) has BlocksByRange capacity. `None` if no target is
    /// pinned or no eligible peer is connected.
    fn pick_sync_peer(&self) -> Option<usize> {
        let target = self.current_sync_target();
        let mut best: Option<(usize, f64)> = None;
        for (peer, ssz) in self.database.iter_live_status_bytes() {
            if self.burnt_for_target.contains(&peer) {
                tracing::warn!(peer, ?target, "pick_sync_peer skipping burnt peer");
                continue;
            }
            let matches = match target {
                SyncUpdate::SyncingFinalised { target_epoch, target_root } => {
                    StatusView::finalized_epoch(ssz) == target_epoch &&
                        *StatusView::finalized_root(ssz) == target_root
                }
                SyncUpdate::SyncingHead { head_root, .. } => {
                    *StatusView::head_root(ssz) == head_root
                }
                SyncUpdate::Following => return None,
            };
            if !matches {
                tracing::warn!(
                    peer,
                    ?target,
                    peer_finalized_epoch = StatusView::finalized_epoch(ssz),
                    peer_finalized_root = ?StatusView::finalized_root(ssz),
                    peer_head_slot = StatusView::head_slot(ssz),
                    peer_head_root = ?StatusView::head_root(ssz),
                    "pick_sync_peer peer status does not match pinned target"
                );
                continue;
            }
            if outbound_count(&self.outbound_in_flight, peer, StreamProtocol::BeaconBlocksByRange) >=
                MAX_RPC_PROTOCOL_IN_FLIGHT
            {
                tracing::warn!("too many rpcs in flight already");
                continue;
            }
            let s = self.score(peer).unwrap_or(f64::NEG_INFINITY);
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
    pub fn fan_out_ping(&mut self, emit: &mut impl FnMut(PeerControl)) {
        let metadata = self.metadata();
        let ping = RpcRequest::Ping(MetadataView::seq_number(metadata).to_le_bytes());
        let peers: Vec<usize> = self.live_peers().collect();
        for peer in peers {
            record_outbound(&mut self.outbound_in_flight, peer, StreamProtocol::Ping);
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
    /// Does **not** touch `outbound_in_flight` —
    /// Status is single-chunk and the terminal-response path in
    /// `on_rpc_inbound` would underflow on release if we recorded here
    /// without a matching record on the initial outbound emitted from
    /// `on_connected`.
    pub fn fan_out_status(&mut self, emit: &mut impl FnMut(PeerControl)) {
        let Some(status) = self.status().copied() else {
            return;
        };
        let request = RpcRequest::StatusV2(status);
        let peers: Vec<usize> = self.live_peers().collect();
        for peer in peers {
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
