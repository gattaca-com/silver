//! Live forward data-column catch-up (policy, authoritative): the
//! `DataColumnSidecarsByRange` counterpart to the block driver, owned by the
//! `Syncing` phase and paced to trail the block watermark. Lifted from
//! `PeerManager`'s `col_syncreq` lifecycle. Range-first; the remainder is
//! conceded to storage's by-root straggler wheel after `max_colreq_attempts`.
//! PM keeps the custody-aware peer pick (`best_peer_for_data_columns`) + caps +
//! send; the engine owns the range, the `remaining` custody mask, the
//! watermark, and completion.

use std::{
    collections::HashSet,
    time::{Duration, Instant},
};

use silver_common::{BASE_REQUEST_ID, RpcSeverity};

use super::{Ctx, event::SyncAction, syncing::ISSUE_RETRY_BACKOFF};

/// The one per-range column attempt, with stable `request_id` across re-routes.
/// [`ColReqState`] tracks its lifecycle (mirrors the block driver's
/// `ReqState`).
#[derive(Clone, Copy)]
struct ColAttempt {
    request_id: u64,
    state: ColReqState,
}

/// Column-attempt lifecycle. emit → `AwaitingPeer`; PM routes → `InFlight`;
/// terminator → `Delivered` / `Errored`; `resolve` consumes the terminal states
/// and re-issues / advances. A route failure loops `AwaitingPeer` → re-emit.
#[derive(Clone, Copy)]
enum ColReqState {
    /// Emitted; PM placed it with no custody peer. Re-emit the same request
    /// (stable `request_id`, the full `remaining` overlap) no sooner than
    /// `retry_at`.
    AwaitingPeer { retry_at: Instant },
    /// Routed to `peer` requesting the claimed-custody `columns` overlap;
    /// awaiting sidecars / terminator. `peer_head_at_issue` caps the watermark
    /// advance — never claim columns past the serving peer's tip.
    InFlight { peer: usize, columns: u128, peer_head_at_issue: u64, last_progress_at: Instant },
    /// `Complete`: `columns` served up to `peer_head_at_issue`.
    Delivered { columns: u128, peer_head_at_issue: u64 },
    /// Error terminator (peer already scored at the RPC layer): re-issue
    /// elsewhere — `peer` added to `tried`.
    Errored { peer: usize },
}

/// The active catch-up range over our custody set. `remaining` shrinks as
/// attempts deliver; `served_through` is the min serving-peer head across
/// deliveries (caps the watermark advance).
#[derive(Clone, Copy)]
struct ColRange {
    start_slot: u64,
    count: u64,
    remaining: u128,
    attempts: u64,
    served_through: u64,
    attempt: Option<ColAttempt>,
}

#[derive(Default)]
pub(super) struct ColumnSync {
    /// Highest slot whose custody columns a peer has confirmed-served this
    /// catch-up.
    synced_through: u64,
    range: Option<ColRange>,
    /// Peers that failed (error / timeout) the active range; the picker skips
    /// them so the remainder goes elsewhere. Cleared per range.
    tried: HashSet<usize>,
}

impl ColumnSync {
    pub(super) fn synced_through(&self) -> u64 {
        self.synced_through
    }

    /// Seed the watermark to the applied head when columns first turn on at the
    /// finalized→head edge (columns aren't fetched during `SyncingFinalized`).
    pub(super) fn seed(&mut self, head: u64) {
        *self = Self::default();
        self.synced_through = head;
    }

    pub(super) fn tried_peers(&self) -> Vec<usize> {
        self.tried.iter().copied().collect()
    }

    pub(super) fn on_chunk(&mut self, request_id: u64, now: Instant) {
        if let Some(range) = self.range.as_mut() &&
            let Some(att) = range.attempt.as_mut() &&
            att.request_id == request_id &&
            let ColReqState::InFlight { last_progress_at, .. } = &mut att.state
        {
            *last_progress_at = now;
        }
    }

    pub(super) fn on_terminator(&mut self, request_id: u64, delivered: bool) {
        if let Some(range) = self.range.as_mut() &&
            let Some(att) = range.attempt.as_mut() &&
            att.request_id == request_id &&
            let ColReqState::InFlight { peer, columns, peer_head_at_issue, .. } = att.state
        {
            att.state = if delivered {
                ColReqState::Delivered { columns, peer_head_at_issue }
            } else {
                ColReqState::Errored { peer }
            };
        }
    }

    pub(super) fn on_request_issued(
        &mut self,
        ctx: &Ctx,
        request_id: u64,
        peer: Option<(usize, u128)>,
        now: Instant,
    ) {
        let Some(range) = self.range.as_mut() else { return };
        let state = match peer {
            Some((peer, overlap)) => {
                range.attempts += 1;
                ColReqState::InFlight {
                    peer,
                    columns: overlap,
                    peer_head_at_issue: ctx.peers.head_slot_of(peer).unwrap_or(0),
                    last_progress_at: now,
                }
            }
            None => ColReqState::AwaitingPeer { retry_at: now + ISSUE_RETRY_BACKOFF },
        };
        range.attempt = Some(ColAttempt { request_id, state });
    }

    pub(super) fn drive(
        &mut self,
        ctx: &mut Ctx,
        block_synced_through: u64,
        block_inflight_end: u64,
        now: Instant,
        emit: &mut impl FnMut(SyncAction),
    ) {
        if ctx.custody_columns == 0 {
            return;
        }
        self.resolve(now, Duration::from_millis(ctx.cfg.inflight_progress_timeout_ms), emit);
        self.open_range(
            block_synced_through,
            block_inflight_end,
            ctx.local.head_imported_slot,
            ctx.custody_columns,
            ctx.cfg.max_blocks_by_range_batch,
        );
        self.issue(ctx, now, emit);
    }

    fn resolve(&mut self, now: Instant, timeout: Duration, emit: &mut impl FnMut(SyncAction)) {
        let Some(mut range) = self.range else { return };
        let Some(att) = range.attempt else { return };

        match att.state {
            ColReqState::AwaitingPeer { retry_at } => {
                if now >= retry_at {
                    emit(SyncAction::RequestColumnsByRange {
                        request_id: att.request_id,
                        peer: 0,
                        start: range.start_slot,
                        count: range.count,
                        columns: range.remaining,
                        tried_peers: self.tried_peers(),
                    });
                }
                self.range = Some(range);
            }
            ColReqState::InFlight { peer, last_progress_at, .. } => {
                if now.saturating_duration_since(last_progress_at) >= timeout {
                    // No terminator / no sidecar for a full window: peer stall.
                    self.tried.insert(peer);
                    range.attempt = None;
                    self.range = Some(range);
                    emit(SyncAction::ScorePeer { peer, severity: RpcSeverity::HighTolerance });
                } else {
                    self.range = Some(range);
                }
            }
            ColReqState::Delivered { columns, peer_head_at_issue } => {
                range.served_through = range.served_through.min(peer_head_at_issue);
                range.remaining &= !columns;
                range.attempts = 0;
                range.attempt = None;
                if range.remaining == 0 {
                    let end = (range.start_slot + range.count - 1).min(range.served_through);
                    self.synced_through = self.synced_through.max(end);
                    self.tried.clear();
                    self.range = None;
                } else {
                    self.range = Some(range);
                }
            }
            ColReqState::Errored { peer } => {
                self.tried.insert(peer);
                range.attempt = None;
                self.range = Some(range);
            }
        }
    }

    fn open_range(
        &mut self,
        block_synced_through: u64,
        block_inflight_end: u64,
        local_head: u64,
        custody: u128,
        batch: u64,
    ) {
        if self.range.is_some() {
            return;
        }
        let base = self.synced_through.max(local_head);
        let cap = block_synced_through.max(block_inflight_end);
        if base >= cap {
            return;
        }
        let count = (cap - base).min(batch);
        self.tried.clear();
        self.range = Some(ColRange {
            start_slot: base + 1,
            count,
            remaining: custody,
            attempts: 0,
            served_through: u64::MAX,
            attempt: None,
        });
    }

    fn issue(&mut self, ctx: &mut Ctx, _now: Instant, emit: &mut impl FnMut(SyncAction)) {
        let Some(range) = self.range.as_mut() else { return };
        if range.attempt.is_some() {
            return;
        }
        if range.attempts >= ctx.cfg.max_colreq_attempts {
            // Concede: advance past the range; storage's by-root wheel picks up
            // the stragglers as blocks land.
            self.synced_through = self.synced_through.max(range.start_slot + range.count - 1);
            self.tried.clear();
            self.range = None;
            return;
        }
        let request_id = BASE_REQUEST_ID | ctx.next_request_id;
        ctx.next_request_id += 1;
        emit(SyncAction::RequestColumnsByRange {
            request_id,
            peer: 0,
            start: range.start_slot,
            count: range.count,
            columns: range.remaining,
            tried_peers: self.tried_peers(),
        });
    }
}
