use std::time::{Duration, Instant};

use silver_common::{RpcSeverity, SyncUpdate, msg_is_envelope_request, msg_is_live_column_request};

use super::{
    Ctx, SLOTS_PER_EPOCH,
    event::SyncAction,
    range_driver::{ColumnSync, EnvelopeSync},
    same_target_identity,
};

pub(super) const IMPORT_STALL_TIMEOUT: Duration = Duration::from_secs(24);
const HEAD_SYNC_BLOCKS_BY_RANGE_BATCH: u64 = 32;
const HEAD_SYNC_MAX_AHEAD_SLOTS: u64 = 64;
pub(super) const ISSUE_RETRY_BACKOFF: Duration = Duration::from_millis(250);

#[derive(Clone, Copy)]
struct ForwardReq {
    request_id: u64,
    start_slot: u64,
    count: u64,
    state: ReqState,
}

#[derive(Clone, Copy)]
enum ReqState {
    AwaitingPeer {
        retry_at: Instant,
    },
    InFlight {
        peer: usize,
        peer_head_at_issue: u64,
        last_observed_head_slot: u64,
        last_progress_at: Instant,
    },
    Delivered {
        peer_head_at_issue: u64,
    },
    Errored,
}

pub(super) struct Syncing {
    target: SyncUpdate,
    synced_through: u64,
    inflight: Option<ForwardReq>,
    pending_since: Option<Instant>,
    columns: ColumnSync,
    envelopes: EnvelopeSync,
}

impl Syncing {
    pub(super) fn new(target: SyncUpdate) -> Self {
        Self {
            target,
            synced_through: 0,
            inflight: None,
            pending_since: None,
            columns: ColumnSync::default(),
            envelopes: EnvelopeSync::default(),
        }
    }

    pub(super) fn target(&self) -> SyncUpdate {
        self.target
    }

    pub(super) fn synced_through(&self) -> u64 {
        self.synced_through
    }

    pub(super) fn inflight_end(&self) -> u64 {
        self.inflight.map_or(0, |r| r.start_slot + r.count - 1)
    }

    /// Re-point at a new target. A monotonic finalized advance, a
    /// finalized→head handoff, or a small head bump is the *same* chain
    /// continuing — keep the watermark + in-flight. A genuine chain-segment
    /// change resets them so the next batch re-derives from the applied head.
    /// On the finalized→head edge, seed the column watermark to the applied
    /// head (columns aren't fetched during `SyncingFinalized`).
    pub(super) fn retarget(&mut self, new: SyncUpdate, head_lag_threshold_slots: u64, head: u64) {
        let prev = self.target;
        self.target = new;
        if same_target_identity(prev, new) {
            return;
        }
        let small_head_advance = match (prev, new) {
            (
                SyncUpdate::SyncingHead { head_slot: p, .. },
                SyncUpdate::SyncingHead { head_slot: n, .. },
            ) => n.abs_diff(p) <= head_lag_threshold_slots,
            _ => false,
        };
        if small_head_advance {
            return;
        }
        let same_chain_forward = match (prev, new) {
            (
                SyncUpdate::SyncingFinalized { target_epoch: p, .. },
                SyncUpdate::SyncingFinalized { target_epoch: n, .. },
            ) => n >= p,
            (SyncUpdate::SyncingFinalized { .. }, SyncUpdate::SyncingHead { .. }) => true,
            _ => false,
        };
        if !same_chain_forward {
            self.inflight = None;
            self.synced_through = 0;
        } else if matches!(prev, SyncUpdate::SyncingFinalized { .. }) &&
            matches!(new, SyncUpdate::SyncingHead { .. })
        {
            self.columns.seed(head);
        }
    }

    /// Applied head advanced — restart the stall clock.
    pub(super) fn on_head_advance(&mut self) {
        self.pending_since = None;
    }

    /// A rejected block breaks the delivered chain past our applied head —
    /// re-derive blocks + columns from the applied head.
    pub(super) fn on_block_rejected(&mut self) {
        self.synced_through = 0;
        self.inflight = None;
        self.columns = ColumnSync::default();
        self.envelopes = EnvelopeSync::default();
    }

    /// Forward terminator (engine-issued). The `BASE_REQUEST_ID` prefix routes
    /// column requests; the rest are block requests. Transitions the in-flight
    /// request to `Delivered` (advances the watermark in `drive`) or `Errored`
    /// (retry from the applied head).
    pub(super) fn on_terminator(&mut self, request_id: u64, peer: usize, delivered: bool) {
        if msg_is_live_column_request(request_id) {
            self.columns.on_terminator(request_id, delivered);
        } else if msg_is_envelope_request(request_id) {
            self.envelopes.on_terminator(request_id, delivered);
        } else if let Some(r) = self.inflight.as_mut() &&
            r.request_id == request_id &&
            let ReqState::InFlight { peer: p, peer_head_at_issue, .. } = r.state &&
            p == peer
        {
            tracing::info!(delivered, peer, target=?self.target, "sync request completed");
            r.state = if delivered {
                ReqState::Delivered { peer_head_at_issue }
            } else {
                ReqState::Errored
            };
        }
    }

    /// `DataColumnSidecar` chunk — refresh the column attempt's progress timer
    /// (blocks are head-paced, so block chunks are ignored).
    pub(super) fn on_chunk(&mut self, request_id: u64, now: Instant) {
        if msg_is_live_column_request(request_id) {
            self.columns.on_chunk(request_id, now);
        } else if msg_is_envelope_request(request_id) {
            self.envelopes.on_chunk(request_id, now);
        }
    }

    /// Record the outcome of routing the last emitted `RequestBlocksByRange`.
    /// `Some(peer)`: PM picked + sent → `InFlight`. `None`: no eligible peer /
    /// over cap → `AwaitingPeer`, re-emitted after the backoff.
    pub(super) fn on_request_issued(
        &mut self,
        ctx: &Ctx,
        request_id: u64,
        start: u64,
        count: u64,
        peer: Option<usize>,
        now: Instant,
    ) {
        let state = match peer {
            Some(peer) => ReqState::InFlight {
                peer,
                peer_head_at_issue: ctx.peers.head_slot_of(peer).unwrap_or(0),
                last_observed_head_slot: ctx.local.head_imported_slot,
                last_progress_at: now,
            },
            None => ReqState::AwaitingPeer { retry_at: now + ISSUE_RETRY_BACKOFF },
        };
        self.inflight = Some(ForwardReq { request_id, start_slot: start, count, state });
    }

    pub(super) fn on_range_request_issued(
        &mut self,
        ctx: &Ctx,
        request_id: u64,
        peer: Option<(usize, u128)>,
        now: Instant,
    ) {
        if msg_is_live_column_request(request_id) {
            self.columns.on_request_issued(ctx, request_id, peer, now);
        } else if msg_is_envelope_request(request_id) {
            self.envelopes.on_request_issued(ctx, request_id, peer, now);
        }
    }

    /// Drive the lifecycle: block completion (terminator-driven), progress/
    /// timeout, import-stall backtrack, block issuance, then the trailing
    /// column driver. Issuance emits `RequestBlocksByRange` /
    /// `RequestColumnsByRange` (peer unset; PM picks + caps on routing,
    /// then `on_request_issued` / `on_range_request_issued` records the
    /// chosen peer); a stalled peer is scored via `ScorePeer`.
    pub(super) fn drive(&mut self, ctx: &mut Ctx, now: Instant, emit: &mut impl FnMut(SyncAction)) {
        if ctx.awaiting_local_replay {
            return;
        }
        // Trailing column catch-up first — the block-issuance early-returns
        // below must not starve it (head-sync only; columns aren't fetched
        // during SyncingFinalized). Paced to the block watermark + in-flight.
        if !matches!(self.target, SyncUpdate::SyncingFinalized { .. }) {
            let block_inflight_end = self.inflight_end();
            self.columns.drive(ctx, self.synced_through, block_inflight_end, now, emit);
        }
        // Trailing envelope catch-up. Every full-payload gloas block needs its
        // envelope before its child can apply, so fetch at block pace — in both
        // sync phases.
        let block_inflight_end = self.inflight_end();
        self.envelopes.drive(ctx, self.synced_through, block_inflight_end, now, emit);
        let head_slot = ctx.local.head_imported_slot;

        let (sync_through, complete) = match &mut self.inflight {
            None => (None, true),
            Some(req) => {
                let end_inclusive = req.start_slot + req.count - 1;
                match &mut req.state {
                    ReqState::AwaitingPeer { retry_at } => {
                        if now >= *retry_at {
                            emit(SyncAction::RequestBlocksByRange {
                                request_id: req.request_id,
                                peer: 0,
                                start: req.start_slot,
                                count: req.count,
                            });
                            // Re-arm locally; pacing must not depend on the caller
                            // round-tripping back through `on_request_issued`.
                            *retry_at = now + ISSUE_RETRY_BACKOFF;
                        }
                        (None, false)
                    }
                    ReqState::InFlight {
                        peer, last_observed_head_slot, last_progress_at, ..
                    } => {
                        if head_slot > *last_observed_head_slot {
                            *last_observed_head_slot = head_slot;
                            *last_progress_at = now;
                            (None, false)
                        } else {
                            let timeout =
                                Duration::from_millis(ctx.cfg.inflight_progress_timeout_ms);
                            let mut sync_through = None;
                            if now.saturating_duration_since(*last_progress_at) >= timeout {
                                if head_slot < req.start_slot {
                                    emit(SyncAction::ScorePeer {
                                        peer: *peer,
                                        severity: RpcSeverity::HighTolerance,
                                    });
                                } else if head_slot >= end_inclusive {
                                    sync_through = Some(end_inclusive);
                                }
                                (sync_through, true)
                            } else {
                                (None, false)
                            }
                        }
                    }
                    ReqState::Delivered { peer_head_at_issue } => {
                        (Some(end_inclusive.min(*peer_head_at_issue)), true)
                    }
                    ReqState::Errored => (None, true),
                }
            }
        };

        if let Some(sync) = sync_through {
            self.synced_through = self.synced_through.max(sync);
        }
        if complete {
            self.inflight = None;
        }

        // Import-stall backtrack: the watermark led import (normal) but import
        // froze — reset to the applied head, drop in-flight, re-fetch from the
        // frontier this loop. A fresh delivery does *not* refresh the clock;
        // only the applied head advancing does (via `on_head_advance`).
        if ctx.local.have_status && self.synced_through > head_slot {
            let since = *self.pending_since.get_or_insert(now);
            if now.saturating_duration_since(since) >= IMPORT_STALL_TIMEOUT {
                tracing::warn!(
                    synced_through = self.synced_through,
                    local_head = head_slot,
                    "sync-engine: import stalled; backtracking watermark to applied head"
                );
                self.synced_through = head_slot;
                self.inflight = None;
                self.pending_since = None;
            }
        } else {
            self.pending_since = None;
        }

        if self.inflight.is_some() || !ctx.local.have_status {
            return;
        }

        let target_end_slot = match self.target {
            SyncUpdate::SyncingFinalized { target_epoch, .. } => {
                target_epoch.saturating_add(2).saturating_mul(SLOTS_PER_EPOCH)
            }
            SyncUpdate::SyncingHead { head_slot, .. } => head_slot,
            SyncUpdate::Following => return,
        };
        if head_slot >= target_end_slot {
            return;
        }

        let next_base = head_slot.max(self.synced_through);
        if next_base >= target_end_slot {
            return;
        }

        let max_ahead = match self.target {
            SyncUpdate::SyncingHead { .. } => HEAD_SYNC_MAX_AHEAD_SLOTS,
            _ => ctx.cfg.max_blocks_by_range_batch,
        };
        if self.synced_through > head_slot + max_ahead {
            return;
        }

        if !matches!(self.target, SyncUpdate::SyncingFinalized { .. }) &&
            ctx.custody_columns != 0 &&
            self.synced_through >
                self.columns.synced_through() + ctx.cfg.max_blocks_by_range_batch
        {
            return;
        }

        let start_slot = next_base + 1;
        let remaining = target_end_slot.saturating_sub(next_base);
        let count = match self.target {
            SyncUpdate::SyncingFinalized { target_epoch, .. } => {
                let target_slot = target_epoch.saturating_mul(SLOTS_PER_EPOCH) + 1;
                target_slot
                    .saturating_sub(start_slot)
                    .min(remaining)
                    .min(ctx.cfg.max_blocks_by_range_batch)
            }
            SyncUpdate::SyncingHead { .. } => {
                let ahead_cap = (head_slot + HEAD_SYNC_MAX_AHEAD_SLOTS).saturating_sub(next_base);
                remaining
                    .min(HEAD_SYNC_BLOCKS_BY_RANGE_BATCH)
                    .min(ctx.cfg.max_blocks_by_range_batch)
                    .min(ahead_cap)
            }
            SyncUpdate::Following => return,
        };
        if count == 0 {
            return;
        }

        let request_id = ctx.next_request_id;
        ctx.next_request_id += 1;
        tracing::info!(target = ?self.target, start = start_slot, count, "sync-engine: forward BlocksByRange");
        emit(SyncAction::RequestBlocksByRange { request_id, peer: 0, start: start_slot, count });
    }
}
