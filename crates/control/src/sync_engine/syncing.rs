use std::time::{Duration, Instant};

use silver_common::{DataKind, Origin, Scope, SyncUpdate, hex32};

use super::{
    BATCH, ControlCounters, Ctx, SETTLE_TIMEOUT, SyncAction,
    ranges::Ranges,
    sync_window::{Needs, Slot, SyncWindow},
};

pub(super) const TAIL_UNAVAILABLE_TIMEOUT: Duration = Duration::from_secs(8);
pub(super) const CHAIN_UNAVAILABLE_TIMEOUT: Duration = Duration::from_secs(32);

#[derive(Default)]
struct Stall {
    since: Option<Instant>,
    reported: Option<Slot>,
    abandoned: Option<Slot>,
}

pub(super) struct Syncing {
    target: SyncUpdate,
    ranges: Ranges,
    stall: Stall,
}

impl Syncing {
    pub(super) fn new(target: SyncUpdate, custody_columns: u128) -> Self {
        debug_assert!(!target.is_following(), "`Syncing` chases a chain; `Following` is not one");
        Self {
            target,
            ranges: Ranges::new(Origin::Live, BATCH, custody_columns, SETTLE_TIMEOUT),
            stall: Stall::default(),
        }
    }

    pub(super) fn target(&self) -> SyncUpdate {
        self.target
    }

    pub(super) fn repin(&mut self, target: SyncUpdate) {
        debug_assert!(self.target.same_target_as(target), "`repin` is for the same chain");
        self.target = target;
    }

    pub(super) fn restart(&mut self) {
        self.ranges.reset();
        self.stall = Stall::default();
    }

    fn chain_root(&self) -> [u8; 32] {
        match self.target {
            SyncUpdate::SyncingFinalized { target_root, .. } => target_root,
            SyncUpdate::SyncingHead { head_root, .. } => head_root,
            SyncUpdate::Following => [0u8; 32],
        }
    }

    fn needs(&self, ctx: &Ctx) -> Needs {
        Needs {
            data_availability_floor: self
                .target
                .data_availability_floor(ctx.local.finalized_slot()),
            custodies_columns: ctx.custody_columns != 0,
            gloas_fork_slot: ctx.spec.gloas_fork_slot(),
        }
    }

    pub(super) fn inflight_span(&self, kind: DataKind) -> Option<(Slot, Slot)> {
        self.ranges.inflight_span(kind)
    }

    pub(super) fn on_msg_served(&mut self, request_id: u64) {
        self.ranges.on_msg_served(request_id);
    }

    pub(super) fn note_report(&mut self, kind: DataKind, slot: Slot) {
        self.ranges.note_report(kind, slot);
    }

    pub(super) fn on_terminator(
        &mut self,
        ctx: &mut Ctx,
        window: &mut SyncWindow,
        request_id: u64,
        peer: usize,
        delivered: bool,
        now: Instant,
    ) {
        let Some(d) = self.ranges.on_terminator(request_id, delivered, now) else {
            return;
        };
        // Silence across a span the peer holds is the one emptiness proof
        // beacon state cannot supply: with no block above the run, no
        // `parent_slot` ever spans it, and the tail would owe these slots
        // forever. Which *delivered* slots settle is beacon state's call, not
        // the wire's — a block it has not reported may still be in its hands.
        if d.kind == DataKind::Block &&
            d.served == 0 &&
            ctx.peers.claims_span(peer, d.span.0..=d.span.1)
        {
            for slot in d.span.0..=d.span.1 {
                window.mark_empty(slot);
            }
        }
    }

    /// Returns true when the chain was marked unavailable, so the caller
    /// re-runs target selection.
    pub(super) fn drive(
        &mut self,
        ctx: &mut Ctx,
        window: &mut SyncWindow,
        now: Instant,
        emit: &mut impl FnMut(SyncAction) -> bool,
    ) -> bool {
        self.ranges.reoffer_unplaced(now, emit);
        self.advance_tail(ctx, window, now);
        self.ranges.retire_overtaken(window.tail());
        let abandoned = self.report_stalled_tail(ctx, window, now, emit);
        self.issue_requests(ctx, window, now, emit);
        abandoned
    }

    fn advance_tail(&mut self, ctx: &Ctx, window: &mut SyncWindow, now: Instant) {
        let needs = self.needs(ctx);
        if window.advance_tail(self.target.end_slot(), needs) {
            self.stall = Stall::default();
        } else {
            self.stall.since.get_or_insert(now);
        }
    }

    fn report_stalled_tail(
        &mut self,
        ctx: &mut Ctx,
        window: &mut SyncWindow,
        now: Instant,
        emit: &mut impl FnMut(SyncAction) -> bool,
    ) -> bool {
        let Some(since) = self.stall.since else { return false };
        let stalled_for = now.saturating_duration_since(since);
        let slot = window.tail() + 1;

        if stalled_for >= TAIL_UNAVAILABLE_TIMEOUT && self.stall.reported != Some(slot) {
            self.stall.reported = Some(slot);
            ControlCounters::TailUnavailable.inc();
            emit(SyncAction::DiscoverPeers);
            let (needs_outstanding, oldest) = ctx.root_requests.outstanding();
            let arrivals = window.seen_blocks(slot);
            tracing::error!(
                owed_from = slot,
                applied_head = ctx.local.head_imported_slot,
                coverage = ?window.coverage(slot),
                block_root = (arrivals.count > 0).then(|| hex32(&arrivals.root)),
                blocks_seen = arrivals.count,
                asked_for_blocks = ?self.inflight_span(DataKind::Block),
                ?stalled_for,
                target = ?self.target,
                needs_outstanding,
                need_root = oldest.as_ref().map(|n| hex32(&n.root)),
                need_kind = ?oldest.as_ref().map(|n| n.kind),
                need_wanted_at = oldest.as_ref().map(|n| n.wanted_at),
                need_attempts = oldest.as_ref().map(|n| n.attempts),
                "sync stalled: no peer served this slot's missing coverage"
            );
        }

        if stalled_for < CHAIN_UNAVAILABLE_TIMEOUT || self.stall.abandoned == Some(slot) {
            return false;
        }
        self.stall.abandoned = Some(slot);
        let arrivals = window.seen_blocks(slot);
        ctx.peers.mark_unavailable(self.chain_root());
        tracing::error!(
            owed_from = slot,
            coverage = ?window.coverage(slot),
            block_root = (arrivals.count > 0).then(|| hex32(&arrivals.root)),
            blocks_seen = arrivals.count,
            ?stalled_for,
            target = ?self.target,
            "sync stalled on one slot: marking the chain unavailable for selection"
        );
        true
    }

    fn issue_requests(
        &mut self,
        ctx: &mut Ctx,
        window: &mut SyncWindow,
        now: Instant,
        emit: &mut impl FnMut(SyncAction) -> bool,
    ) {
        if !ctx.local.have_status {
            return;
        }
        let needs = self.needs(ctx);
        let target = self.target;
        self.ranges.issue(window, target.end_slot(), needs, &mut ctx.next_request_id, now, &mut |action| {
            if let SyncAction::Request { request, .. } = &action &&
                let Scope::Range { start, count } = request.scope
            {
                tracing::info!(kind = ?request.kind, start, count, ?target, "sync: range request");
            }
            emit(action)
        });
    }
}
