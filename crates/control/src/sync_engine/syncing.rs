use std::time::{Duration, Instant};

use silver_common::{DataKind, Origin, RequestId, Scope, SyncRequest, SyncUpdate, hex32};

use super::{
    BATCH, ControlCounters, Ctx, Placement, SETTLE_TIMEOUT, SyncAction,
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

#[derive(Clone, Copy)]
struct Range {
    request_id: u64,
    start: Slot,
    count: u64,
}

impl Range {
    fn end(self) -> Slot {
        self.start + self.count - 1
    }

    fn covers(self, slot: Slot) -> bool {
        (self.start..=self.end()).contains(&slot)
    }

    fn action(self, kind: DataKind, custody_columns: u128) -> SyncAction {
        SyncAction::Request {
            request_id: self.request_id,
            request: SyncRequest {
                kind,
                origin: Origin::Live,
                scope: Scope::Range { start: self.start, count: self.count },
                columns: custody_columns,
            },
        }
    }
}

#[derive(Clone, Copy)]
struct Inflight {
    range: Range,
    placement: Placement,
    /// Chunks the wire handed over for this range, and slots inside it the
    /// tiles have reported back on.
    served: u32,
    reported: u32,
}

/// A span a peer delivered, held while the tiles that consume it work through
/// what arrived.
#[derive(Clone, Copy)]
struct Settling {
    span: (Slot, Slot),
    served: u32,
    reported: u32,
    /// `reported` when the wait last restarted, and when that was.
    progress_at: u32,
    since: Instant,
}

impl Settling {
    /// Whether the range this delivery covered is still worth waiting on.
    fn holds(&mut self, start: Slot, now: Instant) -> bool {
        if !self.covers(start) || self.reported >= self.served {
            return false;
        }
        if self.reported != self.progress_at {
            (self.progress_at, self.since) = (self.reported, now);
        }
        now.saturating_duration_since(self.since) < SETTLE_TIMEOUT
    }

    fn covers(&self, slot: Slot) -> bool {
        (self.span.0..=self.span.1).contains(&slot)
    }
}

#[derive(Clone, Copy, Default)]
enum RangeState {
    #[default]
    Idle,
    WithPeers(Inflight),
    Settling(Settling),
}

pub(super) struct Syncing {
    target: SyncUpdate,
    ranges: [RangeState; 3],
    stall: Stall,
}

impl Syncing {
    pub(super) fn new(target: SyncUpdate) -> Self {
        debug_assert!(!target.is_following(), "`Syncing` chases a chain; `Following` is not one");
        Self { target, ranges: [RangeState::Idle; 3], stall: Stall::default() }
    }

    pub(super) fn target(&self) -> SyncUpdate {
        self.target
    }

    pub(super) fn repin(&mut self, target: SyncUpdate) {
        debug_assert!(self.target.same_target_as(target), "`repin` is for the same chain");
        self.target = target;
    }

    pub(super) fn restart(&mut self) {
        *self = Self::new(self.target);
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

    fn inflight_of(&mut self, request_id: u64) -> Option<(DataKind, &mut Inflight)> {
        self.ranges.iter_mut().enumerate().find_map(|(i, state)| match state {
            RangeState::WithPeers(r) if r.range.request_id == request_id => {
                Some((DataKind::ALL[i], r))
            }
            _ => None,
        })
    }

    pub(super) fn inflight_span(&self, kind: DataKind) -> Option<(Slot, Slot)> {
        match self.ranges[kind.index()] {
            RangeState::WithPeers(r) => Some((r.range.start, r.range.end())),
            RangeState::Idle | RangeState::Settling(_) => None,
        }
    }

    pub(super) fn on_msg_served(&mut self, request_id: u64) {
        if let Some((_, r)) = self.inflight_of(request_id) {
            r.served = r.served.saturating_add(1);
        }
    }

    pub(super) fn note_report(&mut self, kind: DataKind, slot: Slot) {
        match &mut self.ranges[kind.index()] {
            RangeState::WithPeers(r) if r.range.covers(slot) => {
                r.reported = r.reported.saturating_add(1)
            }
            RangeState::Settling(s) if s.covers(slot) => s.reported = s.reported.saturating_add(1),
            RangeState::Idle | RangeState::WithPeers(_) | RangeState::Settling(_) => {}
        }
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
        let Some((kind, r)) = self.inflight_of(request_id) else {
            return;
        };
        let (range, served, reported) = (r.range, r.served, r.reported);
        // Silence across a span the peer holds is the one emptiness proof
        // beacon state cannot supply: with no block above the run, no
        // `parent_slot` ever spans it, and the tail would owe these slots
        // forever. Which *delivered* slots settle is beacon state's call, not
        // the wire's — a block it has not reported may still be in its hands.
        if delivered &&
            kind == DataKind::Block &&
            served == 0 &&
            ctx.peers.claims_span(peer, range.start..=range.end())
        {
            for slot in range.start..=range.end() {
                window.mark_empty(slot);
            }
        }
        // Silence leaves nothing in anyone's hands to wait for, so the span is
        // free to be offered to another peer at once.
        self.ranges[kind.index()] = match delivered && served > 0 {
            true => RangeState::Settling(Settling {
                span: (range.start, range.end()),
                served,
                reported,
                progress_at: reported,
                since: now,
            }),
            false => RangeState::Idle,
        };
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
        self.reoffer_unplaced(ctx, now, emit);
        self.advance_tail(ctx, window, now);
        self.retire_overtaken_ranges(window);
        let abandoned = self.report_stalled_tail(ctx, window, now, emit);
        self.issue_requests(ctx, window, now, emit);
        abandoned
    }

    fn reoffer_unplaced(
        &mut self,
        ctx: &Ctx,
        now: Instant,
        emit: &mut impl FnMut(SyncAction) -> bool,
    ) {
        for kind in DataKind::ALL {
            let RangeState::WithPeers(mut r) = self.ranges[kind.index()] else { continue };
            if !r.placement.needs_reoffer(now) {
                continue;
            }
            let placed = emit(r.range.action(kind, ctx.custody_columns));
            r.placement = Placement::after_emit(placed, now);
            self.ranges[kind.index()] = RangeState::WithPeers(r);
        }
    }

    fn retire_overtaken_ranges(&mut self, window: &SyncWindow) {
        let tail = window.tail();
        for state in &mut self.ranges {
            let end = match state {
                RangeState::WithPeers(r) => r.range.end(),
                RangeState::Settling(s) => s.span.1,
                RangeState::Idle => continue,
            };
            if end <= tail {
                *state = RangeState::Idle;
            }
        }
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
                applied_head = window.applied_head(),
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
        let last = self.target.end_slot().min(window.ceiling());
        let needs = self.needs(ctx);

        for kind in DataKind::ALL {
            let state = &mut self.ranges[kind.index()];
            if matches!(state, RangeState::WithPeers(_)) || !needs.reachable(kind, last) {
                continue;
            }
            let Some(start) = (window.tail() + 1..=last)
                .find(|&slot| window.coverage(slot).owes(kind, slot, needs))
            else {
                continue;
            };
            if let RangeState::Settling(settling) = state &&
                settling.holds(start, now)
            {
                continue;
            }
            // Trim both ends to what is owed: `start` already skipped what we
            // hold below, and gossip fills the top of the window while the
            // middle is still being fetched.
            let cap = last.min(start + BATCH - 1);
            let end = (start..=cap)
                .rev()
                .find(|&slot| window.coverage(slot).owes(kind, slot, needs))
                .unwrap_or(start);
            let count = end - start + 1;
            let request_id = RequestId::next(kind, Origin::Live, &mut ctx.next_request_id);
            let range = Range { request_id, start, count };

            tracing::info!(?kind, start, count, target = ?self.target, "sync: range request");
            let placed = emit(range.action(kind, ctx.custody_columns));
            if placed {
                ControlCounters::RangesIssued.inc();
            } else {
                ControlCounters::RangesUnplaced.inc();
            }
            self.ranges[kind.index()] = RangeState::WithPeers(Inflight {
                range,
                placement: Placement::after_emit(placed, now),
                served: 0,
                reported: 0,
            });
        }
    }
}
