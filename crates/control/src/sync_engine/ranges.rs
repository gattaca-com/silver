use std::time::{Duration, Instant};

use silver_common::{DataKind, Origin, RequestId, Scope, SyncRequest};

use super::{
    ControlCounters, Placement, SyncAction,
    peers::PeerView,
    sync_window::{Needs, Slot, SyncWindow},
};

#[derive(Clone, Copy)]
struct Range {
    request_id: u64,
    start: Slot,
    count: u64,
}

impl Range {
    fn end(self) -> Slot {
        self.start.saturating_add(self.count.saturating_sub(1))
    }

    fn covers(self, slot: Slot) -> bool {
        (self.start..=self.end()).contains(&slot)
    }

    fn action(
        self,
        kind: DataKind,
        origin: Origin,
        columns: u128,
        exclude: Option<usize>,
    ) -> SyncAction {
        SyncAction::Request {
            request_id: self.request_id,
            request: SyncRequest {
                kind,
                origin,
                scope: Scope::Range { start: self.start, count: self.count },
                columns,
            },
            exclude,
        }
    }
}

#[derive(Clone, Copy)]
struct Inflight {
    range: Range,
    placement: Placement,
    served: u32,
    reported: u32,
    silent_from: Option<usize>,
}

#[derive(Clone, Copy)]
struct Settling {
    span: (Slot, Slot),
    served: u32,
    reported: u32,
    progress_at: u32,
    since: Instant,
}

impl Settling {
    fn holds(&mut self, start: Slot, now: Instant, settle: Duration) -> bool {
        if !self.covers(start) || self.reported >= self.served {
            return false;
        }
        if self.reported != self.progress_at {
            (self.progress_at, self.since) = (self.reported, now);
        }
        now.saturating_duration_since(self.since) < settle
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

pub(super) struct Ranges {
    origin: Origin,
    batch: u64,
    columns: u128,
    settle: Duration,
    ranges: [RangeState; 3],
}

impl Ranges {
    pub(super) fn new(origin: Origin, batch: u64, columns: u128, settle: Duration) -> Self {
        Self { origin, batch, columns, settle, ranges: [RangeState::Idle; 3] }
    }

    pub(super) fn set_columns(&mut self, columns: u128) {
        self.columns = columns;
    }

    pub(super) fn reset(&mut self) {
        self.ranges = [RangeState::Idle; 3];
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

    /// Returns a block span that two peers holding it answered with silence.
    /// One peer's silence is not believed: it re-offers the range to any
    /// other peer.
    pub(super) fn on_terminator(
        &mut self,
        peers: &PeerView,
        request_id: u64,
        peer: usize,
        delivered: bool,
        now: Instant,
    ) -> Option<(Slot, Slot)> {
        let (kind, r) = self.inflight_of(request_id)?;
        let (range, served, reported) = (r.range, r.served, r.reported);
        let span = (range.start, range.end());
        let silent = delivered &&
            served == 0 &&
            kind == DataKind::Block &&
            peers.claims_span(peer, span.0..=span.1);
        if silent && r.silent_from.is_none_or(|first| first == peer) {
            silver_log::debug!(peer, start = span.0, end = span.1, "silent range, confirming");
            r.silent_from = Some(peer);
            r.placement = Placement::AwaitingPeer { retry_at: now };
            return None;
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
        silent.then_some(span)
    }

    pub(super) fn reoffer_unplaced(
        &mut self,
        now: Instant,
        emit: &mut impl FnMut(SyncAction) -> bool,
    ) {
        for kind in DataKind::ALL {
            let RangeState::WithPeers(mut r) = self.ranges[kind.index()] else { continue };
            if !r.placement.needs_reoffer(now) {
                continue;
            }
            let placed = emit(r.range.action(kind, self.origin, self.columns, r.silent_from));
            r.placement = Placement::after_emit(placed, now);
            self.ranges[kind.index()] = RangeState::WithPeers(r);
        }
    }

    pub(super) fn retire_overtaken(&mut self, tail: Slot) {
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

    /// A kind already in flight, or still settling over the slot the next range
    /// would start at, is left alone.
    pub(super) fn issue(
        &mut self,
        window: &SyncWindow,
        up_to: Slot,
        needs: Needs,
        next_id: &mut u64,
        now: Instant,
        emit: &mut impl FnMut(SyncAction) -> bool,
    ) {
        let last = up_to.min(window.ceiling());
        for kind in DataKind::ALL {
            let state = &mut self.ranges[kind.index()];
            if matches!(state, RangeState::WithPeers(_)) || !needs.reachable(kind, last) {
                continue;
            }
            let Some(start) = (window.tail().saturating_add(1)..=last)
                .find(|&slot| window.coverage(slot).owes(kind, slot, needs))
            else {
                continue;
            };
            if let RangeState::Settling(settling) = state &&
                settling.holds(start, now, self.settle)
            {
                continue;
            }
            // Trim both ends to what is owed: `start` already skipped what we
            // hold below, and gossip fills the top of the window while the
            // middle is still being fetched.
            let cap = last.min(start.saturating_add(self.batch.saturating_sub(1)));
            let end = (start..=cap)
                .rev()
                .find(|&slot| window.coverage(slot).owes(kind, slot, needs))
                .unwrap_or(start);
            let count = end.saturating_sub(start).saturating_add(1);
            let request_id = RequestId::next(kind, self.origin, next_id);
            let range = Range { request_id, start, count };

            silver_log::debug!(?kind, start, count, origin = ?self.origin, "range request");
            let placed = emit(range.action(kind, self.origin, self.columns, None));
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
                silent_from: None,
            });
        }
    }
}
