use std::time::Instant;

use silver_common::{DataKind, Origin, RequestId, Scope, SyncRequest};

use super::{Placement, SETTLE_TIMEOUT, SyncAction};

#[derive(Default)]
pub(super) struct BackfillPlan {
    blocks: RangeWalk,
    columns: RangeWalk,
    envelopes: RangeWalk,
}

#[derive(Default)]
struct RangeWalk {
    floor: u64,
    next: u64,
    req: Option<Req>,
    settling: Option<Settling>,
    /// Objects storage has reported landing for this kind. The count moving is
    /// the only honest sign of progress: a column set clearing in the middle of
    /// the owed span moves neither of its bounds.
    landed: u32,
}

struct Settling {
    start: u64,
    since: Instant,
    landed: u32,
}

#[derive(Clone, Copy)]
struct Req {
    request_id: u64,
    start: u64,
    placement: Placement,
}

impl RangeWalk {
    fn set_gap(&mut self, floor: u64, next: u64) {
        self.floor = floor;
        self.next = next;
        // Storage linked past where the request started, so the range is done
        // with rather than merely quiet.
        if self.settling.as_ref().is_some_and(|s| next <= s.start) {
            self.settling = None;
        }
    }

    fn on_arrived(&mut self) {
        self.landed = self.landed.wrapping_add(1);
    }

    fn done(&self) -> bool {
        self.next <= self.floor
    }

    fn on_complete(&mut self, request_id: u64, now: Instant) {
        let Some(req) = self.req.as_ref().filter(|r| r.request_id == request_id) else {
            return;
        };
        self.settling = Some(Settling { start: req.start, since: now, landed: self.landed });
        self.req = None;
    }

    fn on_failed(&mut self, request_id: u64) {
        if self.req.as_ref().is_some_and(|r| r.request_id == request_id) {
            self.req = None;
        }
    }

    fn drive(
        &mut self,
        kind: DataKind,
        columns: u128,
        batch: u64,
        next_id: &mut u64,
        now: Instant,
        emit: &mut impl FnMut(SyncAction) -> bool,
    ) {
        let ask = |request_id, start, count| SyncAction::Request {
            request_id,
            request: SyncRequest {
                kind,
                origin: Origin::Backfill,
                scope: Scope::Range { start, count },
                columns,
            },
        };
        if let Some(&Req { request_id, start, placement }) = self.req.as_ref() {
            if !placement.needs_reoffer(now) {
                return;
            }
            if start < self.next {
                let placed = emit(ask(request_id, start, self.next - start));
                self.req =
                    Some(Req { request_id, start, placement: Placement::after_emit(placed, now) });
                return;
            }
            // Storage moved `next` below this offer's own start while it sat
            // unplaced, so the span it names is no longer owed.
            self.req = None;
        }
        if self.done() {
            return;
        }

        if let Some(settling) = self.settling.as_mut() {
            if settling.landed != self.landed {
                settling.landed = self.landed;
                settling.since = now;
            }
            if now.saturating_duration_since(settling.since) < SETTLE_TIMEOUT {
                return;
            }
            tracing::warn!(
                start = settling.start,
                next = self.next,
                ?kind,
                "backfill range unconfirmed by storage; asking again"
            );
            self.settling = None;
        }

        let start = self.floor.max(self.next.saturating_sub(batch));
        let request_id = RequestId::next(kind, Origin::Backfill, next_id);
        let placed = emit(ask(request_id, start, self.next - start));
        self.req = Some(Req { request_id, start, placement: Placement::after_emit(placed, now) });
    }
}

impl BackfillPlan {
    pub(super) fn set_owed(&mut self, kind: DataKind, floor: u64, next: u64) {
        self.walk_for(kind).set_gap(floor, next);
    }

    pub(super) fn on_arrived(&mut self, kind: DataKind) {
        self.walk_for(kind).on_arrived();
    }

    pub(super) fn on_terminator(&mut self, request_id: u64, delivered: bool, now: Instant) {
        let id = RequestId::from(request_id);
        if id.origin != Origin::Backfill {
            return;
        }
        let walk = self.walk_for(id.kind);
        if delivered {
            walk.on_complete(request_id, now);
        } else {
            walk.on_failed(request_id);
        }
    }

    fn walk_for(&mut self, kind: DataKind) -> &mut RangeWalk {
        match kind {
            DataKind::Block => &mut self.blocks,
            DataKind::Columns => &mut self.columns,
            DataKind::Envelope => &mut self.envelopes,
        }
    }

    pub(super) fn drive(
        &mut self,
        custody_columns: u128,
        batch: u64,
        next_id: &mut u64,
        now: Instant,
        emit: &mut impl FnMut(SyncAction) -> bool,
    ) {
        self.blocks.drive(DataKind::Block, 0, batch, next_id, now, emit);
        self.columns.drive(DataKind::Columns, custody_columns, batch, next_id, now, emit);
        self.envelopes.drive(DataKind::Envelope, 0, batch, next_id, now, emit);
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{super::ISSUE_RETRY_BACKOFF, *};

    fn plan(floor: u64, earliest: u64) -> BackfillPlan {
        let mut plan = BackfillPlan::default();
        plan.set_owed(DataKind::Block, floor, earliest);
        plan
    }

    /// The driver plus the request-id counter the engine threads through it —
    /// held across calls, or every request would reuse the same id.
    #[derive(Default)]
    struct Driver {
        next_id: u64,
    }

    impl Driver {
        /// Drive once, telling the driver how many wire requests each action
        /// became.
        fn drive(
            &mut self,
            plan: &mut BackfillPlan,
            now: Instant,
            placed: bool,
        ) -> Vec<SyncAction> {
            let mut out = Vec::new();
            plan.drive(0, 64, &mut self.next_id, now, &mut |a| {
                out.push(a);
                placed
            });
            out
        }
    }

    fn block_range(actions: &[SyncAction]) -> Option<(u64, u64, u64)> {
        actions.iter().find_map(|a| match a {
            SyncAction::Request {
                request_id,
                request:
                    SyncRequest { kind: DataKind::Block, scope: Scope::Range { start, count }, .. },
            } => Some((*request_id, *start, *count)),
            _ => None,
        })
    }

    fn range_of(actions: &[SyncAction], kind: DataKind) -> Option<(u64, u64, u64)> {
        actions.iter().find_map(|a| match a {
            SyncAction::Request {
                request_id,
                request: SyncRequest { kind: k, scope: Scope::Range { start, count }, .. },
            } if *k == kind => Some((*request_id, *start, *count)),
            _ => None,
        })
    }

    /// Storage takes many passes to work through what one range delivered, and
    /// reading that as silence re-asks the whole span mid-delivery. What says
    /// it is still working is an object landing — not the span, whose two
    /// bounds a slot clearing in the middle of it does not move.
    #[test]
    fn walk_that_is_still_landing_objects_is_not_silence() {
        let t0 = Instant::now();
        let mut d = Driver::default();
        let mut plan = plan(0, 5120);
        plan.set_owed(DataKind::Columns, 4992, 5056);

        let (rid, start, _) = range_of(&d.drive(&mut plan, t0, true), DataKind::Columns)
            .expect("column range issued");
        assert_eq!(start, 4992);
        plan.on_terminator(rid, true, t0);

        // Slots clear from the middle of the span, so neither bound moves. None
        // of it may trigger a second request.
        let mut at = t0;
        for landed in 1..=8u64 {
            at += SETTLE_TIMEOUT / 2;
            plan.on_arrived(DataKind::Columns);
            assert!(
                range_of(&d.drive(&mut plan, at, true), DataKind::Columns).is_none(),
                "the delivery is still being accounted for, {landed} objects in"
            );
        }

        // Once it does go quiet for a whole timeout, the remainder is asked again.
        plan.set_owed(DataKind::Columns, 5000, 5056);
        at += SETTLE_TIMEOUT + Duration::from_millis(1);
        let (_, start, _) = range_of(&d.drive(&mut plan, at, true), DataKind::Columns)
            .expect("asked again after real silence");
        assert_eq!(start, 5000, "and only for what is left, not the whole window");
    }

    /// An object landing for one kind says nothing about another: the three
    /// walks are independent, and a busy block walk must not hold a column
    /// range that nobody is working on.
    #[test]
    fn one_kind_landing_does_not_hold_another_kinds_range() {
        let t0 = Instant::now();
        let mut d = Driver::default();
        let mut plan = plan(0, 5120);
        plan.set_owed(DataKind::Columns, 4992, 5056);

        let (rid, ..) = range_of(&d.drive(&mut plan, t0, true), DataKind::Columns)
            .expect("column range issued");
        plan.on_terminator(rid, true, t0);

        let mut at = t0;
        for _ in 0..8 {
            at += SETTLE_TIMEOUT / 4;
            plan.on_arrived(DataKind::Block);
        }
        assert!(
            range_of(&d.drive(&mut plan, at, true), DataKind::Columns).is_some(),
            "the column walk went quiet, whatever the block walk was doing"
        );
    }

    /// The disk scan finds owed slots on its way down, so a span can grow while
    /// the peer that was asked has gone quiet. Growth is discovery, not an
    /// answer, and must not keep the remainder from being asked again.
    #[test]
    fn span_that_only_grew_is_still_silence() {
        let t0 = Instant::now();
        let mut d = Driver::default();
        let mut plan = plan(0, 5120);
        plan.set_owed(DataKind::Columns, 4992, 5056);

        let (rid, ..) = range_of(&d.drive(&mut plan, t0, true), DataKind::Columns)
            .expect("column range issued");
        plan.on_terminator(rid, true, t0);

        // The scan seeds lower slots: the floor falls, nothing was delivered.
        let mut at = t0;
        for seeded in 1..=8u64 {
            at += SETTLE_TIMEOUT / 4;
            plan.set_owed(DataKind::Columns, 4992 - seeded, 5056);
        }

        let (_, start, _) = range_of(&d.drive(&mut plan, at, true), DataKind::Columns)
            .expect("asked again: nothing was ever delivered");
        assert_eq!(start, 4992, "one batch below the span's top");
    }

    /// Before the fork there are no envelopes to have, so storage reports an
    /// empty span. Asking anyway would walk history that cannot answer.
    #[test]
    fn an_empty_envelope_span_asks_for_nothing() {
        let now = Instant::now();
        let mut plan = plan(1, 500);
        plan.set_owed(DataKind::Envelope, 0, 0);

        let issued = Driver::default().drive(&mut plan, now, true);

        assert!(range_of(&issued, DataKind::Envelope).is_none(), "no envelopes exist to ask for");
        assert!(range_of(&issued, DataKind::Block).is_some(), "blocks are unaffected");
    }

    /// The fork slot is the bottom of envelope history: the walk works down to
    /// it and stops, because the slots below it never had an envelope to
    /// serve.
    #[test]
    fn the_envelope_walk_stops_at_the_fork_floor() {
        let now = Instant::now();
        let fork_slot = 320;
        let mut plan = BackfillPlan::default();
        plan.set_owed(DataKind::Envelope, fork_slot, fork_slot + 100);

        let mut driver = Driver::default();
        let mut asked = Vec::new();
        for _ in 0..4 {
            let issued = driver.drive(&mut plan, now, true);
            let Some((id, start, count)) = range_of(&issued, DataKind::Envelope) else { break };
            asked.push((start, count));
            // Storage confirms by reporting the lower cursor its writes reached.
            plan.on_terminator(id, true, now);
            plan.set_owed(DataKind::Envelope, fork_slot, start);
        }

        assert!(!asked.is_empty(), "the span above the fork is walked");
        assert!(
            asked.iter().all(|&(start, _)| start >= fork_slot),
            "nothing below the fork is ever asked for: {asked:?}"
        );
        assert_eq!(asked.last().map(|&(start, _)| start), Some(fork_slot), "and it reaches it");
    }

    /// Backfill walks downward, so the range ends where the last one began.
    #[test]
    fn completed_range_moves_the_cursor_down() {
        let now = Instant::now();
        let mut d = Driver::default();
        let mut plan = plan(0, 100);

        let (rid, start, count) = block_range(&d.drive(&mut plan, now, true)).expect("issued");
        assert_eq!((start, count), (36, 64), "one batch below the earliest we hold");

        plan.on_terminator(rid, true, now);
        plan.set_owed(DataKind::Block, 0, 36); // storage linked the whole range
        let (_, start, _) = block_range(&d.drive(&mut plan, now, true)).expect("next batch");
        assert_eq!(start, 0, "resumes at the floor, not below it");
    }

    /// The dead end this closes: a peer may end a range having served only part
    /// of it, and backfill blocks reach no other component that could
    /// notice. Left alone, the cursor walks past the hole, storage can
    /// never link past it, and backfill stops for good.
    #[test]
    fn range_storage_could_not_link_is_asked_for_again() {
        let t0 = Instant::now();
        let mut d = Driver::default();
        let mut plan = plan(0, 100);

        let (rid, start, _) = block_range(&d.drive(&mut plan, t0, true)).expect("issued");
        plan.on_terminator(rid, true, t0);

        // Storage reports the floor it reached: unchanged, so nothing linked.
        plan.set_owed(DataKind::Block, 0, 100);
        assert!(
            block_range(&d.drive(&mut plan, t0, true)).is_none(),
            "no re-ask while storage may still be writing"
        );

        let later = t0 + SETTLE_TIMEOUT + Duration::from_millis(1);
        let (_, again, count) = block_range(&d.drive(&mut plan, later, true)).expect("re-asked");
        assert_eq!((again, count), (start, 64), "the same range, from storage's floor");
    }

    /// A short response that linked *some* of the range resumes from what
    /// landed, not from what was asked for.
    #[test]
    fn partial_link_resumes_from_what_landed() {
        let t0 = Instant::now();
        let mut d = Driver::default();
        let mut plan = plan(0, 100);

        let (rid, ..) = block_range(&d.drive(&mut plan, t0, true)).expect("issued");
        plan.on_terminator(rid, true, t0);
        plan.set_owed(DataKind::Block, 0, 60); // linked 60..100, the rest never arrived

        let later = t0 + SETTLE_TIMEOUT + Duration::from_millis(1);
        let (_, start, _) = block_range(&d.drive(&mut plan, later, true)).expect("re-asked");
        assert_eq!(start, 0, "next batch covers everything below 60");
    }

    /// The range is held while it is outstanding, so the driver does not
    /// re-derive it every loop.
    #[test]
    fn outstanding_range_suppresses_the_next() {
        let now = Instant::now();
        let mut d = Driver::default();
        let mut plan = plan(0, 100);

        assert!(block_range(&d.drive(&mut plan, now, true)).is_some(), "issued");
        assert!(block_range(&d.drive(&mut plan, now, true)).is_none(), "still in flight");
    }

    /// Regression: an unplaced range used to record nothing, so the driver
    /// re-emitted it on every control-loop iteration with a fresh request id.
    #[test]
    fn unplaced_range_backs_off_instead_of_spinning() {
        let t0 = Instant::now();
        let mut d = Driver::default();
        let mut plan = plan(0, 100);

        let (rid, ..) = block_range(&d.drive(&mut plan, t0, false)).expect("offered");
        for _ in 0..5 {
            assert!(
                block_range(&d.drive(&mut plan, t0, false)).is_none(),
                "no re-offer before the backoff expires"
            );
        }

        let later = t0 + ISSUE_RETRY_BACKOFF + Duration::from_millis(1);
        let (again, ..) = block_range(&d.drive(&mut plan, later, true)).expect("re-offered");
        assert_eq!(again, rid, "the same range, not a new request id");
    }

    /// A failure releases the range so the next pass can place it elsewhere.
    #[test]
    fn failed_range_is_reissued() {
        let now = Instant::now();
        let mut d = Driver::default();
        let mut plan = plan(0, 100);

        let (rid, start, _) = block_range(&d.drive(&mut plan, now, true)).expect("issued");
        plan.on_terminator(rid, false, now);
        let (again, start2, _) = block_range(&d.drive(&mut plan, now, true)).expect("reissued");
        assert_ne!(again, rid, "a fresh request");
        assert_eq!(start2, start, "covering the same gap");
    }
}
