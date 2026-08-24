use std::{
    collections::hash_map::Entry,
    time::{Duration, Instant},
};

use fxhash::FxHashMap;
use silver_common::{DataKind, Origin, RequestId, Scope, SyncRequest, hex32};

use super::{ControlCounters, SyncAction, sync_window::Slot};

const COLUMN_RETRY: Duration = Duration::from_millis(3000);
const PARENT_CHASE_BACKOFF: Duration = Duration::from_millis(500);

/// Held before chasing a freshly-declared live column need.
const COLUMN_GOSSIP_WAIT_PERIOD: Duration = Duration::from_millis(400);

const ATTEMPTS_BEFORE_REPORT: u32 = 8;

#[derive(Clone, Copy)]
struct Need {
    kind: DataKind,
    origin: Origin,
    columns: u128,
    /// Latest slot that wants this root.
    wanted_at: Slot,
    due: Instant,
    attempts: u32,
}

impl Need {
    fn backoff(&self) -> Duration {
        match self.kind {
            DataKind::Columns => COLUMN_RETRY,
            DataKind::Block | DataKind::Envelope => PARENT_CHASE_BACKOFF,
        }
    }

    fn due_in(&self) -> Duration {
        match (self.kind, self.origin) {
            (DataKind::Columns, Origin::Live) => COLUMN_GOSSIP_WAIT_PERIOD,
            _ => Duration::ZERO,
        }
    }

    fn dead_at(&self, finalized_slot: Slot) -> bool {
        self.wanted_at <= finalized_slot && self.origin == Origin::Live
    }

    fn new(kind: DataKind, origin: Origin, columns: u128, wanted_at: Slot, now: Instant) -> Self {
        let mut need = Self { kind, origin, columns, wanted_at, due: now, attempts: 0 };
        need.due = now + need.due_in();
        need
    }

    fn due_now(&self, now: Instant, claim_covers: &impl Fn(Slot) -> bool) -> bool {
        now >= self.due &&
            !(self.kind == DataKind::Columns &&
                self.origin == Origin::Live &&
                claim_covers(self.wanted_at))
    }

    fn request(&self, root: [u8; 32]) -> SyncRequest {
        SyncRequest {
            kind: self.kind,
            origin: self.origin,
            scope: Scope::Root(root),
            columns: self.columns,
        }
    }
}

pub(super) struct OldestNeed {
    pub(super) root: [u8; 32],
    pub(super) kind: DataKind,
    pub(super) wanted_at: Slot,
    pub(super) attempts: u32,
}

pub(super) struct ByRootRequests {
    needs: FxHashMap<[u8; 32], Need>,
    next_due: Option<Instant>,
    cap: usize,
}

impl ByRootRequests {
    pub(super) fn new(cap: usize) -> Self {
        Self { needs: FxHashMap::default(), next_due: None, cap }
    }

    fn insert(&mut self, root: [u8; 32], need: Need) {
        if self.needs.len() >= self.cap && !self.needs.contains_key(&root) {
            ControlCounters::RootNeedsRefused.inc();
            tracing::warn!(
                root = hex32(&root),
                kind = ?need.kind,
                wanted_at = need.wanted_at,
                cap = self.cap,
                "by-root chases are full; not chasing this root"
            );
            return;
        }
        match self.needs.entry(root) {
            Entry::Occupied(mut e) => {
                let held = e.get_mut();
                (held.kind, held.origin, held.columns) = (need.kind, need.origin, need.columns);
                held.wanted_at = held.wanted_at.max(need.wanted_at);
            }
            Entry::Vacant(e) => {
                let due = need.due;
                e.insert(need);
                self.next_due = Some(self.next_due.map_or(due, |held| held.min(due)));
            }
        }
        ControlCounters::RootNeedsTracked.set(self.needs.len() as u64);
    }

    pub(super) fn want(
        &mut self,
        root: [u8; 32],
        kind: DataKind,
        columns: u128,
        origin: Origin,
        wanted_at: Slot,
        now: Instant,
    ) {
        debug_assert!(
            kind != DataKind::Columns || columns != 0,
            "an empty column mask asks for nothing; `Arrived` is how a need clears"
        );
        self.insert(root, Need::new(kind, origin, columns, wanted_at, now));
    }

    pub(super) fn retire(&mut self, root: &[u8; 32]) {
        if let Some(need) = self.needs.remove(root) {
            tracing::info!(
                root = hex32(root),
                kind = ?need.kind,
                wanted_at = need.wanted_at,
                attempts = need.attempts,
                "by-root chase answered"
            );
        }
        ControlCounters::RootNeedsTracked.set(self.needs.len() as u64);
    }

    pub(super) fn prune_finalized(&mut self, finalized_slot: Slot) {
        self.needs.retain(|_, need| !need.dead_at(finalized_slot));
        ControlCounters::RootNeedsTracked.set(self.needs.len() as u64);
    }

    /// What the stall report reads: how many roots are outstanding, and the one
    /// wanted for the oldest slot.
    pub(super) fn outstanding(&self) -> (usize, Option<OldestNeed>) {
        let oldest =
            self.needs.iter().min_by_key(|(_, need)| need.wanted_at).map(|(root, need)| {
                OldestNeed {
                    root: *root,
                    kind: need.kind,
                    wanted_at: need.wanted_at,
                    attempts: need.attempts,
                }
            });
        (self.needs.len(), oldest)
    }

    pub(super) fn drive(
        &mut self,
        next_id: &mut u64,
        now: Instant,
        claim_covers: impl Fn(Slot) -> bool,
        emit: &mut impl FnMut(SyncAction) -> bool,
    ) {
        if self.next_due.is_none_or(|due| now < due) {
            return;
        }

        if let Some(root) = self.oldest_slot_due(now, &claim_covers) &&
            let Some(need) = self.needs.get_mut(&root)
        {
            count_chase(need.kind);
            let placed = emit(offer(need, root, next_id, now));
            report_unplaced(placed, need, &root);
        }

        let mut next_due = None;
        for (root, need) in self.needs.iter_mut() {
            if need.due_now(now, &claim_covers) {
                count_chase(need.kind);
                let placed = emit(offer(need, *root, next_id, now));
                report_unplaced(placed, need, root);
            }
            next_due = Some(next_due.map_or(need.due, |held: Instant| held.min(need.due)));
        }
        self.next_due = next_due;
    }

    fn oldest_slot_due(
        &self,
        now: Instant,
        claim_covers: &impl Fn(Slot) -> bool,
    ) -> Option<[u8; 32]> {
        self.needs
            .iter()
            .filter(|(_, need)| need.due_now(now, claim_covers))
            .min_by_key(|(_, need)| need.wanted_at)
            .map(|(root, _)| *root)
    }
}

fn count_chase(kind: DataKind) {
    if kind == DataKind::Block {
        ControlCounters::BlocksChasedByRoot.inc();
    }
}

/// A chase nobody would carry, said once: the retry cadence would otherwise
/// repeat it every backoff for as long as no peer can serve the root.
fn report_unplaced(placed: bool, need: &Need, root: &[u8; 32]) {
    if !placed && need.attempts == 1 {
        tracing::info!(
            root = hex32(root),
            kind = ?need.kind,
            wanted_at = need.wanted_at,
            "by-root chase unplaced: no peer took it"
        );
    }
}

fn offer(need: &mut Need, root: [u8; 32], next_id: &mut u64, now: Instant) -> SyncAction {
    let request_id = RequestId::next(need.kind, need.origin, next_id);
    need.due = now + need.backoff();
    need.attempts += 1;
    if need.attempts == 1 {
        tracing::info!(
            root = hex32(&root),
            kind = ?need.kind,
            origin = ?need.origin,
            wanted_at = need.wanted_at,
            "by-root chase started"
        );
    }
    if need.attempts == ATTEMPTS_BEFORE_REPORT {
        ControlCounters::RootNeedsStalled.inc();
        tracing::warn!(
            root = hex32(&root),
            kind = ?need.kind,
            attempts = need.attempts,
            "by-root need unanswered; still escalating"
        );
    }
    SyncAction::Request { request_id, request: need.request(root) }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: [u8; 32] = [1; 32];

    /// Generous enough that no test here is about the cap.
    const BY_ROOT_CAP: usize = 1024;

    fn want_block(needs: &mut ByRootRequests, root: [u8; 32], wanted_at: Slot, now: Instant) {
        needs.want(root, DataKind::Block, 0, Origin::Live, wanted_at, now);
    }

    fn want_envelope(needs: &mut ByRootRequests, root: [u8; 32], wanted_at: Slot, now: Instant) {
        needs.want(root, DataKind::Envelope, 0, Origin::Live, wanted_at, now);
    }

    fn drive(
        needs: &mut ByRootRequests,
        next_id: &mut u64,
        now: Instant,
        placed: bool,
    ) -> Vec<u64> {
        drive_under_claim(needs, next_id, now, placed, |_| false)
    }

    fn drive_under_claim(
        needs: &mut ByRootRequests,
        next_id: &mut u64,
        now: Instant,
        placed: bool,
        claim_covers: impl Fn(Slot) -> bool,
    ) -> Vec<u64> {
        let mut out = Vec::new();
        needs.drive(next_id, now, claim_covers, &mut |a| {
            if let SyncAction::Request { request_id, request } = a {
                assert!(matches!(request.scope, Scope::Root(_)), "chased by root, never by range");
                out.push(if request.kind == DataKind::Columns { request_id } else { 0 });
            }
            placed
        });
        out
    }

    fn want_columns(needs: &mut ByRootRequests, now: Instant, origin: Origin) {
        needs.want(ROOT, DataKind::Columns, 0b11, origin, 7, now - COLUMN_GOSSIP_WAIT_PERIOD);
    }

    /// Reporting tiles are meant to be capped by the pending buffer behind
    /// them, so the cap is normally slack. It is what stops a report with no
    /// buffer behind it from turning a local fault into unbounded outbound
    /// traffic — and what it sheds is the newest need, because the oldest is
    /// the one holding the tail.
    #[test]
    fn full_chase_set_sheds_the_newest_need() {
        let t0 = Instant::now();
        let (mut needs, mut next_id) = (ByRootRequests::new(2), 0);
        want_block(&mut needs, [1; 32], 10, t0);
        want_block(&mut needs, [2; 32], 11, t0);
        want_block(&mut needs, [3; 32], 12, t0);

        assert_eq!(needs.outstanding().0, 2, "the cap holds");
        assert_eq!(
            needs.outstanding().1.map(|oldest| oldest.wanted_at),
            Some(10),
            "and what it kept is the slot nearest the tail"
        );
        assert_eq!(
            drive(&mut needs, &mut next_id, t0, true).len(),
            2,
            "only what is tracked is chased"
        );

        // A root already tracked is still refreshed at the cap: it is not a
        // newcomer, and refusing it would drop a need we are already serving.
        want_block(&mut needs, [1; 32], 20, t0);
        assert_eq!(needs.outstanding().0, 2);
        assert_eq!(needs.outstanding().1.map(|oldest| oldest.wanted_at), Some(11));
    }

    /// A block arrives just before the last of its sidecars, so an immediate
    /// by-root would duplicate what the subnets are already delivering.
    #[test]
    fn live_column_need_waits_out_the_gossip_delay() {
        let t0 = Instant::now();
        let (mut needs, mut next_id) = (ByRootRequests::new(BY_ROOT_CAP), 0);
        needs.want(ROOT, DataKind::Columns, 0b11, Origin::Live, 7, t0);

        assert!(
            drive(&mut needs, &mut next_id, t0, true).is_empty(),
            "held while gossip may deliver"
        );
        assert_eq!(
            drive(&mut needs, &mut next_id, t0 + COLUMN_GOSSIP_WAIT_PERIOD, true).len(),
            1,
            "chased once the delay expires"
        );
    }

    /// Nothing else is fetching a parent nobody sent us, so there is nothing to
    /// wait for.
    #[test]
    fn parent_chase_is_not_delayed() {
        let t0 = Instant::now();
        let (mut needs, mut next_id) = (ByRootRequests::new(BY_ROOT_CAP), 0);
        want_block(&mut needs, ROOT, 9, t0);

        assert_eq!(drive(&mut needs, &mut next_id, t0, true).len(), 1, "asked straight away");
    }

    #[test]
    fn coverage_retires_a_column_need() {
        let t0 = Instant::now();
        let (mut needs, mut next_id) = (ByRootRequests::new(BY_ROOT_CAP), 0);
        want_columns(&mut needs, t0, Origin::Live);

        let ids = drive(&mut needs, &mut next_id, t0, true);
        assert_eq!(ids.len(), 1, "asked once");
        needs.retire(&ROOT);

        assert!(
            drive(&mut needs, &mut next_id, t0 + COLUMN_RETRY * 4, true).is_empty(),
            "never asked again"
        );
    }

    /// The backoff is the engine's half of the throttle: PM caps how many
    /// column requests are out at once, and this keeps a refused one from
    /// being re-offered on the very next loop.
    #[test]
    fn column_need_backs_off_after_being_offered() {
        let t0 = Instant::now();
        let (mut needs, mut next_id) = (ByRootRequests::new(BY_ROOT_CAP), 0);
        want_columns(&mut needs, t0, Origin::Live);

        assert_eq!(drive(&mut needs, &mut next_id, t0, false).len(), 1, "offered");
        assert!(drive(&mut needs, &mut next_id, t0, false).is_empty(), "gated, not spinning");

        let later = t0 + COLUMN_RETRY + Duration::from_millis(1);
        assert_eq!(drive(&mut needs, &mut next_id, later, true).len(), 1, "re-offered");
    }

    /// Under PM's cap the order decides who waits, and the lowest slot owed is
    /// the one holding the tail. Hash order would let it starve behind slots
    /// the tail has already gone past.
    #[test]
    fn the_lowest_slot_owed_is_offered_first() {
        let t0 = Instant::now();
        let (mut needs, mut next_id) = (ByRootRequests::new(BY_ROOT_CAP), 0);
        for (root, slot) in [([9u8; 32], 90), ([2u8; 32], 20), ([5u8; 32], 50)] {
            needs.want(root, DataKind::Columns, 0b1, Origin::Live, slot, t0);
        }

        let mut order = Vec::new();
        needs.drive(&mut next_id, t0 + COLUMN_GOSSIP_WAIT_PERIOD, |_| false, &mut |a| {
            if let SyncAction::Request { request, .. } = a {
                let Scope::Root(root) = request.scope else { unreachable!() };
                order.push(root[0]);
            }
            true
        });
        assert_eq!(order.first(), Some(&2), "the slot holding the tail goes first");
        order.sort_unstable();
        assert_eq!(order, vec![2, 5, 9], "and nothing else was skipped");
    }

    /// Re-declaration is level-triggered and arrives per block, so it must not
    /// reset the backoff.
    #[test]
    fn redeclaring_a_need_does_not_reset_its_backoff() {
        let t0 = Instant::now();
        let (mut needs, mut next_id) = (ByRootRequests::new(BY_ROOT_CAP), 0);
        want_block(&mut needs, ROOT, 9, t0);

        assert_eq!(drive(&mut needs, &mut next_id, t0, true).len(), 1);
        want_block(&mut needs, ROOT, 9, t0);
        assert!(drive(&mut needs, &mut next_id, t0, true).is_empty(), "backoff survived");
    }

    #[test]
    fn claim_covering_the_slot_suppresses_a_live_by_root() {
        let t0 = Instant::now();
        let (mut needs, mut next_id) = (ByRootRequests::new(BY_ROOT_CAP), 0);
        want_columns(&mut needs, t0, Origin::Live);

        assert!(
            drive_under_claim(&mut needs, &mut next_id, t0, true, |slot| slot == 7).is_empty(),
            "the range claim delivers these columns"
        );
        assert_eq!(
            drive(&mut needs, &mut next_id, t0, true).len(),
            1,
            "asked once the claim is gone"
        );
    }

    /// Backfill columns are outside any forward claim's span, so a claim must
    /// not gate them.
    #[test]
    fn claim_does_not_suppress_a_backfill_by_root() {
        let t0 = Instant::now();
        let (mut needs, mut next_id) = (ByRootRequests::new(BY_ROOT_CAP), 0);
        want_columns(&mut needs, t0, Origin::Backfill);

        let ids = drive_under_claim(&mut needs, &mut next_id, t0, true, |slot| slot == 7);
        assert_eq!(ids.len(), 1);
        assert_eq!(
            RequestId::from(ids[0]).origin,
            Origin::Backfill,
            "issued under the backfill origin"
        );
    }

    /// An unmet need escalates for as long as it could still matter: there is
    /// no conceding path, so the only exits are coverage and finalization.
    #[test]
    fn unanswered_need_escalates_indefinitely() {
        let mut now = Instant::now();
        let (mut needs, mut next_id) = (ByRootRequests::new(BY_ROOT_CAP), 0);
        want_block(&mut needs, ROOT, 9, now);

        for _ in 0..ATTEMPTS_BEFORE_REPORT * 3 {
            assert_eq!(drive(&mut needs, &mut next_id, now, true).len(), 1, "still asking");
            now += PARENT_CHASE_BACKOFF;
        }
    }

    /// `pending_blocks` keys children by parent root, so several blocks at
    /// different slots want one root. Taking the last declaration would let
    /// finalization drop the need while a later child still waits on it.
    #[test]
    fn later_wanter_outlives_an_earlier_declaration() {
        let now = Instant::now();
        let (mut needs, mut next_id) = (ByRootRequests::new(BY_ROOT_CAP), 0);
        want_block(&mut needs, ROOT, 200, now);
        want_block(&mut needs, ROOT, 100, now);

        needs.prune_finalized(150);
        assert_eq!(
            drive(&mut needs, &mut next_id, now, true).len(),
            1,
            "the slot-200 child still needs this parent"
        );
    }

    /// The leak this closes: beacon state drops a parked block at finalization
    /// and never tells the engine, so nothing else would ever clear the need.
    #[test]
    fn finalization_drops_needs_nothing_can_want_any_more() {
        let now = Instant::now();
        let (mut needs, mut next_id) = (ByRootRequests::new(BY_ROOT_CAP), 0);
        want_block(&mut needs, ROOT, 9, now);
        want_envelope(&mut needs, [2; 32], 40, now);
        needs.want([3; 32], DataKind::Columns, 0b1, Origin::Live, 12, now);

        needs.prune_finalized(32);

        assert_eq!(needs.needs.len(), 1, "only the need above the finalized slot survives");
        assert!(needs.needs.contains_key(&[2; 32]));
        assert_eq!(drive(&mut needs, &mut next_id, now, true).len(), 1);
    }

    /// Backfill runs below finalization by definition; storage clears those
    /// needs itself with `missing: 0`.
    #[test]
    fn finalization_does_not_drop_a_backfill_need() {
        let now = Instant::now();
        let (mut needs, mut next_id) = (ByRootRequests::new(BY_ROOT_CAP), 0);
        want_columns(&mut needs, now, Origin::Backfill);

        needs.prune_finalized(u64::MAX);
        assert_eq!(drive(&mut needs, &mut next_id, now, true).len(), 1, "still wanted");

        needs.retire(&ROOT);
        assert!(needs.needs.is_empty(), "storage's own `Arrived` retires it");
    }
}
