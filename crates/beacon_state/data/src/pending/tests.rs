use super::{PendingGroup, delta::QueueDelta};
use crate::types::PendingConsolidation;

fn pc(i: u64) -> PendingConsolidation {
    PendingConsolidation { source_index: i, target_index: i }
}

/// End-to-end: a survivor that drained into the winner's appended entries
/// keeps its own appends across finalization (regression: they were dropped
/// and the drained entry resurrected).
#[test]
fn finalize_preserves_survivor_queue_after_inherited_drain() {
    let mut g = PendingGroup::new(Default::default());

    let winner = {
        let mut wv = g.roll_fresh();
        wv.push_pending_consolidation(pc(1));
        wv.push_pending_consolidation(pc(2));
        wv.commit()
    };
    let survivor = {
        let mut wv = g.roll_from(winner);
        wv.drain_pending_consolidations(1); // consumes inherited `1`
        wv.push_pending_consolidation(pc(3));
        wv.commit()
    };

    let fresh = g.finalize(winner, &[winner, survivor]);

    let v = g.view(fresh[1]);
    assert_eq!(v.pending_consolidations_len(), 2);
    assert_eq!(v.pending_consolidation(0).source_index, 2);
    assert_eq!(v.pending_consolidation(1).source_index, 3);
}

// ---- QueueDelta drain/rebase arithmetic ----

fn delta(drain_offset: u32, appended: &[u32]) -> QueueDelta<u32> {
    QueueDelta { drain_offset, appended: appended.to_vec() }
}

fn effective(d: &QueueDelta<u32>, base: &[u32]) -> Vec<u32> {
    (0..d.len(base.len())).map(|i| *d.get(base, i)).collect()
}

/// Finalize a winner against one survivor: rebase pre-promotion (as
/// `PendingGroup::finalize` does), then promote into the base.
fn finalize(winner: &QueueDelta<u32>, survivor: &mut QueueDelta<u32>, base: &mut Vec<u32>) {
    survivor.rebase(winner, base.len());
    winner.promote_into(base);
}

#[test]
fn drain_accumulates_past_base() {
    let base = [10, 11];
    let mut d = delta(0, &[20, 21]);
    d.drain(base.len(), 3); // both base entries + appended[0]
    assert_eq!(d.drain_offset, 3);
    assert_eq!(effective(&d, &base), vec![21]);
    d.drain(base.len(), 1);
    assert_eq!(d.drain_offset, 4);
    assert_eq!(effective(&d, &base), Vec::<u32>::new());
}

/// Regression: a survivor that drained into the winner's appended entries
/// lost its own appends at rebase (and resurrected the drained entry).
#[test]
fn rebase_keeps_own_appends_after_draining_inherited() {
    let mut base: Vec<u32> = vec![]; // e.g. an empty consolidations queue
    let winner = delta(0, &[1, 2]);

    let mut survivor = QueueDelta::default();
    survivor.reset_from(&winner);
    survivor.drain(base.len(), 1); // consumes inherited `1`
    survivor.appended.push(3);

    finalize(&winner, &mut survivor, &mut base);
    assert_eq!(base, vec![1, 2]);
    assert_eq!(effective(&survivor, &base), vec![2, 3]);
}

/// Regression: the winner's own past-base drain (it ate into its own
/// appends) must not count against the survivor's inherited prefix.
#[test]
fn rebase_subtracts_winner_overshoot() {
    let mut base: Vec<u32> = vec![10];
    let mut winner = delta(0, &[1, 2]);
    winner.drain(base.len(), 2); // base entry + own `1`
    assert_eq!(effective(&winner, &base), vec![2]);

    let mut survivor = QueueDelta::default();
    survivor.reset_from(&winner);
    survivor.drain(base.len(), 1); // consumes inherited `2`
    survivor.appended.push(3);

    finalize(&winner, &mut survivor, &mut base);
    assert_eq!(base, vec![2]);
    assert_eq!(effective(&survivor, &base), vec![3]);
}

/// A survivor that drained past the whole inherited prefix into its own
/// appends has nothing left to drop at rebase.
#[test]
fn rebase_when_survivor_drained_past_inherited() {
    let mut base: Vec<u32> = vec![];
    let winner = delta(0, &[1]);

    let mut survivor = QueueDelta::default();
    survivor.reset_from(&winner);
    survivor.appended.push(2);
    survivor.drain(base.len(), 2); // inherited `1` + own `2`
    survivor.appended.push(3);

    finalize(&winner, &mut survivor, &mut base);
    assert_eq!(base, vec![1]);
    assert_eq!(effective(&survivor, &base), vec![3]);
}

/// The common shape: drains stay within the base; the survivor drops the
/// full inherited prefix and keeps a relative drain.
#[test]
fn rebase_plain_base_drains() {
    let mut base: Vec<u32> = vec![10, 11, 12];
    let mut winner = delta(0, &[1]);
    winner.drain(base.len(), 1);

    let mut survivor = QueueDelta::default();
    survivor.reset_from(&winner);
    survivor.drain(base.len(), 1);
    survivor.appended.push(2);
    assert_eq!(effective(&survivor, &base), vec![12, 1, 2]);

    finalize(&winner, &mut survivor, &mut base);
    assert_eq!(base, vec![11, 12, 1]);
    assert_eq!(effective(&survivor, &base), vec![12, 1, 2]);
}
