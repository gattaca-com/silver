use super::{LongtailGroup, LongtailState};
use crate::types::HistoricalSummary;

fn summary(b: u8) -> HistoricalSummary {
    HistoricalSummary { block_summary_root: [b; 32], state_summary_root: [b; 32] }
}

#[test]
fn historical_summary_base_then_none() {
    let mut base = LongtailState::default();
    base.historical_summaries.push(summary(1));
    base.historical_summaries.push(summary(2));

    let g = LongtailGroup::new(base);
    let view = g.finalized_view();
    assert_eq!(view.historical_summary(0).unwrap().block_summary_root, [1; 32]);
    assert_eq!(view.historical_summary(1).unwrap().block_summary_root, [2; 32]);
    assert!(view.historical_summary(2).is_none());
    assert_eq!(view.historical_summaries_len(), 2);
}

#[test]
fn historical_summary_diverged_extends_past_base() {
    let mut base = LongtailState::default();
    base.historical_summaries.push(summary(1));

    let mut g = LongtailGroup::new(base);
    let id = {
        let mut wv = g.roll_fresh();
        wv.push_historical_summary(summary(3));
        wv.commit()
    };

    let view = g.view(id);
    assert_eq!(view.historical_summaries_len(), 2);
    assert_eq!(view.historical_summary(0).unwrap().block_summary_root, [1; 32]);
    assert_eq!(view.historical_summary(1).unwrap().block_summary_root, [3; 32]);
}

#[test]
fn finalize_rotates_committees_and_extends_summaries() {
    let mut base = LongtailState::default();
    base.historical_summaries.push(summary(1));

    let mut g = LongtailGroup::new(base);
    let winner = {
        let mut wv = g.roll_fresh();
        wv.push_historical_summary(summary(2));
        wv.state_mut().current_sync_committee.pubkeys[0] = [0x77; 48];
        wv.state_mut().next_sync_committee.pubkeys[0] = [0x88; 48];
        wv.state_mut().sync_committee_indices[0] = 42;
        wv.commit()
    };

    g.finalize(winner, &[winner]);

    let base = g.finalized();
    assert_eq!(base.current_sync_committee.pubkeys[0], [0x77; 48]);
    assert_eq!(base.next_sync_committee.pubkeys[0], [0x88; 48]);
    assert_eq!(base.sync_committee_indices[0], 42);
    assert_eq!(base.historical_summaries.len(), 2);
    assert_eq!(base.historical_summaries[0].block_summary_root, [1; 32]);
    assert_eq!(base.historical_summaries[1].block_summary_root, [2; 32]);
}

/// Reanchor across rotations: finalize must hold the old ids plus one fresh
/// slot per distinct survivor at once (regression: the 2-slot ring panicked
/// "would trample head" at the first finalize after the second rotation).
#[test]
fn finalize_reanchors_survivors_across_rotation() {
    let mut g = LongtailGroup::new(LongtailState::default());

    // First rotation: a parentless fresh roll, finalized as winner.
    let r1 = {
        let mut wv = g.roll_fresh();
        wv.push_historical_summary(summary(1));
        wv.commit()
    };
    let pre = g.finalize(r1, &[r1])[0];

    // Second rotation inherits; finalize on the pre-rotation winner with
    // survivors spanning both entries.
    let r2 = {
        let mut wv = g.roll_from(pre);
        wv.push_historical_summary(summary(2));
        wv.commit()
    };
    let fresh = g.finalize(pre, &[pre, r2]);

    assert_eq!(g.finalized().historical_summaries.len(), 1);
    let survivor = g.view(fresh[1]);
    assert_eq!(survivor.historical_summaries_len(), 2);
    assert_eq!(survivor.historical_summary(1).unwrap().block_summary_root, [2; 32]);
}

/// `prune_to_base` drops the promoted historical-summary prefix — the
/// survivor reanchor arithmetic in isolation (the full reanchor path is
/// covered by `finalize_reanchors_survivors_across_rotation`).
#[test]
fn prune_to_base_drops_promoted_prefix() {
    let mut survivor = LongtailState::default();
    survivor.historical_summaries.extend([summary(0xA), summary(0xB), summary(0xC)]);
    let mut promoted = LongtailState::default();
    promoted.historical_summaries.extend([summary(0xA), summary(0xB)]);

    survivor.prune_to_base(&promoted);
    assert_eq!(survivor.historical_summaries.len(), 1);
    assert_eq!(survivor.historical_summaries[0].block_summary_root, [0xC; 32]);
}
