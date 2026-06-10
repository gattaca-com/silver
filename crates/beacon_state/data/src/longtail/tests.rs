use super::{LongtailGroup, LongtailState};
use crate::types::HistoricalSummary;

fn summary(b: u8) -> HistoricalSummary {
    HistoricalSummary { block_summary_root: [b; 32], state_summary_root: [b; 32] }
}

/// `LongtailView::historical_summary` with no fork reads the base log; an index
/// past the base returns `None`.
#[test]
fn historical_summary_base_then_none() {
    let mut base = LongtailState::default();
    base.historical_summaries.push(summary(1));
    base.historical_summaries.push(summary(2));

    let g = LongtailGroup::new(base);
    let view = g.base_view();
    assert_eq!(view.historical_summary(0).unwrap().block_summary_root, [1; 32]);
    assert_eq!(view.historical_summary(1).unwrap().block_summary_root, [2; 32]);
    assert!(view.historical_summary(2).is_none());
    assert_eq!(view.historical_summaries_len(), 2);
}

/// A diverged fork extends the base log: reads past the base length resolve
/// against the fork's appended tail.
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

/// Finalization rotates sync committees + indices (absolute replace) and
/// **extends** the base historical-summary log with the winner's appends.
/// (Was `apply_delta_overlays_longtail_tier`.)
#[test]
fn finalize_rotates_committees_and_extends_summaries() {
    let mut base = LongtailState::default();
    base.historical_summaries.push(summary(1));

    let mut g = LongtailGroup::new(base);
    let winner = {
        let mut wv = g.roll_fresh();
        wv.push_historical_summary(summary(2));
        // Rotate the winner's sync committees + indices.
        wv.state_mut().current_sync_committee.pubkeys[0] = [0x77; 48];
        wv.state_mut().next_sync_committee.pubkeys[0] = [0x88; 48];
        wv.state_mut().sync_committee_indices[0] = 42;
        wv.commit()
    };

    g.finalize(winner, &[]);

    let base = g.base();
    assert_eq!(base.current_sync_committee.pubkeys[0], [0x77; 48]);
    assert_eq!(base.next_sync_committee.pubkeys[0], [0x88; 48]);
    assert_eq!(base.sync_committee_indices[0], 42);
    // Base entry kept, winner's appended.
    assert_eq!(base.historical_summaries.len(), 2);
    assert_eq!(base.historical_summaries[0].block_summary_root, [1; 32]);
    assert_eq!(base.historical_summaries[1].block_summary_root, [2; 32]);
}

/// `prune_to_base` drops the promoted historical-summary prefix (the survivor
/// reanchor arithmetic; the full reanchor path is exercised by the tile's
/// `multi_fork_finalize` and the slot-shaped epoch test — the 2-slot longtail
/// ring can't hold survivor + winner + fresh simultaneously).
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
