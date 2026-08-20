use super::{LongtailGroup, LongtailState, finalized::hash_summaries};
use crate::{
    merkle::B256,
    types::{HistoricalSummary, SYNC_COMMITTEE_SIZE, SyncCommittee},
};

fn summary(b: u8) -> HistoricalSummary {
    HistoricalSummary { block_summary_root: [b; 32], state_summary_root: [b; 32] }
}

/// A base whose stored summaries root matches its list — what decompose
/// produces and what every fork seeds from.
fn base_with(summaries: &[HistoricalSummary]) -> LongtailState {
    let mut base = LongtailState::default();
    base.historical_summaries.extend_from_slice(summaries);
    base.historical_summaries_root = hash_summaries(&base.historical_summaries);
    base
}

fn committee(pubkey0: u8) -> SyncCommittee {
    let mut c = SyncCommittee::default();
    c.pubkeys[0] = [pubkey0; 48];
    c
}

fn seed_committees(lt: &mut LongtailState, current: &SyncCommittee, next: &SyncCommittee) {
    lt.committees.fill_rehashing(|c, n| {
        *c = *current;
        *n = *next;
    });
}

#[test]
fn historical_summary_base_then_none() {
    let g = LongtailGroup::new(base_with(&[summary(1), summary(2)]));
    let view = g.finalized_view();
    assert_eq!(view.historical_summary(0).unwrap().block_summary_root, [1; 32]);
    assert_eq!(view.historical_summary(1).unwrap().block_summary_root, [2; 32]);
    assert!(view.historical_summary(2).is_none());
    assert_eq!(view.historical_summaries_len(), 2);
}

#[test]
fn historical_summary_diverged_extends_past_base() {
    let mut g = LongtailGroup::new(base_with(&[summary(1)]));
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
    let mut base = base_with(&[summary(1)]);
    seed_committees(&mut base, &committee(0x77), &committee(0x88));

    let mut g = LongtailGroup::new(base);
    let winner = {
        let mut wv = g.roll_fresh();
        wv.push_historical_summary(summary(2));
        let mut indices = [0u32; SYNC_COMMITTEE_SIZE];
        indices[0] = 42;
        wv.rotate_sync_committees(&committee(0x99), indices);
        wv.commit()
    };

    g.finalize(winner, &[winner]);

    let base = g.finalized();
    let committees = base.sync_committees();
    assert_eq!(committees.current().pubkeys[0], [0x88; 48]);
    assert_eq!(committees.next().pubkeys[0], [0x99; 48]);
    assert_eq!(committees.indices()[0], 42);
    assert_eq!(base.historical_summaries.len(), 2);
    assert_eq!(base.historical_summaries[0].block_summary_root, [1; 32]);
    assert_eq!(base.historical_summaries[1].block_summary_root, [2; 32]);
}

/// The rotation promotes `next`'s cached root with the committee itself, and
/// both roots keep matching a from-scratch hash.
#[test]
fn sync_committee_roots_track_rotation() {
    let (c77, c88, c99) = (committee(0x77), committee(0x88), committee(0x99));
    let mut base = LongtailState::default();
    seed_committees(&mut base, &c77, &c88);

    let mut g = LongtailGroup::new(base);
    let mut wv = g.roll_fresh();
    assert_eq!(wv.reader().sync_committees().current_root(), c77.hash_root());
    assert_eq!(wv.reader().sync_committees().next_root(), c88.hash_root());

    wv.rotate_sync_committees(&c99, [0; SYNC_COMMITTEE_SIZE]);
    assert_eq!(wv.reader().sync_committees().current_root(), c88.hash_root());
    assert_eq!(wv.reader().sync_committees().next_root(), c99.hash_root());

    let winner = wv.commit();
    g.finalize(winner, &[winner]);
    assert_eq!(g.finalized().sync_committees().current_root(), c88.hash_root());
    assert_eq!(g.finalized().sync_committees().next_root(), c99.hash_root());
}

/// The stored summaries root tracks the *merged* list across appends,
/// finalization (base swap) and a survivor's reanchor.
#[test]
fn historical_summaries_root_tracks_merged_list() {
    fn oracle(view: &super::LongtailView) -> B256 {
        let n = view.historical_summaries_len();
        let all: Vec<_> = (0..n).map(|i| view.historical_summary(i).unwrap()).collect();
        hash_summaries(&all)
    }

    let mut g = LongtailGroup::new(base_with(&[summary(1)]));
    assert_eq!(g.finalized_view().historical_summaries_root(), oracle(&g.finalized_view()));

    let winner = {
        let mut wv = g.roll_fresh();
        wv.push_historical_summary(summary(2));
        assert_eq!(wv.reader().historical_summaries_root(), oracle(&wv.reader()));
        wv.commit()
    };
    let survivor = {
        let mut wv = g.roll_from(winner);
        wv.push_historical_summary(summary(3));
        assert_eq!(wv.reader().historical_summaries_root(), oracle(&wv.reader()));
        wv.commit()
    };
    let before = g.view(survivor).historical_summaries_root();

    let fresh = g.finalize(winner, &[winner, survivor]);

    assert_eq!(g.finalized_view().historical_summaries_root(), oracle(&g.finalized_view()));
    assert_eq!(g.view(fresh[1]).historical_summaries_root(), before);
    assert_eq!(g.view(fresh[1]).historical_summaries_root(), oracle(&g.view(fresh[1])));
}

/// Reanchor across rotations: finalize must hold the old ids plus one fresh
/// slot per distinct survivor at once (regression: the 2-slot ring panicked
/// "would trample head" at the first finalize after the second rotation).
#[test]
fn finalize_reanchors_survivors_across_rotation() {
    let mut g = LongtailGroup::new(base_with(&[]));

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
    let mut survivor = base_with(&[summary(0xA), summary(0xB), summary(0xC)]);
    let promoted = base_with(&[summary(0xA), summary(0xB)]);

    survivor.prune_to_base(&promoted);
    assert_eq!(survivor.historical_summaries.len(), 1);
    assert_eq!(survivor.historical_summaries[0].block_summary_root, [0xC; 32]);
}
