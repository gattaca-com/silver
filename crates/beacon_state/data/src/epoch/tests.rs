use super::{EpochGroup, EpochStateFinalized, delta::EpochStateDelta};
use crate::{
    gloas::zeroed_ptc_window,
    types::{Checkpoint, SLOTS_PER_EPOCH},
};

const FIN_SLOT: u64 = 100;
const FIN_EPOCH: u64 = FIN_SLOT / SLOTS_PER_EPOCH;

#[test]
fn randao_anchored_reads_base() {
    let mut base = EpochStateFinalized::default();
    let target_epoch = 4;
    let idx = target_epoch as usize % base.randao_mixes.len();
    base.randao_mixes[idx] = [0xAB; 32];

    let g = EpochGroup::new(base);
    assert_eq!(g.finalized_view().randao_mix_at_epoch(target_epoch, FIN_EPOCH), [0xAB; 32]);
}

#[test]
fn randao_diverged_hits_delta_then_base() {
    let mut base = EpochStateFinalized::default();
    // Base value for FIN_EPOCH+1; would normally have wrapped via finalization.
    let post_idx = (FIN_EPOCH + 1) as usize % base.randao_mixes.len();
    base.randao_mixes[post_idx] = [0x11; 32];

    let mut g = EpochGroup::new(base);
    let id = {
        // The fresh fork seeds scalars from the base; one log entry for FIN_EPOCH.
        let mut wv = g.roll_fresh();
        wv.push_randao_mix([0xCC; 32]);
        wv.commit()
    };

    let view = g.view(id);
    assert_eq!(view.randao_mix_at_epoch(FIN_EPOCH, FIN_EPOCH), [0xCC; 32]);
    assert_eq!(view.randao_mix_at_epoch(FIN_EPOCH + 1, FIN_EPOCH), [0x11; 32]);
}

#[test]
fn finalize_overlays_randao_ring_and_replaces_state() {
    let mut base = EpochStateFinalized::default();
    let hv = base.randao_mixes.len();
    let old = FIN_EPOCH as usize;

    // Plant baselines to confirm they get overwritten where delta entries land.
    base.randao_mixes[old % hv] = [0x01; 32];
    base.randao_mixes[(old + 1) % hv] = [0x02; 32];

    let mut g = EpochGroup::new(base);
    let winner = {
        let mut wv = g.roll_fresh();
        wv.push_randao_mix([0xAA; 32]);
        wv.push_randao_mix([0xBB; 32]);
        // Set a recognizable scalar state on the winner.
        wv.state_mut().justification_bits = 0x0F;
        wv.state_mut().deposit_balance_to_consume = 999;
        wv.commit()
    };

    g.finalize(winner, &[winner], old);

    let base = g.finalized();
    assert_eq!(base.randao_mixes[old % hv], [0xAA; 32]);
    assert_eq!(base.randao_mixes[(old + 1) % hv], [0xBB; 32]);
    assert_eq!(base.state.justification_bits, 0x0F);
    assert_eq!(base.state.deposit_balance_to_consume, 999);
}

/// A reanchored survivor drops the promoted log prefix (`prune_to_base`) so its
/// remaining logs continue past the new base.
#[test]
fn finalize_reanchors_survivor_dropping_promoted_prefix() {
    let mut g = EpochGroup::new(EpochStateFinalized::default());

    // Winner promotes one completed-epoch mix (prefix len 1).
    let winner = {
        let mut wv = g.roll_fresh();
        wv.push_randao_mix([0xA; 32]);
        wv.commit()
    };
    // Survivor: two completed-epoch randao mixes, rolled after the winner —
    // survivors are the winner's descendants.
    let survivor = {
        let mut wv = g.roll_fresh();
        wv.push_randao_mix([0xA; 32]);
        wv.push_randao_mix([0xB; 32]);
        wv.commit()
    };

    let fresh = g.finalize(winner, &[winner, survivor], FIN_EPOCH as usize);
    assert_eq!(fresh.len(), 2);
    // The promoted winner had 1 randao mix, so the reanchored survivor drops
    // that prefix, keeping its second entry.
    assert_eq!(g.view(fresh[1]).delta_randao_mixes(), &[[0xB; 32]]);
}

// Mirror of `EpochStateDelta`'s use in finalize: confirm `prune_to_base`
// arithmetic directly (the survivor copy path uses it via `reanchor`).
#[test]
fn prune_to_base_drops_min_prefix() {
    let mut survivor =
        EpochStateDelta { randao_mixes: vec![[1; 32], [2; 32], [3; 32]], ..Default::default() };
    let promoted = EpochStateDelta { randao_mixes: vec![[1; 32], [2; 32]], ..Default::default() };
    survivor.prune_to_base(&promoted);
    assert_eq!(survivor.randao_mixes, vec![[3; 32]]);
}

/// `ptc_window` rides the epoch tier as a sibling of `EpochState`: a fresh fork
/// seeds it from the base, the write view overrides it, the delta view shadows
/// the base, and `finalize` folds the winner's into the base.
#[test]
fn ptc_window_seeds_overrides_and_folds() {
    let mut base = EpochStateFinalized::default();
    base.ptc_window[1][2] = 0xBEEF;

    let mut g = EpochGroup::new(base);
    let winner = {
        let mut wv = g.roll_fresh();
        // Fresh fork inherits the base window (seed_from_base).
        assert_eq!(wv.reader().ptc_window()[1][2], 0xBEEF);
        // Override the whole window on the fork.
        let mut win = zeroed_ptc_window();
        win[3][4] = 0xCAFE;
        wv.set_ptc_window(win);
        wv.commit()
    };

    // The committed fork's view shadows the base with its delta window.
    let view = g.view(winner);
    assert_eq!(view.ptc_window()[3][4], 0xCAFE);
    assert_eq!(view.ptc_window()[1][2], 0);
    // A view with no delta still reads the base.
    assert_eq!(g.finalized_view().ptc_window()[1][2], 0xBEEF);

    // Finalization folds the winner's window into the base.
    g.finalize(winner, &[winner], FIN_EPOCH as usize);
    assert_eq!(g.finalized().ptc_window[3][4], 0xCAFE);
    assert_eq!(g.finalized().ptc_window[1][2], 0);
}

/// `roll_from` clones the parent delta (`reset_from`), carrying its
/// `ptc_window`.
#[test]
fn ptc_window_carried_by_roll_from() {
    let mut g = EpochGroup::new(EpochStateFinalized::default());
    let parent = {
        let mut wv = g.roll_fresh();
        let mut win = zeroed_ptc_window();
        win[0][0] = 5;
        wv.set_ptc_window(win);
        wv.commit()
    };
    let child = g.roll_from(parent).commit();
    assert_eq!(g.view(child).ptc_window()[0][0], 5);
}

/// Finalization covers every slot up to the checkpoint epoch's first: the
/// checkpoint names the newest block at or before it, so a block anywhere
/// below is that one or an ancestor. The epoch is state-derived, so its
/// boundary is computed without overflowing.
#[test]
fn finalization_covers_the_slots_up_to_the_checkpoint_epoch_s_first() {
    const BOUNDARY: u64 = FIN_EPOCH * SLOTS_PER_EPOCH;

    let mut base = EpochStateFinalized::default();
    base.state.finalized_checkpoint = Checkpoint { epoch: FIN_EPOCH, root: [0x77; 32] };
    let g = EpochGroup::new(base);
    let view = g.finalized_view();

    assert!(view.finalizes_slot(0));
    assert!(view.finalizes_slot(BOUNDARY));
    assert!(!view.finalizes_slot(BOUNDARY + 1));
    assert_eq!(view.finalized_block_root(), Some([0x77; 32]));

    let mut unfinalized = EpochStateFinalized::default();
    unfinalized.state.finalized_checkpoint.epoch = u64::MAX;
    let g = EpochGroup::new(unfinalized);
    assert!(g.finalized_view().finalizes_slot(u64::MAX), "no epoch may overflow the boundary");
    assert_eq!(g.finalized_view().finalized_block_root(), None, "the pre-finalization zero");
}
