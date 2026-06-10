use super::{EpochGroup, EpochStateFinalized, delta::EpochStateDelta};
use crate::types::SLOTS_PER_EPOCH;

const FIN_SLOT: u64 = 100;
const FIN_EPOCH: u64 = FIN_SLOT / SLOTS_PER_EPOCH;

/// `EpochView::randao_mix_at_epoch` with no fork delta reads the base ring.
#[test]
fn randao_anchored_reads_base() {
    let mut base = EpochStateFinalized::default();
    let target_epoch = 4;
    let idx = target_epoch as usize % base.randao_mixes.len();
    base.randao_mixes[idx] = [0xAB; 32];

    let g = EpochGroup::new(base);
    assert_eq!(g.base_view().randao_mix_at_epoch(target_epoch, FIN_EPOCH), [0xAB; 32]);
}

/// A diverged fork delta hits the overlay for the epochs it covers, then falls
/// through to the base for the rest.
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
    // FIN_EPOCH → delta hit
    assert_eq!(view.randao_mix_at_epoch(FIN_EPOCH, FIN_EPOCH), [0xCC; 32]);
    // FIN_EPOCH+1 → falls through to base
    assert_eq!(view.randao_mix_at_epoch(FIN_EPOCH + 1, FIN_EPOCH), [0x11; 32]);
}

/// Finalization overlays the winner fork's per-completed-epoch logs into the
/// base circular buffers at `(old_fin_epoch + k) % cap` and replaces the scalar
/// `EpochState`. (Was `apply_delta_overlays_epoch_tier`.)
#[test]
fn finalize_overlays_rings_and_replaces_state() {
    let mut base = EpochStateFinalized::default();
    let hv = base.randao_mixes.len();
    let sv = base.slashings.len();
    let old = FIN_EPOCH as usize;

    // Plant baselines to confirm they get overwritten where delta entries land.
    base.randao_mixes[old % hv] = [0x01; 32];
    base.randao_mixes[(old + 1) % hv] = [0x02; 32];
    base.slashings[old % sv] = 100;
    base.slashings[(old + 1) % sv] = 200;

    let mut g = EpochGroup::new(base);
    let winner = {
        let mut wv = g.roll_fresh();
        wv.push_randao_mix([0xAA; 32]);
        wv.push_randao_mix([0xBB; 32]);
        wv.push_slashings(123);
        wv.push_slashings(456);
        // Set a recognizable scalar state on the winner.
        wv.state_mut().justification_bits = 0x0F;
        wv.state_mut().deposit_balance_to_consume = 999;
        wv.commit()
    };

    g.finalize(winner, &[], old);

    let base = g.base();
    assert_eq!(base.randao_mixes[old % hv], [0xAA; 32]);
    assert_eq!(base.randao_mixes[(old + 1) % hv], [0xBB; 32]);
    assert_eq!(base.slashings[old % sv], 123);
    assert_eq!(base.slashings[(old + 1) % sv], 456);
    assert_eq!(base.state.justification_bits, 0x0F);
    assert_eq!(base.state.deposit_balance_to_consume, 999);
}

/// A reanchored survivor drops the promoted log prefix (`prune_to_base`) so its
/// remaining logs continue past the new base.
#[test]
fn finalize_reanchors_survivor_dropping_promoted_prefix() {
    let mut g = EpochGroup::new(EpochStateFinalized::default());

    // Survivor: two completed-epoch randao mixes.
    let survivor = {
        let mut wv = g.roll_fresh();
        wv.push_randao_mix([0xA; 32]);
        wv.push_randao_mix([0xB; 32]);
        wv.commit()
    };
    // Winner promotes one completed-epoch mix (prefix len 1).
    let winner = {
        let mut wv = g.roll_fresh();
        wv.push_randao_mix([0xA; 32]);
        wv.commit()
    };

    let fresh = g.finalize(winner, &[survivor], FIN_EPOCH as usize);
    assert_eq!(fresh.len(), 1);
    // The promoted winner had 1 randao mix, so the reanchored survivor drops
    // that prefix, keeping its second entry.
    assert_eq!(g.view(fresh[0]).delta_randao_mixes(), &[[0xB; 32]]);
}

// Mirror of `EpochStateDelta`'s use in finalize: confirm `prune_to_base`
// arithmetic directly (the survivor copy path uses it via `reanchor`).
#[test]
fn prune_to_base_drops_min_prefix() {
    let mut survivor = EpochStateDelta {
        randao_mixes: vec![[1; 32], [2; 32], [3; 32]],
        slashings: vec![10, 20],
        state: Default::default(),
    };
    let promoted = EpochStateDelta {
        randao_mixes: vec![[1; 32], [2; 32]],
        slashings: vec![10],
        state: Default::default(),
    };
    survivor.prune_to_base(&promoted);
    assert_eq!(survivor.randao_mixes, vec![[3; 32]]);
    assert_eq!(survivor.slashings, vec![20]);
}
