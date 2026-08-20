use super::{EpochGroup, EpochStateFinalized};
use crate::gloas::zeroed_ptc_window;

#[test]
fn finalize_replaces_state() {
    let mut g = EpochGroup::new(EpochStateFinalized::default());
    let winner = {
        let mut wv = g.roll_fresh();
        wv.state_mut().justification_bits = 0x0F;
        wv.state_mut().deposit_balance_to_consume = 999;
        wv.commit()
    };

    g.finalize(winner, &[winner]);

    let base = g.finalized();
    assert_eq!(base.state.justification_bits, 0x0F);
    assert_eq!(base.state.deposit_balance_to_consume, 999);
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
    g.finalize(winner, &[winner]);
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
