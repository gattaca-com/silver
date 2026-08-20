use super::{EpochGroup, EpochStateFinalized};
use crate::{
    PtcWindow,
    gloas::{PTC_SIZE, PTC_WINDOW_LEN, PtcCommittee, zeroed_ptc_window},
    merkle::{B256, MerkleStack, hash_uint64_vector, hash_vector},
    types::SLOTS_PER_EPOCH,
};

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
    let mut base_win = zeroed_ptc_window();
    base_win[1][2] = 0xBEEF;
    base.ptc_window = PtcWindow::new(base_win);

    let mut g = EpochGroup::new(base);
    let winner = {
        let mut wv = g.roll_fresh();
        // Fresh fork inherits the base window.
        assert_eq!(wv.reader().ptc_window().committees()[1][2], 0xBEEF);
        // Override the whole window on the fork.
        let mut win = zeroed_ptc_window();
        win[3][4] = 0xCAFE;
        wv.set_ptc_window(win);
        wv.commit()
    };

    // The committed fork's view shadows the base with its delta window.
    let view = g.view(winner);
    assert_eq!(view.ptc_window().committees()[3][4], 0xCAFE);
    assert_eq!(view.ptc_window().committees()[1][2], 0);
    // A view with no delta still reads the base.
    assert_eq!(g.finalized_view().ptc_window().committees()[1][2], 0xBEEF);

    // Finalization folds the winner's window into the base.
    g.finalize(winner, &[winner]);
    assert_eq!(g.finalized().ptc_window.committees()[3][4], 0xCAFE);
    assert_eq!(g.finalized().ptc_window.committees()[1][2], 0);
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
    assert_eq!(g.view(child).ptc_window().committees()[0][0], 5);
}

/// Re-merkleize the window from its committees — what `hash_root` replaces.
fn oracle_root(w: &PtcWindow) -> B256 {
    hash_vector(
        MerkleStack::new(PTC_WINDOW_LEN),
        w.committees().iter().map(|c| hash_uint64_vector(c)),
    )
}

/// The cached committee roots track the zeroed window, a whole-window
/// override, and each epoch rotation.
#[test]
fn ptc_window_hash_root_matches_oracle() {
    let mut g = EpochGroup::new(EpochStateFinalized::default());
    assert_eq!(g.finalized_view().ptc_window().hash_root(), oracle_root(&PtcWindow::default()));

    let mut wv = g.roll_fresh();
    let mut win = zeroed_ptc_window();
    for (i, c) in win.iter_mut().enumerate() {
        c[i] = i as u64 + 1;
    }
    wv.set_ptc_window(win);
    assert_eq!(wv.reader().ptc_window().hash_root(), oracle_root(wv.reader().ptc_window()));

    for round in 0..4u64 {
        let new_epoch: Vec<PtcCommittee> = (0..SLOTS_PER_EPOCH)
            .map(|s| {
                let mut c = [0u64; PTC_SIZE];
                c[s as usize] = round * 100 + s + 1;
                c
            })
            .collect();
        wv.rotate_ptc_window(&new_epoch);
        assert_eq!(wv.reader().ptc_window().hash_root(), oracle_root(wv.reader().ptc_window()));
    }

    // Promoting the winner carries the cache into the base.
    let winner = wv.commit();
    let before = g.view(winner).ptc_window().hash_root();
    g.finalize(winner, &[winner]);
    assert_eq!(g.finalized_view().ptc_window().hash_root(), before);
    assert_eq!(g.finalized_view().ptc_window().hash_root(), oracle_root(&g.finalized().ptc_window));
}
