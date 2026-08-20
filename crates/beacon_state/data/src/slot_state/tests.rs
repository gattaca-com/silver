use super::{SlotStateFinalized, SlotStateGroup};

const FIN_SLOT: u64 = 100;

fn anchored_base() -> SlotStateFinalized {
    let mut base = SlotStateFinalized::default();
    base.slot.slot = FIN_SLOT;
    base
}

#[test]
fn finalize_adopts_the_winners_slot_state() {
    let mut g = SlotStateGroup::new(anchored_base());
    let winner = {
        let mut wv = g.roll_fresh();
        wv.state_mut().slot = 105;
        wv.commit()
    };
    g.finalize(winner, &[winner]);

    assert_eq!(g.finalized_view().slot_number(), 105);
}

/// A reanchored survivor keeps reading its own `SlotState`, not the newly
/// promoted base's.
#[test]
fn reanchored_survivor_keeps_its_own_state() {
    let mut g = SlotStateGroup::new(anchored_base());
    let winner = {
        let mut wv = g.roll_fresh();
        wv.state_mut().slot = 105;
        wv.commit()
    };
    let sibling = {
        let mut wv = g.roll_from(winner);
        wv.state_mut().slot = 106;
        wv.commit()
    };

    let fresh = g.finalize(winner, &[winner, sibling]);

    assert_eq!(g.view(fresh[0]).slot_number(), 105);
    assert_eq!(g.view(fresh[1]).slot_number(), 106);
}
