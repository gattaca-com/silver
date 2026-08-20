use super::{SlotStateFinalized, SlotStateGroup};

const FIN_SLOT: u64 = 100;

fn anchored_base() -> SlotStateFinalized {
    let mut base = SlotStateFinalized::default();
    base.slot.slot = FIN_SLOT;
    base
}

#[test]
fn block_root_anchored_reads_base() {
    let mut base = anchored_base();
    let target_slot = 50;
    let idx = target_slot as usize % base.block_roots.len();
    base.block_roots[idx] = [0xEE; 32];

    let mut g = SlotStateGroup::new(base);
    let wv = g.roll_fresh();
    // slot < fin_slot → falls through to the finalized circular buffer.
    assert_eq!(wv.reader().block_root_at_slot(target_slot), [0xEE; 32]);
}

#[test]
fn block_root_diverged_hits_delta_then_base() {
    let mut base = anchored_base();
    let post_idx = (FIN_SLOT + 1) as usize % base.block_roots.len();
    base.block_roots[post_idx] = [0x22; 32];

    let mut g = SlotStateGroup::new(base);
    let mut wv = g.roll_fresh();
    wv.push_block_root([0xDD; 32]); // entry 0 = slot FIN_SLOT
    let view = wv.reader();
    assert_eq!(view.block_root_at_slot(FIN_SLOT), [0xDD; 32]);
    assert_eq!(view.block_root_at_slot(FIN_SLOT + 1), [0x22; 32]);
}

/// Finalization promotes the winner fork's `SlotState` into the base and writes
/// its appended block roots into the circular buffer at the slots they cover
/// (entry 0 → old finalized slot).
#[test]
fn finalize_advances_base_slot_and_writes_roots() {
    let mut g = SlotStateGroup::new(anchored_base());
    let winner = {
        let mut wv = g.roll_fresh();
        wv.state_mut().slot = 105;
        wv.push_block_root([0x55; 32]);
        wv.commit()
    };
    g.finalize(winner, &[winner]);

    let base = g.finalized_view();
    assert_eq!(base.slot_number(), 105);
    let roots = base.finalized_block_roots();
    assert_eq!(roots[FIN_SLOT as usize % roots.len()], [0x55; 32]);
}

/// A chain older than `SLOTS_PER_HISTORICAL_ROOT`, so `slot % cap` is the
/// wrapped index rather than the slot, and the base ring is what answers for
/// everything below the fork's own delta.
mod ring_reads {
    use super::*;
    use crate::types::{B256, SLOTS_PER_HISTORICAL_ROOT};

    const WRAPPED_FIN_SLOT: u64 = SLOTS_PER_HISTORICAL_ROOT as u64 + 500;
    const STATE_SLOT: u64 = WRAPPED_FIN_SLOT + 2;

    fn root_of(slot: u64) -> B256 {
        let mut root = [0xA0; 32];
        root[24..].copy_from_slice(&slot.to_be_bytes());
        root
    }

    /// Base ring holding a distinct root for every slot below
    /// `WRAPPED_FIN_SLOT`, bar `repeated_at`, which carries its predecessor's
    /// the way `process_slot` does through a slot that had no block.
    fn wrapped_group(repeated_at: Option<u64>) -> SlotStateGroup {
        let mut base = SlotStateFinalized::default();
        base.slot.slot = WRAPPED_FIN_SLOT;
        let cap = base.block_roots.len() as u64;
        for slot in WRAPPED_FIN_SLOT - cap..WRAPPED_FIN_SLOT {
            let named = if repeated_at == Some(slot) { slot - 1 } else { slot };
            base.block_roots[slot as usize % cap as usize] = root_of(named);
        }
        SlotStateGroup::new(base)
    }

    /// An entry differing from its predecessor is a block of the slot's own;
    /// a repeated one is a slot that carried none. Both sides of the base /
    /// delta join answer, and the base side reads at the wrapped index.
    #[test]
    fn a_repeated_entry_is_an_empty_slot_and_a_new_one_a_block() {
        let empty = WRAPPED_FIN_SLOT - 1;
        let mut g = wrapped_group(Some(empty));
        let mut wv = g.roll_fresh();
        wv.push_block_root(root_of(WRAPPED_FIN_SLOT));
        wv.push_block_root(root_of(WRAPPED_FIN_SLOT));
        wv.state_mut().slot = STATE_SLOT;
        let view = wv.reader();

        let cap = view.finalized_block_roots().len();
        assert!(WRAPPED_FIN_SLOT as usize > cap, "the fixture must wrap for the wrap to be tested");
        assert_eq!(
            view.block_root_at_slot(empty),
            root_of(empty - 1),
            "the base ring answers at the wrapped index",
        );

        assert_eq!(view.block_root_proposed_at(empty - 1), Some(root_of(empty - 1)));
        assert_eq!(view.block_root_proposed_at(empty), None);
        assert_eq!(view.block_root_proposed_at(WRAPPED_FIN_SLOT), Some(root_of(WRAPPED_FIN_SLOT)));
        assert_eq!(view.block_root_proposed_at(WRAPPED_FIN_SLOT + 1), None);
    }

    /// The ring covers the `SLOTS_PER_HISTORICAL_ROOT` slots below the state's
    /// own, and naming a block needs its predecessor's entry too — so the
    /// floor itself cannot be named however distinct its entry is, and the
    /// state's own slot has no entry until the `process_slot` that leaves it.
    #[test]
    fn the_ring_bounds_which_slots_can_be_named() {
        let mut g = wrapped_group(None);
        let mut wv = g.roll_fresh();
        wv.state_mut().slot = STATE_SLOT;
        let view = wv.reader();

        let floor = STATE_SLOT - view.finalized_block_roots().len() as u64;
        assert_eq!(view.block_root_proposed_at(floor + 1), Some(root_of(floor + 1)));
        assert_eq!(view.block_root_proposed_at(floor), None, "the floor has no predecessor");
        assert_eq!(view.block_root_proposed_at(floor - 1), None, "below the floor");
        assert_eq!(view.block_root_proposed_at(STATE_SLOT), None, "the state's own slot");
        assert_eq!(view.block_root_proposed_at(STATE_SLOT + 1), None, "past it");
    }

    /// Reading the entry itself asks only that the ring still cover the slot,
    /// so the floor answers where naming a block there cannot, and an empty
    /// slot answers with the root it repeats.
    #[test]
    fn a_recorded_entry_reads_back_wherever_the_ring_covers_its_slot() {
        let empty = WRAPPED_FIN_SLOT - 1;
        let mut g = wrapped_group(Some(empty));
        let mut wv = g.roll_fresh();
        wv.push_block_root(root_of(WRAPPED_FIN_SLOT));
        wv.state_mut().slot = WRAPPED_FIN_SLOT + 1;
        let view = wv.reader();

        let state_slot = view.state().slot;
        let floor = state_slot - view.finalized_block_roots().len() as u64;
        assert_eq!(view.recorded_block_root_at(empty), Some(root_of(empty - 1)));
        assert_eq!(view.recorded_block_root_at(WRAPPED_FIN_SLOT), Some(root_of(WRAPPED_FIN_SLOT)));
        assert_eq!(view.recorded_block_root_at(floor), Some(root_of(floor)));
        assert_eq!(view.recorded_block_root_at(floor - 1), None, "below the floor");
        assert_eq!(view.recorded_block_root_at(state_slot), None, "the state's own slot");
    }
}
