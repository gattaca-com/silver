use super::{SlotStateFinalized, SlotStateGroup};

const FIN_SLOT: u64 = 100;

/// Default base anchored at finalized `FIN_SLOT`.
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
    g.finalize(winner, &[]);

    let base = g.base_view();
    assert_eq!(base.slot_number(), 105);
    let roots = base.finalized_block_roots();
    assert_eq!(roots[FIN_SLOT as usize % roots.len()], [0x55; 32]);
}
