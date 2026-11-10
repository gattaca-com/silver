use super::{SlotStateFinalized, SlotStateGroup};
use crate::{ExecutionPayloadBid, ring::Ring};

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

fn bid(count: usize, fill: u8) -> ExecutionPayloadBid {
    ExecutionPayloadBid {
        blob_kzg_commitments: vec![[fill; 48]; count].into(),
        ..Default::default()
    }
}

#[test]
fn reused_and_grown_ring_slots_retain_replaced_commitments() {
    let mut group = SlotStateGroup::new(anchored_base());
    group.deltas = Ring::new(2);
    let first_id = {
        let mut writer = group.roll_fresh();
        writer.state_mut().latest_execution_payload_bid.clone_from(&bid(1, 7));
        writer.commit()
    };
    let first =
        group.view(first_id).state().latest_execution_payload_bid.blob_kzg_commitments.as_ptr();
    let second_id = {
        let mut writer = group.roll_from(first_id);
        writer.state_mut().latest_execution_payload_bid.clone_from(&bid(32, 8));
        writer.commit()
    };
    let second =
        group.view(second_id).state().latest_execution_payload_bid.blob_kzg_commitments.as_ptr();

    group.deltas.free_outdated(&[second_id]);
    let reused = group.roll_from(second_id).commit();
    group.deltas.free_outdated(&[reused]);
    let reset = {
        let mut writer = group.roll_fresh();
        writer.state_mut().latest_execution_payload_bid.clone_from(&bid(128, 9));
        writer.commit()
    };
    let grown = group.roll_from(reset).commit();
    assert_eq!(
        group.view(grown).state().latest_execution_payload_bid.blob_kzg_commitments.len(),
        128
    );

    // SAFETY: slot resets preserve retirement history, and ring growth keeps the
    // old generation alive.
    unsafe {
        assert_eq!(*first, [7; 48]);
        assert_eq!(*second.add(31), [8; 48]);
    }
}

#[test]
fn promotion_and_copy_retain_finalized_commitments() {
    let mut base = anchored_base();
    base.slot.latest_execution_payload_bid.clone_from(&bid(1, 7));
    let old = base.slot.latest_execution_payload_bid.blob_kzg_commitments.as_ptr();
    let mut group = SlotStateGroup::new(base);
    let winner = {
        let mut writer = group.roll_fresh();
        writer.state_mut().latest_execution_payload_bid.clone_from(&bid(32, 8));
        writer.commit()
    };
    group.finalize(winner, &[winner]);
    group.finalized.clone_from(&anchored_base());
    // SAFETY: promotion retires the old buffer, and copying preserves that
    // retirement history.
    assert_eq!(unsafe { *old }, [7; 48]);
}
