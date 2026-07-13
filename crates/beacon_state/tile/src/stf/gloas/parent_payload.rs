use silver_beacon_state_data::{
    BuilderPendingWithdrawal, EpochView, SLOTS_PER_EPOCH, SLOTS_PER_HISTORICAL_ROOT, SpecConfig,
    StateWriterView,
};
use silver_common::ssz_view::{
    BeaconBlockBodyGloasView, ExecutionPayloadBidView, SignedExecutionPayloadBidView,
};

use super::builders::{
    BUILDER_DEPOSIT_SSZ, BUILDER_EXIT_SSZ, process_builder_deposit_request,
    process_builder_exit_request, settle_builder_payment,
};
use crate::{
    error::ParentExecutionPayloadError as E,
    ssz_hash::hash_execution_requests_gloas,
    stf::{process_consolidation_requests, process_deposit_requests, process_withdrawal_requests},
};

const SPE: usize = SLOTS_PER_EPOCH as usize;

/// Validate and apply the parent block's execution payload. The
/// child's bid declares the parent FULL (matching `parent_block_hash`) or
/// EMPTY; FULL applies the parent's deferred execution requests and settles its
/// builder payment, EMPTY must carry no requests.
pub fn process_parent_execution_payload(
    view: &mut StateWriterView,
    epoch: &EpochView,
    cfg: &SpecConfig,
    body: &[u8],
) -> Result<(), E> {
    let (signed_bid, requests) = body_sections(body)?;
    let bid_parent_block_hash: [u8; 32] = *ExecutionPayloadBidView::parent_block_hash(
        SignedExecutionPayloadBidView::message(signed_bid),
    );
    let parent_bid_block_hash = view.slot.state().latest_execution_payload_bid.block_hash;

    if bid_parent_block_hash != parent_bid_block_hash {
        // Parent was EMPTY: no execution requests may be carried.
        if hash_execution_requests_gloas(requests) != hash_execution_requests_gloas(&[]) {
            return Err(E::EmptyParentHasRequests);
        }
        return Ok(());
    }

    // Parent was FULL: the carried requests must match the parent bid's commitment.
    let expected = view.slot.state().latest_execution_payload_bid.execution_requests_root;
    let got = hash_execution_requests_gloas(requests);
    if got != expected {
        return Err(E::RequestsRootMismatch { expected, got });
    }
    apply_parent_execution_payload(view, epoch, cfg, requests);
    Ok(())
}

fn apply_parent_execution_payload(
    view: &mut StateWriterView,
    epoch: &EpochView,
    cfg: &SpecConfig,
    requests: &[u8],
) {
    let (parent_slot, parent_value, parent_fee_recipient, parent_builder_index, parent_block_hash) = {
        let pb = &view.slot.state().latest_execution_payload_bid;
        (pb.slot, pb.value, pb.fee_recipient, pb.builder_index, pb.block_hash)
    };
    let current_epoch = view.slot.state().slot / SLOTS_PER_EPOCH;
    let parent_epoch = parent_slot / SLOTS_PER_EPOCH;
    let finalized_epoch = epoch.state().finalized_checkpoint.epoch;

    // The parent's deferred execution requests apply at this (child) slot.
    let [deposits, withdrawals, consolidations, builder_deposits, builder_exits] =
        request_sections(requests);
    process_deposit_requests(view, deposits);
    process_withdrawal_requests(view, cfg, withdrawals);
    process_consolidation_requests(view, cfg, consolidations);
    for i in 0..builder_deposits.len() / BUILDER_DEPOSIT_SSZ {
        process_builder_deposit_request(
            view,
            &builder_deposits[i * BUILDER_DEPOSIT_SSZ..][..BUILDER_DEPOSIT_SSZ],
        );
    }
    for i in 0..builder_exits.len() / BUILDER_EXIT_SSZ {
        process_builder_exit_request(
            view,
            finalized_epoch,
            &builder_exits[i * BUILDER_EXIT_SSZ..][..BUILDER_EXIT_SSZ],
        );
    }

    // Settle the parent's builder payment from the two-epoch window, or directly
    // if its window entry has already aged out.
    if parent_epoch == current_epoch {
        settle_builder_payment(view, SPE + (parent_slot % SLOTS_PER_EPOCH) as usize);
    } else if current_epoch > 0 && parent_epoch == current_epoch - 1 {
        settle_builder_payment(view, (parent_slot % SLOTS_PER_EPOCH) as usize);
    } else if parent_value > 0 {
        view.pending.builder_withdrawals.push(BuilderPendingWithdrawal {
            fee_recipient: parent_fee_recipient,
            amount: parent_value,
            builder_index: parent_builder_index,
        });
    }

    let bit = (parent_slot % SLOTS_PER_HISTORICAL_ROOT as u64) as usize;
    let slot = view.slot.state_mut();
    slot.execution_payload_availability[bit / 8] |= 1u8 << (bit % 8);
    slot.latest_block_hash = parent_block_hash;
}

/// Bound the `signed_execution_payload_bid` and `parent_execution_requests`
/// fields within a Gloas block body (the bid ends where `payload_attestations`
/// starts; the requests run to the body end).
fn body_sections(body: &[u8]) -> Result<(&[u8], &[u8]), E> {
    let bid_off = BeaconBlockBodyGloasView::signed_execution_payload_bid_offset(body) as usize;
    let pa_off = BeaconBlockBodyGloasView::payload_attestations_offset(body) as usize;
    let req_off = BeaconBlockBodyGloasView::parent_execution_requests_offset(body) as usize;
    if bid_off > pa_off || pa_off > body.len() || req_off > body.len() {
        return Err(E::Malformed);
    }
    let signed_bid = &body[bid_off..pa_off];
    if signed_bid.len() < 132 {
        return Err(E::Malformed);
    }
    Ok((signed_bid, &body[req_off..]))
}

/// Split a serialized `ExecutionRequests` container into its five list bodies.
fn request_sections(data: &[u8]) -> [&[u8]; 5] {
    let mut out: [&[u8]; 5] = [&[]; 5];
    if data.len() < 20 {
        return out;
    }
    let off = |pos: usize| u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
    let bounds = [off(0), off(4), off(8), off(12), off(16)];
    for i in 0..5 {
        let start = bounds[i];
        let end = if i + 1 < 5 { bounds[i + 1] } else { data.len() };
        if start <= end && end <= data.len() {
            out[i] = &data[start..end];
        }
    }
    out
}
