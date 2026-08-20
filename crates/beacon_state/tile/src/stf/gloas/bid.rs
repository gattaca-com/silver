use blst::min_pk::PublicKey;
use flux_profiler::timed;
use silver_beacon_state_data::{
    BuilderPendingPayment, BuilderPendingWithdrawal, BuildersView, Epoch, EpochView,
    ExecutionPayloadBid, Immutable, SLOTS_PER_EPOCH, SpecConfig, StateWriterView,
};
use silver_common::ssz_view::SignedExecutionPayloadBidView;

use super::builders::{
    BUILDER_INDEX_SELF_BUILD, PAYLOAD_BUILDER_VERSION, can_builder_cover_bid, is_active_builder,
};
use crate::{
    bls::{self, DOMAIN_BEACON_BUILDER, G2_POINT_AT_INFINITY, SigBatch},
    error::ExecutionPayloadBidError as E,
    ssz_hash_gloas::hash_execution_payload_bid,
    stf::get_beacon_proposer_index,
    tile::get_blob_parameters,
};

/// Record the block's execution payload bid. The bid's
/// external-builder signature is batch-verified separately
/// ([`collect_sigs_execution_payload_bid`]); this applies the non-signature
/// asserts and the pending-payment bookkeeping.
pub fn process_execution_payload_bid(
    view: &mut StateWriterView,
    epoch: &EpochView,
    cfg: &SpecConfig,
    signed_bid: &[u8],
) -> Result<(), E> {
    let bid = decode_bid(signed_bid)?;
    let current_epoch = view.slot.state().slot / SLOTS_PER_EPOCH;

    if bid.builder_index == BUILDER_INDEX_SELF_BUILD {
        if bid.value != 0 {
            return Err(E::SelfBuildNonZeroValue { value: bid.value });
        }
        if *SignedExecutionPayloadBidView::signature(signed_bid) != G2_POINT_AT_INFINITY {
            return Err(E::SelfBuildSignature);
        }
    } else {
        let builders = view.builders.reader();
        let builder = builders
            .get(bid.builder_index as usize)
            .ok_or(E::BuilderOutOfRange { index: bid.builder_index, count: builders.len() })?;
        if !is_active_builder(builder, epoch.state().finalized_checkpoint.epoch) {
            return Err(E::BuilderInactive { index: bid.builder_index });
        }
        if builder.version != PAYLOAD_BUILDER_VERSION {
            return Err(E::BuilderVersion { index: bid.builder_index, version: builder.version });
        }
        if !can_builder_cover_bid(view, bid.builder_index, bid.value) {
            return Err(E::InsufficientBalance { index: bid.builder_index, value: bid.value });
        }
    }

    let max_blobs =
        get_blob_parameters(current_epoch, &cfg.blob_schedule, cfg.default_blob_params())
            .max_blobs_per_block as usize;
    if bid.blob_kzg_commitments.len() > max_blobs {
        return Err(E::TooManyBlobCommitments {
            got: bid.blob_kzg_commitments.len(),
            max: max_blobs,
        });
    }

    let slot = view.slot.state().slot;
    if bid.slot != slot {
        return Err(E::SlotMismatch { bid: bid.slot, state: slot });
    }
    if slot == 0 {
        return Err(E::GenesisSlot);
    }
    if bid.parent_block_hash != view.slot.state().latest_block_hash {
        return Err(E::ParentBlockHashMismatch);
    }
    if bid.parent_block_root != view.slot.block_root_at_slot(slot - 1) {
        return Err(E::ParentBlockRootMismatch);
    }
    if bid.prev_randao != view.slot.state().randao_mix_current {
        return Err(E::PrevRandaoMismatch);
    }

    if bid.value > 0 {
        let payment = BuilderPendingPayment {
            weight: 0,
            withdrawal: BuilderPendingWithdrawal {
                fee_recipient: bid.fee_recipient,
                amount: bid.value,
                builder_index: bid.builder_index,
            },
            proposer_index: get_beacon_proposer_index(&view.slot, *epoch) as u64,
        };
        let idx = SLOTS_PER_EPOCH as usize + (bid.slot % SLOTS_PER_EPOCH) as usize;
        view.slot.state_mut().builder_pending_payments[idx] = payment;
    }
    view.slot.state_mut().latest_execution_payload_bid = bid;
    Ok(())
}

/// Push an external builder's bid signature onto `batch`
/// (`DOMAIN_BEACON_BUILDER`). Self-builds carry the infinity signature, checked
/// in [`process_execution_payload_bid`].
#[timed]
pub fn collect_sigs_execution_payload_bid(
    imm: &Immutable,
    epoch: &EpochView,
    builders: &BuildersView,
    signed_bid: &[u8],
    current_epoch: Epoch,
    batch: &mut SigBatch,
) -> Result<(), E> {
    let bid = decode_bid(signed_bid)?;
    if bid.builder_index == BUILDER_INDEX_SELF_BUILD {
        return Ok(());
    }
    let pubkey_bytes = builders
        .get(bid.builder_index as usize)
        .map(|b| b.pubkey)
        .ok_or(E::BuilderOutOfRange { index: bid.builder_index, count: builders.len() })?;
    let Ok(pubkey) = PublicKey::from_bytes(&pubkey_bytes) else {
        return Err(E::BadBuilderPubkey { index: bid.builder_index });
    };

    let fork_version = epoch.fork_version_at(current_epoch);
    let domain =
        bls::compute_domain(DOMAIN_BEACON_BUILDER, fork_version, &imm.genesis_validators_root);
    let signing_root = bls::compute_signing_root(&hash_execution_payload_bid(&bid), &domain);
    batch.push_one(&pubkey, SignedExecutionPayloadBidView::signature(signed_bid), signing_root);
    Ok(())
}

fn decode_bid(signed_bid: &[u8]) -> Result<ExecutionPayloadBid, E> {
    if !SignedExecutionPayloadBidView::check_size(signed_bid) {
        return Err(E::Malformed { len: signed_bid.len() });
    }
    ExecutionPayloadBid::from_ssz(SignedExecutionPayloadBidView::message(signed_bid))
        .map_err(|_| E::Malformed { len: signed_bid.len() })
}
