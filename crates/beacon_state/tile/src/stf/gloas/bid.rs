use blst::min_pk::PublicKey;
use flux_profiler::timed;
use silver_beacon_state_data::{
    B256, BuilderPendingPayment, BuilderPendingWithdrawal, BuildersView, Epoch, EpochView,
    ExecutionPayloadBid, Immutable, SLOTS_PER_EPOCH, Slot, SpecConfig, StateWriterView,
};
use silver_common::ssz_view::{ExecutionPayloadBidView, SignedExecutionPayloadBidView};

use super::builders::{
    BUILDER_INDEX_SELF_BUILD, BuilderLedger, PAYLOAD_BUILDER_VERSION, is_active_builder,
};
use crate::{
    bls::{self, DOMAIN_BEACON_BUILDER, G2_POINT_AT_INFINITY, SigBatch},
    error::ExecutionPayloadBidError as E,
    ssz_hash_gloas::hash_execution_payload_bid,
    stf::get_beacon_proposer_index,
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
) -> Result<Slot, E> {
    let bid = decode_bid(signed_bid)?;
    let signature = SignedExecutionPayloadBidView::signature(signed_bid);
    validate_execution_payload_bid(view, epoch, cfg, &bid, signature)?;

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
    let parent_slot = view.slot.state().latest_execution_payload_bid.slot;
    view.slot.state_mut().latest_execution_payload_bid = bid;
    Ok(parent_slot)
}

fn validate_execution_payload_bid(
    view: &mut StateWriterView,
    epoch: &EpochView,
    cfg: &SpecConfig,
    bid: &ExecutionPayloadBid,
    signature: &[u8; 96],
) -> Result<(), E> {
    let current_epoch = view.slot.state().slot / SLOTS_PER_EPOCH;

    if bid.builder_index == BUILDER_INDEX_SELF_BUILD {
        if bid.value != 0 {
            return Err(E::SelfBuildNonZeroValue { value: bid.value });
        }
        if *signature != G2_POINT_AT_INFINITY {
            return Err(E::SelfBuildSignature);
        }
    } else {
        let finalized_epoch = epoch.state().finalized_checkpoint.epoch;
        validate_bid_builder(&BuilderLedger::of_writer(view), finalized_epoch, bid)?;
    }

    let max_blobs = cfg.blob_params_at(current_epoch).max_blobs_per_block as usize;
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
    if bid.parent_block_root != view.block_roots.at_slot(slot - 1) {
        return Err(E::ParentBlockRootMismatch);
    }
    if bid.prev_randao != view.randao_mixes.at_epoch(slot / SLOTS_PER_EPOCH) {
        return Err(E::PrevRandaoMismatch);
    }

    Ok(())
}

/// Index, version, activity and collateral of an external builder's bid.
pub fn validate_bid_builder(
    ledger: &BuilderLedger,
    finalized_epoch: Epoch,
    bid: &ExecutionPayloadBid,
) -> Result<(), E> {
    let builders = ledger.builders();
    let builder = builders
        .get(bid.builder_index as usize)
        .ok_or(E::BuilderOutOfRange { index: bid.builder_index, count: builders.len() })?;
    if !is_active_builder(builder, finalized_epoch) {
        return Err(E::BuilderInactive { index: bid.builder_index });
    }
    if builder.version != PAYLOAD_BUILDER_VERSION {
        return Err(E::BuilderVersion { index: bid.builder_index, version: builder.version });
    }
    if !ledger.can_cover_bid(bid.builder_index, bid.value) {
        return Err(E::InsufficientBalance { index: bid.builder_index, value: bid.value });
    }
    Ok(())
}

/// Builder key and signing root of an external builder's bid
/// (`DOMAIN_BEACON_BUILDER` at `fork_epoch`); `None` for a self-build, whose
/// infinity signature [`validate_execution_payload_bid`] checks.
fn bid_signing_input(
    imm: &Immutable,
    epoch: &EpochView,
    builders: &BuildersView,
    bid: &ExecutionPayloadBid,
    fork_epoch: Epoch,
) -> Result<Option<(PublicKey, B256)>, E> {
    if bid.builder_index == BUILDER_INDEX_SELF_BUILD {
        return Ok(None);
    }
    let pubkey_bytes = builders
        .get(bid.builder_index as usize)
        .map(|b| b.pubkey)
        .ok_or(E::BuilderOutOfRange { index: bid.builder_index, count: builders.len() })?;
    let Ok(pubkey) = PublicKey::from_bytes(&pubkey_bytes) else {
        return Err(E::BadBuilderPubkey { index: bid.builder_index });
    };

    let fork_version = epoch.fork_version_at(fork_epoch);
    let domain =
        bls::compute_domain(DOMAIN_BEACON_BUILDER, fork_version, &imm.genesis_validators_root);
    let signing_root = bls::compute_signing_root(&hash_execution_payload_bid(bid), &domain);
    Ok(Some((pubkey, signing_root)))
}

/// Push an external builder's bid signature onto `batch`.
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
    if let Some((pubkey, signing_root)) =
        bid_signing_input(imm, epoch, builders, &bid, current_epoch)?
    {
        batch.push_one(&pubkey, SignedExecutionPayloadBidView::signature(signed_bid), signing_root);
    }
    Ok(())
}

/// Verifies under the fork of the bid's own epoch, as the spec does against
/// the parent state advanced to `bid.slot`. Self-builds are not gossiped, so
/// one here is an error.
#[timed]
pub fn verify_execution_payload_bid_signature(
    imm: &Immutable,
    epoch: &EpochView,
    builders: &BuildersView,
    bid: &ExecutionPayloadBid,
    signature: &[u8; 96],
) -> Result<(), E> {
    let bid_epoch = bid.slot / SLOTS_PER_EPOCH;
    let Some((pubkey, signing_root)) = bid_signing_input(imm, epoch, builders, bid, bid_epoch)?
    else {
        return Err(E::SelfBuildUnsigned);
    };
    if !bls::verify_one(&pubkey, signature, &signing_root) {
        return Err(E::BadSignature { index: bid.builder_index });
    }
    Ok(())
}

pub fn decode_bid(signed_bid: &[u8]) -> Result<ExecutionPayloadBid, E> {
    if !SignedExecutionPayloadBidView::check_size(signed_bid) {
        return Err(E::Malformed { len: signed_bid.len() });
    }
    let message = SignedExecutionPayloadBidView::message(signed_bid);
    if !ExecutionPayloadBidView::check_size(message) {
        return Err(E::Malformed { len: signed_bid.len() });
    }
    ExecutionPayloadBid::from_ssz(message).map_err(|_| E::Malformed { len: signed_bid.len() })
}

/// Spec `is_gas_limit_target_compatible`: the EIP-1559 step from `parent`
/// towards `target`, clamped to the reachable range.
pub fn is_gas_limit_target_compatible(parent: u64, gas_limit: u64, target: u64) -> bool {
    let max_step = (parent / 1024).saturating_sub(1);
    gas_limit == target.clamp(parent - max_step, parent.saturating_add(max_step))
}

#[cfg(test)]
mod tests {
    use silver_common::ssz_view::SIGNED_EXECUTION_PAYLOAD_BID_MIN;

    use super::*;

    #[test]
    fn gas_limit_moves_one_step_towards_target() {
        let parent = 60_000_000;
        let step = parent / 1024 - 1;
        assert!(is_gas_limit_target_compatible(parent, parent, parent));
        assert!(is_gas_limit_target_compatible(parent, parent + 100, parent + 100));
        assert!(!is_gas_limit_target_compatible(parent, parent, parent + 100), "target reachable");
        assert!(is_gas_limit_target_compatible(parent, parent + step, u64::MAX));
        assert!(!is_gas_limit_target_compatible(parent, parent + step + 1, u64::MAX));
        assert!(is_gas_limit_target_compatible(parent, parent - step, 0));
        assert!(!is_gas_limit_target_compatible(parent, parent - step - 1, 0));
    }

    #[test]
    fn gas_limit_under_one_step_cannot_move() {
        assert!(is_gas_limit_target_compatible(1023, 1023, 0));
        assert!(!is_gas_limit_target_compatible(1023, 1024, u64::MAX));
    }

    #[test]
    fn decode_bid_rejects_bad_inner_bid_offset() {
        let mut signed_bid = vec![0; SIGNED_EXECUTION_PAYLOAD_BID_MIN];
        signed_bid[..4].copy_from_slice(&100u32.to_le_bytes());
        signed_bid[100 + 188..100 + 192].copy_from_slice(&225u32.to_le_bytes());

        let err = match decode_bid(&signed_bid) {
            Ok(_) => panic!("bad inner bid offset must be malformed"),
            Err(err) => err,
        };
        assert!(matches!(err, E::Malformed { len } if len == signed_bid.len()));
    }
}
