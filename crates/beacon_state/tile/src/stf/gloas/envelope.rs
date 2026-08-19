//! Envelope verification minus the EL call — the engine verdict arrives
//! asynchronously, not inline.

use flux_profiler::timed;
use silver_beacon_state_data::{SpecConfig, StateReadView};
use silver_common::{
    ssz_hash_gloas::ExecutionRequestsView,
    ssz_view::{
        EXECUTION_PAYLOAD_FIXED_GLOAS, ExecutionPayloadEnvelopeView, ExecutionPayloadView,
        SignedExecutionPayloadEnvelopeView, WITHDRAWAL_SIZE, WithdrawalView,
    },
};

use super::builders::BUILDER_INDEX_SELF_BUILD;
use crate::{
    bls::{self, DOMAIN_BEACON_BUILDER},
    error::EnvelopeError as E,
};

pub fn verify_execution_payload_envelope(
    rv: &StateReadView,
    cfg: &SpecConfig,
    signed: &[u8],
) -> Result<(), E> {
    let envelope = SignedExecutionPayloadEnvelopeView::message(signed);
    let payload = ExecutionPayloadEnvelopeView::payload(envelope);
    if payload.len() < EXECUTION_PAYLOAD_FIXED_GLOAS {
        return Err(E::Malformed);
    }
    let wd_off = ExecutionPayloadView::withdrawals_offset(payload) as usize;
    let bal_off = ExecutionPayloadView::block_access_list_offset(payload) as usize;
    if wd_off < EXECUTION_PAYLOAD_FIXED_GLOAS || bal_off < wd_off || payload.len() < bal_off {
        return Err(E::Malformed);
    }

    let state = rv.slot.state();

    // beacon_block_root == the block this state belongs to: the caller found
    // `rv` by looking the root up in fork choice.
    if *ExecutionPayloadEnvelopeView::parent_beacon_block_root(envelope) !=
        state.latest_block_header.parent_root
    {
        return Err(E::PayloadMismatch { field: "parent_beacon_block_root" });
    }

    let bid = &state.latest_execution_payload_bid;
    let builder_index = ExecutionPayloadEnvelopeView::builder_index(envelope);
    if builder_index != bid.builder_index {
        return Err(E::BidMismatch { field: "builder_index" });
    }
    if *ExecutionPayloadView::prev_randao(payload) != bid.prev_randao {
        return Err(E::BidMismatch { field: "prev_randao" });
    }
    if ExecutionPayloadView::gas_limit(payload) != bid.gas_limit {
        return Err(E::BidMismatch { field: "gas_limit" });
    }
    if *ExecutionPayloadView::block_hash(payload) != bid.block_hash {
        return Err(E::BidMismatch { field: "block_hash" });
    }
    let requests = ExecutionPayloadEnvelopeView::execution_requests(envelope);
    if ExecutionRequestsView::hash_tree_root(requests) != bid.execution_requests_root {
        return Err(E::BidMismatch { field: "execution_requests_root" });
    }

    if ExecutionPayloadView::slot_number(payload) != state.slot {
        return Err(E::PayloadMismatch { field: "slot_number" });
    }
    if *ExecutionPayloadView::parent_hash(payload) != state.latest_block_hash {
        return Err(E::PayloadMismatch { field: "parent_hash" });
    }
    let expected_timestamp = rv.imm.genesis_time + state.slot * cfg.seconds_per_slot;
    if ExecutionPayloadView::timestamp(payload) != expected_timestamp {
        return Err(E::PayloadMismatch { field: "timestamp" });
    }

    let withdrawals = &payload[wd_off..bal_off];
    let expected = &state.payload_expected_withdrawals;
    if withdrawals.len() != expected.len() * WITHDRAWAL_SIZE {
        return Err(E::PayloadMismatch { field: "withdrawals" });
    }
    for (w, e) in withdrawals.chunks_exact(WITHDRAWAL_SIZE).zip(expected) {
        let w: &[u8; WITHDRAWAL_SIZE] = w.try_into().unwrap();
        let matches = WithdrawalView::index(w) == e.index &&
            WithdrawalView::validator_index(w) == e.validator_index &&
            *WithdrawalView::address(w) == e.address &&
            WithdrawalView::amount(w) == e.amount;
        if !matches {
            return Err(E::PayloadMismatch { field: "withdrawals" });
        }
    }

    verify_envelope_signature(rv, envelope, signed, builder_index)
}

#[timed]
fn verify_envelope_signature(
    rv: &StateReadView,
    envelope: &[u8],
    signed: &[u8],
    builder_index: u64,
) -> Result<(), E> {
    let message_root = ExecutionPayloadEnvelopeView::hash_tree_root(envelope);
    let fork_version = rv.epoch.fork_version_at(rv.slot.current_epoch());
    let domain =
        bls::compute_domain(DOMAIN_BEACON_BUILDER, fork_version, &rv.imm.genesis_validators_root);
    let signing_root = bls::compute_signing_root(&message_root, &domain);
    let sig = SignedExecutionPayloadEnvelopeView::signature(signed);

    let valid = if builder_index == BUILDER_INDEX_SELF_BUILD {
        let proposer = rv.slot.state().latest_block_header.proposer_index as usize;
        if proposer >= rv.validators.count() {
            return Err(E::BuilderOutOfRange { index: builder_index });
        }
        bls::verify_one(rv.validators.pubkey_decompressed(proposer), sig, &signing_root)
    } else {
        let builder = rv
            .builders
            .get(builder_index as usize)
            .ok_or(E::BuilderOutOfRange { index: builder_index })?;
        bls::verify_one_compressed(&builder.pubkey, sig, &signing_root)
    };
    if !valid {
        return Err(E::BadSignature);
    }
    Ok(())
}
