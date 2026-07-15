use blst::min_pk::PublicKey;
use silver_beacon_state_data::{
    EpochView, Immutable, SLOTS_PER_EPOCH, StateWriterView, ValidatorsView, gloas::PTC_SIZE,
};
use silver_common::ssz_view::{
    PAYLOAD_ATTESTATION_SIZE, PayloadAttestationDataView, PayloadAttestationView,
};

use super::committee::get_ptc;
use crate::{
    bls::{self, DOMAIN_PTC_ATTESTER, SigBatch},
    error::PayloadAttestationError as E,
    merkle::{merkleize, uint64_chunk},
};

#[inline]
fn bit_set(bits: &[u8], i: usize) -> bool {
    bits[i / 8] >> (i % 8) & 1 == 1
}

pub fn process_payload_attestations(view: &StateWriterView, section: &[u8]) -> Result<(), E> {
    for pa in section.chunks_exact(PAYLOAD_ATTESTATION_SIZE) {
        process_payload_attestation(view, pa)?;
    }

    Ok(())
}

/// Validate a payload attestation against the parent block. The PTC
/// aggregate signature is batch-verified separately by
/// [`collect_sigs_payload_attestation`]; this applies the non-signature
/// asserts.
fn process_payload_attestation(view: &StateWriterView, pa: &[u8]) -> Result<(), E> {
    if pa.len() != PAYLOAD_ATTESTATION_SIZE {
        return Err(E::Malformed { len: pa.len() });
    }
    let pa: &[u8; PAYLOAD_ATTESTATION_SIZE] = pa.try_into().unwrap();
    let data = PayloadAttestationView::data(pa);
    let state_slot = view.slot.state().slot;

    if *PayloadAttestationDataView::beacon_block_root(data) !=
        view.slot.state().latest_block_header.parent_root
    {
        return Err(E::BadBeaconBlockRoot);
    }
    let pa_slot = PayloadAttestationDataView::slot(data);
    if pa_slot + 1 != state_slot {
        return Err(E::BadSlot { slot: pa_slot, state: state_slot });
    }
    let bits = PayloadAttestationView::aggregation_bits(pa);
    if !(0..PTC_SIZE).any(|i| bit_set(bits, i)) {
        return Err(E::NoAttestingIndices);
    }
    Ok(())
}
pub fn collect_sigs_payload_attestations(
    imm: &Immutable,
    validators: &ValidatorsView,
    epoch: &EpochView,
    state_slot: u64,
    section: &[u8],
    batch: &mut SigBatch,
) -> Result<(), E> {
    for pa in section.chunks_exact(PAYLOAD_ATTESTATION_SIZE) {
        collect_sigs_payload_attestation(imm, validators, epoch, state_slot, pa, batch)?;
    }
    Ok(())
}

fn collect_sigs_payload_attestation(
    imm: &Immutable,
    validators: &ValidatorsView,
    epoch: &EpochView,
    state_slot: u64,
    pa: &[u8],
    batch: &mut SigBatch,
) -> Result<(), E> {
    if pa.len() != PAYLOAD_ATTESTATION_SIZE {
        return Err(E::Malformed { len: pa.len() });
    }
    let pa: &[u8; PAYLOAD_ATTESTATION_SIZE] = pa.try_into().unwrap();
    let bits = PayloadAttestationView::aggregation_bits(pa);
    let data = PayloadAttestationView::data(pa);
    let signature = PayloadAttestationView::signature(pa);
    let pa_slot = PayloadAttestationDataView::slot(data);

    let Some(ptc) = get_ptc(epoch, state_slot / SLOTS_PER_EPOCH, pa_slot) else {
        return Err(E::BadSlot { slot: pa_slot, state: state_slot });
    };
    let pubkeys: Vec<&PublicKey> = (0..PTC_SIZE)
        .filter(|&i| bit_set(bits, i))
        .map(|i| validators.pubkey_decompressed(ptc[i] as usize))
        .collect();

    let fork_version = epoch.fork_version_at(pa_slot / SLOTS_PER_EPOCH);
    let domain =
        bls::compute_domain(DOMAIN_PTC_ATTESTER, fork_version, &imm.genesis_validators_root);
    let signing_root = bls::compute_signing_root(&hash_payload_attestation_data(data), &domain);
    batch.push_aggregate(pubkeys, signature, signing_root);
    Ok(())
}

fn hash_payload_attestation_data(data: &[u8; 42]) -> silver_beacon_state_data::B256 {
    let bool_chunk = |b: u8| {
        let mut c = [0u8; 32];
        c[0] = b;
        c
    };
    merkleize(&[
        data[0..32].try_into().unwrap(),
        uint64_chunk(PayloadAttestationDataView::slot(data)),
        bool_chunk(data[40]),
        bool_chunk(data[41]),
    ])
}
