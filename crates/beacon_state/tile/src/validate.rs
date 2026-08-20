use silver_beacon_state_data::{
    Epoch, SLOTS_PER_EPOCH, Slot, SpecConfig, StateWriterView, ValidatorsView,
};
use silver_common::ssz_view::{
    ATTESTATION_FIXED, AttestationView, EXECUTION_PAYLOAD_FIXED, ExecutionPayloadView,
    PROPOSER_SLASHING_SIZE, ProposerSlashingView,
};

use crate::{
    error::{
        AttestationError, BlsToExecutionChangeError, ExecutionPayloadError, ProposerSlashingError,
        Result, VoluntaryExitError,
    },
    merkle,
};

/// Attestation `data.index` gossip rule: pre-Gloas the committee is encoded in
/// `committee_index` so `index` must be 0; Gloas repurposes it as the
/// payload-presence bit.
#[inline]
pub fn attestation_index_ok(is_gloas: bool, index: u64) -> bool {
    if is_gloas { index < 2 } else { index == 0 }
}

pub fn validate_attestation_data(
    att: &[u8],
    state_slot: Slot,
    current_epoch: Epoch,
    previous_epoch: Epoch,
    is_gloas: bool,
) -> Result<(), AttestationError> {
    if att.len() < ATTESTATION_FIXED {
        return Err(AttestationError::TooShort { len: att.len(), min: ATTESTATION_FIXED });
    }

    let data = AttestationView::data(att);
    let att_slot = data.slot();
    let att_index = data.index();
    let target_epoch = data.target_epoch();

    if att_slot >= state_slot {
        return Err(AttestationError::SlotNotPast { att_slot, state_slot });
    }

    let att_epoch = att_slot / SLOTS_PER_EPOCH;
    if target_epoch != att_epoch {
        return Err(AttestationError::TargetEpochMismatch { target: target_epoch, att: att_epoch });
    }

    if target_epoch != current_epoch && target_epoch != previous_epoch {
        return Err(AttestationError::TargetEpochOutOfWindow {
            target: target_epoch,
            prev: previous_epoch,
            curr: current_epoch,
        });
    }

    if !attestation_index_ok(is_gloas, att_index) {
        return Err(AttestationError::IndexNonZero { idx: att_index });
    }

    Ok(())
}

pub fn validate_proposer_slashing(data: &[u8]) -> Result<(), ProposerSlashingError> {
    if data.len() < PROPOSER_SLASHING_SIZE {
        return Err(ProposerSlashingError::TooShort {
            len: data.len(),
            min: PROPOSER_SLASHING_SIZE,
        });
    }
    let s: &[u8; PROPOSER_SLASHING_SIZE] = data[..PROPOSER_SLASHING_SIZE].try_into().unwrap();
    let h1_idx = ProposerSlashingView::h1_proposer_index(s);
    let h2_idx = ProposerSlashingView::h2_proposer_index(s);
    if h1_idx != h2_idx {
        return Err(ProposerSlashingError::ProposerIndexMismatch { h1: h1_idx, h2: h2_idx });
    }
    let h1_slot = ProposerSlashingView::h1_slot(s);
    let h2_slot = ProposerSlashingView::h2_slot(s);
    if h1_slot != h2_slot {
        return Err(ProposerSlashingError::SlotMismatch { h1: h1_slot, h2: h2_slot });
    }
    // Distinct headers — same SignedBeaconBlockHeader is not slashable.
    if data[0..112] == data[208..320] {
        return Err(ProposerSlashingError::SameHeader);
    }
    Ok(())
}

pub fn validate_voluntary_exit(
    cfg: &SpecConfig,
    validators: &ValidatorsView,
    vi: u32,
    exit_epoch: Epoch,
    current_epoch: Epoch,
) -> Result<(), VoluntaryExitError> {
    let count = validators.count();
    if (vi as usize) >= count {
        return Err(VoluntaryExitError::ValidatorOutOfRange { vi: vi as usize, count });
    }
    let pubkey = *validators.pubkey(vi as usize);
    let act = validators.activation_epoch(vi as usize);
    let exit = validators.exit_epoch(vi as usize);
    if act > current_epoch || current_epoch >= exit {
        return Err(VoluntaryExitError::NotActive { vi: vi as usize, pubkey, epoch: current_epoch });
    }
    if exit != u64::MAX {
        return Err(VoluntaryExitError::AlreadyExiting { vi: vi as usize, pubkey });
    }
    if current_epoch < exit_epoch {
        return Err(VoluntaryExitError::ExitEpochInFuture {
            current: current_epoch,
            exit: exit_epoch,
        });
    }
    if current_epoch < act + cfg.shard_committee_period {
        return Err(VoluntaryExitError::TooEarly { vi: vi as usize, pubkey });
    }
    Ok(())
}

pub fn validate_bls_to_execution_change(
    validators: &ValidatorsView,
    vi: u32,
    from_pubkey: &[u8; 48],
) -> Result<(), BlsToExecutionChangeError> {
    let count = validators.count();
    if (vi as usize) >= count {
        return Err(BlsToExecutionChangeError::ValidatorOutOfRange { vi: vi as usize, count });
    }
    let creds = *validators.credentials(vi as usize);
    let prefix = creds.0[0];
    if prefix != 0x00 {
        return Err(BlsToExecutionChangeError::BadCredentialPrefix {
            vi: vi as usize,
            pubkey: *validators.pubkey(vi as usize),
            prefix,
        });
    }
    let pubkey_hash = merkle::sha256(from_pubkey);
    if creds.0[1..] != pubkey_hash[1..] {
        let mut expected = [0u8; 32];
        expected[1..].copy_from_slice(&creds.0[1..]);
        return Err(BlsToExecutionChangeError::PubkeyHashMismatch {
            from_pubkey: *from_pubkey,
            expected,
            got: pubkey_hash,
        });
    }
    Ok(())
}

pub fn validate_execution_payload(
    cfg: &SpecConfig,
    view: &StateWriterView,
    payload: &[u8],
    block_slot: Slot,
) -> Result<(), ExecutionPayloadError> {
    if payload.len() < EXECUTION_PAYLOAD_FIXED {
        return Err(ExecutionPayloadError::TooShort {
            len: payload.len(),
            min: EXECUTION_PAYLOAD_FIXED,
        });
    }
    let slot = view.slot.reader();
    let header = &slot.state().latest_execution_payload_header;
    let expected_randao = view.randao_mixes.reader().at_epoch(block_slot / SLOTS_PER_EPOCH);

    let got_parent = *ExecutionPayloadView::parent_hash(payload);
    let expected_parent = header.block_hash;
    if got_parent != expected_parent && header.block_number > 0 {
        return Err(ExecutionPayloadError::ParentHashMismatch {
            expected: expected_parent,
            got: got_parent,
        });
    }

    let expected_timestamp = view.imm.genesis_time + block_slot * cfg.seconds_per_slot;
    let got_timestamp = ExecutionPayloadView::timestamp(payload);
    if got_timestamp != expected_timestamp {
        return Err(ExecutionPayloadError::TimestampMismatch {
            expected: expected_timestamp,
            got: got_timestamp,
        });
    }

    let got_randao = *ExecutionPayloadView::prev_randao(payload);
    if got_randao != expected_randao {
        return Err(ExecutionPayloadError::RandaoMismatch {
            expected: expected_randao,
            got: got_randao,
        });
    }

    Ok(())
}
