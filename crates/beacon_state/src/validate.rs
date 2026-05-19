use silver_common::ssz_view::{
    ATTESTATION_FIXED, AttestationDataView, AttestationView, EXECUTION_PAYLOAD_FIXED,
    ExecutionPayloadView, PROPOSER_SLASHING_SIZE, ProposerSlashingView,
};

use crate::{
    error::{
        AttestationError, BlockError, BlsToExecutionChangeError, ExecutionPayloadError,
        OperationKind, ProposerSlashingError, Result, VoluntaryExitError,
    },
    ssz_hash,
    types::*,
    validator_identity::ValidatorsState,
};

const SECONDS_PER_SLOT: u64 = 12;

// Spec operation limits — `_ELECTRA` suffixed constants retain the spec
// name; values are unchanged in Fulu.
pub const MAX_PROPOSER_SLASHINGS: usize = 16;
pub const MAX_ATTESTER_SLASHINGS_ELECTRA: usize = 1;
pub const MAX_ATTESTATIONS_ELECTRA: usize = 8;
pub const MAX_DEPOSITS: usize = 16;
pub const MAX_VOLUNTARY_EXITS: usize = 16;
pub const MAX_BLS_TO_EXECUTION_CHANGES: usize = 16;

pub fn validate_attestation_data(
    att: &[u8],
    state_slot: Slot,
    current_epoch: Epoch,
    previous_epoch: Epoch,
) -> Result<(), AttestationError> {
    if att.len() < ATTESTATION_FIXED {
        return Err(AttestationError::TooShort { len: att.len(), min: ATTESTATION_FIXED });
    }

    let data = AttestationView::data(att);
    let att_slot = AttestationDataView::slot(data);
    let att_index = AttestationDataView::index(data);
    let target_epoch = AttestationDataView::target_epoch(data);

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
            cur: current_epoch,
        });
    }

    if att_index != 0 {
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
    vs: &ValidatorsState,
    epoch: &EpochData,
    vi: usize,
    exit_epoch: Epoch,
    current_epoch: Epoch,
) -> Result<(), VoluntaryExitError> {
    let cnt = vs.validator_cnt();
    if vi >= cnt {
        return Err(VoluntaryExitError::ValidatorOutOfRange { vi, cnt });
    }
    let pubkey = *vs.pubkey(vi);
    if epoch.val_activation_epoch[vi] > current_epoch || current_epoch >= epoch.val_exit_epoch[vi] {
        return Err(VoluntaryExitError::NotActive { vi, pubkey, epoch: current_epoch });
    }
    if epoch.val_exit_epoch[vi] != u64::MAX {
        return Err(VoluntaryExitError::AlreadyExiting { vi, pubkey });
    }
    if current_epoch < exit_epoch {
        return Err(VoluntaryExitError::ExitEpochInFuture {
            current: current_epoch,
            exit: exit_epoch,
        });
    }
    const SHARD_COMMITTEE_PERIOD: u64 = 256;
    if current_epoch < epoch.val_activation_epoch[vi] + SHARD_COMMITTEE_PERIOD {
        return Err(VoluntaryExitError::TooEarly { vi, pubkey });
    }
    Ok(())
}

pub fn validate_bls_to_execution_change(
    vs: &ValidatorsState,
    vi: usize,
    from_pubkey: &[u8; 48],
) -> Result<(), BlsToExecutionChangeError> {
    let cnt = vs.validator_cnt();
    if vi >= cnt {
        return Err(BlsToExecutionChangeError::ValidatorOutOfRange { vi, cnt });
    }
    let creds = vs.withdrawal_credentials(vi);
    let prefix = creds.prefix();
    if prefix != 0x00 {
        return Err(BlsToExecutionChangeError::BadCredentialPrefix {
            vi,
            pubkey: *vs.pubkey(vi),
            prefix,
        });
    }
    let pubkey_hash = ssz_hash::sha256(from_pubkey);
    if creds[1..] != pubkey_hash[1..] {
        let mut expected = [0u8; 32];
        expected[1..].copy_from_slice(&creds[1..]);
        return Err(BlsToExecutionChangeError::PubkeyHashMismatch {
            from_pubkey: *from_pubkey,
            expected,
            got: pubkey_hash,
        });
    }
    Ok(())
}

pub fn validate_execution_payload(
    imm: &Immutable,
    sd: &SlotData,
    payload: &[u8],
    block_slot: Slot,
) -> Result<(), ExecutionPayloadError> {
    if payload.len() < EXECUTION_PAYLOAD_FIXED {
        return Err(ExecutionPayloadError::TooShort {
            len: payload.len(),
            min: EXECUTION_PAYLOAD_FIXED,
        });
    }

    // parent_hash == state.latest_execution_payload_header.block_hash
    let got_parent = *ExecutionPayloadView::parent_hash(payload);
    let expected_parent = sd.latest_execution_payload_header.block_hash;
    if got_parent != expected_parent && sd.latest_execution_payload_header.block_number > 0 {
        return Err(ExecutionPayloadError::ParentHashMismatch {
            expected: expected_parent,
            got: got_parent,
        });
    }

    // Spec: timestamp == compute_timestamp_at_slot(state, block.slot).
    let expected_timestamp = imm.genesis_time + block_slot * SECONDS_PER_SLOT;
    let got_timestamp = ExecutionPayloadView::timestamp(payload);
    if got_timestamp != expected_timestamp {
        return Err(ExecutionPayloadError::TimestampMismatch {
            expected: expected_timestamp,
            got: got_timestamp,
        });
    }

    // Spec: prev_randao == get_randao_mix(state, current_epoch).
    let got_randao = *ExecutionPayloadView::prev_randao(payload);
    if got_randao != sd.randao_mix_current {
        return Err(ExecutionPayloadError::RandaoMismatch {
            expected: sd.randao_mix_current,
            got: got_randao,
        });
    }

    // TODO(EL): full payload acceptance is determined by engine_newPayloadV4
    // (VALID/INVALID/SYNCING). See process_block_body — flag block as
    // optimistic on SYNCING, reject on INVALID.

    Ok(())
}

pub fn validate_operation_counts(body: &[u8]) -> Result<(), BlockError> {
    if body.len() < 396 {
        return Err(BlockError::BodyTooShort { len: body.len(), min: 396 });
    }
    let off = |pos: usize| u32::from_le_bytes(body[pos..pos + 4].try_into().unwrap()) as usize;

    // Variable field offsets in SSZ field order (skipping fixed fields).
    let ps_off = off(200); // proposer_slashings
    let as_off = off(204); // attester_slashings
    let att_off = off(208); // attestations
    let dep_off = off(212); // deposits
    let ve_off = off(216); // voluntary_exits
    let ep_off = off(380); // execution_payload (next variable after voluntary_exits)
    let bls_off = off(384); // bls_to_execution_changes
    let blob_off = off(388); // blob_kzg_commitments
    let exec_req_off = off(392); // execution_requests

    let offsets: &[(usize, &'static str, usize)] = &[
        (200, "proposer_slashings", ps_off),
        (204, "attester_slashings", as_off),
        (208, "attestations", att_off),
        (212, "deposits", dep_off),
        (216, "voluntary_exits", ve_off),
        (380, "execution_payload", ep_off),
        (384, "bls_to_execution_changes", bls_off),
        (388, "blob_kzg_commitments", blob_off),
        (392, "execution_requests", exec_req_off),
    ];
    let body_len = body.len();
    for (i, &(at, field, off_val)) in offsets.iter().enumerate() {
        let next_off = offsets.get(i + 1).map(|(_, _, o)| *o);
        let exceeds_body = off_val > body_len;
        let non_monotone = next_off.is_some_and(|n| n < off_val);
        if exceeds_body || non_monotone {
            return Err(BlockError::BodyOffsetOutOfRange {
                at,
                field,
                off: off_val,
                next_off,
                body_len,
            });
        }
    }

    // Fixed-size element counts from region sizes.
    let safe_count = |start: usize, end: usize, elem_size: usize| -> usize {
        if end >= start && elem_size > 0 { (end - start) / elem_size } else { 0 }
    };

    let check = |op: OperationKind, count: usize, max: usize| -> Result<(), BlockError> {
        if count > max {
            Err(BlockError::OperationCountOutOfBounds { op, count, max })
        } else {
            Ok(())
        }
    };

    check(
        OperationKind::ProposerSlashings,
        safe_count(ps_off, as_off, 416),
        MAX_PROPOSER_SLASHINGS,
    )?;
    check(OperationKind::Deposits, safe_count(dep_off, ve_off, 1240), MAX_DEPOSITS)?;
    check(OperationKind::VoluntaryExits, safe_count(ve_off, ep_off, 112), MAX_VOLUNTARY_EXITS)?;
    check(
        OperationKind::BlsToExecutionChanges,
        safe_count(bls_off, blob_off, 172),
        MAX_BLS_TO_EXECUTION_CHANGES,
    )?;

    // Variable-size element counts from offset tables.
    let var_count = |start: usize, end: usize| -> usize {
        if end <= start || start >= body.len() {
            return 0;
        }
        let data = &body[start..end.min(body.len())];
        if data.len() < 4 {
            return 0;
        }
        let first = u32::from_le_bytes(data[..4].try_into().unwrap()) as usize;
        if first > 0 && first.is_multiple_of(4) { first / 4 } else { 0 }
    };

    check(
        OperationKind::AttesterSlashings,
        var_count(as_off, att_off),
        MAX_ATTESTER_SLASHINGS_ELECTRA,
    )?;
    check(OperationKind::Attestations, var_count(att_off, dep_off), MAX_ATTESTATIONS_ELECTRA)?;

    Ok(())
}
