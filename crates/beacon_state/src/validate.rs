use crate::{ssz_hash, types::*};

const SECONDS_PER_SLOT: u64 = 12;

// Spec operation limits (Electra).
pub const MAX_PROPOSER_SLASHINGS: usize = 16;
pub const MAX_ATTESTER_SLASHINGS_ELECTRA: usize = 1;
pub const MAX_ATTESTATIONS_ELECTRA: usize = 8;
pub const MAX_DEPOSITS: usize = 16;
pub const MAX_VOLUNTARY_EXITS: usize = 16;
pub const MAX_BLS_TO_EXECUTION_CHANGES: usize = 16;

// TODO(BLS): caller must FastAggregateVerify each attestation's aggregate
// signature against the participants' pubkeys under DOMAIN_BEACON_ATTESTER for
// the attestation's target epoch. Not yet wired into process_single_attestation
// — every block-included attestation should be BLS-checked before
// participation flags are set.
pub fn validate_attestation_data(
    att: &[u8],
    state_slot: Slot,
    current_epoch: Epoch,
    previous_epoch: Epoch,
) -> bool {
    if att.len() < 236 {
        return false;
    }

    let att_slot = u64::from_le_bytes(att[4..12].try_into().unwrap());
    let att_index = u64::from_le_bytes(att[12..20].try_into().unwrap());
    let target_epoch = u64::from_le_bytes(att[92..100].try_into().unwrap());

    if att_slot >= state_slot {
        return false;
    }

    let att_epoch = att_slot / SLOTS_PER_EPOCH;
    if target_epoch != att_epoch {
        return false;
    }

    if target_epoch != current_epoch && target_epoch != previous_epoch {
        return false;
    }

    if att_index != 0 {
        return false;
    }

    true
}

pub fn validate_proposer_slashing(data: &[u8]) -> bool {
    if data.len() < 416 {
        return false;
    }
    // Header 1: slot at [0..8), proposer at [8..16)
    // Header 2: slot at [208..216), proposer at [216..224)
    let slot_1 = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let proposer_1 = u64::from_le_bytes(data[8..16].try_into().unwrap());
    let slot_2 = u64::from_le_bytes(data[208..216].try_into().unwrap());
    let proposer_2 = u64::from_le_bytes(data[216..224].try_into().unwrap());

    if proposer_1 != proposer_2 {
        return false;
    }
    if slot_1 != slot_2 {
        return false;
    }
    if data[0..112] == data[208..320] {
        return false;
    }
    // TODO(spec): is_slashable_validator(state.validators[proposer], current_epoch)
    // — currently checked at process_proposer_slashings via `val_slashed == 0`
    // only; spec also requires `activation_epoch <= current_epoch` and
    // `current_epoch < withdrawable_epoch`.
    // TODO(BLS): verify SignedBeaconBlockHeader signatures on both headers under
    // DOMAIN_BEACON_PROPOSER (sig at data[112..208] and data[320..416]).
    true
}

// TODO(BLS): caller must verify SignedVoluntaryExit signature under
// DOMAIN_VOLUNTARY_EXIT before invoking this. The sig is the trailing 96 B of
// the SSZ container; not currently checked in process_voluntary_exits.
pub fn validate_voluntary_exit(
    vid: &ValidatorIdentity,
    epoch: &EpochData,
    vi: usize,
    exit_epoch: Epoch,
    current_epoch: Epoch,
) -> bool {
    if vi >= vid.validator_cnt {
        return false;
    }
    if epoch.val_activation_epoch[vi] > current_epoch || current_epoch >= epoch.val_exit_epoch[vi] {
        return false;
    }
    if epoch.val_exit_epoch[vi] != u64::MAX {
        return false;
    }
    if current_epoch < exit_epoch {
        return false;
    }
    const SHARD_COMMITTEE_PERIOD: u64 = 256;
    if current_epoch < epoch.val_activation_epoch[vi] + SHARD_COMMITTEE_PERIOD {
        return false;
    }
    true
}

// TODO(BLS): verify the SignedBLSToExecutionChange signature under
// DOMAIN_BLS_TO_EXECUTION_CHANGE (Capella). Caller in
// process_bls_to_execution_changes drops only structural / credential checks.
pub fn validate_bls_to_execution_change(
    vid: &ValidatorIdentity,
    vi: usize,
    from_pubkey: &[u8; 48],
) -> bool {
    if vi >= vid.validator_cnt {
        return false;
    }
    if vid.val_withdrawal_credentials[vi][0] != 0x00 {
        return false;
    }
    let pubkey_hash = ssz_hash::sha256(from_pubkey);
    if vid.val_withdrawal_credentials[vi][1..] != pubkey_hash[1..] {
        return false;
    }
    true
}

pub fn validate_execution_payload(
    imm: &Immutable,
    sd: &SlotData,
    payload: &[u8],
    block_slot: Slot,
) -> bool {
    if payload.len() < 528 {
        return false;
    }
    let b256 = |off: usize| -> B256 { payload[off..off + 32].try_into().unwrap() };
    let u64le =
        |off: usize| -> u64 { u64::from_le_bytes(payload[off..off + 8].try_into().unwrap()) };

    // parent_hash == state.latest_execution_payload_header.block_hash
    let parent_hash = b256(0);
    if parent_hash != sd.latest_execution_payload_header.block_hash &&
        sd.latest_execution_payload_header.block_number > 0
    {
        return false;
    }

    // Spec: timestamp == compute_timestamp_at_slot(state, block.slot).
    let expected_timestamp = imm.genesis_time + block_slot * SECONDS_PER_SLOT;
    if u64le(428) != expected_timestamp {
        return false;
    }

    // Spec: prev_randao == get_randao_mix(state, current_epoch).
    if b256(372) != sd.randao_mix_current {
        return false;
    }

    // TODO(EL): full payload acceptance is determined by engine_newPayloadV4
    // (VALID/INVALID/SYNCING). See process_block_body — flag block as
    // optimistic on SYNCING, reject on INVALID.

    true
}

pub fn validate_operation_counts(body: &[u8]) -> bool {
    if body.len() < 396 {
        return false;
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

    // Fixed-size element counts from region sizes.
    let safe_count = |start: usize, end: usize, elem_size: usize| -> usize {
        if end >= start && elem_size > 0 { (end - start) / elem_size } else { 0 }
    };

    if safe_count(ps_off, as_off, 416) > MAX_PROPOSER_SLASHINGS {
        return false;
    }
    if safe_count(dep_off, ve_off, 1240) > MAX_DEPOSITS {
        return false;
    }
    if safe_count(ve_off, ep_off, 112) > MAX_VOLUNTARY_EXITS {
        return false;
    }
    if safe_count(bls_off, blob_off, 172) > MAX_BLS_TO_EXECUTION_CHANGES {
        return false;
    }

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

    if var_count(as_off, att_off) > MAX_ATTESTER_SLASHINGS_ELECTRA {
        return false;
    }
    if var_count(att_off, dep_off) > MAX_ATTESTATIONS_ELECTRA {
        return false;
    }

    true
}
