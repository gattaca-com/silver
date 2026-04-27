use crate::{
    epoch_transition, ssz_hash,
    types::{
        B256, Checkpoint, EPOCHS_PER_HISTORICAL_VECTOR, EPOCHS_PER_SLASHINGS_VECTOR, EpochData,
        Eth1Data, ExecutionPayloadHeader, Fork, HISTORICAL_ROOTS_LIMIT, HISTORICAL_SUMMARIES_CAP,
        HistoricalLongtail, HistoricalSummary, Immutable, MAX_ETH1_VOTES, MAX_VALIDATORS,
        PENDING_CONSOLIDATIONS_LIMIT, PENDING_DEPOSITS_LIMIT, PENDING_PARTIAL_WITHDRAWALS_LIMIT,
        PendingConsolidation, PendingDeposit, PendingPartialWithdrawal, PendingQueues,
        SLOTS_PER_EPOCH, SLOTS_PER_HISTORICAL_ROOT, SYNC_COMMITTEE_SIZE, SlotData, SlotRoots,
        SyncCommittee, ValidatorIdentity,
    },
};

// SSZ Validator: pubkey(48) + withdrawal_credentials(32) + effective_balance(8)
// + slashed(1) + activation_eligibility_epoch(8) + activation_epoch(8)
// + exit_epoch(8) + withdrawable_epoch(8) = 121 bytes.
const VALIDATOR_SSZ_SIZE: usize = 121;
const ETH1_DATA_SSZ_SIZE: usize = 72;
const HISTORICAL_SUMMARY_SSZ_SIZE: usize = 64;
const PENDING_DEPOSIT_SSZ_SIZE: usize = 192;
const PENDING_PARTIAL_WITHDRAWAL_SSZ_SIZE: usize = 24;
const PENDING_CONSOLIDATION_SSZ_SIZE: usize = 16;
const EPH_FIXED_PART: usize = 584;

// Byte offsets of each field in the BeaconState SSZ fixed part.
// Fields 0–37, Fulu fork. Variable-length fields store a 4-byte offset.
const F0: usize = 0; // genesis_time: 8
const F1: usize = 8; // genesis_validators_root: 32
const F2: usize = 40; // slot: 8
const F3: usize = 48; // fork: 16
const F4: usize = 64; // latest_block_header: 112
const F5: usize = 176; // block_roots: Vector[B32, 8192] = 262144
const F6: usize = 262_320; // state_roots: Vector[B32, 8192] = 262144
const F7_OFF: usize = 524_464; // historical_roots offset: 4
const F8: usize = 524_468; // eth1_data: 72
const F9_OFF: usize = 524_540; // eth1_data_votes offset: 4
const F10: usize = 524_544; // eth1_deposit_index: 8
const F11_OFF: usize = 524_552; // validators offset: 4
const F12_OFF: usize = 524_556; // balances offset: 4
const F13: usize = 524_560; // randao_mixes: Vector[B32, 65536] = 2097152
const F14: usize = 2_621_712; // slashings: Vector[u64, 8192] = 65536
const F15_OFF: usize = 2_687_248; // previous_epoch_participation offset: 4
const F16_OFF: usize = 2_687_252; // current_epoch_participation offset: 4
const F17: usize = 2_687_256; // justification_bits: 1
const F18: usize = 2_687_257; // previous_justified_checkpoint: 40
const F19: usize = 2_687_297; // current_justified_checkpoint: 40
const F20: usize = 2_687_337; // finalized_checkpoint: 40
const F21_OFF: usize = 2_687_377; // inactivity_scores offset: 4
const F22: usize = 2_687_381; // current_sync_committee: 24624
const F23: usize = 2_712_005; // next_sync_committee: 24624
const F24_OFF: usize = 2_736_629; // latest_execution_payload_header offset: 4
const F25: usize = 2_736_633; // next_withdrawal_index: 8
const F26: usize = 2_736_641; // next_withdrawal_validator_index: 8
const F27_OFF: usize = 2_736_649; // historical_summaries offset: 4
const F28: usize = 2_736_653; // deposit_requests_start_index: 8
const F29: usize = 2_736_661; // deposit_balance_to_consume: 8
const F30: usize = 2_736_669; // exit_balance_to_consume: 8
const F31: usize = 2_736_677; // earliest_exit_epoch: 8
const F32: usize = 2_736_685; // consolidation_balance_to_consume: 8
const F33: usize = 2_736_693; // earliest_consolidation_epoch: 8
const F34_OFF: usize = 2_736_701; // pending_deposits offset: 4
const F35_OFF: usize = 2_736_705; // pending_partial_withdrawals offset: 4
const F36_OFF: usize = 2_736_709; // pending_consolidations offset: 4
const F37: usize = 2_736_713; // proposer_lookahead: Vector[u64, 64] = 512
const FIXED_PART: usize = 2_737_225;

fn u32_le(s: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(s[off..off + 4].try_into().unwrap())
}

fn u64_le(s: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(s[off..off + 8].try_into().unwrap())
}

fn b256(s: &[u8], off: usize) -> B256 {
    s[off..off + 32].try_into().unwrap()
}

// On `None`, destinations may have been partially populated.
#[allow(clippy::too_many_arguments)]
pub fn decompose_beacon_state(
    ssz: &[u8],
    zh: &[B256],
    imm: &mut Immutable,
    vid: &mut ValidatorIdentity,
    longtail: &mut HistoricalLongtail,
    epoch: &mut EpochData,
    roots: &mut SlotRoots,
    sd: &mut SlotData,
) -> Option<PendingQueues> {
    if ssz.len() < FIXED_PART {
        return None;
    }

    // Read variable-field offsets.
    let off_historical_roots = u32_le(ssz, F7_OFF) as usize;
    let off_eth1_votes = u32_le(ssz, F9_OFF) as usize;
    let off_validators = u32_le(ssz, F11_OFF) as usize;
    let off_balances = u32_le(ssz, F12_OFF) as usize;
    let off_prev_participation = u32_le(ssz, F15_OFF) as usize;
    let off_cur_participation = u32_le(ssz, F16_OFF) as usize;
    let off_inactivity = u32_le(ssz, F21_OFF) as usize;
    let off_eph = u32_le(ssz, F24_OFF) as usize;
    let off_hist_summaries = u32_le(ssz, F27_OFF) as usize;
    let off_pending_deposits = u32_le(ssz, F34_OFF) as usize;
    let off_pending_withdrawals = u32_le(ssz, F35_OFF) as usize;
    let off_pending_consolidations = u32_le(ssz, F36_OFF) as usize;

    // All variable-field offsets in SSZ-declared order. They must be
    // monotonically non-decreasing and all within `ssz.len()`; the first
    // must start at or past `FIXED_PART`. Any violation => malformed SSZ.
    let offsets = [
        off_historical_roots,
        off_eth1_votes,
        off_validators,
        off_balances,
        off_prev_participation,
        off_cur_participation,
        off_inactivity,
        off_eph,
        off_hist_summaries,
        off_pending_deposits,
        off_pending_withdrawals,
        off_pending_consolidations,
    ];
    if offsets[0] < FIXED_PART {
        return None;
    }
    for w in offsets.windows(2) {
        if w[0] > w[1] {
            return None;
        }
    }
    if *offsets.last().unwrap() > ssz.len() {
        return None;
    }

    let mut pq = PendingQueues::new();

    imm.genesis_time = u64_le(ssz, F0);
    imm.genesis_validators_root = b256(ssz, F1);

    // Fork (3 fields, 16B)
    imm.fork = Fork {
        previous_version: ssz[F3..F3 + 4].try_into().unwrap(),
        current_version: ssz[F3 + 4..F3 + 8].try_into().unwrap(),
        epoch: u64_le(ssz, F3 + 8),
    };

    // randao_mixes: Vector[B256, 65536] (2 097 152B). B256 has alignment 1
    // (asserted in types.rs); bulk memcpy via raw-parts cast.
    let randao_src: &[B256] = unsafe {
        std::slice::from_raw_parts(ssz[F13..].as_ptr().cast::<B256>(), EPOCHS_PER_HISTORICAL_VECTOR)
    };
    epoch.randao_mixes.copy_from_slice(randao_src);

    // slashings: Vector[u64, 8192] (65 536B)
    for i in 0..EPOCHS_PER_SLASHINGS_VECTOR {
        epoch.slashings[i] = u64_le(ssz, F14 + i * 8);
    }

    // current_sync_committee, next_sync_committee (24 624B each)
    read_sync_committee(ssz, F22, &mut longtail.current_sync_committee)?;
    read_sync_committee(ssz, F23, &mut longtail.next_sync_committee)?;

    let block_src: &[B256] = unsafe {
        std::slice::from_raw_parts(ssz[F5..].as_ptr().cast::<B256>(), SLOTS_PER_HISTORICAL_ROOT)
    };
    roots.block_roots.copy_from_slice(block_src);
    let state_src: &[B256] = unsafe {
        std::slice::from_raw_parts(ssz[F6..].as_ptr().cast::<B256>(), SLOTS_PER_HISTORICAL_ROOT)
    };
    roots.state_roots.copy_from_slice(state_src);

    sd.slot = u64_le(ssz, F2);

    // latest_block_header (112B)
    sd.latest_block_header.slot = u64_le(ssz, F4);
    sd.latest_block_header.proposer_index = u64_le(ssz, F4 + 8);
    sd.latest_block_header.parent_root = b256(ssz, F4 + 16);
    sd.latest_block_header.state_root = b256(ssz, F4 + 48);
    sd.latest_block_header.body_root = b256(ssz, F4 + 80);

    // eth1_data (72B)
    sd.eth1_data = Eth1Data {
        deposit_root: b256(ssz, F8),
        deposit_count: u64_le(ssz, F8 + 32),
        block_hash: b256(ssz, F8 + 40),
    };

    sd.eth1_deposit_index = u64_le(ssz, F10);
    sd.justification_bits = ssz[F17] & 0x0F;

    sd.previous_justified_checkpoint = read_checkpoint(ssz, F18);
    sd.current_justified_checkpoint = read_checkpoint(ssz, F19);
    sd.finalized_checkpoint = read_checkpoint(ssz, F20);

    sd.next_withdrawal_index = u64_le(ssz, F25);
    sd.next_withdrawal_validator_index = u64_le(ssz, F26);

    sd.deposit_requests_start_index = u64_le(ssz, F28);
    sd.deposit_balance_to_consume = u64_le(ssz, F29);
    sd.exit_balance_to_consume = u64_le(ssz, F30);
    sd.earliest_exit_epoch = u64_le(ssz, F31);
    sd.consolidation_balance_to_consume = u64_le(ssz, F32);
    sd.earliest_consolidation_epoch = u64_le(ssz, F33);

    // proposer_lookahead: Vector[u64, 64] (512B)
    for i in 0..64 {
        sd.proposer_lookahead[i] = u64_le(ssz, F37 + i * 8);
    }

    // Set randao_mix_current to the current epoch's mix.
    let current_epoch = sd.slot / SLOTS_PER_EPOCH;
    let mix_idx = current_epoch as usize % EPOCHS_PER_HISTORICAL_VECTOR;
    sd.randao_mix_current = epoch.randao_mixes[mix_idx];

    // Validators → split across ValidatorIdentity + EpochData (columnar)
    let val_bytes = &ssz[off_validators..off_balances];
    if !val_bytes.len().is_multiple_of(VALIDATOR_SSZ_SIZE) {
        return None;
    }
    let n = val_bytes.len() / VALIDATOR_SSZ_SIZE;
    if n > MAX_VALIDATORS {
        return None;
    }
    vid.validator_cnt = n;
    for i in 0..n {
        let v = &val_bytes[i * VALIDATOR_SSZ_SIZE..];
        vid.val_pubkey[i].copy_from_slice(&v[..48]);
        vid.val_withdrawal_credentials[i] = b256(v, 48);
        epoch.val_effective_balance[i] = u64_le(v, 80);
        epoch.set_val_slashed(i, v[88] != 0);
        epoch.val_activation_eligibility_epoch[i] = u64_le(v, 89);
        epoch.val_activation_epoch[i] = u64_le(v, 97);
        epoch.val_exit_epoch[i] = u64_le(v, 105);
        epoch.val_withdrawable_epoch[i] = u64_le(v, 113);
    }

    // Balances → SlotData
    let bal_bytes = &ssz[off_balances..off_prev_participation];
    if !bal_bytes.len().is_multiple_of(8) || bal_bytes.len() / 8 != n {
        return None;
    }
    for i in 0..n {
        sd.balances[i] = u64_le(bal_bytes, i * 8);
    }

    // Previous/current epoch participation → SlotData
    let prev_part = &ssz[off_prev_participation..off_cur_participation];
    if prev_part.len() != n {
        return None;
    }
    sd.previous_epoch_participation[..n].copy_from_slice(prev_part);

    // current_epoch_participation ends at inactivity_scores offset.
    // But we need to find what comes after cur_participation. The variable
    // fields are ordered by offset slot, and the next offset after 16
    // (cur_participation) is 21 (inactivity_scores). However, in between
    // there are fixed fields 17-20 that are in the fixed part. The variable
    // data is laid out after the fixed part in offset order: historical_roots,
    // eth1_votes, validators, balances, prev_participation, cur_participation,
    // inactivity_scores, eph, hist_summaries, pending_deposits,
    // pending_withdrawals, pending_consolidations.
    let cur_part = &ssz[off_cur_participation..off_inactivity];
    if cur_part.len() != n {
        return None;
    }
    sd.current_epoch_participation[..n].copy_from_slice(cur_part);

    // Inactivity scores → EpochData
    let inact_bytes = &ssz[off_inactivity..off_eph];
    if !inact_bytes.len().is_multiple_of(8) || inact_bytes.len() / 8 != n {
        return None;
    }
    for i in 0..n {
        epoch.inactivity_scores[i] = u64_le(inact_bytes, i * 8);
    }

    // Execution payload header → SlotData
    read_execution_payload_header(
        ssz,
        off_eph,
        off_hist_summaries,
        &mut sd.latest_execution_payload_header,
    )?;

    // Eth1 data votes → SlotData
    let votes_bytes = &ssz[off_eth1_votes..off_validators];
    if !votes_bytes.len().is_multiple_of(ETH1_DATA_SSZ_SIZE) {
        return None;
    }
    let vote_count = votes_bytes.len() / ETH1_DATA_SSZ_SIZE;
    if vote_count > MAX_ETH1_VOTES {
        return None;
    }
    for i in 0..vote_count {
        let v = &votes_bytes[i * ETH1_DATA_SSZ_SIZE..];
        sd.eth1_votes.push(Eth1Data {
            deposit_root: b256(v, 0),
            deposit_count: u64_le(v, 32),
            block_hash: b256(v, 40),
        });
    }

    // Historical roots → EpochData (compute hash, list is frozen)
    let hr_bytes = &ssz[off_historical_roots..off_eth1_votes];
    if !hr_bytes.len().is_multiple_of(32) {
        return None;
    }
    let hr_count = hr_bytes.len() / 32;
    if hr_count > HISTORICAL_ROOTS_LIMIT {
        return None;
    }
    // Safe: B256 has alignment 1; hr_bytes length is a multiple of 32.
    let hr_chunks: &[B256] =
        unsafe { std::slice::from_raw_parts(hr_bytes.as_ptr().cast::<B256>(), hr_count) };
    let hr_root = ssz_hash::merkleize_padded(hr_chunks, HISTORICAL_ROOTS_LIMIT, zh);
    imm.historical_roots_hash = ssz_hash::mix_in_length(&hr_root, hr_count);

    // Historical summaries → HistoricalLongtail
    let hs_bytes = &ssz[off_hist_summaries..off_pending_deposits];
    if !hs_bytes.len().is_multiple_of(HISTORICAL_SUMMARY_SSZ_SIZE) {
        return None;
    }
    let hs_count = hs_bytes.len() / HISTORICAL_SUMMARY_SSZ_SIZE;
    if hs_count > HISTORICAL_SUMMARIES_CAP {
        return None;
    }
    for i in 0..hs_count {
        let s = &hs_bytes[i * HISTORICAL_SUMMARY_SSZ_SIZE..];
        longtail.historical_summaries.push(HistoricalSummary {
            block_summary_root: b256(s, 0),
            state_summary_root: b256(s, 32),
        });
    }

    // Pending deposits → SlotData
    let pd_bytes = &ssz[off_pending_deposits..off_pending_withdrawals];
    if !pd_bytes.len().is_multiple_of(PENDING_DEPOSIT_SSZ_SIZE) {
        return None;
    }
    let pd_count = pd_bytes.len() / PENDING_DEPOSIT_SSZ_SIZE;
    if pd_count > PENDING_DEPOSITS_LIMIT {
        return None;
    }
    for i in 0..pd_count {
        let d = &pd_bytes[i * PENDING_DEPOSIT_SSZ_SIZE..];
        let mut pubkey = [0u8; 48];
        pubkey.copy_from_slice(&d[..48]);
        let mut signature = [0u8; 96];
        signature.copy_from_slice(&d[88..184]);
        pq.pending_deposits.push(PendingDeposit {
            pubkey,
            withdrawal_credentials: b256(d, 48),
            amount: u64_le(d, 80),
            signature,
            slot: u64_le(d, 184),
        });
    }

    // Pending partial withdrawals → SlotData
    let pw_bytes = &ssz[off_pending_withdrawals..off_pending_consolidations];
    if !pw_bytes.len().is_multiple_of(PENDING_PARTIAL_WITHDRAWAL_SSZ_SIZE) {
        return None;
    }
    let pw_count = pw_bytes.len() / PENDING_PARTIAL_WITHDRAWAL_SSZ_SIZE;
    if pw_count > PENDING_PARTIAL_WITHDRAWALS_LIMIT {
        return None;
    }
    for i in 0..pw_count {
        let w = &pw_bytes[i * PENDING_PARTIAL_WITHDRAWAL_SSZ_SIZE..];
        pq.pending_partial_withdrawals.push(PendingPartialWithdrawal {
            index: u64_le(w, 0),
            amount: u64_le(w, 8),
            withdrawable_epoch: u64_le(w, 16),
        });
    }

    // Pending consolidations → SlotData
    let pc_bytes = &ssz[off_pending_consolidations..];
    if !pc_bytes.len().is_multiple_of(PENDING_CONSOLIDATION_SSZ_SIZE) {
        return None;
    }
    let pc_count = pc_bytes.len() / PENDING_CONSOLIDATION_SSZ_SIZE;
    if pc_count > PENDING_CONSOLIDATIONS_LIMIT {
        return None;
    }
    for i in 0..pc_count {
        let c = &pc_bytes[i * PENDING_CONSOLIDATION_SSZ_SIZE..];
        pq.pending_consolidations
            .push(PendingConsolidation { source_index: u64_le(c, 0), target_index: u64_le(c, 8) });
    }

    epoch_transition::rebuild_sync_committee_indices(vid, longtail);

    Some(pq)
}

fn read_checkpoint(s: &[u8], off: usize) -> Checkpoint {
    Checkpoint { epoch: u64_le(s, off), root: b256(s, off + 8) }
}

fn read_sync_committee(s: &[u8], off: usize, sc: &mut SyncCommittee) -> Option<()> {
    const SC_SIZE: usize = SYNC_COMMITTEE_SIZE * 48 + 48;
    let bytes = s.get(off..off.checked_add(SC_SIZE)?)?;
    for i in 0..SYNC_COMMITTEE_SIZE {
        sc.pubkeys[i].copy_from_slice(&bytes[i * 48..(i + 1) * 48]);
    }
    sc.aggregate_pubkey
        .copy_from_slice(&bytes[SYNC_COMMITTEE_SIZE * 48..SYNC_COMMITTEE_SIZE * 48 + 48]);
    Some(())
}

fn read_execution_payload_header(
    ssz: &[u8],
    start: usize,
    end: usize,
    out: &mut ExecutionPayloadHeader,
) -> Option<()> {
    let eph = &ssz[start..end];
    if eph.len() < EPH_FIXED_PART {
        return None;
    }

    out.parent_hash = b256(eph, 0);
    out.fee_recipient.copy_from_slice(&eph[32..52]);
    out.state_root = b256(eph, 52);
    out.receipts_root = b256(eph, 84);
    out.logs_bloom.copy_from_slice(&eph[116..372]);
    out.prev_randao = b256(eph, 372);
    out.block_number = u64_le(eph, 404);
    out.gas_limit = u64_le(eph, 412);
    out.gas_used = u64_le(eph, 420);
    out.timestamp = u64_le(eph, 428);
    // extra_data offset at [436..440]
    out.base_fee_per_gas = b256(eph, 440);
    out.block_hash = b256(eph, 472);
    out.transactions_root = b256(eph, 504);
    out.withdrawals_root = b256(eph, 536);
    out.blob_gas_used = u64_le(eph, 568);
    out.excess_blob_gas = u64_le(eph, 576);

    // extra_data: variable part
    let extra_off = u32_le(eph, 436) as usize;
    if extra_off < EPH_FIXED_PART || extra_off > eph.len() {
        return None;
    }
    let extra_len = eph.len() - extra_off;
    if extra_len > 32 {
        return None;
    }
    out.extra_data_len = extra_len as u8;
    out.extra_data[..extra_len].copy_from_slice(&eph[extra_off..]);

    Some(())
}
