use core::cmp::{max, min};

use crate::{
    bls, epoch_transition,
    shuffling::{self, DOMAIN_BEACON_ATTESTER},
    ssz_hash::{self, hash_tree_root_block_header, hash_tree_root_state},
    types::{
        self, B256, BeaconBlockHeader, EPOCHS_PER_SLASHINGS_VECTOR, Epoch, EpochData, Eth1Data,
        ExecutionPayloadHeader, HistoricalLongtail, Immutable, MAX_WITHDRAWALS_PER_PAYLOAD,
        PendingConsolidation, PendingDeposit, PendingPartialWithdrawal, PendingQueues,
        SLOTS_PER_EPOCH, SLOTS_PER_HISTORICAL_ROOT, SYNC_COMMITTEE_SIZE, Slot, SlotData, SlotRoots,
        ValidatorIdentity,
    },
    validate,
};

const WHISTLEBLOWER_REWARD_QUOTIENT: u64 = 4096;
const MIN_SLASHING_PENALTY_QUOTIENT: u64 = 4096;
const FULL_EXIT_REQUEST_AMOUNT: u64 = 0;
const SHARD_COMMITTEE_PERIOD: u64 = 256;
const MIN_ACTIVATION_BALANCE: u64 = 32_000_000_000;
const MAX_SEED_LOOKAHEAD: u64 = 4;
const MIN_VALIDATOR_WITHDRAWABILITY_DELAY: u64 = 256;
const COMPOUNDING_WITHDRAWAL_PREFIX: u8 = 0x02;
const ETH1_ADDRESS_WITHDRAWAL_PREFIX: u8 = 0x01;
const UNSET_DEPOSIT_REQUESTS_START_INDEX: u64 = u64::MAX;
const EFFECTIVE_BALANCE_INCREMENT: u64 = 1_000_000_000;
// BLS G2 point at infinity (compressed): 0xc0 followed by 95 zero bytes.
const G2_POINT_AT_INFINITY: [u8; 96] = {
    let mut buf = [0u8; 96];
    buf[0] = 0xc0;
    buf
};

#[allow(clippy::too_many_arguments)]
pub fn apply_block(
    imm: &Immutable,
    vid: &mut ValidatorIdentity,
    longtail: &mut HistoricalLongtail,
    epoch: &mut EpochData,
    roots: &mut SlotRoots,
    sd: &mut SlotData,
    pq: &mut PendingQueues,
    block_bytes: &[u8],
    block_slot: Slot,
    proposer_index: u64,
    parent_root: B256,
    body_root: B256,
    block_state_root: B256,
    shuffling: Option<&ShufflingRef<'_>>,
    zh: &[B256],
    active_scratch: &mut Vec<u32>,
    postponed_scratch: &mut Vec<types::PendingDeposit>,
) -> bool {
    if block_slot > sd.slot {
        process_slots(
            imm,
            vid,
            longtail,
            epoch,
            roots,
            sd,
            pq,
            block_slot,
            zh,
            active_scratch,
            postponed_scratch,
        );
    }
    if block_slot != sd.slot {
        return false;
    }

    if !bls::verify_block_signature(
        imm,
        vid,
        block_bytes,
        block_slot,
        proposer_index,
        body_root,
        zh,
    ) {
        return false;
    }

    if !process_block_header(vid, epoch, sd, block_slot, proposer_index, parent_root, body_root, zh)
    {
        return false;
    }

    let body = if block_bytes.len() > 184 { &block_bytes[184..] } else { &[] };
    if !process_block_body(
        imm,
        vid,
        longtail,
        epoch,
        roots,
        sd,
        pq,
        body,
        block_slot,
        proposer_index,
        shuffling,
        zh,
    ) {
        return false;
    }

    let actual = hash_tree_root_state(imm, vid, longtail, epoch, roots, sd, pq, zh);
    if actual != block_state_root {
        return false;
    }

    true
}

/// Shuffle active indices for current and previous epoch into the caller's
/// buffers. Returns (cur_cps, prev_cps, current_epoch, prev_epoch).
fn build_shuffling(
    vid: &ValidatorIdentity,
    epoch: &EpochData,
    sd: &SlotData,
    cur: &mut Vec<u32>,
    prev: &mut Vec<u32>,
) -> (usize, usize, Epoch, Epoch) {
    let current_epoch = sd.slot / SLOTS_PER_EPOCH;
    let prev_epoch = current_epoch.saturating_sub(1);
    let cur_seed = shuffling::get_seed(epoch, current_epoch, DOMAIN_BEACON_ATTESTER);
    let prev_seed = shuffling::get_seed(epoch, prev_epoch, DOMAIN_BEACON_ATTESTER);
    shuffling::get_active_validator_indices_into(epoch, vid.validator_cnt, current_epoch, cur);
    shuffling::get_active_validator_indices_into(epoch, vid.validator_cnt, prev_epoch, prev);
    let cur_cps = shuffling::committees_per_slot(cur.len());
    let prev_cps = shuffling::committees_per_slot(prev.len());
    shuffling::shuffle_list(cur, &cur_seed);
    shuffling::shuffle_list(prev, &prev_seed);
    (cur_cps, prev_cps, current_epoch, prev_epoch)
}

/// Test-only full-block apply path. Decomposes the block SSZ, builds a
/// shuffling from scratch, runs state transition, and compares the
/// post-state root against the block's `state_root`. Production path is
/// `apply_block` (called from the tile, which supplies cached shufflings
/// and pooled scratch buffers).
#[allow(clippy::too_many_arguments)]
pub fn apply_signed_block_debug(
    imm: &Immutable,
    vid: &mut ValidatorIdentity,
    longtail: &mut HistoricalLongtail,
    epoch: &mut EpochData,
    roots: &mut SlotRoots,
    sd: &mut SlotData,
    pq: &mut PendingQueues,
    block_bytes: &[u8],
    zh: &[B256],
) -> Result<(), String> {
    if block_bytes.len() < 184 {
        return Err("block too short".into());
    }
    let block_slot = u64::from_le_bytes(block_bytes[100..108].try_into().unwrap());
    let proposer_index = u64::from_le_bytes(block_bytes[108..116].try_into().unwrap());
    let parent_root: B256 = block_bytes[116..148].try_into().unwrap();
    let state_root: B256 = block_bytes[148..180].try_into().unwrap();
    let body = &block_bytes[184..];
    let body_root = ssz_hash::hash_tree_root_body(body, zh);

    let mut active_scratch = Vec::new();
    let mut postponed_scratch = Vec::new();
    if block_slot > sd.slot {
        process_slots(
            imm,
            vid,
            longtail,
            epoch,
            roots,
            sd,
            pq,
            block_slot,
            zh,
            &mut active_scratch,
            &mut postponed_scratch,
        );
    }
    if block_slot != sd.slot {
        return Err(format!("slot mismatch: block={block_slot} state={}", sd.slot));
    }
    if !bls::verify_block_signature(
        imm,
        vid,
        block_bytes,
        block_slot,
        proposer_index,
        body_root,
        zh,
    ) {
        return Err(format!("BLS sig failed: slot={block_slot} proposer={proposer_index}"));
    }
    if !process_block_header(vid, epoch, sd, block_slot, proposer_index, parent_root, body_root, zh)
    {
        return Err("block_header check failed".into());
    }

    let mut curr = Vec::new();
    let mut prev = Vec::new();
    let (cur_cps, prev_cps, ce, pe) = build_shuffling(vid, epoch, sd, &mut curr, &mut prev);
    let sref = ShufflingRef {
        current_epoch: ce,
        current_shuffled: &curr,
        current_cps: cur_cps,
        previous_epoch: pe,
        previous_shuffled: &prev,
        previous_cps: prev_cps,
    };
    if !process_block_body(
        imm,
        vid,
        longtail,
        epoch,
        roots,
        sd,
        pq,
        body,
        block_slot,
        proposer_index,
        Some(&sref),
        zh,
    ) {
        return Err("process_block_body rejected".into());
    }

    let actual = hash_tree_root_state(imm, vid, longtail, epoch, roots, sd, pq, zh);
    if actual != state_root {
        return Err("post-state root mismatch".into());
    }
    Ok(())
}

/// Advance state from `sd.slot` to `target_slot`, processing empty slots.
/// Handles epoch transitions at boundaries (spec: process_epoch runs when
/// `(state.slot + 1) % SLOTS_PER_EPOCH == 0`).
#[allow(clippy::too_many_arguments)]
pub fn process_slots(
    imm: &Immutable,
    vid: &mut ValidatorIdentity,
    longtail: &mut HistoricalLongtail,
    epoch: &mut EpochData,
    roots: &mut SlotRoots,
    sd: &mut SlotData,
    pq: &mut PendingQueues,
    target_slot: Slot,
    zh: &[B256],
    active_scratch: &mut Vec<u32>,
    postponed_scratch: &mut Vec<types::PendingDeposit>,
) {
    while sd.slot < target_slot {
        process_slot(imm, vid, longtail, epoch, roots, sd, pq, zh);
        if (sd.slot + 1).is_multiple_of(SLOTS_PER_EPOCH) {
            epoch_transition::process_epoch(
                vid,
                longtail,
                epoch,
                sd,
                pq,
                roots,
                zh,
                active_scratch,
                postponed_scratch,
            );
        }
        sd.slot += 1;
    }
}

#[allow(clippy::too_many_arguments)]
fn process_slot(
    imm: &Immutable,
    vid: &ValidatorIdentity,
    longtail: &HistoricalLongtail,
    epoch: &EpochData,
    roots: &mut SlotRoots,
    sd: &mut SlotData,
    pq: &PendingQueues,
    zh: &[B256],
) {
    let idx = sd.slot as usize % SLOTS_PER_HISTORICAL_ROOT;

    let prev_state_root = hash_tree_root_state(imm, vid, longtail, epoch, roots, sd, pq, zh);
    roots.state_roots[idx] = prev_state_root;

    if sd.latest_block_header.state_root == [0u8; 32] {
        sd.latest_block_header.state_root = prev_state_root;
    }

    let block_root = hash_tree_root_block_header(&sd.latest_block_header, zh);
    roots.block_roots[idx] = block_root;
}

#[allow(clippy::too_many_arguments)]
pub fn process_block_header(
    vid: &ValidatorIdentity,
    epoch: &EpochData,
    sd: &mut SlotData,
    block_slot: Slot,
    proposer_index: u64,
    parent_root: B256,
    body_root: B256,
    zh: &[B256],
) -> bool {
    if block_slot != sd.slot {
        return false;
    }
    if block_slot <= sd.latest_block_header.slot {
        return false;
    }
    if proposer_index as usize >= vid.validator_cnt {
        return false;
    }
    if epoch.val_slashed(proposer_index as usize) {
        return false;
    }

    let expected_parent = hash_tree_root_block_header(&sd.latest_block_header, zh);
    if parent_root != expected_parent {
        return false;
    }

    sd.latest_block_header = BeaconBlockHeader {
        slot: block_slot,
        proposer_index,
        parent_root,
        state_root: [0u8; 32],
        body_root,
    };

    true
}

/// Shuffled indices for current and previous epoch, needed for attestation
/// processing.
pub struct ShufflingRef<'a> {
    pub current_epoch: Epoch,
    pub current_shuffled: &'a [u32],
    pub current_cps: usize,
    pub previous_epoch: Epoch,
    pub previous_shuffled: &'a [u32],
    pub previous_cps: usize,
}

#[allow(clippy::too_many_arguments)]
pub fn process_block_body(
    imm: &Immutable,
    vid: &mut ValidatorIdentity,
    longtail: &HistoricalLongtail,
    epoch: &mut EpochData,
    roots: &SlotRoots,
    sd: &mut SlotData,
    pq: &mut PendingQueues,
    body: &[u8],
    block_slot: Slot,
    proposer_index: u64,
    shuffling: Option<&ShufflingRef<'_>>,
    zh: &[B256],
) -> bool {
    if body.len() < 396 {
        return false;
    }

    if !validate::validate_operation_counts(body) {
        return false;
    }

    let offset = |pos: usize| -> usize {
        u32::from_le_bytes(body[pos..pos + 4].try_into().unwrap()) as usize
    };

    let exec_off = offset(380);
    let bls_off = offset(384);
    let payload = if exec_off <= bls_off && bls_off <= body.len() {
        &body[exec_off..bls_off]
    } else {
        &[] as &[u8]
    };

    // Spec order: withdrawals, then execution_payload, then randao, then eth1.
    // TODO(EL): before processing, send NewPayloadRequest to execution engine
    // via Engine API (engine_newPayloadV4). This verifies the payload is valid
    // and returns VALID/INVALID/SYNCING. On SYNCING, mark block as optimistic
    // in fork choice. On INVALID, reject the block.
    process_withdrawals(vid, epoch, sd, pq, payload);
    if !process_execution_payload(imm, sd, payload, block_slot, zh) {
        return false;
    }
    process_randao(imm, vid, sd, body, block_slot, proposer_index, zh);
    process_eth1_data(sd, body);

    let proposer_slashings_off = offset(200);
    let attester_slashings_off = offset(204);
    let attestations_off = offset(208);
    let deposits_off = offset(212);

    if proposer_slashings_off <= attester_slashings_off && attester_slashings_off <= body.len() {
        process_proposer_slashings(
            vid,
            epoch,
            sd,
            &body[proposer_slashings_off..attester_slashings_off],
        );
    }
    if attester_slashings_off <= attestations_off && attestations_off <= body.len() {
        process_attester_slashings(vid, epoch, sd, &body[attester_slashings_off..attestations_off]);
    }
    if attestations_off <= deposits_off && deposits_off <= body.len() {
        process_attestations(
            vid,
            epoch,
            roots,
            sd,
            &body[attestations_off..deposits_off],
            block_slot,
            proposer_index,
            shuffling,
        );
    }

    let voluntary_exits_off = offset(216);
    if deposits_off <= voluntary_exits_off && voluntary_exits_off <= body.len() {
        process_deposits(vid, epoch, sd, pq, &body[deposits_off..voluntary_exits_off], zh);
    }

    // voluntary_exits data runs from off(216) to off(380) (next variable field =
    // exec payload).
    if voluntary_exits_off <= exec_off && exec_off <= body.len() {
        process_voluntary_exits(vid, epoch, sd, pq, &body[voluntary_exits_off..exec_off]);
    }

    let bls_changes_off = offset(384);
    let blob_off = offset(388);
    if bls_changes_off <= blob_off && blob_off <= body.len() {
        process_bls_to_execution_changes(vid, sd, &body[bls_changes_off..blob_off]);
    }

    process_sync_aggregate(vid, longtail, epoch, sd, &body[220..380], proposer_index);

    let exec_requests_off = offset(392);
    if exec_requests_off <= body.len() {
        process_execution_requests(vid, epoch, sd, pq, &body[exec_requests_off..]);
    }
    true
}

/// XOR the hash of the randao reveal into the per-block mix accumulator.
/// The accumulated mix lives in SlotData.randao_mix_current (per-fork).
/// At epoch boundary, the tile copies it into the new EpochData.randao_mixes.
fn process_randao(
    imm: &Immutable,
    vid: &ValidatorIdentity,
    sd: &mut SlotData,
    body: &[u8],
    block_slot: Slot,
    proposer_index: u64,
    zh: &[B256],
) {
    let reveal = &body[0..96];

    if !bls::verify_randao_reveal(imm, vid, reveal, block_slot, proposer_index, zh) {
        return; // invalid reveal — don't XOR
    }

    let reveal_hash = ssz_hash::sha256(reveal);
    for (byte, &rh) in sd.randao_mix_current.iter_mut().zip(reveal_hash.iter()) {
        *byte ^= rh;
    }
}

fn process_eth1_data(sd: &mut SlotData, body: &[u8]) {
    // eth1_data at body[96..168]: deposit_root(32) + deposit_count(8) +
    // block_hash(32)
    let deposit_root: B256 = body[96..128].try_into().unwrap();
    let deposit_count = u64::from_le_bytes(body[128..136].try_into().unwrap());
    let block_hash: B256 = body[136..168].try_into().unwrap();

    let vote = Eth1Data { deposit_root, deposit_count, block_hash };
    sd.eth1_votes.push(vote);

    // Check if this vote reaches majority.
    let mut count = 0usize;
    for i in 0..sd.eth1_votes.len() {
        if sd.eth1_votes[i].deposit_root == deposit_root &&
            sd.eth1_votes[i].deposit_count == deposit_count &&
            sd.eth1_votes[i].block_hash == block_hash
        {
            count += 1;
        }
    }
    // Majority = more than half of the voting period slots.
    let slots_per_eth1_voting_period = 64 * SLOTS_PER_EPOCH; // EPOCHS_PER_ETH1_VOTING_PERIOD * SLOTS_PER_EPOCH
    if count * 2 > slots_per_eth1_voting_period as usize {
        sd.eth1_data = vote;
    }
}

#[allow(clippy::too_many_arguments)]
pub fn process_attestations(
    vid: &ValidatorIdentity,
    epoch: &EpochData,
    roots: &SlotRoots,
    sd: &mut SlotData,
    attestation_data: &[u8],
    block_slot: Slot,
    proposer_index: u64,
    shuffling: Option<&ShufflingRef<'_>>,
) {
    // Electra attestations are variable-size (have committee_bits).
    // SSZ list of variable-size elements: first N*4 bytes are offsets.
    if attestation_data.is_empty() {
        return;
    }

    let first_offset =
        u32::from_le_bytes(attestation_data[..4].try_into().unwrap_or([0; 4])) as usize;
    if first_offset == 0 || !first_offset.is_multiple_of(4) || first_offset > attestation_data.len()
    {
        return;
    }
    let count = first_offset / 4;

    let current_epoch = block_slot / SLOTS_PER_EPOCH;
    let previous_epoch = current_epoch.saturating_sub(1);

    // TODO(BLS): for each attestation, FastAggregateVerify the aggregate sig
    // against the participants' pubkeys under DOMAIN_BEACON_ATTESTER. Without
    // this, junk-signature attestations can set participation flags and earn
    // rewards. Single-attestation gossip path (tile.rs handle_attestation) has
    // the same gap.
    for i in 0..count {
        let att_start =
            u32::from_le_bytes(attestation_data[i * 4..(i + 1) * 4].try_into().unwrap()) as usize;
        let att_end = if i + 1 < count {
            u32::from_le_bytes(attestation_data[(i + 1) * 4..(i + 2) * 4].try_into().unwrap())
                as usize
        } else {
            attestation_data.len()
        };
        if att_start >= att_end || att_end > attestation_data.len() {
            continue;
        }
        let att = &attestation_data[att_start..att_end];
        let reward = process_single_attestation(
            vid,
            epoch,
            roots,
            sd,
            att,
            current_epoch,
            previous_epoch,
            shuffling,
        );
        // Proposer reward from newly-set participation flags.
        if reward > 0 && (proposer_index as usize) < vid.validator_cnt {
            const PROPOSER_WEIGHT: u64 = 8;
            const WEIGHT_DENOMINATOR: u64 = 64;
            let proposer_reward_denominator =
                (WEIGHT_DENOMINATOR - PROPOSER_WEIGHT) * WEIGHT_DENOMINATOR / PROPOSER_WEIGHT;
            let proposer_reward = reward / proposer_reward_denominator;
            sd.balances[proposer_index as usize] =
                sd.balances[proposer_index as usize].saturating_add(proposer_reward);
        }
    }
}

/// Process a single Electra attestation.
/// Electra Attestation layout (variable):
///   Fixed part:
///     [0..4)    offset: aggregation_bits
///     [4..132)  AttestationData (128B)
///       [4..12)    slot
///       [12..20)   index (always 0 post-Electra)
///       [20..52)   beacon_block_root
///       [52..60)   source.epoch
///       [60..92)   source.root
///       [92..100)  target.epoch
///       [100..132) target.root
///     [132..228)  signature (96B)
///     [228..236)  committee_bits (8B for Electra)
///     [236..)     aggregation_bits (variable)
/// Returns proposer_reward_numerator (sum of base_reward * weight for newly set
/// flags).
#[allow(clippy::too_many_arguments)]
pub fn process_single_attestation(
    vid: &ValidatorIdentity,
    epoch: &EpochData,
    roots: &SlotRoots,
    sd: &mut SlotData,
    att: &[u8],
    current_epoch: Epoch,
    previous_epoch: Epoch,
    shuffling: Option<&ShufflingRef<'_>>,
) -> u64 {
    if !validate::validate_attestation_data(att, sd.slot, current_epoch, previous_epoch) {
        return 0;
    }

    let att_slot = u64::from_le_bytes(att[4..12].try_into().unwrap());
    let beacon_block_root: B256 = att[20..52].try_into().unwrap();
    let source_epoch = u64::from_le_bytes(att[52..60].try_into().unwrap());
    let source_root: B256 = att[60..92].try_into().unwrap();
    let target_epoch = u64::from_le_bytes(att[92..100].try_into().unwrap());
    let target_root: B256 = att[100..132].try_into().unwrap();

    let is_current = target_epoch == current_epoch;
    if !is_current && target_epoch != previous_epoch {
        return 0;
    }

    // Verify source matches the justified checkpoint for the attestation's target
    // epoch.
    let justified =
        if is_current { sd.current_justified_checkpoint } else { sd.previous_justified_checkpoint };
    if source_epoch != justified.epoch || source_root != justified.root {
        return 0; // incorrect source
    }

    let expected_target_root = get_block_root_at_epoch(roots, target_epoch);
    let is_matching_target = target_root == expected_target_root;

    let expected_head_root = roots.block_roots[att_slot as usize % SLOTS_PER_HISTORICAL_ROOT];
    let is_matching_head = is_matching_target && beacon_block_root == expected_head_root;

    // Participation flags.
    let inclusion_delay = sd.slot.saturating_sub(att_slot);
    let mut flags = 0u8;
    let mut flag_weights = [false; 3]; // track which flags are newly set

    // TIMELY_SOURCE: inclusion_delay <= integer_sqrt(SLOTS_PER_EPOCH) = 5
    if inclusion_delay <= 5 {
        flags |= 1 << 0;
        flag_weights[0] = true;
    }
    // TIMELY_TARGET (Deneb+): no inclusion delay requirement
    if is_matching_target {
        flags |= 1 << 1;
        flag_weights[1] = true;
    }
    // TIMELY_HEAD: inclusion_delay == 1
    if is_matching_head && inclusion_delay == 1 {
        flags |= 1 << 2;
        flag_weights[2] = true;
    }

    if flags == 0 {
        return 0;
    }

    let shuffling = match shuffling {
        Some(s) => s,
        None => return 0,
    };

    let (shuffled, cps) = if is_current {
        (shuffling.current_shuffled, shuffling.current_cps)
    } else {
        (shuffling.previous_shuffled, shuffling.previous_cps)
    };
    if shuffled.is_empty() || cps == 0 {
        return 0;
    }

    let committee_bits = u64::from_le_bytes(att[228..236].try_into().unwrap());
    let agg_bits = &att[236..];

    // TODO(perf): total_active_balance recomputed once per attestation (up to
    // MAX_ATTESTATIONS_ELECTRA=8 per block) and again in process_sync_aggregate
    // — O(n_validators) loops on the hot path. Cache once per epoch on
    // EpochData and invalidate on stake-changing events.
    // Base reward computation for proposer reward accumulation.
    let total_active = {
        let n = vid.validator_cnt;
        let mut t = 0u64;
        for i in 0..n {
            if epoch.val_activation_epoch[i] <= current_epoch &&
                current_epoch < epoch.val_exit_epoch[i]
            {
                t += epoch.val_effective_balance[i];
            }
        }
        t.max(1_000_000_000)
    };
    let sqrt_total = epoch_transition::integer_sqrt(total_active);
    let base_reward_per_increment = 1_000_000_000u64 * 64 / sqrt_total; // EBI * BASE_REWARD_FACTOR / sqrt

    const PARTICIPATION_WEIGHTS: [u64; 3] = [14, 26, 14]; // source, target, head

    let mut proposer_reward_numerator = 0u64;

    let mut agg_offset = 0usize;
    for ci in 0..cps {
        if committee_bits & (1u64 << ci) == 0 {
            continue;
        }
        let committee = shuffling::get_beacon_committee(shuffled, att_slot, ci, cps);

        for (j, &validator_idx) in committee.iter().enumerate() {
            let bit_pos = agg_offset + j;
            let byte_idx = bit_pos / 8;
            let bit_idx = bit_pos % 8;
            if byte_idx >= agg_bits.len() || agg_bits[byte_idx] & (1 << bit_idx) == 0 {
                continue;
            }

            let vi = validator_idx as usize;
            let participation = if is_current {
                &mut sd.current_epoch_participation[vi]
            } else {
                &mut sd.previous_epoch_participation[vi]
            };

            let base_reward =
                (epoch.val_effective_balance[vi] / 1_000_000_000) * base_reward_per_increment;

            // Set flags and accumulate reward for newly set flags only.
            for (fi, &weight) in PARTICIPATION_WEIGHTS.iter().enumerate() {
                let flag_bit = 1u8 << fi;
                if flag_weights[fi] && *participation & flag_bit == 0 {
                    *participation |= flag_bit;
                    proposer_reward_numerator += base_reward * weight;
                }
            }
        }
        agg_offset += committee.len();
    }

    proposer_reward_numerator
}

fn get_block_root_at_epoch(roots: &SlotRoots, epoch: Epoch) -> B256 {
    let slot = epoch * SLOTS_PER_EPOCH;
    roots.block_roots[slot as usize % SLOTS_PER_HISTORICAL_ROOT]
}

/// Cache the execution payload header into the beacon state.
pub fn process_execution_payload(
    imm: &Immutable,
    sd: &mut SlotData,
    payload_bytes: &[u8],
    block_slot: Slot,
    zh: &[B256],
) -> bool {
    if payload_bytes.len() < 528 {
        return false;
    }
    if !validate::validate_execution_payload(imm, sd, payload_bytes, block_slot) {
        return false;
    }

    let b256 = |off: usize| -> B256 { payload_bytes[off..off + 32].try_into().unwrap() };
    let u64le =
        |off: usize| -> u64 { u64::from_le_bytes(payload_bytes[off..off + 8].try_into().unwrap()) };
    let off32 = |pos: usize| -> usize {
        u32::from_le_bytes(payload_bytes[pos..pos + 4].try_into().unwrap()) as usize
    };

    let extra_data_off = off32(436);
    let transactions_off = off32(504);

    let extra_data_len = if extra_data_off < transactions_off {
        (transactions_off - extra_data_off).min(32)
    } else {
        0
    };

    let mut extra_data = [0u8; 32];
    if extra_data_len > 0 && extra_data_off + extra_data_len <= payload_bytes.len() {
        extra_data[..extra_data_len]
            .copy_from_slice(&payload_bytes[extra_data_off..extra_data_off + extra_data_len]);
    }

    // Store the execution payload header.
    // transactions_root and withdrawals_root are computed hashes, not stored
    // directly. For a passive follower, we store the header fields for state
    // hashing.
    sd.latest_execution_payload_header = ExecutionPayloadHeader {
        parent_hash: b256(0),
        fee_recipient: payload_bytes[32..52].try_into().unwrap(),
        state_root: b256(52),
        receipts_root: b256(84),
        logs_bloom: payload_bytes[116..372].try_into().unwrap(),
        prev_randao: b256(372),
        block_number: u64le(404),
        gas_limit: u64le(412),
        gas_used: u64le(420),
        timestamp: u64le(428),
        extra_data_len: extra_data_len as u8,
        extra_data,
        base_fee_per_gas: b256(440),
        block_hash: b256(472),
        transactions_root: ssz_hash::hash_transactions_from_payload(payload_bytes, zh),
        withdrawals_root: ssz_hash::hash_withdrawals_from_payload(payload_bytes, zh),
        blob_gas_used: u64le(512),
        excess_blob_gas: u64le(520),
    };

    true
}

/// Process withdrawals from the execution payload.
/// Withdrawal SSZ: index(8) + validator_index(8) + address(20) + amount(8) = 44
/// bytes.
pub fn process_withdrawals(
    vid: &ValidatorIdentity,
    epoch: &EpochData,
    sd: &mut SlotData,
    pq: &mut PendingQueues,
    payload_bytes: &[u8],
) {
    if payload_bytes.len() < 528 {
        return;
    }
    let off32 = |pos: usize| -> usize {
        u32::from_le_bytes(payload_bytes[pos..pos + 4].try_into().unwrap()) as usize
    };
    let withdrawals_off = off32(508);
    if withdrawals_off > payload_bytes.len() {
        return;
    }
    let withdrawals_data = &payload_bytes[withdrawals_off..];

    const WITHDRAWAL_SIZE: usize = 44;
    const MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP: u64 = 16384;
    let count = withdrawals_data.len() / WITHDRAWAL_SIZE;
    let n_validators = vid.validator_cnt as u64;

    let current_epoch = sd.slot / SLOTS_PER_EPOCH;
    const MAX_PENDING_PARTIALS_PER_SWEEP: usize = 8;

    // Replay get_pending_partial_withdrawals to find processed_count.
    // Iterates pending queue, checking eligibility. All iterated entries
    // count as processed (whether eligible or not). Stops at
    // !is_withdrawable or withdrawal limit reached.
    //
    // Without subtracting prior selected, two partials against the same
    // validator can both pass eligibility when only the first should — the
    // queue then drains the wrong number of entries vs the proposer's
    // selection and the state root diverges.
    let withdrawals_limit = min(MAX_PENDING_PARTIALS_PER_SWEEP, MAX_WITHDRAWALS_PER_PAYLOAD - 1);
    let mut processed_partial_count: usize = 0;
    let mut partials_emitted: usize = 0;
    let mut selected: [(u64, u64); MAX_PENDING_PARTIALS_PER_SWEEP] =
        [(0, 0); MAX_PENDING_PARTIALS_PER_SWEEP];
    for qi in 0..pq.pending_partial_withdrawals.len() {
        let pw = &pq.pending_partial_withdrawals[qi];
        if pw.withdrawable_epoch > current_epoch || partials_emitted >= withdrawals_limit {
            break;
        }
        let vi = pw.index as usize;
        if vi < vid.validator_cnt {
            let mut total_withdrawn = 0u64;
            for &(svi, samt) in &selected[..partials_emitted] {
                if svi == pw.index {
                    total_withdrawn = total_withdrawn.saturating_add(samt);
                }
            }
            let balance = sd.balances[vi].saturating_sub(total_withdrawn);
            let eligible = epoch.val_exit_epoch[vi] == u64::MAX &&
                epoch.val_effective_balance[vi] >= MIN_ACTIVATION_BALANCE &&
                balance > MIN_ACTIVATION_BALANCE;
            if eligible {
                let withdrawable = min(balance - MIN_ACTIVATION_BALANCE, pw.amount);
                selected[partials_emitted] = (pw.index, withdrawable);
                partials_emitted += 1;
            }
        }
        processed_partial_count += 1;
    }

    // apply_withdrawals: decrease balance (payout to execution layer).
    for i in 0..count {
        let w = &withdrawals_data[i * WITHDRAWAL_SIZE..(i + 1) * WITHDRAWAL_SIZE];
        let validator_index = u64::from_le_bytes(w[8..16].try_into().unwrap()) as usize;
        let amount = u64::from_le_bytes(w[36..44].try_into().unwrap());
        if validator_index < vid.validator_cnt {
            sd.balances[validator_index] = sd.balances[validator_index].saturating_sub(amount);
        }
    }

    if count > 0 {
        let last_w = &withdrawals_data[(count - 1) * WITHDRAWAL_SIZE..count * WITHDRAWAL_SIZE];
        let last_index = u64::from_le_bytes(last_w[0..8].try_into().unwrap());
        sd.next_withdrawal_index = last_index + 1;
    }

    if processed_partial_count > 0 {
        pq.pending_partial_withdrawals.drain(..processed_partial_count);
    }

    if n_validators > 0 {
        if count == MAX_WITHDRAWALS_PER_PAYLOAD {
            let last_w = &withdrawals_data[(count - 1) * WITHDRAWAL_SIZE..count * WITHDRAWAL_SIZE];
            let last_vi = u64::from_le_bytes(last_w[8..16].try_into().unwrap());
            sd.next_withdrawal_validator_index = (last_vi + 1) % n_validators;
        } else {
            sd.next_withdrawal_validator_index = (sd.next_withdrawal_validator_index +
                MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP) %
                n_validators;
        }
    }
}

pub fn process_sync_aggregate(
    vid: &ValidatorIdentity,
    longtail: &HistoricalLongtail,
    epoch: &EpochData,
    sd: &mut SlotData,
    sync_agg: &[u8],
    proposer_index: u64,
) {
    if sync_agg.len() < 160 {
        return;
    }
    // TODO(BLS): eth_fast_aggregate_verify over previous-slot block root under
    // DOMAIN_SYNC_COMMITTEE for the participating subset of
    // current_sync_committee. Without this we apply rewards/penalties for a
    // forged sync aggregate. Sig is at sync_agg[64..160].

    let bits = &sync_agg[0..64];

    // Compute total active balance + base reward per increment.
    let total_active = {
        let mut t = 0u64;
        let current_epoch = sd.slot / SLOTS_PER_EPOCH;
        for i in 0..vid.validator_cnt {
            if epoch.val_activation_epoch[i] <= current_epoch &&
                current_epoch < epoch.val_exit_epoch[i]
            {
                t += epoch.val_effective_balance[i];
            }
        }
        t.max(1_000_000_000)
    };
    let sqrt_total = epoch_transition::integer_sqrt(total_active);
    let base_reward_per_increment = 1_000_000_000u64 * 64 / sqrt_total;

    // total_active_increments = total_active_balance / EFFECTIVE_BALANCE_INCREMENT
    let total_active_increments = total_active / 1_000_000_000;

    const SYNC_REWARD_WEIGHT: u64 = 2;
    const WEIGHT_DENOMINATOR: u64 = 64;
    const PROPOSER_WEIGHT: u64 = 8;

    // Uniform reward per participant per slot:
    // total_base_rewards = base_reward_per_increment * total_active_increments
    // max_participant_rewards = total_base_rewards * SYNC_REWARD_WEIGHT /
    // WEIGHT_DENOMINATOR / SLOTS_PER_EPOCH participant_reward =
    // max_participant_rewards / SYNC_COMMITTEE_SIZE
    let total_base_rewards = base_reward_per_increment * total_active_increments;
    let participant_reward = if total_active_increments > 0 {
        total_base_rewards * SYNC_REWARD_WEIGHT /
            WEIGHT_DENOMINATOR /
            SLOTS_PER_EPOCH /
            SYNC_COMMITTEE_SIZE as u64
    } else {
        0
    };
    let proposer_reward_per =
        participant_reward * PROPOSER_WEIGHT / (WEIGHT_DENOMINATOR - PROPOSER_WEIGHT);

    let mut proposer_reward_sum = 0u64;

    for i in 0..SYNC_COMMITTEE_SIZE {
        let vi = longtail.sync_committee_indices[i] as usize;
        if vi >= vid.validator_cnt {
            continue;
        }

        let byte_idx = i / 8;
        let bit_idx = i % 8;
        let participated = bits[byte_idx] & (1 << bit_idx) != 0;

        if participated {
            sd.balances[vi] = sd.balances[vi].saturating_add(participant_reward);
            proposer_reward_sum += proposer_reward_per;
        } else {
            sd.balances[vi] = sd.balances[vi].saturating_sub(participant_reward);
        }
    }

    if (proposer_index as usize) < vid.validator_cnt {
        sd.balances[proposer_index as usize] =
            sd.balances[proposer_index as usize].saturating_add(proposer_reward_sum);
    }
}

pub fn process_voluntary_exits(
    vid: &ValidatorIdentity,
    epoch: &mut EpochData,
    sd: &mut SlotData,
    pq: &PendingQueues,
    data: &[u8],
) {
    // TODO(BLS): SignedVoluntaryExit signature missing — see validate.rs.
    const EXIT_SIZE: usize = 112;
    let count = data.len() / EXIT_SIZE;
    let current_epoch = sd.slot / SLOTS_PER_EPOCH;

    for i in 0..count {
        let exit = &data[i * EXIT_SIZE..(i + 1) * EXIT_SIZE];
        let exit_epoch_msg = u64::from_le_bytes(exit[0..8].try_into().unwrap());
        let vi = u64::from_le_bytes(exit[8..16].try_into().unwrap()) as usize;

        if !validate::validate_voluntary_exit(vid, epoch, vi, exit_epoch_msg, current_epoch) {
            continue;
        }
        if get_pending_balance_to_withdraw(pq, vi) != 0 {
            continue;
        }
        initiate_validator_exit(epoch, sd, vid.validator_cnt, vi, current_epoch);
    }
}

fn process_execution_requests(
    vid: &mut ValidatorIdentity,
    epoch: &mut EpochData,
    sd: &mut SlotData,
    pq: &mut PendingQueues,
    data: &[u8],
) {
    if data.len() < 12 {
        return;
    }
    let off = |pos: usize| -> usize {
        u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize
    };
    let offsets = [off(0), off(4), off(8)];
    let field = |idx: usize| -> &[u8] {
        let start = offsets[idx];
        let end = if idx + 1 < offsets.len() { offsets[idx + 1] } else { data.len() };
        if start <= end && end <= data.len() { &data[start..end] } else { &[] }
    };
    process_deposit_requests(sd, pq, field(0));
    process_withdrawal_requests(vid, epoch, sd, pq, field(1));
    process_consolidation_requests(vid, epoch, sd, pq, field(2));
}

pub fn process_deposit_requests(sd: &mut SlotData, pq: &mut PendingQueues, data: &[u8]) {
    const DEPOSIT_SIZE: usize = 192;
    let count = data.len() / DEPOSIT_SIZE;

    for i in 0..count {
        let d = &data[i * DEPOSIT_SIZE..(i + 1) * DEPOSIT_SIZE];
        let pubkey: [u8; 48] = d[0..48].try_into().unwrap();
        let credentials: B256 = d[48..80].try_into().unwrap();
        let amount = u64::from_le_bytes(d[80..88].try_into().unwrap());
        let signature: [u8; 96] = d[88..184].try_into().unwrap();
        let index = u64::from_le_bytes(d[184..192].try_into().unwrap());

        if sd.deposit_requests_start_index == UNSET_DEPOSIT_REQUESTS_START_INDEX {
            sd.deposit_requests_start_index = index;
        }

        pq.pending_deposits.push(PendingDeposit {
            pubkey,
            withdrawal_credentials: credentials,
            amount,
            signature,
            slot: sd.slot,
        });
    }
}

pub fn process_withdrawal_requests(
    vid: &ValidatorIdentity,
    epoch: &mut EpochData,
    sd: &mut SlotData,
    pq: &mut PendingQueues,
    data: &[u8],
) {
    const REQUEST_SIZE: usize = 76;
    let count = data.len() / REQUEST_SIZE;
    let current_epoch = sd.slot / SLOTS_PER_EPOCH;
    let n = vid.validator_cnt;

    for i in 0..count {
        let r = &data[i * REQUEST_SIZE..(i + 1) * REQUEST_SIZE];
        let source_address: &[u8; 20] = r[0..20].try_into().unwrap();
        let validator_pubkey: &[u8; 48] = r[20..68].try_into().unwrap();
        let amount = u64::from_le_bytes(r[68..76].try_into().unwrap());
        let is_full_exit = amount == FULL_EXIT_REQUEST_AMOUNT;

        if pq.pending_partial_withdrawals.len() >= types::PENDING_PARTIAL_WITHDRAWALS_LIMIT &&
            !is_full_exit
        {
            return;
        }

        let vi = match find_validator_by_pubkey(vid, validator_pubkey) {
            Some(idx) => idx,
            None => continue,
        };

        if !has_execution_withdrawal_credential(vid, vi) {
            continue;
        }
        if vid.val_withdrawal_credentials[vi][12..32] != *source_address {
            continue;
        }
        if !is_active(epoch, vi, current_epoch) {
            continue;
        }
        if epoch.val_exit_epoch[vi] != u64::MAX {
            continue;
        }
        if current_epoch < epoch.val_activation_epoch[vi] + SHARD_COMMITTEE_PERIOD {
            continue;
        }

        let pending_balance = get_pending_balance_to_withdraw(pq, vi);

        if is_full_exit {
            if pending_balance == 0 {
                initiate_validator_exit(epoch, sd, n, vi, current_epoch);
            }
            continue;
        }

        let has_sufficient_eff = epoch.val_effective_balance[vi] >= MIN_ACTIVATION_BALANCE;
        let has_excess = sd.balances[vi] > MIN_ACTIVATION_BALANCE + pending_balance;

        if has_compounding_credential(vid, vi) && has_sufficient_eff && has_excess {
            let to_withdraw =
                min(sd.balances[vi] - MIN_ACTIVATION_BALANCE - pending_balance, amount);
            let exit_queue_epoch =
                compute_exit_epoch_and_update_churn(epoch, sd, n, to_withdraw, current_epoch);
            let withdrawable_epoch = exit_queue_epoch + MIN_VALIDATOR_WITHDRAWABILITY_DELAY;
            pq.pending_partial_withdrawals.push(PendingPartialWithdrawal {
                index: vi as u64,
                amount: to_withdraw,
                withdrawable_epoch,
            });
        }
    }
}

pub fn process_consolidation_requests(
    vid: &mut ValidatorIdentity,
    epoch: &mut EpochData,
    sd: &mut SlotData,
    pq: &mut PendingQueues,
    data: &[u8],
) {
    const REQUEST_SIZE: usize = 116;
    let count = data.len() / REQUEST_SIZE;
    let current_epoch = sd.slot / SLOTS_PER_EPOCH;
    let n = vid.validator_cnt;

    for i in 0..count {
        let r = &data[i * REQUEST_SIZE..(i + 1) * REQUEST_SIZE];
        let source_address: &[u8; 20] = r[0..20].try_into().unwrap();
        let source_pubkey: &[u8; 48] = r[20..68].try_into().unwrap();
        let target_pubkey: &[u8; 48] = r[68..116].try_into().unwrap();

        if source_pubkey == target_pubkey {
            if let Some(src) = find_validator_by_pubkey(vid, source_pubkey) {
                if vid.val_withdrawal_credentials[src][12..32] == *source_address &&
                    vid.val_withdrawal_credentials[src][0] == ETH1_ADDRESS_WITHDRAWAL_PREFIX &&
                    is_active(epoch, src, current_epoch) &&
                    epoch.val_exit_epoch[src] == u64::MAX
                {
                    switch_to_compounding_validator(vid, sd, pq, src);
                }
            }
            continue;
        }

        // Full consolidation.
        if pq.pending_consolidations.len() >= types::PENDING_CONSOLIDATIONS_LIMIT {
            continue;
        }
        let churn_limit = get_consolidation_churn_limit(epoch, n, current_epoch);
        if churn_limit <= MIN_ACTIVATION_BALANCE {
            continue;
        }

        let source_idx = match find_validator_by_pubkey(vid, source_pubkey) {
            Some(idx) => idx,
            None => continue,
        };
        let target_idx = match find_validator_by_pubkey(vid, target_pubkey) {
            Some(idx) => idx,
            None => continue,
        };

        if !has_execution_withdrawal_credential(vid, source_idx) {
            continue;
        }
        if vid.val_withdrawal_credentials[source_idx][12..32] != *source_address {
            continue;
        }
        if !has_compounding_credential(vid, target_idx) {
            continue;
        }
        if !is_active(epoch, source_idx, current_epoch) ||
            !is_active(epoch, target_idx, current_epoch)
        {
            continue;
        }
        if epoch.val_exit_epoch[source_idx] != u64::MAX ||
            epoch.val_exit_epoch[target_idx] != u64::MAX
        {
            continue;
        }
        if current_epoch < epoch.val_activation_epoch[source_idx] + SHARD_COMMITTEE_PERIOD {
            continue;
        }
        if get_pending_balance_to_withdraw(pq, source_idx) > 0 {
            continue;
        }

        let exit_epoch = compute_consolidation_epoch_and_update_churn(
            epoch,
            sd,
            n,
            epoch.val_effective_balance[source_idx],
            current_epoch,
        );
        epoch.val_exit_epoch[source_idx] = exit_epoch;
        epoch.val_withdrawable_epoch[source_idx] = exit_epoch + MIN_VALIDATOR_WITHDRAWABILITY_DELAY;
        pq.pending_consolidations.push(PendingConsolidation {
            source_index: source_idx as u64,
            target_index: target_idx as u64,
        });
    }
}

pub fn process_proposer_slashings(
    vid: &ValidatorIdentity,
    epoch: &mut EpochData,
    sd: &mut SlotData,
    data: &[u8],
) {
    const SLASHING_SIZE: usize = 416;
    let count = data.len() / SLASHING_SIZE;
    let proposer_index = get_beacon_proposer_index(sd);
    let n = vid.validator_cnt;

    // TODO(BLS): per-header BLS verification missing — see
    // validate::validate_proposer_slashing. An attacker-crafted slashing with
    // junk sigs would silently slash here.
    let current_epoch = sd.slot / SLOTS_PER_EPOCH;
    for i in 0..count {
        let s = &data[i * SLASHING_SIZE..(i + 1) * SLASHING_SIZE];
        if !validate::validate_proposer_slashing(s) {
            continue;
        }
        let vi = u64::from_le_bytes(s[8..16].try_into().unwrap()) as usize;
        if vi >= n || !is_slashable_validator(epoch, vi, current_epoch) {
            continue;
        }
        slash_validator(epoch, sd, n, vi, proposer_index);
    }
}

// TODO(spec): verify the 33-level Merkle branch against
// state.eth1_data.deposit_root before queueing — currently skipped, so a junk
// proof on a body-included Deposit would be accepted. (Lighthouse:
// is_valid_merkle_branch.)
pub fn process_deposits(
    vid: &mut ValidatorIdentity,
    epoch: &mut EpochData,
    sd: &mut SlotData,
    pq: &mut PendingQueues,
    data: &[u8],
    zh: &[B256],
) {
    const DEPOSIT_SIZE: usize = 1240;
    const PROOF_SIZE: usize = 33 * 32;
    let count = data.len() / DEPOSIT_SIZE;

    for i in 0..count {
        let d = &data[i * DEPOSIT_SIZE..(i + 1) * DEPOSIT_SIZE];
        let dd = &d[PROOF_SIZE..]; // DepositData starts after proof.
        let pubkey: &[u8; 48] = dd[0..48].try_into().unwrap();
        let credentials: B256 = dd[48..80].try_into().unwrap();
        let amount = u64::from_le_bytes(dd[80..88].try_into().unwrap());
        let signature: [u8; 96] = dd[88..184].try_into().unwrap();

        apply_deposit(vid, epoch, sd, pq, pubkey, &credentials, amount, &signature, zh);
        sd.eth1_deposit_index += 1;
    }
}

pub fn process_bls_to_execution_changes(
    vid: &mut ValidatorIdentity,
    _sd: &mut SlotData,
    data: &[u8],
) {
    // TODO(BLS): SignedBLSToExecutionChange signature missing — see validate.rs.
    const CHANGE_SIZE: usize = 172;
    let count = data.len() / CHANGE_SIZE;

    for i in 0..count {
        let c = &data[i * CHANGE_SIZE..(i + 1) * CHANGE_SIZE];
        let validator_index = u64::from_le_bytes(c[0..8].try_into().unwrap()) as usize;
        let from_bls_pubkey: &[u8; 48] = c[8..56].try_into().unwrap();
        let to_execution_address: &[u8; 20] = c[56..76].try_into().unwrap();

        if !validate::validate_bls_to_execution_change(vid, validator_index, from_bls_pubkey) {
            continue;
        }

        let cred = &mut vid.val_withdrawal_credentials[validator_index];
        cred[0] = ETH1_ADDRESS_WITHDRAWAL_PREFIX;
        cred[1..12].fill(0);
        cred[12..32].copy_from_slice(to_execution_address);
    }
}

// TODO(BLS): each IndexedAttestation needs a FastAggregateVerify under
// DOMAIN_BEACON_ATTESTER for its target epoch (sig at offset 132..228).
pub fn process_attester_slashings(
    vid: &ValidatorIdentity,
    epoch: &mut EpochData,
    sd: &mut SlotData,
    data: &[u8],
) {
    if data.is_empty() {
        return;
    }
    let first_offset = u32::from_le_bytes(data[..4].try_into().unwrap_or([0; 4])) as usize;
    if first_offset == 0 || !first_offset.is_multiple_of(4) || first_offset > data.len() {
        return;
    }
    let count = first_offset / 4;
    let proposer_index = get_beacon_proposer_index(sd);
    let n = vid.validator_cnt;

    for i in 0..count {
        let start = u32::from_le_bytes(data[i * 4..(i + 1) * 4].try_into().unwrap()) as usize;
        let end = if i + 1 < count {
            u32::from_le_bytes(data[(i + 1) * 4..(i + 2) * 4].try_into().unwrap()) as usize
        } else {
            data.len()
        };
        if start >= end || end > data.len() {
            continue;
        }
        process_single_attester_slashing(n, epoch, sd, &data[start..end], proposer_index);
    }
}

pub fn process_single_attester_slashing(
    n: usize,
    epoch: &mut EpochData,
    sd: &mut SlotData,
    slashing: &[u8],
    proposer_index: usize,
) {
    if slashing.len() < 8 {
        return;
    }
    let off1 = u32::from_le_bytes(slashing[0..4].try_into().unwrap()) as usize;
    let off2 = u32::from_le_bytes(slashing[4..8].try_into().unwrap()) as usize;

    // Spec is_slashable_attestation_data over the two IndexedAttestations'
    // AttestationData regions. Reject the whole slashing if neither
    // double-vote nor surround-vote.
    if off1 + 132 > slashing.len() || off2 + 132 > slashing.len() || off2 < off1 + 132 {
        return;
    }
    let d1 = &slashing[off1 + 4..off1 + 132];
    let d2 = &slashing[off2 + 4..off2 + 132];
    if !is_slashable_attestation_data(d1, d2) {
        return;
    }

    let i1 = attesting_indices_bytes(slashing, off1, off2);
    let i2 = attesting_indices_bytes(slashing, off2, slashing.len());

    // SSZ List[uint64] invariant: strictly ascending. Reject if violated.
    if !indices_sorted_unique(i1) || !indices_sorted_unique(i2) {
        return;
    }

    let current_epoch = sd.slot / SLOTS_PER_EPOCH;

    // Walk both sorted lists in lockstep for O(n+m) intersection.
    let read = |s: &[u8], i: usize| u64::from_le_bytes(s[i * 8..i * 8 + 8].try_into().unwrap());
    let (n1, n2) = (i1.len() / 8, i2.len() / 8);
    let (mut a, mut b) = (0usize, 0usize);
    while a < n1 && b < n2 {
        let x = read(i1, a);
        let y = read(i2, b);
        match x.cmp(&y) {
            core::cmp::Ordering::Less => a += 1,
            core::cmp::Ordering::Greater => b += 1,
            core::cmp::Ordering::Equal => {
                let vi = x as usize;
                if vi < n && is_slashable_validator(epoch, vi, current_epoch) {
                    slash_validator(epoch, sd, n, vi, proposer_index);
                }
                a += 1;
                b += 1;
            }
        }
    }
}

/// View an IndexedAttestation's attesting_indices SSZ bytes (skips the 228
/// byte fixed part: indices_offset(4) + data(128) + sig(96)).
fn attesting_indices_bytes(data: &[u8], start: usize, end: usize) -> &[u8] {
    if start + 228 > end || end > data.len() {
        return &[];
    }
    let slice = &data[start + 228..end];
    let whole = slice.len() - slice.len() % 8;
    &slice[..whole]
}

fn slash_validator(
    epoch: &mut EpochData,
    sd: &mut SlotData,
    n: usize,
    vi: usize,
    proposer_index: usize,
) {
    let current_epoch = sd.slot / SLOTS_PER_EPOCH;

    initiate_validator_exit(epoch, sd, n, vi, current_epoch);
    epoch.set_val_slashed(vi, true);
    epoch.val_withdrawable_epoch[vi] =
        max(epoch.val_withdrawable_epoch[vi], current_epoch + EPOCHS_PER_SLASHINGS_VECTOR as u64);
    epoch.slashings[current_epoch as usize % EPOCHS_PER_SLASHINGS_VECTOR] +=
        epoch.val_effective_balance[vi];

    let penalty = epoch.val_effective_balance[vi] / MIN_SLASHING_PENALTY_QUOTIENT;
    sd.balances[vi] = sd.balances[vi].saturating_sub(penalty);

    // Spec: increase_balance(proposer, proposer_reward); increase_balance(
    // whistleblower, whistleblower_reward - proposer_reward). With no
    // explicit whistleblower (block-included slashings), whistleblower_index
    // defaults to proposer_index, so the proposer receives the full
    // whistleblower_reward.
    let whistleblower_reward = epoch.val_effective_balance[vi] / WHISTLEBLOWER_REWARD_QUOTIENT;
    sd.balances[proposer_index] = sd.balances[proposer_index].saturating_add(whistleblower_reward);
}

fn initiate_validator_exit(
    epoch: &mut EpochData,
    sd: &mut SlotData,
    n: usize,
    vi: usize,
    current_epoch: Epoch,
) {
    if epoch.val_exit_epoch[vi] != u64::MAX {
        return;
    }
    let exit_epoch = compute_exit_epoch_and_update_churn(
        epoch,
        sd,
        n,
        epoch.val_effective_balance[vi],
        current_epoch,
    );
    epoch.val_exit_epoch[vi] = exit_epoch;
    epoch.val_withdrawable_epoch[vi] = exit_epoch + MIN_VALIDATOR_WITHDRAWABILITY_DELAY;
}

fn compute_exit_epoch_and_update_churn(
    epoch: &EpochData,
    sd: &mut SlotData,
    n: usize,
    exit_balance: u64,
    current_epoch: Epoch,
) -> Epoch {
    let activation_exit_epoch = current_epoch + 1 + MAX_SEED_LOOKAHEAD;
    let mut earliest = max(sd.earliest_exit_epoch, activation_exit_epoch);
    let per_epoch_churn = get_activation_exit_churn_limit(epoch, n, current_epoch);

    let mut balance_to_consume = if sd.earliest_exit_epoch < earliest {
        per_epoch_churn
    } else {
        sd.exit_balance_to_consume
    };

    if exit_balance > balance_to_consume {
        let to_process = exit_balance - balance_to_consume;
        let additional = (to_process - 1) / per_epoch_churn + 1;
        earliest += additional;
        balance_to_consume += additional * per_epoch_churn;
    }

    sd.exit_balance_to_consume = balance_to_consume - exit_balance;
    sd.earliest_exit_epoch = earliest;
    earliest
}

fn compute_consolidation_epoch_and_update_churn(
    epoch: &EpochData,
    sd: &mut SlotData,
    n: usize,
    consolidation_balance: u64,
    current_epoch: Epoch,
) -> Epoch {
    let activation_exit_epoch = current_epoch + 1 + MAX_SEED_LOOKAHEAD;
    let mut earliest = max(sd.earliest_consolidation_epoch, activation_exit_epoch);
    let per_epoch_churn = get_consolidation_churn_limit(epoch, n, current_epoch);

    let mut balance_to_consume = if sd.earliest_consolidation_epoch < earliest {
        per_epoch_churn
    } else {
        sd.consolidation_balance_to_consume
    };

    if consolidation_balance > balance_to_consume {
        let to_process = consolidation_balance - balance_to_consume;
        let additional = (to_process - 1) / per_epoch_churn + 1;
        earliest += additional;
        balance_to_consume += additional * per_epoch_churn;
    }

    sd.consolidation_balance_to_consume = balance_to_consume - consolidation_balance;
    sd.earliest_consolidation_epoch = earliest;
    earliest
}

fn get_balance_churn_limit(epoch: &EpochData, n: usize, current_epoch: Epoch) -> u64 {
    let total = total_active_balance(epoch, n, current_epoch);
    let churn = max(128_000_000_000u64, total / (1u64 << 16));
    churn - churn % EFFECTIVE_BALANCE_INCREMENT
}

fn get_activation_exit_churn_limit(epoch: &EpochData, n: usize, current_epoch: Epoch) -> u64 {
    min(256_000_000_000u64, get_balance_churn_limit(epoch, n, current_epoch))
}

fn get_consolidation_churn_limit(epoch: &EpochData, n: usize, current_epoch: Epoch) -> u64 {
    get_balance_churn_limit(epoch, n, current_epoch) -
        get_activation_exit_churn_limit(epoch, n, current_epoch)
}

fn total_active_balance(epoch: &EpochData, n: usize, current_epoch: Epoch) -> u64 {
    let mut total: u64 = 0;
    for i in 0..n {
        if is_active(epoch, i, current_epoch) {
            total += epoch.val_effective_balance[i];
        }
    }
    total.max(EFFECTIVE_BALANCE_INCREMENT)
}

fn get_pending_balance_to_withdraw(pq: &PendingQueues, vi: usize) -> u64 {
    let mut total = 0u64;
    for pw in &pq.pending_partial_withdrawals {
        if pw.index == vi as u64 {
            total += pw.amount;
        }
    }
    total
}

fn is_active(epoch: &EpochData, vi: usize, e: Epoch) -> bool {
    epoch.val_activation_epoch[vi] <= e && e < epoch.val_exit_epoch[vi]
}

/// Spec: not slashed AND activation_epoch <= epoch < withdrawable_epoch.
fn is_slashable_validator(epoch: &EpochData, vi: usize, e: Epoch) -> bool {
    !epoch.val_slashed(vi) &&
        epoch.val_activation_epoch[vi] <= e &&
        e < epoch.val_withdrawable_epoch[vi]
}

/// Spec: double-vote OR surround-vote. `data` slices are the 128-byte
/// AttestationData regions of two IndexedAttestations.
fn is_slashable_attestation_data(d1: &[u8], d2: &[u8]) -> bool {
    if d1.len() < 128 || d2.len() < 128 {
        return false;
    }
    let s1 = u64::from_le_bytes(d1[48..56].try_into().unwrap());
    let t1 = u64::from_le_bytes(d1[88..96].try_into().unwrap());
    let s2 = u64::from_le_bytes(d2[48..56].try_into().unwrap());
    let t2 = u64::from_le_bytes(d2[88..96].try_into().unwrap());

    // Double vote: distinct data, same target epoch.
    if d1 != d2 && t1 == t2 {
        return true;
    }
    // Surround vote: data_1 surrounds data_2.
    s1 < s2 && t2 < t1
}

/// Spec: SSZ List[uint64] invariant — strictly ascending.
fn indices_sorted_unique(indices: &[u8]) -> bool {
    let n = indices.len() / 8;
    if n < 2 {
        return true;
    }
    let read = |i: usize| u64::from_le_bytes(indices[i * 8..i * 8 + 8].try_into().unwrap());
    let mut prev = read(0);
    for i in 1..n {
        let cur = read(i);
        if cur <= prev {
            return false;
        }
        prev = cur;
    }
    true
}

fn has_execution_withdrawal_credential(vid: &ValidatorIdentity, vi: usize) -> bool {
    let prefix = vid.val_withdrawal_credentials[vi][0];
    prefix == ETH1_ADDRESS_WITHDRAWAL_PREFIX || prefix == COMPOUNDING_WITHDRAWAL_PREFIX
}

fn has_compounding_credential(vid: &ValidatorIdentity, vi: usize) -> bool {
    vid.val_withdrawal_credentials[vi][0] == COMPOUNDING_WITHDRAWAL_PREFIX
}

fn get_beacon_proposer_index(sd: &SlotData) -> usize {
    sd.proposer_lookahead[(sd.slot % SLOTS_PER_EPOCH) as usize] as usize
}

fn switch_to_compounding_validator(
    vid: &mut ValidatorIdentity,
    sd: &mut SlotData,
    pq: &mut PendingQueues,
    vi: usize,
) {
    vid.val_withdrawal_credentials[vi][0] = COMPOUNDING_WITHDRAWAL_PREFIX;
    // Queue excess balance above MIN_ACTIVATION_BALANCE.
    let balance = sd.balances[vi];
    if balance > MIN_ACTIVATION_BALANCE {
        let excess = balance - MIN_ACTIVATION_BALANCE;
        sd.balances[vi] = MIN_ACTIVATION_BALANCE;
        pq.pending_deposits.push(PendingDeposit {
            pubkey: vid.val_pubkey[vi],
            withdrawal_credentials: vid.val_withdrawal_credentials[vi],
            amount: excess,
            signature: G2_POINT_AT_INFINITY,
            slot: 0, // GENESIS_SLOT
        });
    }
}

/// Electra apply_deposit: for new validators, BLS-verify then add to registry
/// with 0 balance; always queue a PendingDeposit for the amount.
#[allow(clippy::too_many_arguments)]
fn apply_deposit(
    vid: &mut ValidatorIdentity,
    epoch: &mut EpochData,
    sd: &mut SlotData,
    pq: &mut PendingQueues,
    pubkey: &[u8; 48],
    credentials: &B256,
    amount: u64,
    signature: &[u8; 96],
    zh: &[B256],
) {
    let existing = find_validator_by_pubkey(vid, pubkey);
    if existing.is_none() {
        if !epoch_transition::is_valid_deposit_signature(pubkey, credentials, amount, signature, zh)
        {
            return;
        }
        // Add to registry with 0 effective balance and 0 actual balance.
        let idx = vid.validator_cnt;
        vid.val_pubkey[idx] = *pubkey;
        vid.val_withdrawal_credentials[idx] = *credentials;
        epoch.val_effective_balance[idx] = 0;
        epoch.set_val_slashed(idx, false);
        epoch.val_activation_eligibility_epoch[idx] = u64::MAX;
        epoch.val_activation_epoch[idx] = u64::MAX;
        epoch.val_exit_epoch[idx] = u64::MAX;
        epoch.val_withdrawable_epoch[idx] = u64::MAX;
        epoch.inactivity_scores[idx] = 0;
        sd.balances[idx] = 0;
        sd.previous_epoch_participation[idx] = 0;
        sd.current_epoch_participation[idx] = 0;
        vid.validator_cnt = idx + 1;
    }

    pq.pending_deposits.push(PendingDeposit {
        pubkey: *pubkey,
        withdrawal_credentials: *credentials,
        amount,
        signature: *signature,
        slot: 0, // GENESIS_SLOT — Eth1 bridge deposit.
    });
}

// TODO(perf): O(n_validators) scan per call. Hit on every deposit-request,
// withdrawal-request, consolidation-request, and apply_deposit, plus
// rebuild_sync_committee_indices (512 × n). At 2M validators sync rotation is
// ~1B comparisons. Replace with a per-VID-tier sorted Vec<(pubkey_hash, idx)>
// or HashMap that COWs with the VID tier. (~24 MB sorted vs ~120 MB HashMap.)
fn find_validator_by_pubkey(vid: &ValidatorIdentity, pubkey: &[u8; 48]) -> Option<usize> {
    vid.val_pubkey[..vid.validator_cnt].iter().position(|pk| pk == pubkey)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::box_zeroed;

    /// EF `sanity_blocks` doesn't exercise the eth1 majority threshold
    /// directly (its blocks vote at most a couple of times). Cover it here.
    #[test]
    fn eth1_data_vote_majority() {
        let mut sd: Box<SlotData> = box_zeroed();
        sd.slot = 32; // epoch 1

        // Build a body with eth1_data at [96..168).
        let mut body = vec![0u8; 396];
        let deposit_root = [0xAA; 32];
        body[96..128].copy_from_slice(&deposit_root);
        body[128..136].copy_from_slice(&42u64.to_le_bytes()); // deposit_count
        body[136..168].copy_from_slice(&[0xBB; 32]); // block_hash

        // slots_per_eth1_voting_period = 64 * 32 = 2048; need > 1024 votes.
        process_eth1_data(&mut sd, &body);
        assert_eq!(sd.eth1_votes.len(), 1);
        assert_ne!(sd.eth1_data.deposit_root, deposit_root);

        for _ in 0..1024 {
            sd.eth1_votes.push(Eth1Data {
                deposit_root,
                deposit_count: 42,
                block_hash: [0xBB; 32],
            });
        }
        process_eth1_data(&mut sd, &body);
        assert_eq!(sd.eth1_data.deposit_root, deposit_root);
    }
}
