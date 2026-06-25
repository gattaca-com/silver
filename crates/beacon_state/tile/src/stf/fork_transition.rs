use silver_beacon_state_data::{
    Builder, EpochView, EpochWriteView, ExecutionPayloadBid, FAR_FUTURE_EPOCH, MIN_SEED_LOOKAHEAD,
    PendingDeposit, SLOTS_PER_EPOCH, StateWriterView, ValidatorsView,
    gloas::{
        EXECUTION_PAYLOAD_AVAILABILITY_BYTES, PTC_SIZE, PTC_WINDOW_LEN, PtcCommittee,
        zeroed_ptc_window,
    },
    types::B256,
};

use super::epoch::is_valid_deposit_signature;
use crate::{
    bls::{DOMAIN_BEACON_ATTESTER, DOMAIN_PTC_ATTESTER},
    shuffling::{
        MAX_EFFECTIVE_BALANCE, committees_per_slot, get_active_validator_indices_into,
        get_beacon_committee, get_seed_from_state, shuffle_list,
    },
    ssz_hash::{ZERO_HASHES, merkleize, mix_in_length, sha256},
};

/// `uint8(0)` — the only builder version (`PAYLOAD_BUILDER_VERSION`).
const PAYLOAD_BUILDER_VERSION: u8 = 0;
/// `2**16 - 1` — the 16-bit acceptance ceiling in balance-weighted selection.
const MAX_RANDOM_16: u64 = 0xFFFF;

/// Initialise the Gloas-only state on a fork view that has just advanced to the
/// first slot of `GLOAS_FORK_EPOCH`.
pub fn upgrade_to_gloas(view: &mut StateWriterView, epoch: &mut EpochWriteView) {
    // `latest_block_hash` and the placeholder bid derive from the Fulu
    // execution payload header (kept on the slot tier for Fulu hashing).
    let (block_hash, gas_limit) = {
        let eph = &view.slot.state().latest_execution_payload_header;
        (eph.block_hash, eph.gas_limit)
    };
    {
        let s = view.slot.state_mut();
        s.latest_block_hash = block_hash;
        s.execution_payload_availability = [0xFF; EXECUTION_PAYLOAD_AVAILABILITY_BYTES];
        s.latest_execution_payload_bid = ExecutionPayloadBid {
            block_hash,
            gas_limit,
            execution_requests_root: empty_execution_requests_root(),
            ..Default::default()
        };
        // The remaining Gloas slot fields (`next_withdrawal_builder_index`,
        // `builder_pending_payments`, `builder_pending_withdrawals`,
        // `payload_expected_withdrawals`) match the spec's empty/zero init,
        // which is the inherited slot state's default.
    }

    let window = build_ptc_window(view, &epoch.reader());
    epoch.state_mut().ptc_window = window;

    onboard_builders_from_pending_deposits(view);
}

/// `initialize_ptc_window`: the empty previous epoch followed by the PTCs for
/// the current and lookahead epochs.
fn build_ptc_window(
    view: &StateWriterView,
    epoch: &EpochView,
) -> Box<[PtcCommittee; PTC_WINDOW_LEN]> {
    let mut window = zeroed_ptc_window();
    let slot = view.slot.reader();
    let validators = view.validators.reader();
    let current_epoch = slot.state().slot / SLOTS_PER_EPOCH;

    // window[0..SLOTS_PER_EPOCH] is the empty previous epoch (left zero).
    let mut out = SLOTS_PER_EPOCH as usize;
    let mut active = Vec::new();
    for e in 0..=MIN_SEED_LOOKAHEAD {
        let target_epoch = current_epoch + e;
        get_active_validator_indices_into(&validators, target_epoch, &mut active);
        let committee_seed =
            get_seed_from_state(epoch, &slot, target_epoch, DOMAIN_BEACON_ATTESTER);
        shuffle_list(&mut active, &committee_seed);
        let cps = committees_per_slot(active.len());
        let ptc_seed = get_seed_from_state(epoch, &slot, target_epoch, DOMAIN_PTC_ATTESTER);
        for i in 0..SLOTS_PER_EPOCH {
            window[out] = compute_ptc(
                &validators,
                &active,
                cps,
                &ptc_seed,
                target_epoch * SLOTS_PER_EPOCH + i,
            );
            out += 1;
        }
    }
    window
}

/// `compute_ptc`: balance-weighted selection of `PTC_SIZE` indices (with
/// duplicates) over the concatenation of `slot`'s committees.
fn compute_ptc(
    validators: &ValidatorsView,
    shuffled_active: &[u32],
    committees_per_slot: usize,
    epoch_seed: &B256,
    slot: u64,
) -> PtcCommittee {
    let mut committee = [0u64; PTC_SIZE];
    let mut indices = Vec::new();
    for ci in 0..committees_per_slot {
        indices.extend_from_slice(get_beacon_committee(
            shuffled_active,
            slot,
            ci,
            committees_per_slot,
        ));
    }
    if indices.is_empty() {
        return committee;
    }

    let mut seed_input = [0u8; 40];
    seed_input[..32].copy_from_slice(epoch_seed);
    seed_input[32..40].copy_from_slice(&slot.to_le_bytes());
    let seed = sha256(&seed_input);

    balance_weighted_select(validators, &indices, &seed, &mut committee);
    committee
}

/// `compute_balance_weighted_selection` with `shuffle_indices=False` (the PTC
/// case): traverse `indices` in order, accepting each by effective-balance
/// rejection sampling until `out` is full. Mirrors the proposer/sync sampler.
fn balance_weighted_select(
    validators: &ValidatorsView,
    indices: &[u32],
    seed: &B256,
    out: &mut [u64],
) {
    let total = indices.len() as u64;
    let mut i: u64 = 0;
    let mut filled = 0;
    let mut block_no = u64::MAX;
    let mut block_hash = [0u8; 32];
    while filled < out.len() {
        let next = (i % total) as usize;
        let candidate = indices[next] as usize;
        let block = i / 16;
        if block != block_no {
            let mut buf = [0u8; 40];
            buf[..32].copy_from_slice(seed);
            buf[32..40].copy_from_slice(&block.to_le_bytes());
            block_hash = sha256(&buf);
            block_no = block;
        }
        let offset = ((i % 16) * 2) as usize;
        let random = u16::from_le_bytes([block_hash[offset], block_hash[offset + 1]]) as u64;
        if validators.effective_balance(candidate) * MAX_RANDOM_16 >= MAX_EFFECTIVE_BALANCE * random
        {
            out[filled] = indices[next] as u64;
            filled += 1;
        }
        i += 1;
    }
}

/// `onboard_builders_from_pending_deposits`: the one-time deposit path that
/// seeds the builder registry at the fork. Rebuilds `pending_deposits`, keeping
/// validator and non-onboarded deposits; the registry starts empty, so every
/// builder is appended this pass (top-ups hit `add_balance`).
fn onboard_builders_from_pending_deposits(view: &mut StateWriterView) {
    let count = view.pending.deposits.reader().len();
    let snapshot: Vec<PendingDeposit> =
        (0..count).map(|i| *view.pending.deposits.reader().get(i)).collect();
    view.pending.deposits.drain(count);

    for d in snapshot {
        // Deposits for existing validators stay in the queue.
        if view.validators.find_by_pubkey(&d.pubkey).is_some() {
            view.pending.deposits.push(d);
            continue;
        }
        // Top up an already-onboarded builder (recomputed each iteration).
        let existing = view.builders.reader().iter().position(|b| b.pubkey == d.pubkey);
        if let Some(bi) = existing {
            view.builders.add_balance(bi, d.amount);
            continue;
        }
        // New builder candidate: must carry a builder credential, must not be a
        // pending validator, and must have a valid deposit signature.
        if !d.withdrawal_credentials.has_builder_credential() {
            view.pending.deposits.push(d);
            continue;
        }
        if pending_deposit_has_valid_sig(view, &d.pubkey) {
            view.pending.deposits.push(d);
            continue;
        }
        if !is_valid_deposit_signature(&d.pubkey, &d.withdrawal_credentials, d.amount, &d.signature)
        {
            continue;
        }
        view.builders.push(Builder {
            pubkey: d.pubkey,
            version: PAYLOAD_BUILDER_VERSION,
            execution_address: *d.withdrawal_credentials.execution_address(),
            balance: d.amount,
            deposit_epoch: d.slot / SLOTS_PER_EPOCH,
            withdrawable_epoch: FAR_FUTURE_EPOCH,
        });
    }
}

/// `is_pending_validator`: a kept deposit for `pubkey` with a valid signature
/// is already queued.
fn pending_deposit_has_valid_sig(view: &StateWriterView, pubkey: &[u8; 48]) -> bool {
    let q = view.pending.deposits.reader();
    (0..q.len()).any(|i| {
        let pd = q.get(i);
        pd.pubkey == *pubkey &&
            is_valid_deposit_signature(
                &pd.pubkey,
                &pd.withdrawal_credentials,
                pd.amount,
                &pd.signature,
            )
    })
}

/// `hash_tree_root(ExecutionRequests())` — the placeholder bid's
/// `execution_requests_root`. Five empty `List[_, 2^d]` fields (Gloas adds
/// `builder_deposits`, `builder_exits`); an empty list root is
/// `mix_in_length(zeros[d], 0)`.
fn empty_execution_requests_root() -> B256 {
    let empty = |depth: usize| mix_in_length(&ZERO_HASHES[depth], 0);
    merkleize(&[
        empty(13), // deposits:         MAX_DEPOSIT_REQUESTS_PER_PAYLOAD = 2^13
        empty(4),  // withdrawals:       MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD = 2^4
        empty(1),  // consolidations:    MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD = 2
        empty(8),  // builder_deposits:  MAX_BUILDER_DEPOSIT_REQUESTS_PER_PAYLOAD = 2^8
        empty(4),  // builder_exits:     MAX_BUILDER_EXIT_REQUESTS_PER_PAYLOAD = 2^4
    ])
}
