use silver_beacon_state_data::{
    EpochView, EpochWriteView, MIN_SEED_LOOKAHEAD, SLOTS_PER_EPOCH, SlotStateView, StateWriterView,
    ValidatorsView,
    gloas::{PTC_SIZE, PtcCommittee},
    types::B256,
};

use crate::{
    bls::DOMAIN_PTC_ATTESTER,
    merkle::sha256,
    shuffling::{MAX_EFFECTIVE_BALANCE, get_seed_from_state},
    stf::EpochShuffling,
};

/// `2**16 - 1` — the 16-bit acceptance ceiling in balance-weighted selection.
const MAX_RANDOM_16: u64 = 0xFFFF;
const SPE: usize = SLOTS_PER_EPOCH as usize;

pub(crate) fn get_ptc<'a>(
    epoch: &EpochView<'a>,
    state_epoch: u64,
    slot: u64,
) -> Option<&'a PtcCommittee> {
    let target_epoch = slot / SLOTS_PER_EPOCH;
    let idx = if target_epoch < state_epoch {
        if target_epoch + 1 != state_epoch {
            return None;
        }
        slot % SLOTS_PER_EPOCH
    } else {
        if target_epoch > state_epoch + MIN_SEED_LOOKAHEAD {
            return None;
        }
        (target_epoch - state_epoch + 1) * SLOTS_PER_EPOCH + slot % SLOTS_PER_EPOCH
    };
    epoch.ptc_window().get(idx as usize)
}

pub(crate) fn fill_epoch_ptc(
    out: &mut [PtcCommittee],
    validators: &ValidatorsView,
    slot: &SlotStateView,
    epoch: &EpochView,
    target_epoch: u64,
    active: &mut Vec<u32>,
) {
    let sh = EpochShuffling::build(validators, slot, epoch, target_epoch, active);
    let ptc_seed = get_seed_from_state(epoch, slot, target_epoch, DOMAIN_PTC_ATTESTER);
    for (i, dst) in out.iter_mut().enumerate() {
        *dst = compute_ptc(validators, &sh, &ptc_seed, target_epoch * SLOTS_PER_EPOCH + i as u64);
    }
}

/// `compute_ptc`: balance-weighted selection of `PTC_SIZE` indices (with
/// duplicates) over the concatenation of `slot`'s committees.
pub(crate) fn compute_ptc(
    validators: &ValidatorsView,
    sh: &EpochShuffling<'_>,
    epoch_seed: &B256,
    slot: u64,
) -> PtcCommittee {
    let mut committee = [0u64; PTC_SIZE];
    let mut indices = Vec::new();
    for ci in 0..sh.committees_per_slot {
        indices.extend_from_slice(sh.committee(slot, ci));
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

pub fn process_ptc_window(view: &StateWriterView, epoch: &mut EpochWriteView, current_epoch: u64) {
    let target_epoch = current_epoch + MIN_SEED_LOOKAHEAD + 1;
    let mut new_epoch = vec![[0u64; PTC_SIZE]; SPE];
    let mut active = Vec::new();
    fill_epoch_ptc(
        &mut new_epoch,
        &view.validators.reader(),
        &view.slot.reader(),
        &epoch.reader(),
        target_epoch,
        &mut active,
    );
    epoch.rotate_ptc_window(&new_epoch);
}
