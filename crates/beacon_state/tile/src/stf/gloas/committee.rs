use silver_beacon_state_data::{
    EpochView, EpochWriteView, MIN_SEED_LOOKAHEAD, RandaoMixesView, SLOTS_PER_EPOCH,
    StateWriterView, ValidatorsView,
    gloas::{PTC_SIZE, PtcCommittee},
};

use crate::{
    bls::DOMAIN_PTC_ATTESTER,
    shuffling::{MAX_EFFECTIVE_BALANCE, Seed},
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
    randao: &RandaoMixesView,
    target_epoch: u64,
    active: &mut Vec<u32>,
) {
    let shuffling = EpochShuffling::from_views(validators, randao, target_epoch, active);
    let ptc_seed = Seed::from_randao(randao, target_epoch, DOMAIN_PTC_ATTESTER);
    for (i, dst) in out.iter_mut().enumerate() {
        *dst = compute_ptc(
            validators,
            &shuffling,
            &ptc_seed,
            target_epoch * SLOTS_PER_EPOCH + i as u64,
        );
    }
}

/// `compute_ptc`: balance-weighted selection of `PTC_SIZE` indices (with
/// duplicates) over the concatenation of `slot`'s committees.
pub(crate) fn compute_ptc(
    validators: &ValidatorsView,
    shuffling: &EpochShuffling<'_>,
    epoch_seed: &Seed,
    slot: u64,
) -> PtcCommittee {
    let mut committee = [0u64; PTC_SIZE];
    let mut indices = Vec::new();
    for ci in 0..shuffling.committees_per_slot {
        indices.extend_from_slice(shuffling.committee(slot, ci));
    }
    if indices.is_empty() {
        return committee;
    }

    balance_weighted_select(validators, &indices, &epoch_seed.for_slot(slot), &mut committee);
    committee
}

/// `compute_balance_weighted_selection` with `shuffle_indices=False` (the PTC
/// case): traverse `indices` in order, accepting each by effective-balance
/// rejection sampling until `out` is full. Mirrors the proposer/sync sampler.
fn balance_weighted_select(
    validators: &ValidatorsView,
    indices: &[u32],
    seed: &Seed,
    out: &mut [u64],
) {
    let total = indices.len() as u64;
    let mut i: u64 = 0;
    let mut filled = 0;
    let mut draws = seed.draws();
    while filled < out.len() {
        let next = (i % total) as usize;
        let candidate = indices[next] as usize;
        let random = draws.at(i);
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
        &view.randao_mixes.reader(),
        target_epoch,
        &mut active,
    );
    epoch.rotate_ptc_window(&new_epoch);
}
