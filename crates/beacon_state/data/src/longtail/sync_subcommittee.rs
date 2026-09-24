use crate::{
    StateReadView, ValidatorsView,
    types::{
        BLSPubkey, EPOCHS_PER_SYNC_COMMITTEE_PERIOD, SLOTS_PER_EPOCH, SYNC_COMMITTEE_SUBNETS,
        SYNC_SUBCOMMITTEE_SIZE, Slot,
    },
};

pub const SYNC_SUBCOMMITTEE_MASK_WORDS: usize = SYNC_SUBCOMMITTEE_SIZE.div_ceil(64);

#[inline]
pub fn uses_next_sync_committee(slot: Slot) -> bool {
    let epoch = slot / SLOTS_PER_EPOCH;
    let next_slot_epoch = slot.saturating_add(1) / SLOTS_PER_EPOCH;
    epoch / EPOCHS_PER_SYNC_COMMITTEE_PERIOD != next_slot_epoch / EPOCHS_PER_SYNC_COMMITTEE_PERIOD
}

pub enum SyncSubcommittee<'a> {
    /// Current committee indices are cached in the state.
    Current(&'a [u32]),
    /// The next committee has no index cache; resolve only the positions that
    /// validation needs from its committed pubkeys.
    Next(&'a [BLSPubkey]),
}

impl<'a> SyncSubcommittee<'a> {
    pub fn of(view: &StateReadView<'a>, subcommittee: usize) -> Self {
        let base = subcommittee * SYNC_SUBCOMMITTEE_SIZE;
        let end = base + SYNC_SUBCOMMITTEE_SIZE;
        let committees = view.longtail.sync_committees();
        // The spec selects from the state at `state.slot + 1`, not from the
        // message slot. They differ during the clock-disparity window.
        if uses_next_sync_committee(view.slot.slot_number()) {
            Self::Next(&committees.next().pubkeys[base..end])
        } else {
            Self::Current(&committees.indices()[base..end])
        }
    }

    pub fn subnets_of(view: &StateReadView<'a>, validator: usize) -> u8 {
        if validator >= view.validators.count() {
            return 0;
        }
        (0..SYNC_COMMITTEE_SUBNETS)
            .filter(|&subnet| Self::of(view, subnet).contains(validator, &view.validators))
            .fold(0, |subnets, subnet| subnets | 1 << subnet)
    }

    pub fn contains(&self, validator: usize, validators: &ValidatorsView<'_>) -> bool {
        match self {
            Self::Current(indices) => indices.iter().any(|&v| v as usize == validator),
            Self::Next(pubkeys) => {
                validator < validators.count() && pubkeys.contains(validators.pubkey(validator))
            }
        }
    }

    pub fn positions(
        &self,
        validator: usize,
        validators: &ValidatorsView<'_>,
    ) -> [u64; SYNC_SUBCOMMITTEE_MASK_WORDS] {
        let mut positions = [0u64; SYNC_SUBCOMMITTEE_MASK_WORDS];
        match self {
            Self::Current(indices) => {
                for (position, &member) in indices.iter().enumerate() {
                    if member as usize == validator {
                        positions[position / 64] |= 1 << (position % 64);
                    }
                }
            }
            Self::Next(pubkeys) if validator < validators.count() => {
                let validator_pubkey = validators.pubkey(validator);
                for (position, member) in pubkeys.iter().enumerate() {
                    if member == validator_pubkey {
                        positions[position / 64] |= 1 << (position % 64);
                    }
                }
            }
            Self::Next(_) => {}
        }
        positions
    }

    pub fn validator_at(&self, position: usize, validators: &ValidatorsView<'_>) -> Option<usize> {
        match self {
            Self::Current(indices) => {
                let validator = *indices.get(position)? as usize;
                (validator < validators.count()).then_some(validator)
            }
            Self::Next(pubkeys) => validators
                .find_by_pubkey(pubkeys.get(position)?)
                .map(|validator| validator as usize),
        }
    }
}
