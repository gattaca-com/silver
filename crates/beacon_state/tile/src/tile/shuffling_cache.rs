use flux_profiler::timed;
use silver_beacon_state_data::{
    B256, BeaconStateOwner, EPOCHS_PER_HISTORICAL_VECTOR, Epoch, MIN_SEED_LOOKAHEAD, StateId,
    StateReadView, randao_mix_at_epoch,
};

use crate::{
    shuffling::{self, DOMAIN_BEACON_ATTESTER},
    stf,
};

const MAX_SHUFFLING_CACHE: usize = 4;

pub struct ShufflingCache {
    entries: [ShufflingEntry; MAX_SHUFFLING_CACHE],
}

struct ShufflingEntry {
    epoch: Epoch,
    mix: B256,
    shuffled_indices: Vec<u32>,
    is_valid: bool,
}

impl ShufflingCache {
    pub fn with_capacity(capacity: usize) -> Box<Self> {
        Box::new(Self {
            entries: std::array::from_fn(|_| ShufflingEntry {
                epoch: 0,
                mix: [0u8; 32],
                shuffled_indices: Vec::with_capacity(capacity),
                is_valid: false,
            }),
        })
    }

    /// The effective randao mix epoch driving `get_seed(_, epoch, ATTESTER)`
    /// (one `randao_mixes[]` slot, `MIN_SEED_LOOKAHEAD` ahead of the boundary).
    fn mix(view: &StateReadView, epoch: Epoch) -> B256 {
        let mix_epoch = epoch + EPOCHS_PER_HISTORICAL_VECTOR as u64 - MIN_SEED_LOOKAHEAD - 1;
        randao_mix_at_epoch(&view.epoch, &view.slot, mix_epoch)
    }

    /// Compute and cache the attester shuffling for `epoch` and `epoch - 1`
    /// against the post-state named by `state_id`. Maintains the 2-epoch
    /// window so attestations with `target_epoch ∈ {epoch, epoch - 1}` resolve.
    /// `scratch` is a reusable active-index buffer (cleared on entry).
    #[timed]
    pub fn ensure_window(
        &mut self,
        state: &BeaconStateOwner,
        state_id: StateId,
        epoch: Epoch,
        scratch: &mut Vec<u32>,
    ) {
        self.ensure(state, state_id, epoch, scratch);
        if epoch > 0 {
            self.ensure(state, state_id, epoch - 1, scratch);
        }
    }

    fn ensure(
        &mut self,
        state: &BeaconStateOwner,
        state_id: StateId,
        epoch: Epoch,
        scratch: &mut Vec<u32>,
    ) {
        let mix = {
            let view = state.read_view(state_id);
            Self::mix(&view, epoch)
        };
        if self.entries.iter().any(|e| e.is_valid && e.epoch == epoch && e.mix == mix) {
            return;
        }

        scratch.clear();
        {
            let view = state.read_view(state_id);
            shuffling::get_active_validator_indices_into(&view.validators, epoch, scratch);
        }
        let seed = shuffling::get_seed(&mix, epoch, DOMAIN_BEACON_ATTESTER);
        shuffling::shuffle_list(scratch, &seed);

        let slot = self.find_slot();
        let entry = &mut self.entries[slot];
        entry.epoch = epoch;
        entry.mix = mix;
        entry.is_valid = true;
        entry.shuffled_indices.clear();
        entry.shuffled_indices.extend_from_slice(scratch);
    }

    /// Empty slot first, otherwise lowest-epoch among live entries. Mix is
    /// frozen data not tied to any arena slot, so there's no "dead gen"
    /// staleness to check — entries simply become uninteresting once the
    /// chain advances past their epoch.
    fn find_slot(&self) -> usize {
        let mut best_live = 0;
        let mut best_live_epoch = u64::MAX;
        for (i, entry) in self.entries.iter().enumerate() {
            if !entry.is_valid {
                return i;
            }
            if entry.epoch < best_live_epoch {
                best_live_epoch = entry.epoch;
                best_live = i;
            }
        }
        best_live
    }

    fn get(&self, epoch: Epoch, mix: B256) -> Option<&ShufflingEntry> {
        self.entries.iter().find(|e| e.is_valid && e.epoch == epoch && e.mix == mix)
    }

    /// First cached shuffled active-index slice for `epoch`, mix-agnostic.
    /// Test helper — production lookups key on the mix too.
    #[cfg(test)]
    pub(crate) fn shuffled_by_epoch(&self, epoch: Epoch) -> Option<&[u32]> {
        self.entries
            .iter()
            .find(|e| e.is_valid && e.epoch == epoch)
            .map(|e| e.shuffled_indices.as_slice())
    }

    /// Cached shuffled active-index slice for `epoch` against `view`'s state,
    /// or `None` if not cached (caller should have run [`ensure_window`]
    /// first).
    pub fn lookup<'a>(&'a self, view: &StateReadView, epoch: Epoch) -> Option<&'a [u32]> {
        let mix = Self::mix(view, epoch);
        self.get(epoch, mix).map(|e| e.shuffled_indices.as_slice())
    }

    /// Assemble a [`stf::ShufflingRef`] over the cached current+previous epoch
    /// shufflings for `block_epoch`. Panics if either is uncached.
    pub fn build_ref<'a>(
        &'a self,
        state: &BeaconStateOwner,
        state_id: StateId,
        block_epoch: Epoch,
    ) -> stf::ShufflingRef<'a> {
        let prev_epoch = block_epoch.saturating_sub(1);
        let (curr_mix, prev_mix) = {
            let view = state.read_view(state_id);
            (Self::mix(&view, block_epoch), Self::mix(&view, prev_epoch))
        };
        let curr = self.get(block_epoch, curr_mix).expect("ensure_window cached current epoch");
        let prev = self.get(prev_epoch, prev_mix).expect("ensure_window cached previous epoch");
        stf::ShufflingRef {
            curr_epoch: block_epoch,
            curr_shuffled: curr.shuffled_indices.as_slice(),
            curr_committees_per_slot: shuffling::committees_per_slot(curr.shuffled_indices.len()),
            prev_epoch,
            prev_shuffled: prev.shuffled_indices.as_slice(),
            prev_committees_per_slot: shuffling::committees_per_slot(prev.shuffled_indices.len()),
        }
    }
}
