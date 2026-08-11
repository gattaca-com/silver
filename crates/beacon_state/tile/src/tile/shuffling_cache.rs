use blst::min_pk::PublicKey;
use flux_profiler::timed;
use silver_beacon_state_data::{
    B256, EPOCHS_PER_HISTORICAL_VECTOR, Epoch, MIN_SEED_LOOKAHEAD, SLOTS_PER_EPOCH, StateReadView,
    randao_mix_at_epoch,
};

use crate::{
    bls,
    shuffling::{self, DOMAIN_BEACON_ATTESTER},
    stf,
};

const MAX_SHUFFLING_CACHE: usize = 4;

pub struct ShufflingCache {
    entries: [ShufflingEntry; MAX_SHUFFLING_CACHE],
    aggregator: bls::PubkeyAggregator,
}

struct ShufflingEntry {
    epoch: Epoch,
    mix: B256,
    shuffled_indices: Vec<u32>,
    built_against: usize,
    committee_aggs: Vec<PublicKey>,
    is_valid: bool,
}

impl ShufflingEntry {
    fn committee_aggs_opt(&self) -> Option<&[PublicKey]> {
        (!self.committee_aggs.is_empty()).then_some(self.committee_aggs.as_slice())
    }

    fn shuffling(&self) -> stf::EpochShuffling<'_> {
        stf::EpochShuffling::new(&self.shuffled_indices, self.built_against)
    }

    fn is_valid_for(&self, epoch: Epoch, mix: B256) -> bool {
        self.is_valid && self.epoch == epoch && self.mix == mix
    }

    /// Reshuffle in place for `(epoch, mix)`, replacing whatever this slot
    /// held. Stays invalid until the shuffle completes, so a half-filled
    /// entry is never readable.
    fn make_valid_for(&mut self, view: &StateReadView, epoch: Epoch, mix: B256) {
        self.is_valid = false;
        self.shuffled_indices.clear();
        self.committee_aggs.clear();

        shuffling::get_active_validator_indices_into(
            &view.validators,
            epoch,
            &mut self.shuffled_indices,
        );
        let seed = shuffling::get_seed(&mix, epoch, DOMAIN_BEACON_ATTESTER);
        shuffling::shuffle_list(&mut self.shuffled_indices, &seed);

        self.epoch = epoch;
        self.mix = mix;
        self.built_against = view.validators.count();
        self.is_valid = true;
    }

    /// One aggregate pubkey per beacon committee of the epoch. No-op once
    /// filled, or while the entry holds no shuffling.
    fn fill_committee_aggs(
        &mut self,
        view: &StateReadView,
        aggregator: &mut bls::PubkeyAggregator,
    ) {
        if !self.committee_aggs.is_empty() || self.shuffled_indices.is_empty() {
            return;
        }
        let shuffling = stf::EpochShuffling::new(&self.shuffled_indices, self.built_against);
        for slot_in_epoch in 0..SLOTS_PER_EPOCH {
            for ci in 0..shuffling.committees_per_slot {
                self.committee_aggs.push(
                    aggregator.aggregate_or_identity(
                        shuffling
                            .committee(slot_in_epoch, ci)
                            .iter()
                            .map(|&vi| view.validators.pubkey_decompressed(vi as usize)),
                    ),
                );
            }
        }
    }
}

impl ShufflingCache {
    pub fn with_capacity(capacity: usize) -> Box<Self> {
        Box::new(Self {
            aggregator: bls::PubkeyAggregator::default(),
            entries: std::array::from_fn(|_| ShufflingEntry {
                epoch: 0,
                mix: [0u8; 32],
                shuffled_indices: Vec::with_capacity(capacity),
                built_against: 0,
                committee_aggs: Vec::new(),
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

    fn window(epoch: Epoch) -> impl Iterator<Item = Epoch> {
        [Some(epoch), epoch.checked_sub(1)].into_iter().flatten()
    }

    /// Maintains the 2-epoch window so attestations with
    /// `target_epoch ∈ {epoch, epoch - 1}` resolve.
    pub fn ensure_window(&mut self, view: &StateReadView, epoch: Epoch) {
        for cached_epoch in Self::window(epoch) {
            self.ensure(view, cached_epoch);
        }
    }

    fn ensure(&mut self, view: &StateReadView, epoch: Epoch) {
        let mix = Self::mix(view, epoch);
        if self.entries.iter().any(|e| e.is_valid_for(epoch, mix)) {
            return;
        }
        self.compute_and_cache(view, epoch, mix);
    }

    #[timed]
    fn compute_and_cache(&mut self, view: &StateReadView, epoch: Epoch, mix: B256) {
        let slot = self.find_slot();
        self.entries[slot].make_valid_for(view, epoch, mix);
    }

    /// Real work at most once per cached `(epoch, mix)` — ~150ns per active
    /// validator — so every other block of the epoch is a no-op.
    #[timed]
    pub fn try_cache_committee_aggs(&mut self, view: &StateReadView, epoch: Epoch) {
        for cached_epoch in Self::window(epoch) {
            self.try_cache_aggs_for(view, cached_epoch);
        }
    }

    fn try_cache_aggs_for(&mut self, view: &StateReadView, epoch: Epoch) {
        let mix = Self::mix(view, epoch);
        if let Some(entry) = self.entries.iter_mut().find(|e| e.is_valid_for(epoch, mix)) {
            entry.fill_committee_aggs(view, &mut self.aggregator);
        }
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
        self.entries.iter().find(|e| e.is_valid_for(epoch, mix))
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

    /// Cached shuffling for `epoch` against `view`'s state, or `None` if not
    /// cached (caller should have run [`ensure_window`] first).
    pub fn lookup<'a>(
        &'a self,
        view: &StateReadView,
        epoch: Epoch,
    ) -> Option<stf::EpochShuffling<'a>> {
        let mix = Self::mix(view, epoch);
        self.get(epoch, mix).map(ShufflingEntry::shuffling)
    }

    /// Assemble a [`stf::ShufflingRef`] over the cached current+previous epoch
    /// shufflings for `block_epoch`. Panics if either is uncached.
    pub fn build_ref<'a>(
        &'a self,
        view: &StateReadView,
        block_epoch: Epoch,
    ) -> stf::ShufflingRef<'a> {
        let prev_epoch = block_epoch.saturating_sub(1);
        let (curr_mix, prev_mix) = (Self::mix(view, block_epoch), Self::mix(view, prev_epoch));
        let curr = self.get(block_epoch, curr_mix).expect("ensure_window cached current epoch");
        let prev = self.get(prev_epoch, prev_mix).expect("ensure_window cached previous epoch");
        stf::ShufflingRef {
            curr: curr.shuffling().with_committee_aggs(curr.committee_aggs_opt()),
            prev: prev.shuffling().with_committee_aggs(prev.committee_aggs_opt()),
        }
    }
}
