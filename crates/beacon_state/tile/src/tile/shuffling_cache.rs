use blst::min_pk::PublicKey;
use flux_profiler::timed;
use silver_beacon_state_data::{B256, Epoch, SLOTS_PER_EPOCH, StateReadView};

use crate::{
    bls,
    shuffling::{self, DOMAIN_BEACON_ATTESTER},
    stf,
};

// Steady state holds {E-1, E, E+1} plus reorg/precompute transients.
const MAX_SHUFFLING_CACHE: usize = 6;

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
    fn shuffling(&self) -> stf::EpochShuffling<'_> {
        let aggs = (!self.committee_aggs.is_empty()).then_some(self.committee_aggs.as_slice());
        stf::EpochShuffling::new(&self.shuffled_indices, self.built_against)
            .with_committee_aggs(aggs)
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

        view.validators.active_indices_into(epoch, &mut self.shuffled_indices);
        shuffling::Seed::new(&mix, epoch, DOMAIN_BEACON_ATTESTER)
            .shuffle(&mut self.shuffled_indices);

        self.epoch = epoch;
        self.mix = mix;
        self.built_against = view.validators.count();
        self.is_valid = true;
    }

    /// One aggregate pubkey per beacon committee of the epoch. No-op once
    /// filled, or while the entry holds no shuffling.
    #[timed]
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

    /// Cached alongside the shuffling because it is the validity key: a
    /// different mix for the same epoch means the shuffle must be redone.
    fn mix(view: &StateReadView, epoch: Epoch) -> B256 {
        view.randao_mixes.seed_mix(epoch)
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
        let slot = self.find_slot(epoch);
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

    /// Empty slot first, otherwise the lowest-epoch live entry outside
    /// `inserted_epoch ± 1` (falling back to plain lowest): an insert must
    /// never evict its window partner, or `ensure_window`'s second insert
    /// could evict its first when far-epoch entries crowd the cache.
    fn find_slot(&self, inserted_epoch: Epoch) -> usize {
        if let Some(empty) = self.entries.iter().position(|e| !e.is_valid) {
            return empty;
        }
        self.entries
            .iter()
            .enumerate()
            .min_by_key(|(_, e)| (e.epoch.abs_diff(inserted_epoch) <= 1, e.epoch))
            .map_or(0, |(slot, _)| slot)
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
        stf::ShufflingRef { curr: curr.shuffling(), prev: prev.shuffling() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cache_with_epochs(epochs: &[Epoch]) -> Box<ShufflingCache> {
        let mut cache = ShufflingCache::with_capacity(0);
        for (entry, &epoch) in cache.entries.iter_mut().zip(epochs) {
            entry.epoch = epoch;
            entry.is_valid = true;
        }
        cache
    }

    #[test]
    fn find_slot_prefers_empty() {
        let cache = cache_with_epochs(&[10, 11, 12]);
        assert!(cache.find_slot(11) >= 3);
    }

    #[test]
    fn find_slot_never_evicts_adjacent_epochs() {
        let cache = cache_with_epochs(&[10, 11, 12, 100, 101, 102]);
        // {10, 11, 12} are within ±1 of the insert; lowest eligible is 100.
        assert_eq!(cache.find_slot(11), 3);
    }

    #[test]
    fn find_slot_window_pair_survives_far_epoch_squatters() {
        let mut cache = cache_with_epochs(&[50, 51, 52, 53, 54, 55]);
        // ensure_window(10) inserts 10 then 9: the first insert takes the
        // lowest live slot, and the second must not evict it.
        let first = cache.find_slot(10);
        assert_eq!(cache.entries[first].epoch, 50);
        cache.entries[first].epoch = 10;
        let second = cache.find_slot(9);
        assert_ne!(second, first);
        assert_eq!(cache.entries[second].epoch, 51);
    }

    #[test]
    fn find_slot_falls_back_to_lowest_when_all_adjacent() {
        let cache = cache_with_epochs(&[10, 11, 12, 11, 10, 12]);
        assert_eq!(cache.find_slot(11), 0);
    }
}
