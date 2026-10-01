use blst::min_pk::PublicKey;
use flux_profiler::timed;
use silver_beacon_state_data::{B256, Epoch, SLOTS_PER_EPOCH, ShufflingId, StateReadView};
use silver_common::{BeaconStateEvent, TCacheProducer, TProducer};

use crate::{bls, stf};

// Steady state holds {E-1, E, E+1} plus reorg/precompute transients.
const MAX_SHUFFLING_CACHE: usize = 8;

pub struct ShufflingCache {
    entries: [ShufflingEntry; MAX_SHUFFLING_CACHE],
    aggregator: bls::PubkeyAggregator,
    posted: [Option<ShufflingId>; 2],
    head: Option<HeadShufflings>,
}

struct HeadShufflings {
    root: B256,
    epoch: Epoch,
    ids: [Option<ShufflingId>; 3],
}

struct ShufflingEntry {
    id: Option<ShufflingId>,
    shuffled_indices: Vec<u32>,
    required_validator_count: usize,
    committee_aggs: Vec<PublicKey>,
}

impl ShufflingEntry {
    fn post(&self, producer: &mut TProducer, emit: impl FnOnce(BeaconStateEvent)) -> bool {
        let Some(id) = self.id else {
            return false;
        };
        let len = size_of_val(self.shuffled_indices.as_slice());
        let Some(indices) = producer.write_with(len, |buffer| {
            for (bytes, index) in
                buffer.chunks_exact_mut(size_of::<u32>()).zip(&self.shuffled_indices)
            {
                bytes.copy_from_slice(&index.to_le_bytes());
            }
        }) else {
            silver_log::warn!(
                epoch = id.epoch,
                len,
                "beacon_state tcache full; shuffling not posted"
            );
            return false;
        };
        emit(BeaconStateEvent::AttestersShuffling { id, indices });
        true
    }

    fn shuffling(&self) -> stf::EpochShuffling<'_> {
        let aggs = (!self.committee_aggs.is_empty()).then_some(self.committee_aggs.as_slice());
        stf::EpochShuffling::new(&self.shuffled_indices, self.required_validator_count)
            .with_committee_aggs(aggs)
    }

    /// Invalid until the complete shuffled active set is ready.
    #[timed]
    fn fill(&mut self, view: &StateReadView, id: ShufflingId) {
        self.id = None;
        self.committee_aggs.clear();
        self.required_validator_count =
            stf::EpochShuffling::from_state(view, id.epoch, &mut self.shuffled_indices)
                .required_validator_count;
        self.id = Some(id);
    }

    /// No-op once filled, or while the entry holds no shuffling.
    fn fill_committee_aggs(
        &mut self,
        view: &StateReadView,
        aggregator: &mut bls::PubkeyAggregator,
    ) {
        if self.committee_aggs.is_empty() && !self.shuffled_indices.is_empty() {
            self.compute_committee_aggs(view, aggregator);
        }
    }

    /// One aggregate pubkey per beacon committee of the epoch.
    #[timed]
    fn compute_committee_aggs(
        &mut self,
        view: &StateReadView,
        aggregator: &mut bls::PubkeyAggregator,
    ) {
        let shuffling =
            stf::EpochShuffling::new(&self.shuffled_indices, self.required_validator_count);
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
            posted: [None; 2],
            head: None,
            entries: std::array::from_fn(|_| ShufflingEntry {
                id: None,
                shuffled_indices: Vec::with_capacity(capacity),
                required_validator_count: 0,
                committee_aggs: Vec::new(),
            }),
        })
    }

    pub fn protect_head(&mut self, view: &StateReadView) {
        let root = view.slot.state().latest_block_root;
        let epoch = view.slot.current_epoch();
        if self.head.as_ref().is_some_and(|head| head.root == root && head.epoch == epoch) {
            return;
        }
        let ids = [epoch.saturating_sub(1), epoch, epoch + 1]
            .map(|epoch| ShufflingId::from_state(view, epoch));
        self.head = Some(HeadShufflings { root, epoch, ids });
    }

    /// Resolve and cache one epoch against the selected state. An unavailable
    /// decision root leaves the cache untouched.
    pub fn get(&mut self, view: &StateReadView, epoch: Epoch) -> Option<stf::EpochShuffling<'_>> {
        let id = ShufflingId::from_state(view, epoch)?;
        let index = self.ensure(view, id, &[]);
        Some(self.entries[index].shuffling())
    }

    /// Resolve both block-validation epochs before filling either, protecting
    /// both identities from eviction throughout the request.
    pub fn for_block(
        &mut self,
        view: &StateReadView,
        epoch: Epoch,
    ) -> Option<stf::ShufflingRef<'_>> {
        let [curr, prev] = self.ensure_pair(view, epoch)?;
        Some(stf::ShufflingRef {
            curr: self.entries[curr].shuffling(),
            prev: self.entries[prev].shuffling(),
        })
    }

    /// Warm an epoch and its predecessor, including their committee aggregates.
    pub fn precompute(&mut self, view: &StateReadView, epoch: Epoch) {
        let Some(indices) = self.ensure_pair(view, epoch) else {
            return;
        };
        for index in indices {
            self.entries[index].fill_committee_aggs(view, &mut self.aggregator);
        }
    }

    fn ensure_pair(&mut self, view: &StateReadView, epoch: Epoch) -> Option<[usize; 2]> {
        let ids = [
            ShufflingId::from_state(view, epoch)?,
            ShufflingId::from_state(view, epoch.saturating_sub(1))?,
        ];
        Some(ids.map(|id| self.ensure(view, id, &ids)))
    }

    fn ensure(
        &mut self,
        view: &StateReadView,
        id: ShufflingId,
        protected: &[ShufflingId],
    ) -> usize {
        if let Some(index) = self.entries.iter().position(|entry| entry.id == Some(id)) {
            return index;
        }
        let index = self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| entry.id.is_none_or(|held| !protected.contains(&held)))
            .filter(|(_, entry)| {
                entry.id.is_none_or(|held| {
                    self.head.as_ref().is_none_or(|head| !head.ids.contains(&Some(held)))
                })
            })
            .min_by_key(|(_, entry)| {
                entry.id.map(|held| (held.epoch.abs_diff(id.epoch) <= 1, held.epoch))
            })
            .map(|(index, _)| index)
            .expect("at most five identities protected in an eight-entry cache");
        self.entries[index].fill(view, id);
        index
    }

    /// Publish only the head's current and next epochs. Publication history
    /// survives cache eviction and changes only after a successful send.
    pub fn post_fresh(
        &mut self,
        view: &StateReadView,
        producer: &mut TProducer,
        mut emit: impl FnMut(BeaconStateEvent),
    ) -> bool {
        let epoch = view.slot.current_epoch();
        let mut any_posted = false;
        for epoch in [epoch, epoch + 1] {
            let id = ShufflingId::from_state(view, epoch)
                .expect("head shuffling decision is in state history");
            let slot = (epoch % 2) as usize;
            if self.posted[slot] == Some(id) {
                continue;
            }
            let index = self.ensure(view, id, &[]);
            if self.entries[index].post(producer, &mut emit) {
                self.posted[slot] = Some(id);
                any_posted = true;
            }
        }
        any_posted
    }
}

#[cfg(test)]
mod tests {
    use silver_beacon_state_data::{
        BeaconState, BeaconStateOwner, EpochStateFinalized, StateId, ValSeed,
    };

    use super::*;
    use crate::test_signing;

    fn state(branch: u8, active: usize, count: usize) -> (BeaconStateOwner, StateId) {
        let seeds = (0..count)
            .map(|i| ValSeed {
                pubkey: test_signing::pubkey_pk(i % test_signing::PRIVKEY_HEX.len()).to_bytes(),
                activation_epoch: if i < active { 0 } else { u64::MAX },
                ..Default::default()
            })
            .collect::<Vec<_>>();
        let mut owner = BeaconStateOwner::new(BeaconState::for_test(
            EpochStateFinalized::default(),
            &seeds,
            70,
        ));
        let base = owner.roll_fresh();
        let mut fork = owner.apply_block_view(base);
        fork.view.slot.state_mut().latest_block_root = [branch; 32];
        for slot in [0, 31, 63] {
            fork.view.block_roots.set(slot, [branch; 32]);
        }
        let id = fork.commit();
        (owner, id)
    }

    fn members(shuffling: &stf::EpochShuffling<'_>, epoch: Epoch) -> Vec<u32> {
        let mut members = (epoch * SLOTS_PER_EPOCH..(epoch + 1) * SLOTS_PER_EPOCH)
            .flat_map(|slot| {
                (0..shuffling.committees_per_slot)
                    .flat_map(move |committee| shuffling.committee(slot, committee).iter().copied())
            })
            .collect::<Vec<_>>();
        members.sort_unstable();
        members
    }

    #[test]
    fn head_shufflings_survive_competing_branch_requests() {
        let (owner, id) = state(1, 8, 8);
        let head = owner.read_view(id);
        let mut cache = ShufflingCache::with_capacity(8);
        cache.protect_head(&head);
        cache.precompute(&head, 2);
        cache.precompute(&head, 3);

        for branch in 2..20 {
            let (other, id) = state(branch, 7, 8);
            let view = other.read_view(id);
            cache.precompute(&view, 2);
            let pair = cache.for_block(&view, 3).unwrap();
            assert_eq!(members(&pair.curr, 3), (0..7).collect::<Vec<_>>());
            assert_eq!(members(&pair.prev, 2), (0..7).collect::<Vec<_>>());
            for epoch in 1..=3 {
                let shuffling = cache.get(&head, epoch).unwrap();
                assert!(shuffling.committee_aggs.is_some(), "head entry must not be rebuilt");
                assert_eq!(members(&shuffling, epoch), (0..8).collect::<Vec<_>>());
            }
        }
    }

    #[test]
    fn protection_moves_to_the_new_head_and_releases_old_entries() {
        let mut cache = ShufflingCache::with_capacity(8);
        for branch in 1..20 {
            let (owner, id) = state(branch, 8, 8);
            let view = owner.read_view(id);
            cache.protect_head(&view);
            cache.precompute(&view, 2);
            cache.precompute(&view, 3);
            let (other, id) = state(branch + 20, 7, 8);
            let other = other.read_view(id);
            cache.precompute(&other, 2);
            cache.precompute(&other, 3);
            for epoch in 1..=3 {
                assert!(cache.get(&view, epoch).unwrap().committee_aggs.is_some());
            }
        }
    }

    #[test]
    fn protection_advances_with_empty_slots_on_the_same_head() {
        let (mut owner, id) = state(1, 8, 8);
        let mut cache = ShufflingCache::with_capacity(8);
        cache.protect_head(&owner.read_view(id));
        let mut fork = owner.apply_block_view(id);
        fork.view.slot.state_mut().slot = 96;
        fork.view.block_roots.set(95, [1; 32]);
        let advanced = fork.commit();
        let view = owner.read_view(advanced);
        cache.protect_head(&view);
        assert_eq!(
            cache.head.as_ref().unwrap().ids,
            [2, 3, 4].map(|epoch| ShufflingId::from_state(&view, epoch)),
        );
    }

    #[test]
    fn verification_and_aggregates_follow_branch_identity_with_the_same_mix() {
        let (a, a_id) = state(1, 8, 8);
        let (b, b_id) = state(2, 7, 8);
        let a = a.read_view(a_id);
        let b = b.read_view(b_id);
        assert_eq!(a.randao_mixes.seed_mix(2), b.randao_mixes.seed_mix(2));
        let mut cache = ShufflingCache::with_capacity(8);
        for (view, active) in [(&a, 8), (&b, 7), (&a, 8)] {
            cache.precompute(view, 2);
            let pair = cache.for_block(view, 2).unwrap();
            for (epoch, shuffling) in [(2, pair.curr), (1, pair.prev)] {
                assert_eq!(members(&shuffling, epoch), (0..active).collect::<Vec<_>>());
                let aggregates = shuffling.committee_aggs.unwrap();
                for slot in 0..SLOTS_PER_EPOCH {
                    let committee = shuffling.committee(slot, 0);
                    if let [validator] = committee {
                        assert_eq!(
                            aggregates[slot as usize].to_bytes(),
                            *view.validators.pubkey(*validator as usize)
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn shared_identity_reuses_aggregates_without_requiring_unrelated_validators() {
        let (large, large_id) = state(1, 8, 9);
        let (small, small_id) = state(1, 8, 8);
        let large = large.read_view(large_id);
        let small = small.read_view(small_id);
        assert_eq!(ShufflingId::from_state(&large, 2), ShufflingId::from_state(&small, 2));
        let mut cache = ShufflingCache::with_capacity(9);
        cache.precompute(&large, 2);
        let shuffling = cache.get(&small, 2).unwrap();
        assert!(shuffling.committee_aggs.is_some(), "same identity reuses precomputed aggregates");
        assert!(shuffling.indices_in_range(8));
        assert!(!shuffling.indices_in_range(7), "an active index must remain addressable");
    }

    #[test]
    fn two_epoch_requests_survive_competing_branches_in_a_full_cache() {
        let mut cache = ShufflingCache::with_capacity(8);
        for branch in 1..=MAX_SHUFFLING_CACHE as u8 + 2 {
            let (owner, id) = state(branch, branch as usize, 8);
            let view = owner.read_view(id);
            cache.get(&view, 2).unwrap();
        }
        let (owner, id) = state(20, 5, 8);
        let view = owner.read_view(id);
        // Insert the older half first. Filling the newer half must retain it.
        cache.precompute(&view, 1);
        // Displace epoch zero so the requested previous epoch is the oldest.
        cache.get(&view, 3).unwrap();
        let pair = cache.for_block(&view, 2).unwrap();
        assert_eq!(members(&pair.curr, 2), (0..5).collect::<Vec<_>>());
        assert_eq!(members(&pair.prev, 1), (0..5).collect::<Vec<_>>());
        assert!(pair.prev.committee_aggs.is_some(), "requested identity was retained");
        for branch in 21..=28 {
            let (owner, id) = state(branch, 6, 8);
            let view = owner.read_view(id);
            let pair = cache.for_block(&view, 2).unwrap();
            assert_eq!(members(&pair.curr, 2), (0..6).collect::<Vec<_>>());
            assert_eq!(members(&pair.prev, 1), (0..6).collect::<Vec<_>>());
        }
    }

    #[test]
    fn unavailable_decisions_do_not_poison_a_cached_identity() {
        let (owner, id) = state(1, 8, 8);
        let view = owner.read_view(id);
        let mut cache = ShufflingCache::with_capacity(8);
        cache.precompute(&view, 2);
        assert!(cache.get(&view, 4).is_none());
        assert!(cache.for_block(&view, 4).is_none());
        assert!(cache.get(&view, 2).unwrap().committee_aggs.is_some());
    }
}
