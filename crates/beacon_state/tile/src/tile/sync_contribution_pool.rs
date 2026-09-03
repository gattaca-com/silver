use blst::min_pk::{AggregateSignature, Signature};
use rustc_hash::FxHashMap;
use silver_beacon_state_data::{B256, SYNC_COMMITTEE_SIZE, Slot};
use silver_common::{
    SYNC_COMMITTEE_SUBNETS, metrics::timed, ssz_view::SYNC_COMMITTEE_CONTRIBUTION_SIZE,
};

use super::attestation_pool::InsertOutcome;

const SYNC_SUBCOMMITTEE_SIZE: usize = SYNC_COMMITTEE_SIZE / SYNC_COMMITTEE_SUBNETS;
pub(super) const SYNC_SUBCOMMITTEE_MASK_WORDS: usize = SYNC_SUBCOMMITTEE_SIZE.div_ceil(64);
const AGGREGATION_BITS_BYTES: usize = SYNC_SUBCOMMITTEE_SIZE.div_ceil(8);

/// Retention is two slots (current + previous), with four subcommittees
/// per slot. The x4 leaves room for competing beacon-block roots; each
/// additional entry requires a valid sync-committee member signature.
const MAX_ENTRIES: usize = 4 * 2 * SYNC_COMMITTEE_SUBNETS;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct ContributionKey {
    slot: Slot,
    subcommittee_index: u64,
    beacon_block_root: B256,
}

struct ContributionEntry {
    aggregation_bits: [u64; SYNC_SUBCOMMITTEE_MASK_WORDS],
    signature: AggregateSignature,
}

pub(super) struct SyncContributionPool {
    entries: FxHashMap<ContributionKey, ContributionEntry>,
    floor: Slot,
}

impl SyncContributionPool {
    pub(super) fn new() -> Self {
        Self {
            entries: FxHashMap::with_capacity_and_hasher(MAX_ENTRIES, Default::default()),
            floor: 0,
        }
    }

    /// Adds an already-verified `SyncCommitteeMessage`. `positions` contains
    /// every occurrence of its validator in this subcommittee. The same
    /// signature is deliberately aggregated once per new position, as
    /// required when a validator occurs more than once in a sync committee.
    #[timed]
    pub(super) fn insert_verified(
        &mut self,
        slot: Slot,
        subcommittee_index: u64,
        beacon_block_root: B256,
        positions: &[u64; SYNC_SUBCOMMITTEE_MASK_WORDS],
        signature: &Signature,
    ) -> InsertOutcome {
        if subcommittee_index >= SYNC_COMMITTEE_SUBNETS as u64 ||
            positions.iter().all(|&word| word == 0)
        {
            return InsertOutcome::Inconsistent;
        }
        if slot < self.floor {
            return InsertOutcome::Stale;
        }

        let key = ContributionKey { slot, subcommittee_index, beacon_block_root };
        if let Some(entry) = self.entries.get_mut(&key) {
            return entry.add(positions, signature);
        }
        if self.entries.len() >= MAX_ENTRIES {
            return InsertOutcome::Full;
        }

        self.entries.insert(key, ContributionEntry::new(*positions, signature));
        InsertOutcome::Inserted
    }

    /// Materializes the unsigned `SyncCommitteeContribution` that a selected
    /// validator will wrap in `ContributionAndProof` and sign. The surrounding
    /// selection proof and validator signatures intentionally remain outside
    /// this pool.
    #[allow(dead_code)] // retrieval interface for the local-validator milestone
    #[timed]
    pub(super) fn contribution_ssz(
        &self,
        slot: Slot,
        subcommittee_index: u64,
        beacon_block_root: B256,
    ) -> Option<[u8; SYNC_COMMITTEE_CONTRIBUTION_SIZE]> {
        let entry =
            self.entries.get(&ContributionKey { slot, subcommittee_index, beacon_block_root })?;
        let mut out = [0u8; SYNC_COMMITTEE_CONTRIBUTION_SIZE];
        out[0..8].copy_from_slice(&slot.to_le_bytes());
        out[8..40].copy_from_slice(&beacon_block_root);
        out[40..48].copy_from_slice(&subcommittee_index.to_le_bytes());
        for (i, word) in entry.aggregation_bits.iter().enumerate() {
            let start = 48 + i * 8;
            out[start..start + 8].copy_from_slice(&word.to_le_bytes());
        }
        let signature_offset = 48 + AGGREGATION_BITS_BYTES;
        out[signature_offset..].copy_from_slice(&entry.signature.to_signature().to_bytes());
        Some(out)
    }

    #[timed]
    pub(super) fn prune_before(&mut self, floor: Slot) {
        self.floor = floor;
        self.entries.retain(|key, _| key.slot >= floor);
    }
}

impl ContributionEntry {
    fn new(aggregation_bits: [u64; SYNC_SUBCOMMITTEE_MASK_WORDS], signature: &Signature) -> Self {
        let copies = aggregation_bits.iter().map(|word| word.count_ones()).sum::<u32>();
        debug_assert!(copies > 0);
        let mut aggregate = AggregateSignature::from_signature(signature);
        for _ in 1..copies {
            aggregate.add_signature(signature, false).expect("infallible without groupcheck");
        }
        Self { aggregation_bits, signature: aggregate }
    }

    #[timed]
    fn add(
        &mut self,
        positions: &[u64; SYNC_SUBCOMMITTEE_MASK_WORDS],
        signature: &Signature,
    ) -> InsertOutcome {
        let mut new_positions = [0u64; SYNC_SUBCOMMITTEE_MASK_WORDS];
        let mut copies = 0u32;
        for ((new, &incoming), &existing) in
            new_positions.iter_mut().zip(positions).zip(&self.aggregation_bits)
        {
            *new = incoming & !existing;
            copies += new.count_ones();
        }
        if copies == 0 {
            return InsertOutcome::Duplicate;
        }

        // The caller only supplies a subgroup-checked, successfully verified
        // signature. BLS addition is not idempotent, so only positions not
        // already represented above may add another signature copy.
        for _ in 0..copies {
            self.signature.add_signature(signature, false).expect("infallible without groupcheck");
        }
        for (bits, new) in self.aggregation_bits.iter_mut().zip(new_positions) {
            *bits |= new;
        }
        InsertOutcome::Inserted
    }
}

#[cfg(test)]
mod tests {
    use blst::BLST_ERROR;
    use silver_common::ssz_view::SyncCommitteeContributionView;

    use super::*;
    use crate::{bls, test_signing};

    const SLOT: Slot = 3;
    const SUBCOMMITTEE: u64 = 1;
    const BLOCK_ROOT: B256 = [0xAB; 32];
    const SIGNING_ROOT: B256 = [0xCD; 32];

    fn signature(sk_idx: usize) -> Signature {
        Signature::from_bytes(&test_signing::sign(sk_idx, &SIGNING_ROOT)).unwrap()
    }

    fn positions(indices: &[usize]) -> [u64; SYNC_SUBCOMMITTEE_MASK_WORDS] {
        let mut mask = [0u64; SYNC_SUBCOMMITTEE_MASK_WORDS];
        for &position in indices {
            mask[position / 64] |= 1 << (position % 64);
        }
        mask
    }

    #[test]
    fn messages_aggregate_to_bits_and_verifying_signature() {
        let mut pool = SyncContributionPool::new();
        assert_eq!(
            pool.insert_verified(SLOT, SUBCOMMITTEE, BLOCK_ROOT, &positions(&[1]), &signature(0)),
            InsertOutcome::Inserted
        );
        assert_eq!(
            pool.insert_verified(SLOT, SUBCOMMITTEE, BLOCK_ROOT, &positions(&[65]), &signature(1)),
            InsertOutcome::Inserted
        );

        let out = pool.contribution_ssz(SLOT, SUBCOMMITTEE, BLOCK_ROOT).unwrap();
        assert_eq!(SyncCommitteeContributionView::slot(&out), SLOT);
        assert_eq!(SyncCommitteeContributionView::beacon_block_root(&out), &BLOCK_ROOT);
        assert_eq!(SyncCommitteeContributionView::subcommittee_index(&out), SUBCOMMITTEE);
        let bits = SyncCommitteeContributionView::aggregation_bits(&out);
        assert_eq!(bits[0], 0b0000_0010);
        assert_eq!(bits[8], 0b0000_0010);

        let sig = Signature::from_bytes(SyncCommitteeContributionView::signature(&out)).unwrap();
        let pks = [&test_signing::pubkey_pk(0), &test_signing::pubkey_pk(1)];
        assert_eq!(
            sig.fast_aggregate_verify(true, &SIGNING_ROOT, bls::DST, &pks),
            BLST_ERROR::BLST_SUCCESS
        );
    }

    #[test]
    fn repeated_validator_positions_repeat_its_signature() {
        let mut pool = SyncContributionPool::new();
        assert_eq!(
            pool.insert_verified(
                SLOT,
                SUBCOMMITTEE,
                BLOCK_ROOT,
                &positions(&[2, 70]),
                &signature(0),
            ),
            InsertOutcome::Inserted
        );

        let out = pool.contribution_ssz(SLOT, SUBCOMMITTEE, BLOCK_ROOT).unwrap();
        let sig = Signature::from_bytes(SyncCommitteeContributionView::signature(&out)).unwrap();
        let pk = test_signing::pubkey_pk(0);
        assert_eq!(
            sig.fast_aggregate_verify(true, &SIGNING_ROOT, bls::DST, &[&pk, &pk]),
            BLST_ERROR::BLST_SUCCESS
        );
        assert_ne!(
            sig.fast_aggregate_verify(true, &SIGNING_ROOT, bls::DST, &[&pk]),
            BLST_ERROR::BLST_SUCCESS
        );
    }

    #[test]
    fn duplicate_positions_do_not_change_signature() {
        let mut pool = SyncContributionPool::new();
        let mask = positions(&[4, 68]);
        assert_eq!(
            pool.insert_verified(SLOT, SUBCOMMITTEE, BLOCK_ROOT, &mask, &signature(0)),
            InsertOutcome::Inserted
        );
        let before = pool.contribution_ssz(SLOT, SUBCOMMITTEE, BLOCK_ROOT).unwrap();

        assert_eq!(
            pool.insert_verified(SLOT, SUBCOMMITTEE, BLOCK_ROOT, &mask, &signature(0)),
            InsertOutcome::Duplicate
        );
        assert_eq!(pool.contribution_ssz(SLOT, SUBCOMMITTEE, BLOCK_ROOT).unwrap(), before);
    }

    #[test]
    fn roots_and_subcommittees_are_separate_and_old_slots_are_pruned() {
        let mut pool = SyncContributionPool::new();
        let other_root = [0xBC; 32];
        let mask = positions(&[0]);
        assert_eq!(
            pool.insert_verified(SLOT, SUBCOMMITTEE, BLOCK_ROOT, &mask, &signature(0)),
            InsertOutcome::Inserted
        );
        assert_eq!(
            pool.insert_verified(SLOT + 1, SUBCOMMITTEE, other_root, &mask, &signature(0)),
            InsertOutcome::Inserted
        );
        assert_eq!(
            pool.insert_verified(SLOT + 1, SUBCOMMITTEE + 1, BLOCK_ROOT, &mask, &signature(0)),
            InsertOutcome::Inserted
        );

        pool.prune_before(SLOT + 1);

        assert_eq!(pool.contribution_ssz(SLOT, SUBCOMMITTEE, BLOCK_ROOT), None);
        assert!(pool.contribution_ssz(SLOT + 1, SUBCOMMITTEE, other_root).is_some());
        assert!(pool.contribution_ssz(SLOT + 1, SUBCOMMITTEE + 1, BLOCK_ROOT).is_some());
        assert_eq!(
            pool.insert_verified(SLOT, SUBCOMMITTEE, BLOCK_ROOT, &mask, &signature(0)),
            InsertOutcome::Stale
        );
    }
}
