use blst::min_pk::{AggregateSignature, Signature};
use rustc_hash::FxHashMap;
use silver_beacon_state_data::{
    B256, SYNC_COMMITTEE_SIZE, SYNC_SUBCOMMITTEE_MASK_WORDS, SYNC_SUBCOMMITTEE_SIZE, Slot,
};
use silver_common::{
    SYNC_COMMITTEE_SUBNETS,
    metrics::timed,
    ssz_view::{BLOCK_SYNC_AGGREGATE_SIZE, SYNC_COMMITTEE_CONTRIBUTION_SIZE},
};
use silver_ssz::block_body::EMPTY_SYNC_AGGREGATE;

use super::attestation_pool::InsertOutcome;

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

/// A gossiped contribution, already verified. The signature stays compressed
/// until a block packs it.
struct ReceivedContribution {
    aggregation_bits: [u64; SYNC_SUBCOMMITTEE_MASK_WORDS],
    signature: [u8; 96],
}

pub(super) struct SyncContributionPool {
    /// Aggregated from single messages.
    entries: FxHashMap<ContributionKey, ContributionEntry>,
    /// The widest contribution received per key.
    received: FxHashMap<ContributionKey, ReceivedContribution>,
    floor: Slot,
}

impl SyncContributionPool {
    pub(super) fn new() -> Self {
        Self {
            entries: FxHashMap::with_capacity_and_hasher(MAX_ENTRIES, Default::default()),
            received: FxHashMap::with_capacity_and_hasher(MAX_ENTRIES, Default::default()),
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
            return InsertOutcome::Invalid;
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

    /// Keeps a verified gossip contribution when it covers more positions
    /// than the one held for its key.
    #[timed]
    pub(super) fn insert_received(
        &mut self,
        slot: Slot,
        subcommittee_index: u64,
        beacon_block_root: B256,
        aggregation_bits: &[u8; AGGREGATION_BITS_BYTES],
        signature: &[u8; 96],
    ) -> InsertOutcome {
        if subcommittee_index >= SYNC_COMMITTEE_SUBNETS as u64 {
            return InsertOutcome::Invalid;
        }
        if slot < self.floor {
            return InsertOutcome::Stale;
        }

        let key = ContributionKey { slot, subcommittee_index, beacon_block_root };
        let aggregation_bits = bit_words(aggregation_bits);
        let held = self.received.get(&key);
        if held.is_some_and(|held| popcount(&held.aggregation_bits) >= popcount(&aggregation_bits))
        {
            return InsertOutcome::Duplicate;
        }
        if held.is_none() && self.received.len() >= MAX_ENTRIES {
            return InsertOutcome::Full;
        }

        self.received.insert(key, ReceivedContribution { aggregation_bits, signature: *signature });
        InsertOutcome::Inserted
    }

    pub(super) fn contribution(
        &self,
        slot: Slot,
        subcommittee_index: u64,
        beacon_block_root: B256,
    ) -> Option<PooledContribution<'_>> {
        let key = ContributionKey { slot, subcommittee_index, beacon_block_root };
        self.entries.get(&key).map(|entry| PooledContribution { key, entry })
    }

    /// The `SyncAggregate` for `beacon_block_root` at `slot`. Per
    /// subcommittee, the message aggregate and the received contribution are
    /// joined when disjoint; otherwise the wider is taken, as overlapping
    /// signatures cannot be separated.
    #[timed]
    pub(super) fn write_sync_aggregate(
        &self,
        slot: Slot,
        beacon_block_root: B256,
        out: &mut [u8; BLOCK_SYNC_AGGREGATE_SIZE],
    ) {
        *out = EMPTY_SYNC_AGGREGATE;
        let mut signature: Option<AggregateSignature> = None;
        for subcommittee_index in 0..SYNC_COMMITTEE_SUBNETS {
            let key = ContributionKey {
                slot,
                subcommittee_index: subcommittee_index as u64,
                beacon_block_root,
            };
            let Some((aggregation_bits, subcommittee_signature)) =
                self.subcommittee_aggregate(&key)
            else {
                continue;
            };
            let bits = &mut out[subcommittee_index * AGGREGATION_BITS_BYTES..];
            for (word, bytes) in aggregation_bits.iter().zip(bits.as_chunks_mut().0) {
                *bytes = word.to_le_bytes();
            }
            match &mut signature {
                Some(signature) => signature.add_aggregate(&subcommittee_signature),
                None => signature = Some(subcommittee_signature),
            }
        }
        if let Some(signature) = signature {
            out[SYNC_COMMITTEE_SIZE / 8..].copy_from_slice(&signature.to_signature().to_bytes());
        }
    }

    fn subcommittee_aggregate(
        &self,
        key: &ContributionKey,
    ) -> Option<([u64; SYNC_SUBCOMMITTEE_MASK_WORDS], AggregateSignature)> {
        let messages = self.entries.get(key);
        let received = self.received.get(key).and_then(|received| {
            // Verified on receipt, so the subgroup check is not repeated.
            let signature = Signature::from_bytes(&received.signature).ok()?;
            Some((received.aggregation_bits, signature))
        });
        let (messages, (received_bits, received_signature)) = match (messages, received) {
            (None, None) => return None,
            (Some(messages), None) => return Some((messages.aggregation_bits, messages.signature)),
            (None, Some((bits, signature))) => {
                return Some((bits, AggregateSignature::from_signature(&signature)));
            }
            (Some(messages), Some(received)) => (messages, received),
        };

        let disjoint =
            messages.aggregation_bits.iter().zip(&received_bits).all(|(held, new)| held & new == 0);
        if disjoint {
            let mut signature = messages.signature;
            signature
                .add_signature(&received_signature, false)
                .expect("infallible without groupcheck");
            let mut bits = messages.aggregation_bits;
            for (bits, received) in bits.iter_mut().zip(received_bits) {
                *bits |= received;
            }
            return Some((bits, signature));
        }
        if popcount(&received_bits) > popcount(&messages.aggregation_bits) {
            return Some((received_bits, AggregateSignature::from_signature(&received_signature)));
        }
        Some((messages.aggregation_bits, messages.signature))
    }

    #[timed]
    pub(super) fn prune_before(&mut self, floor: Slot) {
        self.floor = floor;
        self.entries.retain(|key, _| key.slot >= floor);
        self.received.retain(|key, _| key.slot >= floor);
    }
}

fn bit_words(bytes: &[u8; AGGREGATION_BITS_BYTES]) -> [u64; SYNC_SUBCOMMITTEE_MASK_WORDS] {
    let mut words = [0; SYNC_SUBCOMMITTEE_MASK_WORDS];
    for (word, chunk) in words.iter_mut().zip(bytes.as_chunks::<8>().0) {
        *word = u64::from_le_bytes(*chunk);
    }
    words
}

fn popcount(words: &[u64; SYNC_SUBCOMMITTEE_MASK_WORDS]) -> u32 {
    words.iter().map(|word| word.count_ones()).sum()
}

pub(super) struct PooledContribution<'a> {
    key: ContributionKey,
    entry: &'a ContributionEntry,
}

impl PooledContribution<'_> {
    #[timed]
    pub(super) fn write_ssz(&self, out: &mut [u8; SYNC_COMMITTEE_CONTRIBUTION_SIZE]) {
        let ContributionKey { slot, subcommittee_index, beacon_block_root } = self.key;
        out[0..8].copy_from_slice(&slot.to_le_bytes());
        out[8..40].copy_from_slice(&beacon_block_root);
        out[40..48].copy_from_slice(&subcommittee_index.to_le_bytes());
        for (i, word) in self.entry.aggregation_bits.iter().enumerate() {
            let start = 48 + i * 8;
            out[start..start + 8].copy_from_slice(&word.to_le_bytes());
        }
        let signature_offset = 48 + AGGREGATION_BITS_BYTES;
        out[signature_offset..].copy_from_slice(&self.entry.signature.to_signature().to_bytes());
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

    impl SyncContributionPool {
        pub(in crate::tile) fn contribution_ssz(
            &self,
            slot: Slot,
            subcommittee_index: u64,
            beacon_block_root: B256,
        ) -> Option<[u8; SYNC_COMMITTEE_CONTRIBUTION_SIZE]> {
            let contribution = self.contribution(slot, subcommittee_index, beacon_block_root)?;
            let mut out = [0u8; SYNC_COMMITTEE_CONTRIBUTION_SIZE];
            contribution.write_ssz(&mut out);
            Some(out)
        }
    }

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
    fn sync_aggregate_concatenates_subcommittees_for_its_root() {
        let mut pool = SyncContributionPool::new();
        assert_eq!(pool_aggregate(&pool), EMPTY_SYNC_AGGREGATE);

        pool.insert_verified(SLOT, 0, BLOCK_ROOT, &positions(&[1]), &signature(0));
        pool.insert_verified(SLOT, 2, BLOCK_ROOT, &positions(&[64]), &signature(1));
        pool.insert_verified(SLOT, 1, [0xBC; 32], &positions(&[0]), &signature(2));
        pool.insert_verified(SLOT + 1, 3, BLOCK_ROOT, &positions(&[0]), &signature(2));

        let out = pool_aggregate(&pool);
        let (bits, sig) = out.split_at(SYNC_COMMITTEE_SIZE / 8);
        let mut expected_bits = [0u8; SYNC_COMMITTEE_SIZE / 8];
        expected_bits[0] = 0b0000_0010;
        expected_bits[2 * AGGREGATION_BITS_BYTES + 8] = 0b0000_0001;
        assert_eq!(bits, expected_bits);

        let sig = Signature::from_bytes(sig).unwrap();
        let pks = [&test_signing::pubkey_pk(0), &test_signing::pubkey_pk(1)];
        assert_eq!(
            sig.fast_aggregate_verify(true, &SIGNING_ROOT, bls::DST, &pks),
            BLST_ERROR::BLST_SUCCESS
        );
    }

    /// A gossiped contribution signed by `(position, secret key)` pairs.
    fn insert_received(
        pool: &mut SyncContributionPool,
        subcommittee_index: u64,
        beacon_block_root: B256,
        signers: &[(usize, usize)],
    ) -> InsertOutcome {
        let bits = bits_of(&signers.iter().map(|&(position, _)| position).collect::<Vec<_>>());
        let mut aggregate = AggregateSignature::from_signature(&signature(signers[0].1));
        for &(_, sk_idx) in &signers[1..] {
            aggregate.add_signature(&signature(sk_idx), false).unwrap();
        }
        let aggregate = aggregate.to_signature().to_bytes();
        pool.insert_received(SLOT, subcommittee_index, beacon_block_root, &bits, &aggregate)
    }

    /// Bits of subcommittee `index` in the aggregate, and whether its signature
    /// verifies against `signers`.
    fn aggregate_bits_and_verifies(
        pool: &SyncContributionPool,
        index: usize,
        signers: &[usize],
    ) -> ([u8; AGGREGATION_BITS_BYTES], bool) {
        let out = pool_aggregate(pool);
        let start = index * AGGREGATION_BITS_BYTES;
        let bits = out[start..start + AGGREGATION_BITS_BYTES].try_into().unwrap();
        let sig = Signature::from_bytes(&out[SYNC_COMMITTEE_SIZE / 8..]).unwrap();
        let pks: Vec<_> = signers.iter().map(|&i| test_signing::pubkey_pk(i)).collect();
        let pks: Vec<_> = pks.iter().collect();
        let verifies = sig.fast_aggregate_verify(true, &SIGNING_ROOT, bls::DST, &pks) ==
            BLST_ERROR::BLST_SUCCESS;
        (bits, verifies)
    }

    fn bits_of(positions: &[usize]) -> [u8; AGGREGATION_BITS_BYTES] {
        let mut bits = [0u8; AGGREGATION_BITS_BYTES];
        for &position in positions {
            bits[position / 8] |= 1 << (position % 8);
        }
        bits
    }

    /// A proposer outside a subnet holds no messages for it; the gossiped
    /// contribution alone fills its bits.
    #[test]
    fn received_contribution_fills_a_subcommittee_without_messages() {
        let mut pool = SyncContributionPool::new();
        let outcome = insert_received(&mut pool, SUBCOMMITTEE, BLOCK_ROOT, &[(3, 0), (90, 1)]);
        assert_eq!(outcome, InsertOutcome::Inserted);

        let (bits, verifies) = aggregate_bits_and_verifies(&pool, SUBCOMMITTEE as usize, &[0, 1]);
        assert_eq!(bits, bits_of(&[3, 90]));
        assert!(verifies);
    }

    #[test]
    fn disjoint_messages_and_contribution_are_joined() {
        let mut pool = SyncContributionPool::new();
        pool.insert_verified(SLOT, SUBCOMMITTEE, BLOCK_ROOT, &positions(&[1]), &signature(0));
        insert_received(&mut pool, SUBCOMMITTEE, BLOCK_ROOT, &[(2, 1), (100, 2)]);

        let (bits, verifies) =
            aggregate_bits_and_verifies(&pool, SUBCOMMITTEE as usize, &[0, 1, 2]);
        assert_eq!(bits, bits_of(&[1, 2, 100]));
        assert!(verifies);
    }

    #[test]
    fn overlapping_messages_and_contribution_yield_the_wider() {
        let mut pool = SyncContributionPool::new();
        pool.insert_verified(SLOT, SUBCOMMITTEE, BLOCK_ROOT, &positions(&[1]), &signature(0));
        pool.insert_verified(SLOT, SUBCOMMITTEE, BLOCK_ROOT, &positions(&[2]), &signature(1));
        insert_received(&mut pool, SUBCOMMITTEE, BLOCK_ROOT, &[(2, 1), (3, 2), (4, 0)]);
        let (bits, verifies) =
            aggregate_bits_and_verifies(&pool, SUBCOMMITTEE as usize, &[1, 2, 0]);
        assert_eq!(bits, bits_of(&[2, 3, 4]), "the contribution is wider");
        assert!(verifies);

        let mut pool = SyncContributionPool::new();
        for (position, sk_idx) in [(1, 0), (2, 1), (5, 2)] {
            let mask = positions(&[position]);
            pool.insert_verified(SLOT, SUBCOMMITTEE, BLOCK_ROOT, &mask, &signature(sk_idx));
        }
        insert_received(&mut pool, SUBCOMMITTEE, BLOCK_ROOT, &[(2, 1), (3, 2)]);
        let (bits, verifies) =
            aggregate_bits_and_verifies(&pool, SUBCOMMITTEE as usize, &[0, 1, 2]);
        assert_eq!(bits, bits_of(&[1, 2, 5]), "the messages are wider");
        assert!(verifies);
    }

    #[test]
    fn only_a_wider_contribution_replaces_the_held_one() {
        let mut pool = SyncContributionPool::new();
        let wide = [(1, 0), (2, 1)];
        assert_eq!(insert_received(&mut pool, 0, BLOCK_ROOT, &wide), InsertOutcome::Inserted);
        assert_eq!(insert_received(&mut pool, 0, BLOCK_ROOT, &[(3, 2)]), InsertOutcome::Duplicate);
        assert_eq!(
            insert_received(&mut pool, 0, BLOCK_ROOT, &[(3, 2), (4, 0)]),
            InsertOutcome::Duplicate,
            "equal width keeps the first"
        );
        assert_eq!(
            insert_received(&mut pool, 0, BLOCK_ROOT, &[(3, 2), (4, 0), (5, 1)]),
            InsertOutcome::Inserted
        );
        let (bits, verifies) = aggregate_bits_and_verifies(&pool, 0, &[2, 0, 1]);
        assert_eq!(bits, bits_of(&[3, 4, 5]));
        assert!(verifies);
    }

    #[test]
    fn received_contributions_are_kept_per_root_and_pruned() {
        let mut pool = SyncContributionPool::new();
        insert_received(&mut pool, SUBCOMMITTEE, [0xBC; 32], &[(1, 0)]);
        assert_eq!(pool_aggregate(&pool), EMPTY_SYNC_AGGREGATE, "another root");

        insert_received(&mut pool, SUBCOMMITTEE, BLOCK_ROOT, &[(1, 0)]);
        assert_ne!(pool_aggregate(&pool), EMPTY_SYNC_AGGREGATE);
        pool.prune_before(SLOT + 1);
        assert_eq!(pool_aggregate(&pool), EMPTY_SYNC_AGGREGATE);
        assert_eq!(
            insert_received(&mut pool, SUBCOMMITTEE, BLOCK_ROOT, &[(1, 0)]),
            InsertOutcome::Stale
        );
    }

    fn pool_aggregate(pool: &SyncContributionPool) -> [u8; BLOCK_SYNC_AGGREGATE_SIZE] {
        let mut out = [0; BLOCK_SYNC_AGGREGATE_SIZE];
        pool.write_sync_aggregate(SLOT, BLOCK_ROOT, &mut out);
        out
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
