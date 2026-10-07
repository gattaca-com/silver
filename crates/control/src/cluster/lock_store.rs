use std::{collections::hash_map::Entry, io};

use fxhash::FxHashMap;
use silver_common::{
    MAX_CLUSTER_MESSAGE_BYTES, SLOTS_PER_EPOCH, merkle, ssz_view::SingleAttestationView,
};

use super::command::{AttestationLockCommand, BlockKey, BlockLockCommand};

/// Admission accepts `[wall - SLOTS_PER_EPOCH, wall]`, which spans at most two
/// epochs.
const LOCK_RING_SIZE: usize = 2;
const SNAPSHOT_MAGIC: &[u8; 8] = b"SLVLOCK\x03";
const SNAPSHOT_BLOCK_LEN: usize = 8 + 8 + 96;
const MAX_SNAPSHOT_BYTES: usize = MAX_CLUSTER_MESSAGE_BYTES - 1024;
const SNAPSHOT_FIXED_LEN: usize = 8 + 8 + 8 + LOCK_RING_SIZE * SNAPSHOT_BUCKET_LEN + 4 + 4;
const SNAPSHOT_BUCKET_LEN: usize = 1 + 8 + 4;
const SNAPSHOT_VOTE_LEN: usize = 8 + 32 + 8;
const SNAPSHOT_EVICTED_LEN: usize = 8 + 8;

/// Result of applying a committed attestation or block lock command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockResult {
    /// The first message selected for its validator: the attestation's
    /// target epoch, or the block's slot.
    Accepted,
    /// The same signed message was selected previously; it does not conflict
    /// with the cluster's choice. Processing still requires temporal
    /// admission.
    AlreadyAcceptedSame,
    /// A different signed message was selected previously. This candidate
    /// must not enter validation or gossip publication.
    Conflicting,
    /// Surrounds or is surrounded by a selected attestation.
    Surrounding,
    /// The replicated retention floor or the epoch ring has advanced beyond
    /// this message.
    TooOld,
    Invalid,
}

/// Anti-equivocation state shared by standalone and replicated admission.
#[derive(Debug, Default)]
pub(crate) struct SlashingLockStore {
    /// Commands below this slot are rejected even if proposed by a node with a
    /// stale wall clock. Replicated stores advance this through committed
    /// commands.
    minimum_slot: u64,
    minimum_target: u64,
    locks: [EpochLocks; LOCK_RING_SIZE],
    /// Maximum evicted source per validator. Targets below `minimum_target` are
    /// refused, so a new vote surrounds an evicted vote exactly when its
    /// source is lower.
    evicted_sources: FxHashMap<u64, u64>,
    blocks: FxHashMap<BlockKey, [u8; 96]>,
}

#[derive(Debug, Default)]
struct EpochLocks {
    /// The absolute epoch occupying this modulo bucket. The tag prevents a
    /// late older command from clearing locks for a newer colliding epoch.
    epoch: Option<u64>,
    attestations: FxHashMap<u64, Vote>,
}

#[derive(Debug, Clone, Copy)]
struct Vote {
    /// Includes the signature so byte-distinct retries cannot bypass the lock.
    hash: [u8; 32],
    source: u64,
}

impl SlashingLockStore {
    pub(crate) fn apply(&mut self, cmd: &AttestationLockCommand) -> LockResult {
        let target = cmd.key.slot / SLOTS_PER_EPOCH;
        let source = SingleAttestationView::source_epoch(&cmd.ssz);
        // A malformed source could otherwise block the validator permanently.
        if SingleAttestationView::target_epoch(&cmd.ssz) != target || source > target {
            return LockResult::Invalid;
        }
        if cmd.key.slot < self.minimum_slot || target < self.minimum_target {
            return LockResult::TooOld;
        }

        let bucket = target as usize % LOCK_RING_SIZE;
        match self.locks[bucket].epoch {
            Some(bucket_epoch) if bucket_epoch > target => return LockResult::TooOld,
            Some(bucket_epoch) if bucket_epoch < target => {
                self.evict_below(bucket_epoch + 1);
                self.locks[bucket].epoch = Some(target);
            }
            None => self.locks[bucket].epoch = Some(target),
            Some(_) => {}
        }

        let validator = cmd.key.attester_index;
        let hash = merkle::sha256(&cmd.ssz);
        match self.locks[bucket].attestations.get(&validator) {
            Some(vote) if vote.hash == hash => return LockResult::AlreadyAcceptedSame,
            Some(_) => return LockResult::Conflicting,
            None => {}
        }
        if self.is_surround_vote(validator, source, target) {
            return LockResult::Surrounding;
        }
        self.locks[bucket].attestations.insert(validator, Vote { hash, source });
        LockResult::Accepted
    }

    fn is_surround_vote(&self, validator: u64, source: u64, target: u64) -> bool {
        if self.evicted_sources.get(&validator).is_some_and(|&evicted| source < evicted) {
            return true;
        }
        self.locks.iter().any(|bucket| {
            let (Some(epoch), Some(vote)) = (bucket.epoch, bucket.attestations.get(&validator))
            else {
                return false;
            };
            (source < vote.source && epoch < target) || (vote.source < source && target < epoch)
        })
    }

    fn evict_below(&mut self, minimum_target: u64) {
        if minimum_target <= self.minimum_target {
            return;
        }

        self.minimum_target = minimum_target;
        for bucket in &mut self.locks {
            if bucket.epoch.is_some_and(|epoch| epoch < minimum_target) {
                for (&validator, vote) in &bucket.attestations {
                    let evicted = self.evicted_sources.entry(validator).or_insert(vote.source);
                    *evicted = (*evicted).max(vote.source);
                }
                bucket.attestations.clear();
            }
        }
    }

    pub(crate) fn apply_block(&mut self, cmd: &BlockLockCommand) -> LockResult {
        if cmd.key.slot < self.minimum_slot {
            return LockResult::TooOld;
        }
        match self.blocks.entry(cmd.key) {
            Entry::Vacant(entry) => {
                entry.insert(cmd.signature);
                LockResult::Accepted
            }
            Entry::Occupied(entry) if entry.get() == &cmd.signature => {
                LockResult::AlreadyAcceptedSame
            }
            Entry::Occupied(_) => LockResult::Conflicting,
        }
    }

    pub(super) fn minimum_slot(&self) -> u64 {
        self.minimum_slot
    }

    pub(super) fn encode_snapshot(&self) -> io::Result<Vec<u8>> {
        let votes: usize = self.locks.iter().map(|bucket| bucket.attestations.len()).sum();
        let length = SNAPSHOT_FIXED_LEN +
            votes * SNAPSHOT_VOTE_LEN +
            self.evicted_sources.len() * SNAPSHOT_EVICTED_LEN +
            self.blocks.len() * SNAPSHOT_BLOCK_LEN;
        if length > MAX_SNAPSHOT_BYTES {
            return Err(invalid_snapshot("lock snapshot exceeds transport limit"));
        }
        let mut bytes = Vec::with_capacity(length);
        bytes.extend_from_slice(SNAPSHOT_MAGIC);
        bytes.extend_from_slice(&self.minimum_slot.to_le_bytes());
        bytes.extend_from_slice(&self.minimum_target.to_le_bytes());
        for bucket in &self.locks {
            let Some(epoch) = bucket.epoch else {
                bytes.push(0);
                continue;
            };
            // Keep the epoch tag even when its locks expired: it prevents ring reuse by
            // older commands.
            bytes.push(1);
            bytes.extend_from_slice(&epoch.to_le_bytes());
            bytes.extend_from_slice(&(bucket.attestations.len() as u32).to_le_bytes());
            for (validator, vote) in &bucket.attestations {
                bytes.extend_from_slice(&validator.to_le_bytes());
                bytes.extend_from_slice(&vote.hash);
                bytes.extend_from_slice(&vote.source.to_le_bytes());
            }
        }
        bytes.extend_from_slice(&(self.evicted_sources.len() as u32).to_le_bytes());
        for (validator, source) in &self.evicted_sources {
            bytes.extend_from_slice(&validator.to_le_bytes());
            bytes.extend_from_slice(&source.to_le_bytes());
        }
        bytes.extend_from_slice(&(self.blocks.len() as u32).to_le_bytes());
        for (key, signature) in &self.blocks {
            bytes.extend_from_slice(&key.proposer_index.to_le_bytes());
            bytes.extend_from_slice(&key.slot.to_le_bytes());
            bytes.extend_from_slice(signature);
        }
        Ok(bytes)
    }

    pub(super) fn decode_snapshot(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() > MAX_SNAPSHOT_BYTES {
            return Err(invalid_snapshot("lock snapshot exceeds transport limit"));
        }
        let mut cursor = SnapshotCursor(bytes);
        if &cursor.take::<8>()? != SNAPSHOT_MAGIC {
            return Err(invalid_snapshot("unsupported attestation lock snapshot"));
        }
        let mut store = Self {
            minimum_slot: u64::from_le_bytes(cursor.take()?),
            minimum_target: u64::from_le_bytes(cursor.take()?),
            ..Self::default()
        };
        for (index, bucket) in store.locks.iter_mut().enumerate() {
            match cursor.take::<1>()?[0] {
                0 => continue,
                1 => {}
                _ => return Err(invalid_snapshot("invalid snapshot epoch tag")),
            }
            let epoch = u64::from_le_bytes(cursor.take()?);
            if epoch as usize % LOCK_RING_SIZE != index {
                return Err(invalid_snapshot("snapshot epoch is in the wrong ring bucket"));
            }
            bucket.epoch = Some(epoch);
            let count = u32::from_le_bytes(cursor.take()?) as usize;
            if count > cursor.0.len() / SNAPSHOT_VOTE_LEN {
                return Err(invalid_snapshot("invalid snapshot lock count"));
            }
            bucket.attestations.reserve(count);
            for _ in 0..count {
                let validator = u64::from_le_bytes(cursor.take()?);
                let vote =
                    Vote { hash: cursor.take()?, source: u64::from_le_bytes(cursor.take()?) };
                if bucket.attestations.insert(validator, vote).is_some() {
                    return Err(invalid_snapshot("duplicate validator in snapshot epoch"));
                }
            }
        }
        let count = u32::from_le_bytes(cursor.take()?) as usize;
        if count > cursor.0.len() / SNAPSHOT_EVICTED_LEN {
            return Err(invalid_snapshot("invalid snapshot evicted source count"));
        }
        store.evicted_sources.reserve(count);
        for _ in 0..count {
            let validator = u64::from_le_bytes(cursor.take()?);
            let source = u64::from_le_bytes(cursor.take()?);
            if store.evicted_sources.insert(validator, source).is_some() {
                return Err(invalid_snapshot("duplicate validator in evicted sources"));
            }
        }
        let count = u32::from_le_bytes(cursor.take()?) as usize;
        if count > cursor.0.len() / SNAPSHOT_BLOCK_LEN {
            return Err(invalid_snapshot("invalid snapshot block count"));
        }
        store.blocks.reserve(count);
        for _ in 0..count {
            let proposer_index = u64::from_le_bytes(cursor.take()?);
            let slot = u64::from_le_bytes(cursor.take()?);
            if slot < store.minimum_slot {
                return Err(invalid_snapshot("snapshot block is below the minimum slot"));
            }
            let key = BlockKey { proposer_index, slot };
            if store.blocks.insert(key, cursor.take()?).is_some() {
                return Err(invalid_snapshot("duplicate block in snapshot"));
            }
        }
        if !cursor.0.is_empty() {
            return Err(invalid_snapshot("trailing attestation snapshot bytes"));
        }
        Ok(store)
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.locks.iter().map(|bucket| bucket.attestations.len()).sum()
    }

    pub(crate) fn advance_minimum_slot(&mut self, minimum_slot: u64) {
        if minimum_slot <= self.minimum_slot {
            return;
        }

        self.minimum_slot = minimum_slot;
        self.evict_below(minimum_slot / SLOTS_PER_EPOCH);
        self.blocks.retain(|key, _| key.slot >= minimum_slot);
    }
}

struct SnapshotCursor<'a>(&'a [u8]);

impl SnapshotCursor<'_> {
    fn take<const N: usize>(&mut self) -> io::Result<[u8; N]> {
        let (bytes, rest) = self
            .0
            .split_at_checked(N)
            .ok_or_else(|| invalid_snapshot("truncated attestation snapshot"))?;
        self.0 = rest;
        bytes.try_into().map_err(|_| invalid_snapshot("invalid attestation snapshot field"))
    }
}

fn invalid_snapshot(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster::AttestationKey;

    fn command(slot: u64, root: u8) -> AttestationLockCommand {
        command_for(slot, 7, root)
    }

    fn command_for(slot: u64, validator: u64, root: u8) -> AttestationLockCommand {
        let mut ssz = [0; silver_common::ssz_view::SINGLE_ATT_SIZE];
        ssz[0] = root;
        ssz[104..112].copy_from_slice(&(slot / SLOTS_PER_EPOCH).to_le_bytes());
        AttestationLockCommand {
            key: AttestationKey { attester_index: validator, slot },
            subnet: u64::from(root) % silver_common::ATTESTATION_SUBNETS as u64,
            ssz,
        }
    }

    fn vote(validator: u64, source: u64, target: u64) -> AttestationLockCommand {
        let mut command = command_for(target * SLOTS_PER_EPOCH, validator, 0);
        command.ssz[64..72].copy_from_slice(&source.to_le_bytes());
        command
    }

    #[test]
    fn surround_votes_against_selected_attestations_are_refused_both_ways() {
        let mut store = SlashingLockStore::default();
        assert_eq!(store.apply(&vote(7, 3, 5)), LockResult::Accepted);

        assert_eq!(store.apply(&vote(7, 4, 4)), LockResult::Surrounding, "surrounded by (3, 5)");
        assert_eq!(store.apply(&vote(7, 2, 6)), LockResult::Surrounding, "surrounds (3, 5)");
        assert_eq!(
            store.apply(&vote(8, 2, 6)),
            LockResult::Accepted,
            "other validators vote freely"
        );
    }

    #[test]
    fn non_surrounding_votes_are_accepted_in_any_order() {
        let mut store = SlashingLockStore::default();
        assert_eq!(store.apply(&vote(7, 3, 5)), LockResult::Accepted);
        assert_eq!(
            store.apply(&vote(7, 2, 4)),
            LockResult::Accepted,
            "earlier target, lower source"
        );

        let mut store = SlashingLockStore::default();
        assert_eq!(store.apply(&vote(7, 3, 5)), LockResult::Accepted);
        assert_eq!(store.apply(&vote(7, 3, 4)), LockResult::Accepted, "same source");
        assert_eq!(store.apply(&vote(7, 3, 6)), LockResult::Accepted, "same source");
    }

    #[test]
    fn surround_of_an_evicted_attestation_is_refused() {
        let mut store = SlashingLockStore::default();
        assert_eq!(store.apply(&vote(7, 3, 5)), LockResult::Accepted);
        assert_eq!(store.apply(&vote(7, 4, 7)), LockResult::Accepted, "reuses epoch 5's bucket");

        assert_eq!(store.apply(&vote(7, 2, 6)), LockResult::Surrounding, "surrounds (3, 5)");
        assert_eq!(store.apply(&vote(8, 2, 6)), LockResult::Accepted);
    }

    #[test]
    fn evicted_sources_keep_the_highest_per_validator() {
        let mut store = SlashingLockStore::default();
        assert_eq!(store.apply(&vote(7, 4, 6)), LockResult::Accepted);
        assert_eq!(store.apply(&vote(7, 3, 5)), LockResult::Accepted);
        store.advance_minimum_slot(7 * SLOTS_PER_EPOCH);

        assert_eq!(store.apply(&vote(7, 3, 7)), LockResult::Surrounding, "surrounds (4, 6)");
        assert_eq!(store.apply(&vote(7, 4, 7)), LockResult::Accepted);

        assert_eq!(store.apply(&vote(8, 3, 7)), LockResult::Accepted);
        store.advance_minimum_slot(8 * SLOTS_PER_EPOCH);
        assert_eq!(store.apply(&vote(8, 4, 8)), LockResult::Accepted);
        store.advance_minimum_slot(9 * SLOTS_PER_EPOCH);
        assert_eq!(store.apply(&vote(8, 3, 9)), LockResult::Surrounding, "surrounds (4, 8)");
    }

    #[test]
    fn eviction_refuses_every_lower_target() {
        let mut store = SlashingLockStore::default();
        assert_eq!(store.apply(&vote(7, 0, 3)), LockResult::Accepted);
        assert_eq!(store.apply(&vote(8, 0, 4)), LockResult::Accepted);
        assert_eq!(store.apply(&vote(9, 0, 6)), LockResult::Accepted, "reuses epoch 4's bucket");

        assert_eq!(
            store.apply(&vote(8, 1, 3)),
            LockResult::TooOld,
            "(0, 4) surrounds it, but only its source is kept"
        );
    }

    #[test]
    fn malformed_votes_are_refused_without_a_lock() {
        let mut store = SlashingLockStore::default();
        let mut wrong_target = vote(7, 3, 5);
        wrong_target.ssz[104..112].copy_from_slice(&6u64.to_le_bytes());

        assert_eq!(store.apply(&vote(7, 6, 5)), LockResult::Invalid, "source after target");
        assert_eq!(store.apply(&wrong_target), LockResult::Invalid);
        assert_eq!(store.apply(&vote(7, 3, 5)), LockResult::Accepted);
    }

    #[test]
    fn snapshot_preserves_vote_sources_and_the_target_floor() {
        let mut store = SlashingLockStore::default();
        store.apply(&vote(7, 0, 3));
        store.apply(&vote(8, 2, 4));
        store.apply(&vote(9, 2, 6));
        let mut restored =
            SlashingLockStore::decode_snapshot(&store.encode_snapshot().unwrap()).unwrap();

        assert_eq!(restored.apply(&vote(7, 1, 3)), LockResult::TooOld);
        assert_eq!(restored.apply(&vote(8, 1, 5)), LockResult::Surrounding, "surrounds (2, 4)");
        assert_eq!(restored.apply(&vote(9, 1, 7)), LockResult::Surrounding, "surrounds (2, 6)");
        assert_eq!(restored.apply(&vote(9, 2, 7)), LockResult::Accepted);
    }

    #[test]
    fn snapshot_fits_the_documented_cluster_capacity() {
        let mut store = SlashingLockStore::default();
        for slot in 0..=SLOTS_PER_EPOCH {
            assert_eq!(store.apply_block(&block(slot, slot, 1)), LockResult::Accepted);
        }
        for target in 1..=3 {
            for validator in 0..149_753 {
                assert_eq!(store.apply(&vote(validator, target - 1, target)), LockResult::Accepted);
            }
        }

        assert!(store.encode_snapshot().is_ok());
    }

    #[test]
    fn duplicate_evicted_sources_are_rejected() {
        let mut store = SlashingLockStore::default();
        store.apply(&vote(7, 0, 3));
        store.advance_minimum_slot(4 * SLOTS_PER_EPOCH);
        let mut bytes = store.encode_snapshot().unwrap();
        let blocks_at = bytes.len() - 4;
        let record = blocks_at - SNAPSHOT_EVICTED_LEN..blocks_at;
        bytes[record.start - 4..record.start].copy_from_slice(&2u32.to_le_bytes());
        let duplicate = bytes[record.clone()].to_vec();
        bytes.splice(record.end..record.end, duplicate);

        assert!(SlashingLockStore::decode_snapshot(&bytes).is_err());
    }

    #[test]
    fn snapshot_preserves_epoch_locks_floor_and_ring_reuse_protection() {
        let mut store = SlashingLockStore::default();
        store.apply(&command_for(10, 7, 1));
        store.apply(&command_for(40, 8, 2));
        store.advance_minimum_slot(20);
        let mut restored =
            SlashingLockStore::decode_snapshot(&store.encode_snapshot().unwrap()).unwrap();
        assert_eq!(restored.minimum_slot(), 20);
        assert_eq!(restored.apply(&command_for(10, 7, 1)), LockResult::TooOld);
        assert_eq!(restored.apply(&command_for(21, 7, 3)), LockResult::Conflicting);
        assert_eq!(restored.apply(&command_for(40, 8, 2)), LockResult::AlreadyAcceptedSame);

        store.apply(&command_for(100, 9, 4));
        let mut restored =
            SlashingLockStore::decode_snapshot(&store.encode_snapshot().unwrap()).unwrap();
        assert_eq!(restored.apply(&command_for(40, 8, 2)), LockResult::TooOld);
        assert_eq!(restored.apply(&command_for(100, 9, 4)), LockResult::AlreadyAcceptedSame);
        store.advance_minimum_slot(128);
        let restored =
            SlashingLockStore::decode_snapshot(&store.encode_snapshot().unwrap()).unwrap();
        assert_eq!(restored.minimum_slot(), 128);
        assert_eq!(restored.len(), 0, "expired hashes should not be serialized");
    }

    #[test]
    fn snapshot_preserves_block_locks() {
        let mut store = SlashingLockStore::default();
        store.apply_block(&block(10, 3, 1));
        store.apply_block(&block(30, 4, 2));
        store.advance_minimum_slot(20);

        let mut restored =
            SlashingLockStore::decode_snapshot(&store.encode_snapshot().unwrap()).unwrap();

        assert_eq!(restored.apply_block(&block(10, 3, 1)), LockResult::TooOld);
        assert_eq!(restored.apply_block(&block(30, 4, 2)), LockResult::AlreadyAcceptedSame);
        assert_eq!(restored.apply_block(&block(30, 4, 5)), LockResult::Conflicting);
    }

    #[test]
    fn malformed_lock_snapshots_are_rejected() {
        let mut store = SlashingLockStore::default();
        store.apply(&command_for(10, 7, 1));
        let bytes = store.encode_snapshot().unwrap();
        for len in 0..bytes.len() {
            assert!(SlashingLockStore::decode_snapshot(&bytes[..len]).is_err());
        }
        let mut invalid = bytes.clone();
        invalid.push(0);
        assert!(SlashingLockStore::decode_snapshot(&invalid).is_err());
        let tag = 24;
        let mut invalid = bytes.clone();
        invalid[tag] = 2;
        assert!(SlashingLockStore::decode_snapshot(&invalid).is_err());
        let mut invalid = bytes.clone();
        invalid[tag + 1] = 1;
        assert!(SlashingLockStore::decode_snapshot(&invalid).is_err());
        let count = tag + 1 + 8;
        let record = count + 4..count + 4 + SNAPSHOT_VOTE_LEN;
        let mut duplicate = bytes.clone();
        duplicate[count..count + 4].copy_from_slice(&2u32.to_le_bytes());
        duplicate.splice(record.end..record.end, bytes[record].to_vec());
        assert!(SlashingLockStore::decode_snapshot(&duplicate).is_err());
    }

    #[test]
    fn malformed_block_snapshots_are_rejected() {
        let mut store = SlashingLockStore::default();
        store.apply_block(&block(10, 3, 1));
        let bytes = store.encode_snapshot().unwrap();
        let blocks_at = bytes.len() - 4 - SNAPSHOT_BLOCK_LEN;
        for len in 0..bytes.len() {
            assert!(SlashingLockStore::decode_snapshot(&bytes[..len]).is_err());
        }

        let mut duplicate = bytes.clone();
        duplicate[blocks_at..blocks_at + 4].copy_from_slice(&2u32.to_le_bytes());
        duplicate.extend_from_slice(&bytes[blocks_at + 4..]);
        assert!(SlashingLockStore::decode_snapshot(&duplicate).is_err());

        let mut below_floor = bytes;
        below_floor[8..16].copy_from_slice(&11u64.to_le_bytes());
        assert!(SlashingLockStore::decode_snapshot(&below_floor).is_err());
    }

    #[test]
    fn selection_results_distinguish_same_and_conflicting_attestations() {
        let mut store = SlashingLockStore::default();

        assert_eq!(store.apply(&command(12, 1)), LockResult::Accepted);
        assert_eq!(store.apply(&command(12, 1)), LockResult::AlreadyAcceptedSame);
        assert_eq!(store.apply(&command(12, 2)), LockResult::Conflicting);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn different_signed_bytes_conflict() {
        let mut store = SlashingLockStore::default();
        let first = command(12, 1);
        let mut different = first;
        different.ssz[1] = 1;

        assert_eq!(store.apply(&first), LockResult::Accepted);
        assert_eq!(store.apply(&different), LockResult::Conflicting);
    }

    #[test]
    fn different_slots_in_one_target_epoch_conflict() {
        let mut store = SlashingLockStore::default();

        assert_eq!(store.apply(&command_for(10, 7, 1)), LockResult::Accepted);
        assert_eq!(store.apply(&command_for(11, 7, 2)), LockResult::Conflicting);
        assert_eq!(store.apply(&command_for(11, 8, 2)), LockResult::Accepted);
        assert_eq!(store.apply(&command_for(32, 7, 3)), LockResult::Accepted);
    }

    #[test]
    fn committed_minimum_slot_hides_and_rejects_old_commands() {
        let mut store = SlashingLockStore::default();
        assert_eq!(store.apply(&command(10, 1)), LockResult::Accepted);
        assert_eq!(store.apply(&command(40, 2)), LockResult::Accepted);

        store.advance_minimum_slot(40);

        assert_eq!(store.minimum_slot(), 40);
        assert_eq!(store.len(), 1);
        assert_eq!(store.apply(&command(10, 3)), LockResult::TooOld);
        assert_eq!(store.apply(&command(40, 3)), LockResult::Conflicting);
    }

    fn block(slot: u64, proposer_index: u64, signature: u8) -> BlockLockCommand {
        BlockLockCommand { key: BlockKey { proposer_index, slot }, signature: [signature; 96] }
    }

    #[test]
    fn first_block_for_a_proposer_and_slot_is_the_only_one() {
        let mut store = SlashingLockStore::default();

        assert_eq!(store.apply_block(&block(12, 3, 1)), LockResult::Accepted);
        assert_eq!(store.apply_block(&block(12, 3, 1)), LockResult::AlreadyAcceptedSame);
        assert_eq!(store.apply_block(&block(12, 3, 2)), LockResult::Conflicting);
        assert_eq!(store.apply_block(&block(12, 4, 2)), LockResult::Accepted);
        assert_eq!(store.apply_block(&block(13, 3, 2)), LockResult::Accepted);
    }

    #[test]
    fn committed_minimum_slot_drops_and_rejects_old_blocks() {
        let mut store = SlashingLockStore::default();
        assert_eq!(store.apply_block(&block(10, 3, 1)), LockResult::Accepted);

        store.advance_minimum_slot(11);

        assert!(store.blocks.is_empty());
        assert_eq!(store.apply_block(&block(10, 3, 1)), LockResult::TooOld);
    }

    #[test]
    fn epoch_ring_reuses_a_bucket_without_losing_newer_locks() {
        let mut store = SlashingLockStore::default();
        assert_eq!(store.locks.len(), 2);

        assert_eq!(store.apply(&command_for(10, 7, 1)), LockResult::Accepted);
        assert_eq!(store.apply(&command_for(10, 8, 2)), LockResult::Accepted);
        assert_eq!(store.apply(&command_for(40, 7, 3)), LockResult::Accepted);
        assert_eq!(store.len(), 3);

        // Epoch 2 reuses epoch 0's modulo bucket and drops only that bucket.
        assert_eq!(store.apply(&command_for(70, 9, 4)), LockResult::Accepted);
        assert_eq!(store.len(), 2);
        assert_eq!(store.apply(&command_for(70, 9, 4)), LockResult::AlreadyAcceptedSame);
        assert_eq!(store.apply(&command_for(70, 9, 5)), LockResult::Conflicting);

        // A late command for the displaced epoch cannot clear epoch 2.
        assert_eq!(store.apply(&command_for(10, 7, 6)), LockResult::TooOld);
        assert_eq!(store.apply(&command_for(70, 9, 4)), LockResult::AlreadyAcceptedSame);

        // The adjacent bucket was not scanned or cleared during rollover.
        assert_eq!(store.apply(&command_for(40, 7, 6)), LockResult::Conflicting);
    }
}
