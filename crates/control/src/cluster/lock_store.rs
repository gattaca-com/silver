use std::{collections::hash_map::Entry, io};

use fxhash::FxHashMap;
use silver_common::{MAX_CLUSTER_MESSAGE_BYTES, SLOTS_PER_EPOCH, merkle};

use super::command::AttestationLockCommand;

/// Admission accepts `[wall - SLOTS_PER_EPOCH, wall]`, which spans at most two
/// epochs.
const LOCK_RING_SIZE: usize = 2;
const SNAPSHOT_MAGIC: &[u8; 8] = b"SLVLOCK\x01";
const MAX_SNAPSHOT_BYTES: usize = MAX_CLUSTER_MESSAGE_BYTES - 1024;

/// Result of applying a committed attestation selection command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockResult {
    /// This is the first selected attestation for the validator and target
    /// epoch.
    Accepted,
    /// The same signed attestation was selected previously; it does not
    /// conflict with the cluster's choice. Processing still requires temporal
    /// admission.
    AlreadyAcceptedSame,
    /// A different signed attestation was selected previously. This candidate
    /// must not enter validation or gossip publication.
    ConflictingAttestation,
    /// The replicated retention floor or the epoch ring has advanced beyond
    /// this attestation.
    TooOld,
}

/// Anti-equivocation state shared by standalone and replicated admission.
#[derive(Debug, Default)]
pub(crate) struct AttestationLockStore {
    /// Commands below this slot are rejected even if proposed by a node with a
    /// stale wall clock. Replicated stores advance this through committed
    /// commands.
    minimum_slot: u64,
    locks: [EpochLocks; LOCK_RING_SIZE],
}

#[derive(Debug, Default)]
struct EpochLocks {
    /// The absolute epoch occupying this modulo bucket. The tag prevents a
    /// late older command from clearing locks for a newer colliding epoch.
    epoch: Option<u64>,
    /// Full-message hashes, including the signature. Comparing only the
    /// signing root would allow a later byte-distinct candidate for the same
    /// attestation data to bypass the first-candidate-wins rule.
    attestations: FxHashMap<u64, [u8; 32]>,
}

impl AttestationLockStore {
    pub(crate) fn apply(&mut self, cmd: &AttestationLockCommand) -> LockResult {
        if cmd.key.slot < self.minimum_slot {
            return LockResult::TooOld;
        }

        let epoch = cmd.key.slot / SLOTS_PER_EPOCH;
        let bucket = &mut self.locks[epoch as usize % LOCK_RING_SIZE];
        match bucket.epoch {
            Some(bucket_epoch) if bucket_epoch > epoch => return LockResult::TooOld,
            Some(bucket_epoch) if bucket_epoch < epoch => {
                bucket.attestations.clear();
                bucket.epoch = Some(epoch);
            }
            None => bucket.epoch = Some(epoch),
            Some(_) => {}
        }

        let attestation_hash = merkle::sha256(&cmd.ssz);
        match bucket.attestations.entry(cmd.key.attester_index) {
            Entry::Vacant(entry) => {
                entry.insert(attestation_hash);
                LockResult::Accepted
            }
            Entry::Occupied(entry) if entry.get() == &attestation_hash => {
                LockResult::AlreadyAcceptedSame
            }
            Entry::Occupied(_) => LockResult::ConflictingAttestation,
        }
    }

    pub(super) fn minimum_slot(&self) -> u64 {
        self.minimum_slot
    }

    pub(super) fn encode_snapshot(&self) -> io::Result<Vec<u8>> {
        let retained = |bucket: &EpochLocks| {
            bucket.epoch.is_some_and(|epoch| epoch >= self.minimum_slot / SLOTS_PER_EPOCH)
        };
        let count: usize = self
            .locks
            .iter()
            .filter(|bucket| retained(bucket))
            .map(|bucket| bucket.attestations.len())
            .sum();
        let length = count
            .checked_mul(40)
            .and_then(|n| n.checked_add(16 + LOCK_RING_SIZE * 13))
            .filter(|n| *n <= MAX_SNAPSHOT_BYTES)
            .ok_or_else(|| invalid_snapshot("attestation lock snapshot exceeds transport limit"))?;
        let mut bytes = Vec::with_capacity(length);
        bytes.extend_from_slice(SNAPSHOT_MAGIC);
        bytes.extend_from_slice(&self.minimum_slot.to_le_bytes());
        for bucket in &self.locks {
            let Some(epoch) = bucket.epoch else {
                bytes.push(0);
                continue;
            };
            // Keep the epoch tag even when its locks expired: it prevents ring reuse by
            // older commands.
            bytes.push(1);
            bytes.extend_from_slice(&epoch.to_le_bytes());
            let count = if retained(bucket) { bucket.attestations.len() } else { 0 };
            bytes.extend_from_slice(&(count as u32).to_le_bytes());
            if count != 0 {
                for (validator, hash) in &bucket.attestations {
                    bytes.extend_from_slice(&validator.to_le_bytes());
                    bytes.extend_from_slice(hash);
                }
            }
        }
        Ok(bytes)
    }

    pub(super) fn decode_snapshot(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() > MAX_SNAPSHOT_BYTES {
            return Err(invalid_snapshot("attestation lock snapshot exceeds transport limit"));
        }
        let mut cursor = SnapshotCursor(bytes);
        if &cursor.take::<8>()? != SNAPSHOT_MAGIC {
            return Err(invalid_snapshot("unsupported attestation lock snapshot"));
        }
        let mut store =
            Self { minimum_slot: u64::from_le_bytes(cursor.take()?), ..Self::default() };
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
            if count > cursor.0.len() / 40 {
                return Err(invalid_snapshot("invalid snapshot lock count"));
            }
            bucket.attestations.reserve(count);
            for _ in 0..count {
                let validator = u64::from_le_bytes(cursor.take()?);
                if bucket.attestations.insert(validator, cursor.take()?).is_some() {
                    return Err(invalid_snapshot("duplicate validator in snapshot epoch"));
                }
            }
        }
        if !cursor.0.is_empty() {
            return Err(invalid_snapshot("trailing attestation snapshot bytes"));
        }
        Ok(store)
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.locks
            .iter()
            .filter(|bucket| {
                bucket.epoch.is_some_and(|epoch| epoch >= self.minimum_slot / SLOTS_PER_EPOCH)
            })
            .map(|bucket| bucket.attestations.len())
            .sum()
    }

    /// Advance the retention floor. Inaccessible buckets retain
    /// their allocations and are cleared lazily when their ring slot is reused.
    pub(crate) fn advance_minimum_slot(&mut self, minimum_slot: u64) {
        if minimum_slot <= self.minimum_slot {
            return;
        }

        self.minimum_slot = minimum_slot;
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

    fn command_for(slot: u64, validator: u8, root: u8) -> AttestationLockCommand {
        let mut ssz = [0; silver_common::ssz_view::SINGLE_ATT_SIZE];
        ssz[0] = root;
        AttestationLockCommand {
            key: AttestationKey { attester_index: u64::from(validator), slot },
            subnet: u64::from(root) % silver_common::ATTESTATION_SUBNETS as u64,
            ssz,
        }
    }

    #[test]
    fn snapshot_preserves_epoch_locks_floor_and_ring_reuse_protection() {
        let mut store = AttestationLockStore::default();
        store.apply(&command_for(10, 7, 1));
        store.apply(&command_for(40, 8, 2));
        store.advance_minimum_slot(20);
        let mut restored =
            AttestationLockStore::decode_snapshot(&store.encode_snapshot().unwrap()).unwrap();
        assert_eq!(restored.minimum_slot(), 20);
        assert_eq!(restored.apply(&command_for(10, 7, 1)), LockResult::TooOld);
        assert_eq!(restored.apply(&command_for(21, 7, 3)), LockResult::ConflictingAttestation);
        assert_eq!(restored.apply(&command_for(40, 8, 2)), LockResult::AlreadyAcceptedSame);

        store.apply(&command_for(100, 9, 4));
        let mut restored =
            AttestationLockStore::decode_snapshot(&store.encode_snapshot().unwrap()).unwrap();
        assert_eq!(restored.apply(&command_for(40, 8, 2)), LockResult::TooOld);
        assert_eq!(restored.apply(&command_for(100, 9, 4)), LockResult::AlreadyAcceptedSame);
        store.advance_minimum_slot(128);
        let bytes = store.encode_snapshot().unwrap();
        assert!(bytes.len() < 64, "expired hashes should not be serialized");
        let restored = AttestationLockStore::decode_snapshot(&bytes).unwrap();
        assert_eq!(restored.minimum_slot(), 128);
    }

    #[test]
    fn malformed_lock_snapshots_are_rejected() {
        let mut store = AttestationLockStore::default();
        store.apply(&command_for(10, 7, 1));
        let bytes = store.encode_snapshot().unwrap();
        for len in 0..bytes.len() {
            assert!(AttestationLockStore::decode_snapshot(&bytes[..len]).is_err());
        }
        let mut invalid = bytes.clone();
        invalid.push(0);
        assert!(AttestationLockStore::decode_snapshot(&invalid).is_err());
        let mut invalid = bytes.clone();
        invalid[16] = 2;
        assert!(AttestationLockStore::decode_snapshot(&invalid).is_err());
        let mut invalid = bytes.clone();
        invalid[17] = 1;
        assert!(AttestationLockStore::decode_snapshot(&invalid).is_err());
        let mut duplicate = bytes;
        duplicate[25..29].copy_from_slice(&2u32.to_le_bytes());
        let record = duplicate[29..69].to_vec();
        duplicate.splice(69..69, record);
        assert!(AttestationLockStore::decode_snapshot(&duplicate).is_err());
    }

    #[test]
    fn selection_results_distinguish_same_and_conflicting_attestations() {
        let mut store = AttestationLockStore::default();

        assert_eq!(store.apply(&command(12, 1)), LockResult::Accepted);
        assert_eq!(store.apply(&command(12, 1)), LockResult::AlreadyAcceptedSame);
        assert_eq!(store.apply(&command(12, 2)), LockResult::ConflictingAttestation);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn different_signed_bytes_conflict() {
        let mut store = AttestationLockStore::default();
        let first = command(12, 1);
        let mut different = first;
        different.ssz[1] = 1;

        assert_eq!(store.apply(&first), LockResult::Accepted);
        assert_eq!(store.apply(&different), LockResult::ConflictingAttestation);
    }

    #[test]
    fn different_slots_in_one_target_epoch_conflict() {
        let mut store = AttestationLockStore::default();

        assert_eq!(store.apply(&command_for(10, 7, 1)), LockResult::Accepted);
        assert_eq!(store.apply(&command_for(11, 7, 2)), LockResult::ConflictingAttestation);
        assert_eq!(store.apply(&command_for(11, 8, 2)), LockResult::Accepted);
        assert_eq!(store.apply(&command_for(32, 7, 3)), LockResult::Accepted);
    }

    #[test]
    fn committed_minimum_slot_hides_and_rejects_old_commands() {
        let mut store = AttestationLockStore::default();
        assert_eq!(store.apply(&command(10, 1)), LockResult::Accepted);
        assert_eq!(store.apply(&command(40, 2)), LockResult::Accepted);

        store.advance_minimum_slot(40);

        assert_eq!(store.minimum_slot(), 40);
        assert_eq!(store.len(), 1);
        assert_eq!(store.apply(&command(10, 3)), LockResult::TooOld);
        assert_eq!(store.apply(&command(40, 3)), LockResult::ConflictingAttestation);
    }

    #[test]
    fn epoch_ring_reuses_a_bucket_without_losing_newer_locks() {
        let mut store = AttestationLockStore::default();
        assert_eq!(store.locks.len(), 2);

        assert_eq!(store.apply(&command_for(10, 7, 1)), LockResult::Accepted);
        assert_eq!(store.apply(&command_for(10, 8, 2)), LockResult::Accepted);
        assert_eq!(store.apply(&command_for(40, 7, 3)), LockResult::Accepted);
        assert_eq!(store.len(), 3);

        // Epoch 2 reuses epoch 0's modulo bucket and drops only that bucket.
        assert_eq!(store.apply(&command_for(70, 9, 4)), LockResult::Accepted);
        assert_eq!(store.len(), 2);
        assert_eq!(store.apply(&command_for(70, 9, 4)), LockResult::AlreadyAcceptedSame);
        assert_eq!(store.apply(&command_for(70, 9, 5)), LockResult::ConflictingAttestation);

        // A late command for the displaced epoch cannot clear epoch 2.
        assert_eq!(store.apply(&command_for(10, 7, 6)), LockResult::TooOld);
        assert_eq!(store.apply(&command_for(70, 9, 4)), LockResult::AlreadyAcceptedSame);

        // The adjacent bucket was not scanned or cleared during rollover.
        assert_eq!(store.apply(&command_for(40, 7, 6)), LockResult::ConflictingAttestation);
    }
}
