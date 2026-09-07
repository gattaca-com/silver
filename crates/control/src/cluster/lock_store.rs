use std::collections::hash_map::Entry;

use fxhash::FxHashMap;
use silver_common::{SLOTS_PER_EPOCH, merkle};

use super::command::AttestationLockCommand;

const LOCK_RING_SIZE: usize = SLOTS_PER_EPOCH as usize;

/// Result of applying a committed attestation selection command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockResult {
    /// This is the first selected attestation for the validator and slot.
    Accepted,
    /// The same signed attestation was selected previously; it does not
    /// conflict with the cluster's choice. Processing still requires temporal
    /// admission.
    AlreadyAcceptedSame,
    /// A different signed attestation was selected previously. This candidate
    /// must not enter validation or gossip publication.
    ConflictingAttestation,
    /// The replicated retention floor or the slot ring has advanced beyond
    /// this attestation.
    TooOld,
}

/// Anti-equivocation state shared by standalone and replicated admission.
#[derive(Default)]
pub(crate) struct AttestationLockStore {
    /// Commands below this slot are rejected even if proposed by a node with a
    /// stale wall clock. Replicated stores advance this through committed
    /// commands.
    minimum_slot: u64,
    locks: [SlotLocks; LOCK_RING_SIZE],
}

#[derive(Default)]
struct SlotLocks {
    /// The absolute slot occupying this modulo bucket. The tag prevents a
    /// late older command from clearing locks for a newer colliding slot.
    slot: Option<u64>,
    /// Full-message hashes, including the signature. Comparing only the
    /// signing root would allow a later byte-distinct candidate for the same
    /// attestation data to bypass the first-candidate-wins rule.
    attestations: FxHashMap<[u8; 48], [u8; 32]>,
}

impl AttestationLockStore {
    pub(crate) fn apply(&mut self, cmd: &AttestationLockCommand) -> LockResult {
        if cmd.key.slot < self.minimum_slot {
            return LockResult::TooOld;
        }

        let bucket = &mut self.locks[(cmd.key.slot % SLOTS_PER_EPOCH) as usize];
        match bucket.slot {
            Some(slot) if slot > cmd.key.slot => return LockResult::TooOld,
            Some(slot) if slot < cmd.key.slot => {
                bucket.attestations.clear();
                bucket.slot = Some(cmd.key.slot);
            }
            None => bucket.slot = Some(cmd.key.slot),
            Some(_) => {}
        }

        let attestation_hash = merkle::sha256(&cmd.ssz);
        match bucket.attestations.entry(cmd.key.validator_pubkey) {
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

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.locks
            .iter()
            .filter(|bucket| bucket.slot.is_some_and(|slot| slot >= self.minimum_slot))
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
            key: AttestationKey { validator_pubkey: [validator; 48], slot },
            subnet: u64::from(root) % silver_common::ATTESTATION_SUBNETS as u64,
            ssz,
        }
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
    fn committed_minimum_slot_hides_and_rejects_old_commands() {
        let mut store = AttestationLockStore::default();
        assert_eq!(store.apply(&command(10, 1)), LockResult::Accepted);
        assert_eq!(store.apply(&command(11, 2)), LockResult::Accepted);

        store.advance_minimum_slot(11);

        assert_eq!(store.minimum_slot(), 11);
        assert_eq!(store.len(), 1);
        assert_eq!(store.apply(&command(10, 3)), LockResult::TooOld);
        assert_eq!(store.apply(&command(11, 3)), LockResult::ConflictingAttestation);
    }

    #[test]
    fn slot_ring_reuses_a_bucket_without_losing_newer_locks() {
        let mut store = AttestationLockStore::default();
        assert_eq!(store.locks.len(), 32);

        assert_eq!(store.apply(&command_for(10, 7, 1)), LockResult::Accepted);
        assert_eq!(store.apply(&command_for(10, 8, 2)), LockResult::Accepted);
        assert_eq!(store.apply(&command_for(11, 7, 3)), LockResult::Accepted);
        assert_eq!(store.len(), 3);

        // Slot 42 reuses slot 10's modulo bucket and drops only that bucket.
        assert_eq!(store.apply(&command_for(42, 9, 4)), LockResult::Accepted);
        assert_eq!(store.len(), 2);
        assert_eq!(store.apply(&command_for(42, 9, 4)), LockResult::AlreadyAcceptedSame);
        assert_eq!(store.apply(&command_for(42, 9, 5)), LockResult::ConflictingAttestation);

        // A late command for the displaced slot cannot clear slot 42.
        assert_eq!(store.apply(&command_for(10, 7, 6)), LockResult::TooOld);
        assert_eq!(store.apply(&command_for(42, 9, 4)), LockResult::AlreadyAcceptedSame);

        // The adjacent bucket was not scanned or cleared during rollover.
        assert_eq!(store.apply(&command_for(11, 7, 6)), LockResult::ConflictingAttestation);
    }
}
