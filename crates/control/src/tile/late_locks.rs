use fxhash::FxHashMap;

use super::slashing_protection::{PendingAttestation, PendingBlock};
use crate::cluster::ProposalId;

/// A proposal that never commits was most likely lost with its leader, and a
/// block this late would be orphaned anyway.
const LATE_COMMIT_SLOTS: u64 = 2;

/// Local messages whose lock proposal timed out after their request was
/// answered. If the proposal still commits, the lock holds exactly these
/// bytes, so they are published without an answer.
#[derive(Default)]
pub(super) struct LateLocks {
    attestations: FxHashMap<ProposalId, PendingAttestation>,
    blocks: FxHashMap<ProposalId, PendingBlock>,
}

impl LateLocks {
    pub(super) fn insert_attestation(&mut self, id: ProposalId, attestation: PendingAttestation) {
        self.attestations.insert(id, attestation);
    }

    pub(super) fn insert_block(&mut self, id: ProposalId, block: PendingBlock) {
        self.blocks.insert(id, block);
    }

    pub(super) fn take_attestation(&mut self, id: ProposalId) -> Option<PendingAttestation> {
        self.attestations.remove(&id)
    }

    pub(super) fn take_block(&mut self, id: ProposalId) -> Option<PendingBlock> {
        self.blocks.remove(&id)
    }

    /// Releases block submissions pinned in the submissions tcache.
    pub(super) fn expire(&mut self, wall_slot: u64) {
        let live = |slot: u64| slot.saturating_add(LATE_COMMIT_SLOTS) > wall_slot;
        self.attestations.retain(|_, attestation| live(attestation.slot()));
        self.blocks.retain(|_, block| live(block.slot()));
    }

    pub(super) fn clear(&mut self) {
        self.attestations.clear();
        self.blocks.clear();
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.attestations.len() + self.blocks.len()
    }
}
