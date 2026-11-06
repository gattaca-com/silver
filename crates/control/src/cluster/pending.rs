use std::{collections::VecDeque, time::Instant};

use raft::eraftpb::Entry;
use silver_common::{ClusterDuty, ClusterOutcome};

use super::{metrics::ResolvedProposal, node::ProposalId};

#[derive(Debug, Clone, Copy)]
pub(super) struct PendingProposal {
    pub(super) id: ProposalId,
    pub(super) slot: u64,
    pub(super) duty: ClusterDuty,
    pub(super) leader_origin: bool,
    pub(super) submitted: Instant,
    pub(super) deadline: Instant,
    appended: Option<Instant>,
    persisted: Option<Instant>,
}

impl PendingProposal {
    pub(super) fn new(
        id: ProposalId,
        slot: u64,
        duty: ClusterDuty,
        leader_origin: bool,
        submitted: Instant,
        deadline: Instant,
    ) -> Self {
        Self { id, slot, duty, leader_origin, submitted, deadline, appended: None, persisted: None }
    }

    pub(super) fn resolve(self, resolved: Instant, outcome: ClusterOutcome) -> ResolvedProposal {
        ResolvedProposal {
            slot: self.slot,
            duty: self.duty,
            leader_origin: self.leader_origin,
            submitted: self.submitted,
            appended: self.appended,
            persisted: self.persisted,
            resolved,
            outcome,
        }
    }
}

/// Ordered by deadline, since proposals arrive with nondecreasing `now`.
#[derive(Debug, Default)]
pub(super) struct PendingProposals {
    proposals: VecDeque<PendingProposal>,
}

impl PendingProposals {
    pub(super) fn push(&mut self, proposal: PendingProposal) {
        debug_assert!(
            self.proposals.back().is_none_or(|pending| pending.deadline <= proposal.deadline),
            "proposal timestamps must be monotonic"
        );
        self.proposals.push_back(proposal);
    }

    pub(super) fn len(&self) -> usize {
        self.proposals.len()
    }

    pub(super) fn clear(&mut self) {
        self.proposals.clear();
    }

    pub(super) fn take(&mut self, id: ProposalId) -> Option<PendingProposal> {
        let index = self.proposals.iter().position(|pending| pending.id == id)?;
        self.proposals.remove(index)
    }

    pub(super) fn pop_expired(&mut self, now: Instant) -> Option<PendingProposal> {
        self.proposals
            .front()
            .is_some_and(|proposal| now >= proposal.deadline)
            .then(|| self.proposals.pop_front().expect("front exists"))
    }

    pub(super) fn pop_from_sequence(&mut self, first: u64) -> Option<PendingProposal> {
        self.proposals
            .back()
            .is_some_and(|proposal| proposal.id.sequence >= first)
            .then(|| self.proposals.pop_back().expect("back exists"))
    }

    /// `entries` are those about to enter this node's Raft log.
    pub(super) fn appended(
        &mut self,
        entries: &[Entry],
        origin: u64,
        incarnation: [u8; 16],
        now: Instant,
    ) {
        for entry in entries {
            let Ok(id) = ProposalId::decode(&entry.context) else { continue };
            if id.origin_node_id != origin || id.incarnation != incarnation {
                continue;
            }
            if let Some(pending) = self.proposals.iter_mut().find(|pending| pending.id == id) {
                pending.appended.get_or_insert(now);
            }
        }
    }

    /// One journal write is in flight at a time, so its completion covers
    /// every entry appended so far.
    pub(super) fn persisted(&mut self, now: Instant) {
        for pending in &mut self.proposals {
            if pending.appended.is_some() && pending.persisted.is_none() {
                pending.persisted = Some(now);
            }
        }
    }
}
