use super::delta::PendingQueuesDelta;
use crate::types::{PendingConsolidation, PendingDeposit, PendingPartialWithdrawal};

/// Finalized base for the three pending FIFO queues (`pending_deposits`,
/// `pending_partial_withdrawals`, `pending_consolidations`).
// size: ~72 B (3 × Vec header)
#[derive(Clone, Default)]
pub struct PendingQueues {
    pub pending_deposits: Vec<PendingDeposit>,
    pub pending_partial_withdrawals: Vec<PendingPartialWithdrawal>,
    pub pending_consolidations: Vec<PendingConsolidation>,
}

impl PendingQueues {
    /// Fold a fork's delta into the base — drain the promoted prefix, append
    /// the new entries (per queue). The data half of finalization.
    pub(super) fn promote(&mut self, delta: &PendingQueuesDelta) {
        let n = (delta.deposits_drain_offset as usize).min(self.pending_deposits.len());
        self.pending_deposits.drain(..n);
        self.pending_deposits.extend_from_slice(&delta.deposits_appended);

        let n = (delta.partial_withdrawals_drain_offset as usize)
            .min(self.pending_partial_withdrawals.len());
        self.pending_partial_withdrawals.drain(..n);
        self.pending_partial_withdrawals.extend_from_slice(&delta.partial_withdrawals_appended);

        let n = (delta.consolidations_drain_offset as usize).min(self.pending_consolidations.len());
        self.pending_consolidations.drain(..n);
        self.pending_consolidations.extend_from_slice(&delta.consolidations_appended);
    }
}
