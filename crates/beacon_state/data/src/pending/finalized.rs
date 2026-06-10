use std::io::{self, Write};

use super::delta::PendingQueuesDelta;
use crate::types::{PendingConsolidation, PendingDeposit, PendingPartialWithdrawal};

/// SSZ-serialised `PendingDeposit` size; mirrors `decompose`/`encode`.
const PENDING_DEPOSIT_SSZ: usize = 192;

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
    /// SSZ-encode the `pending_deposits` queue — checkpoint section body.
    /// Callers hold the group's promote barrier (`with_base_locked`).
    pub(crate) fn write_deposits_ssz<W: Write>(&self, w: &mut W) -> io::Result<()> {
        let mut buf = [0u8; PENDING_DEPOSIT_SSZ];
        for d in &self.pending_deposits {
            buf[0..48].copy_from_slice(&d.pubkey);
            buf[48..80].copy_from_slice(&d.withdrawal_credentials.0);
            buf[80..88].copy_from_slice(&d.amount.to_le_bytes());
            buf[88..184].copy_from_slice(&d.signature);
            buf[184..192].copy_from_slice(&d.slot.to_le_bytes());
            w.write_all(&buf)?;
        }
        Ok(())
    }

    /// SSZ-encode the `pending_partial_withdrawals` queue — checkpoint
    /// section body, under the same barrier as above.
    pub(crate) fn write_partial_withdrawals_ssz<W: Write>(&self, w: &mut W) -> io::Result<()> {
        for pw in &self.pending_partial_withdrawals {
            w.write_all(&pw.index.to_le_bytes())?;
            w.write_all(&pw.amount.to_le_bytes())?;
            w.write_all(&pw.withdrawable_epoch.to_le_bytes())?;
        }
        Ok(())
    }

    /// SSZ-encode the `pending_consolidations` queue — checkpoint section
    /// body, under the same barrier as above.
    pub(crate) fn write_consolidations_ssz<W: Write>(&self, w: &mut W) -> io::Result<()> {
        for pc in &self.pending_consolidations {
            w.write_all(&pc.source_index.to_le_bytes())?;
            w.write_all(&pc.target_index.to_le_bytes())?;
        }
        Ok(())
    }

    /// Fold a fork's delta into the base — drain the promoted prefix, append
    /// the new entries (per queue). The data half of finalization.
    pub(super) fn promote(&mut self, delta: &PendingQueuesDelta) {
        delta.deposits.promote_into(&mut self.pending_deposits);
        delta.partial_withdrawals.promote_into(&mut self.pending_partial_withdrawals);
        delta.consolidations.promote_into(&mut self.pending_consolidations);
    }
}
