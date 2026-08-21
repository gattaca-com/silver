use flux_profiler::timed;

use super::{delta::EpochStateDelta, ptc_window::PtcWindow};
use crate::{
    decompose::{
        common::{F17, F18, F19, F20, F29, F37, read_checkpoint, read_fork, u64_le},
        gloas::{G_DEPOSIT_BALANCE_TO_CONSUME, G_PROPOSER_LOOKAHEAD, G_PTC_WINDOW},
    },
    gloas::{PTC_SIZE, zeroed_ptc_window},
    types::EpochState,
};

// size: ~680 B stack (Box headers + EpochState); the 393 KB PTC window and its
// 3 KB of cached roots are the only heap.
#[derive(Clone, Default)]
pub struct EpochStateFinalized {
    pub(crate) state: EpochState,
    /// [New in Gloas]
    pub(crate) ptc_window: PtcWindow,
}

impl EpochStateFinalized {
    #[inline]
    pub fn state(&self) -> &EpochState {
        &self.state
    }

    /// The published base is mutated only via [`promote`](Self::promote).
    pub fn from_state(state: EpochState) -> Self {
        Self { state, ptc_window: PtcWindow::default() }
    }

    /// Adopt a fork's delta as the base — the data half of finalization.
    pub(super) fn promote(&mut self, delta: &EpochStateDelta) {
        self.state = delta.state;
        self.ptc_window.clone_from(&delta.ptc_window);
    }

    #[timed]
    pub(crate) fn from_ssz_fulu(ssz: &[u8]) -> Self {
        Self { state: read_epoch_state(ssz, F37, F29), ptc_window: PtcWindow::default() }
    }

    pub(crate) fn from_ssz_gloas(ssz: &[u8]) -> Self {
        let mut ptc_window = zeroed_ptc_window();
        for (c, committee) in ptc_window.iter_mut().enumerate() {
            for (j, v) in committee.iter_mut().enumerate() {
                *v = u64_le(ssz, G_PTC_WINDOW + (c * PTC_SIZE + j) * 8);
            }
        }

        Self {
            state: read_epoch_state(ssz, G_PROPOSER_LOOKAHEAD, G_DEPOSIT_BALANCE_TO_CONSUME),
            ptc_window: PtcWindow::new(ptc_window),
        }
    }
}

fn read_epoch_state(ssz: &[u8], lookahead_off: usize, deposit_balance_off: usize) -> EpochState {
    EpochState {
        proposer_lookahead: std::array::from_fn(|i| u64_le(ssz, lookahead_off + i * 8)),
        justification_bits: ssz[F17] & 0x0F,
        previous_justified_checkpoint: read_checkpoint(ssz, F18),
        current_justified_checkpoint: read_checkpoint(ssz, F19),
        finalized_checkpoint: read_checkpoint(ssz, F20),
        deposit_balance_to_consume: u64_le(ssz, deposit_balance_off),
        fork: read_fork(ssz),
    }
}
