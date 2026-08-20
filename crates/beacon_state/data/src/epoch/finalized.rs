use flux_profiler::timed;

use super::delta::EpochStateDelta;
use crate::{
    decompose::{
        common::{F17, F18, F19, F20, F29, F37, read_checkpoint, read_fork, u64_le},
        gloas::{G_DEPOSIT_BALANCE_TO_CONSUME, G_PROPOSER_LOOKAHEAD, G_PTC_WINDOW},
    },
    gloas::{PTC_SIZE, PTC_WINDOW_LEN, PtcCommittee, zeroed_ptc_window},
    types::EpochState,
};

// size: ~680 B stack (Box header + EpochState); the 393 KB PTC window is the
// only heap.
#[derive(Clone)]
pub struct EpochStateFinalized {
    pub(crate) state: EpochState,
    /// [New in Gloas]
    pub(crate) ptc_window: Box<[PtcCommittee; PTC_WINDOW_LEN]>,
}

impl Default for EpochStateFinalized {
    fn default() -> Self {
        Self { state: Default::default(), ptc_window: zeroed_ptc_window() }
    }
}

impl EpochStateFinalized {
    #[inline]
    pub fn state(&self) -> &EpochState {
        &self.state
    }

    /// The published base is mutated only via [`promote`](Self::promote).
    pub fn from_state(state: EpochState) -> Self {
        Self { state, ptc_window: zeroed_ptc_window() }
    }

    /// Adopt a fork's delta as the base — the data half of finalization.
    pub(super) fn promote(&mut self, delta: &EpochStateDelta) {
        self.state = delta.state;
        self.ptc_window.clone_from(&delta.ptc_window);
    }

    #[timed]
    pub(crate) fn from_ssz_fulu(ssz: &[u8]) -> Self {
        Self {
            state: EpochState {
                proposer_lookahead: std::array::from_fn(|i| u64_le(ssz, F37 + i * 8)),
                justification_bits: ssz[F17] & 0x0F,
                previous_justified_checkpoint: read_checkpoint(ssz, F18),
                current_justified_checkpoint: read_checkpoint(ssz, F19),
                finalized_checkpoint: read_checkpoint(ssz, F20),
                deposit_balance_to_consume: u64_le(ssz, F29),
                fork: read_fork(ssz),
            },
            ptc_window: zeroed_ptc_window(),
        }
    }

    pub(crate) fn from_ssz_gloas(ssz: &[u8]) -> Self {
        let mut ptc_window = zeroed_ptc_window();
        for (c, committee) in ptc_window.iter_mut().enumerate() {
            for (j, v) in committee.iter_mut().enumerate() {
                *v = u64_le(ssz, G_PTC_WINDOW + (c * PTC_SIZE + j) * 8);
            }
        }

        Self {
            state: EpochState {
                proposer_lookahead: std::array::from_fn(|i| {
                    u64_le(ssz, G_PROPOSER_LOOKAHEAD + i * 8)
                }),
                justification_bits: ssz[F17] & 0x0F,
                previous_justified_checkpoint: read_checkpoint(ssz, F18),
                current_justified_checkpoint: read_checkpoint(ssz, F19),
                finalized_checkpoint: read_checkpoint(ssz, F20),
                deposit_balance_to_consume: u64_le(ssz, G_DEPOSIT_BALANCE_TO_CONSUME),
                fork: read_fork(ssz),
            },
            ptc_window,
        }
    }
}
