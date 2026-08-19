use flux_profiler::timed;

use super::delta::EpochStateDelta;
use crate::{
    decompose::{
        common::{F13, F17, F18, F19, F20, F29, F37, read_checkpoint, read_fork, u64_le},
        gloas::{G_DEPOSIT_BALANCE_TO_CONSUME, G_PROPOSER_LOOKAHEAD, G_PTC_WINDOW},
    },
    gloas::{PTC_SIZE, PTC_WINDOW_LEN, PtcCommittee, zeroed_ptc_window},
    reanchor::write_ring_window,
    types::{B256, EPOCHS_PER_HISTORICAL_VECTOR, EpochState},
};

// size: ~680 B stack (2 × Box<[T]> header + EpochState); heap at default-init
// ~2 MB (the randao_mixes ring).
#[derive(Clone)]
pub struct EpochStateFinalized {
    // last EPOCHS_PER_HISTORICAL_VECTOR (circular buffer indexed by `epoch % HV`)
    pub(crate) randao_mixes: Box<[B256]>,
    pub(crate) state: EpochState,
    /// [New in Gloas]
    pub(crate) ptc_window: Box<[PtcCommittee; PTC_WINDOW_LEN]>,
}

impl Default for EpochStateFinalized {
    fn default() -> Self {
        Self {
            randao_mixes: vec![[0u8; 32]; EPOCHS_PER_HISTORICAL_VECTOR].into_boxed_slice(),
            state: Default::default(),
            ptc_window: zeroed_ptc_window(),
        }
    }
}

impl EpochStateFinalized {
    #[inline]
    pub fn state(&self) -> &EpochState {
        &self.state
    }

    /// The published base is mutated only via [`promote`](Self::promote).
    pub fn from_parts(state: EpochState, randao_mixes: Box<[B256]>) -> Self {
        debug_assert_eq!(randao_mixes.len(), EPOCHS_PER_HISTORICAL_VECTOR);
        Self { randao_mixes, state, ptc_window: zeroed_ptc_window() }
    }

    /// Fold a fork's delta into the base: write its per-completed-epoch
    /// `randao_mixes` logs into the circular buffer at the epochs
    /// they cover (`(old_fin_epoch + i) % cap`), then adopt its scalar
    /// [`EpochState`] and `ptc_window`. The data half of finalization.
    pub(super) fn promote(&mut self, delta: &EpochStateDelta, old_fin_epoch: usize) {
        write_ring_window(&mut self.randao_mixes, old_fin_epoch, &delta.randao_mixes);
        self.state = delta.state;
        self.ptc_window.clone_from(&delta.ptc_window);
    }

    #[timed]
    pub(crate) fn from_ssz_fulu(ssz: &[u8]) -> Self {
        // SAFETY: `B256` is align-1, so the randao region reinterprets as `&[B256]`.
        let randao_src: &[B256] = unsafe {
            std::slice::from_raw_parts(
                ssz[F13..].as_ptr().cast::<B256>(),
                EPOCHS_PER_HISTORICAL_VECTOR,
            )
        };

        Self {
            randao_mixes: randao_src.to_vec().into_boxed_slice(),
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
        // SAFETY: `B256` is align-1, so the randao region reinterprets as `&[B256]`.
        let randao_src: &[B256] = unsafe {
            std::slice::from_raw_parts(
                ssz[F13..].as_ptr().cast::<B256>(),
                EPOCHS_PER_HISTORICAL_VECTOR,
            )
        };

        let mut ptc_window = zeroed_ptc_window();
        for (c, committee) in ptc_window.iter_mut().enumerate() {
            for (j, v) in committee.iter_mut().enumerate() {
                *v = u64_le(ssz, G_PTC_WINDOW + (c * PTC_SIZE + j) * 8);
            }
        }

        Self {
            randao_mixes: randao_src.to_vec().into_boxed_slice(),
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
