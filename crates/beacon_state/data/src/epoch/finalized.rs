use silver_common_macros::timed;

use super::delta::EpochStateDelta;
use crate::{
    buffer::write_ring_window,
    decompose::{
        common::{F13, F14, F17, F18, F19, F20, F29, F37, read_checkpoint, u64_le},
        gloas::{G_DEPOSIT_BALANCE_TO_CONSUME, G_PROPOSER_LOOKAHEAD, G_PTC_WINDOW},
    },
    gloas::{PTC_SIZE, PTC_WINDOW_LEN, PtcCommittee, zeroed_ptc_window},
    types::{
        B256, EPOCHS_PER_HISTORICAL_VECTOR, EPOCHS_PER_SLASHINGS_VECTOR, EpochState,
        PROPOSER_LOOKAHEAD_SIZE,
    },
};

// size: ~680 B stack (2 × Box<[T]> header + EpochState); heap at default-init
// ~2.064 MB (randao_mixes 2 MB + slashings 64 KB rings).
#[derive(Clone)]
pub struct EpochStateFinalized {
    // last EPOCHS_PER_HISTORICAL_VECTOR (circular buffer indexed by `epoch % HV`)
    pub(crate) randao_mixes: Box<[B256]>,
    // last EPOCHS_PER_SLASHINGS_VECTOR (circular buffer indexed by `epoch % SV`)
    pub(crate) slashings: Box<[u64]>,
    pub(crate) state: EpochState,
    /// [New in Gloas] Sibling of `state` (not a field of it) to keep
    /// `EpochState` a small `Copy` scalar type. Zeroed (unused) pre-Gloas.
    pub(crate) ptc_window: Box<[PtcCommittee; PTC_WINDOW_LEN]>,
}

impl Default for EpochStateFinalized {
    fn default() -> Self {
        Self {
            randao_mixes: vec![[0u8; 32]; EPOCHS_PER_HISTORICAL_VECTOR].into_boxed_slice(),
            slashings: vec![0; EPOCHS_PER_SLASHINGS_VECTOR].into_boxed_slice(),
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
    pub fn from_parts(state: EpochState, randao_mixes: Box<[B256]>, slashings: Box<[u64]>) -> Self {
        debug_assert_eq!(randao_mixes.len(), EPOCHS_PER_HISTORICAL_VECTOR);
        debug_assert_eq!(slashings.len(), EPOCHS_PER_SLASHINGS_VECTOR);
        Self { randao_mixes, slashings, state, ptc_window: zeroed_ptc_window() }
    }

    /// Fold a fork's delta into the base: write its per-completed-epoch
    /// `randao_mixes`/`slashings` log into the circular buffers at the epochs
    /// they cover (`(old_fin_epoch + i) % cap`), then adopt its scalar
    /// [`EpochState`] and `ptc_window`. The data half of finalization.
    pub(super) fn promote(&mut self, delta: &EpochStateDelta, old_fin_epoch: usize) {
        write_ring_window(&mut self.randao_mixes, old_fin_epoch, &delta.randao_mixes);
        write_ring_window(&mut self.slashings, old_fin_epoch, &delta.slashings);
        self.state = delta.state;
        self.ptc_window.clone_from(&delta.ptc_window);
    }

    #[timed]
    pub(crate) fn from_ssz(ssz: &[u8]) -> Self {
        let mut fin = Self::default();

        let randao_src: &[B256] = unsafe {
            std::slice::from_raw_parts(
                ssz[F13..].as_ptr().cast::<B256>(),
                EPOCHS_PER_HISTORICAL_VECTOR,
            )
        };
        fin.randao_mixes.copy_from_slice(randao_src);

        for i in 0..EPOCHS_PER_SLASHINGS_VECTOR {
            fin.slashings[i] = u64_le(ssz, F14 + i * 8);
        }

        let est = &mut fin.state;
        for i in 0..PROPOSER_LOOKAHEAD_SIZE {
            est.proposer_lookahead[i] = u64_le(ssz, F37 + i * 8);
        }
        est.justification_bits = ssz[F17] & 0x0F;
        est.previous_justified_checkpoint = read_checkpoint(ssz, F18);
        est.current_justified_checkpoint = read_checkpoint(ssz, F19);
        est.finalized_checkpoint = read_checkpoint(ssz, F20);
        est.deposit_balance_to_consume = u64_le(ssz, F29);

        fin
    }

    pub(crate) fn from_ssz_gloas(ssz: &[u8]) -> Self {
        let mut randao_mixes = vec![[0u8; 32]; EPOCHS_PER_HISTORICAL_VECTOR].into_boxed_slice();
        let randao_src: &[B256] = unsafe {
            std::slice::from_raw_parts(
                ssz[F13..].as_ptr().cast::<B256>(),
                EPOCHS_PER_HISTORICAL_VECTOR,
            )
        };
        randao_mixes.copy_from_slice(randao_src);

        let mut slashings = vec![0u64; EPOCHS_PER_SLASHINGS_VECTOR].into_boxed_slice();
        for (i, s) in slashings.iter_mut().enumerate() {
            *s = u64_le(ssz, F14 + i * 8);
        }

        let mut est = EpochState::default();
        for (i, p) in est.proposer_lookahead.iter_mut().enumerate() {
            *p = u64_le(ssz, G_PROPOSER_LOOKAHEAD + i * 8);
        }
        debug_assert_eq!(est.proposer_lookahead.len(), PROPOSER_LOOKAHEAD_SIZE);
        est.justification_bits = ssz[F17] & 0x0F;
        est.previous_justified_checkpoint = read_checkpoint(ssz, F18);
        est.current_justified_checkpoint = read_checkpoint(ssz, F19);
        est.finalized_checkpoint = read_checkpoint(ssz, F20);
        est.deposit_balance_to_consume = u64_le(ssz, G_DEPOSIT_BALANCE_TO_CONSUME);

        let mut ptc_window = zeroed_ptc_window();
        for (c, committee) in ptc_window.iter_mut().enumerate() {
            for (j, v) in committee.iter_mut().enumerate() {
                *v = u64_le(ssz, G_PTC_WINDOW + (c * PTC_SIZE + j) * 8);
            }
        }

        let mut fin = Self::from_parts(est, randao_mixes, slashings);
        fin.ptc_window = ptc_window;
        fin
    }
}
