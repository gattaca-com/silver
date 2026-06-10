use super::delta::EpochStateDelta;
use crate::{
    buffer::write_ring_window,
    types::{B256, EPOCHS_PER_HISTORICAL_VECTOR, EPOCHS_PER_SLASHINGS_VECTOR, EpochState},
};

/// Finalized base for the epoch tier: the canonical [`EpochState`] scalars plus
/// the `randao_mixes`/`slashings` circular buffers (indexed by `epoch % HV` /
/// `epoch % SV`).
// size: ~680 B stack (2 × Box<[T]> header + EpochState); heap at default-init
// ~2.064 MB (randao_mixes 2 MB + slashings 64 KB rings).
#[derive(Clone)]
pub struct EpochStateFinalized {
    // last EPOCHS_PER_HISTORICAL_VECTOR (circular buffer indexed by `epoch % HV`)
    pub(crate) randao_mixes: Box<[B256]>,
    // last EPOCHS_PER_SLASHINGS_VECTOR (circular buffer indexed by `epoch % SV`)
    pub(crate) slashings: Box<[u64]>,
    pub(crate) state: EpochState,
}

impl Default for EpochStateFinalized {
    fn default() -> Self {
        Self {
            randao_mixes: vec![[0u8; 32]; EPOCHS_PER_HISTORICAL_VECTOR].into_boxed_slice(),
            slashings: vec![0; EPOCHS_PER_SLASHINGS_VECTOR].into_boxed_slice(),
            state: Default::default(),
        }
    }
}

impl EpochStateFinalized {
    /// The scalar [`EpochState`] of the finalized base.
    #[inline]
    pub fn state(&self) -> &EpochState {
        &self.state
    }

    /// Base from fully-specified parts (`randao_mixes`/`slashings` must be
    /// `EPOCHS_PER_HISTORICAL_VECTOR` / `EPOCHS_PER_SLASHINGS_VECTOR` long).
    /// The published base is otherwise mutated only via
    /// [`promote`](Self::promote).
    pub fn from_parts(state: EpochState, randao_mixes: Box<[B256]>, slashings: Box<[u64]>) -> Self {
        debug_assert_eq!(randao_mixes.len(), EPOCHS_PER_HISTORICAL_VECTOR);
        debug_assert_eq!(slashings.len(), EPOCHS_PER_SLASHINGS_VECTOR);
        Self { randao_mixes, slashings, state }
    }

    /// Fold a fork's delta into the base: write its per-completed-epoch
    /// `randao_mixes`/`slashings` log into the circular buffers at the epochs
    /// they cover (`(old_fin_epoch + i) % cap`), then adopt its scalar
    /// [`EpochState`]. The data half of finalization.
    pub(super) fn promote(&mut self, delta: &EpochStateDelta, old_fin_epoch: usize) {
        write_ring_window(&mut self.randao_mixes, old_fin_epoch, &delta.randao_mixes);
        write_ring_window(&mut self.slashings, old_fin_epoch, &delta.slashings);
        self.state = delta.state;
    }
}
