pub use balances::{BalancesDelta, FinalizedBalances};
pub use buffer::DeltaBuffer;
pub use delta_view::{StateDeltaReadView, StateDeltaView, ValidatorRow};
pub use encode::VAR_SECTIONS;
pub use hash_tree::{DeltaHashTree, FinalizedHashTree};
pub use silver_chain_spec::{BlobParameters, SpecConfig};
pub(crate) use silver_ssz::ssz_hash;
pub use types::*;
pub use validators::{
    AppendedValidator, FinalizedValidators, ValSeed, ValidatorsDecodeError, ValidatorsDelta,
    validator_hash,
};
pub use view::{BeaconStateOwner, BeaconStateReader};

mod balances;
pub mod buffer;
mod decompose;
mod delta_view;
mod encode;
mod hash_tree;
pub(crate) mod sparse;
pub mod types;
mod validators;
mod view;

pub struct BeaconState {
    pub finalized: Finalized,
    pub longtails: DeltaBuffer<LongtailState, LONGTAILS_RING_N>,
    pub epochs: DeltaBuffer<EpochStateDelta, EPOCHS_RING_N>,
    pub slots: DeltaBuffer<StateDelta, SLOTS_RING_N>,
}

impl BeaconState {
    /// Zero-validator pre-bootstrap state. No `Default` — see
    /// [`Finalized::empty`].
    pub fn empty() -> Self {
        Self {
            finalized: Finalized::empty(),
            longtails: DeltaBuffer::default(),
            epochs: DeltaBuffer::default(),
            slots: DeltaBuffer::default(),
        }
    }
}
