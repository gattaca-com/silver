pub use buffer::DeltaBuffer;
pub use delta_view::{StateDeltaReadView, StateDeltaView, ValidatorRow};
pub use hash_tree::{DeltaHashTree, FinalizedHashTree};
pub use validators::{
    AppendedValidator, FinalizedValidators, ValSeed, ValidatorsDecodeError, ValidatorsDelta,
    validator_hash,
};
pub use view::{BeaconStateOwner, BeaconStateReader};

use crate::{
    EpochStateDelta, Finalized, LongtailState, StateDelta,
    beacon_state::types::{EPOCHS_RING_N, LONGTAILS_RING_N, SLOTS_RING_N},
};

pub mod buffer;
mod decompose;
mod delta_view;
mod hash_tree;
pub mod types;
mod validators;
mod view;

#[derive(Default)]
pub struct BeaconState {
    pub finalized: Finalized,
    pub longtails: DeltaBuffer<LongtailState, LONGTAILS_RING_N>,
    pub epochs: DeltaBuffer<EpochStateDelta, EPOCHS_RING_N>,
    pub slots: DeltaBuffer<StateDelta, SLOTS_RING_N>,
}
