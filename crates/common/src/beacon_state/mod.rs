pub use buffer::DeltaBuffer;
pub use delta_view::StateDeltaView;
pub use view::{BeaconStateOwner, BeaconStateReader};

use crate::{
    EpochStateDelta, Finalised, LongtailState, StateDelta,
    beacon_state::types::{EPOCHS_RING_N, LONGTAILS_RING_N, SLOTS_RING_N},
};

mod buffer;
mod decompose;
mod delta_view;
pub mod types;
mod view;

#[derive(Default)]
pub struct BeaconState {
    pub finalised: Finalised,
    pub longtails: DeltaBuffer<LongtailState, LONGTAILS_RING_N>,
    pub epochs: DeltaBuffer<EpochStateDelta, EPOCHS_RING_N>,
    pub slots: DeltaBuffer<StateDelta, SLOTS_RING_N>,
}
