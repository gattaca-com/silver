pub use buffer::DeltaBuffer;
pub use view::{BeaconStateOwner, BeaconStateReader};

use crate::{EpochStateDelta, Finalised, LongtailState, StateDelta};

mod buffer;
pub mod types;
mod view;

#[derive(Default)]
pub struct BeaconState {
    pub finalised: Finalised,
    pub longtails: DeltaBuffer<LongtailState, 2>,
    pub epochs: DeltaBuffer<EpochStateDelta, 8>,
    pub slots: DeltaBuffer<StateDelta, 256>,
}
