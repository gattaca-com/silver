use std::sync::Arc;

pub use buffer::DeltaBuffer;
pub use view::ViewControl;

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

impl BeaconState {
    /// Returns beacon state and control.
    /// The owner of the beacon state MUST hold the control write lock
    /// when compacting deltas to finalised state.
    /// The write lock must also be held when updating the 'head' and
    /// 'tail' values in the control - but the delta buffers can be rolled and
    /// cleared without holding the lock.
    pub fn new() -> (Box<Self>, Arc<ViewControl>) {
        let mut state = Box::new(Self::default());
        let state_mut_ptr = Box::into_raw(state);
        let state_ptr = state_mut_ptr as *const BeaconState;
        state = unsafe { Box::from_raw(state_mut_ptr) };

        let control = ViewControl::new(state_ptr).into();
        (state, control)
    }
}
