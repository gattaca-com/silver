use std::sync::{self, atomic::Ordering};

use flux::communication::Seqlock;

use crate::{EpochStateDelta, FinalisedView, StateDelta, beacon_state::BeaconState};

pub struct ViewControl {
    state_ptr: *const BeaconState,
    inner: Seqlock<ControlInner>,
}

impl ViewControl {
    pub fn new(state_ptr: *const BeaconState) -> Self {
        Self { state_ptr, inner: Seqlock::new(ControlInner::default()) }
    }

    /// Called by the state owner to publish new delta buffer offsets - should
    /// only be published once the corresponding buffer slot will no longer
    /// be mutated.
    pub fn publish_offsets(&self, epochs: Option<usize>, slots: Option<usize>) {
        let (mut inner, version) = self.inner.read_copy().expect("should never be empty");
        if inner.version & 1 == 1 {
            panic!("attempting to update offsets while a state write is in progress");
        }

        inner.epochs = epochs;
        inner.slots = slots;

        if !self.inner.write_at_version(&inner, version) {
            panic!("concurrent writes to beacon state control")
        }
    }

    /// Should be called when finalized state is being updated.
    pub fn write(&self) -> WriteGuard<'_> {
        let (mut value, version) =
            self.inner.read_copy().expect("control inner should nbever be empty");

        // Set version to odd number - indicates write in progress
        value.version += 1;
        self.inner.write_at_version(&value, version);

        // Set version to even value that will be written when the guard is dropped.
        value.version += 1;

        WriteGuard { value, version: self.inner.version(), inner: &self.inner }
    }

    /// Performs optimistic reads from the beacon state, this will loop if the
    /// finalised state is updated during a read.
    pub fn read<F, R>(&self, reader: &F) -> R
    where
        F: Fn(FinalisedView<'_>, Option<&StateDelta>, Option<&EpochStateDelta>) -> R,
    {
        loop {
            let (control, _) = self.inner.read_copy().expect("should never be empty");
            sync::atomic::compiler_fence(Ordering::Acquire);

            if control.version & 1 == 1 {
                // write in progress
                std::hint::spin_loop();
                continue;
            }
            let version = control.version;
            let state = unsafe { &*self.state_ptr };

            let finalised_view = state.finalised.view();
            let slot_delta = control.slots.map(|i| state.slots.get(i));
            let epoch_delta = control.epochs.map(|i| state.epochs.get(i));

            let result = reader(finalised_view, slot_delta, epoch_delta);

            // check that finalized state was not changed whilst reading.
            sync::atomic::compiler_fence(Ordering::Acquire);
            let (post, _) = self.inner.read_copy().expect("should never be empty");
            if post.version == version {
                return result;
            }
        }
    }
}

pub struct WriteGuard<'a> {
    value: ControlInner,
    version: u64,
    inner: &'a Seqlock<ControlInner>,
}

impl<'a> Drop for WriteGuard<'a> {
    fn drop(&mut self) {
        if !self.inner.write_at_version(&self.value, self.version) {
            panic!("beacon state control version was updated while write guard was held!!");
        }
    }
}

#[derive(Clone, Copy, Default)]
struct ControlInner {
    /// Finalized version - an odd version indicates that finalized state is
    /// being written.
    version: usize,
    epochs: Option<usize>,
    slots: Option<usize>,
}
