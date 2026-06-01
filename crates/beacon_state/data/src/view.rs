use std::{
    ops::{Deref, DerefMut},
    sync::{self, Arc, atomic::Ordering},
};

use flux::communication::Seqlock;

use crate::{
    BeaconState, DeltaBuffer, EpochStateDelta, LongtailState, StateDelta, StateDeltaReadView,
    StateDeltaView,
    types::{EPOCHS_RING_N, LONGTAILS_RING_N, SLOTS_RING_N},
};

/// Beacon state writer control.
/// Single writer.
pub struct BeaconStateOwner {
    state: Box<BeaconState>,
    state_ptr: *const BeaconState,
    inner: Arc<Seqlock<ControlInner>>,
}

// SAFETY: `state_ptr` aliases the owner's own `Box<BeaconState>` heap
// allocation, which is stable across a move (only the `Box` pointer moves,
// not the heap data). The owner is the single writer and is pinned to one
// thread after construction; cross-thread readers go through
// `BeaconStateReader` (its own `unsafe impl`). Sending the owner to its tile
// thread once is therefore sound.
unsafe impl Send for BeaconStateOwner {}

impl BeaconStateOwner {
    pub fn new(state: BeaconState) -> Self {
        let mut box_state = Box::new(state);
        let state_mut_ptr = Box::into_raw(box_state);
        let state_ptr = state_mut_ptr as *const BeaconState;
        box_state = unsafe { Box::from_raw(state_mut_ptr) };
        Self { state: box_state, state_ptr, inner: Arc::new(Seqlock::new(ControlInner::default())) }
    }

    pub fn state(&self) -> &BeaconState {
        &self.state
    }

    pub fn longtails(&mut self) -> &mut DeltaBuffer<LongtailState, LONGTAILS_RING_N> {
        &mut self.state.longtails
    }

    pub fn epochs(&mut self) -> &mut DeltaBuffer<EpochStateDelta, EPOCHS_RING_N> {
        &mut self.state.epochs
    }

    pub fn slots(&mut self) -> &mut DeltaBuffer<StateDelta, SLOTS_RING_N> {
        &mut self.state.slots
    }

    pub fn delta_view(&mut self, slot_seq: usize) -> StateDeltaView<'_> {
        let s = &mut *self.state;
        // Production state-transition path: finalized base must be populated
        // (decompose from genesis SSZ or a checkpoint). The zero-validator
        // `Finalized::empty()` is the unanchored stub used only by tests
        // and the pre-bootstrap owner.
        assert!(
            s.finalized.validators.validator_count() > 0,
            "delta_view: operating on empty finalized state",
        );
        StateDeltaView::new(
            &s.finalized,
            s.slots.get_mut(slot_seq),
            &mut s.epochs,
            &mut s.longtails,
        )
    }

    /// Called by the state owner to publish new delta buffer offsets - should
    /// only be published once the corresponding buffer slot will no longer
    /// be mutated.
    pub fn publish_offsets(&mut self, epochs: Option<usize>, slots: Option<usize>) {
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
    pub fn write(&mut self) -> WriteGuard<'_> {
        let (mut value, version) =
            self.inner.read_copy().expect("control inner should nbever be empty");

        // Set version to odd number - indicates write in progress
        value.version += 1;
        self.inner.write_at_version(&value, version);

        // Set version to even value that will be written when the guard is dropped.
        value.version += 1;

        WriteGuard {
            beacon_state: &mut self.state,
            value,
            version: self.inner.version(),
            inner: &self.inner,
        }
    }

    pub fn reader(&mut self) -> BeaconStateReader {
        BeaconStateReader { state_ptr: self.state_ptr, inner: self.inner.clone() }
    }
}

pub struct BeaconStateReader {
    state_ptr: *const BeaconState,
    inner: Arc<Seqlock<ControlInner>>,
}

// SAFETY: `state_ptr` aliases the `BeaconState` heap allocation owned by the
// writer thread. The writer must keep that allocation live for the lifetime
// of every `ViewControl` clone, and mutate the state only through the
// publish-offsets / write-guard protocol below. With those invariants, the
// pointer is safe to share and to dereference from any thread.
unsafe impl Send for BeaconStateReader {}
unsafe impl Sync for BeaconStateReader {}

impl BeaconStateReader {
    /// Performs optimistic reads from the beacon state, this will loop if the
    /// finalized state is updated during a read.
    pub fn read<F, R>(&self, reader: &F) -> R
    where
        F: Fn(StateDeltaReadView<'_>) -> R,
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

            let slot_delta = control.slots.map(|i| state.slots.get(i));
            let epoch_delta = control.epochs.map(|i| state.epochs.get(i));

            let result = reader(StateDeltaReadView::new(&state.finalized, slot_delta, epoch_delta));

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
    beacon_state: &'a mut BeaconState,
    value: ControlInner,
    version: u64,
    inner: &'a Seqlock<ControlInner>,
}

impl<'a> Deref for WriteGuard<'a> {
    type Target = BeaconState;

    fn deref(&self) -> &Self::Target {
        self.beacon_state
    }
}

impl<'a> DerefMut for WriteGuard<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.beacon_state
    }
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
