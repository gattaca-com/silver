#![allow(clippy::result_large_err)]

pub mod bls;
pub mod epoch_transition;
pub mod error;
mod fork_choice;
pub mod shuffling;
pub mod ssz_hash;
pub mod state_transition;
pub mod ticker;
pub mod tile;
mod validate;

#[cfg(test)]
pub(crate) mod test_signing;

pub use error::{Error, PrecheckError, Result};
pub use silver_common::MAX_VALIDATORS;
pub use ticker::SlotTicker;
pub use tile::BeaconStateTile;

/// Heap-allocate a zeroed `T` without going through the stack. Used for big
/// fixed-size arrays (`[Vote; MAX_VALIDATORS]`, `ShufflingCache`) — alloc
/// goes through `mmap MAP_ANONYMOUS` on Linux so physical RAM only follows
/// pages actually touched.
pub(crate) fn box_zeroed<T>() -> Box<T> {
    let layout = std::alloc::Layout::new::<T>();
    unsafe {
        let ptr = std::alloc::alloc_zeroed(layout);
        assert!(!ptr.is_null(), "allocation failed");
        Box::from_raw(ptr.cast::<T>())
    }
}
