#![allow(clippy::result_large_err)]

pub mod bls;
pub mod epoch_transition;
pub mod error;
mod fork_choice;
pub mod shuffling;
pub mod ssz_hash;
pub mod state_transition;
pub mod tile;
mod validate;

#[cfg(test)]
pub(crate) mod test_signing;
#[cfg(test)]
pub(crate) mod test_state;

pub use error::{Error, PrecheckError, Result};
pub use silver_common::ticker::SlotTicker;
pub use tile::BeaconStateTile;
