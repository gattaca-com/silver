#![allow(clippy::result_large_err)]

pub mod arena;
pub mod bls;
pub mod decompose;
pub mod epoch_transition;
pub mod error;
mod fork_choice;
pub mod hash_tree;
pub mod shuffling;
pub mod ssz_hash;
pub mod state_transition;
pub mod ticker;
pub mod tile;
pub mod types;
mod validate;
pub mod validator_identity;

#[cfg(test)]
pub(crate) mod test_signing;

pub use error::{Error, PrecheckError, Result};
pub use ticker::SlotTicker;
pub use tile::BeaconStateTile;
