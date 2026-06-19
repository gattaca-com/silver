#![allow(clippy::result_large_err)]

pub mod bls;
pub mod error;
mod fork_choice;
pub mod shuffling;
pub mod ssz_hash;
pub mod stf;
pub mod tile;
mod validate;
mod weak_subjectivity;

#[cfg(test)]
pub(crate) mod test_signing;
#[cfg(test)]
pub(crate) mod test_state;

pub use error::{Error, PrecheckError, Result};
// Fork-choice store types, exposed only for the EF vector harnesses' read
// access via `BeaconStateTile::ef_fork_choice`.
#[cfg(feature = "ef_tests")]
pub use fork_choice::{ExecutionStatus, ForkChoice, ForkChoiceNode};
pub use silver_common::ticker::SlotTicker;
pub use tile::BeaconStateTile;
