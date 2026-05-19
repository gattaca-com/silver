//! Validator-identity layer: finalized base, per-fork delta overlay,
//! and the pubkey → index cache that makes lookups O(1).
//!
//! - [`FinalizedValidators`] — owns the canonical `ValidatorsData` and its
//!   `PubkeyIndex`.
//! - [`ValidatorsState`] — a per-fork overlay: borrows the finalized base via a
//!   raw pointer, owns a [`ValidatorsDelta`] of speculative appends +
//!   credential edits. Lives inside `BeaconStateRef`.
//! - [`ValidatorsDelta`] / [`AppendedValidator`] — the delta payload.
//! - [`PubkeyIndex`] — the full-pubkey-keyed lookup cache.

mod credentials;
mod delta;
mod finalized;
mod state;

#[cfg(test)]
mod tests;

pub use credentials::Withdrawals;
pub use delta::{AppendedValidator, ValidatorsDelta};
pub use finalized::{FinalizedValidators, PubkeyIndex};
pub use state::ValidatorsState;
