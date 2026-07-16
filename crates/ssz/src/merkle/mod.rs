//! Core SSZ Merkleization — all fork-agnostic. Split by concern: [`hash`]
//! primitives + zero-subtree table, the incremental [`stack`] tree builder,
//! the chunk→root [`merkleize`] family, and generic [`list`] collection
//! hashers. Eth2-shape hashers that decode specific containers live in
//! [`crate::ssz_hash`].

mod hash;
mod list;
mod merkleize;
mod stack;

#[cfg(test)]
mod tests;

pub use hash::*;
pub use list::*;
pub use merkleize::*;
pub use stack::*;
