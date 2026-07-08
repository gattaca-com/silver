//! Sparse base+delta column model — the original `ColumnGroup`, now used only
//! for inactivity scores. Inactivity is written just at epoch boundaries and on
//! new-validator deposits, so its per-fork delta stays near-empty and a ring
//! roll is an `Arc` bump + tiny `Edits` clone. The every-block columns
//! (balances, participation) use the whole-tree model in `crate::column`.

mod delta;
mod finalized;
mod group;

#[cfg(test)]
mod tests;

pub use delta::{ColumnReader, ColumnWriteView};
pub use group::ColumnGroup;

use crate::{buffer::Id, column::ColumnSpec};

pub struct Inactivity;
impl ColumnSpec for Inactivity {
    type Val = u64;
}

pub type InactivityScoresGroup = ColumnGroup<Inactivity>;
pub type InactivityId = Id<InactivityScoresGroup>;
pub type InactivityView<'a> = ColumnReader<'a, Inactivity>;
pub type InactivityWriteView<'a> = ColumnWriteView<'a, Inactivity>;
