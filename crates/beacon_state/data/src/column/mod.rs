mod fulu;
mod gloas;
mod group;
mod pool;
mod shape;
mod snapshot;
mod store;
mod tree;
mod view;

#[cfg(test)]
mod tests;

pub use group::ColumnGroup;
pub use silver_ssz::scalar::SszScalar;
pub use view::{ColumnReader, ColumnWriteView};

use crate::ring::Id;

/// A column's marker: its scalar `Val` plus a distinct type identity, so ring
/// ids of different columns can't be mixed.
pub trait ColumnSpec {
    type Val: SszScalar;
}

/// Column markers — one zero-sized type per registry-aligned column. Distinct
/// named types (rather than a discriminated `Col<V, ID>`) so ring ids of
/// different columns can't mix *and* `type_name` reads cleanly in perf frames
/// (`Balances`, not `Col<u64, 3>`).
pub struct Previous;
impl ColumnSpec for Previous {
    type Val = u8;
}

pub struct Current;
impl ColumnSpec for Current {
    type Val = u8;
}

pub struct Balances;
impl ColumnSpec for Balances {
    type Val = u64;
}

pub type PreviousParticipationGroup = ColumnGroup<Previous>;
pub type PreviousParticipationId = Id<PreviousParticipationGroup>;

pub type CurrentParticipationGroup = ColumnGroup<Current>;
pub type CurrentParticipationId = Id<CurrentParticipationGroup>;

pub type ParticipationView<'a, M> = ColumnReader<'a, M>;
pub type ParticipationWriteView<'a, M> = ColumnWriteView<'a, M>;

pub type BalancesGroup = ColumnGroup<Balances>;
pub type BalancesId = Id<BalancesGroup>;

pub type BalancesReader<'a> = ColumnReader<'a, Balances>;
pub type BalancesWriteView<'a> = ColumnWriteView<'a, Balances>;

pub struct Inactivity;
impl ColumnSpec for Inactivity {
    type Val = u64;
}

pub type InactivityScoresGroup = ColumnGroup<Inactivity>;
pub type InactivityId = Id<InactivityScoresGroup>;
pub type InactivityView<'a> = ColumnReader<'a, Inactivity>;
pub type InactivityWriteView<'a> = ColumnWriteView<'a, Inactivity>;
