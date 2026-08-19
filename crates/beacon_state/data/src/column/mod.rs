mod format;
mod group;
mod list;
mod pool;
mod progressive_list;
mod snapshot;
mod store;
mod subtree;
mod tree;
mod view;

#[cfg(test)]
mod tests;

pub use group::ColumnGroup;
pub use silver_ssz::scalar::SszScalar;
pub use view::{ColumnReader, ColumnWriteView};

use crate::{
    ring::Id,
    types::{B256, EPOCHS_PER_SLASHINGS_VECTOR, HashFormat, VALIDATOR_REGISTRY_LIMIT},
};

/// A column's marker: its scalar `Val` plus a distinct type identity, so ring
/// ids of different columns can't be mixed.
pub trait ColumnSpec {
    type Val: SszScalar;
    /// The SSZ type's capacity: `N` for `Vector[T, N]`, the limit for
    /// `List[T, N]`. Roots pad to its chunk depth regardless of how much the
    /// tree currently materializes.
    const SSZ_LIMIT: usize;
    /// A list mixes its length into the root and can grow; a vector does
    /// neither.
    const IS_LIST: bool;
}

/// Column markers — one zero-sized type per registry-aligned column. Distinct
/// named types (rather than a discriminated `Col<V, ID>`) so ring ids of
/// different columns can't mix *and* `type_name` reads cleanly in perf frames
/// (`Balances`, not `Col<u64, 3>`).
pub struct Previous;
impl ColumnSpec for Previous {
    type Val = u8;
    const SSZ_LIMIT: usize = VALIDATOR_REGISTRY_LIMIT;
    const IS_LIST: bool = true;
}

pub struct Current;
impl ColumnSpec for Current {
    type Val = u8;
    const SSZ_LIMIT: usize = VALIDATOR_REGISTRY_LIMIT;
    const IS_LIST: bool = true;
}

pub struct Balances;
impl ColumnSpec for Balances {
    type Val = u64;
    const SSZ_LIMIT: usize = VALIDATOR_REGISTRY_LIMIT;
    const IS_LIST: bool = true;
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
    const SSZ_LIMIT: usize = VALIDATOR_REGISTRY_LIMIT;
    const IS_LIST: bool = true;
}

pub struct ValidatorsHash;
impl ColumnSpec for ValidatorsHash {
    type Val = B256;
    const SSZ_LIMIT: usize = VALIDATOR_REGISTRY_LIMIT;
    const IS_LIST: bool = true;
}

pub struct BuildersHash;
impl ColumnSpec for BuildersHash {
    type Val = B256;
    const SSZ_LIMIT: usize = VALIDATOR_REGISTRY_LIMIT;
    const IS_LIST: bool = true;
}

/// `Vector[Gwei, EPOCHS_PER_SLASHINGS_VECTOR]` — the first vector column, and
/// the only one written pointwise rather than swept: one bucket per epoch, plus
/// the running total as slashings land inside the current epoch.
pub struct Slashings;
impl ColumnSpec for Slashings {
    type Val = u64;
    const SSZ_LIMIT: usize = EPOCHS_PER_SLASHINGS_VECTOR;
    const IS_LIST: bool = false;
}

pub type SlashingsGroup = ColumnGroup<Slashings>;

impl SlashingsGroup {
    /// A vector is fork-invariant, so the geometry is always the binary one —
    /// `HashFormat::Gloas` never applies here.
    pub fn from_ring(ring: &[u64]) -> Self {
        debug_assert_eq!(ring.len(), EPOCHS_PER_SLASHINGS_VECTOR);
        Self::new(
            EPOCHS_PER_SLASHINGS_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            &<u64 as SszScalar>::as_ssz_bytes(ring),
            HashFormat::Fulu,
        )
        .expect("slashings ring is exactly the vector length")
    }
}

pub type SlashingsId = Id<SlashingsGroup>;
pub type SlashingsView<'a> = ColumnReader<'a, Slashings>;
pub type SlashingsWriteView<'a> = ColumnWriteView<'a, Slashings>;

pub type InactivityScoresGroup = ColumnGroup<Inactivity>;
pub type InactivityId = Id<InactivityScoresGroup>;
pub type InactivityView<'a> = ColumnReader<'a, Inactivity>;
pub type InactivityWriteView<'a> = ColumnWriteView<'a, Inactivity>;
