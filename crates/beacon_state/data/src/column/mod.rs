mod format;
mod group;
mod list;
mod pool;
mod progressive_list;
mod roots;
mod snapshot;
mod store;
mod subtree;
mod tree;
mod view;

#[cfg(test)]
mod tests;

use format::{MAX_SEGS, seg_off};
pub use group::ColumnGroup;
pub use pool::PageArray;
pub use roots::{
    BlockRoots, BlockRootsGroup, BlockRootsId, RootsView, RootsWriteView, StateRoots,
    StateRootsGroup, StateRootsId,
};
pub use silver_ssz::scalar::SszScalar;
pub use view::{ColumnReader, ColumnWriteView};

use crate::{
    ring::Id,
    types::{B256, EPOCHS_PER_SLASHINGS_VECTOR, VALIDATOR_REGISTRY_LIMIT},
};

/// A column's marker: its scalar `Val` plus a distinct type identity, so ring
/// ids of different columns can't be mixed.
pub trait ColumnSpec {
    type Val: SszScalar;
    /// This column's COW page. Tunable per column: pointwise-written trees want
    /// fewer nodes per page (less copied per dirty leaf), densely swept ones
    /// want more (smaller page tables to diff every roll).
    type Page: PageArray;
    /// The SSZ type's capacity: `N` for `Vector[T, N]`, the limit for
    /// `List[T, N]`. Roots pad to its chunk depth regardless of how much the
    /// tree currently materializes. Defaults to the registry limit — most
    /// columns are registry-aligned.
    const SSZ_LIMIT: usize = VALIDATOR_REGISTRY_LIMIT;
    /// A list mixes its length into the root and can grow; a vector does
    /// neither.
    const IS_LIST: bool = true;

    /// Geometry derived from `Val`/`Page` at compile time — these defaults
    /// *are* the definition; columns never override them.
    const VALS_PER_CHUNK: usize = <Self::Val as SszScalar>::VALS_PER_CHUNK;
    const PAGE_NODES: usize = <Self::Page as PageArray>::LEN;
    const SEG_OFF: [usize; MAX_SEGS + 1] = seg_off(Self::PAGE_NODES);
}

/// Column markers — one zero-sized type per registry-aligned column, named
/// (rather than a discriminated `Col<V, ID>`) so `type_name` reads cleanly in
/// perf frames (`Balances`, not `Col<u64, 3>`).
pub struct Previous;
impl ColumnSpec for Previous {
    type Val = u8;
    type Page = [B256; 32];
}

pub struct Current;
impl ColumnSpec for Current {
    type Val = u8;
    type Page = [B256; 32];
}

pub struct Balances;
impl ColumnSpec for Balances {
    type Val = u64;
    type Page = [B256; 32];
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
    type Page = [B256; 256];
}

pub struct ValidatorsHash;
impl ColumnSpec for ValidatorsHash {
    type Val = B256;
    type Page = [B256; 1024];
}

pub struct BuildersHash;
impl ColumnSpec for BuildersHash {
    type Val = B256;
    type Page = [B256; 32];
}

/// `Vector[Gwei, EPOCHS_PER_SLASHINGS_VECTOR]`, written pointwise rather than
/// swept: one bucket per epoch, plus the running total as slashings land
/// inside the current epoch.
pub struct Slashings;
impl ColumnSpec for Slashings {
    type Val = u64;
    type Page = [B256; 32];
    const SSZ_LIMIT: usize = EPOCHS_PER_SLASHINGS_VECTOR;
    const IS_LIST: bool = false;
}

pub type SlashingsGroup = ColumnGroup<Slashings>;
pub type SlashingsId = Id<SlashingsGroup>;
pub type SlashingsView<'a> = ColumnReader<'a, Slashings>;
pub type SlashingsWriteView<'a> = ColumnWriteView<'a, Slashings>;

pub type InactivityScoresGroup = ColumnGroup<Inactivity>;
pub type InactivityId = Id<InactivityScoresGroup>;
pub type InactivityView<'a> = ColumnReader<'a, Inactivity>;
pub type InactivityWriteView<'a> = ColumnWriteView<'a, Inactivity>;
