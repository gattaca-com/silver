mod chunk_bits;
mod chunk_writes;
mod flat;
mod format;
mod group;
mod hashing_writer;
mod list;
mod page_format;
mod pool;
mod progressive_list;
mod randao;
mod roots;
mod snapshot;
mod store;
mod subtree;
mod view;

#[cfg(test)]
mod tests;

use format::{MAX_SEGS, seg_off};
pub use group::TreeGroup;
pub use pool::PageArray;
pub use randao::{
    RandaoMixes, RandaoMixesGroup, RandaoMixesId, RandaoMixesView, RandaoMixesWriteView,
};
pub use roots::{
    BlockRoots, BlockRootsGroup, BlockRootsId, RootsView, RootsWriteView, StateRoots,
    StateRootsGroup, StateRootsId,
};
pub use silver_ssz::scalar::SszScalar;
pub use view::{TreeReader, TreeWriteView};

use crate::{
    ring::Id,
    types::{B256, EPOCHS_PER_SLASHINGS_VECTOR, VALIDATOR_REGISTRY_LIMIT},
};

pub type TreeView<'a, C> = TreeReader<'a, C>;

/// A column's marker: its scalar `Val` plus a distinct type identity, so ring
/// ids of different columns can't be mixed.
pub trait TreeSpec {
    type Val: SszScalar;
    /// This column's COW page. Tunable per column: pointwise-written trees want
    /// fewer nodes per page (less copied per dirty leaf), densely written ones
    /// want more (fewer pages to share and free per fork).
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

/// Tree markers — one zero-sized type per registry-aligned list, named
/// (rather than a discriminated `Col<V, ID>`) so `type_name` reads cleanly in
/// perf frames (`Balances`, not `Col<u64, 3>`).
pub struct Previous;
impl TreeSpec for Previous {
    type Val = u8;
    type Page = [B256; 256];
}

pub struct Current;
impl TreeSpec for Current {
    type Val = u8;
    type Page = [B256; 256];
}

pub struct Balances;
impl TreeSpec for Balances {
    type Val = u64;
    type Page = [B256; 16];
}

pub type PreviousParticipationGroup = TreeGroup<Previous>;
pub type PreviousParticipationId = Id<PreviousParticipationGroup>;

pub type CurrentParticipationGroup = TreeGroup<Current>;
pub type CurrentParticipationId = Id<CurrentParticipationGroup>;

pub type ParticipationView<'a, M> = TreeView<'a, M>;
pub type ParticipationWriteView<'a, M> = TreeWriteView<'a, M>;

pub type BalancesGroup = TreeGroup<Balances>;
pub type BalancesId = Id<BalancesGroup>;

pub type BalancesReader<'a> = TreeView<'a, Balances>;
pub type BalancesWriteView<'a> = TreeWriteView<'a, Balances>;

pub struct Inactivity;
impl TreeSpec for Inactivity {
    type Val = u64;
    type Page = [B256; 256];
}

pub struct ValidatorsHash;
impl TreeSpec for ValidatorsHash {
    type Val = B256;
    type Page = [B256; 1024];
}

pub struct BuildersHash;
impl TreeSpec for BuildersHash {
    type Val = B256;
    type Page = [B256; 32];
}

/// `Vector[Gwei, EPOCHS_PER_SLASHINGS_VECTOR]`, written pointwise rather than
/// swept: one bucket per epoch, plus the running total as slashings land
/// inside the current epoch.
pub struct Slashings;
impl TreeSpec for Slashings {
    type Val = u64;
    type Page = [B256; 32];
    const SSZ_LIMIT: usize = EPOCHS_PER_SLASHINGS_VECTOR;
    const IS_LIST: bool = false;
}

pub type SlashingsGroup = TreeGroup<Slashings>;
pub type SlashingsId = Id<SlashingsGroup>;
pub type SlashingsView<'a> = TreeView<'a, Slashings>;
pub type SlashingsWriteView<'a> = TreeWriteView<'a, Slashings>;

pub type InactivityScoresGroup = TreeGroup<Inactivity>;
pub type InactivityId = Id<InactivityScoresGroup>;
pub type InactivityView<'a> = TreeView<'a, Inactivity>;
pub type InactivityWriteView<'a> = TreeWriteView<'a, Inactivity>;
