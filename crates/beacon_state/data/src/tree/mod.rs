mod group;
mod hashing_writer;
mod randao;
mod roots;
mod view;

#[cfg(test)]
mod progressive_tests;
#[cfg(test)]
mod tests;

pub use group::TreeGroup;
pub use randao::{
    RandaoMixes, RandaoMixesGroup, RandaoMixesId, RandaoMixesView, RandaoMixesWriteView,
};
pub use roots::{
    BlockRoots, BlockRootsGroup, BlockRootsId, RootsView, RootsWriteView, StateRoots,
    StateRootsGroup, StateRootsId,
};
pub use silver_hashing::{PageArray, TreeSpec};
pub use silver_ssz::scalar::SszScalar;
pub use view::{TreeView, TreeWriteView};

use crate::{
    ring::Id,
    types::{B256, EPOCHS_PER_SLASHINGS_VECTOR},
};

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
