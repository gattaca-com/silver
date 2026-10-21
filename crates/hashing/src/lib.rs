//! SSZ Merkle roots for the large lists of an Ethereum beacon state.
//!
//! A list is written as one flat array of hashes ([`FlatTree`]). Writes mark
//! their chunks, and a rehash hashes only the marked paths, one level at a
//! time. A commit cuts the array into copy-on-write pages, so every copy of
//! the list shares the pages it did not write.
//!
//! Hashing never decides who owns a page: it reaches pages only through
//! [`PageStore`] and [`PageAlloc`]. Two storages implement them:
//!
//! - [`PagePool`] + [`PageSnapshot`]: one writer, with forks freed explicitly
//!   against a finalized base.
//! - [`SharedList`]: refcounted pages that any thread may clone and drop.

mod flat_hashing;
pub mod merkle;
#[cfg(feature = "multi-owner")]
mod multi_owner;
pub mod progressive;
pub mod scalar;
mod single_owner;
mod storage;

pub use flat_hashing::{FlatTree, TreeFormat, TreeReader};
use flat_hashing::{MAX_SEGS, seg_off};
pub use merkle::B256;
#[cfg(feature = "multi-owner")]
pub use multi_owner::SharedList;
pub use scalar::SszScalar;
pub use single_owner::{PagePool, PageSnapshot};
pub use storage::{PageAlloc, PageArray, PageId, PageStore, PageTable};

const VALIDATOR_REGISTRY_LIMIT: usize = 1 << 40;

/// One SSZ list or vector of basic values: its element type, page size and
/// limit. Each list is a zero-sized marker type implementing this.
pub trait TreeSpec {
    type Val: SszScalar;
    /// The copy-on-write page. Lists written at scattered indices want small
    /// pages, so each write copies less. Lists rewritten in bulk want large
    /// ones, so a commit shares and frees fewer pages.
    type Page: PageArray;
    /// `N` of `Vector[T, N]` or `List[T, N]`. The root is padded to this
    /// depth, however few leaves the tree holds. Defaults to the validator
    /// registry limit.
    const SSZ_LIMIT: usize = VALIDATOR_REGISTRY_LIMIT;
    /// A list mixes its length into the root and can grow; a vector does
    /// neither.
    const IS_LIST: bool = true;

    /// Derived from `Val` and `Page`; never overridden.
    const VALS_PER_CHUNK: usize = <Self::Val as SszScalar>::VALS_PER_CHUNK;
    const PAGE_NODES: usize = <Self::Page as PageArray>::LEN;
    const SEG_OFF: [usize; MAX_SEGS + 1] = seg_off(Self::PAGE_NODES);
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HashFormat {
    Fixed,
    Progressive,
}
