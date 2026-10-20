//! SSZ Merkle roots for the large lists of an Ethereum beacon state.
//!
//! A list is written as one flat array of hashes ([`FlatTree`]). Writes mark
//! their chunks, and a rehash hashes only the marked paths, one level at a
//! time. A commit cuts the array into copy-on-write pages, so every copy of
//! the list shares the pages it did not write.

mod chunk_bits;
mod chunk_writes;
mod flat;
mod format;
mod list;
pub mod merkle;
mod page_format;
mod pool;
pub mod progressive;
mod progressive_list;
mod reader;
pub mod scalar;
mod snapshot;
mod storage;
mod store;
mod subtree;
mod table;

pub use flat::FlatTree;
pub use format::TreeFormat;
use format::{MAX_SEGS, seg_off};
pub use merkle::B256;
pub use pool::PagePool;
pub use reader::TreeReader;
pub use scalar::SszScalar;
pub use snapshot::PageSnapshot;
pub use storage::{PageAlloc, PageArray, PageId, PageStore};
pub use table::PageTable;

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
