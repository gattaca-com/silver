use std::marker::PhantomData;

use crate::{
    B256, FlatTree, SszScalar, TreeSpec, format::TreeFormat, storage::PageStore, table::PageTable,
};

/// What a read walks: the writer's flat tree or a committed tree's pages.
/// `get` and `hash_root` are written once over [`node`](Self::node); only node
/// addressing differs.
enum Nodes<'a, C: TreeSpec, Store> {
    Flat(&'a FlatTree<C>),
    Paged(&'a Store, &'a PageTable),
}

impl<C: TreeSpec, Store: PageStore> Nodes<'_, C, Store> {
    #[inline]
    fn node(&self, n: usize) -> &B256 {
        match self {
            Nodes::Flat(t) => t.node(n),
            Nodes::Paged(pages, table) => table.node::<C>(*pages, n),
        }
    }

    #[inline]
    fn count(&self) -> usize {
        match self {
            Nodes::Flat(t) => t.count(),
            Nodes::Paged(_, table) => table.len(),
        }
    }
}

/// Reads a list's values and SSZ root, from the writer's flat tree or from a
/// committed table in `Store`.
pub struct TreeReader<'a, C: TreeSpec, Store> {
    nodes: Nodes<'a, C, Store>,
    /// Resolved once at construction so per-element reads pay a single
    /// layout match.
    format: TreeFormat,
    _marker: PhantomData<fn() -> C>,
}

impl<'a, C: TreeSpec, Store: PageStore> TreeReader<'a, C, Store> {
    #[inline]
    pub fn flat(tree: &'a FlatTree<C>) -> Self {
        Self { nodes: Nodes::Flat(tree), format: tree.format(), _marker: PhantomData }
    }

    #[inline]
    pub fn paged(pages: &'a Store, table: &'a PageTable) -> Self {
        Self { nodes: Nodes::Paged(pages, table), format: table.format(), _marker: PhantomData }
    }

    #[inline]
    fn leaf_pos(&self, chunk: usize) -> usize {
        self.format.leaf_pos::<C>(chunk)
    }

    #[inline]
    pub fn get(&self, ix: usize) -> C::Val {
        let k = C::VALS_PER_CHUNK;
        <C::Val>::lane(self.nodes.node(self.leaf_pos(ix / k)), ix % k)
    }

    #[inline]
    pub fn hash_root(&self) -> B256 {
        if let Nodes::Flat(t) = self.nodes {
            debug_assert!(!t.has_pending_rehash(), "deferred writes not rehashed before root");
        }
        self.format.hash_root::<C>(self.nodes.count(), |n| *self.nodes.node(n))
    }
}
