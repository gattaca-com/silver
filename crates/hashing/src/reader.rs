use std::marker::PhantomData;

use crate::{
    B256, FlatTree, SszScalar, TreeSpec, format::TreeFormat, pool::PagePool, snapshot::PageSnapshot,
};

/// What a read walks: the writer's flat tree or a committed tree's pages.
/// `get` and `hash_root` are written once over [`node`](Self::node); only node
/// addressing differs.
enum Nodes<'a, C: TreeSpec> {
    Flat(&'a FlatTree<C>),
    Paged(&'a PagePool<C::Page>, &'a PageSnapshot),
}

impl<'a, C: TreeSpec> Nodes<'a, C> {
    #[inline]
    fn node(&self, n: usize) -> &B256 {
        match self {
            Nodes::Flat(t) => t.node(n),
            Nodes::Paged(pool, snap) => snap.node::<C>(pool, n),
        }
    }

    #[inline]
    fn count(&self) -> usize {
        match self {
            Nodes::Flat(t) => t.count(),
            Nodes::Paged(_, snap) => snap.len(),
        }
    }
}

/// Reads a list's values and SSZ root, from the writer's flat tree or from a
/// committed [`PageSnapshot`].
pub struct TreeReader<'a, C: TreeSpec> {
    nodes: Nodes<'a, C>,
    /// Resolved once at construction so per-element reads pay a single
    /// layout match.
    format: TreeFormat,
    _marker: PhantomData<fn() -> C>,
}

impl<'a, C: TreeSpec> TreeReader<'a, C> {
    #[inline]
    pub fn flat(tree: &'a FlatTree<C>) -> Self {
        Self { nodes: Nodes::Flat(tree), format: tree.format(), _marker: PhantomData }
    }

    #[inline]
    pub fn paged(pool: &'a PagePool<C::Page>, snap: &'a PageSnapshot) -> Self {
        Self { nodes: Nodes::Paged(pool, snap), format: snap.format(), _marker: PhantomData }
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
