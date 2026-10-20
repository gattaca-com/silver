use silver_hashing::{FlatTree, PagePool, PageSnapshot, PageTable};

use super::{TreeGroup, TreeSpec};
use crate::ring::{Id, Ring};

/// The group's flat tree, plus which committed table it matches outside its
/// uncommitted chunks, if any. A load diffs against that table, so it copies
/// only the pages that differ.
///
/// Equal page ids prove equal content only while those pages are live. Pages
/// are freed only at finalize, which forgets a table that did not survive.
pub(super) struct HashingWriter<C: TreeSpec> {
    tree: FlatTree<C>,
    loaded: Option<Committed<C>>,
}

pub(super) enum Committed<C: TreeSpec> {
    Base,
    Entry(Id<TreeGroup<C>>),
}

impl<C: TreeSpec> Committed<C> {
    #[inline]
    fn table<'a>(&self, base: &'a PageSnapshot, ring: &'a Ring<TreeGroup<C>>) -> &'a PageTable {
        match self {
            Committed::Base => base.table(),
            Committed::Entry(id) => ring.get(*id).table(),
        }
    }
}

impl<C: TreeSpec> HashingWriter<C> {
    /// The writer, and `tree` committed as the base it matches.
    pub(super) fn new(mut tree: FlatTree<C>, pool: &mut PagePool<C::Page>) -> (Self, PageSnapshot) {
        let base = PageSnapshot::from_tree(&mut tree, pool);
        (Self { tree, loaded: Some(Committed::Base) }, base)
    }

    #[inline]
    pub(super) fn tree(&self) -> &FlatTree<C> {
        &self.tree
    }

    #[inline]
    pub(super) fn tree_mut(&mut self) -> &mut FlatTree<C> {
        &mut self.tree
    }

    pub(super) fn load(
        &mut self,
        pool: &PagePool<C::Page>,
        base: &PageSnapshot,
        ring: &Ring<TreeGroup<C>>,
        target: Committed<C>,
    ) {
        let nothing = PageTable::default();
        let loaded = self.loaded.as_ref().map_or(&nothing, |l| l.table(base, ring));
        self.tree.load(pool, loaded, target.table(base, ring));
        self.loaded = Some(target);
    }

    pub(super) fn commit(
        &mut self,
        pool: &mut PagePool<C::Page>,
        dst: &mut PageSnapshot,
        parent: &PageSnapshot,
        id: Id<TreeGroup<C>>,
    ) {
        dst.commit(&mut self.tree, pool, parent);
        self.loaded = Some(Committed::Entry(id));
    }

    /// `winner` now names the base; `base_kept` says the promotion left the
    /// base's pages as they were.
    pub(super) fn forget_dead(
        &mut self,
        winner: Id<TreeGroup<C>>,
        base_kept: bool,
        is_survivor: impl Fn(Id<TreeGroup<C>>) -> bool,
    ) {
        self.loaded = match self.loaded.take() {
            Some(Committed::Entry(id)) if id == winner => Some(Committed::Base),
            Some(Committed::Entry(id)) if is_survivor(id) => Some(Committed::Entry(id)),
            Some(Committed::Base) if base_kept => Some(Committed::Base),
            _ => None,
        };
    }
}
