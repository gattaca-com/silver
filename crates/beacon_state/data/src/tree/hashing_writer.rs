use super::{TreeGroup, TreeSpec, flat::FlatTree, pool::PagePool, snapshot::PageSnapshot};
use crate::ring::Id;

/// A flat writable copy of one fork. `mirror` is what `tree` holds outside its
/// uncommitted chunks, as the ring entry `mirror_of` (`None`: the base) had it.
/// A mirror owns no pages, so an equal page id proves equal content only while
/// the mirrored pages are live. Pages are freed only at finalize, and a mirror
/// of a survivor or of the unchanged base names only live ids, so finalize
/// unmirrors any other.
pub(super) struct HashingWriter<C: TreeSpec> {
    tree: FlatTree<C>,
    mirror: PageSnapshot,
    mirror_of: Option<Id<TreeGroup<C>>>,
}

impl<C: TreeSpec> HashingWriter<C> {
    /// The writer, and `tree` committed as the base it mirrors.
    pub(super) fn new(mut tree: FlatTree<C>, pool: &mut PagePool<C::Page>) -> (Self, PageSnapshot) {
        let base = tree.to_snapshot(pool);
        let mut mirror = PageSnapshot::default();
        mirror.mirror(&base);
        (Self { tree, mirror, mirror_of: None }, base)
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
        target: &PageSnapshot,
        of: Option<Id<TreeGroup<C>>>,
    ) {
        self.tree.load(pool, &self.mirror, target);
        self.mirror.mirror(target);
        self.mirror_of = of;
    }

    pub(super) fn commit(
        &mut self,
        pool: &mut PagePool<C::Page>,
        dst: &mut PageSnapshot,
        parent: &PageSnapshot,
        id: Id<TreeGroup<C>>,
    ) {
        self.tree.commit(pool, dst, Some(parent));
        self.mirror.mirror(dst);
        self.mirror_of = Some(id);
    }

    pub(super) fn unmirror_dead(
        &mut self,
        base: &PageSnapshot,
        is_survivor: impl Fn(Id<TreeGroup<C>>) -> bool,
    ) {
        let live = match self.mirror_of {
            Some(id) => is_survivor(id),
            None => self.mirror.same_pages(base),
        };
        if !live {
            self.mirror.unmirror();
        }
    }
}
