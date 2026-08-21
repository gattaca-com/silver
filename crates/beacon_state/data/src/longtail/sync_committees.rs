use crate::{
    merkle::B256,
    types::{SYNC_COMMITTEE_SIZE, SyncCommittee},
};

/// The two sync committees, their cached SSZ roots, and the current
/// committee's validator indices — one bundle because the period rotation
/// writes all five together. The rotation costs one committee hash (24 KB of
/// pubkeys): the promoted `next` brings its root with it.
pub struct SyncCommittees {
    current: SyncCommittee,
    next: SyncCommittee,
    /// Validator index per `current` pubkey, `u32::MAX` where unknown.
    indices: [u32; SYNC_COMMITTEE_SIZE],
    current_root: B256,
    next_root: B256,
}

// Manual, not derived: the derived `clone_from` would route through
// `clone()`, putting the two 24 KB committees on the stack — enough, layered
// under `decompose`, to overflow a test thread.
impl Clone for SyncCommittees {
    fn clone(&self) -> Self {
        let mut c = Self::default();
        c.clone_from(self);
        c
    }

    fn clone_from(&mut self, source: &Self) {
        self.current = source.current;
        self.next = source.next;
        self.indices = source.indices;
        self.current_root = source.current_root;
        self.next_root = source.next_root;
    }
}

impl Default for SyncCommittees {
    fn default() -> Self {
        Self {
            current: SyncCommittee::default(),
            next: SyncCommittee::default(),
            indices: [0; SYNC_COMMITTEE_SIZE],
            current_root: B256::default(),
            next_root: B256::default(),
        }
    }
}

impl SyncCommittees {
    /// Fill both committees in place (24 KB each never rides the stack), then
    /// re-derive the cached roots.
    pub(crate) fn fill_rehashing<R>(
        &mut self,
        fill: impl FnOnce(&mut SyncCommittee, &mut SyncCommittee) -> R,
    ) -> R {
        let result = fill(&mut self.current, &mut self.next);
        self.current_root = self.current.hash_root();
        self.next_root = self.next.hash_root();
        result
    }

    #[inline]
    pub fn current(&self) -> &SyncCommittee {
        &self.current
    }

    #[inline]
    pub fn next(&self) -> &SyncCommittee {
        &self.next
    }

    #[inline]
    pub fn indices(&self) -> &[u32; SYNC_COMMITTEE_SIZE] {
        &self.indices
    }

    #[inline]
    pub fn current_root(&self) -> B256 {
        self.current_root
    }

    #[inline]
    pub fn next_root(&self) -> B256 {
        self.next_root
    }

    pub(crate) fn set_indices(&mut self, indices: [u32; SYNC_COMMITTEE_SIZE]) {
        self.indices = indices;
    }

    /// `indices` addresses the freshly-promoted current committee (the old
    /// `next`), not `new_next`.
    pub(super) fn rotate(&mut self, new_next: &SyncCommittee, indices: [u32; SYNC_COMMITTEE_SIZE]) {
        self.current = self.next;
        self.current_root = self.next_root;
        self.next_root = new_next.hash_root();
        self.next = *new_next;
        self.indices = indices;
    }
}
