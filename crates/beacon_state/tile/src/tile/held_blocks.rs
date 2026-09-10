use rustc_hash::FxHashMap;
use silver_beacon_state_data::{B256, Slot, StateId};
use silver_common::{BlockSource, NewGossipMsg, P2pStreamId, TCacheRead, hex32};
use silver_config::PendingBounds;

use super::block::StagedBlock;

const MAX_ORPHANS_PER_PARENT: usize = 4;

/// A staged block waiting for its data columns. `read` is not acquired, so
/// the ring may lap it; import re-acquires and asks for the block again on a
/// miss.
pub(super) struct WaitingBlock {
    pub(super) staged: StagedBlock,
    pub(super) read: TCacheRead,
    pub(super) source: BlockSource,
}

pub(super) struct Orphan {
    pub(super) block_root: B256,
    pub(super) slot: Slot,
    pub(super) pending: PendingBlock,
}

pub(super) enum PendingBlock {
    Gossip(NewGossipMsg),
    Rpc(P2pStreamId, TCacheRead),
}

impl PendingBlock {
    pub(super) fn source(&self) -> BlockSource {
        match self {
            Self::Gossip(_) => BlockSource::Gossip,
            Self::Rpc(..) => BlockSource::Rpc,
        }
    }
}

/// Blocks parked on a dependency, keyed by the root they wait for.
pub(super) struct OrphanPool {
    by_parent: FxHashMap<B256, Vec<Orphan>>,
    max_parents: usize,
}

impl OrphanPool {
    fn new(max_parents: usize) -> Self {
        Self { by_parent: FxHashMap::default(), max_parents }
    }

    pub(super) fn parents(&self) -> usize {
        self.by_parent.len()
    }

    /// True when the orphan is held afterwards, including one already held.
    pub(super) fn park(&mut self, parent_root: B256, orphan: Orphan) -> bool {
        let existing = self.by_parent.get(&parent_root);
        if existing.is_some_and(|v| v.iter().any(|held| held.block_root == orphan.block_root)) {
            return true;
        }

        let at_parent_cap = existing.is_some_and(|v| v.len() >= MAX_ORPHANS_PER_PARENT);
        let new_parent = existing.is_none();
        if at_parent_cap || (new_parent && self.by_parent.len() >= self.max_parents) {
            tracing::warn!(
                parent = hex32(&parent_root),
                block = hex32(&orphan.block_root),
                at_parent_cap,
                parents = self.by_parent.len(),
                cap = self.max_parents,
                "orphan buffer full; dropping orphan"
            );
            return false;
        }

        self.by_parent.entry(parent_root).or_default().push(orphan);
        true
    }

    pub(super) fn take(&mut self, parent_root: &B256) -> Vec<Orphan> {
        self.by_parent.remove(parent_root).unwrap_or_default()
    }

    fn drop_children(&mut self, parent_root: &B256) {
        self.by_parent.remove(parent_root);
    }

    fn clear_outdated(&mut self, finalized_slot: Slot) {
        self.by_parent.retain(|_, orphans| {
            orphans.retain(|orphan| orphan.slot > finalized_slot);
            !orphans.is_empty()
        });
    }
}

/// Every block held for a dependency, and what travels with it. Orphans wait on
/// a parent (or its payload envelope); staged blocks wait on their data
/// columns. A staged root is in at most one of `staged` / `available` at rest.
pub(super) struct HeldBlocks {
    pub(super) orphans: OrphanPool,
    pub(super) payload_orphans: OrphanPool,
    staged: FxHashMap<B256, WaitingBlock>,
    available: FxHashMap<B256, Slot>,
    /// Roots whose block failed the state transition or the EL, so a re-fetch
    /// or a child's parent chase does not run the same block again.
    rejected: FxHashMap<B256, Slot>,
}

impl HeldBlocks {
    pub(super) fn new(bounds: &PendingBounds) -> Self {
        Self {
            orphans: OrphanPool::new(bounds.max_parents),
            payload_orphans: OrphanPool::new(bounds.max_dc),
            staged: FxHashMap::default(),
            available: FxHashMap::default(),
            rejected: FxHashMap::default(),
        }
    }

    pub(super) fn staged_len(&self) -> usize {
        self.staged.len()
    }

    pub(super) fn is_staged(&self, block_root: &B256) -> bool {
        self.staged.contains_key(block_root)
    }

    pub(super) fn is_available(&self, block_root: &B256) -> bool {
        self.available.contains_key(block_root)
    }

    pub(super) fn is_rejected(&self, block_root: &B256) -> bool {
        self.rejected.contains_key(block_root)
    }

    pub(super) fn reject(&mut self, block_root: B256, slot: Slot) {
        self.rejected.insert(block_root, slot);
    }

    pub(super) fn discard_available(&mut self, block_root: &B256) {
        self.available.remove(block_root);
    }

    pub(super) fn stage(&mut self, waiting: WaitingBlock) -> B256 {
        let block_root = waiting.staged.parsed.block_root;
        debug_assert!(!self.staged.contains_key(&block_root));
        debug_assert!(!self.available.contains_key(&block_root));
        self.staged.insert(block_root, waiting);
        block_root
    }

    /// Availability is announced once, so the record outlives the release
    /// until an import consumes it.
    pub(super) fn mark_available(&mut self, block_root: B256, slot: Slot) -> Option<WaitingBlock> {
        self.available.insert(block_root, slot);
        self.staged.remove(&block_root)
    }

    /// The EL declared a staged block invalid: it is remembered as rejected so
    /// neither a re-fetch nor a child's parent chase runs it again.
    pub(super) fn reject_staged(&mut self, block_root: &B256) -> Option<BlockSource> {
        let waiting = self.staged.remove(block_root)?;
        self.rejected.insert(*block_root, waiting.staged.parsed.header.slot);
        self.orphans.drop_children(block_root);
        Some(waiting.source)
    }

    /// Finalization pruned fork choice; staged blocks whose parent went with
    /// it, and the orphans parked on them, no longer descend from it.
    pub(super) fn drop_outdated(&mut self, parent_known: impl Fn(&B256) -> bool) {
        let Self { staged, orphans, .. } = self;
        staged.retain(|root, waiting| {
            if parent_known(&waiting.staged.parsed.header.parent_root) {
                return true;
            }
            tracing::warn!(
                block = hex32(root),
                "staged block dropped at finalization: its parent left fork choice"
            );
            orphans.drop_children(root);
            false
        });
    }

    /// Below a finalized target no block waits for its columns, and range sync
    /// re-delivers the staged ones; a copy left staged would shadow that
    /// delivery.
    pub(super) fn drop_all_staged(&mut self) -> usize {
        for root in self.staged.keys() {
            self.orphans.drop_children(root);
        }
        let dropped = self.staged.len();
        self.staged.clear();
        dropped
    }

    pub(super) fn clear_outdated(&mut self, finalized_slot: Slot) {
        self.available.retain(|_, slot| *slot > finalized_slot);
        self.rejected.retain(|_, slot| *slot > finalized_slot);
        self.orphans.clear_outdated(finalized_slot);
        self.payload_orphans.clear_outdated(finalized_slot);
    }

    pub(super) fn state_ids_mut(&mut self) -> impl Iterator<Item = &mut StateId> {
        self.staged.values_mut().map(|waiting| waiting.staged.state_id_mut())
    }
}
