use std::{collections::VecDeque, io::Error, path::Path};

use fxhash::FxHashMap;

use super::{PayloadKey, read_unfinalized_dir};
use crate::store::{PendingWrite, io};

/// One node of the unfinalized fork tree. The edge (`parent_root`) is durable
/// in the on-disk filename; this is the in-memory index rebuilt from `readdir`
/// on load for O(1) ancestor walks.
struct UnfinalizedBlock {
    slot: u64,
    parent_root: [u8; 32],
}

/// Unfinalized block fork tree: block_root → (slot, parent_root).
#[derive(Default)]
pub(crate) struct UnfinalizedBlocks(FxHashMap<[u8; 32], UnfinalizedBlock>);

impl UnfinalizedBlocks {
    pub(crate) const FINALIZED_DIR: &'static str = "blocks";
    /// Flat (no slot grouping) — bounded by the `[finalized, head]` window, a
    /// few epochs. Files: `<slot>_<parent_root>_<block_root>.ssz`.
    pub(crate) const UNFINALIZED_DIR: &'static str = "unfinalized";

    pub(crate) fn load(store_dir: &str) -> Result<Self, Error> {
        let mut map = FxHashMap::default();
        let dir = Path::new(store_dir).join(Self::UNFINALIZED_DIR);
        read_unfinalized_dir(&dir, |name| {
            if let Some((block_root, slot, parent_root)) = io::parse_unfinalized_name(name) {
                map.insert(block_root, UnfinalizedBlock { slot, parent_root });
            }
        })?;
        Ok(Self(map))
    }

    pub(crate) fn contains(&self, root: &[u8; 32]) -> bool {
        self.0.contains_key(root)
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    /// (slot, parent_root) of an unfinalized block, if present.
    pub(crate) fn get(&self, root: &[u8; 32]) -> Option<(u64, [u8; 32])> {
        self.0.get(root).map(|b| (b.slot, b.parent_root))
    }

    pub(crate) fn insert(&mut self, root: [u8; 32], slot: u64, parent_root: [u8; 32]) {
        self.0.insert(root, UnfinalizedBlock { slot, parent_root });
    }

    pub(crate) fn remove(&mut self, root: &[u8; 32]) -> Option<(u64, [u8; 32])> {
        self.0.remove(root).map(|b| (b.slot, b.parent_root))
    }

    /// (block_root, slot, parent_root) for each unfinalized block.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (&[u8; 32], u64, [u8; 32])> {
        self.0.iter().map(|(root, b)| (root, b.slot, b.parent_root))
    }

    /// Canonical blocks with slot in `[start, end)`, walking ancestors of the
    /// head through the tree. Maps slot → (parent_root, block_root). Empty
    /// before the first Status.
    pub(crate) fn canonical_chain_in_range(
        &self,
        head_root: [u8; 32],
        head_slot: u64,
        start: u64,
        end: u64,
    ) -> FxHashMap<u64, ([u8; 32], [u8; 32])> {
        let mut chain = FxHashMap::default();
        let mut root = head_root;
        // Enforce strictly-decreasing slots towards the root. A cycle — a
        // self-parenting block or A→B→A from malformed gossip or a stale
        // on-disk filename — would otherwise spin forever: a remote DoS via any
        // BlocksByRange. Seed at head_slot+1 so the head block (whose slot is
        // head_slot) is admitted.
        let mut prev_slot = head_slot.saturating_add(1);
        while let Some(block) = self.0.get(&root) {
            if block.slot >= prev_slot || block.slot < start {
                break;
            }
            if block.slot < end {
                chain.insert(block.slot, (block.parent_root, root));
            }
            prev_slot = block.slot;
            root = block.parent_root;
        }
        chain
    }

    /// Drop entries at or below `finalized_slot` (orphaned forks), queuing a
    /// prune write for each.
    pub(crate) fn prune_below(
        &mut self,
        finalized_slot: u64,
        write_queue: &mut VecDeque<PendingWrite>,
    ) {
        self.0.retain(|root, block| {
            if block.slot <= finalized_slot {
                write_queue.push_back(PendingWrite::Prune {
                    slot: block.slot,
                    key: PayloadKey::Block { parent_root: block.parent_root, block_root: *root },
                });
                false
            } else {
                true
            }
        });
    }
}
