use std::{io::Error, path::Path};

use fxhash::FxHashMap;
use silver_beacon_state_data::SpecConfig;
use silver_common::{merkle::B256, ssz_view::SignedBeaconBlockView};

use super::{PayloadKey, read_unfinalized_dir};
use crate::store::{Head, PendingWrite, WriteQueue, backfill::PayloadFacts, io};

/// One node of the unfinalized fork tree. The edge (`parent_root`) is durable
/// in the on-disk filename; this is the in-memory index rebuilt from `readdir`
/// on load for O(1) ancestor walks.
struct UnfinalizedBlock {
    slot: u64,
    parent_root: [u8; 32],
    payload_facts: PayloadFacts,
}

/// Unfinalized block fork tree: block_root → (slot, parent_root).
#[derive(Default)]
pub(crate) struct UnfinalizedBlocks(FxHashMap<[u8; 32], UnfinalizedBlock>);

impl UnfinalizedBlocks {
    pub(crate) const FINALIZED_DIR: &'static str = "blocks";
    /// Flat (no slot grouping) — bounded by the `[finalized, head]` window, a
    /// few epochs. Files: `<slot>_<parent_root>_<block_root>.ssz`.
    pub(crate) const UNFINALIZED_DIR: &'static str = "unfinalized";

    pub(crate) fn load(store_dir: &str, spec: &SpecConfig) -> Result<Self, Error> {
        let mut map = FxHashMap::default();
        let dir = Path::new(store_dir).join(Self::UNFINALIZED_DIR);
        read_unfinalized_dir(&dir, |name| {
            if let Some((block_root, slot, parent_root)) = io::parse_unfinalized_name(name) {
                let facts = match std::fs::read(dir.join(name)) {
                    Ok(ssz) if SignedBeaconBlockView::check_size(&ssz) => {
                        PayloadFacts::of(&ssz, spec.is_gloas_at_slot(slot))
                    }
                    _ => PayloadFacts::default(),
                };
                map.insert(block_root, UnfinalizedBlock {
                    slot,
                    parent_root,
                    payload_facts: facts,
                });
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

    pub(crate) fn insert(
        &mut self,
        root: [u8; 32],
        slot: u64,
        parent_root: [u8; 32],
        facts: PayloadFacts,
    ) {
        self.0.insert(root, UnfinalizedBlock { slot, parent_root, payload_facts: facts });
    }

    pub(crate) fn remove(&mut self, root: &[u8; 32]) -> Option<(u64, [u8; 32], PayloadFacts)> {
        self.0.remove(root).map(|b| (b.slot, b.parent_root, b.payload_facts))
    }

    /// The bid `parent_block_hash` of the canonical child of `root`: the block
    /// on the head's chain built on it.
    pub(crate) fn child_payload_parent(
        &self,
        head_slot: u64,
        head_root: B256,
        root: &B256,
    ) -> Option<B256> {
        let mut at = head_root;
        // Slots must strictly decrease towards the root, or a cycle from a
        // malformed filename would spin forever.
        let mut prev_slot = head_slot.saturating_add(1);
        while let Some(block) = self.0.get(&at) {
            if block.slot >= prev_slot {
                return None;
            }
            if block.parent_root == *root {
                return Some(block.payload_facts.parent_payload_hash);
            }
            prev_slot = block.slot;
            at = block.parent_root;
        }
        None
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

    pub(crate) fn canonical_payloads_in_range(
        &self,
        head: &Head,
        start: u64,
        end: u64,
    ) -> FxHashMap<u64, [u8; 32]> {
        let mut chain = FxHashMap::default();
        let mut root = head.root;
        let mut child_payload_parent = None;
        let mut prev_slot = head.slot.saturating_add(1);
        while let Some(block) = self.0.get(&root) {
            if block.slot >= prev_slot || block.slot < start {
                break;
            }
            let on_chain = match child_payload_parent {
                Some(parent) => parent == block.payload_facts.payload_hash,
                None => head.payload_full,
            };
            if block.slot < end && on_chain {
                chain.insert(block.slot, root);
            }
            child_payload_parent = Some(block.payload_facts.parent_payload_hash);
            prev_slot = block.slot;
            root = block.parent_root;
        }
        chain
    }

    /// Drop entries at or below `finalized_slot` (orphaned forks), queuing a
    /// prune write for each.
    pub(crate) fn prune_below(&mut self, finalized_slot: u64, write_queue: &mut WriteQueue) {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(payload: u8, parent_payload: u8) -> PayloadFacts {
        PayloadFacts {
            has_blobs: false,
            payload_hash: [payload; 32],
            parent_payload_hash: [parent_payload; 32],
        }
    }

    /// A ← B (builds on A's payload) ← C (builds on B's parent payload, so
    /// B's own payload is orphaned).
    #[test]
    fn canonical_payloads_follow_the_child_bids_and_the_head_resolution() {
        let mut blocks = UnfinalizedBlocks::default();
        blocks.insert([1; 32], 1, [0; 32], facts(1, 0));
        blocks.insert([2; 32], 2, [1; 32], facts(2, 1));
        blocks.insert([3; 32], 3, [2; 32], facts(3, 1));

        let mut head = Head { slot: 3, root: [3; 32], payload_full: true, ..Default::default() };
        let full = blocks.canonical_payloads_in_range(&head, 1, 4);
        assert_eq!(full.get(&1), Some(&[1; 32]));
        assert_eq!(full.get(&2), None, "the child built on its parent's payload instead");
        assert_eq!(full.get(&3), Some(&[3; 32]));

        head.payload_full = false;
        let empty = blocks.canonical_payloads_in_range(&head, 1, 4);
        assert_eq!(empty.get(&3), None, "fork choice resolved the head EMPTY");
        assert_eq!(empty.get(&1), Some(&[1; 32]));
    }
}
