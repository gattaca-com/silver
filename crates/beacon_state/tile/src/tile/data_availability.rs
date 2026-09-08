use rustc_hash::FxHashMap;
use silver_beacon_state_data::{B256, Slot, StateId};
use silver_common::{BlockSource, TCacheRead, TRandomAccess, hex32};

use super::{BeaconStateTile, Producers, block::StagedBlock};

/// A staged block waiting for its data columns. `read` is not acquired, so
/// the ring may lap it; import re-acquires and drops on a miss.
pub(super) struct WaitingBlock {
    pub(super) staged: StagedBlock,
    pub(super) read: TCacheRead,
    pub(super) source: BlockSource,
}

/// Per block root, whichever of the two arrived first: the columns'
/// availability, or the block itself with its state transition done. A root
/// is in at most one map.
pub(super) struct DataAvailability {
    available: FxHashMap<B256, Slot>,
    awaiting: FxHashMap<B256, WaitingBlock>,
    max_awaiting: usize,
}

impl DataAvailability {
    pub(super) fn new(max_awaiting: usize) -> Self {
        Self { available: FxHashMap::default(), awaiting: FxHashMap::default(), max_awaiting }
    }

    pub(super) fn awaiting_len(&self) -> usize {
        self.awaiting.len()
    }

    pub(super) fn is_available(&self, block_root: &B256) -> bool {
        self.available.contains_key(block_root)
    }

    pub(super) fn is_awaiting(&self, block_root: &B256) -> bool {
        self.awaiting.contains_key(block_root)
    }

    pub(super) fn discard_available(&mut self, block_root: &B256) {
        self.available.remove(block_root);
    }

    pub(super) fn has_room(&self) -> bool {
        self.awaiting.len() < self.max_awaiting
    }

    pub(super) fn hold(&mut self, waiting: WaitingBlock) {
        let block_root = waiting.staged.parsed.block_root;
        debug_assert!(!self.awaiting.contains_key(&block_root));
        debug_assert!(!self.available.contains_key(&block_root));
        self.awaiting.insert(block_root, waiting);
    }

    /// Records availability; returns the block it releases, if any.
    pub(super) fn mark_available(&mut self, block_root: B256, slot: Slot) -> Option<WaitingBlock> {
        let released = self.awaiting.remove(&block_root);
        if released.is_none() {
            self.available.insert(block_root, slot);
        }
        released
    }

    pub(super) fn clear_finalized(&mut self, finalized_slot: Slot) {
        self.available.retain(|_, slot| *slot > finalized_slot);
    }

    /// Finalization pruned fork choice; a waiting block whose parent went with
    /// it no longer descends from the finalized block.
    pub(super) fn drop_outdated(&mut self, parent_known: impl Fn(&B256) -> bool) {
        self.awaiting.retain(|root, waiting| {
            let keep = parent_known(&waiting.staged.parsed.header.parent_root);
            if !keep {
                tracing::warn!(
                    block = hex32(root),
                    "staged block dropped at finalization: its parent left fork choice"
                );
            }
            keep
        });
    }

    pub(super) fn state_ids_mut(&mut self) -> impl Iterator<Item = &mut StateId> {
        self.awaiting.values_mut().map(|waiting| waiting.staged.state_id_mut())
    }

    #[cfg(test)]
    pub(super) fn state_id(&self, block_root: &B256) -> Option<StateId> {
        self.awaiting.get(block_root).map(|waiting| waiting.staged.state_id())
    }
}

impl BeaconStateTile {
    pub(super) fn handle_data_columns_available(
        &mut self,
        block_root: B256,
        slot: Slot,
        producers: &mut Producers,
    ) {
        let Some(waiting) = self.data_availability.mark_available(block_root, slot) else {
            tracing::debug!(block = hex32(&block_root), slot, "DataColumnsAvailable received");
            return;
        };
        let WaitingBlock { staged, read, source } = waiting;

        let acquired = self.block_consumer(source).acquire(read);
        let Ok((data, _)) = acquired.buffer() else {
            tracing::error!(
                block = hex32(&block_root),
                slot,
                "block lapped in the tcache before its data columns arrived; dropped"
            );
            return;
        };

        self.import_staged(staged, data);
        self.announce_imported(data, block_root, read, source, producers);
        self.on_accept(Some(block_root), producers);
    }

    fn block_consumer(&mut self, source: BlockSource) -> &mut TRandomAccess {
        match source {
            BlockSource::Gossip => &mut self.gossip_consumer,
            BlockSource::Rpc => &mut self.rpc_consumer,
        }
    }
}
