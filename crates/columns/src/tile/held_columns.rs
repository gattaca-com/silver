use std::time::{Duration, Instant};

use silver_beacon_state_data::SLOTS_PER_EPOCH;
use silver_common::{SszCache, Wheel, ssz_view::NUMBER_OF_COLUMNS};

use crate::{BlockRoot, validate::PendingColumn};

const MAX_GOSSIP_KEYS: usize = 2 * SLOTS_PER_EPOCH as usize;
/// Room for a full range batch even with every gossip key taken.
const MAX_KEYS: usize = 2 * MAX_GOSSIP_KEYS;

/// Sidecars that cannot be checked until another block validates, keyed by
/// that block's root. Nothing ties a held sidecar to its block yet, so a key
/// keeps the first copy of each column. Gossip opens at most half the keys,
/// so it never crowds out sidecars this node asked for.
pub(super) struct HeldColumns {
    wheel: Wheel<BlockRoot, Held, 4>,
}

struct Held {
    opened_by_gossip: bool,
    columns: Vec<HeldColumn>,
}

struct HeldColumn {
    block_root: BlockRoot,
    column_index: u64,
    column: PendingColumn,
}

impl HeldColumns {
    pub(super) fn new(interval: Duration) -> Self {
        Self { wheel: Wheel::new(interval) }
    }

    pub(super) fn hold_for_block(
        &mut self,
        block_root: BlockRoot,
        column_index: u64,
        column: PendingColumn,
    ) -> bool {
        self.hold(block_root, block_root, column_index, column)
    }

    pub(super) fn hold(
        &mut self,
        key: BlockRoot,
        block_root: BlockRoot,
        column_index: u64,
        column: PendingColumn,
    ) -> bool {
        let gossip = column.gossip_subnet.is_some();
        if !self.wheel.contains(&key) && !self.opens_key(gossip) {
            return false;
        }
        let held = self
            .wheel
            .entry(key)
            .or_insert_with(|| Held { opened_by_gossip: gossip, columns: Vec::new() });
        let duplicate = held
            .columns
            .iter()
            .any(|held| held.block_root == block_root && held.column_index == column_index);
        if duplicate || held.columns.len() >= NUMBER_OF_COLUMNS {
            return false;
        }
        held.columns.push(HeldColumn { block_root, column_index, column });
        true
    }

    fn opens_key(&self, gossip: bool) -> bool {
        self.wheel.len() < MAX_KEYS &&
            (!gossip ||
                self.wheel.values().filter(|held| held.opened_by_gossip).count() <
                    MAX_GOSSIP_KEYS)
    }

    pub(super) fn take(
        &mut self,
        key: &BlockRoot,
    ) -> Option<impl Iterator<Item = PendingColumn> + use<>> {
        let held = self.wheel.remove(key)?;
        Some(held.columns.into_iter().map(|held| held.column))
    }

    pub(super) fn remove(&mut self, key: &BlockRoot) {
        self.wheel.remove(key);
    }

    pub(super) fn maybe_rotate(&mut self, now: Instant) {
        self.wheel.maybe_rotate(now);
    }

    pub(super) fn retain_from(&mut self, seq: u64) {
        self.wheel.retain(|_, held| {
            held.columns.retain(|held| {
                held.column.ssz_cache != SszCache::DataColumns || held.column.sidecar.seq() >= seq
            });
            !held.columns.is_empty()
        });
    }

    #[cfg(test)]
    pub(super) fn contains(&self, key: &BlockRoot) -> bool {
        self.wheel.contains(key)
    }

    #[cfg(test)]
    pub(super) fn is_empty(&self) -> bool {
        self.wheel.is_empty()
    }

    #[cfg(test)]
    pub(super) fn len_of(&self, key: &BlockRoot) -> usize {
        self.wheel.get(key).map_or(0, |held| held.columns.len())
    }
}
