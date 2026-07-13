use std::{collections::VecDeque, io::Error, path::Path};

use fxhash::FxHashMap;

use super::{PayloadKey, read_unfinalized_dir};
use crate::store::{PendingWrite, io};

/// Unfinalized custodied columns: block_root → (slot, bitmask of columns on
/// disk). Canonicity follows the owning block. Owns all custody-bitmask logic.
#[derive(Default)]
pub(crate) struct UnfinalizedColumns(FxHashMap<[u8; 32], (u64, u128)>);

impl UnfinalizedColumns {
    pub(crate) const FINALIZED_DIR: &'static str = "columns";
    /// Keyed by owning block (columns have no fork of their own — canonicity
    /// follows the block). Files: `<slot>_<block_root>_<column>.ssz`.
    pub(crate) const UNFINALIZED_DIR: &'static str = "unfinalized_columns";

    pub(crate) fn load(store_dir: &str) -> Result<Self, Error> {
        let mut map: FxHashMap<[u8; 32], (u64, u128)> = FxHashMap::default();
        let dir = Path::new(store_dir).join(Self::UNFINALIZED_DIR);
        read_unfinalized_dir(&dir, |name| {
            if let Some((block_root, slot, column)) = io::parse_unfinalized_column_name(name) {
                map.entry(block_root).or_insert((slot, 0)).1 |= 1u128 << column;
            }
        })?;
        Ok(Self(map))
    }

    /// Mark `column` present for `root`, seeding the slot on first sight.
    pub(crate) fn record(&mut self, root: [u8; 32], slot: u64, column: u64) {
        self.0.entry(root).or_insert((slot, 0)).1 |= 1u128 << column;
    }

    pub(crate) fn slot_of(&self, root: &[u8; 32]) -> Option<u64> {
        self.0.get(root).map(|&(slot, _)| slot)
    }

    #[cfg(test)]
    pub(crate) fn contains(&self, root: &[u8; 32]) -> bool {
        self.0.contains_key(root)
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// True iff every custody column for `root` is on disk.
    pub(crate) fn has_full_custody(&self, root: &[u8; 32], custody: u128) -> bool {
        let present = self.0.get(root).map_or(0, |&(_, mask)| mask);
        present & custody == custody
    }

    /// Promote every custody column of `root` to the flat store.
    pub(crate) fn promote(&mut self, root: [u8; 32], write_queue: &mut VecDeque<PendingWrite>) {
        if let Some((slot, bitmask)) = self.0.remove(&root) {
            for column in columns_of(bitmask) {
                write_queue.push_back(PendingWrite::Promote {
                    slot,
                    key: PayloadKey::Column { block_root: root, column },
                });
            }
        }
    }

    /// Drop entries at or below `finalized_slot` (orphaned forks), queuing a
    /// prune write per column.
    pub(crate) fn prune_below(
        &mut self,
        finalized_slot: u64,
        write_queue: &mut VecDeque<PendingWrite>,
    ) {
        self.0.retain(|root, &mut (slot, bitmask)| {
            if slot <= finalized_slot {
                for column in columns_of(bitmask) {
                    write_queue.push_back(PendingWrite::Prune {
                        slot,
                        key: PayloadKey::Column { block_root: *root, column },
                    });
                }
                false
            } else {
                true
            }
        });
    }
}

/// Set bit positions of a column bitmask, ascending.
pub(crate) fn columns_of(bitmask: u128) -> impl Iterator<Item = u64> {
    (0..128u64).filter(move |c| bitmask & (1u128 << c) != 0)
}
