use std::{collections::VecDeque, io::Error, path::Path};

use fxhash::FxHashMap;

use super::{PayloadKey, read_unfinalized_dir};
use crate::store::{PendingWrite, io};

/// Unfinalized envelopes: block_root → slot. One per block; canonicity follows
/// the owning block.
#[derive(Default)]
pub(crate) struct UnfinalizedEnvelopes(FxHashMap<[u8; 32], u64>);

impl UnfinalizedEnvelopes {
    pub(crate) const FINALIZED_DIR: &'static str = "envelopes";
    /// Keyed by owning block (one per block — canonicity follows the block).
    /// Files: `<slot>_<block_root>.ssz`.
    pub(crate) const UNFINALIZED_DIR: &'static str = "unfinalized_envelopes";

    pub(crate) fn load(store_dir: &str) -> Result<Self, Error> {
        let mut map = FxHashMap::default();
        let dir = Path::new(store_dir).join(Self::UNFINALIZED_DIR);
        read_unfinalized_dir(&dir, |name| {
            if let Some((block_root, slot)) = io::parse_unfinalized_envelope_name(name) {
                map.insert(block_root, slot);
            }
        })?;
        Ok(Self(map))
    }

    pub(crate) fn insert(&mut self, root: [u8; 32], slot: u64) -> bool {
        self.0.insert(root, slot).is_none()
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(crate) fn slot_of(&self, root: &[u8; 32]) -> Option<u64> {
        self.0.get(root).copied()
    }

    pub(crate) fn promote(&mut self, root: [u8; 32], write_queue: &mut VecDeque<PendingWrite>) {
        if let Some(slot) = self.0.remove(&root) {
            write_queue.push_back(PendingWrite::Promote {
                slot,
                key: PayloadKey::Envelope { block_root: root },
            });
        }
    }

    /// Drop entries at or below `finalized_slot` (orphaned forks), queuing a
    /// prune write for each.
    pub(crate) fn prune_below(
        &mut self,
        finalized_slot: u64,
        write_queue: &mut VecDeque<PendingWrite>,
    ) {
        self.0.retain(|root, &mut slot| {
            if slot <= finalized_slot {
                write_queue.push_back(PendingWrite::Prune {
                    slot,
                    key: PayloadKey::Envelope { block_root: *root },
                });
                false
            } else {
                true
            }
        });
    }
}
