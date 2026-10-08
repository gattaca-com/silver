use flux::spine::SpineProducers;
use rustc_hash::FxHashMap;
use silver_beacon_state_data::{B256, Slot};
use silver_common::{SyncNeed, TRead, hex32};

use super::{Producers, root_map};

pub(super) struct ParkedEnvelope {
    pub(super) read: TRead,
    pub(super) from_disk: bool,
}

pub(super) struct PendingEnvelopes {
    parked: FxHashMap<B256, ParkedEnvelope>,
    cap: usize,
}

impl PendingEnvelopes {
    pub(super) fn new(cap: usize) -> Self {
        Self { parked: root_map(), cap }
    }

    pub(super) fn park(&mut self, block_root: B256, read: TRead, from_disk: bool) {
        let has_room = self.parked.len() < self.cap || self.parked.contains_key(&block_root);
        if !has_room {
            silver_log::warn!(
                block = hex32(&block_root),
                cap = self.cap,
                "pending-envelope buffer full; envelope dropped"
            );
            return;
        }
        self.parked.insert(block_root, ParkedEnvelope { read, from_disk });
    }

    pub(super) fn take(&mut self, block_root: &B256) -> Option<ParkedEnvelope> {
        self.parked.remove(block_root)
    }

    pub(super) fn holds(&self, block_root: &B256) -> bool {
        self.parked.contains_key(block_root)
    }

    /// A parked envelope is already held; fetching it again would only park the
    /// copy.
    pub(super) fn request(&self, block_root: B256, slot: Slot, producers: &mut Producers) {
        if !self.holds(&block_root) {
            producers.produce(SyncNeed::missing_envelope(block_root, slot));
        }
    }

    pub(super) fn drop_evicted(&mut self) {
        self.parked.retain(|root, parked| {
            let held = parked.read.buffer().is_ok();
            if !held {
                silver_log::error!(
                    block = hex32(root),
                    "parked envelope lapped in the tcache before its block arrived"
                );
            }
            held
        });
    }
}
