use flux::spine::SpineProducers;
use rustc_hash::FxHashMap;
use silver_beacon_state_data::{B256, Slot};
use silver_common::{BlockSource, SyncNeed, TRead, hex32};

use super::{Producers, root_map};

pub(super) struct ParkedEnvelope {
    pub(super) read: TRead,
    pub(super) from_disk: bool,
}

/// Announced only once the EL has not rejected it: consensus checks cannot tie
/// the body to its block hash, so a forged body would otherwise be persisted
/// and served.
pub(super) struct UnverifiedEnvelope {
    pub(super) read: TRead,
    pub(super) source: BlockSource,
    pub(super) slot: Slot,
    pub(super) signature: [u8; 96],
}

pub(super) struct PendingEnvelopes {
    parked: FxHashMap<B256, ParkedEnvelope>,
    awaiting_verdict: FxHashMap<B256, UnverifiedEnvelope>,
    cap: usize,
}

impl PendingEnvelopes {
    pub(super) fn new(cap: usize) -> Self {
        Self { parked: root_map(), awaiting_verdict: root_map(), cap }
    }

    pub(super) fn await_verdict(&mut self, block_root: B256, envelope: UnverifiedEnvelope) {
        self.awaiting_verdict.insert(block_root, envelope);
    }

    pub(super) fn take_verdict(&mut self, block_root: &B256) -> Option<UnverifiedEnvelope> {
        self.awaiting_verdict.remove(block_root)
    }

    pub(super) fn awaits_verdict(&self, block_root: &B256) -> bool {
        self.awaiting_verdict.contains_key(block_root)
    }

    pub(super) fn drop_verdicts_unless(&mut self, keep: impl Fn(&B256) -> bool) {
        self.awaiting_verdict.retain(|root, _| keep(root));
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
        self.parked.contains_key(block_root) || self.awaits_verdict(block_root)
    }

    /// A held envelope, parked or awaiting its EL verdict, needs no second
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
