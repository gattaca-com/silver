use flux::spine::SpineProducers;
use rustc_hash::FxHashMap;
use silver_beacon_state_data::{B256, Slot};
use silver_common::{BlockSource, SyncNeed, TRead, hex32};

use super::{Producers, root_map};

/// Slots a signed envelope waits for its block, its own included. A block
/// later than that has its envelope fetched by root, like any other.
pub(super) const BLOCK_WAIT_SLOTS: Slot = 2;

pub(super) struct ParkedEnvelope {
    pub(super) read: TRead,
    pub(super) kind: ParkedKind,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ParkedKind {
    /// Its block is unknown, and only its signature is checked: the signer
    /// can still put a body the bid does not commit to under it.
    Signed {
        slot: Slot,
        builder_index: u64,
    },
    /// Verified against its block, awaiting the block's columns.
    Verified,
    FromDisk,
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

    /// A signer publishes one envelope per slot, so a second root under the
    /// same signer and slot is the signer spamming, not a payload to keep.
    pub(super) fn admits_signed(&self, block_root: &B256, slot: Slot, builder_index: u64) -> bool {
        let signed = ParkedKind::Signed { slot, builder_index };
        !self.parked.contains_key(block_root) &&
            !self.parked.values().any(|parked| parked.kind == signed)
    }

    pub(super) fn park(&mut self, block_root: B256, parked: ParkedEnvelope) {
        if let ParkedKind::Signed { slot, builder_index } = parked.kind &&
            !self.admits_signed(&block_root, slot, builder_index)
        {
            return;
        }
        let has_room = self.parked.len() < self.cap || self.parked.contains_key(&block_root);
        if !has_room {
            silver_log::warn!(
                block = hex32(&block_root),
                cap = self.cap,
                "pending-envelope buffer full; envelope dropped"
            );
            return;
        }
        self.parked.insert(block_root, parked);
    }

    pub(super) fn drop_signed_before(&mut self, oldest_slot: Slot) {
        self.parked.retain(|_, parked| match parked.kind {
            ParkedKind::Signed { slot, .. } => slot >= oldest_slot,
            ParkedKind::Verified | ParkedKind::FromDisk => true,
        });
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
