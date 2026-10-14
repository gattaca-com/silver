use rustc_hash::FxHashMap;
use silver_beacon_state_data::{B256, Slot};

const PAYLOAD_DUE_BPS: u64 = 5000;

struct Arrival {
    slot: Slot,
    ms_since_genesis: u64,
}

/// First time an envelope for each recent block passed gossip checks.
#[derive(Default)]
pub(super) struct EnvelopeArrivals(FxHashMap<B256, Arrival>);

impl EnvelopeArrivals {
    pub fn record(&mut self, block_root: B256, slot: Slot, ms_since_genesis: u64) {
        self.0.entry(block_root).or_insert(Arrival { slot, ms_since_genesis });
    }

    /// Spec `payload_present` for a PTC member: seen before
    /// `PAYLOAD_DUE_BPS` into the block's slot.
    pub fn timely(&self, block_root: &B256, slot_ms: u64) -> bool {
        self.0.get(block_root).is_some_and(|arrival| {
            arrival.ms_since_genesis <= arrival.slot * slot_ms + slot_ms * PAYLOAD_DUE_BPS / 10_000
        })
    }

    /// PTC members attest only to the current slot's block.
    pub fn on_slot(&mut self, slot: Slot) {
        self.0.retain(|_, arrival| arrival.slot >= slot.saturating_sub(1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SLOT_MS: u64 = 12_000;
    const ROOT: B256 = [7; 32];

    #[test]
    fn the_first_sighting_decides_and_ages_out() {
        let mut arrivals = EnvelopeArrivals::default();
        arrivals.record(ROOT, 10, 10 * SLOT_MS + SLOT_MS / 2);
        arrivals.record(ROOT, 10, 11 * SLOT_MS);
        assert!(arrivals.timely(&ROOT, SLOT_MS));

        let late = [8; 32];
        arrivals.record(late, 10, 10 * SLOT_MS + SLOT_MS / 2 + 1);
        assert!(!arrivals.timely(&late, SLOT_MS));
        assert!(!arrivals.timely(&[9; 32], SLOT_MS));

        arrivals.on_slot(11);
        assert!(arrivals.timely(&ROOT, SLOT_MS));
        arrivals.on_slot(12);
        assert!(!arrivals.timely(&ROOT, SLOT_MS));
    }
}
