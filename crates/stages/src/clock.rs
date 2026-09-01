use flux::timing::Nanos;

/// Replay and backfill ingest historical blocks at the current wall clock, so
/// beyond this much slack the arrival says nothing about the block's slot. The
/// second slot keeps genuinely late arrivals.
const LIVE_ARRIVAL_SLOTS: u64 = 2;

/// Slot arithmetic against a chain's genesis.
#[derive(Clone, Copy)]
pub struct SlotClock {
    genesis: Nanos,
    slot_dur: Nanos,
}

impl SlotClock {
    pub fn new(genesis_unix_secs: u64, slot_ms: u64) -> Self {
        Self {
            genesis: Nanos::from_secs(genesis_unix_secs),
            slot_dur: Nanos::from_millis(slot_ms.max(1)),
        }
    }

    pub fn slot_duration(&self) -> Nanos {
        self.slot_dur
    }

    pub fn slot_start(&self, slot: u64) -> Nanos {
        self.genesis + self.slot_dur * slot
    }

    /// `None` once the wall clock no longer belongs to the slot
    /// (replay/backfill).
    pub fn offset_in_slot(&self, t: Nanos, slot: u64) -> Option<Nanos> {
        let start = self.slot_start(slot);
        let live = start..start + self.slot_dur * LIVE_ARRIVAL_SLOTS;
        live.contains(&t).then(|| t - start)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GENESIS_SECS: u64 = 1_000;
    const SLOT_MS: u64 = 12_000;

    fn at(slot: u64, ms_into_slot: u64) -> Nanos {
        Nanos::from_secs(GENESIS_SECS) + Nanos::from_millis(slot * SLOT_MS + ms_into_slot)
    }

    /// Replay/backfill arrivals keep every stage observable, but the wall
    /// clock says nothing about the slot.
    #[test]
    fn offset_is_live_arrivals_only() {
        let clock = SlotClock::new(GENESIS_SECS, SLOT_MS);
        assert_eq!(clock.offset_in_slot(at(2, 300), 2), Some(Nanos::from_millis(300)));
        assert_eq!(clock.offset_in_slot(at(2, 13_000), 2), Some(Nanos::from_millis(13_000)));
        assert_eq!(clock.offset_in_slot(at(900, 4_000), 7), None, "replay clock");
        assert_eq!(clock.slot_start(2), at(2, 0));
    }
}
