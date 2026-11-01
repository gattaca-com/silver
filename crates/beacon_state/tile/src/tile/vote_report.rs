use silver_beacon_state_data::{B256, SLOTS_PER_EPOCH, Slot, SpecConfig};
use silver_common::{VoteStats, ticker::SlotTicker};

/// Admissions between two loop iterations; past it they are dropped.
const ADMITTED_CAP: usize = 4096;

/// Vote telemetry: received aggregates buffered until the loop can publish
/// them, and the slot whose aggregate due time next tallies the singles.
pub(super) struct VoteReport {
    admitted: Vec<VoteStats>,
    tally_slot: Slot,
}

impl VoteReport {
    pub(super) fn new() -> Self {
        Self { admitted: Vec::with_capacity(ADMITTED_CAP), tally_slot: 0 }
    }

    pub(super) fn aggregate_admitted(&mut self, block_root: &B256, slot: Slot, count: u32) {
        if self.admitted.len() < ADMITTED_CAP {
            self.admitted.push(VoteStats::Aggregate { block_root: *block_root, slot, count });
        }
    }

    pub(super) fn drain(&mut self, mut emit: impl FnMut(VoteStats)) {
        for stats in self.admitted.drain(..) {
            emit(stats);
        }
    }

    /// The current slot once its aggregate due time passed, once per slot. A
    /// check later than its slot, as after boot or a stall, yields nothing.
    pub(super) fn due_tally(&mut self, ticker: &SlotTicker, spec: &SpecConfig) -> Option<Slot> {
        let slot = self.tally_slot;
        if !ticker.is_past_aggregate_due(slot, spec.is_gloas_at(slot / SLOTS_PER_EPOCH)) {
            return None;
        }
        let wall = ticker.current_slot();
        self.tally_slot = wall + 1;
        (slot == wall).then_some(slot)
    }
}
