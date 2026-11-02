use silver_beacon_state_data::{B256, SLOTS_PER_EPOCH, Slot, SpecConfig};
use silver_common::{VoteStats, ssz_view::MAX_COMMITTEES_PER_SLOT, ticker::SlotTicker};

/// Voted roots tracked per slot; aggregates for further roots are not reported.
const ROOTS_MAX: usize = 8;
/// Reports between two loop iterations; past it they are dropped.
const PENDING_CAP: usize = 1024;

/// Vote telemetry of the current slot: each new largest aggregate per
/// subscribed committee, buffered until the loop can publish it, and the slot
/// whose aggregate due time is still to be reported.
pub(super) struct VoteReport {
    slot: Option<Slot>,
    due_taken: bool,
    /// Bit per committee index a gossip single arrived for: singles arrive
    /// only on subscribed subnets, one committee each.
    subscribed: u64,
    largest: Vec<(B256, [u32; MAX_COMMITTEES_PER_SLOT])>,
    pending: Vec<VoteStats>,
}

impl VoteReport {
    pub(super) fn new() -> Self {
        Self {
            slot: None,
            due_taken: false,
            subscribed: 0,
            largest: Vec::with_capacity(ROOTS_MAX),
            pending: Vec::with_capacity(PENDING_CAP),
        }
    }

    pub(super) fn gossip_single(&mut self, slot: Slot, committee: usize) {
        if self.slot == Some(slot) {
            self.subscribed |= 1 << committee;
        }
    }

    pub(super) fn aggregate_received(
        &mut self,
        block_root: &B256,
        slot: Slot,
        committee: usize,
        count: u32,
    ) {
        if self.slot != Some(slot) || self.subscribed & 1 << committee == 0 {
            return;
        }
        let i = match self.largest.iter().position(|(root, _)| root == block_root) {
            Some(i) => i,
            None if self.largest.len() < ROOTS_MAX => {
                self.largest.push((*block_root, [0; MAX_COMMITTEES_PER_SLOT]));
                self.largest.len() - 1
            }
            None => return,
        };
        let largest = &mut self.largest[i].1[committee];
        if count > *largest && self.pending.len() < PENDING_CAP {
            *largest = count;
            let committee = committee as u8;
            self.pending.push(VoteStats::LargestAggregate {
                block_root: *block_root,
                slot,
                committee,
                count,
            });
        }
    }

    pub(super) fn drain(&mut self, mut emit: impl FnMut(VoteStats)) {
        for stats in self.pending.drain(..) {
            emit(stats);
        }
    }

    /// The tracked slot, once, after its aggregate due time.
    pub(super) fn take_due_slot(&mut self, ticker: &SlotTicker, spec: &SpecConfig) -> Option<Slot> {
        let slot = self.slot.filter(|_| !self.due_taken)?;
        self.due_taken =
            ticker.is_past_aggregate_due(slot, spec.is_gloas_at(slot / SLOTS_PER_EPOCH));
        self.due_taken.then_some(slot)
    }

    /// Tracks `next`; returns the slot it ends. A slot not ended by its
    /// successor's start, as after a stall, is not returned.
    pub(super) fn end_slot(&mut self, next: Slot) -> Option<Slot> {
        let ended = self.slot.filter(|&s| s + 1 == next);
        self.slot = Some(next);
        self.due_taken = false;
        self.subscribed = 0;
        self.largest.clear();
        ended
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn drained(report: &mut VoteReport) -> Vec<VoteStats> {
        let mut out = Vec::new();
        report.drain(|stats| out.push(stats));
        out
    }

    #[test]
    fn reports_each_new_largest_aggregate_of_subscribed_committees() {
        let mut report = VoteReport::new();
        assert_eq!(report.end_slot(5), None);
        report.gossip_single(5, 3);
        report.gossip_single(4, 7);
        report.aggregate_received(&[1; 32], 5, 7, 60);

        report.aggregate_received(&[1; 32], 5, 3, 10);
        report.aggregate_received(&[1; 32], 5, 3, 40);
        report.aggregate_received(&[1; 32], 5, 3, 20);
        report.aggregate_received(&[1; 32], 4, 7, 99);
        assert!(matches!(drained(&mut report)[..], [
            VoteStats::LargestAggregate { slot: 5, committee: 3, count: 10, .. },
            VoteStats::LargestAggregate { slot: 5, committee: 3, count: 40, .. },
        ]));

        assert_eq!(report.end_slot(6), Some(5));
        report.aggregate_received(&[1; 32], 6, 3, 5);
        assert!(drained(&mut report).is_empty(), "subscriptions restart per slot");
        report.gossip_single(6, 3);
        report.aggregate_received(&[1; 32], 6, 3, 5);
        assert_eq!(drained(&mut report).len(), 1, "largest restarts per slot");
        assert_eq!(report.end_slot(8), None, "a slot not ended by its successor");
    }
}
