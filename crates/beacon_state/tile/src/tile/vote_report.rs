use silver_beacon_state_data::{B256, SLOTS_PER_EPOCH, Slot, SpecConfig};
use silver_common::{VoteStats, ssz_view::MAX_COMMITTEES_PER_SLOT, ticker::SlotTicker};

/// Voted roots tracked per slot; votes for further roots are not reported.
const ROOTS_MAX: usize = 8;

struct RootVotes {
    block_root: B256,
    singles_at_due: Option<u32>,
    singles_at_end: Option<u32>,
    largest_aggregate: [u32; MAX_COMMITTEES_PER_SLOT],
}

/// Vote telemetry of the current slot, reported once at its end: per voted
/// root, the singles held at the aggregate due time and at the end, and the
/// largest valid aggregate received per committee.
pub(super) struct VoteReport {
    slot: Option<Slot>,
    due_taken: bool,
    roots: Vec<RootVotes>,
}

impl VoteReport {
    pub(super) fn new() -> Self {
        Self { slot: None, due_taken: false, roots: Vec::with_capacity(ROOTS_MAX) }
    }

    fn root(&mut self, block_root: &B256) -> Option<&mut RootVotes> {
        let i = match self.roots.iter().position(|r| r.block_root == *block_root) {
            Some(i) => i,
            None if self.roots.len() < ROOTS_MAX => {
                self.roots.push(RootVotes {
                    block_root: *block_root,
                    singles_at_due: None,
                    singles_at_end: None,
                    largest_aggregate: [0; MAX_COMMITTEES_PER_SLOT],
                });
                self.roots.len() - 1
            }
            None => return None,
        };
        Some(&mut self.roots[i])
    }

    pub(super) fn aggregate_received(
        &mut self,
        block_root: &B256,
        slot: Slot,
        committee: usize,
        count: u32,
    ) {
        if self.slot != Some(slot) {
            return;
        }
        if let Some(r) = self.root(block_root) {
            r.largest_aggregate[committee] = r.largest_aggregate[committee].max(count);
        }
    }

    /// The tracked slot, once, after its aggregate due time.
    pub(super) fn take_due_slot(&mut self, ticker: &SlotTicker, spec: &SpecConfig) -> Option<Slot> {
        let slot = self.slot.filter(|_| !self.due_taken)?;
        self.due_taken =
            ticker.is_past_aggregate_due(slot, spec.is_gloas_at(slot / SLOTS_PER_EPOCH));
        self.due_taken.then_some(slot)
    }

    pub(super) fn singles_at_due(&mut self, block_root: &B256, count: u32) {
        if let Some(r) = self.root(block_root) {
            r.singles_at_due = Some(count);
        }
    }

    pub(super) fn singles_at_end(&mut self, block_root: &B256, count: u32) {
        if let Some(r) = self.root(block_root) {
            r.singles_at_end = Some(count);
        }
    }

    /// Emits the ended slot's singles and the largest aggregates of
    /// `subscribed` committees (bit per index), then tracks `next`. A slot not
    /// ended by its successor's start, as after a stall, is not reported.
    pub(super) fn end_slot(
        &mut self,
        next: Slot,
        subscribed: u64,
        mut emit: impl FnMut(VoteStats),
    ) {
        if let Some(slot) = self.slot.filter(|&s| s + 1 == next) {
            for r in &self.roots {
                let block_root = r.block_root;
                if let Some(count) = r.singles_at_due {
                    emit(VoteStats::SinglesAtDue { block_root, slot, count });
                }
                if let Some(count) = r.singles_at_end {
                    emit(VoteStats::SinglesAtEnd { block_root, slot, count });
                }
                for (committee, &count) in r.largest_aggregate.iter().enumerate() {
                    if count > 0 && subscribed & 1 << committee != 0 {
                        let committee = committee as u8;
                        emit(VoteStats::LargestAggregate { block_root, slot, committee, count });
                    }
                }
            }
        }
        self.slot = Some(next);
        self.due_taken = false;
        self.roots.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ended(report: &mut VoteReport, next: Slot) -> Vec<String> {
        let mut out = Vec::new();
        report.end_slot(next, u64::MAX, |stats| out.push(format!("{stats:?}")));
        out
    }

    #[test]
    fn reports_singles_and_largest_aggregate_of_subscribed_committees_at_slot_end() {
        let mut report = VoteReport::new();
        assert!(ended(&mut report, 5).is_empty());

        report.aggregate_received(&[1; 32], 5, 3, 10);
        report.aggregate_received(&[1; 32], 5, 3, 40);
        report.aggregate_received(&[1; 32], 5, 3, 20);
        report.aggregate_received(&[1; 32], 4, 7, 99);
        report.aggregate_received(&[1; 32], 5, 9, 50);
        report.singles_at_due(&[1; 32], 30);
        report.singles_at_end(&[1; 32], 35);

        let mut emitted = Vec::new();
        report.end_slot(6, 1 << 3, |stats| emitted.push(stats));
        assert!(matches!(emitted[..], [
            VoteStats::SinglesAtDue { slot: 5, count: 30, .. },
            VoteStats::SinglesAtEnd { slot: 5, count: 35, .. },
            VoteStats::LargestAggregate { slot: 5, committee: 3, count: 40, .. },
        ]));
        assert!(ended(&mut report, 6).is_empty(), "a slot not ended by its successor");
    }
}
