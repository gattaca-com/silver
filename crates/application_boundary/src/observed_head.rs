use silver_beacon_api::HeadEvent;
use silver_beacon_state_data::{B256, Epoch, SLOTS_PER_EPOCH};
use silver_common::HeadRoots;

/// The last complete observation, including the initial unpublished baseline.
#[derive(Clone, Copy)]
struct Reported {
    root: B256,
    optimistic: bool,
    epoch: Epoch,
}

/// Tracks complete head observations even when no subscribers are connected.
#[derive(Default)]
pub(crate) struct ObservedHead {
    reported: Option<Reported>,
}

impl ObservedHead {
    /// Incomplete snapshots leave the baseline unchanged. The first complete
    /// observation establishes it without producing an event.
    pub(crate) fn observe(
        &mut self,
        slot: u64,
        root: B256,
        optimistic: bool,
        roots: HeadRoots,
    ) -> Option<HeadEvent> {
        if !roots.is_complete() {
            return None;
        }
        let epoch = slot / SLOTS_PER_EPOCH;
        let previous = self.reported.replace(Reported { root, optimistic, epoch })?;
        if previous.root == root && previous.optimistic == optimistic {
            return None;
        }
        Some(HeadEvent {
            slot,
            block_root: root,
            roots,
            epoch_transition: epoch > previous.epoch,
            execution_optimistic: optimistic,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEAD: B256 = [0x11; 32];
    const OTHER: B256 = [0x22; 32];

    fn roots(tag: u8) -> HeadRoots {
        HeadRoots {
            state_root: [tag; 32],
            previous_duty_dependent_root: [tag.wrapping_add(1); 32],
            current_duty_dependent_root: [tag.wrapping_add(2); 32],
        }
    }

    fn reported(event: Option<HeadEvent>) -> Option<(u64, B256, HeadRoots, bool, bool)> {
        event.map(|e| (e.slot, e.block_root, e.roots, e.epoch_transition, e.execution_optimistic))
    }

    fn observed_at(slot: u64, root: B256, optimistic: bool) -> ObservedHead {
        let mut head = ObservedHead::default();
        assert!(head.observe(slot, root, optimistic, roots(0x30)).is_none(), "baseline only");
        assert!(head.observe(slot, root, optimistic, roots(0x30)).is_none(), "and its repeat");
        head
    }

    /// An incomplete startup snapshot must not make the first real head appear
    /// to advance from epoch zero.
    #[test]
    fn an_incomplete_status_neither_reports_nor_baselines() {
        let mut head = ObservedHead::default();
        assert!(head.observe(0, [0u8; 32], true, HeadRoots::default()).is_none());
        assert!(head.observe(0, [0u8; 32], true, HeadRoots::default()).is_none(), "repeat");

        assert!(head.observe(40, HEAD, true, roots(0x30)).is_none());
        assert_eq!(
            reported(head.observe(72, OTHER, true, roots(0x40))),
            Some((72, OTHER, roots(0x40), true, true)),
            "epoch 2 against the epoch-1 baseline, not against epoch 0"
        );
    }

    #[test]
    fn a_status_repeating_the_same_head_reports_nothing() {
        let mut head = observed_at(40, HEAD, true);
        assert!(head.observe(40, HEAD, true, roots(0x50)).is_none(), "other fields changed");
        assert!(head.observe(40, HEAD, true, roots(0x50)).is_none());
    }

    #[test]
    fn a_validated_head_reports_once_with_no_epoch_transition() {
        let mut head = observed_at(40, HEAD, true);
        assert_eq!(
            reported(head.observe(40, HEAD, false, roots(0x30))),
            Some((40, HEAD, roots(0x30), false, false))
        );
        assert!(head.observe(40, HEAD, false, roots(0x30)).is_none(), "repeat");
    }

    #[test]
    fn a_head_change_inside_one_epoch_reports_no_transition() {
        let mut head = observed_at(40, HEAD, true);
        assert_eq!(
            reported(head.observe(41, OTHER, true, roots(0x40))),
            Some((41, OTHER, roots(0x40), false, true))
        );
        assert!(head.observe(41, OTHER, true, roots(0x40)).is_none(), "repeat");
    }

    #[test]
    fn a_head_change_into_a_later_epoch_reports_the_transition() {
        let mut head = observed_at(40, HEAD, true);
        assert_eq!(
            reported(head.observe(64, OTHER, true, roots(0x40))),
            Some((64, OTHER, roots(0x40), true, true))
        );
        assert!(head.observe(64, OTHER, true, roots(0x40)).is_none(), "repeat");
    }

    #[test]
    fn a_head_change_into_an_earlier_epoch_reports_no_transition() {
        let mut head = observed_at(64, HEAD, true);
        assert_eq!(
            reported(head.observe(40, OTHER, true, roots(0x40))),
            Some((40, OTHER, roots(0x40), false, true))
        );
        assert!(head.observe(40, OTHER, true, roots(0x40)).is_none(), "repeat");
    }

    #[test]
    fn a_validation_right_after_an_epoch_change_reports_no_transition() {
        let mut head = observed_at(40, HEAD, true);
        assert_eq!(
            reported(head.observe(64, OTHER, true, roots(0x40))),
            Some((64, OTHER, roots(0x40), true, true))
        );
        assert_eq!(
            reported(head.observe(64, OTHER, false, roots(0x40))),
            Some((64, OTHER, roots(0x40), false, false))
        );
    }
}
