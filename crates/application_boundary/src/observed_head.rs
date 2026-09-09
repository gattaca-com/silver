use silver_beacon_api::HeadEvent;
use silver_beacon_state_data::{B256, Epoch, SLOTS_PER_EPOCH};
use silver_common::{HeadRoots, PayloadResolution};

/// The last complete observation, including the initial unpublished baseline.
#[derive(Clone, Copy)]
struct Reported {
    root: B256,
    optimistic: bool,
    payload: PayloadResolution,
    epoch: Epoch,
}

/// Every change publishes to `head_v2`; `legacy` also selects `head` when
/// the root or optimism changed.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct HeadChange {
    pub(crate) event: HeadEvent,
    pub(crate) legacy: bool,
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
        payload: PayloadResolution,
        roots: HeadRoots,
    ) -> Option<HeadChange> {
        if !roots.is_complete() {
            return None;
        }
        let epoch = slot / SLOTS_PER_EPOCH;
        let previous = self.reported.replace(Reported { root, optimistic, payload, epoch })?;
        let legacy = previous.root != root || previous.optimistic != optimistic;
        if !legacy && previous.payload == payload {
            return None;
        }
        let event = HeadEvent {
            slot,
            block_root: root,
            roots,
            payload,
            epoch_transition: epoch > previous.epoch,
            execution_optimistic: optimistic,
        };
        Some(HeadChange { event, legacy })
    }
}

#[cfg(test)]
mod tests {
    use PayloadResolution::{Empty, Full};

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

    fn event(
        slot: u64,
        root: B256,
        tag: u8,
        payload: PayloadResolution,
        epoch_transition: bool,
        optimistic: bool,
    ) -> HeadEvent {
        HeadEvent {
            slot,
            block_root: root,
            roots: roots(tag),
            payload,
            epoch_transition,
            execution_optimistic: optimistic,
        }
    }

    fn both_topics(event: HeadEvent) -> Option<HeadChange> {
        Some(HeadChange { event, legacy: true })
    }

    fn v2_only(event: HeadEvent) -> Option<HeadChange> {
        Some(HeadChange { event, legacy: false })
    }

    fn observed_at(
        slot: u64,
        root: B256,
        optimistic: bool,
        payload: PayloadResolution,
    ) -> ObservedHead {
        let mut head = ObservedHead::default();
        assert!(
            head.observe(slot, root, optimistic, payload, roots(0x30)).is_none(),
            "baseline only"
        );
        assert!(
            head.observe(slot, root, optimistic, payload, roots(0x30)).is_none(),
            "and its repeat"
        );
        head
    }

    /// An incomplete startup snapshot must not make the first real head appear
    /// to advance from epoch zero.
    #[test]
    fn an_incomplete_status_neither_reports_nor_baselines() {
        let mut head = ObservedHead::default();
        assert!(head.observe(0, [0u8; 32], true, Empty, HeadRoots::default()).is_none());
        assert!(head.observe(0, [0u8; 32], true, Empty, HeadRoots::default()).is_none(), "repeat");

        assert!(head.observe(40, HEAD, true, Full, roots(0x30)).is_none());
        assert_eq!(
            head.observe(72, OTHER, true, Full, roots(0x40)),
            both_topics(event(72, OTHER, 0x40, Full, true, true)),
            "epoch 2 against the epoch-1 baseline, not against epoch 0"
        );
    }

    #[test]
    fn a_status_repeating_the_same_head_reports_nothing() {
        let mut head = observed_at(40, HEAD, true, Full);
        assert!(head.observe(40, HEAD, true, Full, roots(0x50)).is_none(), "other fields changed");
        assert!(head.observe(40, HEAD, true, Full, roots(0x50)).is_none());
    }

    #[test]
    fn a_validated_head_reports_once_with_no_epoch_transition() {
        let mut head = observed_at(40, HEAD, true, Full);
        assert_eq!(
            head.observe(40, HEAD, false, Full, roots(0x30)),
            both_topics(event(40, HEAD, 0x30, Full, false, false))
        );
        assert!(head.observe(40, HEAD, false, Full, roots(0x30)).is_none(), "repeat");
    }

    #[test]
    fn a_payload_resolution_change_alone_reaches_only_head_v2() {
        let mut head = observed_at(40, HEAD, true, Empty);
        assert_eq!(
            head.observe(40, HEAD, true, Full, roots(0x30)),
            v2_only(event(40, HEAD, 0x30, Full, false, true))
        );
        assert!(head.observe(40, HEAD, true, Full, roots(0x30)).is_none(), "repeat");

        assert_eq!(
            head.observe(40, HEAD, true, Empty, roots(0x30)),
            v2_only(event(40, HEAD, 0x30, Empty, false, true)),
            "the reverse transition is published too"
        );
        assert!(head.observe(40, HEAD, true, Empty, roots(0x30)).is_none(), "repeat");
    }

    #[test]
    fn a_change_in_every_dimension_is_one_event_for_both_topics() {
        let mut head = observed_at(40, HEAD, true, Empty);
        assert_eq!(
            head.observe(41, OTHER, false, Full, roots(0x40)),
            both_topics(event(41, OTHER, 0x40, Full, false, false))
        );
        assert!(head.observe(41, OTHER, false, Full, roots(0x40)).is_none(), "repeat");
    }

    #[test]
    fn a_head_change_inside_one_epoch_reports_no_transition() {
        let mut head = observed_at(40, HEAD, true, Full);
        assert_eq!(
            head.observe(41, OTHER, true, Full, roots(0x40)),
            both_topics(event(41, OTHER, 0x40, Full, false, true))
        );
        assert!(head.observe(41, OTHER, true, Full, roots(0x40)).is_none(), "repeat");
    }

    #[test]
    fn a_head_change_into_a_later_epoch_reports_the_transition() {
        let mut head = observed_at(40, HEAD, true, Full);
        assert_eq!(
            head.observe(64, OTHER, true, Full, roots(0x40)),
            both_topics(event(64, OTHER, 0x40, Full, true, true))
        );
        assert!(head.observe(64, OTHER, true, Full, roots(0x40)).is_none(), "repeat");
    }

    #[test]
    fn a_head_change_into_an_earlier_epoch_reports_no_transition() {
        let mut head = observed_at(64, HEAD, true, Full);
        assert_eq!(
            head.observe(40, OTHER, true, Full, roots(0x40)),
            both_topics(event(40, OTHER, 0x40, Full, false, true))
        );
        assert!(head.observe(40, OTHER, true, Full, roots(0x40)).is_none(), "repeat");
    }

    /// The transition flag belongs to the observation that crossed the epoch,
    /// not to later updates of the same head.
    #[test]
    fn updates_right_after_an_epoch_change_report_no_transition() {
        let mut head = observed_at(40, HEAD, true, Empty);
        assert_eq!(
            head.observe(64, OTHER, true, Empty, roots(0x40)),
            both_topics(event(64, OTHER, 0x40, Empty, true, true))
        );
        assert_eq!(
            head.observe(64, OTHER, true, Full, roots(0x40)),
            v2_only(event(64, OTHER, 0x40, Full, false, true))
        );
        assert_eq!(
            head.observe(64, OTHER, false, Full, roots(0x40)),
            both_topics(event(64, OTHER, 0x40, Full, false, false))
        );
    }

    #[test]
    fn an_incomplete_snapshot_between_complete_ones_keeps_the_earlier_baseline() {
        let mut head = observed_at(40, HEAD, true, Empty);
        assert!(head.observe(41, OTHER, false, Full, HeadRoots::default()).is_none());
        assert_eq!(
            head.observe(40, HEAD, true, Full, roots(0x30)),
            v2_only(event(40, HEAD, 0x30, Full, false, true)),
            "only the payload differs from the last complete observation"
        );
    }
}
