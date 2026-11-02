use std::{ops::Range, time::Duration};

use silver_common::{
    ATTESTATION_SUBNETS, EPOCHS_PER_SYNC_COMMITTEE_PERIOD, GossipTopic, SLOTS_PER_EPOCH,
    SYNC_COMMITTEE_SUBNETS, SlotSubnets, SubnetsBySlot,
};

const LEAD_SLOTS: u64 = 4;
/// Members sign from the slot before their period, so the mesh must form ahead
/// of it.
const SYNC_LEAD_EPOCHS: u64 = 4;

#[derive(Default)]
pub(super) struct SubnetDuties {
    duties: SubnetsBySlot,
    sync_epochs: [Range<u64>; SYNC_COMMITTEE_SUBNETS],
    long_lived: Subnets,
    joined: Subnets,
    attesting: u64,
    rejoin_guard_slots: u64,
    evaluated_at: Option<u64>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Subnets {
    pub(super) attnets: u64,
    pub(super) syncnets: u8,
}

impl Subnets {
    pub(super) fn topics(self) -> impl Iterator<Item = GossipTopic> {
        attestation_topics(self.attnets).chain(sync_topics(self.syncnets))
    }

    fn without(self, other: Self) -> Self {
        Self { attnets: self.attnets & !other.attnets, syncnets: self.syncnets & !other.syncnets }
    }

    fn is_empty(self) -> bool {
        self == Self::default()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct SubnetChanges {
    join: Subnets,
    leave: Subnets,
    pub(super) attesting: u64,
}

impl SubnetChanges {
    pub(super) fn joined(&self) -> impl Iterator<Item = GossipTopic> {
        self.join.topics()
    }

    pub(super) fn left(&self) -> impl Iterator<Item = GossipTopic> {
        self.leave.topics()
    }
}

impl SubnetDuties {
    pub(super) fn new(long_lived: Subnets) -> Self {
        Self { long_lived, ..Self::default() }
    }

    pub(super) fn long_lived(&self) -> Subnets {
        self.long_lived
    }

    pub(super) fn set_rejoin_wait(&mut self, wait: Duration, slot_duration: Duration) {
        let wait_slots = wait.as_millis().div_ceil(slot_duration.as_millis()) as u64;
        self.rejoin_guard_slots = wait_slots.saturating_sub(1);
    }

    pub(super) fn add(&mut self, added: SlotSubnets, wall_slot: u64) {
        if !SubnetsBySlot::window(wall_slot).contains(&added.slot) {
            return;
        }
        self.duties.insert(added);
        self.evaluated_at = None;
    }

    /// A range still running absorbs the added one; consecutive periods
    /// overlap by the lead, so membership stays continuous.
    pub(super) fn add_sync(&mut self, until_epochs: [u64; SYNC_COMMITTEE_SUBNETS], wall_slot: u64) {
        let wall_epoch = wall_slot / SLOTS_PER_EPOCH;
        for (held, until) in self.sync_epochs.iter_mut().zip(until_epochs) {
            if until <= wall_epoch {
                continue;
            }
            let added = sync_join_epoch(until)..until;
            *held = if held.end > wall_epoch {
                held.start.min(added.start)..held.end.max(added.end)
            } else {
                added
            };
        }
        self.evaluated_at = None;
    }

    pub(super) fn advance(&mut self, wall_slot: u64) -> Option<SubnetChanges> {
        if self.evaluated_at == Some(wall_slot) {
            return None;
        }
        self.evaluated_at = Some(wall_slot);

        let attesting = self.subnets_due(wall_slot, 0, |duty| duty.attesting);
        let joined = self.subnets_to_join(wall_slot);
        let changes = SubnetChanges {
            join: joined.without(self.joined),
            leave: self.joined.without(joined),
            attesting,
        };
        let changed =
            !changes.join.is_empty() || !changes.leave.is_empty() || attesting != self.attesting;

        self.joined = joined;
        self.attesting = attesting;
        changed.then_some(changes)
    }

    fn subnets_to_join(&self, wall_slot: u64) -> Subnets {
        let due = self.subnets_due(wall_slot, 0, |duty| duty.aggregating);
        // Leaving a subnet due again this soon would rejoin inside the peers' prune
        // backoff.
        let due_before_rejoin =
            self.subnets_due(wall_slot, self.rejoin_guard_slots, |duty| duty.aggregating);
        let attnets = (due | self.joined.attnets & due_before_rejoin) & !self.long_lived.attnets;
        let wall_epoch = wall_slot / SLOTS_PER_EPOCH;
        let syncnets = (0..SYNC_COMMITTEE_SUBNETS)
            .filter(|&subnet| self.sync_epochs[subnet].contains(&wall_epoch))
            .fold(0, |mask, subnet| mask | 1 << subnet) &
            !self.long_lived.syncnets;
        Subnets { attnets, syncnets }
    }

    fn subnets_due(
        &self,
        wall_slot: u64,
        extra_lead_slots: u64,
        subnets: impl Fn(&SlotSubnets) -> u64,
    ) -> u64 {
        let first = wall_slot.saturating_sub(SubnetsBySlot::LINGER_SLOTS);
        let last = wall_slot + LEAD_SLOTS + extra_lead_slots;
        self.duties.subnets_in(first..=last, subnets)
    }
}

fn sync_join_epoch(until_epoch: u64) -> u64 {
    let last = until_epoch - 1;
    (last - last % EPOCHS_PER_SYNC_COMMITTEE_PERIOD).saturating_sub(SYNC_LEAD_EPOCHS)
}

fn attestation_topics(mask: u64) -> impl Iterator<Item = GossipTopic> {
    (0..ATTESTATION_SUBNETS as u64)
        .filter(move |subnet| mask >> subnet & 1 == 1)
        .map(GossipTopic::BeaconAttestation)
}

fn sync_topics(mask: u8) -> impl Iterator<Item = GossipTopic> {
    (0..SYNC_COMMITTEE_SUBNETS as u64)
        .filter(move |subnet| mask >> subnet & 1 == 1)
        .map(GossipTopic::SyncCommittee)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mask(subnets: &[u64]) -> u64 {
        subnets.iter().fold(0, |mask, subnet| mask | 1 << subnet)
    }

    fn aggregating(slot: u64, subnets: &[u64]) -> SlotSubnets {
        SlotSubnets { slot, attesting: mask(subnets), aggregating: mask(subnets) }
    }

    fn changes(join: &[u64], leave: &[u64], attesting: &[u64]) -> Option<SubnetChanges> {
        let attnets = |subnets| Subnets { attnets: mask(subnets), syncnets: 0 };
        Some(SubnetChanges {
            join: attnets(join),
            leave: attnets(leave),
            attesting: mask(attesting),
        })
    }

    fn sync_changes(join: u8, leave: u8) -> Option<SubnetChanges> {
        let syncnets = |syncnets| Subnets { attnets: 0, syncnets };
        Some(SubnetChanges { join: syncnets(join), leave: syncnets(leave), attesting: 0 })
    }

    #[test]
    fn duty_subnet_is_held_from_lead_to_linger_except_long_lived() {
        let mut duties = SubnetDuties::new(Subnets { attnets: 1 << 1, syncnets: 0 });
        duties.add(aggregating(110, &[1, 5]), 100);

        assert_eq!(duties.advance(100), None);
        assert_eq!(duties.advance(106), changes(&[5], &[], &[1, 5]));
        assert_eq!(duties.advance(106), None);
        assert_eq!(duties.advance(111), None);
        assert_eq!(duties.advance(112), changes(&[], &[5], &[]));
    }

    #[test]
    fn attester_duty_asks_for_peers_without_joining() {
        let mut duties = SubnetDuties::default();
        duties.add(SlotSubnets { slot: 110, attesting: 1 << 3, aggregating: 0 }, 100);

        assert_eq!(duties.advance(106), changes(&[], &[], &[3]));
        assert_eq!(duties.advance(111), None);
        assert_eq!(duties.advance(112), changes(&[], &[], &[]));
    }

    #[test]
    fn subnet_is_kept_when_leaving_would_rejoin_inside_the_backoff() {
        let mut duties = SubnetDuties::default();
        duties.set_rejoin_wait(Duration::from_millis(10_700), Duration::from_secs(6));
        duties.add(aggregating(110, &[5]), 100);
        duties.add(aggregating(117, &[5]), 100);
        duties.add(aggregating(118, &[7]), 100);

        assert_eq!(duties.advance(106), changes(&[5], &[], &[5]));
        assert_eq!(duties.advance(112), changes(&[], &[], &[]));
        assert_eq!(duties.advance(114), changes(&[7], &[], &[5, 7]));
        assert_eq!(duties.advance(119), changes(&[], &[5], &[7]));
        assert_eq!(duties.advance(120), changes(&[], &[7], &[]));
    }

    #[test]
    fn past_and_distant_duties_are_ignored() {
        let mut duties = SubnetDuties::default();
        duties.add(aggregating(99, &[0]), 100);
        duties.add(aggregating(100 + SubnetsBySlot::LOOKAHEAD_SLOTS + 1, &[0]), 100);
        assert_eq!(duties.advance(100), None);
        assert_eq!(duties.duties.held().count(), 0);
    }

    #[test]
    fn sync_subnet_is_joined_until_its_epoch() {
        let epoch = |epoch: u64| epoch * SLOTS_PER_EPOCH;
        let mut duties = SubnetDuties::default();
        duties.add_sync([12, 0, 10, 0], epoch(9));

        assert_eq!(duties.advance(epoch(9)), sync_changes(0b0101, 0));
        assert_eq!(duties.advance(epoch(9) + 1), None);
        assert_eq!(duties.advance(epoch(10)), sync_changes(0, 0b0100));
        duties.add_sync([0, 0, 0, 20], epoch(10));
        assert_eq!(duties.advance(epoch(11)), sync_changes(0b1000, 0));
        assert_eq!(duties.advance(epoch(12)), sync_changes(0, 0b0001));
    }

    #[test]
    fn coming_period_is_joined_only_in_its_lead_epochs() {
        let epoch = |epoch: u64| epoch * SLOTS_PER_EPOCH;
        let next = EPOCHS_PER_SYNC_COMMITTEE_PERIOD;
        let mut duties = SubnetDuties::default();
        duties.add_sync([next + EPOCHS_PER_SYNC_COMMITTEE_PERIOD, 0, 0, 0], 0);

        assert_eq!(duties.advance(epoch(next - SYNC_LEAD_EPOCHS - 1)), None);
        assert_eq!(duties.advance(epoch(next - SYNC_LEAD_EPOCHS)), sync_changes(0b0001, 0));
    }

    #[test]
    fn next_period_extends_the_current_one() {
        let epoch = |epoch: u64| epoch * SLOTS_PER_EPOCH;
        let period = EPOCHS_PER_SYNC_COMMITTEE_PERIOD;
        let mut duties = SubnetDuties::default();
        duties.add_sync([period, 0, 0, 0], 0);
        duties.add_sync([2 * period, 0, 0, 0], 0);

        assert_eq!(duties.advance(epoch(1)), sync_changes(0b0001, 0));
        assert_eq!(duties.advance(epoch(period)), None);
        assert_eq!(duties.advance(epoch(2 * period)), sync_changes(0, 0b0001));
    }

    #[test]
    fn expired_period_does_not_pull_a_later_one_forward() {
        let epoch = |epoch: u64| epoch * SLOTS_PER_EPOCH;
        let period = EPOCHS_PER_SYNC_COMMITTEE_PERIOD;
        let mut duties = SubnetDuties::default();
        duties.add_sync([period, 0, 0, 0], 0);
        duties.add_sync([4 * period, 0, 0, 0], epoch(2 * period));

        assert_eq!(duties.advance(epoch(2 * period)), None);
        assert_eq!(duties.advance(epoch(3 * period)), sync_changes(0b0001, 0));
    }

    #[test]
    fn subscription_already_over_is_ignored() {
        let epoch = |epoch: u64| epoch * SLOTS_PER_EPOCH;
        let mut duties = SubnetDuties::default();
        duties.add_sync([10, 0, 0, 0], epoch(10));
        assert_eq!(duties.advance(epoch(10)), None);
    }

    #[test]
    fn long_lived_sync_subnets_are_never_joined_or_left() {
        let mut duties = SubnetDuties::new(Subnets { attnets: 0, syncnets: 0b1111 });
        duties.add_sync([12, 12, 12, 12], 9 * SLOTS_PER_EPOCH);
        assert_eq!(duties.advance(9 * SLOTS_PER_EPOCH), None);
        assert_eq!(duties.advance(12 * SLOTS_PER_EPOCH), None);
    }
}
