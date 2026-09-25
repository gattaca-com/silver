use std::time::Duration;

use silver_common::{
    ATTESTATION_SUBNETS, GossipTopic, SLOTS_PER_EPOCH, SlotSubnets, SubnetsBySlot,
};

const LEAD_SLOTS: u64 = 4;
const LINGER_SLOTS: u64 = 1;
const LOOKAHEAD_SLOTS: u64 = 2 * SLOTS_PER_EPOCH;
const _: () = assert!(LINGER_SLOTS + LOOKAHEAD_SLOTS < SubnetsBySlot::SLOTS as u64);

#[derive(Default)]
pub(super) struct AttnetDuties {
    duties: SubnetsBySlot,
    long_lived: u64,
    joined: u64,
    attesting: u64,
    rejoin_guard_slots: u64,
    evaluated_at: Option<u64>,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct SubnetChanges {
    join: u64,
    leave: u64,
    pub(super) attesting: u64,
}

impl SubnetChanges {
    pub(super) fn joined(&self) -> impl Iterator<Item = GossipTopic> {
        attestation_topics(self.join)
    }

    pub(super) fn left(&self) -> impl Iterator<Item = GossipTopic> {
        attestation_topics(self.leave)
    }
}

impl AttnetDuties {
    pub(super) fn set_long_lived(&mut self, topics: &[GossipTopic]) {
        self.long_lived = topics.iter().fold(0, |mask, topic| match topic {
            GossipTopic::BeaconAttestation(subnet) => mask | 1 << subnet,
            _ => mask,
        });
    }

    pub(super) fn set_rejoin_wait(&mut self, wait: Duration, slot_duration: Duration) {
        let wait_slots = wait.as_millis().div_ceil(slot_duration.as_millis()) as u64;
        self.rejoin_guard_slots = wait_slots.saturating_sub(1);
    }

    pub(super) fn add(&mut self, added: SlotSubnets, wall_slot: u64) {
        if added.slot < wall_slot || added.slot > wall_slot + LOOKAHEAD_SLOTS {
            return;
        }
        self.duties.insert(added);
        self.evaluated_at = None;
    }

    pub(super) fn advance(&mut self, wall_slot: u64) -> Option<SubnetChanges> {
        if self.evaluated_at == Some(wall_slot) {
            return None;
        }
        self.evaluated_at = Some(wall_slot);

        let attesting = self.subnets_due(wall_slot, 0, |duty| duty.attesting);
        let joined = self.subnets_to_join(wall_slot);
        let changes =
            SubnetChanges { join: joined & !self.joined, leave: self.joined & !joined, attesting };
        let changed = changes.join | changes.leave != 0 || attesting != self.attesting;

        self.joined = joined;
        self.attesting = attesting;
        changed.then_some(changes)
    }

    fn subnets_to_join(&self, wall_slot: u64) -> u64 {
        let due = self.subnets_due(wall_slot, 0, |duty| duty.aggregating);
        // Leaving a subnet due again this soon would rejoin inside the peers' prune
        // backoff.
        let due_before_rejoin =
            self.subnets_due(wall_slot, self.rejoin_guard_slots, |duty| duty.aggregating);
        (due | self.joined & due_before_rejoin) & !self.long_lived
    }

    fn subnets_due(
        &self,
        wall_slot: u64,
        extra_lead_slots: u64,
        subnets: impl Fn(&SlotSubnets) -> u64,
    ) -> u64 {
        let first = wall_slot.saturating_sub(LINGER_SLOTS);
        let last = wall_slot + LEAD_SLOTS + extra_lead_slots;
        self.duties.subnets_in(first..=last, subnets)
    }
}

fn attestation_topics(mask: u64) -> impl Iterator<Item = GossipTopic> {
    (0..ATTESTATION_SUBNETS as u64)
        .filter(move |subnet| mask >> subnet & 1 == 1)
        .map(GossipTopic::BeaconAttestation)
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
        Some(SubnetChanges { join: mask(join), leave: mask(leave), attesting: mask(attesting) })
    }

    #[test]
    fn duty_subnet_is_held_from_lead_to_linger_except_long_lived() {
        let mut duties = AttnetDuties::default();
        duties.set_long_lived(&[GossipTopic::BeaconAttestation(1)]);
        duties.add(aggregating(110, &[1, 5]), 100);

        assert_eq!(duties.advance(100), None);
        assert_eq!(duties.advance(106), changes(&[5], &[], &[1, 5]));
        assert_eq!(duties.advance(106), None);
        assert_eq!(duties.advance(111), None);
        assert_eq!(duties.advance(112), changes(&[], &[5], &[]));
    }

    #[test]
    fn attester_duty_asks_for_peers_without_joining() {
        let mut duties = AttnetDuties::default();
        duties.add(SlotSubnets { slot: 110, attesting: 1 << 3, aggregating: 0 }, 100);

        assert_eq!(duties.advance(106), changes(&[], &[], &[3]));
        assert_eq!(duties.advance(111), None);
        assert_eq!(duties.advance(112), changes(&[], &[], &[]));
    }

    #[test]
    fn subnet_is_kept_when_leaving_would_rejoin_inside_the_backoff() {
        let mut duties = AttnetDuties::default();
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
        let mut duties = AttnetDuties::default();
        duties.add(aggregating(99, &[0]), 100);
        duties.add(aggregating(100 + LOOKAHEAD_SLOTS + 1, &[0]), 100);
        assert_eq!(duties.advance(100), None);
        assert_eq!(duties.duties.held().count(), 0);
    }
}
