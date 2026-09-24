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
    subscribed: u64,
    rejoin_slots: u64,
    evaluated_at: Option<u64>,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct SubnetChanges {
    join: u64,
    leave: u64,
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
        self.rejoin_slots = wait.as_millis().div_ceil(slot_duration.as_millis()) as u64;
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
        let first = wall_slot.saturating_sub(LINGER_SLOTS);
        let joining = self.duties.subnets_in(first..=wall_slot + LEAD_SLOTS);
        let rejoin_horizon = wall_slot + LEAD_SLOTS + self.rejoin_slots.saturating_sub(1);
        let due_within_rejoin_wait = self.duties.subnets_in(first..=rejoin_horizon);
        let wanted = (joining | self.subscribed & due_within_rejoin_wait) & !self.long_lived;
        let join = wanted & !self.subscribed;
        let leave = self.subscribed & !wanted;
        self.subscribed = wanted;
        (join | leave != 0).then_some(SubnetChanges { join, leave })
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

    fn changes(join: &[u64], leave: &[u64]) -> Option<SubnetChanges> {
        let mask = |subnets: &[u64]| subnets.iter().fold(0, |mask, subnet| mask | 1 << subnet);
        Some(SubnetChanges { join: mask(join), leave: mask(leave) })
    }

    #[test]
    fn duty_subnet_is_held_from_lead_to_linger_except_long_lived() {
        let mut duties = AttnetDuties::default();
        duties.set_long_lived(&[GossipTopic::BeaconAttestation(1)]);
        duties.add(SlotSubnets { slot: 110, subnets: 1 << 1 | 1 << 5 }, 100);

        assert_eq!(duties.advance(100), None);
        assert_eq!(duties.advance(106), changes(&[5], &[]));
        assert_eq!(duties.advance(106), None);
        assert_eq!(duties.advance(111), None);
        assert_eq!(duties.advance(112), changes(&[], &[5]));
    }

    #[test]
    fn subnet_is_kept_when_leaving_would_rejoin_inside_the_backoff() {
        let mut duties = AttnetDuties::default();
        duties.set_rejoin_wait(Duration::from_millis(10_700), Duration::from_secs(6));
        duties.add(SlotSubnets { slot: 110, subnets: 1 << 5 }, 100);
        duties.add(SlotSubnets { slot: 117, subnets: 1 << 5 }, 100);
        duties.add(SlotSubnets { slot: 118, subnets: 1 << 7 }, 100);

        assert_eq!(duties.advance(106), changes(&[5], &[]));
        assert_eq!(duties.advance(112), None);
        assert_eq!(duties.advance(114), changes(&[7], &[]));
        assert_eq!(duties.advance(119), changes(&[], &[5]));
        assert_eq!(duties.advance(120), changes(&[], &[7]));
    }

    #[test]
    fn past_and_distant_duties_are_ignored() {
        let mut duties = AttnetDuties::default();
        duties.add(SlotSubnets { slot: 99, subnets: 1 }, 100);
        duties.add(SlotSubnets { slot: 100 + LOOKAHEAD_SLOTS + 1, subnets: 1 }, 100);
        assert_eq!(duties.advance(100), None);
        assert_eq!(duties.duties.held().count(), 0);
    }
}
