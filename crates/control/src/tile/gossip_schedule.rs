use silver_chain_spec::{ForkName, SpecConfig};
use silver_common::{FAR_FUTURE_EPOCH, GossipDomain, SLOTS_PER_EPOCH, ticker::SlotTicker};

const ADVANCE_EPOCHS: u64 = 1;
const RETAIN_EPOCHS: u64 = 2;

struct Transition {
    epoch: u64,
    domain: GossipDomain,
    enr_fork_id: [u8; 16],
}

pub(super) struct GossipSchedule {
    pub(super) ticker: SlotTicker,
    transitions: Vec<Transition>,
    last_epoch: Option<u64>,
    current: GossipDomain,
}

pub(super) struct DomainUpdate {
    pub current: GossipDomain,
    pub other: Option<GossipDomain>,
    pub epoch: u64,
    pub enr_fork_id: [u8; 16],
}

impl GossipSchedule {
    pub(super) fn new(
        spec: &SpecConfig,
        genesis_validators_root: &[u8; 32],
        ticker: SlotTicker,
    ) -> Self {
        let mut epochs: Vec<_> = ForkName::ALL
            .into_iter()
            .map(|fork| spec.fork_epoch(fork))
            .chain(spec.blob_schedule.iter().map(|entry| entry.epoch))
            .filter(|epoch| *epoch != FAR_FUTURE_EPOCH)
            .collect();
        epochs.sort_unstable();
        epochs.dedup();
        let mut transitions: Vec<Transition> = Vec::with_capacity(epochs.len());
        for epoch in epochs {
            let domain = GossipDomain::new(
                spec.fork_digest_at(epoch, genesis_validators_root),
                spec.fork_at(epoch),
            );
            if transitions.last().is_some_and(|previous| previous.domain == domain) {
                continue;
            }
            let (next_version, next_epoch) = spec.next_fork(epoch);
            let mut enr_fork_id = [0; 16];
            enr_fork_id[..4].copy_from_slice(&domain.digest());
            enr_fork_id[4..8].copy_from_slice(&next_version);
            enr_fork_id[8..].copy_from_slice(&next_epoch.to_le_bytes());
            transitions.push(Transition { epoch, domain, enr_fork_id });
        }
        let epoch = ticker.current_slot() / SLOTS_PER_EPOCH;
        let current = transitions
            [transitions.partition_point(|transition| transition.epoch <= epoch) - 1]
            .domain;
        Self { ticker, transitions, last_epoch: None, current }
    }

    pub(super) fn current(&self) -> GossipDomain {
        self.current
    }

    pub(super) fn advance(&mut self) -> Option<DomainUpdate> {
        let epoch = self.ticker.current_slot() / SLOTS_PER_EPOCH;
        if self.last_epoch == Some(epoch) {
            return None;
        }
        self.last_epoch = Some(epoch);
        let index = self.transitions.partition_point(|transition| transition.epoch <= epoch) - 1;
        let transition = &self.transitions[index];
        self.current = transition.domain;
        // With tightly spaced forks, preserving the draining domain takes precedence
        // over advance subscription.
        let other = if index > 0 && epoch - transition.epoch < RETAIN_EPOCHS {
            Some(self.transitions[index - 1].domain)
        } else {
            self.transitions
                .get(index + 1)
                .filter(|next| next.epoch - epoch <= ADVANCE_EPOCHS)
                .map(|next| next.domain)
        };
        Some(DomainUpdate {
            current: self.current,
            other,
            epoch,
            enr_fork_id: transition.enr_fork_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use silver_chain_spec::BlobParameters;

    use super::*;

    fn schedule() -> GossipSchedule {
        let mut spec = SpecConfig::mainnet();
        spec.fulu_fork_epoch = 0;
        spec.gloas_fork_epoch = 10;
        spec.blob_schedule = vec![BlobParameters { epoch: 20, max_blobs_per_block: 21 }];
        let mut ticker = SlotTicker::new(0, Duration::from_secs(12), Duration::from_secs(3));
        ticker.set_current_slot(0);
        GossipSchedule::new(&spec, &[0; 32], ticker)
    }

    fn at(schedule: &mut GossipSchedule, epoch: u64) -> DomainUpdate {
        schedule.ticker.set_current_slot(epoch * SLOTS_PER_EPOCH);
        schedule.advance().unwrap()
    }

    #[test]
    fn advance_cutover_and_retirement_follow_wall_epoch() {
        let mut schedule = schedule();
        let initial = at(&mut schedule, 0);
        assert_eq!(initial.current.format(), ForkName::Fulu);
        assert!(initial.other.is_none());
        assert!(schedule.advance().is_none());
        assert!(at(&mut schedule, 8).other.is_none());
        let advance = at(&mut schedule, 9);
        let gloas = advance.other.unwrap();
        assert_eq!(gloas.format(), ForkName::Gloas);
        let cutover = at(&mut schedule, 10);
        assert_eq!(cutover.current, gloas);
        assert_eq!(cutover.other, Some(initial.current));
        assert_eq!(&cutover.enr_fork_id[..4], &gloas.digest());
        assert_eq!(at(&mut schedule, 11).other, Some(initial.current));
        assert!(at(&mut schedule, 12).other.is_none());
    }

    #[test]
    fn blob_schedule_changes_digest_without_changing_format() {
        let mut schedule = schedule();
        let advance = at(&mut schedule, 19);
        let next = advance.other.unwrap();
        assert_eq!(next.format(), advance.current.format());
        assert_ne!(next.digest(), advance.current.digest());
        let cutover = at(&mut schedule, 20);
        assert_eq!(cutover.current, next);
        assert_eq!(cutover.other, Some(advance.current));
    }

    #[test]
    fn skipped_epochs_and_startup_reconstruct_the_active_domains() {
        let mut schedule = schedule();
        at(&mut schedule, 0);
        let after = at(&mut schedule, 21);
        assert_eq!(after.current, schedule.transitions[2].domain);
        assert_eq!(after.other, Some(schedule.transitions[1].domain));
        assert!(at(&mut schedule, 25).other.is_none());
        schedule.last_epoch = None;
        let startup = at(&mut schedule, 11);
        assert_eq!(startup.current.format(), ForkName::Gloas);
        assert_eq!(startup.other.unwrap().format(), ForkName::Fulu);
    }
}
