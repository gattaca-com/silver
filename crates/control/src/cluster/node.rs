use std::{
    collections::VecDeque,
    error::Error,
    fmt,
    time::{Duration, Instant},
};

use raft::{
    Config, RawNode, StateRole,
    eraftpb::{Entry, EntryType, Message},
    storage::MemStorage,
};

use super::{
    admission::{AdmissionError, AttestationAdmission},
    command::{AttestationLockCommand, CommandDecodeError, ReplicatedCommand},
    lock_store::{AttestationLockStore, LockResult},
};

const DEFAULT_TICK_INTERVAL: Duration = Duration::from_millis(100);
const DEFAULT_HEARTBEAT_TICKS: usize = 2;
const DEFAULT_ELECTION_TICKS: usize = 20;
const DEFAULT_PROPOSAL_TIMEOUT: Duration = Duration::from_millis(100);
const MAX_ELAPSED_TICKS_PER_SPIN: usize = 32;
const PROPOSAL_CONTEXT_LEN: usize = 16;

/// Static Raft membership and timing configuration.
#[derive(Debug, Clone)]
pub struct AttestationClusterConfig {
    pub node_id: u64,
    pub voters: Vec<u64>,
    pub tick_interval: Duration,
    pub heartbeat_ticks: usize,
    pub election_ticks: usize,
    /// Maximum time between accepting a local proposal and observing its
    /// commit on this node.
    pub proposal_timeout: Duration,
}

impl AttestationClusterConfig {
    pub fn new(node_id: u64, voters: Vec<u64>) -> Self {
        Self {
            node_id,
            voters,
            tick_interval: DEFAULT_TICK_INTERVAL,
            heartbeat_ticks: DEFAULT_HEARTBEAT_TICKS,
            election_ticks: DEFAULT_ELECTION_TICKS,
            proposal_timeout: DEFAULT_PROPOSAL_TIMEOUT,
        }
    }

    fn validate(&self) -> Result<(), ClusterError> {
        if self.node_id == 0 {
            return Err(ClusterError::InvalidConfig("Raft node id must be non-zero"));
        }
        if self.tick_interval.is_zero() {
            return Err(ClusterError::InvalidConfig("Raft tick interval must be non-zero"));
        }
        if self.proposal_timeout.is_zero() {
            return Err(ClusterError::InvalidConfig("Raft proposal timeout must be non-zero"));
        }
        if self.voters.is_empty() {
            return Err(ClusterError::InvalidConfig("Raft voter set must not be empty"));
        }
        if !self.voters.contains(&self.node_id) {
            return Err(ClusterError::InvalidConfig("local Raft node is not in voter set"));
        }
        if self.voters.contains(&0) {
            return Err(ClusterError::InvalidConfig("Raft voter ids must be non-zero"));
        }

        let mut voters = self.voters.clone();
        voters.sort_unstable();
        voters.dedup();
        if voters.len() != self.voters.len() {
            return Err(ClusterError::InvalidConfig("Raft voter ids must be unique"));
        }

        self.raft_config().validate().map_err(ClusterError::Raft)
    }

    fn raft_config(&self) -> Config {
        Config {
            id: self.node_id,
            heartbeat_tick: self.heartbeat_ticks,
            election_tick: self.election_ticks,
            check_quorum: true,
            pre_vote: true,
            ..Config::default()
        }
    }
}

/// Globally unique identifier for a proposal submitted through one cluster
/// node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProposalId {
    pub origin_node_id: u64,
    pub sequence: u64,
}

impl ProposalId {
    fn encode(self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(PROPOSAL_CONTEXT_LEN);
        encoded.extend_from_slice(&self.origin_node_id.to_le_bytes());
        encoded.extend_from_slice(&self.sequence.to_le_bytes());
        encoded
    }

    fn decode(encoded: &[u8]) -> Result<Self, usize> {
        if encoded.len() != PROPOSAL_CONTEXT_LEN {
            return Err(encoded.len());
        }

        Ok(Self {
            origin_node_id: u64::from_le_bytes(encoded[..8].try_into().expect("slice is 8 bytes")),
            sequence: u64::from_le_bytes(encoded[8..].try_into().expect("slice is 8 bytes")),
        })
    }
}

/// A locally-submitted attestation command after it has committed and been
/// applied. This permits the candidate to enter Beacon State validation; it
/// does not assert that the signed attestation is valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttestationDecision {
    pub proposal_id: ProposalId,
    pub command: AttestationLockCommand,
    pub result: LockResult,
    /// Rechecked when the entry commits, since it may have spent an epoch
    /// waiting for quorum after passing proposal-time admission.
    pub admission: Result<(), AdmissionError>,
}

impl AttestationDecision {
    /// Whether this candidate may enter Beacon State validation. Callers must
    /// not treat an accepted Raft selection alone as sufficient after the
    /// request has expired.
    #[must_use]
    pub fn may_validate(&self) -> bool {
        self.admission.is_ok() &&
            matches!(self.result, LockResult::Accepted | LockResult::AlreadyAcceptedSame)
    }
}

/// Work produced by one nonblocking [`AttestationCluster::spin`] invocation.
#[derive(Debug)]
pub enum ClusterEvent {
    SendRaftMessage(Message),
    AttestationCommitted(AttestationDecision),
    /// The proposal may still commit and reserve its candidate, but must no
    /// longer cause validation or publication for the original request.
    AttestationProposalTimedOut(ProposalId),
}

#[derive(Debug)]
pub enum ProposeError {
    Admission(AdmissionError),
    SequenceExhausted,
    DeadlineOverflow,
    Raft(raft::Error),
}

impl fmt::Display for ProposeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Admission(error) => error.fmt(f),
            Self::SequenceExhausted => f.write_str("Raft proposal sequence exhausted"),
            Self::DeadlineOverflow => f.write_str("Raft proposal deadline overflowed"),
            Self::Raft(error) => write!(f, "Raft rejected proposal: {error}"),
        }
    }
}

impl Error for ProposeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Admission(error) => Some(error),
            Self::Raft(error) => Some(error),
            Self::SequenceExhausted | Self::DeadlineOverflow => None,
        }
    }
}

#[derive(Debug)]
pub enum ClusterError {
    InvalidConfig(&'static str),
    Raft(raft::Error),
    Command(CommandDecodeError),
    InvalidProposalContextLength(usize),
    UnsupportedEntry(EntryType),
    SnapshotsUnsupported,
}

impl fmt::Display for ClusterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(message) => {
                write!(f, "invalid attestation cluster config: {message}")
            }
            Self::Raft(error) => error.fmt(f),
            Self::Command(error) => error.fmt(f),
            Self::InvalidProposalContextLength(actual) => write!(
                f,
                "Raft proposal context has length {actual}, expected {PROPOSAL_CONTEXT_LEN}"
            ),
            Self::UnsupportedEntry(entry_type) => {
                write!(f, "unsupported committed Raft entry type {entry_type:?}")
            }
            Self::SnapshotsUnsupported => {
                f.write_str("attestation Raft snapshots are not supported")
            }
        }
    }
}

impl Error for ClusterError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Raft(error) => Some(error),
            Self::Command(error) => Some(error),
            Self::InvalidConfig(_) |
            Self::UnsupportedEntry(_) |
            Self::SnapshotsUnsupported |
            Self::InvalidProposalContextLength(_) => None,
        }
    }
}

impl From<raft::Error> for ClusterError {
    fn from(error: raft::Error) -> Self {
        Self::Raft(error)
    }
}

/// Single-threaded driver for the attestation Raft group.
///
/// `spin` is a pump: callers invoke it once per Control tile loop. It executes
/// only work that is ready at that point and always returns without waiting.
/// The initial implementation uses `MemStorage`; replacing it with durable
/// storage is required before enabling the cluster in production.
pub struct AttestationCluster {
    node: RawNode<MemStorage>,
    state: AttestationLockStore,
    admission: AttestationAdmission,
    node_id: u64,
    next_proposal_sequence: u64,
    tick_interval: Duration,
    next_tick: Instant,
    proposal_timeout: Duration,
    pending_proposals: VecDeque<PendingProposal>,
    pending_minimum_slot: Option<u64>,
}

#[derive(Debug, Clone, Copy)]
struct PendingProposal {
    id: ProposalId,
    deadline: Instant,
}

impl AttestationCluster {
    /// Construct the Raft node with local attestation admission disabled.
    /// Call [`Self::set_startup_wall_slot`] once this node first catches up to
    /// its wall slot; Raft message processing and elections can run before it.
    pub fn new(config: AttestationClusterConfig, now: Instant) -> Result<Self, ClusterError> {
        config.validate()?;

        let storage = MemStorage::new_with_conf_state((config.voters.clone(), Vec::<u64>::new()));
        let node = RawNode::with_default_logger(&config.raft_config(), storage)?;
        let next_tick = now.checked_add(config.tick_interval).unwrap_or(now);

        Ok(Self {
            node,
            state: AttestationLockStore::default(),
            admission: AttestationAdmission::new(),
            node_id: config.node_id,
            next_proposal_sequence: 1,
            tick_interval: config.tick_interval,
            next_tick,
            proposal_timeout: config.proposal_timeout,
            pending_proposals: VecDeque::new(),
            pending_minimum_slot: None,
        })
    }

    pub fn node_id(&self) -> u64 {
        self.node_id
    }

    /// Enable local attestation admission using the first wall slot at which
    /// this node is synced. The resulting floor is immutable.
    pub fn set_startup_wall_slot(&mut self, startup_wall_slot: u64) -> bool {
        self.admission.set_startup_wall_slot(startup_wall_slot)
    }

    pub fn leader_id(&self) -> Option<u64> {
        let leader_id = self.node.raft.leader_id;
        (leader_id != 0).then_some(leader_id)
    }

    pub fn is_leader(&self) -> bool {
        self.node.raft.state == StateRole::Leader
    }

    #[cfg(test)]
    fn state(&self) -> &AttestationLockStore {
        &self.state
    }

    #[cfg(test)]
    fn pending_proposals(&self) -> usize {
        self.pending_proposals.len()
    }

    /// Explicitly start an election, primarily for controlled startup and
    /// tests.
    pub fn campaign(&mut self) -> Result<(), ClusterError> {
        self.node.campaign().map_err(ClusterError::Raft)
    }

    /// Deliver one decoded message received from another member of this Raft
    /// group.
    pub fn step(&mut self, message: Message) -> Result<(), ClusterError> {
        self.node.step(message).map_err(ClusterError::Raft)
    }

    pub fn report_unreachable(&mut self, node_id: u64) {
        self.node.report_unreachable(node_id);
    }

    /// Submit a locally-originated signed attestation for ordering before
    /// Beacon State validation.
    ///
    /// Success means only that Raft accepted the proposal. Publication must
    /// wait for the matching `AttestationCommitted` event from `spin`.
    /// Successive calls must supply nondecreasing `now` values from the tile's
    /// monotonic clock.
    pub fn propose_attestation(
        &mut self,
        command: AttestationLockCommand,
        wall_slot: u64,
        now: Instant,
    ) -> Result<ProposalId, ProposeError> {
        self.admission.validate(command.key.slot, wall_slot).map_err(ProposeError::Admission)?;

        if command.key.slot < self.state.minimum_slot() {
            return Err(ProposeError::Admission(AdmissionError::TooOld {
                slot: command.key.slot,
                minimum: self.state.minimum_slot(),
            }));
        }

        let sequence = self.next_proposal_sequence;
        self.next_proposal_sequence =
            sequence.checked_add(1).ok_or(ProposeError::SequenceExhausted)?;
        let proposal_id = ProposalId { origin_node_id: self.node_id, sequence };
        let deadline =
            now.checked_add(self.proposal_timeout).ok_or(ProposeError::DeadlineOverflow)?;

        debug_assert!(
            self.pending_proposals.back().is_none_or(|pending| pending.deadline <= deadline),
            "proposal timestamps must be monotonic"
        );

        self.node
            .propose(proposal_id.encode(), ReplicatedCommand::Lock(command).encode())
            .map_err(ProposeError::Raft)?;

        self.pending_proposals.push_back(PendingProposal { id: proposal_id, deadline });

        Ok(proposal_id)
    }

    /// Execute currently-pending Raft work and return immediately.
    ///
    /// The caller invokes this once per tile loop and forwards emitted messages
    /// to their target nodes. No network, disk, timer, or commit is waited on.
    pub fn spin(
        &mut self,
        now: Instant,
        wall_slot: u64,
        mut emit: impl FnMut(ClusterEvent),
    ) -> Result<(), ClusterError> {
        self.expire_proposals(now, &mut emit);
        self.tick_elapsed(now);
        self.maybe_propose_minimum_slot(wall_slot)?;

        while self.node.has_ready() {
            self.process_ready(now, wall_slot, &mut emit)?;
        }

        Ok(())
    }

    fn tick_elapsed(&mut self, now: Instant) {
        let mut ticks = 0;
        while now >= self.next_tick && ticks < MAX_ELAPSED_TICKS_PER_SPIN {
            self.node.tick();
            ticks += 1;
            self.next_tick = self.next_tick.checked_add(self.tick_interval).unwrap_or(now);
        }

        if now >= self.next_tick {
            // A long-stalled tile does not need to replay an unbounded number of
            // obsolete heartbeat intervals in one invocation.
            self.next_tick = now.checked_add(self.tick_interval).unwrap_or(now);
        }
    }

    fn maybe_propose_minimum_slot(&mut self, wall_slot: u64) -> Result<(), ClusterError> {
        if !self.is_leader() {
            self.pending_minimum_slot = None;
            return Ok(());
        }

        let desired = AttestationAdmission::age_floor(wall_slot);
        if desired <= self.state.minimum_slot() {
            self.pending_minimum_slot = None;
            return Ok(());
        }
        if self.pending_minimum_slot.is_some() {
            return Ok(());
        }

        self.node.propose(Vec::new(), ReplicatedCommand::AdvanceMinimumSlot(desired).encode())?;
        self.pending_minimum_slot = Some(desired);
        Ok(())
    }

    fn process_ready(
        &mut self,
        now: Instant,
        wall_slot: u64,
        emit: &mut impl FnMut(ClusterEvent),
    ) -> Result<(), ClusterError> {
        let mut ready = self.node.ready();

        for message in ready.take_messages() {
            emit(ClusterEvent::SendRaftMessage(message));
        }

        if !ready.snapshot().is_empty() {
            // State-machine snapshot encoding will be added with durable
            // storage. Refuse an incomplete snapshot rather than silently
            // losing attestation locks.
            return Err(ClusterError::SnapshotsUnsupported);
        }

        {
            let mut storage = self.node.mut_store().wl();
            storage.append(ready.entries())?;
            if let Some(hard_state) = ready.hs() {
                storage.set_hardstate(hard_state.clone());
            }
        }

        for message in ready.take_persisted_messages() {
            emit(ClusterEvent::SendRaftMessage(message));
        }

        self.apply_entries(ready.take_committed_entries(), now, wall_slot, emit)?;

        let mut light_ready = self.node.advance(ready);
        if let Some(commit_index) = light_ready.commit_index() {
            self.node.mut_store().wl().mut_hard_state().set_commit(commit_index);
        }
        for message in light_ready.take_messages() {
            emit(ClusterEvent::SendRaftMessage(message));
        }
        self.apply_entries(light_ready.take_committed_entries(), now, wall_slot, emit)?;
        self.node.advance_apply();

        Ok(())
    }

    fn apply_entries(
        &mut self,
        entries: Vec<Entry>,
        now: Instant,
        wall_slot: u64,
        emit: &mut impl FnMut(ClusterEvent),
    ) -> Result<(), ClusterError> {
        for entry in entries {
            if entry.data.is_empty() {
                continue;
            }
            if entry.get_entry_type() != EntryType::EntryNormal {
                return Err(ClusterError::UnsupportedEntry(entry.get_entry_type()));
            }

            match ReplicatedCommand::decode(&entry.data).map_err(ClusterError::Command)? {
                ReplicatedCommand::Lock(command) => {
                    let proposal_id = ProposalId::decode(&entry.context)
                        .map_err(ClusterError::InvalidProposalContextLength)?;
                    let result = self.state.apply(&command);
                    if proposal_id.origin_node_id == self.node_id &&
                        let Some(pending) = self.take_pending_proposal(proposal_id)
                    {
                        if now >= pending.deadline {
                            emit(ClusterEvent::AttestationProposalTimedOut(proposal_id));
                        } else {
                            emit(ClusterEvent::AttestationCommitted(AttestationDecision {
                                proposal_id,
                                command,
                                result,
                                admission: self.admission.validate(command.key.slot, wall_slot),
                            }));
                        }
                    }
                }
                ReplicatedCommand::AdvanceMinimumSlot(minimum_slot) => {
                    self.state.advance_minimum_slot(minimum_slot);
                    if self.pending_minimum_slot.is_some_and(|pending| pending <= minimum_slot) {
                        self.pending_minimum_slot = None;
                    }
                }
            }
        }

        Ok(())
    }

    fn take_pending_proposal(&mut self, proposal_id: ProposalId) -> Option<PendingProposal> {
        let index = self.pending_proposals.iter().position(|pending| pending.id == proposal_id)?;
        self.pending_proposals.remove(index)
    }

    fn expire_proposals(&mut self, now: Instant, emit: &mut impl FnMut(ClusterEvent)) {
        while self.pending_proposals.front().is_some_and(|proposal| now >= proposal.deadline) {
            let proposal = self.pending_proposals.pop_front().expect("front exists");
            emit(ClusterEvent::AttestationProposalTimedOut(proposal.id));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster::{AttestationKey, LockResult};

    fn command(slot: u64, root: u8) -> AttestationLockCommand {
        let mut ssz = [0; silver_common::ssz_view::SINGLE_ATT_SIZE];
        ssz[0] = root;
        AttestationLockCommand {
            key: AttestationKey { validator_pubkey: [9; 48], slot },
            subnet: u64::from(root) % silver_common::ATTESTATION_SUBNETS as u64,
            ssz,
        }
    }

    fn test_config(node_id: u64, voters: Vec<u64>) -> AttestationClusterConfig {
        let mut config = AttestationClusterConfig::new(node_id, voters);
        config.tick_interval = Duration::from_millis(1);
        config.heartbeat_ticks = 1;
        config.election_ticks = 5;
        config
    }

    fn initialized_cluster(
        config: AttestationClusterConfig,
        startup_wall_slot: u64,
        now: Instant,
    ) -> AttestationCluster {
        let mut cluster = AttestationCluster::new(config, now).unwrap();
        assert!(cluster.set_startup_wall_slot(startup_wall_slot));
        cluster
    }

    fn pump(
        clusters: &mut [AttestationCluster],
        now: Instant,
        wall_slot: u64,
        decisions: &mut Vec<(u64, AttestationDecision)>,
    ) {
        let mut messages = Vec::new();
        for cluster in clusters.iter_mut() {
            let node_id = cluster.node_id();
            cluster
                .spin(now, wall_slot, |event| match event {
                    ClusterEvent::SendRaftMessage(message) => messages.push(message),
                    ClusterEvent::AttestationCommitted(decision) => {
                        decisions.push((node_id, decision));
                    }
                    ClusterEvent::AttestationProposalTimedOut(proposal_id) => {
                        panic!("unexpected timeout for {proposal_id:?}");
                    }
                })
                .unwrap();
        }

        for message in messages {
            clusters
                .iter_mut()
                .find(|cluster| cluster.node_id() == message.to)
                .expect("Raft message target is a voter")
                .step(message)
                .unwrap();
        }
    }

    #[test]
    fn single_node_proposal_completes_only_from_spin() {
        let now = Instant::now();
        let mut cluster = initialized_cluster(test_config(1, vec![1]), 9, now);
        cluster.campaign().unwrap();

        let proposal_id = cluster.propose_attestation(command(10, 1), 10, now).unwrap();
        let mut events = Vec::new();
        cluster.spin(now, 10, |event| events.push(event)).unwrap();

        let decisions: Vec<_> = events
            .into_iter()
            .filter_map(|event| match event {
                ClusterEvent::AttestationCommitted(decision) => Some(decision),
                ClusterEvent::SendRaftMessage(_) | ClusterEvent::AttestationProposalTimedOut(_) => {
                    None
                }
            })
            .collect();
        assert_eq!(decisions, vec![AttestationDecision {
            proposal_id,
            command: command(10, 1),
            result: LockResult::Accepted,
            admission: Ok(()),
        }]);
    }

    #[test]
    fn proposal_times_out_at_one_hundred_milliseconds_and_remains_locked() {
        let now = Instant::now();
        let mut cluster = initialized_cluster(test_config(1, vec![1]), 9, now);
        assert_eq!(cluster.proposal_timeout, Duration::from_millis(100));
        cluster.campaign().unwrap();

        let proposal_id = cluster.propose_attestation(command(10, 1), 10, now).unwrap();
        assert_eq!(cluster.pending_proposals(), 1);

        let mut committed = Vec::new();
        let mut timed_out = Vec::new();
        cluster
            .spin(now + Duration::from_millis(100), 10, |event| match event {
                ClusterEvent::AttestationCommitted(decision) => committed.push(decision),
                ClusterEvent::AttestationProposalTimedOut(proposal_id) => {
                    timed_out.push(proposal_id);
                }
                ClusterEvent::SendRaftMessage(_) => {}
            })
            .unwrap();

        assert!(committed.is_empty());
        assert_eq!(timed_out, [proposal_id]);
        assert_eq!(cluster.pending_proposals(), 0);
        assert_eq!(cluster.state().len(), 1);
        assert_eq!(cluster.state.apply(&command(10, 2)), LockResult::ConflictingAttestation);
    }

    #[test]
    fn same_attestation_is_idempotent_and_different_attestation_conflicts_through_raft() {
        let now = Instant::now();
        let mut cluster = initialized_cluster(test_config(1, vec![1]), 9, now);
        cluster.campaign().unwrap();

        let mut results = Vec::new();
        for root in [1, 1, 2] {
            cluster.propose_attestation(command(10, root), 10, now).unwrap();
            cluster
                .spin(now, 10, |event| {
                    if let ClusterEvent::AttestationCommitted(decision) = event {
                        results.push(decision.result);
                    }
                })
                .unwrap();
        }

        assert_eq!(results, [
            LockResult::Accepted,
            LockResult::AlreadyAcceptedSame,
            LockResult::ConflictingAttestation,
        ]);
    }

    #[test]
    fn proposal_checks_local_admission_before_raft() {
        let now = Instant::now();
        let mut cluster = AttestationCluster::new(test_config(1, vec![1]), now).unwrap();
        cluster.campaign().unwrap();

        assert!(matches!(
            cluster.propose_attestation(command(101, 1), 101, now),
            Err(ProposeError::Admission(AdmissionError::StartupFloorUnset))
        ));
        assert!(cluster.set_startup_wall_slot(100));
        assert!(!cluster.set_startup_wall_slot(200));
        assert!(matches!(
            cluster.propose_attestation(command(100, 1), 101, now),
            Err(ProposeError::Admission(AdmissionError::BeforeStartupFloor { .. }))
        ));
        assert!(matches!(
            cluster.propose_attestation(command(102, 1), 101, now),
            Err(ProposeError::Admission(AdmissionError::Future { .. }))
        ));
    }

    #[test]
    fn committed_age_floor_protects_against_a_regressed_local_clock() {
        let now = Instant::now();
        let mut cluster = initialized_cluster(test_config(1, vec![1]), 0, now);
        cluster.campaign().unwrap();
        cluster.spin(now, 64, |_| {}).unwrap();

        assert_eq!(cluster.state().minimum_slot(), 64 - silver_common::SLOTS_PER_EPOCH);
        assert!(matches!(
            cluster.propose_attestation(command(31, 1), 31, now),
            Err(ProposeError::Admission(AdmissionError::TooOld { minimum: 32, .. }))
        ));
    }

    #[test]
    fn proposal_that_expires_before_commit_is_not_validatable() {
        let now = Instant::now();
        let mut cluster = initialized_cluster(test_config(1, vec![1]), 0, now);
        cluster.campaign().unwrap();

        cluster.propose_attestation(command(1, 1), 1, now).unwrap();
        let mut decision = None;
        cluster
            .spin(now, 2 + silver_common::SLOTS_PER_EPOCH, |event| {
                if let ClusterEvent::AttestationCommitted(committed) = event {
                    decision = Some(committed);
                }
            })
            .unwrap();

        let decision = decision.expect("proposal committed");
        assert_eq!(decision.result, LockResult::Accepted);
        assert!(matches!(decision.admission, Err(AdmissionError::TooOld { .. })));
        assert!(!decision.may_validate());
    }

    #[test]
    fn follower_proposal_is_committed_and_applied_by_three_nodes() {
        let mut now = Instant::now();
        let voters = vec![1, 2, 3];
        let mut clusters: Vec<_> = voters
            .iter()
            .map(|node_id| initialized_cluster(test_config(*node_id, voters.clone()), 9, now))
            .collect();
        let mut decisions = Vec::new();

        clusters[0].campaign().unwrap();
        for _ in 0..20 {
            pump(&mut clusters, now, 10, &mut decisions);
            now += Duration::from_millis(1);
        }
        assert!(clusters[0].is_leader());
        assert_eq!(clusters[1].leader_id(), Some(1));

        let proposal_id = clusters[1].propose_attestation(command(10, 4), 10, now).unwrap();
        for _ in 0..20 {
            pump(&mut clusters, now, 10, &mut decisions);
            now += Duration::from_millis(1);
            if !decisions.is_empty() {
                break;
            }
        }

        assert_eq!(decisions, vec![(2, AttestationDecision {
            proposal_id,
            command: command(10, 4),
            result: LockResult::Accepted,
            admission: Ok(()),
        })]);
        assert!(clusters.iter().all(|cluster| cluster.state().len() == 1));
    }
}
