use std::{
    error::Error,
    fmt, io, mem,
    time::{Duration, Instant},
};

use flux::utils::ArrayVec;
use raft::{
    Config, RawNode, StateRole,
    eraftpb::{Entry, Message, MessageType},
};
use silver_common::{ClusterDuty, ClusterOutcome, ClusterPeerStats};

#[cfg(any(target_os = "linux", test))]
use super::persistence::RecoveredStorage;
use super::{
    admission::{AdmissionError, SlashingAdmission},
    command::{
        AttestationLockCommand, BlockKey, BlockLockCommand, DecodedEntry, EntryError,
        ReplicatedCommand,
    },
    lock_store::{LockResult, SlashingLockStore},
    member_message_check::{LeaderBoycott, MemberMessageCheck, MemberMessageError},
    metrics::{ClusterCounters, ClusterMetrics, ResolvedProposal},
    peers::ClusterPeers,
    pending::{PendingProposal, PendingProposals},
    persistence::{ClusterStorageConfig, PersistedReady, Persistence, PersistenceEvent},
    raft_storage::{RaftStorage, RestoredSnapshot},
    snapshot_transfers::SnapshotTransfers,
};

const DEFAULT_TICK_INTERVAL: Duration = Duration::from_millis(100);
const DEFAULT_HEARTBEAT_TICKS: usize = 2;
const DEFAULT_ELECTION_TICKS: usize = 20;
// Block import stalls the Control loop; a 3-node kurtosis cluster saw
// follower-origin commits take up to 145 ms then.
const DEFAULT_PROPOSAL_TIMEOUT: Duration = Duration::from_millis(500);
const MAX_ELAPSED_TICKS_PER_SPIN: usize = 32;
const PROPOSAL_CONTEXT_LEN: usize = 32;
const MAX_APPEND_BYTES: u64 = 1024 * 1024;
// Below the 128-message cluster stream queue, which overwrites its oldest
// message when full.
const MAX_INFLIGHT_APPENDS: usize = 64;

/// raft-rs computes the commit index on the stack for up to 7 voters and
/// allocates above that. etcd, whose raft raft-rs ports, also advises at most
/// 7 members.
pub(super) const MAX_VOTERS: usize = 7;
pub(super) type Voters = ArrayVec<u64, MAX_VOTERS>;

/// `None` past `MAX_VOTERS` ids.
pub(super) fn voters(ids: impl IntoIterator<Item = u64>) -> Option<Voters> {
    let mut voters = Voters::new();
    for id in ids {
        if voters.try_push(id).is_some() {
            return None;
        }
    }
    Some(voters)
}

/// Static Raft membership and timing configuration.
#[derive(Debug, Clone)]
pub struct SlashingProtectionConfig {
    pub node_id: u64,
    pub voters: Voters,
    pub storage: ClusterStorageConfig,
    pub tick_interval: Duration,
    pub heartbeat_ticks: usize,
    pub election_ticks: usize,
    /// Maximum time between accepting a local proposal and observing its
    /// commit on this node.
    pub proposal_timeout: Duration,
    pub snapshot_interval: u64,
}

impl SlashingProtectionConfig {
    pub fn new(
        node_id: u64,
        voters: impl IntoIterator<Item = u64>,
        storage: ClusterStorageConfig,
    ) -> Result<Self, ClusterError> {
        let voters = self::voters(voters)
            .ok_or(ClusterError::InvalidConfig("a Raft cluster has at most 7 voters"))?;
        Ok(Self {
            node_id,
            voters,
            storage,
            tick_interval: DEFAULT_TICK_INTERVAL,
            heartbeat_ticks: DEFAULT_HEARTBEAT_TICKS,
            election_ticks: DEFAULT_ELECTION_TICKS,
            proposal_timeout: DEFAULT_PROPOSAL_TIMEOUT,
            snapshot_interval: 4096,
        })
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
        if self.snapshot_interval == 0 {
            return Err(ClusterError::InvalidConfig("Raft snapshot interval must be non-zero"));
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

        let mut voters = self.voters;
        voters.sort_unstable();
        if voters.windows(2).any(|pair| pair[0] == pair[1]) {
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
            max_size_per_msg: MAX_APPEND_BYTES,
            max_inflight_msgs: MAX_INFLIGHT_APPENDS,
            batch_append: true,
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
    pub incarnation: [u8; 16],
}

impl ProposalId {
    fn encode(self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(PROPOSAL_CONTEXT_LEN);
        encoded.extend_from_slice(&self.origin_node_id.to_le_bytes());
        encoded.extend_from_slice(&self.sequence.to_le_bytes());
        encoded.extend_from_slice(&self.incarnation);
        encoded
    }

    pub(super) fn decode(encoded: &[u8]) -> Result<Self, usize> {
        if encoded.len() != PROPOSAL_CONTEXT_LEN && encoded.len() != 16 {
            return Err(encoded.len());
        }

        Ok(Self {
            origin_node_id: u64::from_le_bytes(encoded[..8].try_into().map_err(|_| encoded.len())?),
            sequence: u64::from_le_bytes(encoded[8..16].try_into().map_err(|_| encoded.len())?),
            // Old contexts can still apply, but cannot match this process's requests.
            incarnation: if encoded.len() == 16 {
                [0; 16]
            } else {
                encoded[16..].try_into().map_err(|_| encoded.len())?
            },
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockDecision {
    pub proposal_id: ProposalId,
    pub key: BlockKey,
    pub result: LockResult,
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

/// Work produced by one nonblocking [`SlashingProtectionCluster::spin`]
/// invocation.
#[derive(Debug)]
pub enum ClusterEvent {
    SendRaftMessage(Message),
    AttestationCommitted(AttestationDecision),
    BlockCommitted(BlockDecision),
    /// The proposal may still commit and reserve its candidate, but must no
    /// longer cause validation or publication for the original request.
    ProposalTimedOut(ProposalId),
}

#[derive(Debug)]
pub enum ProposeError {
    Admission(AdmissionError),
    NotReady,
    Failed,
    SequenceExhausted,
    DeadlineOverflow,
}

impl fmt::Display for ProposeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Admission(error) => error.fmt(f),
            Self::NotReady => f.write_str("Raft storage recovery is not complete"),
            Self::Failed => f.write_str("Raft processing has stopped after a failure"),
            Self::SequenceExhausted => f.write_str("Raft proposal sequence exhausted"),
            Self::DeadlineOverflow => f.write_str("Raft proposal deadline overflowed"),
        }
    }
}

impl Error for ProposeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Admission(error) => Some(error),
            Self::NotReady | Self::Failed | Self::SequenceExhausted | Self::DeadlineOverflow => {
                None
            }
        }
    }
}

#[derive(Debug)]
pub enum ClusterError {
    InvalidConfig(&'static str),
    Raft(raft::Error),
    /// A committed entry this binary cannot apply. Every replay fails on it.
    BadEntry {
        index: u64,
        term: u64,
        cause: EntryError,
    },
    MemberMessage(MemberMessageError),
    Snapshot(io::Error),
    Storage(io::Error),
    NotReady,
    Failed,
}

/// What stopped Raft processing, exported as the `FailureKind` gauge so an
/// operator can tell a disk to fix from a binary to replace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum FailureKind {
    /// Journal I/O. A restart on a healthy disk recovers.
    Storage = 1,
    /// A committed entry this binary cannot apply. A restart replays it, so
    /// only a binary that can apply it recovers.
    BadEntry = 2,
    /// An installed or recovered snapshot is invalid.
    Snapshot = 3,
    Raft = 4,
    Other = 5,
}

impl ClusterError {
    pub fn failure_kind(&self) -> FailureKind {
        match self {
            Self::Storage(_) => FailureKind::Storage,
            Self::BadEntry { .. } => FailureKind::BadEntry,
            Self::Snapshot(_) => FailureKind::Snapshot,
            Self::Raft(_) => FailureKind::Raft,
            Self::InvalidConfig(_) | Self::MemberMessage(_) | Self::NotReady | Self::Failed => {
                FailureKind::Other
            }
        }
    }
}

impl fmt::Display for ClusterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(message) => {
                write!(f, "invalid slashing protection config: {message}")
            }
            Self::Raft(error) => error.fmt(f),
            Self::Storage(error) => write!(f, "Raft storage failed: {error}"),
            Self::NotReady => f.write_str("Raft storage recovery is not complete"),
            Self::Failed => f.write_str("Raft processing has stopped after a failure"),
            Self::BadEntry { index, term, cause } => {
                write!(f, "committed Raft entry {index} (term {term}) cannot be applied: {cause}")
            }
            Self::Snapshot(error) => {
                write!(f, "invalid slashing protection Raft snapshot: {error}")
            }
            Self::MemberMessage(error) => write!(f, "refused member Raft message: {error:?}"),
        }
    }
}

impl Error for ClusterError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Raft(error) => Some(error),
            Self::Storage(error) => Some(error),
            Self::Snapshot(error) => Some(error),
            Self::InvalidConfig(_) |
            Self::NotReady |
            Self::Failed |
            Self::BadEntry { .. } |
            Self::MemberMessage(_) => None,
        }
    }
}

impl From<raft::Error> for ClusterError {
    fn from(error: raft::Error) -> Self {
        Self::Raft(error)
    }
}

/// Single-threaded driver for the slashing protection Raft group.
///
/// `spin` is a pump: callers invoke it once per Control tile loop. It executes
/// only work that is ready at that point and always returns without waiting.
pub struct SlashingProtectionCluster {
    node: Option<RawNode<RaftStorage>>,
    config: SlashingProtectionConfig,
    persistence: Persistence,
    failed: bool,
    state: SlashingLockStore,
    admission: SlashingAdmission,
    incarnation: [u8; 16],
    next_proposal_sequence: u64,
    next_tick: Instant,
    pending_proposals: PendingProposals,
    resolved: Vec<ResolvedProposal>,
    persistence_started: Option<Instant>,
    /// Applied index before which compaction is not retried after an
    /// oversized snapshot, so the skip is not logged and counted every loop.
    compaction_retry_at: u64,
    leader_boycott: LeaderBoycott,
    unsubmitted_entries: Vec<Entry>,
    pending_minimum_slot: Option<u64>,
    snapshot_transfers: SnapshotTransfers,
    metrics: ClusterMetrics,
    peers: ClusterPeers,
}

impl SlashingProtectionCluster {
    /// Construct the Raft node with local admission disabled.
    /// Recovery must complete before Raft participation. Local requests also
    /// require a synced startup floor.
    pub fn new(config: SlashingProtectionConfig, now: Instant) -> Result<Self, ClusterError> {
        config.validate()?;
        let persistence = Persistence::new(&config).map_err(ClusterError::Storage)?;
        Ok(Self::with_persistence(config, persistence, now))
    }

    fn with_persistence(
        config: SlashingProtectionConfig,
        persistence: Persistence,
        now: Instant,
    ) -> Self {
        let next_tick = now.checked_add(config.tick_interval).unwrap_or(now);
        let mut incarnation: [u8; 16] = rand::random();
        incarnation[0] |= 1; // Zero is reserved for legacy proposal contexts.
        Self {
            node: None,
            peers: ClusterPeers::new(config.node_id, &config.voters),
            config,
            persistence,
            failed: false,
            state: SlashingLockStore::default(),
            admission: SlashingAdmission::new(),
            incarnation,
            next_proposal_sequence: 1,
            next_tick,
            pending_proposals: PendingProposals::default(),
            resolved: Vec::new(),
            persistence_started: None,
            compaction_retry_at: 0,
            leader_boycott: LeaderBoycott::default(),
            unsubmitted_entries: Vec::new(),
            pending_minimum_slot: None,
            snapshot_transfers: SnapshotTransfers::default(),
            metrics: ClusterMetrics::new(),
        }
    }

    #[cfg(test)]
    pub(crate) fn in_memory(
        config: SlashingProtectionConfig,
        now: Instant,
    ) -> Result<Self, ClusterError> {
        config.validate()?;
        let mut cluster = Self::with_persistence(config, Persistence::memory(), now);
        cluster.recover(RecoveredStorage::default(), now)?;
        Ok(cluster)
    }

    #[cfg(test)]
    pub(crate) fn fail_persistence(&mut self) {
        self.persistence.fail = true;
    }

    pub fn is_ready(&self) -> bool {
        self.node.is_some() && !self.failed
    }

    pub fn is_failed(&self) -> bool {
        self.failed
    }

    pub fn node_id(&self) -> u64 {
        self.config.node_id
    }

    /// Enable local admission using the first wall slot at which
    /// this node is synced. The resulting floor is immutable.
    pub fn set_startup_wall_slot(&mut self, startup_wall_slot: u64) -> bool {
        self.admission.set_startup_wall_slot(startup_wall_slot)
    }

    pub fn leader_id(&self) -> Option<u64> {
        if self.failed {
            return None;
        }
        let leader_id = self.node.as_ref()?.raft.leader_id;
        (leader_id != 0).then_some(leader_id)
    }

    pub fn is_leader(&self) -> bool {
        !self.failed && self.node.as_ref().is_some_and(|node| node.raft.state == StateRole::Leader)
    }

    #[cfg(test)]
    fn state(&self) -> &SlashingLockStore {
        &self.state
    }

    #[cfg(test)]
    fn pending_proposals(&self) -> usize {
        self.pending_proposals.len()
    }

    #[cfg(test)]
    pub(crate) fn minimum_slot(&self) -> u64 {
        self.state.minimum_slot()
    }

    /// Explicitly start an election, primarily for controlled startup and
    /// tests.
    pub fn campaign(&mut self) -> Result<(), ClusterError> {
        if self.failed {
            return Err(ClusterError::Failed);
        }
        self.node.as_mut().ok_or(ClusterError::NotReady)?.campaign().map_err(ClusterError::Raft)
    }

    /// Deliver one decoded message received from another member of this Raft
    /// group.
    pub fn step(
        &mut self,
        message: Message,
        now: Instant,
        wall_slot: u64,
    ) -> Result<(), ClusterError> {
        if self.failed {
            return Err(ClusterError::Failed);
        }
        if self.leader_boycott.covers(&message, wall_slot) {
            return Ok(());
        }
        let node = self.node.as_mut().ok_or(ClusterError::NotReady)?;
        let checked =
            MemberMessageCheck { log: &node.raft.raft_log, voters: &self.config.voters, wall_slot }
                .check(&message);
        if let Err(error) = checked {
            if let MemberMessageError::LeaderAheadOfClock { slot, .. } = error {
                self.leader_boycott.start(&message, slot, wall_slot);
            }
            return Err(ClusterError::MemberMessage(error));
        }
        self.peers.heard(&message, now);
        node.step(message).map_err(ClusterError::Raft)
    }

    pub fn peer_stats(&self, now: Instant) -> impl Iterator<Item = ClusterPeerStats> {
        self.node
            .as_ref()
            .filter(|_| !self.failed)
            .into_iter()
            .flat_map(move |node| self.peers.stats(node, now))
    }

    pub(crate) fn drain_resolved(&mut self) -> impl Iterator<Item = ResolvedProposal> + '_ {
        self.resolved.drain(..)
    }

    pub fn report_unreachable(&mut self, node_id: u64) {
        if !self.failed &&
            let Some(node) = self.node.as_mut()
        {
            node.report_unreachable(node_id);
            self.snapshot_transfers.unreachable(node, node_id);
        }
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
        let slot = command.key.slot;
        self.propose(
            slot,
            ClusterDuty::Attestation,
            ReplicatedCommand::Lock(command),
            wall_slot,
            now,
        )
    }

    pub fn propose_block(
        &mut self,
        command: BlockLockCommand,
        wall_slot: u64,
        now: Instant,
    ) -> Result<ProposalId, ProposeError> {
        let slot = command.key.slot;
        self.propose(
            slot,
            ClusterDuty::Block,
            ReplicatedCommand::BlockLock(command),
            wall_slot,
            now,
        )
    }

    fn propose(
        &mut self,
        slot: u64,
        duty: ClusterDuty,
        command: ReplicatedCommand,
        wall_slot: u64,
        now: Instant,
    ) -> Result<ProposalId, ProposeError> {
        if self.failed {
            return Err(ProposeError::Failed);
        }
        if self.node.is_none() {
            return Err(ProposeError::NotReady);
        }
        self.admission.validate(slot, wall_slot).map_err(ProposeError::Admission)?;

        if slot < self.state.minimum_slot() {
            return Err(ProposeError::Admission(AdmissionError::TooOld {
                slot,
                minimum: self.state.minimum_slot(),
            }));
        }

        let sequence = self.next_proposal_sequence;
        self.next_proposal_sequence =
            sequence.checked_add(1).ok_or(ProposeError::SequenceExhausted)?;
        let proposal_id = ProposalId {
            origin_node_id: self.config.node_id,
            sequence,
            incarnation: self.incarnation,
        };
        let deadline =
            now.checked_add(self.config.proposal_timeout).ok_or(ProposeError::DeadlineOverflow)?;

        self.unsubmitted_entries.push(Entry {
            context: proposal_id.encode().into(),
            data: command.encode().into(),
            ..Entry::default()
        });
        self.pending_proposals.push(PendingProposal::new(
            proposal_id,
            slot,
            duty,
            self.is_leader(),
            now,
            deadline,
        ));
        ClusterCounters::ProposalsSubmitted.inc();

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
        if self.failed {
            return Ok(());
        }
        self.expire_proposals(now, &mut emit);
        let result = self.drive(now, wall_slot, &mut emit);
        if let Err(error) = &result {
            self.failed = true;
            ClusterCounters::Failed.set(1);
            ClusterCounters::FailureKind.set(error.failure_kind() as u64);
            self.pending_proposals.clear();
            self.pending_minimum_slot = None;
        }
        result
    }

    fn drive(
        &mut self,
        now: Instant,
        wall_slot: u64,
        emit: &mut impl FnMut(ClusterEvent),
    ) -> Result<(), ClusterError> {
        self.poll_persistence(now, wall_slot, emit)?;
        if self.node.is_none() {
            return Ok(());
        }
        if let Some(node) = self.node.as_mut() {
            self.snapshot_transfers.expire(node, now);
        }
        self.submit_entries(now, emit)?;
        if self.tick_elapsed(now) {
            self.sample();
        }
        self.maybe_propose_minimum_slot(wall_slot)?;

        while !self.persistence.is_pending() && self.node.as_ref().is_some_and(RawNode::has_ready) {
            self.process_ready(now, emit)?;
            self.poll_persistence(now, wall_slot, emit)?;
        }

        self.maybe_compact(now)
    }

    fn maybe_compact(&mut self, now: Instant) -> Result<(), ClusterError> {
        if self.persistence.is_pending() {
            return Ok(());
        }
        let Some(node) = &self.node else {
            return Ok(());
        };
        let applied = node.raft.raft_log.applied;
        if applied == 0 ||
            (applied.saturating_sub(node.store().snapshot_index()) <
                self.config.snapshot_interval &&
                !self.persistence.compaction_due())
        {
            return Ok(());
        }
        if applied < self.compaction_retry_at {
            return Ok(());
        }
        // Too many locks to ship in one message. The journal keeps every entry
        // since the last snapshot, so skipping costs disk, not safety.
        let data = match self.state.encode_snapshot() {
            Ok(data) => data,
            Err(error) => {
                self.compaction_retry_at = applied.saturating_add(self.config.snapshot_interval);
                ClusterCounters::CompactionsSkipped.inc();
                silver_log::warn!(%error, applied, "lock snapshot compaction skipped");
                return Ok(());
            }
        };
        ClusterCounters::SnapshotBytes.set(data.len() as u64);
        let (snapshot, hard_state) = node.store().checkpoint(applied, data)?;
        let entries = node.store().suffix(applied)?;
        self.persistence.compact(snapshot, &entries, &hard_state).map_err(ClusterError::Storage)?;
        self.persistence_started = Some(now);
        Ok(())
    }

    fn sample(&self) {
        let Some(node) = &self.node else {
            return;
        };
        self.metrics.sample_log(node, self.pending_proposals.len());
        self.state.sample();
        ClusterCounters::JournalBytes.set(self.persistence.appended_bytes());
    }

    fn tick_elapsed(&mut self, now: Instant) -> bool {
        let Some(node) = self.node.as_mut() else {
            return false;
        };
        let mut ticks = 0;
        while now >= self.next_tick && ticks < MAX_ELAPSED_TICKS_PER_SPIN {
            node.tick();
            ticks += 1;
            self.next_tick = self.next_tick.checked_add(self.config.tick_interval).unwrap_or(now);
        }

        if now >= self.next_tick {
            // A long-stalled tile does not need to replay an unbounded number of
            // obsolete heartbeat intervals in one invocation.
            self.next_tick = now.checked_add(self.config.tick_interval).unwrap_or(now);
        }
        ticks > 0
    }

    /// One proposal message per spin, so a burst of local requests costs a
    /// follower one forwarded message and the leader one append per peer.
    fn submit_entries(
        &mut self,
        now: Instant,
        emit: &mut impl FnMut(ClusterEvent),
    ) -> Result<(), ClusterError> {
        if self.unsubmitted_entries.is_empty() {
            return Ok(());
        }
        let node = self.node.as_mut().ok_or(ClusterError::NotReady)?;
        let count = self.unsubmitted_entries.len();
        let mut message = Message::default();
        message.set_msg_type(MessageType::MsgPropose);
        message.from = self.config.node_id;
        message.set_entries(mem::take(&mut self.unsubmitted_entries).into());
        match node.step(message) {
            Ok(()) => Ok(()),
            Err(raft::Error::ProposalDropped) => {
                ClusterCounters::ProposalBatchesDropped.inc();
                silver_log::warn!(
                    count,
                    leader_id = node.raft.leader_id,
                    "Raft dropped local proposals"
                );
                let first_dropped = self.next_proposal_sequence - count as u64;
                while let Some(proposal) = self.pending_proposals.pop_from_sequence(first_dropped) {
                    self.resolved.push(proposal.resolve(now, ClusterOutcome::TimedOut));
                    emit(ClusterEvent::ProposalTimedOut(proposal.id));
                }
                Ok(())
            }
            Err(error) => Err(ClusterError::Raft(error)),
        }
    }

    fn maybe_propose_minimum_slot(&mut self, wall_slot: u64) -> Result<(), ClusterError> {
        if !self.is_leader() {
            self.pending_minimum_slot = None;
            return Ok(());
        }

        let desired = SlashingAdmission::age_floor(wall_slot);
        if desired <= self.state.minimum_slot() {
            self.pending_minimum_slot = None;
            return Ok(());
        }
        if self.pending_minimum_slot.is_some() {
            return Ok(());
        }

        let proposed = self
            .node
            .as_mut()
            .ok_or(ClusterError::NotReady)?
            .propose(Vec::new(), ReplicatedCommand::AdvanceMinimumSlot(desired).encode());
        match proposed {
            Ok(()) => self.pending_minimum_slot = Some(desired),
            // Leadership is moving or the log is full; the next spin retries.
            Err(raft::Error::ProposalDropped) => {
                silver_log::debug!(desired, "minimum slot proposal dropped");
            }
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }

    fn process_ready(
        &mut self,
        now: Instant,
        emit: &mut impl FnMut(ClusterEvent),
    ) -> Result<(), ClusterError> {
        let node = self.node.as_mut().ok_or(ClusterError::NotReady)?;
        self.metrics.observe_role(node);
        let mut ready = node.ready();
        self.pending_proposals.appended(
            ready.entries(),
            self.config.node_id,
            self.incarnation,
            now,
        );

        let snapshot = if ready.snapshot().is_empty() {
            None
        } else {
            let restored = RestoredSnapshot::decode(ready.snapshot(), &self.config.voters)
                .map_err(ClusterError::Snapshot)?;
            if restored.locks.minimum_slot() < self.state.minimum_slot() {
                return Err(ClusterError::Snapshot(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "snapshot retention floor regressed",
                )));
            }
            ClusterCounters::SnapshotsRestored.inc();
            Some(restored)
        };
        self.persistence.submit(&mut ready, snapshot).map_err(ClusterError::Storage)?;
        self.persistence_started = Some(now);
        if !ready.snapshot().is_empty() {
            node.mut_store().install_snapshot(ready.snapshot().clone())?;
        }
        {
            let mut storage = node.mut_store().memory.wl();
            storage.append(ready.entries())?;
            if let Some(hard_state) = ready.hs() {
                storage.set_hardstate(hard_state.clone());
            }
        }

        for message in ready.take_messages() {
            self.snapshot_transfers.sent(&message, now);
            self.peers.sent(&message, now);
            emit(ClusterEvent::SendRaftMessage(message));
        }
        // Release Ready immediately so step/propose/tick remain legal during disk I/O.
        // Durability is acknowledged separately through on_persist_ready.
        node.advance_append_async(ready);
        Ok(())
    }

    fn poll_persistence(
        &mut self,
        now: Instant,
        wall_slot: u64,
        emit: &mut impl FnMut(ClusterEvent),
    ) -> Result<(), ClusterError> {
        match self.persistence.poll().map_err(ClusterError::Storage)? {
            #[cfg(target_os = "linux")]
            Some(PersistenceEvent::Recovered(recovered)) => self.recover(recovered, now),
            Some(PersistenceEvent::Persisted(ready)) => {
                if let Some(started) = self.persistence_started.take() {
                    self.metrics.journal_written(now.saturating_duration_since(started));
                }
                self.pending_proposals.persisted(now);
                self.complete_ready(ready, now, wall_slot, emit)
            }
            Some(PersistenceEvent::Compacted(snapshot)) => {
                let index = snapshot.get_metadata().index;
                self.node.as_mut().ok_or(ClusterError::NotReady)?.mut_store().compact(snapshot)?;
                if let Some(started) = self.persistence_started.take() {
                    self.metrics.compacted(now.saturating_duration_since(started));
                }
                silver_log::debug!(
                    node_id = self.config.node_id,
                    index,
                    "attestation Raft journal compacted"
                );
                Ok(())
            }
            None => Ok(()),
        }
    }

    #[cfg(any(target_os = "linux", test))]
    fn recover(&mut self, recovered: RecoveredStorage, now: Instant) -> Result<(), ClusterError> {
        if self.node.is_some() {
            return Err(ClusterError::InvalidConfig("Raft already recovered"));
        }
        let mut storage = RaftStorage::new(&self.config.voters);
        if !recovered.snapshot.is_empty() {
            self.state = RestoredSnapshot::decode(&recovered.snapshot, &self.config.voters)
                .map_err(ClusterError::Snapshot)?
                .locks;
            storage.install_snapshot(recovered.snapshot)?;
        }
        storage.memory.wl().append(&recovered.entries)?;
        let commit = recovered.hard_state.commit;
        storage.memory.wl().set_hardstate(recovered.hard_state);
        self.apply_entries(
            recovered.entries.into_iter().take_while(|entry| entry.index <= commit),
            now,
            0,
            &mut |_| {},
        )?;
        let mut config = self.config.raft_config();
        config.applied = commit;
        self.node = Some(RawNode::with_default_logger(&config, storage)?);
        self.next_tick = now.checked_add(self.config.tick_interval).unwrap_or(now);
        silver_log::info!(
            node_id = self.config.node_id,
            commit,
            "attestation Raft storage recovered"
        );
        Ok(())
    }

    fn complete_ready(
        &mut self,
        ready: PersistedReady,
        now: Instant,
        wall_slot: u64,
        emit: &mut impl FnMut(ClusterEvent),
    ) -> Result<(), ClusterError> {
        let node = self.node.as_mut().ok_or(ClusterError::NotReady)?;
        node.on_persist_ready(ready.number);
        let snapshot_index = ready.snapshot.as_ref().map(|snapshot| snapshot.index);
        if let Some(snapshot) = ready.snapshot {
            self.state = snapshot.locks;
            self.pending_minimum_slot = None;
        }
        for message in ready.messages {
            self.snapshot_transfers.sent(&message, now);
            self.peers.sent(&message, now);
            emit(ClusterEvent::SendRaftMessage(message));
        }
        let applied = ready.committed_entries.last().map(|entry| entry.index).or(snapshot_index);
        self.apply_entries(ready.committed_entries, now, wall_slot, emit)?;
        if let Some(applied) = applied {
            self.node.as_mut().ok_or(ClusterError::NotReady)?.advance_apply_to(applied);
        }
        Ok(())
    }

    fn apply_entries(
        &mut self,
        entries: impl IntoIterator<Item = Entry>,
        now: Instant,
        wall_slot: u64,
        emit: &mut impl FnMut(ClusterEvent),
    ) -> Result<(), ClusterError> {
        for entry in entries {
            if entry.data.is_empty() {
                continue;
            }
            let decoded = DecodedEntry::decode(&entry).map_err(|cause| ClusterError::BadEntry {
                index: entry.index,
                term: entry.term,
                cause,
            })?;

            match decoded {
                DecodedEntry::Lock(command, proposal_id) => {
                    let result = self.state.apply(&command);
                    if self.resolve_own_commit(proposal_id, result, now) {
                        emit(ClusterEvent::AttestationCommitted(AttestationDecision {
                            proposal_id,
                            command,
                            result,
                            admission: self.admission.validate(command.key.slot, wall_slot),
                        }));
                    }
                }
                DecodedEntry::BlockLock(command, proposal_id) => {
                    let result = self.state.apply_block(&command);
                    if self.resolve_own_commit(proposal_id, result, now) {
                        emit(ClusterEvent::BlockCommitted(BlockDecision {
                            proposal_id,
                            key: command.key,
                            result,
                            admission: self.admission.validate(command.key.slot, wall_slot),
                        }));
                    }
                }
                DecodedEntry::AdvanceMinimumSlot(minimum_slot) => {
                    self.state.advance_minimum_slot(minimum_slot);
                    if self.pending_minimum_slot.is_some_and(|pending| pending <= minimum_slot) {
                        self.pending_minimum_slot = None;
                    }
                }
            }
        }

        Ok(())
    }

    /// Whether this process proposed the entry, so its decision is reported.
    /// A proposal that already timed out is still reported: its lock is held,
    /// so the signed message can still be published.
    fn resolve_own_commit(&mut self, id: ProposalId, result: LockResult, now: Instant) -> bool {
        if id.origin_node_id != self.config.node_id || id.incarnation != self.incarnation {
            return false;
        }
        match self.pending_proposals.take(id) {
            Some(pending) => {
                self.metrics.committed(
                    now.saturating_duration_since(pending.submitted),
                    pending.leader_origin,
                );
                self.resolved.push(pending.resolve(now, result.outcome()));
            }
            None => ClusterCounters::ProposalsCommittedLate.inc(),
        }
        true
    }

    fn expire_proposals(&mut self, now: Instant, emit: &mut impl FnMut(ClusterEvent)) {
        while let Some(proposal) = self.pending_proposals.pop_expired(now) {
            ClusterCounters::ProposalsTimedOut.inc();
            self.resolved.push(proposal.resolve(now, ClusterOutcome::TimedOut));
            emit(ClusterEvent::ProposalTimedOut(proposal.id));
        }
    }
}

#[cfg(test)]
#[path = "node/persistence_tests.rs"]
mod persistence_tests;

#[cfg(test)]
#[path = "node/snapshot_tests.rs"]
mod snapshot_tests;

#[cfg(test)]
mod tests {
    use raft::eraftpb::EntryType;
    use silver_common::SLOTS_PER_EPOCH;

    use super::*;
    use crate::cluster::{
        AttestationKey, BlockKey, BlockLockCommand, LockResult, StorageIdentity,
        command::CommandDecodeError,
    };

    fn command(slot: u64, root: u8) -> AttestationLockCommand {
        let mut ssz = [0; silver_common::ssz_view::SINGLE_ATT_SIZE];
        ssz[32] = root;
        ssz[104..112].copy_from_slice(&(slot / SLOTS_PER_EPOCH).to_le_bytes());
        AttestationLockCommand {
            key: AttestationKey { attester_index: 9, slot },
            subnet: u64::from(root) % silver_common::ATTESTATION_SUBNETS as u64,
            ssz,
        }
    }

    fn test_config(node_id: u64, voters: Vec<u64>) -> SlashingProtectionConfig {
        let mut config = SlashingProtectionConfig::new(
            node_id,
            voters,
            ClusterStorageConfig::Create("unused-test-journal".into()),
        )
        .unwrap();
        config.tick_interval = Duration::from_millis(1);
        config.heartbeat_ticks = 1;
        config.election_ticks = 5;
        config
    }

    fn initialized_cluster(
        config: SlashingProtectionConfig,
        startup_wall_slot: u64,
        now: Instant,
    ) -> SlashingProtectionCluster {
        let mut cluster = SlashingProtectionCluster::in_memory(config, now).unwrap();
        assert!(cluster.set_startup_wall_slot(startup_wall_slot));
        cluster
    }

    fn pump(
        clusters: &mut [SlashingProtectionCluster],
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
                    ClusterEvent::BlockCommitted(decision) => {
                        panic!("unexpected block decision {decision:?}");
                    }
                    ClusterEvent::ProposalTimedOut(proposal_id) => {
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
                .step(message, now, wall_slot)
                .unwrap();
        }
    }

    fn propose_message(from: u64, entries: Vec<Entry>) -> Message {
        Message {
            msg_type: MessageType::MsgPropose,
            from,
            to: 1,
            entries: entries.into(),
            ..Message::default()
        }
    }

    fn forwarded(command: ReplicatedCommand, origin_node_id: u64) -> Entry {
        let id = ProposalId { origin_node_id, sequence: 0, incarnation: [0; 16] };
        Entry { data: command.encode().into(), context: id.encode().into(), ..Entry::default() }
    }

    /// Each proposal either panicked raft-rs on the leader or committed an
    /// entry every node then fails to apply. All are refused at the boundary
    /// and the node keeps serving.
    #[test]
    fn malformed_member_messages_are_refused_before_raft() {
        let now = Instant::now();
        let mut cluster = initialized_cluster(test_config(1, vec![1]), 9, now);
        cluster.campaign().unwrap();
        cluster.spin(now, 10, |_| {}).unwrap();
        assert!(cluster.is_leader());
        let lock = ReplicatedCommand::Lock(command(10, 1));
        let mut conf_change = forwarded(lock, 2);
        conf_change.set_entry_type(EntryType::EntryConfChange);
        let refused = [
            (propose_message(2, vec![]), MemberMessageError::EmptyProposal),
            (
                propose_message(2, vec![conf_change]),
                MemberMessageError::Entry(EntryError::UnsupportedType(EntryType::EntryConfChange)),
            ),
            (
                propose_message(2, vec![forwarded(
                    ReplicatedCommand::AdvanceMinimumSlot(u64::MAX),
                    2,
                )]),
                MemberMessageError::ForwardedMinimumSlot,
            ),
            (propose_message(2, vec![forwarded(lock, 3)]), MemberMessageError::ProposalOrigin {
                origin: 3,
                from: 2,
            }),
            (
                propose_message(2, vec![forwarded(ReplicatedCommand::Lock(command(12, 1)), 2)]),
                MemberMessageError::ProposalAheadOfClock { slot: 12, wall_slot: 10 },
            ),
        ];
        for (message, expected) in refused {
            let result = cluster.step(message, now, 10);
            assert!(
                matches!(result, Err(ClusterError::MemberMessage(error)) if error == expected),
                "expected {expected:?}, got {result:?}"
            );
        }
        cluster.step(propose_message(2, vec![forwarded(lock, 2)]), now, 10).unwrap();
        cluster.spin(now, 10, |_| {}).unwrap();
        assert!(!cluster.is_failed());
    }

    /// Locks past the snapshot limit keep committing; compaction is skipped
    /// and not retried until another snapshot interval has applied.
    #[test]
    fn oversized_lock_state_skips_compaction_without_failing() {
        let now = Instant::now();
        let mut config = test_config(1, vec![1]);
        config.snapshot_interval = 2;
        let mut cluster = initialized_cluster(config, 9, now);
        cluster.campaign().unwrap();
        cluster.spin(now, 10, |_| {}).unwrap();
        cluster.state = SlashingLockStore::oversized();

        cluster.propose_attestation(command(10, 1), 10, now).unwrap();
        let mut committed = 0;
        cluster
            .spin(now, 10, |event| {
                if let ClusterEvent::AttestationCommitted(decision) = event {
                    assert_eq!(decision.result, LockResult::Accepted);
                    committed += 1;
                }
            })
            .unwrap();

        assert_eq!(committed, 1);
        assert!(!cluster.is_failed());
        let node = cluster.node.as_ref().unwrap();
        assert_eq!(node.store().snapshot_index(), 0, "no snapshot was cut");
        assert_eq!(cluster.compaction_retry_at, node.raft.raft_log.applied + 2);
    }

    #[test]
    fn more_than_seven_voters_are_rejected() {
        let storage = || ClusterStorageConfig::Create("unused-test-journal".into());
        assert!(matches!(
            SlashingProtectionConfig::new(1, 1..=8, storage()),
            Err(ClusterError::InvalidConfig(_))
        ));
        assert!(SlashingProtectionConfig::new(1, 1..=7, storage()).is_ok());
        assert_eq!(StorageIdentity::new(1, 1..=8).unwrap_err().kind(), io::ErrorKind::InvalidInput);
    }

    /// A committed entry this binary cannot apply names its position, so the
    /// failure on every replay can be traced to one entry.
    #[test]
    fn unappliable_committed_entry_reports_its_index_and_term() {
        let now = Instant::now();
        let mut cluster = initialized_cluster(test_config(1, vec![1]), 9, now);
        cluster.campaign().unwrap();
        cluster.spin(now, 10, |_| {}).unwrap();
        let node = cluster.node.as_mut().unwrap();
        let index = node.raft.raft_log.last_index() + 1;
        let term = node.raft.term;
        node.propose(Vec::new(), vec![9]).unwrap();

        let error = cluster.spin(now, 10, |_| {}).unwrap_err();
        assert!(
            matches!(error, ClusterError::BadEntry {
                index: i,
                term: t,
                cause: EntryError::Command(CommandDecodeError::UnknownTag(9)),
            } if i == index && t == term),
            "{error:?}"
        );
        assert_eq!(error.failure_kind(), FailureKind::BadEntry);
        assert!(error.to_string().contains(&format!("entry {index} (term {term})")));
        assert!(cluster.is_failed());
    }

    /// One round of a network where node 1's clock is far ahead, and
    /// `crashed` neither spins nor receives.
    fn skewed_round(clusters: &mut [SlashingProtectionCluster], now: Instant, crashed: u64) {
        let wall_slot = |node_id: u64| if node_id == 1 { 1_000 } else { 10 };
        let mut messages = Vec::new();
        for cluster in clusters.iter_mut().filter(|cluster| cluster.node_id() != crashed) {
            cluster
                .spin(now, wall_slot(cluster.node_id()), |event| {
                    if let ClusterEvent::SendRaftMessage(message) = event {
                        messages.push(message);
                    }
                })
                .unwrap();
        }
        for message in messages.into_iter().filter(|message| message.to != crashed) {
            let target = clusters.iter_mut().find(|c| c.node_id() == message.to).unwrap();
            let wall_slot = wall_slot(target.node_id());
            match target.step(message, now, wall_slot) {
                Ok(()) |
                Err(ClusterError::MemberMessage(MemberMessageError::LeaderAheadOfClock {
                    ..
                })) => {}
                Err(error) => panic!("{error:?}"),
            }
        }
        assert!(clusters.iter().all(|cluster| cluster.minimum_slot() == 0));
    }

    #[test]
    fn followers_replace_a_leader_whose_clock_jumped_forward() {
        let mut now = Instant::now();
        let voters = vec![1, 2, 3, 4, 5];
        let mut clusters: Vec<_> = voters
            .iter()
            .map(|node_id| initialized_cluster(test_config(*node_id, voters.clone()), 9, now))
            .collect();
        clusters[0].campaign().unwrap();
        let mut decisions = Vec::new();
        for _ in 0..10 {
            pump(&mut clusters, now, 10, &mut decisions);
        }
        assert!(clusters[0].is_leader());

        let healthy_leader = |clusters: &[SlashingProtectionCluster], crashed: u64| {
            clusters[1..]
                .iter()
                .find(|cluster| cluster.is_leader() && cluster.node_id() != crashed)
                .map(SlashingProtectionCluster::node_id)
        };
        let mut replacement = None;
        for _ in 0..500 {
            now += Duration::from_millis(1);
            skewed_round(&mut clusters, now, 0);
            replacement = healthy_leader(&clusters, 0).filter(|_| !clusters[0].is_leader());
            if replacement.is_some() {
                break;
            }
        }
        let crashed = replacement.expect("a follower with a correct clock takes over");
        assert!(clusters[1..].iter().all(|cluster| cluster.leader_boycott.boycotts(1, 10)));

        let mut reelected = None;
        for _ in 0..2_000 {
            now += Duration::from_millis(1);
            skewed_round(&mut clusters, now, crashed);
            assert!(!clusters[0].is_leader(), "the skewed node led again");
            reelected = reelected.or(healthy_leader(&clusters, crashed));
        }
        assert!(reelected.is_some(), "another follower with a correct clock takes over");
        assert!(
            !clusters[1].leader_boycott.boycotts(1, 1_000),
            "the boycott ends once the clock catches up"
        );
    }

    /// raft-rs drops proposals while leadership is being transferred; the
    /// floor proposal is retried instead of failing the cluster.
    #[test]
    fn dropped_minimum_slot_proposal_is_retried() {
        let now = Instant::now();
        let voters = vec![1, 2, 3];
        let mut clusters: Vec<_> = voters
            .iter()
            .map(|node_id| initialized_cluster(test_config(*node_id, voters.clone()), 9, now))
            .collect();
        clusters[0].campaign().unwrap();
        let mut decisions = Vec::new();
        for _ in 0..10 {
            pump(&mut clusters, now, 9, &mut decisions);
        }
        assert!(clusters[0].is_leader());

        clusters[0].node.as_mut().unwrap().transfer_leader(2);
        clusters[0].spin(now, 9 + 2 * SLOTS_PER_EPOCH, |_| {}).unwrap();

        assert!(!clusters[0].is_failed());
        assert_eq!(clusters[0].pending_minimum_slot, None, "retried on a later spin");
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
                ClusterEvent::SendRaftMessage(_) |
                ClusterEvent::BlockCommitted(_) |
                ClusterEvent::ProposalTimedOut(_) => None,
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
    fn proposal_times_out_at_its_deadline_and_its_late_commit_is_reported() {
        let now = Instant::now();
        let mut cluster = initialized_cluster(test_config(1, vec![1]), 9, now);
        cluster.campaign().unwrap();

        let proposal_id = cluster.propose_attestation(command(10, 1), 10, now).unwrap();
        assert_eq!(cluster.pending_proposals(), 1);

        let mut committed = Vec::new();
        let mut timed_out = Vec::new();
        cluster
            .spin(now + DEFAULT_PROPOSAL_TIMEOUT, 10, |event| match event {
                ClusterEvent::AttestationCommitted(decision) => committed.push(decision),
                ClusterEvent::ProposalTimedOut(proposal_id) => {
                    timed_out.push(proposal_id);
                }
                ClusterEvent::SendRaftMessage(_) | ClusterEvent::BlockCommitted(_) => {}
            })
            .unwrap();

        assert_eq!(timed_out, [proposal_id]);
        assert!(matches!(&committed[..], [decision]
            if decision.proposal_id == proposal_id && decision.result == LockResult::Accepted));
        assert_eq!(cluster.pending_proposals(), 0);
        assert_eq!(cluster.state().len(), 1);
        assert_eq!(cluster.state.apply(&command(10, 2)), LockResult::Conflicting);
    }

    #[test]
    fn same_block_is_idempotent_and_different_block_conflicts_through_raft() {
        let now = Instant::now();
        let mut cluster = initialized_cluster(test_config(1, vec![1]), 9, now);
        cluster.campaign().unwrap();

        let mut results = Vec::new();
        for (proposer_index, signature) in [(4, 1), (4, 1), (4, 2), (5, 2)] {
            let key = BlockKey { proposer_index, slot: 10 };
            let command = BlockLockCommand { key, signature: [signature; 96] };
            let proposal_id = cluster.propose_block(command, 10, now).unwrap();
            cluster
                .spin(now, 10, |event| {
                    if let ClusterEvent::BlockCommitted(decision) = event {
                        assert_eq!(decision.proposal_id, proposal_id);
                        assert_eq!(decision.key, key);
                        results.push(decision.result);
                    }
                })
                .unwrap();
        }

        assert_eq!(results, [
            LockResult::Accepted,
            LockResult::AlreadyAcceptedSame,
            LockResult::Conflicting,
            LockResult::Accepted,
        ]);
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
            LockResult::Conflicting,
        ]);
    }

    #[test]
    fn proposal_checks_local_admission_before_raft() {
        let now = Instant::now();
        let mut cluster =
            SlashingProtectionCluster::in_memory(test_config(1, vec![1]), now).unwrap();
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

        assert_eq!(cluster.state().minimum_slot(), 64 - SLOTS_PER_EPOCH);
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
            .spin(now, 2 + SLOTS_PER_EPOCH, |event| {
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

    #[test]
    fn follower_commit_resolves_with_every_stage_and_leader_measures_raft_rtt() {
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
        clusters[1]
            .propose_block(
                BlockLockCommand {
                    key: BlockKey { proposer_index: 4, slot: 10 },
                    signature: [1; 96],
                },
                10,
                now,
            )
            .unwrap();
        for _ in 0..20 {
            pump_blocks(&mut clusters, now);
            now += Duration::from_millis(1);
        }

        let resolved: Vec<_> = clusters[1].drain_resolved().collect();
        assert_eq!(resolved.len(), 1);
        let resolved = resolved[0];
        assert_eq!(resolved.slot, 10);
        assert_eq!(resolved.duty, ClusterDuty::Block);
        assert!(!resolved.leader_origin);
        assert_eq!(resolved.outcome, ClusterOutcome::Accepted);
        assert!(resolved.appended.is_some_and(|appended| appended >= resolved.submitted));
        assert!(resolved.persisted >= resolved.appended);
        assert!(resolved.resolved >= resolved.persisted.unwrap());
        assert!(clusters[1].drain_resolved().next().is_none());

        let leader_view: Vec<_> = clusters[0].peer_stats(now).collect();
        assert_eq!(leader_view.len(), 2);
        assert!(leader_view.iter().all(|peer| peer.raft_rtt.is_some() && peer.messages_out > 0));
        assert!(clusters[1].peer_stats(now).all(|peer| peer.raft_rtt.is_none()));
    }

    #[test]
    fn expired_proposal_resolves_as_timed_out() {
        let now = Instant::now();
        let mut cluster = initialized_cluster(test_config(1, vec![1]), 9, now);
        cluster.campaign().unwrap();
        cluster.propose_attestation(command(10, 1), 10, now).unwrap();
        cluster.spin(now + DEFAULT_PROPOSAL_TIMEOUT, 10, |_| {}).unwrap();

        let resolved: Vec<_> = cluster.drain_resolved().collect();
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].outcome, ClusterOutcome::TimedOut);
        assert_eq!(resolved[0].duty, ClusterDuty::Attestation);
    }

    /// As `pump`, for block decisions.
    fn pump_blocks(clusters: &mut [SlashingProtectionCluster], now: Instant) {
        let mut messages = Vec::new();
        for cluster in clusters.iter_mut() {
            cluster
                .spin(now, 10, |event| {
                    if let ClusterEvent::SendRaftMessage(message) = event {
                        messages.push(message);
                    }
                })
                .unwrap();
        }
        for message in messages {
            clusters
                .iter_mut()
                .find(|cluster| cluster.node_id() == message.to)
                .expect("Raft message target is a voter")
                .step(message, now, 10)
                .unwrap();
        }
    }

    #[test]
    fn proposal_burst_sends_few_messages_per_peer() {
        const BURST: u64 = 1000;
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

        for (proposer, attester_index) in (0..BURST).map(|i| (i as usize % 3, i)) {
            let mut command = command(10, 4);
            command.key.attester_index = attester_index;
            clusters[proposer].propose_attestation(command, 10, now).unwrap();
        }

        for _ in 0..20 {
            let mut messages = Vec::new();
            for cluster in &mut clusters {
                let node_id = cluster.node_id();
                cluster
                    .spin(now, 10, |event| match event {
                        ClusterEvent::SendRaftMessage(message) => messages.push(message),
                        ClusterEvent::AttestationCommitted(decision) => {
                            decisions.push((node_id, decision));
                        }
                        other => panic!("unexpected event {other:?}"),
                    })
                    .unwrap();
            }
            for from in &voters {
                for to in &voters {
                    let sent = messages.iter().filter(|m| m.from == *from && m.to == *to).count();
                    assert!(sent <= 2, "{from} sent {sent} messages to {to} in one spin");
                }
            }
            for message in messages {
                clusters
                    .iter_mut()
                    .find(|c| c.node_id() == message.to)
                    .unwrap()
                    .step(message, now, 10)
                    .unwrap();
            }
            now += Duration::from_millis(1);
        }

        assert_eq!(decisions.len() as u64, BURST);
        assert!(clusters.iter().all(|cluster| cluster.state().len() as u64 == BURST));
    }
}
