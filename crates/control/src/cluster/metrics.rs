use std::time::{Duration, Instant};

use flux::{Timer, timing::Nanos};
use raft::{RawNode, StateRole};
use silver_common::{ClusterCommit, ClusterDuty, ClusterOutcome, ticker::SlotTicker};

use super::{
    admission::AdmissionError,
    lock_store::LockResult,
    node::{AttestationDecision, BlockDecision},
    raft_storage::RaftStorage,
};

silver_common::declare_counters! {
    pub ClusterCounters => "cluster" {
        // 0 follower, 1 candidate or pre-candidate, 2 leader.
        Role,
        LeaderId,
        Term,
        CommitIndex,
        AppliedIndex,
        LastIndex,
        PendingProposals,
        Failed,
        FloorLatched,
        StartupFloorSlot,
        MinimumSlot,
        LockedVotes,
        BlockLocks,
        EvictedSources,
        SnapshotIndex,
        ProposalsSubmitted,
        ProposalsCommitted,
        ProposalsTimedOut,
        ProposalBatchesDropped,
        AttestationLockAccepted,
        AttestationLockSame,
        AttestationLockConflicting,
        AttestationLockSurrounding,
        AttestationLockTooOld,
        AttestationLockInvalid,
        BlockLockAccepted,
        BlockLockSame,
        BlockLockConflicting,
        BlockLockTooOld,
        AdmissionFuture,
        AdmissionTooOld,
        AdmissionBeforeFloor,
        AdmissionFloorUnset,
        LeaderChanges,
        SnapshotsSent,
        SnapshotsRestored,
        SnapshotTransferTimeouts,
        Compactions,
        InboundInvalid,
        MessagesIn,
        MessagesOut,
        // Longest gap between two Control loop passes in the last second.
        LoopGapMaxUs,
        // Journal bytes appended since the last compaction.
        JournalBytes,
        // 1 when this run has a cluster configured; set at every start.
        Clustered,
    }
}

impl LockResult {
    pub(crate) fn count_attestation(self) {
        match self {
            Self::Accepted => ClusterCounters::AttestationLockAccepted,
            Self::AlreadyAcceptedSame => ClusterCounters::AttestationLockSame,
            Self::Conflicting => ClusterCounters::AttestationLockConflicting,
            Self::Surrounding => ClusterCounters::AttestationLockSurrounding,
            Self::TooOld => ClusterCounters::AttestationLockTooOld,
            Self::Invalid => ClusterCounters::AttestationLockInvalid,
        }
        .inc();
    }

    pub(crate) fn count_block(self) {
        match self {
            Self::Accepted => ClusterCounters::BlockLockAccepted,
            Self::AlreadyAcceptedSame => ClusterCounters::BlockLockSame,
            Self::Conflicting => ClusterCounters::BlockLockConflicting,
            Self::TooOld => ClusterCounters::BlockLockTooOld,
            Self::Surrounding | Self::Invalid => unreachable!("block locks are keyed by slot"),
        }
        .inc();
    }

    pub(super) fn outcome(self) -> ClusterOutcome {
        match self {
            Self::Accepted => ClusterOutcome::Accepted,
            Self::AlreadyAcceptedSame => ClusterOutcome::Same,
            Self::Conflicting => ClusterOutcome::Conflicting,
            Self::Surrounding => ClusterOutcome::Surrounding,
            Self::TooOld => ClusterOutcome::TooOld,
            Self::Invalid => ClusterOutcome::Invalid,
        }
    }
}

impl AdmissionError {
    pub(crate) fn count(self) {
        match self {
            Self::StartupFloorUnset => ClusterCounters::AdmissionFloorUnset,
            Self::BeforeStartupFloor { .. } => ClusterCounters::AdmissionBeforeFloor,
            Self::TooOld { .. } => ClusterCounters::AdmissionTooOld,
            Self::Future { .. } => ClusterCounters::AdmissionFuture,
        }
        .inc();
    }
}

impl AttestationDecision {
    pub(crate) fn count(&self) {
        self.result.count_attestation();
        if let Err(admission) = self.admission {
            admission.count();
        }
    }
}

impl BlockDecision {
    pub(crate) fn count(&self) {
        self.result.count_block();
        if let Err(admission) = self.admission {
            admission.count();
        }
    }
}

/// A locally proposed lock from proposal to commit or timeout.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ResolvedProposal {
    pub(super) slot: u64,
    pub(super) duty: ClusterDuty,
    pub(super) leader_origin: bool,
    pub(super) submitted: Instant,
    pub(super) appended: Option<Instant>,
    pub(super) persisted: Option<Instant>,
    pub(super) resolved: Instant,
    pub(super) outcome: ClusterOutcome,
}

impl ResolvedProposal {
    pub(crate) fn commit_record(&self, ticker: &SlotTicker) -> ClusterCommit {
        let (current, current_start) = ticker.current_slot_start();
        let slot_ms = ticker.slot_duration().as_millis() as u64;
        let slot_start = if self.slot <= current {
            current_start.checked_sub(Duration::from_millis((current - self.slot) * slot_ms))
        } else {
            current_start.checked_add(Duration::from_millis((self.slot - current) * slot_ms))
        };
        let since =
            |from: Instant, to: Option<Instant>| to.map(|to| to.saturating_duration_since(from));
        let quorum =
            self.persisted.map(|persisted| self.resolved.saturating_duration_since(persisted));
        ClusterCommit {
            slot: self.slot,
            slot_offset: slot_start
                .map_or(Duration::ZERO, |start| self.resolved.saturating_duration_since(start)),
            total: self.resolved.saturating_duration_since(self.submitted),
            append: since(self.submitted, self.appended),
            persist: self.appended.and_then(|appended| since(appended, self.persisted)),
            quorum: quorum.filter(|_| self.outcome != ClusterOutcome::TimedOut),
            duty: self.duty,
            leader_origin: self.leader_origin,
            outcome: self.outcome,
        }
    }
}

#[derive(Default)]
pub(crate) struct LoopGap {
    last: Option<Instant>,
    max: Duration,
}

impl LoopGap {
    pub(crate) fn observe(&mut self, now: Instant) {
        if let Some(last) = self.last.replace(now) {
            self.max = self.max.max(now.saturating_duration_since(last));
        }
    }

    pub(crate) fn publish(&mut self) {
        ClusterCounters::LoopGapMaxUs.set(self.max.as_micros() as u64);
        self.max = Duration::ZERO;
    }
}

pub(crate) struct DutyTimers {
    attestation: Timer,
    block: Timer,
}

impl DutyTimers {
    pub(crate) fn new() -> Self {
        Self {
            attestation: Timer::new("silver", "cluster_duty_attestation"),
            block: Timer::new("silver", "cluster_duty_block"),
        }
    }

    pub(crate) fn released(&mut self, duty: ClusterDuty, received: Instant, now: Instant) {
        let timer = match duty {
            ClusterDuty::Attestation => &mut self.attestation,
            ClusterDuty::Block => &mut self.block,
        };
        emit(timer, now.saturating_duration_since(received));
    }
}

fn emit(timer: &mut Timer, latency: Duration) {
    timer.emit_latency_from_nanos(Nanos(0), Nanos(latency.as_nanos() as u64));
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RaftRole {
    state: StateRole,
    leader_id: u64,
    term: u64,
}

impl RaftRole {
    fn of(node: &RawNode<RaftStorage>) -> Self {
        Self { state: node.raft.state, leader_id: node.raft.leader_id, term: node.raft.term }
    }

    fn gauge(self) -> u64 {
        match self.state {
            StateRole::Follower => 0,
            StateRole::Candidate | StateRole::PreCandidate => 1,
            StateRole::Leader => 2,
        }
    }
}

/// Commit latency is split by where the proposal entered Raft: a follower
/// pays an extra forward and round trip to the leader.
pub(super) struct ClusterMetrics {
    role: Option<RaftRole>,
    leader_commit: Timer,
    follower_commit: Timer,
    journal_write: Timer,
    compaction: Timer,
}

impl ClusterMetrics {
    pub(super) fn new() -> Self {
        // Counter files outlive the process; a previous run's state must not show.
        for gauge in [ClusterCounters::Role, ClusterCounters::LeaderId, ClusterCounters::Failed] {
            gauge.set(0);
        }
        Self {
            role: None,
            leader_commit: Timer::new("silver", "cluster_commit_leader"),
            follower_commit: Timer::new("silver", "cluster_commit_follower"),
            journal_write: Timer::new("silver", "cluster_journal_write"),
            compaction: Timer::new("silver", "cluster_compaction"),
        }
    }

    pub(super) fn committed(&mut self, latency: Duration, leader_origin: bool) {
        ClusterCounters::ProposalsCommitted.inc();
        let timer = if leader_origin { &mut self.leader_commit } else { &mut self.follower_commit };
        emit(timer, latency);
    }

    pub(super) fn journal_written(&mut self, latency: Duration) {
        emit(&mut self.journal_write, latency);
    }

    pub(super) fn compacted(&mut self, latency: Duration) {
        ClusterCounters::Compactions.inc();
        emit(&mut self.compaction, latency);
    }

    pub(super) fn observe_role(&mut self, node: &RawNode<RaftStorage>) {
        let role = RaftRole::of(node);
        let previous = self.role.replace(role);
        if previous == Some(role) {
            return;
        }

        if previous.is_some_and(|previous| previous.leader_id != role.leader_id) {
            ClusterCounters::LeaderChanges.inc();
        }
        ClusterCounters::Role.set(role.gauge());
        ClusterCounters::LeaderId.set(role.leader_id);
        ClusterCounters::Term.set(role.term);
        silver_log::info!(
            node_id = node.raft.id,
            role = ?role.state,
            leader_id = role.leader_id,
            term = role.term,
            "Raft role changed"
        );
    }

    pub(super) fn sample_log(&self, node: &RawNode<RaftStorage>, pending_proposals: usize) {
        let log = &node.raft.raft_log;
        ClusterCounters::CommitIndex.set(log.committed);
        ClusterCounters::AppliedIndex.set(log.applied);
        ClusterCounters::LastIndex.set(log.last_index());
        ClusterCounters::SnapshotIndex.set(node.store().snapshot_index());
        ClusterCounters::PendingProposals.set(pending_proposals as u64);
    }
}
