use std::time::Instant;

use flux::spine::{SpineAdapter, SpineProducers};
use flux_profiler::timed;
use fxhash::FxHashMap;
use silver_common::{
    BroadcastValidation, CLUSTER_STATS_INTERVAL, ClusterDuty, ClusterIn, ClusterMsgIn,
    ClusterMsgOut, GossipTopic, LocalGossipFailure, LocalGossipResult, LockedProposal, PeerStats,
    SilverSpine, SilverSpineProducers, TCacheProducer, TCacheReader, TProducer, TRead,
    block_contents::SignedBlockContents,
    ssz_view::{
        SIGNED_BEACON_BLOCK_MIN, SINGLE_ATT_SIZE, SignedBeaconBlockView, SingleAttestationView,
    },
    ticker::SlotTicker,
};
use silver_gossip::GossipHandler;

use super::local_gossip::{LocalGossipHandler, LocalMessage, produce_response};
use crate::cluster::{
    AdmissionError, AttestationDecision, AttestationKey, AttestationLockCommand, BlockDecision,
    BlockKey, BlockLockCommand, ClusterCounters, ClusterError, ClusterEvent, DutyTimers,
    LockResult, LoopGap, ProposalId, ProposeError, SlashingAdmission, SlashingLockStore,
    SlashingProtectionCluster, SlashingProtectionConfig, decode_message, encode_message,
};

/// A proposal still uncommitted this late was most likely lost with its
/// leader, and a block this late would be orphaned anyway.
const LATE_COMMIT_SLOTS: u64 = 2;

/// An API request waiting on its lock. It is answered at most once, but its
/// lock can still commit after a `LockPending` answer and be published late.
#[derive(Debug, Clone, Copy)]
struct PendingRequest {
    id: u64,
    received: Instant,
    answered: bool,
}

impl PendingRequest {
    fn new(id: u64, received: Instant) -> Self {
        Self { id, received, answered: false }
    }

    fn answer(&mut self, response: LocalGossipResult, producers: &mut SilverSpineProducers) {
        if !self.answered {
            produce_response(producers, self.id, response);
            self.answered = true;
        }
    }

    /// An unanswered request waits for its proposal's timeout instead, so
    /// an old but admitted slot still gets its answer.
    fn is_live(&self, slot: u64, wall_slot: u64) -> bool {
        !self.answered || slot.saturating_add(LATE_COMMIT_SLOTS) > wall_slot
    }

    fn release(
        &self,
        message: LocalMessage<'_>,
        now: Instant,
        local_gossip: &mut LocalGossipHandler,
        gossip_handler: &mut GossipHandler,
        producers: &mut SilverSpineProducers,
    ) {
        if self.answered {
            LocalGossipHandler::publish_unawaited(message, gossip_handler);
        } else {
            local_gossip.submit(message, now, gossip_handler, producers);
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) struct PendingAttestation {
    request: PendingRequest,
    command: AttestationLockCommand,
}

impl PendingAttestation {
    pub(super) fn new(
        request_id: u64,
        subnet: u64,
        ssz: [u8; SINGLE_ATT_SIZE],
        received: Instant,
    ) -> Self {
        let key = AttestationKey {
            attester_index: SingleAttestationView::attester_index(&ssz),
            slot: SingleAttestationView::slot(&ssz),
        };
        Self {
            request: PendingRequest::new(request_id, received),
            command: AttestationLockCommand { key, subnet, ssz },
        }
    }

    fn on_commit(
        mut self,
        decision: &AttestationDecision,
        now: Instant,
        duty_timers: &mut DutyTimers,
        local_gossip: &mut LocalGossipHandler,
        gossip_handler: &mut GossipHandler,
        producers: &mut SilverSpineProducers,
    ) {
        if decision.command != self.command {
            self.request.answer(Err(LocalGossipFailure::Internal), producers);
            silver_log::error!(
                ?decision.proposal_id,
                request_id = self.request.id,
                "committed Raft command does not match its pending attestation"
            );
            return;
        }
        let response = decision_response(
            decision.admission,
            decision.result,
            LocalGossipFailure::ConflictingAttestation,
        );
        if response.is_err() {
            self.request.answer(response, producers);
            silver_log::warn!(
                ?decision.result,
                ?decision.admission,
                request_id = self.request.id,
                slot = self.command.key.slot,
                "committed attestation cannot enter validation"
            );
            return;
        }
        duty_timers.released(ClusterDuty::Attestation, self.request.received, now);
        self.request.release(
            self.command.local_message(self.request.id),
            now,
            local_gossip,
            gossip_handler,
            producers,
        );
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SubmittedBlock {
    /// `SignedBlockContents`, published by this node.
    Full(BroadcastValidation),
    /// A Gloas `SignedBeaconBlock`, published by this node. Its blobs travel
    /// with the payload envelope.
    Gloas(BroadcastValidation),
    /// A `SignedBlindedBeaconBlock`; the API has the sidecar reveal it once
    /// told the lock is held.
    Blinded,
}

impl SubmittedBlock {
    /// A block to publish: `SignedBlockContents` lead with offset 12, a bare
    /// `SignedBeaconBlock` with offset 100.
    pub(super) fn framed(bytes: &[u8], validation: BroadcastValidation) -> Self {
        if SignedBeaconBlockView::check_size(bytes) {
            Self::Gloas(validation)
        } else {
            Self::Full(validation)
        }
    }

    fn signed_block(self, bytes: &[u8]) -> Option<&[u8]> {
        match self {
            Self::Full(_) => SignedBlockContents::signed_block(bytes),
            Self::Gloas(_) | Self::Blinded => Some(bytes),
        }
    }
}

/// A signed block waiting on its lock. Its submission stays pinned in the
/// submissions tcache until the lock commits or times out.
#[derive(Debug)]
pub(super) struct PendingBlock {
    request: PendingRequest,
    key: BlockKey,
    contents: TRead,
    block: SubmittedBlock,
}

impl PendingBlock {
    fn new(
        request_id: u64,
        key: BlockKey,
        contents: TRead,
        block: SubmittedBlock,
        received: Instant,
    ) -> Self {
        Self { request: PendingRequest::new(request_id, received), key, contents, block }
    }

    fn release_locked(
        mut self,
        now: Instant,
        duty_timers: &mut DutyTimers,
        local_gossip: &mut LocalGossipHandler,
        gossip_handler: &mut GossipHandler,
        producers: &mut SilverSpineProducers,
    ) {
        let slot = self.key.slot;
        let Some(block) =
            self.contents.buffer().ok().and_then(|(bytes, _)| self.block.signed_block(bytes))
        else {
            self.request.answer(Err(LocalGossipFailure::Internal), producers);
            silver_log::error!(
                request_id = self.request.id,
                slot,
                "submitted block overwritten before its lock committed"
            );
            return;
        };
        duty_timers.released(ClusterDuty::Block, self.request.received, now);
        let message = match self.block {
            SubmittedBlock::Full(validation) => {
                producers.produce(LockedProposal { contents: self.contents.to_read() });
                block_message(self.request.id, block, slot, validation)
            }
            SubmittedBlock::Gloas(validation) => LocalMessage {
                request_id: self.request.id,
                topic: GossipTopic::BeaconBlock,
                ssz: block,
                ssz_read: Some(self.contents.to_read()),
                slot,
                validation,
            },
            SubmittedBlock::Blinded => return self.request.answer(Ok(()), producers),
        };
        self.request.release(message, now, local_gossip, gossip_handler, producers);
    }

    fn on_commit(
        mut self,
        decision: &BlockDecision,
        now: Instant,
        duty_timers: &mut DutyTimers,
        local_gossip: &mut LocalGossipHandler,
        gossip_handler: &mut GossipHandler,
        producers: &mut SilverSpineProducers,
    ) {
        if decision.key != self.key {
            self.request.answer(Err(LocalGossipFailure::Internal), producers);
            silver_log::error!(
                ?decision.proposal_id,
                request_id = self.request.id,
                "committed Raft command does not match its pending block"
            );
            return;
        }
        let slot = self.key.slot;
        let response = decision_response(
            decision.admission,
            decision.result,
            LocalGossipFailure::ConflictingProposal,
        );
        if response.is_err() {
            self.request.answer(response, producers);
            silver_log::warn!(
                ?decision.result,
                ?decision.admission,
                request_id = self.request.id,
                slot,
                "committed block cannot enter validation"
            );
            return;
        }
        self.release_locked(now, duty_timers, local_gossip, gossip_handler, producers);
    }
}

/// Slashing protection for local attestations and blocks: admission and a
/// lock per validator and epoch or slot, agreed through Raft when clustered.
pub(super) struct SlashingProtectionHandler {
    /// Encoded Raft messages are reserved here before `ClusterMsgOut` is
    /// published to the network tile.
    outbound_producer: TProducer,
    cluster: Option<SlashingProtectionCluster>,
    local_locks: SlashingLockStore,
    admission: SlashingAdmission,
    pending_attestations: FxHashMap<ProposalId, PendingAttestation>,
    pending_blocks: FxHashMap<ProposalId, PendingBlock>,
    wall_slot: u64,
    clock: Option<SlotTicker>,
    duty_timers: DutyTimers,
    loop_gap: LoopGap,
    last_sample: Instant,
}

impl SlashingProtectionHandler {
    pub(super) fn loop_start(&mut self) {
        self.outbound_producer.loop_start();
    }

    pub(super) fn new(
        outbound_producer: TProducer,
        config: Option<SlashingProtectionConfig>,
        now: Instant,
    ) -> Result<Self, ClusterError> {
        let cluster =
            config.map(|config| SlashingProtectionCluster::new(config, now)).transpose()?;
        ClusterCounters::Clustered.set(cluster.is_some() as u64);
        ClusterCounters::FloorLatched.set(0);
        ClusterCounters::StartupFloorSlot.set(0);

        Ok(Self {
            outbound_producer,
            cluster,
            local_locks: SlashingLockStore::default(),
            admission: SlashingAdmission::new(),
            pending_attestations: FxHashMap::default(),
            pending_blocks: FxHashMap::default(),
            wall_slot: 0,
            clock: None,
            duty_timers: DutyTimers::new(),
            loop_gap: LoopGap::default(),
            last_sample: now,
        })
    }

    /// The wall slot is known from here on, before Beacon State's first
    /// Status: member messages are checked against it.
    pub(super) fn set_clock(&mut self, ticker: SlotTicker) {
        self.wall_slot = ticker.current_slot();
        self.clock = Some(ticker);
    }

    /// `synced` latches the startup floor. It comes from peer-relative sync
    /// state, so a missed slot cannot keep it from latching.
    pub(super) fn on_status(&mut self, wall_slot: u64, synced: bool) {
        if wall_slot != self.wall_slot {
            self.expire_answered(wall_slot);
        }
        self.wall_slot = wall_slot;
        if self.cluster.is_none() {
            self.local_locks.advance_minimum_slot(SlashingAdmission::age_floor(wall_slot));
        }
        if !synced || !self.admission.set_startup_wall_slot(wall_slot) {
            return;
        }

        if let Some(cluster) = self.cluster.as_mut() {
            let initialized = cluster.set_startup_wall_slot(wall_slot);
            debug_assert!(initialized, "handler and cluster startup floors latch together");
        }
        ClusterCounters::FloorLatched.set(1);
        ClusterCounters::StartupFloorSlot.set(wall_slot.saturating_add(1));
        silver_log::info!(wall_slot, "local slashing protection startup floor latched");
    }

    fn expire_answered(&mut self, wall_slot: u64) {
        self.pending_attestations.retain(|_, attestation| {
            attestation.request.is_live(attestation.command.key.slot, wall_slot)
        });
        self.pending_blocks.retain(|_, block| block.request.is_live(block.key.slot, wall_slot));
    }

    /// Consume inbound Raft messages and pump all work currently ready in the
    /// state machine. This is called once per Control tile loop and never
    /// waits for network or timer work.
    pub(super) fn spin(
        &mut self,
        now: Instant,
        adapter: &mut SpineAdapter<SilverSpine>,
        local_gossip: &mut LocalGossipHandler,
        gossip_handler: &mut GossipHandler,
        inbound_consumer: &mut TCacheReader,
    ) {
        self.loop_gap.observe(now);
        adapter.consume(|message: ClusterIn, _producers| match message {
            ClusterIn::Msg(message) => self.handle_message(message, inbound_consumer, now),
            ClusterIn::NodeUnreachable(id) => {
                if let Some(cluster) = self.cluster.as_mut() {
                    cluster.report_unreachable(id);
                }
            }
        });
        self.drive(now, local_gossip, gossip_handler, &mut adapter.producers);
        self.produce_commits(&mut adapter.producers);
        self.sample(now, &mut adapter.producers);
    }

    fn produce_commits(&mut self, producers: &mut SilverSpineProducers) {
        let Some(cluster) = self.cluster.as_mut() else {
            return;
        };
        for resolved in cluster.drain_resolved() {
            if let Some(clock) = &self.clock {
                producers.produce(resolved.commit_record(clock));
            }
        }
    }

    fn sample(&mut self, now: Instant, producers: &mut SilverSpineProducers) {
        if now.saturating_duration_since(self.last_sample) < CLUSTER_STATS_INTERVAL {
            return;
        }
        self.last_sample = now;
        self.loop_gap.publish();
        let Some(cluster) = &self.cluster else {
            return;
        };
        for stats in cluster.peer_stats(now) {
            producers.produce(PeerStats::Cluster(stats));
        }
    }

    pub(super) fn on_local_attestation(
        &mut self,
        attestation: PendingAttestation,
        now: Instant,
        local_gossip: &mut LocalGossipHandler,
        gossip_handler: &mut GossipHandler,
        producers: &mut SilverSpineProducers,
    ) {
        if let Err(error) = self.admission.validate(attestation.command.key.slot, self.wall_slot) {
            error.count();
            produce_response(producers, attestation.request.id, Err(admission_failure(error)));
            silver_log::warn!(
                ?error,
                request_id = attestation.request.id,
                slot = attestation.command.key.slot,
                "local attestation rejected before cluster proposal"
            );
            return;
        }

        let Some(cluster) = self.cluster.as_mut() else {
            let result = self.local_locks.apply(&attestation.command);
            result.count_attestation();
            let response = lock_response(result, LocalGossipFailure::ConflictingAttestation);
            if response.is_err() {
                produce_response(producers, attestation.request.id, response);
                silver_log::warn!(
                    ?result,
                    request_id = attestation.request.id,
                    slot = attestation.command.key.slot,
                    "local lock rejected attestation"
                );
                return;
            }
            self.duty_timers.released(ClusterDuty::Attestation, attestation.request.received, now);
            local_gossip.submit(
                attestation.command.local_message(attestation.request.id),
                now,
                gossip_handler,
                producers,
            );
            return;
        };

        match cluster.propose_attestation(attestation.command, self.wall_slot, now) {
            Ok(proposal_id) => {
                let previous = self.pending_attestations.insert(proposal_id, attestation);
                debug_assert!(previous.is_none(), "proposal IDs are unique per node");
            }
            Err(error) => {
                if let ProposeError::Admission(admission) = &error {
                    admission.count();
                }
                produce_response(producers, attestation.request.id, Err(proposal_failure(&error)));
                silver_log::warn!(
                    ?error,
                    request_id = attestation.request.id,
                    slot = attestation.command.key.slot,
                    "cluster rejected local attestation"
                );
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    #[timed]
    pub(super) fn on_local_block(
        &mut self,
        request_id: u64,
        contents: TRead,
        block: SubmittedBlock,
        now: Instant,
        local_gossip: &mut LocalGossipHandler,
        gossip_handler: &mut GossipHandler,
        producers: &mut SilverSpineProducers,
    ) {
        let Some(signed_block) = contents
            .buffer()
            .ok()
            .and_then(|(bytes, _)| block.signed_block(bytes))
            .filter(|signed_block| signed_block.len() >= SIGNED_BEACON_BLOCK_MIN)
        else {
            silver_log::error!(request_id, "submitted block is misframed");
            return produce_response(producers, request_id, Err(LocalGossipFailure::Internal));
        };
        let key = BlockKey {
            proposer_index: SignedBeaconBlockView::proposer_index(signed_block),
            slot: SignedBeaconBlockView::slot(signed_block),
        };
        let signature = *SignedBeaconBlockView::signature(signed_block);
        let command = BlockLockCommand { key, signature };
        if let Err(error) = self.admission.validate(key.slot, self.wall_slot) {
            error.count();
            produce_response(producers, request_id, Err(admission_failure(error)));
            silver_log::warn!(
                ?error,
                request_id,
                slot = key.slot,
                "local block rejected before its lock"
            );
            return;
        }

        let Some(cluster) = self.cluster.as_mut() else {
            let result = self.local_locks.apply_block(&command);
            result.count_block();
            if let Err(failure) = lock_response(result, LocalGossipFailure::ConflictingProposal) {
                produce_response(producers, request_id, Err(failure));
                silver_log::warn!(
                    ?result,
                    request_id,
                    slot = key.slot,
                    "local lock rejected block"
                );
                return;
            }
            return PendingBlock::new(request_id, key, contents, block, now).release_locked(
                now,
                &mut self.duty_timers,
                local_gossip,
                gossip_handler,
                producers,
            );
        };

        match cluster.propose_block(command, self.wall_slot, now) {
            Ok(proposal_id) => {
                let previous = self
                    .pending_blocks
                    .insert(proposal_id, PendingBlock::new(request_id, key, contents, block, now));
                debug_assert!(previous.is_none(), "proposal IDs are unique per node");
            }
            Err(error) => {
                if let ProposeError::Admission(admission) = &error {
                    admission.count();
                }
                produce_response(producers, request_id, Err(proposal_failure(&error)));
                silver_log::warn!(
                    ?error,
                    request_id,
                    slot = key.slot,
                    "cluster rejected local block"
                );
            }
        }
    }

    fn handle_message(
        &mut self,
        inbound: ClusterMsgIn,
        inbound_consumer: &mut TCacheReader,
        now: Instant,
    ) {
        ClusterCounters::MessagesIn.inc();
        let Some(acquired) = inbound_consumer.acquire_strict(inbound.data) else {
            silver_log::warn!(
                from = inbound.from,
                seq = inbound.data.seq(),
                "cluster inbound TCache read is no longer available"
            );
            return;
        };
        let Ok((bytes, _)) = acquired.buffer() else {
            silver_log::warn!(
                from = inbound.from,
                seq = inbound.data.seq(),
                "failed to read cluster inbound TCache message"
            );
            return;
        };

        let Some(cluster) = self.cluster.as_mut() else {
            silver_log::debug!(
                from = inbound.from,
                "ignoring cluster message while clustering is disabled"
            );
            return;
        };
        if !cluster.is_ready() {
            return;
        }
        let message = match decode_message(bytes) {
            Ok(message) => message,
            Err(error) => {
                ClusterCounters::InboundInvalid.inc();
                silver_log::warn!(?error, from = inbound.from, "invalid inbound Raft message");
                return;
            }
        };
        if message.from != inbound.from {
            ClusterCounters::InboundInvalid.inc();
            silver_log::warn!(
                authenticated_from = inbound.from,
                encoded_from = message.from,
                "inbound Raft message source does not match authenticated cluster peer"
            );
            return;
        }
        if message.to != cluster.node_id() {
            ClusterCounters::InboundInvalid.inc();
            silver_log::warn!(
                from = inbound.from,
                encoded_to = message.to,
                local_node = cluster.node_id(),
                "inbound Raft message addressed to another cluster node"
            );
            return;
        }
        if let Err(error) = cluster.step(message, now, self.wall_slot) {
            if let ClusterError::MemberMessage(_) = error {
                ClusterCounters::InboundInvalid.inc();
            }
            silver_log::warn!(?error, from = inbound.from, "failed to step inbound Raft message");
        }
    }

    fn drive(
        &mut self,
        now: Instant,
        local_gossip: &mut LocalGossipHandler,
        gossip_handler: &mut GossipHandler,
        producers: &mut SilverSpineProducers,
    ) {
        let Some(cluster) = self.cluster.as_mut() else {
            return;
        };

        let pending_attestations = &mut self.pending_attestations;
        let pending_blocks = &mut self.pending_blocks;
        let outbound_producer = &mut self.outbound_producer;
        let duty_timers = &mut self.duty_timers;
        let result = cluster.spin(now, self.wall_slot, |event| match event {
            ClusterEvent::SendRaftMessage(message) => {
                let to = message.to;
                match encode_message(message, outbound_producer) {
                    Ok(data) => {
                        ClusterCounters::MessagesOut.inc();
                        producers.cluster_outbound.produce(&ClusterMsgOut { to, data }.into());
                    }
                    Err(error) => {
                        silver_log::warn!(?error, to, "failed to buffer outbound Raft message")
                    }
                }
            }
            ClusterEvent::AttestationCommitted(decision) => {
                decision.count();
                if let Some(attestation) = pending_attestations.remove(&decision.proposal_id) {
                    attestation.on_commit(
                        &decision,
                        now,
                        duty_timers,
                        local_gossip,
                        gossip_handler,
                        producers,
                    );
                }
            }
            ClusterEvent::BlockCommitted(decision) => {
                decision.count();
                if let Some(block) = pending_blocks.remove(&decision.proposal_id) {
                    block.on_commit(
                        &decision,
                        now,
                        duty_timers,
                        local_gossip,
                        gossip_handler,
                        producers,
                    );
                }
            }
            ClusterEvent::ProposalTimedOut(proposal_id) => {
                if let Some(block) = pending_blocks.get_mut(&proposal_id) {
                    block.request.answer(Err(LocalGossipFailure::LockPending), producers);
                    silver_log::warn!(
                        ?proposal_id,
                        request_id = block.request.id,
                        slot = block.key.slot,
                        "block cluster proposal timed out"
                    );
                }
                if let Some(attestation) = pending_attestations.get_mut(&proposal_id) {
                    attestation.request.answer(Err(LocalGossipFailure::LockPending), producers);
                    silver_log::warn!(
                        ?proposal_id,
                        request_id = attestation.request.id,
                        slot = attestation.command.key.slot,
                        "attestation cluster proposal timed out"
                    );
                }
            }
        });
        if let Err(error) = result {
            silver_log::error!(
                %error,
                kind = ?error.failure_kind(),
                "slashing protection spin failed"
            );
            for (_, mut attestation) in self.pending_attestations.drain() {
                attestation.request.answer(Err(LocalGossipFailure::Internal), producers);
            }
            for (_, mut block) in self.pending_blocks.drain() {
                block.request.answer(Err(LocalGossipFailure::Internal), producers);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use silver_common::{
        SLOTS_PER_EPOCH, TCache, TCacheId, TCacheProducer, TCacheRead, TCacheTable, TReadMode,
    };

    use super::*;
    use crate::{
        cluster::{ClusterStorageConfig, test_address},
        tile::local_gossip::{VALIDATION_TIMEOUT, tests::Harness},
    };

    #[test]
    fn surround_and_double_vote_are_told_apart() {
        let conflict = LocalGossipFailure::ConflictingAttestation;
        assert_eq!(lock_response(LockResult::Conflicting, conflict), Err(conflict));
        assert_eq!(
            lock_response(LockResult::Surrounding, conflict),
            Err(LocalGossipFailure::SurroundVote)
        );
    }

    /// A signed block just long enough to carry its slot and proposer.
    fn block_bytes(slot: u64, proposer_index: u64, tag: u8) -> Vec<u8> {
        let mut block = vec![tag; SIGNED_BEACON_BLOCK_MIN];
        block[100..108].copy_from_slice(&slot.to_le_bytes());
        block[108..116].copy_from_slice(&proposer_index.to_le_bytes());
        block
    }

    /// Submissions as the API leaves them, and a reader over them.
    struct Submissions {
        producer: TProducer,
        reader: TCacheReader,
    }

    impl Submissions {
        fn new() -> Self {
            let producer = TCache::producer(TCacheId::BoundaryProcessing, 1 << 16);
            let mut reader = TCacheReader::new(TCacheTable::from_iter([producer.cache_ref()]));
            reader
                .open(TCacheId::BoundaryProcessing, "test_submissions", TReadMode::Sliding)
                .unwrap();
            Self { producer, reader }
        }

        fn publish(&mut self, bytes: &[u8]) -> TCacheRead {
            let read = self.producer.write_with(bytes.len(), |out| out.copy_from_slice(bytes));
            self.producer.loop_start();
            read.unwrap()
        }
    }

    fn submit_block(
        handler: &mut SlashingProtectionHandler,
        harness: &mut Harness,
        submissions: &mut Submissions,
        request_id: u64,
        block: &[u8],
        now: Instant,
    ) {
        let blobs_at = (12 + block.len()) as u32;
        let mut contents = [12, blobs_at, blobs_at].map(u32::to_le_bytes).concat();
        contents.extend_from_slice(block);
        lock_block(
            handler,
            harness,
            submissions,
            request_id,
            &contents,
            SubmittedBlock::Full(BroadcastValidation::Gossip),
            now,
        );
    }

    fn lock_block(
        handler: &mut SlashingProtectionHandler,
        harness: &mut Harness,
        submissions: &mut Submissions,
        request_id: u64,
        bytes: &[u8],
        block: SubmittedBlock,
        now: Instant,
    ) {
        let published = submissions.publish(bytes);
        let contents = submissions.reader.acquire(published);
        let Harness { local_gossip, gossip, adapter, .. } = harness;
        handler.on_local_block(
            request_id,
            contents,
            block,
            now,
            local_gossip,
            gossip,
            &mut adapter.producers,
        );
    }

    /// A blinded block shares a full block's envelope, so the same bytes stand
    /// in for one.
    fn reveal_block(
        handler: &mut SlashingProtectionHandler,
        harness: &mut Harness,
        submissions: &mut Submissions,
        request_id: u64,
        block: &[u8],
        now: Instant,
    ) {
        lock_block(handler, harness, submissions, request_id, block, SubmittedBlock::Blinded, now);
    }

    fn locked_proposals(harness: &mut Harness) -> usize {
        let mut locked = 0;
        harness.adapter.consume(|_: LockedProposal, _| locked += 1);
        locked
    }

    #[test]
    fn standalone_block_lock_admits_one_block_per_proposer_and_slot() {
        let now = Instant::now();
        let mut standalone = Standalone::new(now);
        let mut submissions = Submissions::new();
        standalone.handler.on_status(10, true);
        standalone.handler.on_status(11, true);
        let Standalone { handler, harness } = &mut standalone;
        assert_eq!(locked_proposals(harness), 0, "subscribes before anything is locked");

        submit_block(handler, harness, &mut submissions, 1, &block_bytes(11, 4, 1), now);
        let first = harness.pop_gossip();
        assert_eq!(locked_proposals(harness), 1, "the accepted contents follow");
        submit_block(handler, harness, &mut submissions, 2, &block_bytes(11, 4, 1), now);
        assert_eq!(harness.pop_gossip().msg_hash, first.msg_hash, "a resubmission rejoins");
        assert_eq!(locked_proposals(harness), 1, "and is accepted again");
        assert!(harness.responses().is_empty());

        submit_block(handler, harness, &mut submissions, 3, &block_bytes(11, 4, 2), now);
        assert_eq!(harness.responses(), [(3, Err(LocalGossipFailure::ConflictingProposal))]);
        assert!(harness.gossip.pop_event().is_none());
        assert_eq!(locked_proposals(harness), 0, "a refused block's contents go nowhere");

        submit_block(handler, harness, &mut submissions, 4, &block_bytes(11, 5, 2), now);
        harness.pop_gossip();
        assert_eq!(locked_proposals(harness), 1);
        assert!(harness.responses().is_empty());
    }

    #[test]
    fn blinded_block_lock_answers_instead_of_publishing() {
        let now = Instant::now();
        let mut standalone = Standalone::new(now);
        let mut submissions = Submissions::new();
        standalone.handler.on_status(10, true);
        standalone.handler.on_status(11, true);
        let Standalone { handler, harness } = &mut standalone;
        assert_eq!(locked_proposals(harness), 0, "subscribes before anything is locked");

        reveal_block(handler, harness, &mut submissions, 1, &block_bytes(11, 4, 1), now);
        assert_eq!(harness.responses(), [(1, Ok(()))]);
        assert!(harness.gossip.pop_event().is_none(), "the sidecar publishes it");
        assert_eq!(locked_proposals(harness), 0, "and its columns");

        reveal_block(handler, harness, &mut submissions, 2, &block_bytes(11, 4, 1), now);
        assert_eq!(harness.responses(), [(2, Ok(()))], "a resubmission is let through");

        reveal_block(handler, harness, &mut submissions, 3, &block_bytes(11, 4, 2), now);
        submit_block(handler, harness, &mut submissions, 4, &block_bytes(11, 4, 2), now);
        assert_eq!(harness.responses(), [
            (3, Err(LocalGossipFailure::ConflictingProposal)),
            (4, Err(LocalGossipFailure::ConflictingProposal)),
        ]);
        assert!(harness.gossip.pop_event().is_none());
    }

    #[test]
    fn gloas_block_is_published_bare_once_locked() {
        let now = Instant::now();
        let mut standalone = Standalone::new(now);
        let mut submissions = Submissions::new();
        standalone.handler.on_status(10, true);
        standalone.handler.on_status(11, true);
        let Standalone { handler, harness } = &mut standalone;
        assert_eq!(locked_proposals(harness), 0, "subscribes before anything is locked");

        let mut block = block_bytes(11, 4, 1);
        block[..4].copy_from_slice(&100u32.to_le_bytes());
        block[180..184].copy_from_slice(&84u32.to_le_bytes());
        assert_eq!(
            SubmittedBlock::framed(&block, BroadcastValidation::Gossip),
            SubmittedBlock::Gloas(BroadcastValidation::Gossip)
        );
        let validation = BroadcastValidation::ConsensusAndEquivocation;
        lock_block(
            handler,
            harness,
            &mut submissions,
            1,
            &block,
            SubmittedBlock::Gloas(validation),
            now,
        );
        assert_eq!(harness.pop_gossip().validation, validation, "Beacon State applies the level");
        assert_eq!(locked_proposals(harness), 0, "its blobs travel with the envelope");
        assert!(harness.responses().is_empty());

        block[4] = 2;
        lock_block(
            handler,
            harness,
            &mut submissions,
            2,
            &block,
            SubmittedBlock::Gloas(BroadcastValidation::Gossip),
            now,
        );
        assert_eq!(harness.responses(), [(2, Err(LocalGossipFailure::ConflictingProposal))]);
        assert!(harness.gossip.pop_event().is_none());
    }

    #[test]
    fn clustered_block_enters_validation_once_its_lock_commits() {
        let now = Instant::now();
        let mut config = SlashingProtectionConfig::new(
            1,
            [1],
            test_address(1),
            ClusterStorageConfig::Create("unused-test-journal".into()),
        )
        .unwrap();
        config.tick_interval = std::time::Duration::from_millis(1);
        config.election_ticks = 5;
        config.heartbeat_ticks = 1;
        let mut handler = handler(now);
        handler.cluster = Some(SlashingProtectionCluster::in_memory(config, now).unwrap());
        let mut harness = Harness::new();
        let mut submissions = Submissions::new();
        handler.on_status(10, true);
        handler.on_status(11, true);
        handler.cluster.as_mut().unwrap().campaign().unwrap();

        submit_block(&mut handler, &mut harness, &mut submissions, 1, &block_bytes(11, 4, 1), now);
        assert!(harness.gossip.pop_event().is_none(), "nothing leaves before the lock commits");
        assert_eq!(locked_proposals(&mut harness), 0);
        assert_eq!(handler.pending_blocks.len(), 1);

        let Harness { local_gossip, gossip, adapter, .. } = &mut harness;
        handler.spin(now, adapter, local_gossip, gossip, &mut submissions.reader);

        assert!(handler.pending_blocks.is_empty());
        harness.pop_gossip();
        assert_eq!(locked_proposals(&mut harness), 1, "the committed block's contents follow");
        assert!(harness.responses().is_empty());
    }

    const TEST_PROPOSAL_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(100);

    /// A single-node cluster, latched at slot 11 and leading.
    fn clustered_handler(now: Instant) -> SlashingProtectionHandler {
        let mut config = SlashingProtectionConfig::new(
            1,
            [1],
            test_address(1),
            ClusterStorageConfig::Create("unused-test-journal".into()),
        )
        .unwrap();
        config.tick_interval = std::time::Duration::from_millis(1);
        config.election_ticks = 5;
        config.heartbeat_ticks = 1;
        config.proposal_timeout = TEST_PROPOSAL_TIMEOUT;
        let mut handler = handler(now);
        handler.cluster = Some(SlashingProtectionCluster::in_memory(config, now).unwrap());
        handler.on_status(10, true);
        handler.on_status(11, true);
        handler.cluster.as_mut().unwrap().campaign().unwrap();
        handler
    }

    /// Spinning only at the deadline answers the proposal `LockPending`
    /// before it commits in the same spin.
    fn spin_past_deadline(
        handler: &mut SlashingProtectionHandler,
        harness: &mut Harness,
        submissions: &mut Submissions,
        now: Instant,
    ) {
        let later = now + TEST_PROPOSAL_TIMEOUT;
        let Harness { local_gossip, gossip, adapter, .. } = harness;
        handler.spin(later, adapter, local_gossip, gossip, &mut submissions.reader);
    }

    #[test]
    fn late_attestation_lock_is_published_without_a_second_answer() {
        let now = Instant::now();
        let mut handler = clustered_handler(now);
        let mut harness = Harness::new();
        let mut submissions = Submissions::new();
        let Harness { local_gossip, gossip, adapter, .. } = &mut harness;
        handler.on_local_attestation(
            PendingAttestation::new(1, 0, attestation(11, 7), now),
            now,
            local_gossip,
            gossip,
            &mut adapter.producers,
        );

        spin_past_deadline(&mut handler, &mut harness, &mut submissions, now);

        assert_eq!(harness.responses(), [(1, Err(LocalGossipFailure::LockPending))]);
        harness.pop_gossip();
        assert!(handler.pending_attestations.is_empty() && handler.pending_blocks.is_empty());
        assert!(harness.local_gossip.is_empty(), "nobody awaits the late verdict");
    }

    #[test]
    fn late_block_lock_is_published_without_a_second_answer() {
        let now = Instant::now();
        let mut handler = clustered_handler(now);
        let mut harness = Harness::new();
        let mut submissions = Submissions::new();
        submit_block(&mut handler, &mut harness, &mut submissions, 1, &block_bytes(11, 4, 1), now);
        assert_eq!(locked_proposals(&mut harness), 0, "nothing leaves before the lock commits");

        spin_past_deadline(&mut handler, &mut harness, &mut submissions, now);

        harness.pop_gossip();
        assert_eq!(locked_proposals(&mut harness), 1);
        assert_eq!(harness.responses(), [(1, Err(LocalGossipFailure::LockPending))]);
        assert!(handler.pending_attestations.is_empty() && handler.pending_blocks.is_empty());
    }

    /// The API reveals a blinded block through the request that was already
    /// answered, so a late lock for one publishes nothing.
    #[test]
    fn late_blinded_block_lock_is_not_published() {
        let now = Instant::now();
        let mut handler = clustered_handler(now);
        let mut harness = Harness::new();
        let mut submissions = Submissions::new();
        reveal_block(&mut handler, &mut harness, &mut submissions, 1, &block_bytes(11, 4, 1), now);

        spin_past_deadline(&mut handler, &mut harness, &mut submissions, now);

        assert_eq!(harness.responses(), [(1, Err(LocalGossipFailure::LockPending))]);
        assert!(harness.gossip.pop_event().is_none());
        assert!(handler.pending_attestations.is_empty() && handler.pending_blocks.is_empty());
    }

    /// An answered entry waits two slots for a late commit; an unanswered
    /// one waits for its proposal timeout, however old its slot.
    #[test]
    fn answered_pending_locks_expire_two_slots_after_their_slot() {
        let now = Instant::now();
        let mut handler = handler(now);
        handler.on_status(11, true);
        let id = |sequence| ProposalId { origin_node_id: 1, sequence, incarnation: [0; 16] };
        let mut answered = PendingAttestation::new(1, 0, attestation(11, 7), now);
        answered.request.answered = true;
        handler.pending_attestations.insert(id(0), answered);
        handler
            .pending_attestations
            .insert(id(1), PendingAttestation::new(2, 0, attestation(11, 8), now));

        handler.on_status(12, true);
        assert_eq!(handler.pending_attestations.len(), 2);
        handler.on_status(13, true);
        assert_eq!(handler.pending_attestations.keys().collect::<Vec<_>>(), [&id(1)]);
    }

    #[test]
    fn clustered_blinded_block_is_answered_once_its_lock_commits() {
        let now = Instant::now();
        let mut config = SlashingProtectionConfig::new(
            1,
            [1],
            test_address(1),
            ClusterStorageConfig::Create("unused-test-journal".into()),
        )
        .unwrap();
        config.tick_interval = std::time::Duration::from_millis(1);
        config.election_ticks = 5;
        config.heartbeat_ticks = 1;
        let mut handler = handler(now);
        handler.cluster = Some(SlashingProtectionCluster::in_memory(config, now).unwrap());
        let mut harness = Harness::new();
        let mut submissions = Submissions::new();
        handler.on_status(10, true);
        handler.on_status(11, true);
        handler.cluster.as_mut().unwrap().campaign().unwrap();

        reveal_block(&mut handler, &mut harness, &mut submissions, 1, &block_bytes(11, 4, 1), now);
        assert!(harness.responses().is_empty(), "nothing is answered before the lock commits");

        let Harness { local_gossip, gossip, adapter, .. } = &mut harness;
        handler.spin(now, adapter, local_gossip, gossip, &mut submissions.reader);

        assert_eq!(harness.responses(), [(1, Ok(()))]);
        assert!(harness.gossip.pop_event().is_none());
        assert_eq!(locked_proposals(&mut harness), 0);
    }

    fn handler(now: Instant) -> SlashingProtectionHandler {
        SlashingProtectionHandler::new(
            TCache::producer(TCacheId::ClusterOutbound, 1 << 12),
            None,
            now,
        )
        .unwrap()
    }

    struct Standalone {
        handler: SlashingProtectionHandler,
        harness: Harness,
    }

    impl Standalone {
        fn new(now: Instant) -> Self {
            Self { handler: handler(now), harness: Harness::new() }
        }

        fn submit(&mut self, request_id: u64, slot: u64, validator: u8, root: u8, now: Instant) {
            let mut ssz = attestation(slot, validator);
            ssz[32..64].fill(root);
            self.submit_ssz(request_id, ssz, now);
        }

        fn submit_vote(
            &mut self,
            request_id: u64,
            validator: u8,
            source: u64,
            slot: u64,
            now: Instant,
        ) {
            let mut ssz = attestation(slot, validator);
            ssz[64..72].copy_from_slice(&source.to_le_bytes());
            self.submit_ssz(request_id, ssz, now);
        }

        fn submit_ssz(&mut self, request_id: u64, ssz: [u8; SINGLE_ATT_SIZE], now: Instant) {
            let Harness { local_gossip, gossip, adapter, .. } = &mut self.harness;
            self.handler.on_local_attestation(
                PendingAttestation::new(request_id, 0, ssz, now),
                now,
                local_gossip,
                gossip,
                &mut adapter.producers,
            );
        }
    }

    fn attestation(slot: u64, validator: u8) -> [u8; SINGLE_ATT_SIZE] {
        let mut ssz = [0; SINGLE_ATT_SIZE];
        ssz[8..16].copy_from_slice(&u64::from(validator).to_le_bytes());
        ssz[16..24].copy_from_slice(&slot.to_le_bytes());
        ssz[104..112].copy_from_slice(&(slot / SLOTS_PER_EPOCH).to_le_bytes());
        ssz
    }

    #[test]
    fn standalone_refuses_surround_votes_while_selected_and_once_evicted() {
        let now = Instant::now();
        let mut standalone = Standalone::new(now);
        standalone.handler.on_status(10, true);
        standalone.handler.on_status(100, true);
        standalone.submit_vote(1, 7, 2, 100, now);
        standalone.harness.pop_gossip();

        standalone.handler.on_status(130, true);
        standalone.submit_vote(2, 7, 1, 130, now);
        standalone.handler.on_status(170, true);
        standalone.submit_vote(3, 7, 1, 170, now);
        let mut wrong_target = attestation(170, 7);
        wrong_target[104..112].copy_from_slice(&4u64.to_le_bytes());
        standalone.submit_ssz(4, wrong_target, now);
        assert_eq!(standalone.harness.responses(), [
            (2, Err(LocalGossipFailure::SurroundVote)),
            (3, Err(LocalGossipFailure::SurroundVote)),
            (4, Err(LocalGossipFailure::Invalid)),
        ]);
        assert!(standalone.harness.gossip.pop_event().is_none());

        standalone.submit_vote(5, 7, 2, 170, now);
        standalone.harness.pop_gossip();
        assert!(standalone.harness.responses().is_empty());
    }

    #[test]
    fn standalone_locks_before_validation_and_allows_identical_retries() {
        let now = Instant::now();
        let mut standalone = Standalone::new(now);
        standalone.handler.on_status(10, true);
        standalone.handler.on_status(11, true);

        standalone.submit(1, 11, 7, 1, now);
        let message = standalone.harness.pop_gossip();
        assert!(standalone.harness.responses().is_empty());
        assert!(standalone.handler.cluster.is_none());
        assert!(standalone.handler.pending_attestations.is_empty());

        standalone.submit(2, 11, 7, 1, now);
        assert_eq!(standalone.harness.pop_gossip().msg_hash, message.msg_hash);
        assert!(standalone.harness.responses().is_empty());

        standalone.submit(3, 11, 7, 2, now);
        assert_eq!(standalone.harness.responses(), [(
            3,
            Err(LocalGossipFailure::ConflictingAttestation)
        )]);
        assert!(standalone.harness.gossip.pop_event().is_none());

        standalone.harness.complete(message.msg_hash, Ok(()));
        assert_eq!(standalone.harness.responses(), [(1, Ok(())), (2, Ok(()))]);
        assert!(standalone.harness.local_gossip.is_empty());

        standalone.submit(4, 11, 7, 2, now);
        assert_eq!(standalone.harness.responses(), [(
            4,
            Err(LocalGossipFailure::ConflictingAttestation)
        )]);
        assert!(standalone.harness.gossip.pop_event().is_none());
        standalone.submit(5, 11, 7, 1, now);
        assert_eq!(standalone.harness.pop_gossip().msg_hash, message.msg_hash);
        assert!(standalone.harness.responses().is_empty());
    }

    #[test]
    fn standalone_locks_are_per_validator_and_epoch_and_survive_ring_reuse() {
        let now = Instant::now();
        let mut standalone = Standalone::new(now);
        standalone.handler.on_status(10, true);
        standalone.handler.on_status(12, true);

        standalone.submit(1, 11, 7, 1, now);
        standalone.harness.pop_gossip();
        standalone.submit(2, 11, 8, 2, now);
        standalone.harness.pop_gossip();
        standalone.submit(3, 12, 7, 3, now);
        assert_eq!(standalone.harness.responses(), [(
            3,
            Err(LocalGossipFailure::ConflictingAttestation)
        )]);

        standalone.handler.on_status(40, true);
        standalone.submit(4, 40, 7, 4, now);
        standalone.harness.pop_gossip();
        standalone.handler.on_status(70, true);
        standalone.submit(5, 70, 7, 5, now);
        standalone.harness.pop_gossip();
        assert!(standalone.harness.responses().is_empty());

        standalone.submit(6, 11, 7, 6, now);
        standalone.submit(7, 40, 7, 6, now);
        standalone.submit(8, 70, 7, 6, now);
        assert_eq!(standalone.harness.responses(), [
            (6, Err(LocalGossipFailure::TooOld)),
            (7, Err(LocalGossipFailure::ConflictingAttestation)),
            (8, Err(LocalGossipFailure::ConflictingAttestation)),
        ]);
        assert!(standalone.harness.gossip.pop_event().is_none());
    }

    #[test]
    fn standalone_keeps_locks_after_validation_failure_or_timeout() {
        for failure in [
            LocalGossipFailure::Invalid,
            LocalGossipFailure::Unverifiable,
            LocalGossipFailure::TimedOut,
        ] {
            let now = Instant::now();
            let mut standalone = Standalone::new(now);
            standalone.handler.on_status(10, true);
            standalone.handler.on_status(11, true);
            standalone.submit(1, 11, 7, 1, now);
            let message = standalone.harness.pop_gossip();

            match failure {
                LocalGossipFailure::TimedOut => standalone
                    .harness
                    .local_gossip
                    .expire(now + VALIDATION_TIMEOUT, &mut standalone.harness.adapter.producers),
                failure => standalone.harness.complete(message.msg_hash, Err(failure)),
            }
            assert_eq!(standalone.harness.responses(), [(1, Err(failure))]);
            assert!(standalone.harness.local_gossip.is_empty());

            standalone.submit(2, 11, 7, 2, now + VALIDATION_TIMEOUT);
            assert_eq!(standalone.harness.responses(), [(
                2,
                Err(LocalGossipFailure::ConflictingAttestation)
            )]);
            assert!(standalone.harness.gossip.pop_event().is_none());
        }
    }

    #[test]
    fn standalone_admission_precedes_locking_and_retention_never_regresses() {
        let now = Instant::now();
        let mut standalone = Standalone::new(now);
        standalone.submit(1, 11, 7, 1, now);
        assert_eq!(standalone.harness.responses(), [(1, Err(LocalGossipFailure::NotSynced))]);

        standalone.handler.on_status(10, true);
        standalone.submit(2, 10, 7, 1, now);
        standalone.submit(3, 11, 7, 1, now);
        assert_eq!(standalone.harness.responses(), [
            (2, Err(LocalGossipFailure::BeforeStartupFloor)),
            (3, Err(LocalGossipFailure::Future)),
        ]);
        assert!(standalone.harness.gossip.pop_event().is_none());

        standalone.handler.on_status(11, true);
        standalone.submit(4, 11, 7, 2, now);
        standalone.harness.pop_gossip();
        assert!(
            standalone.harness.responses().is_empty(),
            "rejected requests must not acquire locks"
        );

        standalone.handler.on_status(44, false);
        standalone.submit(5, 11, 7, 2, now);
        assert_eq!(standalone.harness.responses(), [(5, Err(LocalGossipFailure::TooOld))]);

        standalone.handler.on_status(43, false);
        assert_eq!(standalone.handler.admission.validate(11, 43), Ok(()));
        standalone.submit(6, 11, 7, 2, now);
        assert_eq!(standalone.harness.responses(), [(6, Err(LocalGossipFailure::TooOld))]);
        assert!(standalone.harness.gossip.pop_event().is_none());
    }

    #[test]
    fn startup_floor_latches_once_synced() {
        let mut handler = handler(Instant::now());

        handler.on_status(10, false);
        assert_eq!(handler.admission.validate(10, 10), Err(AdmissionError::StartupFloorUnset));

        handler.on_status(10, true);
        assert_eq!(
            handler.admission.validate(10, 10),
            Err(AdmissionError::BeforeStartupFloor { slot: 10, minimum: 11 })
        );

        handler.on_status(20, true);
        assert_eq!(handler.admission.validate(11, 20), Ok(()), "floor must not relatch");
    }

    #[test]
    fn failed_cluster_rejects_pending_and_new_requests_without_standalone_fallback() {
        let now = Instant::now();
        let mut handler = handler(now);
        let mut harness = Harness::new();
        handler.cluster = Some(
            SlashingProtectionCluster::in_memory(
                SlashingProtectionConfig::new(
                    1,
                    [1],
                    test_address(1),
                    ClusterStorageConfig::Create("unused-test-journal".into()),
                )
                .unwrap(),
                now,
            )
            .unwrap(),
        );
        handler.on_status(10, true);
        handler.on_status(11, true);
        handler.cluster.as_mut().unwrap().campaign().unwrap();
        handler.drive(
            now,
            &mut harness.local_gossip,
            &mut harness.gossip,
            &mut harness.adapter.producers,
        );

        let mut ssz = [0; SINGLE_ATT_SIZE];
        ssz[16..24].copy_from_slice(&11u64.to_le_bytes());
        let attestation = PendingAttestation::new(1, 0, ssz, now);
        handler.on_local_attestation(
            attestation,
            now,
            &mut harness.local_gossip,
            &mut harness.gossip,
            &mut harness.adapter.producers,
        );
        assert_eq!(handler.pending_attestations.len(), 1);
        assert!(harness.responses().is_empty());
        handler.cluster.as_mut().unwrap().fail_persistence();
        handler.drive(
            now,
            &mut harness.local_gossip,
            &mut harness.gossip,
            &mut harness.adapter.producers,
        );
        assert_eq!(harness.responses(), [(1, Err(LocalGossipFailure::Internal))]);
        assert!(handler.pending_attestations.is_empty());
        assert!(handler.cluster.as_ref().unwrap().is_failed());

        handler.on_local_attestation(
            PendingAttestation { request: PendingRequest::new(2, now), ..attestation },
            now,
            &mut harness.local_gossip,
            &mut harness.gossip,
            &mut harness.adapter.producers,
        );
        assert_eq!(harness.responses(), [(2, Err(LocalGossipFailure::Internal))]);
        assert!(harness.gossip.pop_event().is_none());
        assert!(harness.local_gossip.is_empty());
    }
}

fn decision_response(
    admission: Result<(), AdmissionError>,
    result: LockResult,
    conflict: LocalGossipFailure,
) -> LocalGossipResult {
    admission.map_err(admission_failure)?;
    lock_response(result, conflict)
}

fn lock_response(result: LockResult, conflict: LocalGossipFailure) -> LocalGossipResult {
    match result {
        LockResult::Accepted | LockResult::AlreadyAcceptedSame => Ok(()),
        LockResult::Conflicting => Err(conflict),
        LockResult::Surrounding => Err(LocalGossipFailure::SurroundVote),
        LockResult::TooOld => Err(LocalGossipFailure::TooOld),
        LockResult::Invalid => Err(LocalGossipFailure::Invalid),
    }
}

/// The submission holds the whole `SignedBlockContents`, so the block is
/// copied rather than handed on as the submission's read.
fn block_message(
    request_id: u64,
    ssz: &[u8],
    slot: u64,
    validation: BroadcastValidation,
) -> LocalMessage<'_> {
    let topic = GossipTopic::BeaconBlock;
    LocalMessage { request_id, topic, ssz, ssz_read: None, slot, validation }
}

fn proposal_failure(error: &ProposeError) -> LocalGossipFailure {
    match error {
        ProposeError::Admission(error) => admission_failure(*error),
        ProposeError::NotReady |
        ProposeError::Failed |
        ProposeError::SequenceExhausted |
        ProposeError::DeadlineOverflow => LocalGossipFailure::Internal,
    }
}

fn admission_failure(error: AdmissionError) -> LocalGossipFailure {
    match error {
        AdmissionError::StartupFloorUnset => LocalGossipFailure::NotSynced,
        AdmissionError::BeforeStartupFloor { .. } => LocalGossipFailure::BeforeStartupFloor,
        AdmissionError::TooOld { .. } => LocalGossipFailure::TooOld,
        AdmissionError::Future { .. } => LocalGossipFailure::Future,
    }
}

impl AttestationLockCommand {
    fn local_message(&self, request_id: u64) -> LocalMessage<'_> {
        LocalMessage {
            request_id,
            topic: GossipTopic::BeaconAttestation(self.subnet),
            ssz: &self.ssz,
            ssz_read: None,
            slot: self.key.slot,
            validation: BroadcastValidation::Gossip,
        }
    }
}
