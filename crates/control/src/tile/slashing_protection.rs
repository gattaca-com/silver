use std::time::Instant;

use flux::spine::SpineAdapter;
use flux_profiler::timed;
use fxhash::FxHashMap;
use silver_common::{
    ClusterIn, ClusterMsgIn, ClusterMsgOut, GossipTopic, LocalGossipFailure, LocalGossipResult,
    SilverSpine, SilverSpineProducers, TCacheProducer, TCacheRead, TCacheReader, TProducer,
    block_contents::SignedBlockContents,
    ssz_view::{SINGLE_ATT_SIZE, SignedBeaconBlockView, SingleAttestationView},
};
use silver_gossip::GossipHandler;

use super::local_gossip::{LocalGossipHandler, LocalMessage, produce_response};
use crate::cluster::{
    AdmissionError, AttestationKey, AttestationLockCommand, BlockKey, BlockLockCommand,
    ClusterError, ClusterEvent, LockResult, ProposalId, ProposeError, SlashingAdmission,
    SlashingLockStore, SlashingProtectionCluster, SlashingProtectionConfig, decode_message,
    encode_message,
};

#[derive(Debug, Clone, Copy)]
pub(super) struct PendingAttestation {
    request_id: u64,
    command: AttestationLockCommand,
}

impl PendingAttestation {
    pub(super) fn new(request_id: u64, subnet: u64, ssz: [u8; SINGLE_ATT_SIZE]) -> Self {
        let key = AttestationKey {
            attester_index: SingleAttestationView::attester_index(&ssz),
            slot: SingleAttestationView::slot(&ssz),
        };
        Self { request_id, command: AttestationLockCommand { key, subnet, ssz } }
    }
}

/// A signed block waiting on its lock. Its `SignedBlockContents` stay in the
/// submissions tcache until the lock commits.
#[derive(Debug, Clone, Copy)]
struct PendingBlock {
    request_id: u64,
    key: BlockKey,
    ssz: TCacheRead,
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

        Ok(Self {
            outbound_producer,
            cluster,
            local_locks: SlashingLockStore::default(),
            admission: SlashingAdmission::new(),
            pending_attestations: FxHashMap::default(),
            pending_blocks: FxHashMap::default(),
            wall_slot: 0,
        })
    }

    pub(super) fn on_status(&mut self, head_slot: u64, wall_slot: u64) {
        self.wall_slot = wall_slot;
        if self.cluster.is_none() {
            self.local_locks.advance_minimum_slot(SlashingAdmission::age_floor(wall_slot));
        }
        if head_slot != wall_slot || !self.admission.set_startup_wall_slot(wall_slot) {
            return;
        }

        if let Some(cluster) = self.cluster.as_mut() {
            let initialized = cluster.set_startup_wall_slot(wall_slot);
            debug_assert!(initialized, "handler and cluster startup floors latch together");
        }
        silver_log::info!(wall_slot, "local slashing protection startup floor latched");
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
        adapter.consume(|message: ClusterIn, _producers| match message {
            ClusterIn::Msg(message) => self.handle_message(message, inbound_consumer),
            ClusterIn::NodeUnreachable(id) => {
                if let Some(cluster) = self.cluster.as_mut() {
                    cluster.report_unreachable(id);
                }
            }
        });
        self.drive(now, local_gossip, gossip_handler, inbound_consumer, &mut adapter.producers);
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
            produce_response(producers, attestation.request_id, Err(admission_failure(error)));
            silver_log::warn!(
                ?error,
                request_id = attestation.request_id,
                slot = attestation.command.key.slot,
                "local attestation rejected before cluster proposal"
            );
            return;
        }

        let Some(cluster) = self.cluster.as_mut() else {
            let result = self.local_locks.apply(&attestation.command);
            let response = lock_response(result, LocalGossipFailure::ConflictingAttestation);
            if response.is_err() {
                produce_response(producers, attestation.request_id, response);
                silver_log::warn!(
                    ?result,
                    request_id = attestation.request_id,
                    slot = attestation.command.key.slot,
                    "local lock rejected attestation"
                );
                return;
            }
            local_gossip.submit(
                attestation.command.local_message(attestation.request_id),
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
                produce_response(producers, attestation.request_id, Err(proposal_failure(&error)));
                silver_log::warn!(
                    ?error,
                    request_id = attestation.request_id,
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
        ssz: TCacheRead,
        block: &[u8],
        now: Instant,
        local_gossip: &mut LocalGossipHandler,
        gossip_handler: &mut GossipHandler,
        producers: &mut SilverSpineProducers,
    ) {
        let key = BlockKey {
            proposer_index: SignedBeaconBlockView::proposer_index(block),
            slot: SignedBeaconBlockView::slot(block),
        };
        let command = BlockLockCommand { key, signature: *SignedBeaconBlockView::signature(block) };
        if let Err(error) = self.admission.validate(key.slot, self.wall_slot) {
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
            return local_gossip.submit(
                block_message(request_id, block, key.slot),
                now,
                gossip_handler,
                producers,
            );
        };

        match cluster.propose_block(command, self.wall_slot, now) {
            Ok(proposal_id) => {
                let previous =
                    self.pending_blocks.insert(proposal_id, PendingBlock { request_id, key, ssz });
                debug_assert!(previous.is_none(), "proposal IDs are unique per node");
            }
            Err(error) => {
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

    fn handle_message(&mut self, inbound: ClusterMsgIn, inbound_consumer: &mut TCacheReader) {
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
                silver_log::warn!(?error, from = inbound.from, "invalid inbound Raft message");
                return;
            }
        };
        if message.from != inbound.from {
            silver_log::warn!(
                authenticated_from = inbound.from,
                encoded_from = message.from,
                "inbound Raft message source does not match authenticated cluster peer"
            );
            return;
        }
        if message.to != cluster.node_id() {
            silver_log::warn!(
                from = inbound.from,
                encoded_to = message.to,
                local_node = cluster.node_id(),
                "inbound Raft message addressed to another cluster node"
            );
            return;
        }
        if let Err(error) = cluster.step(message) {
            silver_log::warn!(?error, from = inbound.from, "failed to step inbound Raft message");
        }
    }

    fn drive(
        &mut self,
        now: Instant,
        local_gossip: &mut LocalGossipHandler,
        gossip_handler: &mut GossipHandler,
        reader: &mut TCacheReader,
        producers: &mut SilverSpineProducers,
    ) {
        let Some(cluster) = self.cluster.as_mut() else {
            return;
        };

        let pending_attestations = &mut self.pending_attestations;
        let pending_blocks = &mut self.pending_blocks;
        let outbound_producer = &mut self.outbound_producer;
        let result = cluster.spin(now, self.wall_slot, |event| match event {
            ClusterEvent::SendRaftMessage(message) => {
                let to = message.to;
                match encode_message(message, outbound_producer) {
                    Ok(data) => {
                        producers.cluster_outbound.produce(&ClusterMsgOut { to, data }.into());
                    }
                    Err(error) => {
                        silver_log::warn!(?error, to, "failed to buffer outbound Raft message")
                    }
                }
            }
            ClusterEvent::AttestationCommitted(decision) => {
                let Some(attestation) = pending_attestations.remove(&decision.proposal_id) else {
                    silver_log::warn!(
                        ?decision.proposal_id,
                        "committed local Raft proposal has no pending attestation"
                    );
                    return;
                };
                if decision.command != attestation.command {
                    produce_response(
                        producers,
                        attestation.request_id,
                        Err(LocalGossipFailure::Internal),
                    );
                    silver_log::error!(
                        ?decision.proposal_id,
                        request_id = attestation.request_id,
                        "committed Raft command does not match its pending attestation"
                    );
                    return;
                }
                let response = decision_response(
                    decision.admission,
                    decision.result,
                    LocalGossipFailure::ConflictingAttestation,
                );
                if response.is_ok() {
                    local_gossip.submit(
                        decision.command.local_message(attestation.request_id),
                        now,
                        gossip_handler,
                        producers,
                    );
                } else {
                    produce_response(producers, attestation.request_id, response);
                    silver_log::warn!(
                        ?decision.result,
                        ?decision.admission,
                        request_id = attestation.request_id,
                        slot = attestation.command.key.slot,
                        "committed attestation cannot enter validation"
                    );
                }
            }
            ClusterEvent::BlockCommitted(decision) => {
                let Some(block) = pending_blocks.remove(&decision.proposal_id) else {
                    silver_log::warn!(
                        ?decision.proposal_id,
                        "committed local Raft proposal has no pending block"
                    );
                    return;
                };
                if decision.key != block.key {
                    produce_response(
                        producers,
                        block.request_id,
                        Err(LocalGossipFailure::Internal),
                    );
                    silver_log::error!(
                        ?decision.proposal_id,
                        request_id = block.request_id,
                        "committed Raft command does not match its pending block"
                    );
                    return;
                }
                let slot = block.key.slot;
                let response = decision_response(
                    decision.admission,
                    decision.result,
                    LocalGossipFailure::ConflictingProposal,
                );
                if let Err(failure) = response {
                    produce_response(producers, block.request_id, Err(failure));
                    silver_log::warn!(
                        ?decision.result,
                        ?decision.admission,
                        request_id = block.request_id,
                        slot,
                        "committed block cannot enter validation"
                    );
                    return;
                }
                let acquired = reader.acquire(block.ssz);
                let Some(bytes) = acquired
                    .buffer()
                    .ok()
                    .and_then(|(contents, _)| SignedBlockContents::signed_block(contents))
                else {
                    produce_response(
                        producers,
                        block.request_id,
                        Err(LocalGossipFailure::Internal),
                    );
                    silver_log::error!(
                        request_id = block.request_id,
                        slot,
                        "submitted block overwritten before its lock committed"
                    );
                    return;
                };
                local_gossip.submit(
                    block_message(block.request_id, bytes, slot),
                    now,
                    gossip_handler,
                    producers,
                );
            }
            ClusterEvent::ProposalTimedOut(proposal_id) => {
                if let Some(block) = pending_blocks.remove(&proposal_id) {
                    produce_response(
                        producers,
                        block.request_id,
                        Err(LocalGossipFailure::TimedOut),
                    );
                    silver_log::warn!(
                        ?proposal_id,
                        request_id = block.request_id,
                        slot = block.key.slot,
                        "block cluster proposal timed out"
                    );
                }
                if let Some(attestation) = pending_attestations.remove(&proposal_id) {
                    produce_response(
                        producers,
                        attestation.request_id,
                        Err(LocalGossipFailure::TimedOut),
                    );
                    silver_log::warn!(
                        ?proposal_id,
                        request_id = attestation.request_id,
                        slot = attestation.command.key.slot,
                        "attestation cluster proposal timed out"
                    );
                }
            }
        });
        if let Err(error) = result {
            silver_log::error!(?error, "slashing protection spin failed");
            for (_, attestation) in self.pending_attestations.drain() {
                produce_response(
                    producers,
                    attestation.request_id,
                    Err(LocalGossipFailure::Internal),
                );
            }
            for (_, block) in self.pending_blocks.drain() {
                produce_response(producers, block.request_id, Err(LocalGossipFailure::Internal));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use silver_common::{
        TCache, TCacheId, TCacheProducer, TCacheTable, TReadMode, ssz_view::SIGNED_BEACON_BLOCK_MIN,
    };

    use super::*;
    use crate::{
        cluster::ClusterStorageConfig,
        tile::local_gossip::{VALIDATION_TIMEOUT, tests::Harness},
    };

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
        let ssz = submissions.publish(&contents);
        let Harness { local_gossip, gossip, adapter, .. } = harness;
        handler.on_local_block(
            request_id,
            ssz,
            block,
            now,
            local_gossip,
            gossip,
            &mut adapter.producers,
        );
    }

    #[test]
    fn standalone_block_lock_admits_one_block_per_proposer_and_slot() {
        let now = Instant::now();
        let mut standalone = Standalone::new(now);
        let mut submissions = Submissions::new();
        standalone.handler.on_status(10, 10);
        standalone.handler.on_status(11, 11);
        let Standalone { handler, harness } = &mut standalone;

        submit_block(handler, harness, &mut submissions, 1, &block_bytes(11, 4, 1), now);
        let first = harness.pop_gossip();
        submit_block(handler, harness, &mut submissions, 2, &block_bytes(11, 4, 1), now);
        assert_eq!(harness.pop_gossip().msg_hash, first.msg_hash, "a resubmission rejoins");
        assert!(harness.responses().is_empty());

        submit_block(handler, harness, &mut submissions, 3, &block_bytes(11, 4, 2), now);
        assert_eq!(harness.responses(), [(3, Err(LocalGossipFailure::ConflictingProposal))]);
        assert!(harness.gossip.pop_event().is_none());

        submit_block(handler, harness, &mut submissions, 4, &block_bytes(11, 5, 2), now);
        harness.pop_gossip();
        assert!(harness.responses().is_empty());
    }

    #[test]
    fn clustered_block_enters_validation_once_its_lock_commits() {
        let now = Instant::now();
        let mut config = SlashingProtectionConfig::new(
            1,
            vec![1],
            ClusterStorageConfig::Create("unused-test-journal".into()),
        );
        config.tick_interval = std::time::Duration::from_millis(1);
        config.election_ticks = 5;
        config.heartbeat_ticks = 1;
        let mut handler = handler(now);
        handler.cluster = Some(SlashingProtectionCluster::in_memory(config, now).unwrap());
        let mut harness = Harness::new();
        let mut submissions = Submissions::new();
        handler.on_status(10, 10);
        handler.on_status(11, 11);
        handler.cluster.as_mut().unwrap().campaign().unwrap();

        submit_block(&mut handler, &mut harness, &mut submissions, 1, &block_bytes(11, 4, 1), now);
        assert!(harness.gossip.pop_event().is_none(), "nothing leaves before the lock commits");
        assert_eq!(handler.pending_blocks.len(), 1);

        let Harness { local_gossip, gossip, adapter, .. } = &mut harness;
        handler.spin(now, adapter, local_gossip, gossip, &mut submissions.reader);

        assert!(handler.pending_blocks.is_empty());
        harness.pop_gossip();
        assert!(harness.responses().is_empty());
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
            let mut ssz = [0; SINGLE_ATT_SIZE];
            ssz[8..16].copy_from_slice(&u64::from(validator).to_le_bytes());
            ssz[16..24].copy_from_slice(&slot.to_le_bytes());
            ssz[32..64].fill(root);
            let Harness { local_gossip, gossip, adapter, .. } = &mut self.harness;
            self.handler.on_local_attestation(
                PendingAttestation::new(request_id, 0, ssz),
                now,
                local_gossip,
                gossip,
                &mut adapter.producers,
            );
        }
    }

    #[test]
    fn standalone_locks_before_validation_and_allows_identical_retries() {
        let now = Instant::now();
        let mut standalone = Standalone::new(now);
        standalone.handler.on_status(10, 10);
        standalone.handler.on_status(11, 11);

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
        standalone.handler.on_status(10, 10);
        standalone.handler.on_status(12, 12);

        standalone.submit(1, 11, 7, 1, now);
        standalone.harness.pop_gossip();
        standalone.submit(2, 11, 8, 2, now);
        standalone.harness.pop_gossip();
        standalone.submit(3, 12, 7, 3, now);
        assert_eq!(standalone.harness.responses(), [(
            3,
            Err(LocalGossipFailure::ConflictingAttestation)
        )]);

        standalone.handler.on_status(40, 40);
        standalone.submit(4, 40, 7, 4, now);
        standalone.harness.pop_gossip();
        standalone.handler.on_status(70, 70);
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
            standalone.handler.on_status(10, 10);
            standalone.handler.on_status(11, 11);
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

        standalone.handler.on_status(10, 10);
        standalone.submit(2, 10, 7, 1, now);
        standalone.submit(3, 11, 7, 1, now);
        assert_eq!(standalone.harness.responses(), [
            (2, Err(LocalGossipFailure::BeforeStartupFloor)),
            (3, Err(LocalGossipFailure::Future)),
        ]);
        assert!(standalone.harness.gossip.pop_event().is_none());

        standalone.handler.on_status(11, 11);
        standalone.submit(4, 11, 7, 2, now);
        standalone.harness.pop_gossip();
        assert!(
            standalone.harness.responses().is_empty(),
            "rejected requests must not acquire locks"
        );

        standalone.handler.on_status(42, 44);
        standalone.submit(5, 11, 7, 2, now);
        assert_eq!(standalone.harness.responses(), [(5, Err(LocalGossipFailure::TooOld))]);

        standalone.handler.on_status(42, 43);
        assert_eq!(standalone.handler.admission.validate(11, 43), Ok(()));
        standalone.submit(6, 11, 7, 2, now);
        assert_eq!(standalone.harness.responses(), [(6, Err(LocalGossipFailure::TooOld))]);
        assert!(standalone.harness.gossip.pop_event().is_none());
    }

    #[test]
    fn startup_floor_latches_only_when_head_reaches_wall() {
        let mut handler = handler(Instant::now());

        handler.on_status(9, 10);
        assert_eq!(handler.admission.validate(10, 10), Err(AdmissionError::StartupFloorUnset));

        handler.on_status(10, 10);
        assert_eq!(
            handler.admission.validate(10, 10),
            Err(AdmissionError::BeforeStartupFloor { slot: 10, minimum: 11 })
        );

        handler.on_status(20, 20);
        assert_eq!(handler.admission.validate(11, 20), Ok(()), "floor must not relatch");
    }

    #[test]
    fn failed_cluster_rejects_pending_and_new_requests_without_standalone_fallback() {
        let now = Instant::now();
        let mut handler = handler(now);
        let mut harness = Harness::new();
        let mut submissions = Submissions::new();
        handler.cluster = Some(
            SlashingProtectionCluster::in_memory(
                SlashingProtectionConfig::new(
                    1,
                    vec![1],
                    ClusterStorageConfig::Create("unused-test-journal".into()),
                ),
                now,
            )
            .unwrap(),
        );
        handler.on_status(10, 10);
        handler.on_status(11, 11);
        handler.cluster.as_mut().unwrap().campaign().unwrap();
        handler.drive(
            now,
            &mut harness.local_gossip,
            &mut harness.gossip,
            &mut submissions.reader,
            &mut harness.adapter.producers,
        );

        let mut ssz = [0; SINGLE_ATT_SIZE];
        ssz[16..24].copy_from_slice(&11u64.to_le_bytes());
        let attestation = PendingAttestation::new(1, 0, ssz);
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
            &mut submissions.reader,
            &mut harness.adapter.producers,
        );
        assert_eq!(harness.responses(), [(1, Err(LocalGossipFailure::Internal))]);
        assert!(handler.pending_attestations.is_empty());
        assert!(handler.cluster.as_ref().unwrap().is_failed());

        handler.on_local_attestation(
            PendingAttestation { request_id: 2, ..attestation },
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
        LockResult::TooOld => Err(LocalGossipFailure::TooOld),
    }
}

/// The submission holds the whole `SignedBlockContents`, so the block is
/// copied rather than handed on as the submission's read.
fn block_message(request_id: u64, ssz: &[u8], slot: u64) -> LocalMessage<'_> {
    let topic = GossipTopic::BeaconBlock;
    LocalMessage { request_id, topic, ssz, ssz_read: None, slot }
}

fn proposal_failure(error: &ProposeError) -> LocalGossipFailure {
    match error {
        ProposeError::Admission(error) => admission_failure(*error),
        ProposeError::NotReady |
        ProposeError::Failed |
        ProposeError::SequenceExhausted |
        ProposeError::DeadlineOverflow |
        ProposeError::Raft(_) => LocalGossipFailure::Internal,
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
        }
    }
}
