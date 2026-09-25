use std::time::Instant;

use flux::spine::SpineAdapter;
use fxhash::FxHashMap;
use silver_common::{
    ClusterIn, ClusterMsgIn, ClusterMsgOut, GossipTopic, LocalGossipFailure, LocalGossipResult,
    SilverSpine, SilverSpineProducers, TCacheProducer, TCacheReader, TProducer,
    ssz_view::{SINGLE_ATT_SIZE, SingleAttestationView},
};
use silver_gossip::GossipHandler;

use super::local_validation::{LocalMessage, LocalValidation, produce_response};
use crate::cluster::{
    AdmissionError, AttestationAdmission, AttestationCluster, AttestationClusterConfig,
    AttestationDecision, AttestationKey, AttestationLockCommand, AttestationLockStore,
    ClusterError, ClusterEvent, LockResult, ProposalId, ProposeError, decode_message,
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

/// Slashing protection for local attestations: admission and a lock per
/// validator and epoch, agreed through Raft when clustered.
pub(super) struct AttestationClusterHandler {
    /// Encoded Raft messages are reserved here before `ClusterMsgOut` is
    /// published to the network tile.
    outbound_producer: TProducer,
    cluster: Option<AttestationCluster>,
    local_locks: AttestationLockStore,
    admission: AttestationAdmission,
    pending_attestations: FxHashMap<ProposalId, PendingAttestation>,
    wall_slot: u64,
}

impl AttestationClusterHandler {
    pub(super) fn loop_start(&mut self) {
        self.outbound_producer.loop_start();
    }

    pub(super) fn new(
        outbound_producer: TProducer,
        config: Option<AttestationClusterConfig>,
        now: Instant,
    ) -> Result<Self, ClusterError> {
        let cluster = config.map(|config| AttestationCluster::new(config, now)).transpose()?;

        Ok(Self {
            outbound_producer,
            cluster,
            local_locks: AttestationLockStore::default(),
            admission: AttestationAdmission::new(),
            pending_attestations: FxHashMap::default(),
            wall_slot: 0,
        })
    }

    pub(super) fn on_status(&mut self, head_slot: u64, wall_slot: u64) {
        self.wall_slot = wall_slot;
        if self.cluster.is_none() {
            self.local_locks.advance_minimum_slot(AttestationAdmission::age_floor(wall_slot));
        }
        if head_slot != wall_slot || !self.admission.set_startup_wall_slot(wall_slot) {
            return;
        }

        if let Some(cluster) = self.cluster.as_mut() {
            let initialized = cluster.set_startup_wall_slot(wall_slot);
            debug_assert!(initialized, "handler and cluster startup floors latch together");
        }
        tracing::info!(wall_slot, "local attestation admission enabled");
    }

    /// Consume inbound Raft messages and pump all work currently ready in the
    /// state machine. This is called once per Control tile loop and never
    /// waits for network or timer work.
    pub(super) fn spin(
        &mut self,
        now: Instant,
        adapter: &mut SpineAdapter<SilverSpine>,
        validation: &mut LocalValidation,
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
        self.drive(now, validation, gossip_handler, &mut adapter.producers);
    }

    pub(super) fn on_local_attestation(
        &mut self,
        attestation: PendingAttestation,
        now: Instant,
        validation: &mut LocalValidation,
        gossip_handler: &mut GossipHandler,
        producers: &mut SilverSpineProducers,
    ) {
        if let Err(error) = self.admission.validate(attestation.command.key.slot, self.wall_slot) {
            produce_response(producers, attestation.request_id, Err(admission_failure(error)));
            tracing::warn!(
                ?error,
                request_id = attestation.request_id,
                slot = attestation.command.key.slot,
                "local attestation rejected before cluster proposal"
            );
            return;
        }

        let Some(cluster) = self.cluster.as_mut() else {
            let result = self.local_locks.apply(&attestation.command);
            let response = lock_response(result);
            if response.is_err() {
                produce_response(producers, attestation.request_id, response);
                tracing::warn!(
                    ?result,
                    request_id = attestation.request_id,
                    slot = attestation.command.key.slot,
                    "local lock rejected attestation"
                );
                return;
            }
            validation.submit(
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
                tracing::warn!(
                    ?error,
                    request_id = attestation.request_id,
                    slot = attestation.command.key.slot,
                    "cluster rejected local attestation"
                );
            }
        }
    }

    fn handle_message(&mut self, inbound: ClusterMsgIn, inbound_consumer: &mut TCacheReader) {
        let Some(acquired) = inbound_consumer.acquire_strict(inbound.data) else {
            tracing::warn!(
                from = inbound.from,
                seq = inbound.data.seq(),
                "cluster inbound TCache read is no longer available"
            );
            return;
        };
        let Ok((bytes, _)) = acquired.buffer() else {
            tracing::warn!(
                from = inbound.from,
                seq = inbound.data.seq(),
                "failed to read cluster inbound TCache message"
            );
            return;
        };

        let Some(cluster) = self.cluster.as_mut() else {
            tracing::debug!(
                from = inbound.from,
                "ignoring cluster message while clustering is disabled"
            );
            return;
        };
        let message = match decode_message(bytes) {
            Ok(message) => message,
            Err(error) => {
                tracing::warn!(?error, from = inbound.from, "invalid inbound Raft message");
                return;
            }
        };
        if message.from != inbound.from {
            tracing::warn!(
                authenticated_from = inbound.from,
                encoded_from = message.from,
                "inbound Raft message source does not match authenticated cluster peer"
            );
            return;
        }
        if message.to != cluster.node_id() {
            tracing::warn!(
                from = inbound.from,
                encoded_to = message.to,
                local_node = cluster.node_id(),
                "inbound Raft message addressed to another cluster node"
            );
            return;
        }
        if let Err(error) = cluster.step(message) {
            tracing::warn!(?error, from = inbound.from, "failed to step inbound Raft message");
        }
    }

    fn drive(
        &mut self,
        now: Instant,
        validation: &mut LocalValidation,
        gossip_handler: &mut GossipHandler,
        producers: &mut SilverSpineProducers,
    ) {
        let Some(cluster) = self.cluster.as_mut() else {
            return;
        };

        let pending_attestations = &mut self.pending_attestations;
        let outbound_producer = &mut self.outbound_producer;
        let result = cluster.spin(now, self.wall_slot, |event| match event {
            ClusterEvent::SendRaftMessage(message) => {
                let to = message.to;
                match encode_message(message, outbound_producer) {
                    Ok(data) => {
                        producers.cluster_outbound.produce(&ClusterMsgOut { to, data }.into());
                    }
                    Err(error) => {
                        tracing::warn!(?error, to, "failed to buffer outbound Raft message")
                    }
                }
            }
            ClusterEvent::AttestationCommitted(decision) => {
                let Some(attestation) = pending_attestations.remove(&decision.proposal_id) else {
                    tracing::warn!(
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
                    tracing::error!(
                        ?decision.proposal_id,
                        request_id = attestation.request_id,
                        "committed Raft command does not match its pending attestation"
                    );
                    return;
                }
                let response = decision_response(&decision);
                if response.is_ok() {
                    validation.submit(
                        decision.command.local_message(attestation.request_id),
                        now,
                        gossip_handler,
                        producers,
                    );
                } else {
                    produce_response(producers, attestation.request_id, response);
                    tracing::warn!(
                        ?decision.result,
                        ?decision.admission,
                        request_id = attestation.request_id,
                        slot = attestation.command.key.slot,
                        "committed attestation cannot enter validation"
                    );
                }
            }
            ClusterEvent::AttestationProposalTimedOut(proposal_id) => {
                if let Some(attestation) = pending_attestations.remove(&proposal_id) {
                    produce_response(
                        producers,
                        attestation.request_id,
                        Err(LocalGossipFailure::TimedOut),
                    );
                    tracing::warn!(
                        ?proposal_id,
                        request_id = attestation.request_id,
                        slot = attestation.command.key.slot,
                        "attestation cluster proposal timed out"
                    );
                }
            }
        });
        if let Err(error) = result {
            tracing::error!(?error, "attestation cluster spin failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use silver_common::{TCache, TCacheId};

    use super::*;
    use crate::tile::local_validation::{VALIDATION_TIMEOUT, tests::Harness};

    fn handler(now: Instant) -> AttestationClusterHandler {
        AttestationClusterHandler::new(
            TCache::producer(TCacheId::ClusterOutbound, 1 << 12),
            None,
            now,
        )
        .unwrap()
    }

    struct Standalone {
        handler: AttestationClusterHandler,
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
            let Harness { validation, gossip, adapter, .. } = &mut self.harness;
            self.handler.on_local_attestation(
                PendingAttestation::new(request_id, 0, ssz),
                now,
                validation,
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
        assert!(standalone.harness.validation.is_empty());

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
                    .validation
                    .expire(now + VALIDATION_TIMEOUT, &mut standalone.harness.adapter.producers),
                failure => standalone.harness.complete(message.msg_hash, Err(failure)),
            }
            assert_eq!(standalone.harness.responses(), [(1, Err(failure))]);
            assert!(standalone.harness.validation.is_empty());

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
}

fn decision_response(decision: &AttestationDecision) -> LocalGossipResult {
    if let Err(error) = decision.admission {
        return Err(admission_failure(error));
    }

    lock_response(decision.result)
}

fn lock_response(result: LockResult) -> LocalGossipResult {
    match result {
        LockResult::Accepted | LockResult::AlreadyAcceptedSame => Ok(()),
        LockResult::ConflictingAttestation => Err(LocalGossipFailure::ConflictingAttestation),
        LockResult::TooOld => Err(LocalGossipFailure::TooOld),
    }
}

fn proposal_failure(error: &ProposeError) -> LocalGossipFailure {
    match error {
        ProposeError::Admission(error) => admission_failure(*error),
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
