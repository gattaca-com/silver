use std::time::{Duration, Instant};

use flux::spine::SpineAdapter;
use fxhash::FxHashMap;
use silver_common::{
    BeaconApiRequest, BeaconApiResponse, ClusterIn, ClusterMsgIn, ClusterMsgOut, GossipTopic,
    LocalAttestationFailure, LocalAttestationResult, MessageId, Nanos, PeerEvent, SilverSpine,
    SilverSpineProducers, TProducer, TRandomAccess, ssz_view::SingleAttestationView,
};
use silver_gossip::GossipHandler;

use crate::cluster::{
    AdmissionError, AttestationAdmission, AttestationCluster, AttestationClusterConfig,
    AttestationDecision, AttestationKey, AttestationLockCommand, AttestationLockStore,
    ClusterError, ClusterEvent, LockResult, ProposalId, ProposeError, decode_message,
    encode_message,
};

const LOCAL_ATTESTATION_VALIDATION_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Copy)]
struct PendingAttestation {
    request_id: u64,
    command: AttestationLockCommand,
}

#[derive(Debug)]
struct PendingValidation {
    request: Option<PendingValidationRequest>,
    duplicate_requests: Vec<PendingValidationRequest>,
}

#[derive(Debug, Clone, Copy)]
struct PendingValidationRequest {
    request_id: u64,
    deadline: Instant,
}

impl PendingValidation {
    fn new(request: PendingValidationRequest) -> Self {
        Self { request: Some(request), duplicate_requests: Vec::new() }
    }

    fn push(&mut self, request: PendingValidationRequest) {
        self.duplicate_requests.push(request);
    }

    fn complete(self, mut emit: impl FnMut(u64)) {
        if let Some(request) = self.request {
            emit(request.request_id);
        }
        for request in self.duplicate_requests {
            emit(request.request_id);
        }
    }

    fn expire(&mut self, now: Instant, emit: &mut impl FnMut(u64)) -> usize {
        let mut expired = 0;
        if self.request.is_some_and(|request| request.deadline <= now) {
            let request = self.request.take().unwrap();
            emit(request.request_id);
            expired += 1;
        }
        self.duplicate_requests.retain(|request| {
            if request.deadline > now {
                return true;
            }
            emit(request.request_id);
            expired += 1;
            false
        });
        expired
    }

    fn next_deadline(&self) -> Option<Instant> {
        self.request
            .map(|request| request.deadline)
            .into_iter()
            .chain(self.duplicate_requests.iter().map(|request| request.deadline))
            .min()
    }
}

/// Local attestation admission and validation, with optional Raft consensus.
pub(super) struct AttestationClusterHandler {
    /// Encoded Raft messages are reserved here before `ClusterMsgOut` is
    /// published to the network tile.
    outbound_producer: TProducer,
    /// Acquires encoded Raft messages referenced by `ClusterMsgIn` while the
    /// cluster state machine processes them.
    inbound_consumer: TRandomAccess,
    cluster: Option<AttestationCluster>,
    local_locks: AttestationLockStore,
    admission: AttestationAdmission,
    pending_attestations: FxHashMap<ProposalId, PendingAttestation>,
    pending_validation: FxHashMap<MessageId, PendingValidation>,
    next_validation_deadline: Option<Instant>,
    wall_slot: u64,
}

impl AttestationClusterHandler {
    pub(super) fn new(
        outbound_producer: TProducer,
        inbound_consumer: TRandomAccess,
        config: Option<AttestationClusterConfig>,
        now: Instant,
    ) -> Result<Self, ClusterError> {
        let cluster = config.map(|config| AttestationCluster::new(config, now)).transpose()?;

        Ok(Self {
            outbound_producer,
            inbound_consumer,
            cluster,
            local_locks: AttestationLockStore::default(),
            admission: AttestationAdmission::new(),
            pending_attestations: FxHashMap::default(),
            pending_validation: FxHashMap::default(),
            next_validation_deadline: None,
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

    pub(super) fn on_beacon_api_request(
        &mut self,
        request: BeaconApiRequest,
        now: Instant,
        gossip_handler: &mut GossipHandler,
        producers: &mut SilverSpineProducers,
    ) {
        match request {
            BeaconApiRequest::LocalAttestation { request_id, validator_pubkey, subnet, ssz } => {
                let slot = SingleAttestationView::slot(&ssz);
                self.handle_local_attestation(
                    PendingAttestation {
                        request_id,
                        command: AttestationLockCommand {
                            key: AttestationKey { validator_pubkey, slot },
                            subnet,
                            ssz,
                        },
                    },
                    now,
                    gossip_handler,
                    producers,
                );
            }
        }
    }

    pub(super) fn free(&mut self) {
        self.inbound_consumer.free();
    }

    /// Complete locally-originated requests only once Beacon State has
    /// accepted the message for publication or rejected it as invalid.
    pub(super) fn on_peer_event(
        &mut self,
        event: &PeerEvent,
        producers: &mut SilverSpineProducers,
    ) {
        let (msg_id, response) = match event {
            PeerEvent::SendGossip { msg_hash, .. } => (*msg_hash, LocalAttestationResult::Success),
            PeerEvent::P2pGossipInvalidMsg { hash, .. } => {
                (*hash, LocalAttestationResult::Failure(LocalAttestationFailure::Invalid))
            }
            _ => return,
        };

        if let Some(pending) = self.pending_validation.remove(&msg_id) {
            pending.complete(|request_id| produce_response(producers, request_id, response));
            if self.pending_validation.is_empty() {
                self.next_validation_deadline = None;
            }
        }
    }

    pub(super) fn expire_pending_validation(
        &mut self,
        now: Instant,
        producers: &mut SilverSpineProducers,
    ) {
        if self.next_validation_deadline.is_none_or(|deadline| deadline > now) {
            return;
        }

        let mut next_deadline = None;
        self.pending_validation.retain(|msg_id, pending| {
            let expired = pending.expire(now, &mut |request_id| {
                produce_response(
                    producers,
                    request_id,
                    LocalAttestationResult::Failure(LocalAttestationFailure::TimedOut),
                );
            });
            if expired > 0 {
                tracing::warn!(?msg_id, expired, "local attestation validation timed out");
            }
            if let Some(deadline) = pending.next_deadline() {
                next_deadline =
                    Some(next_deadline.map_or(deadline, |current: Instant| current.min(deadline)));
                true
            } else {
                false
            }
        });
        self.next_validation_deadline = next_deadline;
    }

    /// Consume inbound Raft messages and pump all work currently ready in the
    /// state machine. This is called once per Control tile loop and never
    /// waits for network or timer work.
    pub(super) fn spin(
        &mut self,
        now: Instant,
        adapter: &mut SpineAdapter<SilverSpine>,
        gossip_handler: &mut GossipHandler,
    ) {
        adapter.consume(|message: ClusterIn, _producers| match message {
            ClusterIn::Msg(message) => self.handle_message(message),
            ClusterIn::NodeUnreachable(id) => {
                if let Some(cluster) = self.cluster.as_mut() {
                    cluster.report_unreachable(id);
                }
            }
        });
        self.drive(now, gossip_handler, &mut adapter.producers);
    }

    fn handle_local_attestation(
        &mut self,
        attestation: PendingAttestation,
        now: Instant,
        gossip_handler: &mut GossipHandler,
        producers: &mut SilverSpineProducers,
    ) {
        if let Err(error) = self.admission.validate(attestation.command.key.slot, self.wall_slot) {
            produce_response(
                producers,
                attestation.request_id,
                LocalAttestationResult::Failure(admission_failure(error)),
            );
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
            if response != LocalAttestationResult::Success {
                produce_response(producers, attestation.request_id, response);
                tracing::warn!(
                    ?result,
                    request_id = attestation.request_id,
                    slot = attestation.command.key.slot,
                    "local lock rejected attestation"
                );
                return;
            }
            inject_attestation(
                &mut self.pending_validation,
                &mut self.next_validation_deadline,
                gossip_handler,
                producers,
                now,
                attestation.request_id,
                attestation.command,
            );
            return;
        };

        match cluster.propose_attestation(attestation.command, self.wall_slot, now) {
            Ok(proposal_id) => {
                let previous = self.pending_attestations.insert(proposal_id, attestation);
                debug_assert!(previous.is_none(), "proposal IDs are unique per node");
            }
            Err(error) => {
                produce_response(
                    producers,
                    attestation.request_id,
                    LocalAttestationResult::Failure(proposal_failure(&error)),
                );
                tracing::warn!(
                    ?error,
                    request_id = attestation.request_id,
                    slot = attestation.command.key.slot,
                    "cluster rejected local attestation"
                );
            }
        }
    }

    fn handle_message(&mut self, inbound: ClusterMsgIn) {
        let Some(acquired) = self.inbound_consumer.acquire_strict(inbound.data) else {
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
        gossip_handler: &mut GossipHandler,
        producers: &mut SilverSpineProducers,
    ) {
        let Some(cluster) = self.cluster.as_mut() else {
            return;
        };

        let pending_attestations = &mut self.pending_attestations;
        let pending_validation = &mut self.pending_validation;
        let next_validation_deadline = &mut self.next_validation_deadline;
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
                        LocalAttestationResult::Failure(LocalAttestationFailure::Internal),
                    );
                    tracing::error!(
                        ?decision.proposal_id,
                        request_id = attestation.request_id,
                        "committed Raft command does not match its pending attestation"
                    );
                    return;
                }
                let response = decision_response(&decision);
                if response == LocalAttestationResult::Success {
                    inject_attestation(
                        pending_validation,
                        next_validation_deadline,
                        gossip_handler,
                        producers,
                        now,
                        attestation.request_id,
                        decision.command,
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
                        LocalAttestationResult::Failure(LocalAttestationFailure::TimedOut),
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
    use flux::tile::Tile;
    use silver_common::{NewGossipMsg, TCache, TCacheProducer, ssz_view::SINGLE_ATT_SIZE};
    use silver_gossip::GossipHandlerEvent;
    use tempfile::TempDir;

    use super::*;

    fn handler(now: Instant) -> AttestationClusterHandler {
        let inbound = TCache::producer("test_attestation_cluster_in", 1 << 12);
        let inbound_consumer = inbound
            .cache_ref()
            .strict_random_access("test_attestation_cluster_handler", true)
            .unwrap();
        AttestationClusterHandler::new(
            TCache::producer("test_attestation_cluster_out", 1 << 12),
            inbound_consumer,
            None,
            now,
        )
        .unwrap()
    }

    struct TestTile;

    impl Tile<SilverSpine> for TestTile {
        fn loop_body(&mut self, _adapter: &mut SpineAdapter<SilverSpine>) {}
    }

    struct Standalone {
        handler: AttestationClusterHandler,
        gossip: GossipHandler,
        adapter: SpineAdapter<SilverSpine>,
        _spine: Box<SilverSpine>,
        _base: TempDir,
    }

    impl Standalone {
        fn new(now: Instant) -> Self {
            let base = TempDir::new().unwrap();
            let mut spine = Box::new(SilverSpine::new_with_base_dir(base.path(), None));
            let mut adapter = SpineAdapter::connect_tile(&TestTile, &mut spine);
            // The consumer attaches at the current head on its first read.
            adapter.consume(|_: BeaconApiResponse, _| panic!("unexpected initial response"));
            let incoming = TCache::producer("standalone_gossip_in", 1 << 12);
            let gossip = GossipHandler::new(
                incoming.cache_ref().random_access("standalone_gossip", true).unwrap(),
                TCache::producer("standalone_gossip_ssz", 1 << 12),
                TCache::producer("standalone_gossip_protobuf", 1 << 12),
                "01020304".to_owned(),
            )
            .unwrap();
            Self { handler: handler(now), gossip, adapter, _spine: spine, _base: base }
        }

        fn submit(&mut self, request_id: u64, slot: u64, validator: u8, root: u8, now: Instant) {
            let mut ssz = [0; SINGLE_ATT_SIZE];
            ssz[8..16].copy_from_slice(&u64::from(validator).to_le_bytes());
            ssz[16..24].copy_from_slice(&slot.to_le_bytes());
            ssz[32..64].fill(root);
            self.handler.on_beacon_api_request(
                BeaconApiRequest::LocalAttestation {
                    request_id,
                    validator_pubkey: [validator; 48],
                    subnet: 0,
                    ssz,
                },
                now,
                &mut self.gossip,
                &mut self.adapter.producers,
            );
        }

        fn pop_gossip(&mut self) -> NewGossipMsg {
            match self.gossip.pop_event().expect("attestation enters validation") {
                GossipHandlerEvent::NewGossip(message) => message,
                _ => panic!("unexpected gossip event"),
            }
        }

        fn responses(&mut self) -> Vec<(u64, LocalAttestationResult)> {
            let mut responses = Vec::new();
            self.adapter.consume(|response: BeaconApiResponse, _| match response {
                BeaconApiResponse::LocalAttestationResponse { request_id, response } => {
                    responses.push((request_id, response));
                }
            });
            responses
        }
    }

    #[test]
    fn standalone_locks_before_validation_and_allows_identical_retries() {
        let now = Instant::now();
        let mut standalone = Standalone::new(now);
        standalone.handler.on_status(10, 10);
        standalone.handler.on_status(11, 11);

        standalone.submit(1, 11, 7, 1, now);
        let message = standalone.pop_gossip();
        assert!(standalone.responses().is_empty());
        assert!(standalone.handler.cluster.is_none());
        assert!(standalone.handler.pending_attestations.is_empty());

        standalone.submit(2, 11, 7, 1, now);
        assert_eq!(standalone.pop_gossip().msg_hash, message.msg_hash);
        assert!(standalone.responses().is_empty());

        standalone.submit(3, 11, 7, 2, now);
        assert_eq!(standalone.responses(), [(
            3,
            LocalAttestationResult::Failure(LocalAttestationFailure::ConflictingAttestation)
        )]);
        assert!(standalone.gossip.pop_event().is_none());

        standalone.handler.on_peer_event(
            &PeerEvent::SendGossip {
                originator_stream_id: message.stream_id,
                topic: message.topic,
                msg_hash: message.msg_hash,
                recv_ts: message.recv_ts,
                protobuf: message.protobuf,
            },
            &mut standalone.adapter.producers,
        );
        assert_eq!(standalone.responses(), [
            (1, LocalAttestationResult::Success),
            (2, LocalAttestationResult::Success)
        ]);
        assert!(standalone.handler.pending_validation.is_empty());

        standalone.submit(4, 11, 7, 2, now);
        assert_eq!(standalone.responses(), [(
            4,
            LocalAttestationResult::Failure(LocalAttestationFailure::ConflictingAttestation)
        )]);
        assert!(standalone.gossip.pop_event().is_none());
        standalone.submit(5, 11, 7, 1, now);
        assert_eq!(standalone.pop_gossip().msg_hash, message.msg_hash);
        assert!(standalone.responses().is_empty());
    }

    #[test]
    fn standalone_locks_are_per_validator_and_slot_and_survive_ring_reuse() {
        let now = Instant::now();
        let mut standalone = Standalone::new(now);
        standalone.handler.on_status(10, 10);
        standalone.handler.on_status(12, 12);

        standalone.submit(1, 11, 7, 1, now);
        standalone.pop_gossip();
        standalone.submit(2, 11, 8, 2, now);
        standalone.pop_gossip();
        standalone.submit(3, 12, 7, 3, now);
        standalone.pop_gossip();
        assert!(standalone.responses().is_empty());

        standalone.handler.on_status(43, 43);
        standalone.submit(4, 43, 7, 4, now);
        standalone.pop_gossip();
        standalone.submit(5, 11, 7, 5, now);
        standalone.submit(6, 43, 7, 5, now);
        standalone.submit(7, 12, 7, 5, now);
        assert_eq!(standalone.responses(), [
            (5, LocalAttestationResult::Failure(LocalAttestationFailure::TooOld)),
            (6, LocalAttestationResult::Failure(LocalAttestationFailure::ConflictingAttestation)),
            (7, LocalAttestationResult::Failure(LocalAttestationFailure::ConflictingAttestation)),
        ]);
        assert!(standalone.gossip.pop_event().is_none());
    }

    #[test]
    fn standalone_keeps_locks_after_validation_failure_or_timeout() {
        for failure in [LocalAttestationFailure::Invalid, LocalAttestationFailure::TimedOut] {
            let now = Instant::now();
            let mut standalone = Standalone::new(now);
            standalone.handler.on_status(10, 10);
            standalone.handler.on_status(11, 11);
            standalone.submit(1, 11, 7, 1, now);
            let message = standalone.pop_gossip();

            if failure == LocalAttestationFailure::Invalid {
                standalone.handler.on_peer_event(
                    &PeerEvent::P2pGossipInvalidMsg {
                        p2p_peer: message.stream_id.peer(),
                        topic: message.topic,
                        hash: message.msg_hash,
                    },
                    &mut standalone.adapter.producers,
                );
            } else {
                standalone.handler.expire_pending_validation(
                    now + LOCAL_ATTESTATION_VALIDATION_TIMEOUT,
                    &mut standalone.adapter.producers,
                );
            }
            assert_eq!(standalone.responses(), [(1, LocalAttestationResult::Failure(failure))]);
            assert!(standalone.handler.pending_validation.is_empty());

            standalone.submit(2, 11, 7, 2, now + LOCAL_ATTESTATION_VALIDATION_TIMEOUT);
            assert_eq!(standalone.responses(), [(
                2,
                LocalAttestationResult::Failure(LocalAttestationFailure::ConflictingAttestation)
            )]);
            assert!(standalone.gossip.pop_event().is_none());
        }
    }

    #[test]
    fn standalone_admission_precedes_locking_and_retention_never_regresses() {
        let now = Instant::now();
        let mut standalone = Standalone::new(now);
        standalone.submit(1, 11, 7, 1, now);
        assert_eq!(standalone.responses(), [(
            1,
            LocalAttestationResult::Failure(LocalAttestationFailure::NotSynced)
        )]);

        standalone.handler.on_status(10, 10);
        standalone.submit(2, 10, 7, 1, now);
        standalone.submit(3, 11, 7, 1, now);
        assert_eq!(standalone.responses(), [
            (2, LocalAttestationResult::Failure(LocalAttestationFailure::BeforeStartupFloor)),
            (3, LocalAttestationResult::Failure(LocalAttestationFailure::Future)),
        ]);
        assert!(standalone.gossip.pop_event().is_none());

        standalone.handler.on_status(11, 11);
        standalone.submit(4, 11, 7, 2, now);
        standalone.pop_gossip();
        assert!(standalone.responses().is_empty(), "rejected requests must not acquire locks");

        standalone.handler.on_status(42, 44);
        standalone.submit(5, 11, 7, 2, now);
        assert_eq!(standalone.responses(), [(
            5,
            LocalAttestationResult::Failure(LocalAttestationFailure::TooOld)
        )]);

        standalone.handler.on_status(42, 43);
        assert_eq!(standalone.handler.admission.validate(11, 43), Ok(()));
        standalone.submit(6, 11, 7, 2, now);
        assert_eq!(standalone.responses(), [(
            6,
            LocalAttestationResult::Failure(LocalAttestationFailure::TooOld)
        )]);
        assert!(standalone.gossip.pop_event().is_none());
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
    fn pending_validation_completes_all_requests() {
        let now = Instant::now();
        let mut pending = PendingValidation::new(PendingValidationRequest {
            request_id: 11,
            deadline: now + Duration::from_secs(1),
        });
        pending.push(PendingValidationRequest {
            request_id: 12,
            deadline: now + Duration::from_secs(1),
        });

        let mut completed = Vec::new();
        pending.complete(|request_id| completed.push(request_id));

        assert_eq!(completed, [11, 12]);
    }

    #[test]
    fn pending_validation_requests_expire_independently() {
        let now = Instant::now();
        let mut pending = PendingValidation::new(PendingValidationRequest {
            request_id: 21,
            deadline: now + Duration::from_millis(10),
        });
        pending.push(PendingValidationRequest {
            request_id: 22,
            deadline: now + Duration::from_millis(20),
        });

        let mut expired = Vec::new();
        pending.expire(now + Duration::from_millis(10), &mut |request_id| {
            expired.push(request_id);
        });
        assert_eq!(expired, [21]);
        assert!(pending.next_deadline().is_some());

        pending.expire(now + Duration::from_millis(20), &mut |request_id| {
            expired.push(request_id);
        });
        assert_eq!(expired, [21, 22]);
        assert!(pending.next_deadline().is_none());
    }
}

fn produce_response(
    producers: &mut SilverSpineProducers,
    request_id: u64,
    response: LocalAttestationResult,
) {
    producers
        .beacon_api_responses
        .produce(&BeaconApiResponse::LocalAttestationResponse { request_id, response }.into());
}

fn decision_response(decision: &AttestationDecision) -> LocalAttestationResult {
    if let Err(error) = decision.admission {
        return LocalAttestationResult::Failure(admission_failure(error));
    }

    lock_response(decision.result)
}

fn lock_response(result: LockResult) -> LocalAttestationResult {
    match result {
        LockResult::Accepted | LockResult::AlreadyAcceptedSame => LocalAttestationResult::Success,
        LockResult::ConflictingAttestation => {
            LocalAttestationResult::Failure(LocalAttestationFailure::ConflictingAttestation)
        }
        LockResult::TooOld => LocalAttestationResult::Failure(LocalAttestationFailure::TooOld),
    }
}

fn proposal_failure(error: &ProposeError) -> LocalAttestationFailure {
    match error {
        ProposeError::Admission(error) => admission_failure(*error),
        ProposeError::SequenceExhausted |
        ProposeError::DeadlineOverflow |
        ProposeError::Raft(_) => LocalAttestationFailure::Internal,
    }
}

fn admission_failure(error: AdmissionError) -> LocalAttestationFailure {
    match error {
        AdmissionError::StartupFloorUnset => LocalAttestationFailure::NotSynced,
        AdmissionError::BeforeStartupFloor { .. } => LocalAttestationFailure::BeforeStartupFloor,
        AdmissionError::TooOld { .. } => LocalAttestationFailure::TooOld,
        AdmissionError::Future { .. } => LocalAttestationFailure::Future,
    }
}

fn inject_attestation(
    pending_validation: &mut FxHashMap<MessageId, PendingValidation>,
    next_validation_deadline: &mut Option<Instant>,
    gossip_handler: &mut GossipHandler,
    producers: &mut SilverSpineProducers,
    now: Instant,
    request_id: u64,
    command: AttestationLockCommand,
) {
    let topic = GossipTopic::BeaconAttestation(command.subnet);
    match gossip_handler.inject_local(topic, &command.ssz, Nanos::now()) {
        Ok(Some(msg_id)) => {
            let request = PendingValidationRequest {
                request_id,
                deadline: now + LOCAL_ATTESTATION_VALIDATION_TIMEOUT,
            };
            *next_validation_deadline = Some(
                next_validation_deadline
                    .map_or(request.deadline, |deadline| deadline.min(request.deadline)),
            );
            pending_validation
                .entry(msg_id)
                .and_modify(|pending| pending.push(request))
                .or_insert_with(|| PendingValidation::new(request));
        }
        Ok(None) => {
            produce_response(
                producers,
                request_id,
                LocalAttestationResult::Failure(LocalAttestationFailure::Internal),
            );
            tracing::warn!(
                request_id,
                slot = command.key.slot,
                ?topic,
                "gossip is not ready to validate committed local attestation"
            );
        }
        Err(error) => {
            produce_response(
                producers,
                request_id,
                LocalAttestationResult::Failure(LocalAttestationFailure::Internal),
            );
            tracing::warn!(
                ?error,
                request_id,
                slot = command.key.slot,
                ?topic,
                "failed to inject committed local attestation for validation"
            );
        }
    }
}
