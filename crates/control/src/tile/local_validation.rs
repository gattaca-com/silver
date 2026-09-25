use std::time::{Duration, Instant};

use fxhash::FxHashMap;
use silver_common::{
    BeaconApiResponse, GossipTopic, LocalGossipFailure, LocalGossipResult, MessageId, Nanos,
    SilverSpineProducers, TCacheRead,
};
use silver_gossip::GossipHandler;

pub(super) const VALIDATION_TIMEOUT: Duration = Duration::from_secs(1);

/// Locally submitted gossip messages awaiting Beacon State's verdict. Requests
/// that inject identical bytes share one message id and complete together.
#[derive(Default)]
pub(super) struct LocalValidation {
    pending: FxHashMap<MessageId, Vec<PendingValidationRequest>>,
    next_deadline: Option<Instant>,
}

/// One locally built gossip message on its way into Beacon State validation.
pub(super) struct LocalMessage<'a> {
    pub(super) request_id: u64,
    pub(super) topic: GossipTopic,
    pub(super) ssz: &'a [u8],
    pub(super) ssz_read: Option<TCacheRead>,
    pub(super) slot: u64,
}

impl LocalValidation {
    pub(super) fn submit(
        &mut self,
        message: LocalMessage<'_>,
        now: Instant,
        gossip_handler: &mut GossipHandler,
        producers: &mut SilverSpineProducers,
    ) {
        let LocalMessage { request_id, topic, ssz, ssz_read, slot } = message;
        match gossip_handler.inject_local(topic, ssz, ssz_read, Nanos::now()) {
            Ok(Some(msg_id)) => {
                let request =
                    PendingValidationRequest { request_id, deadline: now + VALIDATION_TIMEOUT };
                self.next_deadline = Some(
                    self.next_deadline
                        .map_or(request.deadline, |deadline| deadline.min(request.deadline)),
                );
                self.pending.entry(msg_id).or_default().push(request);
            }
            Ok(None) => {
                produce_response(producers, request_id, Err(LocalGossipFailure::Internal));
                tracing::warn!(
                    request_id,
                    slot,
                    ?topic,
                    "gossip is not ready to validate local message"
                );
            }
            Err(error) => {
                produce_response(producers, request_id, Err(LocalGossipFailure::Internal));
                tracing::warn!(
                    ?error,
                    request_id,
                    slot,
                    ?topic,
                    "failed to inject local message for validation"
                );
            }
        }
    }

    pub(super) fn complete(
        &mut self,
        msg_id: MessageId,
        response: LocalGossipResult,
        producers: &mut SilverSpineProducers,
    ) {
        if let Some(requests) = self.pending.remove(&msg_id) {
            for request in requests {
                produce_response(producers, request.request_id, response);
            }
            if self.pending.is_empty() {
                self.next_deadline = None;
            }
        }
    }

    pub(super) fn expire(&mut self, now: Instant, producers: &mut SilverSpineProducers) {
        if self.next_deadline.is_none_or(|deadline| deadline > now) {
            return;
        }

        let mut next_deadline = None;
        self.pending.retain(|msg_id, requests| {
            let before = requests.len();
            requests.retain(|request| {
                if request.deadline > now {
                    return true;
                }
                produce_response(producers, request.request_id, Err(LocalGossipFailure::TimedOut));
                false
            });
            let expired = before - requests.len();
            if expired > 0 {
                tracing::warn!(?msg_id, expired, "local message validation timed out");
            }
            if let Some(earliest) = requests.iter().map(|request| request.deadline).min() {
                next_deadline =
                    Some(next_deadline.map_or(earliest, |current: Instant| current.min(earliest)));
            }
            !requests.is_empty()
        });
        self.next_deadline = next_deadline;
    }

    #[cfg(test)]
    pub(super) fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
}

pub(super) fn produce_response(
    producers: &mut SilverSpineProducers,
    request_id: u64,
    response: LocalGossipResult,
) {
    producers
        .beacon_api_responses
        .produce(&BeaconApiResponse::LocalGossipResponse { request_id, response }.into());
}

#[derive(Debug, Clone, Copy)]
struct PendingValidationRequest {
    request_id: u64,
    deadline: Instant,
}

#[cfg(test)]
pub(super) mod tests {
    use flux::{spine::SpineAdapter, tile::Tile};
    use silver_common::{
        NewGossipMsg, SilverSpine, TCache, TCacheId, TCacheProducer, TCacheTable,
        ssz_view::SIGNED_AGG_PROOF_MIN,
    };
    use silver_gossip::GossipHandlerEvent;
    use tempfile::TempDir;

    use super::*;

    struct TestTile;

    impl Tile<SilverSpine> for TestTile {
        fn loop_body(&mut self, _adapter: &mut SpineAdapter<SilverSpine>) {}
    }

    /// A gossip handler and a spine to inject into and answer through.
    pub(in crate::tile) struct Harness {
        pub(in crate::tile) validation: LocalValidation,
        pub(in crate::tile) gossip: GossipHandler,
        pub(in crate::tile) adapter: SpineAdapter<SilverSpine>,
        _spine: Box<SilverSpine>,
        _base: TempDir,
    }

    impl Harness {
        pub(in crate::tile) fn new() -> Self {
            let base = TempDir::new().unwrap();
            let mut spine = Box::new(SilverSpine::new_with_base_dir(base.path(), None));
            let mut adapter = SpineAdapter::connect_tile(&TestTile, &mut spine);
            // The consumer attaches at the current head on its first read.
            adapter.consume(|_: BeaconApiResponse, _| panic!("unexpected initial response"));
            let incoming = TCache::producer(TCacheId::NetworkIngress, 1 << 12);
            let protobuf = TCache::producer(TCacheId::ControlGossip, 1 << 12);
            let mut gossip = GossipHandler::new(
                TCacheTable::from_iter([incoming.cache_ref(), protobuf.cache_ref()]),
                TCache::producer(TCacheId::ControlProcessing, 1 << 12),
                protobuf,
                Some(silver_common::GossipDomain::new([1, 2, 3, 4], silver_common::ForkName::Fulu)),
            )
            .unwrap();
            gossip.open_tcaches().unwrap();
            Self {
                validation: LocalValidation::default(),
                gossip,
                adapter,
                _spine: spine,
                _base: base,
            }
        }

        pub(in crate::tile) fn pop_gossip(&mut self) -> NewGossipMsg {
            match self.gossip.pop_event().expect("message enters validation") {
                GossipHandlerEvent::NewGossip(message) => message,
                _ => panic!("unexpected gossip event"),
            }
        }

        pub(in crate::tile) fn responses(&mut self) -> Vec<(u64, LocalGossipResult)> {
            let mut responses = Vec::new();
            self.adapter.consume(|response: BeaconApiResponse, _| match response {
                BeaconApiResponse::LocalGossipResponse { request_id, response } => {
                    responses.push((request_id, response));
                }
                BeaconApiResponse::AggregateAttestation { .. } |
                BeaconApiResponse::SyncCommitteeContribution { .. } |
                BeaconApiResponse::Block { .. } => {}
            });
            responses
        }

        pub(in crate::tile) fn complete(&mut self, msg_id: MessageId, response: LocalGossipResult) {
            self.validation.complete(msg_id, response, &mut self.adapter.producers);
        }
    }

    fn submit_aggregate(harness: &mut Harness, request_id: u64) {
        let mut aggregate = [0u8; SIGNED_AGG_PROOF_MIN + 1];
        aggregate[SIGNED_AGG_PROOF_MIN] = 1;
        let topic = GossipTopic::BeaconAggregateAndProof;
        let message = LocalMessage { request_id, topic, ssz: &aggregate, ssz_read: None, slot: 0 };
        let Harness { validation, gossip, adapter, .. } = harness;
        validation.submit(message, Instant::now(), gossip, &mut adapter.producers);
    }

    /// The same message submitted twice shares one validation, and every
    /// request completes with its verdict.
    #[test]
    fn identical_messages_share_one_validation() {
        let mut harness = Harness::new();

        submit_aggregate(&mut harness, 1);
        let message = harness.pop_gossip();
        submit_aggregate(&mut harness, 2);
        assert_eq!(harness.pop_gossip().msg_hash, message.msg_hash);
        assert!(harness.responses().is_empty());

        harness.complete(message.msg_hash, Ok(()));
        assert_eq!(harness.responses(), [(1, Ok(())), (2, Ok(()))]);
        assert!(harness.validation.is_empty());
    }

    /// Requests sharing a message expire on their own deadlines.
    #[test]
    fn shared_requests_expire_independently() {
        let mut harness = Harness::new();
        let now = Instant::now();
        let aggregate = [0u8; SIGNED_AGG_PROOF_MIN + 1];
        for (request_id, at) in [(21, now), (22, now + Duration::from_millis(10))] {
            let topic = GossipTopic::BeaconAggregateAndProof;
            let message =
                LocalMessage { request_id, topic, ssz: &aggregate, ssz_read: None, slot: 0 };
            let Harness { validation, gossip, adapter, .. } = &mut harness;
            validation.submit(message, at, gossip, &mut adapter.producers);
        }

        let Harness { validation, adapter, .. } = &mut harness;
        validation.expire(now + VALIDATION_TIMEOUT, &mut adapter.producers);
        assert_eq!(harness.responses(), [(21, Err(LocalGossipFailure::TimedOut))]);
        assert!(!harness.validation.is_empty());

        let Harness { validation, adapter, .. } = &mut harness;
        validation
            .expire(now + VALIDATION_TIMEOUT + Duration::from_millis(10), &mut adapter.producers);
        assert_eq!(harness.responses(), [(22, Err(LocalGossipFailure::TimedOut))]);
        assert!(harness.validation.is_empty());
    }
}
