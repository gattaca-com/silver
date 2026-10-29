use silver_common::{
    BroadcastValidation, LocalGossipFailure, ProposedPayload,
    ssz_view::SignedExecutionPayloadEnvelopeView,
};

use super::*;

impl ProductionRig {
    fn self_build_for_publication(blobs: u8) -> (Self, Vec<u8>, Vec<u8>) {
        let mut rig = Self::new("empty_block_transition");
        rig.tile.sync_target = SyncUpdate::Following;
        let attrs = rig.start(1);
        let frame = rig.payload(attrs, 1, false, blobs);
        rig.respond(attrs.id, &frame);
        let built = rig.one_block(1);
        let block = rig.tile.events_producer.read_buffer(built.header).unwrap().to_vec();
        let root =
            *ExecutionPayloadEnvelopeView::beacon_block_root(&built.envelope_header.unwrap());
        let proposer = u64::from_le_bytes(block[8..16].try_into().unwrap()) as usize;
        let view = rig.tile.state.read_view(rig.tile.canonical_state_id());
        let domain = bls::compute_domain(
            bls::DOMAIN_BEACON_PROPOSER,
            rig.tile.spec.fork_version_at(rig.proposal.slot / SLOTS_PER_EPOCH),
            &view.imm.genesis_validators_root,
        );
        let signature = fixture_secret_key(proposer)
            .sign(&bls::compute_signing_root(&root, &domain), bls::DST, &[])
            .to_bytes();
        let mut signed_block = 100u32.to_le_bytes().to_vec();
        signed_block.extend_from_slice(&signature);
        signed_block.extend_from_slice(&block);
        let (_, read) = publish_block_bytes(&mut rig.gossip, &signed_block);
        let acquired = rig.tile.reader.acquire(read);
        let feedback = rig.tile.apply_block(
            &signed_block,
            &acquired,
            BlockSource::Gossip,
            false,
            &mut rig.adapter.producers,
            |_| {},
        );
        assert_eq!(feedback, Feedback::BlockImported(root));
        let payload = PayloadFrame::parse(&frame).unwrap();
        let mut signed = vec![0; 100];
        signed[..4].copy_from_slice(&100u32.to_le_bytes());
        signed.extend_from_slice(&built.envelope_header.unwrap());
        signed.extend_from_slice(payload.execution_payload);
        signed.extend_from_slice(payload.execution_requests);
        rig.sign_envelope(&mut signed);
        rig.sink.consume(|_: BeaconStateEvent, _| {});
        rig.sink.consume(|_: BeaconApiRequest, _| {});
        rig.sink.consume(|_: BeaconApiResponse, _| {});
        engine_requests(&mut rig.sink);
        (rig, signed, frame)
    }

    fn sign_envelope(&self, signed: &mut [u8]) {
        let envelope = SignedExecutionPayloadEnvelopeView::message(signed);
        let root = ExecutionPayloadEnvelopeView::beacon_block_root(envelope);
        let node = self.tile.fork_choice.node(self.tile.fork_choice.find_node_idx(root).unwrap());
        let view = self.tile.state.read_view(node.state_id);
        let domain = bls::compute_domain(
            bls::DOMAIN_BEACON_BUILDER,
            view.epoch.fork_version_at(view.slot.current_epoch()),
            &view.imm.genesis_validators_root,
        );
        let signing_root = bls::compute_signing_root(
            &ExecutionPayloadEnvelopeView::hash_tree_root(envelope),
            &domain,
        );
        let signature =
            fixture_secret_key(view.slot.state().latest_block_header.proposer_index as usize)
                .sign(&signing_root, bls::DST, &[])
                .to_bytes();
        signed[4..100].copy_from_slice(&signature);
    }

    fn submit_envelope(
        &mut self,
        bytes: &[u8],
        included: bool,
        validation: BroadcastValidation,
    ) -> Vec<ProposedPayload> {
        let (_, read) = publish_block_bytes(&mut self.gossip, bytes);
        self.tile.publish_payload_envelope(
            42,
            read,
            included,
            validation,
            &mut self.adapter.producers,
        );
        let mut proposals = Vec::new();
        self.sink.consume(|event: BeaconStateEvent, _| {
            if let BeaconStateEvent::ProposedPayload(proposal) = event {
                proposals.push(proposal);
            }
        });
        proposals
    }

    fn publication_result(&mut self) -> Vec<Result<(), LocalGossipFailure>> {
        let mut results = Vec::new();
        self.sink.consume(|response: BeaconApiResponse, _| {
            if let BeaconApiResponse::LocalGossipResponse { request_id: 42, response } = response {
                results.push(response);
            }
        });
        results
    }
}

fn contents(signed: &[u8], frame: &[u8]) -> Vec<u8> {
    let frame = PayloadFrame::parse(frame).unwrap();
    let proofs_at = 12 + signed.len();
    let blobs_at = proofs_at + frame.cell_proofs.len();
    let mut contents = [12, proofs_at, blobs_at].map(|n| (n as u32).to_le_bytes()).concat();
    contents.extend_from_slice(signed);
    contents.extend_from_slice(frame.cell_proofs);
    contents.extend_from_slice(frame.blobs);
    contents
}

#[test]
fn cached_payload_reaches_columns_only_after_signature_and_block_validation() {
    let (mut rig, signed, _) = ProductionRig::self_build_for_publication(1);
    let mut bad_signature = signed.clone();
    bad_signature[4..100].fill(0);
    assert!(rig.submit_envelope(&bad_signature, false, BroadcastValidation::Consensus).is_empty());
    assert_eq!(rig.publication_result(), [Err(LocalGossipFailure::Invalid)]);
    let proposals = rig.submit_envelope(&signed, false, BroadcastValidation::Consensus);
    let [proposal] = proposals[..] else { panic!("one verified payload") };
    assert!(proposal.payload.is_some());
    assert_eq!(rig.tile.events_producer.read_buffer(proposal.ssz).unwrap(), signed);
    assert_eq!(rig.tile.events_producer.read_buffer(proposal.commitments).unwrap(), [0x33; 48]);
    assert!(rig.publication_result().is_empty(), "KZG and broadcast are pending");
    assert!(engine_requests(&mut rig.sink).is_empty(), "columns precede EL submission");
}

#[test]
fn stateless_publication_works_without_the_local_payload_cache() {
    let (mut rig, signed, frame) = ProductionRig::self_build_for_publication(1);
    rig.tile.block_production = BlockProduction::new(Duration::from_millis(500));
    assert!(rig.submit_envelope(&signed, false, BroadcastValidation::Consensus).is_empty());
    assert_eq!(rig.publication_result(), [Err(LocalGossipFailure::Unverifiable)]);
    let proposals =
        rig.submit_envelope(&contents(&signed, &frame), true, BroadcastValidation::Consensus);
    let [proposal] = proposals[..] else { panic!("one stateless payload") };
    assert!(proposal.payload.is_none());
    assert!(rig.publication_result().is_empty());
}

#[test]
fn stateful_publication_requires_the_exact_cached_payload() {
    let (mut rig, mut signed, _) = ProductionRig::self_build_for_publication(1);
    signed[180 + 32] ^= 1;
    rig.sign_envelope(&mut signed);
    assert!(rig.submit_envelope(&signed, false, BroadcastValidation::Consensus).is_empty());
    assert_eq!(rig.publication_result(), [Err(LocalGossipFailure::Invalid)]);
}

#[test]
fn blobless_envelope_reaches_engine_and_storage_through_gossip() {
    let (mut rig, signed, _) = ProductionRig::self_build_for_publication(0);
    assert!(rig.submit_envelope(&signed, false, BroadcastValidation::Consensus).is_empty());
    assert!(rig.publication_result().is_empty());
    let mut requests = Vec::new();
    rig.sink.consume(|request: BeaconApiRequest, _| requests.push(request));
    let [
        BeaconApiRequest::LocalGossip {
            request_id: 42,
            topic: GossipTopic::ExecutionPayload,
            ssz,
            validation: BroadcastValidation::Gossip,
        },
    ] = requests[..]
    else {
        panic!("release signed envelope")
    };
    assert_eq!(rig.tile.events_producer.read_buffer(ssz).unwrap(), signed);
    let (_, read) = publish_block_bytes(&mut rig.gossip, &signed);
    let acquired = rig.tile.reader.acquire(read);
    let feedback = rig.tile.handle_execution_payload_envelope(
        acquired,
        &signed,
        BlockSource::Gossip,
        &mut rig.adapter.producers,
    );
    assert_eq!(feedback, Feedback::Accept);
    assert!(matches!(engine_requests(&mut rig.sink).as_slice(), [EngineReq::NewPayloadEnvelope(
        _
    )]));
    let mut persisted = false;
    rig.sink.consume(|event: BeaconStateEvent, _| {
        if let BeaconStateEvent::EnvelopeAvailable { .. } = event {
            persisted = true;
        }
    });
    assert!(persisted);
}

#[test]
fn stateless_publication_rejects_a_blob_count_different_from_the_bid() {
    let (mut rig, signed, _) = ProductionRig::self_build_for_publication(1);
    let end = 12 + signed.len();
    let mut body = [12, end, end].map(|n| (n as u32).to_le_bytes()).concat();
    body.extend_from_slice(&signed);
    assert!(rig.submit_envelope(&body, true, BroadcastValidation::Consensus).is_empty());
    assert_eq!(rig.publication_result(), [Err(LocalGossipFailure::Invalid)]);
}

#[test]
fn withdrawal_mismatch_is_only_broadcast_in_gossip_mode() {
    let (mut rig, signed, frame) = ProductionRig::self_build_for_publication(0);
    let message = SignedExecutionPayloadEnvelopeView::message(&signed);
    let payload = ExecutionPayloadEnvelopeView::payload(message);
    let mut modified = payload.to_vec();
    modified.extend_from_slice(&[0x11; 44]);
    let end = modified.len() as u32;
    modified[528..532].copy_from_slice(&end.to_le_bytes());
    let mut signed = signed[..180].to_vec();
    signed[104..108].copy_from_slice(&(80 + end).to_le_bytes());
    signed.extend_from_slice(&modified);
    signed.extend_from_slice(&EMPTY_EXECUTION_REQUESTS);
    rig.sign_envelope(&mut signed);
    let body = contents(&signed, &frame);
    assert!(rig.submit_envelope(&body, true, BroadcastValidation::Consensus).is_empty());
    assert_eq!(rig.publication_result(), [Err(LocalGossipFailure::Invalid)]);
    assert!(rig.submit_envelope(&body, true, BroadcastValidation::Gossip).is_empty());
    let mut broadcast_only = false;
    rig.sink.consume(|response: BeaconApiResponse, _| {
        if let BeaconApiResponse::PayloadEnvelopeValidation {
            request_id: 42,
            consensus_valid: false,
        } = response
        {
            broadcast_only = true;
        }
    });
    assert!(broadcast_only);
    let mut released = 0;
    rig.sink.consume(|request: BeaconApiRequest, _| {
        if let BeaconApiRequest::LocalGossip { .. } = request {
            released += 1;
        }
    });
    assert_eq!(released, 1);
}

#[test]
fn equivocation_check_refuses_a_second_block_from_the_same_proposer() {
    let (mut rig, signed, frame) = ProductionRig::self_build_for_publication(0);
    let root = ExecutionPayloadEnvelopeView::beacon_block_root(
        SignedExecutionPayloadEnvelopeView::message(&signed),
    );
    let idx = rig.tile.fork_choice.find_node_idx(root).unwrap();
    let mut other = rig.tile.fork_choice.node(idx).clone();
    other.block_root = [0x9a; 32];
    rig.tile.fork_choice.nodes.push(other);
    assert!(
        rig.submit_envelope(
            &contents(&signed, &frame),
            true,
            BroadcastValidation::ConsensusAndEquivocation
        )
        .is_empty()
    );
    assert_eq!(rig.publication_result(), [Err(LocalGossipFailure::ConflictingProposal)]);
}

#[test]
fn envelope_for_an_unknown_block_is_never_released() {
    let (mut rig, mut signed, _) = ProductionRig::self_build_for_publication(0);
    signed[116..148].fill(0xff);
    assert!(rig.submit_envelope(&signed, false, BroadcastValidation::Consensus).is_empty());
    assert_eq!(rig.publication_result(), [Err(LocalGossipFailure::Unverifiable)]);
    rig.sink.consume(|_: BeaconApiRequest, _| panic!("unknown block cannot release a payload"));
}
