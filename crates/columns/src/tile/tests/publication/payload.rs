use silver_common::{
    BeaconApiRequest, BeaconApiResponse, LocalGossipFailure, PayloadFrame, ProposedPayload,
    column_util::{KzgScratch, verify_data_column_sidecar_kzg_proofs_gloas},
    ssz_view::{ExecutionPayloadEnvelopeView, SignedExecutionPayloadEnvelopeView},
    test_util::empty_signed_envelope,
};

use super::*;

const SLOT: u64 = 7;
const ROOT: BlockRoot = [7; 32];

#[test]
fn local_gloas_block_persistence_reads_boundary_cache() {
    let commitments = [0x42; 48];
    let block = SynthBlock::gloas(SLOT, SynthBid::new(&commitments)).into_bytes();
    let root = block_root_gloas(&block);
    let mut rig = Box::new(Rig::gloas(CUSTODY_COLUMNS));
    let mut state = TCacheReader::new(*rig.tile.reader.table());
    state
        .open_forwarder(TileId::BeaconState, TCacheId::BoundaryProcessing, TReadMode::Sliding)
        .unwrap();
    rig.turn();
    let ssz = tcache_write(&mut rig.engine_p, &block);
    let block = state.acquire(ssz);
    rig.inj.produce(BeaconStateEvent::PersistBlock {
        ssz: block.to_read(),
        source: BlockSource::Gossip,
        slot: SLOT,
        block_root: root,
    });
    rig.turn();
    assert_eq!(rig.tile.validator.gloas_commitments(&root), Some(commitments.as_slice()));
    assert!(rig.tile.validator.is_validated(&root));
}

fn proposal(rig: &mut Rig, blobs: &[BlockBlob], cached: bool, bad_proofs: bool) -> ProposedPayload {
    let signed = empty_signed_envelope(SLOT, ROOT);
    let mut proofs: Vec<_> = blobs
        .iter()
        .flat_map(|blob| blob.proofs.iter().flat_map(|proof| proof.to_bytes().into_inner()))
        .collect();
    if bad_proofs {
        let (first, rest) = proofs.split_at_mut(48);
        first.swap_with_slice(&mut rest[..48]);
    }
    let bytes: Vec<_> = blobs.iter().flat_map(|blob| blob.blob.as_ref().iter().copied()).collect();
    let commitments: Vec<_> = blobs.iter().flat_map(|blob| blob.commitment).collect();
    let (contents, payload) = if cached {
        let envelope = SignedExecutionPayloadEnvelopeView::message(&signed);
        let execution_payload = ExecutionPayloadEnvelopeView::payload(envelope);
        let requests = ExecutionPayloadEnvelopeView::execution_requests(envelope);
        let mut frame = vec![0; PayloadFrame::HEADER_LEN];
        PayloadFrame::write_header(
            &mut frame,
            execution_payload.len(),
            requests.len(),
            blobs.len() as u8,
            false,
            &[0; 32],
        );
        frame.extend_from_slice(execution_payload);
        frame.extend_from_slice(&commitments);
        frame.extend_from_slice(requests);
        frame.extend_from_slice(&proofs);
        frame.extend_from_slice(&bytes);
        (signed.clone(), Some(tcache_write(&mut rig.engine_p, &frame)))
    } else {
        let proofs_at = 12 + signed.len();
        let blobs_at = proofs_at + proofs.len();
        let mut contents = [12, proofs_at, blobs_at].map(|n| (n as u32).to_le_bytes()).concat();
        contents.extend_from_slice(&signed);
        contents.extend_from_slice(&proofs);
        contents.extend_from_slice(&bytes);
        (contents, None)
    };
    ProposedPayload {
        request_id: 42,
        ssz: tcache_write(&mut rig.state_p, &signed),
        contents: tcache_write(&mut rig.engine_p, &contents),
        payload,
        commitments: tcache_write(&mut rig.state_p, &commitments),
    }
}

#[test]
fn cached_and_submitted_blobs_publish_every_gloas_column() {
    let blobs = [BlockBlob::counting(), BlockBlob::starting_at(4096)];
    let commitments: Vec<_> = blobs.iter().flat_map(|blob| blob.commitment).collect();
    for cached in [false, true] {
        let mut rig = Box::new(Rig::gloas(CUSTODY_COLUMNS));
        rig.follow([0; 32]);
        rig.turn();
        rig.drain();
        rig.inj.consume(|_: BeaconApiRequest, _| {});
        rig.inj.consume(|_: BeaconApiResponse, _| {});
        let proposal = proposal(&mut rig, &blobs, cached, false);
        rig.inj.produce(BeaconStateEvent::ProposedPayload(proposal));
        rig.turn();
        let out = rig.drain();
        assert_eq!(out.available, 1);
        assert_eq!(out.published_only, !CUSTODY_COLUMNS);
        assert_eq!(out.receipts.len(), CUSTODY_COLUMNS.count_ones() as usize);
        let mut scratch = KzgScratch::default();
        for receipt in out.receipts {
            let DataColumnsEvent::Persist {
                ssz,
                block_root,
                slot,
                column_index,
                domain,
                ssz_cache,
                ..
            } = receipt
            else {
                unreachable!()
            };
            assert_eq!((block_root, slot, ssz_cache), (ROOT, SLOT, SszCache::ProposedColumns));
            assert_eq!(domain.unwrap().format(), ForkName::Gloas);
            let sidecar = rig.tile.proposed.producer.read_buffer(ssz).unwrap();
            assert!(verify_data_column_sidecar_kzg_proofs_gloas(
                sidecar,
                &commitments,
                &mut scratch
            ));
            assert_eq!(SidecarIdentity::of(sidecar).unwrap(), SidecarIdentity {
                slot: SLOT,
                block_root: ROOT,
                column_index,
            });
        }
        let mut requests = Vec::new();
        rig.inj.consume(|request: BeaconApiRequest, _| requests.push(request));
        assert_eq!(requests, [BeaconApiRequest::LocalGossip {
            request_id: 42,
            topic: GossipTopic::ExecutionPayload,
            ssz: proposal.ssz,
            validation: silver_common::BroadcastValidation::Gossip,
        }]);
        rig.inj.consume(|_: BeaconApiResponse, _| panic!("Control must confirm the broadcast"));
    }
}

#[test]
fn misplaced_proofs_release_neither_columns_nor_envelope() {
    let blobs = [BlockBlob::counting()];
    for cached in [false, true] {
        let mut rig = Box::new(Rig::gloas(CUSTODY_COLUMNS));
        rig.turn();
        rig.drain();
        rig.inj.consume(|_: BeaconApiRequest, _| {});
        rig.inj.consume(|_: BeaconApiResponse, _| {});
        let proposal = proposal(&mut rig, &blobs, cached, true);
        rig.inj.produce(BeaconStateEvent::ProposedPayload(proposal));
        rig.turn();
        let out = rig.drain();
        assert_eq!((out.available, out.published_only, out.receipts.len()), (0, 0, 0));
        rig.inj.consume(|_: BeaconApiRequest, _| {
            panic!("invalid blob data cannot release the envelope")
        });
        let mut failures = Vec::new();
        rig.inj.consume(|response: BeaconApiResponse, _| {
            if let BeaconApiResponse::LocalGossipResponse { request_id, response } = response {
                failures.push((request_id, response));
            }
        });
        assert_eq!(failures, [(42, Err(LocalGossipFailure::Invalid))]);
    }
}
