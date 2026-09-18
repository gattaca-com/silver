use silver_common::cell_store::{
    CommitmentContext, ContextData, FuluContextSource, HeaderValidationRequest,
};

use super::*;
use crate::validate::HeaderOutcome;

#[test]
fn pending_sparse_cells_join_full_sidecars_in_the_kzg_batch_and_isolate_invalid_senders() {
    const SLOT: u64 = 7;
    let blobs = [BlockBlob::counting(), BlockBlob::starting_at(1000)];
    let commitments: Vec<_> = blobs.iter().flat_map(|blob| blob.commitment).collect();
    for format in [ForkName::Fulu, ForkName::Gloas] {
        let mut rig = Rig::with_spec(CUSTODY_COLUMNS, SpecConfig {
            fulu_fork_epoch: 0,
            gloas_fork_epoch: if format == ForkName::Gloas { 0 } else { u64::MAX },
            ..SpecConfig::mainnet()
        });
        let mut allocator = rig.attach_cell_store(SLOT, CUSTODY_COLUMNS);
        rig.follow([0; 32]);
        rig.turn();
        let body = if format == ForkName::Fulu {
            fulu_body(&commitments)
        } else {
            gloas_body(&commitments)
        };
        let block = block_around(SLOT, &body);
        let root = block_root(&block, format == ForkName::Gloas);
        let domain = rig.tile.validator.domain_at(SLOT).unwrap();
        let context = CommitmentContext { block_root: root, slot: SLOT, format, blob_count: 2 };
        let candidate = allocator.optimistic(context, domain, None, 1).unwrap();
        let mut requests = Vec::new();
        for (row, blob) in blobs.iter().enumerate() {
            let pending = allocator
                .stage(
                    CellKey { block_root: root, column: 3, row },
                    &blob.cells[3].to_bytes(),
                    &blob.proofs[if row == 0 { 3 } else { 7 }].to_bytes().into_inner(),
                )
                .unwrap()
                .unwrap();
            let request = CellValidationRequest {
                pending,
                slot: SLOT,
                domain,
                deadline: candidate.expires,
                origin: CellOrigin::Gossip {
                    stream_id: P2pStreamId::new(row + 1, 0, StreamProtocol::GossipSubV13, true),
                    topic: GossipTopic::DataColumnSidecar(3),
                    received: Nanos(row as u64 + 1),
                },
            };
            rig.inj.produce(CellStoreEvent::Validate(request));
            requests.push(request);
        }
        rig.turn();
        assert!(rig.tile.cells.as_ref().unwrap().store().context(&root).is_none());
        assert!(!rig.tile.tracker.holds(&root, 3));
        rig.inj.consume(|event: CellStoreEvent, _| {
            assert!(!matches!(event, CellStoreEvent::Validation { .. }))
        });

        let mut header = [0; 208];
        header[..8].copy_from_slice(&SLOT.to_le_bytes());
        header[80..112].copy_from_slice(&body_root(&body));
        let proof = kzg_commitments_inclusion_proof(&body);
        if format == ForkName::Gloas {
            rig.block(&block);
            assert!(rig.tile.cells.as_ref().unwrap().store().context(&root).is_none());
            rig.tile.note_staged_block(root, SLOT, &mut rig.conn.producers);
        } else {
            let data = ContextData::Fulu {
                signed_header: &header,
                inclusion_proof: &proof,
                commitments: &commitments,
            };
            let mut bytes = vec![0; data.encoded_len()];
            data.write(&mut bytes);
            let source = FuluContextSource::Header(tcache_write(allocator.producer_mut(), &bytes));
            let store = rig.tile.cells.as_mut().unwrap().store_mut();
            store.admit_context(context, domain, data, Some(source)).unwrap();
            rig.conn.produce(CellStoreEvent::Allocate(store.request_assemblies(&root).unwrap()));
            rig.tile.tracker.set_signature(root, [0; 96]);
        }
        rig.allocate_cells(&mut allocator);
        assert_eq!(
            allocator.column(requests[0].pending.key).unwrap().reservation.read().seq(),
            requests[0].pending.data.reservation().read().seq()
        );

        let mut full = Vec::new();
        if format == ForkName::Fulu {
            util::push_data_column_sidecar_prefix(&mut full, 7, 2, &header, &proof);
        } else {
            full.resize(56, 0);
            full[..8].copy_from_slice(&7u64.to_le_bytes());
            full[8..12].copy_from_slice(&56u32.to_le_bytes());
            full[12..16].copy_from_slice(&(56u32 + 2 * c_kzg::BYTES_PER_CELL as u32).to_le_bytes());
            full[16..24].copy_from_slice(&SLOT.to_le_bytes());
            full[24..56].copy_from_slice(&root);
        }
        for blob in &blobs {
            full.extend_from_slice(&blob.cells[7].to_bytes());
        }
        if format == ForkName::Fulu {
            full.extend_from_slice(&commitments);
        }
        for blob in &blobs {
            full.extend_from_slice(&blob.proofs[7].to_bytes().into_inner());
        }
        let read = tcache_write(allocator.producer_mut(), &full);
        rig.cached_gossip(read, 7, domain);
        rig.turn();
        let mut outcomes = Vec::new();
        rig.inj.consume(|event: CellStoreEvent, _| {
            if let CellStoreEvent::Validation { request, outcome } = event {
                outcomes.push((request.pending.key.row, outcome));
            }
        });
        assert!(outcomes.contains(&(0, CellValidationOutcome::Accepted)));
        assert!(outcomes.contains(&(1, CellValidationOutcome::Rejected)));
        let mut rejected = Vec::new();
        rig.inj.consume(|event: PeerEvent, _| {
            if let PeerEvent::ColumnVerdict { p2p_peer, accepted: false, .. } = event {
                rejected.push(p2p_peer);
            }
        });
        assert_eq!(rejected, [2]);
        assert!(rig.tile.tracker.holds(&root, 7));
        assert!(!rig.tile.tracker.holds(&root, 3));
        assert_eq!(
            rig.tile.cells.as_ref().unwrap().store().availability(&root, 3).unwrap().available,
            1
        );
        assert_eq!(rig.drain().available, 0);

        let pending = allocator
            .stage(
                requests[1].pending.key,
                &blobs[1].cells[3].to_bytes(),
                &blobs[1].proofs[3].to_bytes().into_inner(),
            )
            .unwrap()
            .unwrap();
        assert!(!allocator.cancel(requests[1].pending).unwrap());
        rig.inj.produce(CellStoreEvent::Validate(CellValidationRequest { pending, ..requests[1] }));
        rig.turn();
        let out = rig.drain();
        assert!(out.persisted(root, 3));
        assert_eq!(out.available, 1);
        assert_eq!(out.custody_complete, 1);
        rig.turn();
        assert_eq!(rig.drain().available, 0);
    }
}

#[test]
fn fulu_headers_use_snapshot_ancestry_and_validate_signature_and_inclusion() {
    const CASE: &str =
        "networking/gossip_data_column_sidecar/pyspec_tests/gossip_data_column_sidecar__valid";
    let Some((sidecar, state)) = ef_sidecar(CASE) else { return };
    let reader = reader_over(&state);
    let index = DataColumnSidecarFuluView::index(&sidecar);
    let slot = DataColumnSidecarFuluView::slot(&sidecar);
    let root = util::block_root_from_sidecar(&sidecar);
    let mut rig = Rig::with_state(1 << index, reader.clone(), SpecConfig {
        max_blobs_per_block_electra: 12,
        blob_schedule: Vec::new(),
        ..fulu_from_genesis()
    });
    let data = ContextData::Fulu {
        signed_header: sidecar[20..228].try_into().unwrap(),
        inclusion_proof: sidecar[228..356].try_into().unwrap(),
        commitments: DataColumnSidecarFuluView::kzg_commitments(&sidecar),
    };
    let mut header = vec![0; data.encoded_len()];
    data.write(&mut header);
    let domain = rig.tile.validator.domain_at(slot).unwrap();
    let directory = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../beacon_state/tile/consensus-spec-tests/tests/mainnet/fulu")
        .join(CASE);
    for entry in std::fs::read_dir(directory).unwrap() {
        let path = entry.unwrap().path();
        if path.file_name().unwrap().to_string_lossy().starts_with("block_") {
            let bytes =
                snap::raw::Decoder::new().decompress_vec(&std::fs::read(path).unwrap()).unwrap();
            let parent = block_root_fulu(&bytes);
            rig.tile.validator.cache_parent_state_root(parent, &bytes);
            rig.tile.validator.note_validated(parent, SignedBeaconBlockView::slot(&bytes));
        }
    }
    rig.follow([0xab; 32]); // A status event from another head cannot change the snapshot's ancestry.
    let verify = |rig: &Rig, bytes: &[u8], root| {
        rig.tile.validator.validate_partial_header(root, domain, bytes, &rig.tile.sync_state)
    };
    let outcome = verify(&rig, &header, root);
    assert!(
        matches!(outcome, HeaderOutcome::Valid(_)),
        "{outcome:?}; slot={slot}; snapshot={:?}",
        reader.read(|view| (view.slot.slot_number(), view.slot.state().latest_block_header))
    );
    assert_eq!(verify(&rig, &header, [0; 32]), HeaderOutcome::Reject);
    for offset in [4 + 112, 212] {
        let mut bad = header.clone();
        bad[offset] ^= 1;
        assert_eq!(verify(&rig, &bad, root), HeaderOutcome::Reject);
    }

    let mut allocator = rig.attach_cell_store(slot, 1 << index);
    rig.turn();
    let context = CommitmentContext {
        block_root: root,
        slot,
        format: ForkName::Fulu,
        blob_count: data.commitments().len() / 48,
    };
    let candidate = allocator.optimistic(context, domain, None, 1).unwrap();
    let origin = CellOrigin::Gossip {
        stream_id: P2pStreamId::new(1, 0, StreamProtocol::GossipSubV13, true),
        topic: GossipTopic::DataColumnSidecar(index),
        received: Nanos::now(),
    };
    for (row, (cell, proof)) in DataColumnSidecarFuluView::column(&sidecar)
        .chunks_exact(c_kzg::BYTES_PER_CELL)
        .zip(DataColumnSidecarFuluView::kzg_proofs(&sidecar).chunks_exact(48))
        .enumerate()
    {
        let pending = allocator
            .stage(
                CellKey { block_root: root, column: index as usize, row },
                cell.try_into().unwrap(),
                proof.try_into().unwrap(),
            )
            .unwrap()
            .unwrap();
        rig.inj.produce(CellStoreEvent::Validate(CellValidationRequest {
            pending,
            slot,
            origin,
            domain,
            deadline: candidate.expires,
        }));
    }
    rig.turn();
    assert!(!rig.tile.tracker.holds(&root, index));
    let ssz = tcache_write(allocator.producer_mut(), &header);
    rig.inj.produce(CellStoreEvent::Header(HeaderValidationRequest {
        block_root: root,
        ssz,
        domain,
        origin,
        deadline: candidate.expires,
    }));
    rig.turn();
    rig.allocate_cells(&mut allocator);
    rig.turn();
    assert!(rig.tile.tracker.holds(&root, index));
    assert!(rig.drain().persisted(root, index));

    let parent = *DataColumnSidecarFuluView::parent_root(&sidecar);
    rig.tile.validator.note_rejected(&parent);
    assert_eq!(verify(&rig, &header, root), HeaderOutcome::Reject);
}
