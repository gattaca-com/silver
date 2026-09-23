use silver_common::cell_store::HeaderValidationRequest;

use super::*;

const SLOT: u64 = 7;

fn frame(blobs: &[Option<&BlockBlob>]) -> Vec<u8> {
    let mut bytes = (blobs.len() as u32).to_le_bytes().to_vec();
    for blob in blobs {
        match blob {
            Some(blob) => bytes.extend_from_slice(&blob.el_frame()[4..]),
            None => bytes.push(0),
        }
    }
    bytes
}

fn rig_for(format: ForkName, columns: u128, blobs: &[BlockBlob]) -> (Rig, Vec<u8>) {
    let commitments: Vec<_> = blobs.iter().flat_map(|blob| blob.commitment).collect();
    match format {
        ForkName::Fulu => Rig::with_fulu_block(columns, SLOT, &commitments),
        ForkName::Gloas => {
            (Rig::gloas(columns), SynthBlock::gloas(SLOT, SynthBid::new(&commitments)).into_bytes())
        }
        _ => unreachable!(),
    }
}

fn full_column(format: ForkName, column: u64, block: &[u8], blobs: &[BlockBlob]) -> Vec<u8> {
    let mut bytes = Vec::new();
    if format == ForkName::Fulu {
        let single = blobs[0].fulu_sidecar(column, block);
        let ContextData::Fulu { signed_header, inclusion_proof, .. } =
            ContextData::from_fulu_sidecar(&single).unwrap()
        else {
            unreachable!()
        };
        util::push_data_column_sidecar_prefix(
            &mut bytes,
            column,
            blobs.len(),
            signed_header,
            inclusion_proof,
        );
    } else {
        bytes.resize(DATA_COLUMN_SIDECAR_GLOAS_MIN, 0);
        bytes[..8].copy_from_slice(&column.to_le_bytes());
        bytes[8..12].copy_from_slice(&(DATA_COLUMN_SIDECAR_GLOAS_MIN as u32).to_le_bytes());
        bytes[12..16].copy_from_slice(
            &((DATA_COLUMN_SIDECAR_GLOAS_MIN + blobs.len() * c_kzg::BYTES_PER_CELL) as u32)
                .to_le_bytes(),
        );
        bytes[16..24].copy_from_slice(&SLOT.to_le_bytes());
        bytes[24..56].copy_from_slice(&block_root_gloas(block));
    }
    for blob in blobs {
        bytes.extend_from_slice(&blob.cells[column as usize].to_bytes());
    }
    if format == ForkName::Fulu {
        for blob in blobs {
            bytes.extend_from_slice(&blob.commitment);
        }
    }
    for blob in blobs {
        bytes.extend_from_slice(&blob.proofs[column as usize].to_bytes().into_inner());
    }
    bytes
}

#[test]
fn fulu_sidecar_context_starts_el_before_block_or_cell_verification_in_all_modes() {
    let blob = BlockBlob::counting();
    for partial in [false, true] {
        let (mut rig, block) = Rig::with_fulu_block(CUSTODY_COLUMNS, SLOT, &blob.commitment);
        let root = block_root_fulu(&block);
        let mut allocator = partial.then(|| rig.attach_cell_store(SLOT, CUSTODY_COLUMNS));
        rig.follow([0; 32]);
        rig.turn();
        let good = blob.fulu_sidecar(3, &block);
        let mut bad_cells = good.clone();
        *bad_cells.last_mut().unwrap() ^= 1;
        if let Some(allocator) = &mut allocator {
            let read = tcache_write(allocator.producer_mut(), &bad_cells);
            let domain = rig.tile.validator.domain_at(SLOT).unwrap();
            rig.cached_gossip(read, 3, domain);
        } else {
            rig.gossip_sidecar(3, &bad_cells);
        }
        assert_eq!(rig.drain().engine, 1, "trusted header does not wait for cell proofs");
        rig.turn();
        assert!(!rig.tile.tracker.holds(&root, 3));
        rig.gossip_sidecar(3, &good);
        rig.block(&block);
        rig.tile.note_staged_block(root, SLOT, &mut rig.conn.producers);
        assert_eq!(rig.drain().engine, 0, "other context sources cannot repeat the lookup");
    }
}

#[test]
fn partial_header_starts_el_without_the_block() {
    let blob = BlockBlob::counting();
    let (mut rig, block) = Rig::with_fulu_block(CUSTODY_COLUMNS, SLOT, &blob.commitment);
    let root = block_root_fulu(&block);
    let mut allocator = rig.attach_cell_store(SLOT, CUSTODY_COLUMNS);
    let domain = rig.tile.validator.domain_at(SLOT).unwrap();
    rig.follow([0; 32]);
    rig.turn();
    let sidecar = blob.fulu_sidecar(3, &block);
    let data = ContextData::from_fulu_sidecar(&sidecar).unwrap();
    let mut header = vec![0; data.encoded_len()];
    data.write(&mut header);
    let request = HeaderValidationRequest {
        block_root: root,
        ssz: tcache_write(allocator.producer_mut(), &header),
        domain,
        deadline: allocator.slot_window().1,
        origin: CellOrigin::Gossip {
            stream_id: P2pStreamId::new(1, 0, StreamProtocol::GossipSubV13, true),
            topic: GossipTopic::DataColumnSidecar(3),
            received: Nanos::now(),
        },
    };
    rig.inj.produce(CellStoreEvent::Header(request));
    rig.turn();
    assert_eq!(rig.drain().engine, 1);
    assert!(rig.tile.cells.as_ref().unwrap().store().context(&root).is_some());
    rig.block(&block);
    rig.tile.note_staged_block(root, SLOT, &mut rig.conn.producers);
    assert_eq!(rig.drain().engine, 0);
}

#[test]
fn block_context_waits_for_validation_and_works_in_either_arrival_order() {
    let blobs = [BlockBlob::counting()];
    for format in [ForkName::Fulu, ForkName::Gloas] {
        for approval_first in [false, true] {
            let (mut rig, block) = rig_for(format, CUSTODY_COLUMNS, &blobs);
            let root = block_root(&block, format == ForkName::Gloas);
            rig.follow([0; 32]);
            rig.turn();
            if approval_first {
                rig.tile.note_staged_block(root, SLOT, &mut rig.conn.producers);
            } else {
                rig.block(&block);
            }
            assert_eq!(rig.drain().engine, 0);
            if approval_first {
                rig.block(&block);
            } else {
                rig.tile.note_staged_block(root, SLOT, &mut rig.conn.producers);
            }
            assert_eq!(rig.drain().engine, 1, "{format:?}, approval_first={approval_first}");
            rig.block(&block);
            rig.tile.note_staged_block(root, SLOT, &mut rig.conn.producers);
            assert_eq!(rig.drain().engine, 0);
        }
    }
}

#[test]
fn fulu_block_approval_does_not_authorize_another_signatures_bytes() {
    let blob = BlockBlob::counting();
    let (mut rig, block) = Rig::with_fulu_block(CUSTODY_COLUMNS, SLOT, &blob.commitment);
    let root = block_root_fulu(&block);
    rig.follow([0; 32]);
    let mut invalid = block.clone();
    invalid[4] ^= 1;
    rig.block(&invalid);
    rig.tile.note_staged_block(root, SLOT, &mut rig.conn.producers);
    assert_eq!(rig.drain().engine, 0);
    rig.block(&block);
    assert_eq!(rig.drain().engine, 1, "a valid copy can replace the untrusted candidate");
}

#[test]
fn incomplete_el_rows_wait_for_allocation_and_merge_with_gossip_on_both_forks() {
    let blobs = [BlockBlob::counting(), BlockBlob::starting_at(1000), BlockBlob::starting_at(2000)];
    let response = frame(&[Some(&blobs[0]), None, Some(&blobs[2])]);
    for format in [ForkName::Fulu, ForkName::Gloas] {
        let (mut rig, block) = rig_for(format, CUSTODY_COLUMNS, &blobs);
        let root = block_root(&block, format == ForkName::Gloas);
        let mut allocator = rig.attach_cell_store(SLOT, CUSTODY_COLUMNS);
        let domain = rig.tile.validator.domain_at(SLOT).unwrap();
        rig.follow([0; 32]);
        rig.turn();
        rig.block(&block);
        rig.tile.note_staged_block(root, SLOT, &mut rig.conn.producers);
        assert_eq!(rig.drain().engine, 1);
        rig.engine_blobs(root, SLOT, &response);
        rig.turn();
        assert_eq!(rig.drain().validated, 0, "the response waits for the assembly handoff");
        rig.allocate_cells(&mut allocator);
        rig.turn();
        assert_eq!(rig.drain().validated, 0, "one blob is still missing");
        let mut requests = Vec::new();
        for column in util::columns_of(CUSTODY_COLUMNS) {
            let available = rig
                .tile
                .cells
                .as_ref()
                .unwrap()
                .store()
                .availability(&root, column as usize)
                .unwrap();
            assert_eq!(available.available, 0b101, "EL rows keep their original positions");
            assert_eq!(
                0b111 & !available.available,
                0b010,
                "only the missing row remains in demand"
            );
            let pending = allocator
                .stage(
                    CellKey { block_root: root, column: column as usize, row: 1 },
                    &blobs[1].cells[column as usize].to_bytes(),
                    &blobs[1].proofs[column as usize].to_bytes().into_inner(),
                )
                .unwrap()
                .unwrap();
            let request = CellValidationRequest {
                pending,
                slot: SLOT,
                domain,
                deadline: allocator.slot_window().1,
                origin: CellOrigin::Gossip {
                    stream_id: P2pStreamId::new(1, 0, StreamProtocol::GossipSubV13, true),
                    topic: GossipTopic::DataColumnSidecar(column),
                    received: Nanos::now(),
                },
            };
            rig.inj.produce(CellStoreEvent::Validate(request));
            requests.push(request);
        }
        rig.turn();
        let out = rig.drain();
        assert_eq!(out.validated, CUSTODY_COLUMNS);
        assert_eq!(out.available, 1);
        assert_eq!(out.custody_complete, 1);
        assert_eq!(out.receipts.len(), CUSTODY_COLUMNS.count_ones() as usize);
        for event in out.receipts {
            let DataColumnsEvent::Persist {
                ssz,
                origin,
                domain: persisted_domain,
                ssz_cache,
                column_index,
                ..
            } = event
            else {
                unreachable!()
            };
            assert_eq!(origin, ColumnOrigin::Assembly);
            assert_eq!(ssz_cache, SszCache::DataColumns);
            assert_eq!(persisted_domain, Some(domain));
            assert_eq!(
                allocator.producer().read_buffer(ssz).unwrap(),
                full_column(format, column_index, &block, &blobs),
            );
        }
        rig.engine_blobs(root, SLOT, &response);
        for request in requests {
            rig.inj.produce(CellStoreEvent::Validate(request));
        }
        rig.block(&block);
        rig.turn();
        let out = rig.drain();
        assert_eq!(out.validated + out.engine as u128, 0);
        assert_eq!(out.available, 0);
        assert!(out.receipts.is_empty());
    }
}

#[test]
fn complete_el_response_uses_assemblies_for_current_and_late_contexts_on_both_forks() {
    let blobs = [BlockBlob::counting(), BlockBlob::starting_at(1000)];
    let response = frame(&[Some(&blobs[0]), Some(&blobs[1])]);
    for format in [ForkName::Fulu, ForkName::Gloas] {
        for current_slot in [SLOT, SLOT + 1] {
            let (mut rig, block) = rig_for(format, CUSTODY_COLUMNS, &blobs);
            let root = block_root(&block, format == ForkName::Gloas);
            let mut allocator = rig.attach_cell_store(current_slot, CUSTODY_COLUMNS);
            let domain = rig.tile.validator.domain_at(SLOT).unwrap();
            rig.follow([0; 32]);
            rig.turn();
            rig.block(&block);
            rig.tile.note_staged_block(root, SLOT, &mut rig.conn.producers);
            assert_eq!(rig.drain().engine, 1);
            if current_slot != SLOT {
                assert!(rig.tile.cells.as_ref().unwrap().store().context(&root).is_none());
            }
            rig.allocate_cells(&mut allocator);
            rig.engine_blobs(root, SLOT, &response);
            rig.turn();
            rig.allocate_cells(&mut allocator);
            rig.turn();
            let out = rig.drain();
            assert_eq!(out.validated, CUSTODY_COLUMNS);
            assert_eq!(out.available, 1);
            assert_eq!(out.receipts.len(), CUSTODY_COLUMNS.count_ones() as usize);
            for event in out.receipts {
                let DataColumnsEvent::Persist {
                    ssz,
                    origin,
                    ssz_cache,
                    domain: persisted_domain,
                    column_index,
                    ..
                } = event
                else {
                    unreachable!()
                };
                assert_eq!(origin, ColumnOrigin::Assembly);
                assert_eq!(ssz_cache, SszCache::DataColumns);
                assert_eq!(persisted_domain, Some(domain));
                assert_eq!(
                    allocator.producer().read_buffer(ssz).unwrap(),
                    full_column(format, column_index, &block, &blobs)
                );
            }
        }
    }
}

#[test]
fn failed_assembly_allocation_retries_without_publishing_unwritten_columns() {
    let blobs = [BlockBlob::counting()];
    let (mut rig, block) = rig_for(ForkName::Gloas, CUSTODY_COLUMNS, &blobs);
    let root = block_root_gloas(&block);
    let mut allocator = rig.attach_cell_store(SLOT, CUSTODY_COLUMNS);
    rig.follow([0; 32]);
    rig.turn();
    rig.block(&block);
    rig.tile.note_staged_block(root, SLOT, &mut rig.conn.producers);
    rig.engine_blobs(root, SLOT, &blobs[0].el_frame());
    rig.turn();
    assert_eq!(rig.drain().validated, 0);
    rig.inj.consume(|event: CellStoreEvent, _| {
        if let CellStoreEvent::Allocate(request) = event {
            rig.tile.cells.as_mut().unwrap().handle_event(
                CellStoreEvent::Allocated { request, set: None },
                Instant::now(),
                &mut rig.conn.producers,
            );
        }
    });
    rig.turn();
    let out = rig.drain();
    assert_eq!(out.validated, 0);
    assert!(out.receipts.is_empty());
    assert_eq!(rig.tile.tracker.to_request(&root), CUSTODY_COLUMNS);
    std::thread::sleep(Duration::from_millis(25));
    rig.turn();
    rig.allocate_cells(&mut allocator);
    rig.turn();
    assert_eq!(rig.drain().validated, CUSTODY_COLUMNS);
}

#[test]
fn el_cannot_overwrite_claimed_gossip_cells() {
    let blobs = [BlockBlob::counting(), BlockBlob::starting_at(1000)];
    let (mut rig, block) = rig_for(ForkName::Gloas, 1 << 3, &blobs);
    let root = block_root_gloas(&block);
    let mut allocator = rig.attach_cell_store(SLOT, 1 << 3);
    let domain = rig.tile.validator.domain_at(SLOT).unwrap();
    rig.follow([0; 32]);
    rig.turn();
    rig.block(&block);
    rig.tile.note_staged_block(root, SLOT, &mut rig.conn.producers);
    rig.allocate_cells(&mut allocator);
    let pending = allocator
        .stage(
            CellKey { block_root: root, column: 3, row: 0 },
            &blobs[0].cells[3].to_bytes(),
            &blobs[0].proofs[3].to_bytes().into_inner(),
        )
        .unwrap()
        .unwrap();
    rig.engine_blobs(root, SLOT, &frame(&[Some(&blobs[0]), Some(&blobs[1])]));
    rig.turn();
    assert_eq!(
        rig.tile.cells.as_ref().unwrap().store().availability(&root, 3).unwrap().available,
        0b10
    );
    let mut rows = Vec::new();
    rig.inj.consume(|event: CellStoreEvent, _| {
        if let CellStoreEvent::Validation { request, outcome } = event {
            assert_eq!(outcome, CellValidationOutcome::Accepted);
            assert!(matches!(request.origin, CellOrigin::El { .. }));
            rows.push(request.pending.key.row);
        }
    });
    assert_eq!(rows, [1]);
    rig.inj.produce(CellStoreEvent::Validate(CellValidationRequest {
        pending,
        slot: SLOT,
        domain,
        deadline: allocator.slot_window().1,
        origin: CellOrigin::Gossip {
            stream_id: P2pStreamId::new(1, 0, StreamProtocol::GossipSubV13, true),
            topic: GossipTopic::DataColumnSidecar(3),
            received: Nanos::now(),
        },
    }));
    rig.turn();
    assert_eq!(rig.drain().validated, 1 << 3);
}

#[test]
fn invalid_el_proof_releases_the_claim_without_penalizing_a_peer() {
    let blobs = [BlockBlob::counting()];
    let (mut rig, block) = rig_for(ForkName::Gloas, 1 << 3, &blobs);
    let root = block_root_gloas(&block);
    let mut allocator = rig.attach_cell_store(SLOT, 1 << 3);
    rig.follow([0; 32]);
    rig.turn();
    rig.block(&block);
    rig.tile.note_staged_block(root, SLOT, &mut rig.conn.producers);
    rig.allocate_cells(&mut allocator);
    let mut response = blobs[0].el_frame();
    response[6 + 3 * BYTES_PER_KZG_PROOF..6 + 4 * BYTES_PER_KZG_PROOF]
        .copy_from_slice(&blobs[0].proofs[7].to_bytes().into_inner());
    rig.engine_blobs(root, SLOT, &response);
    rig.turn();
    rig.inj
        .consume(|event: PeerEvent, _| assert!(!matches!(event, PeerEvent::ColumnVerdict { .. })));
    let mut rejected = 0;
    rig.inj.consume(|event: CellStoreEvent, _| {
        if let CellStoreEvent::Validation { outcome, .. } = event {
            assert_eq!(outcome, CellValidationOutcome::Rejected);
            rejected += 1;
        }
    });
    assert_eq!(rejected, 1);
    assert_eq!(rig.drain().validated, 0);
    let retry = allocator
        .stage(
            CellKey { block_root: root, column: 3, row: 0 },
            &blobs[0].cells[3].to_bytes(),
            &blobs[0].proofs[3].to_bytes().into_inner(),
        )
        .unwrap()
        .unwrap();
    assert!(allocator.cancel(retry).unwrap());
}

#[test]
fn rejected_context_drops_a_response_waiting_for_allocation() {
    let blobs = [BlockBlob::counting(), BlockBlob::starting_at(1000)];
    let (mut rig, block) = rig_for(ForkName::Gloas, CUSTODY_COLUMNS, &blobs);
    let root = block_root_gloas(&block);
    let mut allocator = rig.attach_cell_store(SLOT, CUSTODY_COLUMNS);
    rig.follow([0; 32]);
    rig.turn();
    rig.block(&block);
    rig.tile.note_staged_block(root, SLOT, &mut rig.conn.producers);
    rig.engine_blobs(root, SLOT, &frame(&[Some(&blobs[0]), None]));
    rig.turn();
    rig.tile.handle_beacon_state_event(
        BeaconStateEvent::BlockRejected { block_root: root, source: BlockSource::Gossip },
        &mut rig.conn.producers,
    );
    rig.allocate_cells(&mut allocator);
    rig.turn();
    assert!(rig.tile.cells.as_ref().unwrap().store().context(&root).is_none());
    assert_eq!(rig.drain().validated, 0);
}
