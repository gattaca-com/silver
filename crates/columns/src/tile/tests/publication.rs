use silver_common::{
    GossipDomain,
    cell_store::{CellKey, CellOrigin},
    ssz_hash::kzg_commitments_inclusion_proof,
    ssz_view::{BEACON_BLOCK_BODY_FIXED, DATA_COLUMN_SIDECAR_GLOAS_MIN, EXECUTION_PAYLOAD_BID_MIN},
};
use silver_control::cell_allocator::CellAllocator;

use super::*;

struct BlockBlob {
    commitment: [u8; 48],
    blob: c_kzg::Blob,
    cells: Box<[c_kzg::Cell; c_kzg::CELLS_PER_EXT_BLOB]>,
    proofs: Box<[c_kzg::KzgProof; c_kzg::CELLS_PER_EXT_BLOB]>,
}

impl BlockBlob {
    /// A zero blob gives every column identical cells and proofs, hiding
    /// swapped proofs. Counting field elements keeps columns
    /// distinguishable.
    fn counting() -> Self {
        let settings = c_kzg::ethereum_kzg_settings(0);
        let mut bytes = [0u8; c_kzg::BYTES_PER_BLOB];
        for (i, element) in bytes.chunks_exact_mut(32).enumerate() {
            element[30..32].copy_from_slice(&(i as u16).to_be_bytes());
        }
        let blob = c_kzg::Blob::new(bytes);
        let commitment = settings.blob_to_kzg_commitment(&blob).unwrap().to_bytes().into_inner();
        let (cells, proofs) = settings.compute_cells_and_kzg_proofs(&blob).unwrap();
        Self { commitment, blob, cells, proofs }
    }

    /// Matches the engine tile's `engine_getBlobsV2` tcache frame format.
    fn el_frame(&self) -> Vec<u8> {
        let mut out = 1u32.to_le_bytes().to_vec();
        out.push(1);
        out.push(NUMBER_OF_COLUMNS as u8);
        for proof in self.proofs.iter() {
            out.extend_from_slice(&proof.to_bytes().into_inner());
        }
        out.extend_from_slice(&(c_kzg::BYTES_PER_BLOB as u32).to_le_bytes());
        out.extend_from_slice(self.blob.as_ref());
        out
    }

    fn fulu_sidecar(&self, index: u64, block: &[u8]) -> Vec<u8> {
        let body = SignedBeaconBlockView::body(block);
        let mut header = [0u8; 208];
        header[0..8].copy_from_slice(&SignedBeaconBlockView::slot(block).to_le_bytes());
        header[8..16].copy_from_slice(&SignedBeaconBlockView::proposer_index(block).to_le_bytes());
        header[16..48].copy_from_slice(SignedBeaconBlockView::parent_root(block));
        header[48..80].copy_from_slice(SignedBeaconBlockView::state_root(block));
        header[80..112].copy_from_slice(&util::body_root(body));

        let mut out = Vec::with_capacity(util::data_column_sidecar_len(1));
        util::push_data_column_sidecar_prefix(
            &mut out,
            index,
            1,
            &header,
            &kzg_commitments_inclusion_proof(body),
        );
        out.extend_from_slice(&self.cells[index as usize].to_bytes());
        out.extend_from_slice(&self.commitment);
        out.extend_from_slice(&self.proofs[index as usize].to_bytes().into_inner());
        out
    }

    fn gloas_sidecar(&self, index: u64, slot: u64, block_root: &BlockRoot) -> Vec<u8> {
        self.gloas_sidecar_with_proofs(index, slot, block_root, index)
    }

    fn gloas_sidecar_with_proofs(
        &self,
        index: u64,
        slot: u64,
        block_root: &BlockRoot,
        proof_index: u64,
    ) -> Vec<u8> {
        let column = self.cells[index as usize].to_bytes();
        let mut out = vec![0u8; DATA_COLUMN_SIDECAR_GLOAS_MIN];
        out[0..8].copy_from_slice(&index.to_le_bytes());
        out[8..12].copy_from_slice(&(DATA_COLUMN_SIDECAR_GLOAS_MIN as u32).to_le_bytes());
        out[12..16].copy_from_slice(
            &((DATA_COLUMN_SIDECAR_GLOAS_MIN + column.len()) as u32).to_le_bytes(),
        );
        out[16..24].copy_from_slice(&slot.to_le_bytes());
        out[24..56].copy_from_slice(block_root);
        out.extend_from_slice(&column);
        out.extend_from_slice(&self.proofs[proof_index as usize].to_bytes().into_inner());
        out
    }
}

fn block_around(slot: u64, body: &[u8]) -> Vec<u8> {
    let mut block = vec![0u8; SIGNED_BEACON_BLOCK_MIN + body.len()];
    block[0..4].copy_from_slice(&100u32.to_le_bytes());
    block[100..108].copy_from_slice(&slot.to_le_bytes());
    block[180..184].copy_from_slice(&84u32.to_le_bytes());
    block[SIGNED_BEACON_BLOCK_MIN..].copy_from_slice(body);
    block
}

fn fulu_body(commitments: &[u8]) -> Vec<u8> {
    const FIXED: usize = BEACON_BLOCK_BODY_FIXED;
    let mut body = vec![0u8; FIXED + commitments.len()];
    for off in [200usize, 204, 208, 212, 216, 380, 384, 388] {
        body[off..off + 4].copy_from_slice(&(FIXED as u32).to_le_bytes());
    }
    body[392..396].copy_from_slice(&((FIXED + commitments.len()) as u32).to_le_bytes());
    body[FIXED..].copy_from_slice(commitments);
    body
}

/// Gloas carries commitments in the payload bid.
fn gloas_body(commitments: &[u8]) -> Vec<u8> {
    const FIXED: usize = BEACON_BLOCK_BODY_FIXED;
    let mut bid = vec![0u8; EXECUTION_PAYLOAD_BID_MIN + commitments.len()];
    bid[188..192].copy_from_slice(&(EXECUTION_PAYLOAD_BID_MIN as u32).to_le_bytes());
    bid[EXECUTION_PAYLOAD_BID_MIN..].copy_from_slice(commitments);

    let mut signed_bid = vec![0u8; 100];
    signed_bid[0..4].copy_from_slice(&100u32.to_le_bytes());
    signed_bid.extend_from_slice(&bid);

    let end = FIXED + signed_bid.len();
    let mut body = vec![0u8; end];
    for off in [200usize, 204, 208, 212, 216, 380, 384] {
        body[off..off + 4].copy_from_slice(&(FIXED as u32).to_le_bytes());
    }
    for off in [388usize, 392] {
        body[off..off + 4].copy_from_slice(&(end as u32).to_le_bytes());
    }
    body[FIXED..].copy_from_slice(&signed_bid);
    body
}

impl Rig {
    fn attach_cell_store(&mut self, slot: u64, columns: u128) -> CellAllocator {
        let start = Instant::now();
        let config = CellStoreConfig::new(self.tile.spec.clone(), columns, Duration::ZERO).unwrap();
        let producer = TCache::producer("", config.cache_capacity());
        let consumer = producer.cache_ref().retained_random_access("").unwrap();
        self.tile.cell_store = Some(CellStore::new(config.clone(), slot, start).unwrap());
        self.tile.data_columns_consumer = Some(Box::new(consumer));
        CellAllocator::new(config, producer, slot, start).unwrap()
    }

    fn cached_gossip(&mut self, read: TCacheRead, column: u64, domain: GossipDomain) {
        let protobuf = tcache_write(&mut self.gossip_p, b"encoded frame");
        self.tile.gossip_sidecar(
            column,
            NewGossipMsg {
                stream_id: P2pStreamId::new(1, 0, StreamProtocol::GossipSub, true),
                topic: GossipTopic::DataColumnSidecar(column),
                domain,
                ssz_source: SszSource::DataColumns,
                msg_hash: MessageId { id: [0; 20] },
                recv_ts: Nanos::now(),
                ssz: read,
                protobuf,
            },
            &mut self.conn.producers,
        );
    }

    fn allocate_cells(&mut self, allocator: &mut CellAllocator) {
        self.inj.consume(|event: CellStoreEvent, _| {
            if let CellStoreEvent::Allocate(request) = event {
                let set = allocator.allocate(request).unwrap();
                self.tile.handle_cell_event(
                    CellStoreEvent::Allocated { request, set: Some(set) },
                    Instant::now(),
                    &mut self.conn.producers,
                );
            }
        });
    }

    fn receive_column(&mut self, source: ColumnSource, index: u64, bytes: &[u8]) {
        match source {
            ColumnSource::Gossip => self.gossip_sidecar(index, bytes),
            ColumnSource::Rpc => self.rpc_sidecar(bytes),
            ColumnSource::El | ColumnSource::Assembly => unreachable!(),
        }
    }
}

#[test]
fn rpc_first_requires_validation_of_the_exact_gossip_backing() {
    const SLOT: u64 = 7;
    let blob = BlockBlob::counting();
    let block = block_around(SLOT, &gloas_body(&blob.commitment));
    let root = util::block_root_gloas(&block);
    let mut rig = Rig::gloas(CUSTODY_COLUMNS);
    let mut allocator = rig.attach_cell_store(SLOT, CUSTODY_COLUMNS);
    let domain = rig.tile.validator.domain_at(SLOT).unwrap();
    rig.follow([0; 32]);
    rig.block(&block);
    assert!(rig.tile.cell_store.as_ref().unwrap().context(&root).is_none());
    rig.tile.note_staged_block(root, SLOT, &mut rig.conn.producers);
    rig.rpc_sidecar(&blob.gloas_sidecar(3, SLOT, &root));
    rig.turn();
    assert!(rig.drain().persisted(root, 3));
    assert!(rig.tile.cell_store.as_ref().unwrap().availability(&root, 3).unwrap().full.is_none());

    let bad =
        tcache_write(allocator.producer_mut(), &blob.gloas_sidecar_with_proofs(3, SLOT, &root, 7));
    rig.cached_gossip(bad, 3, domain);
    rig.turn();
    let out = rig.drain();
    assert!(out.receipts.is_empty());
    assert!(out.publications.is_empty());
    assert!(rig.tile.cell_store.as_ref().unwrap().availability(&root, 3).unwrap().full.is_none());

    let good = tcache_write(allocator.producer_mut(), &blob.gloas_sidecar(3, SLOT, &root));
    rig.cached_gossip(good, 3, domain);
    rig.turn();
    let out = rig.drain();
    assert_eq!(out.available, 0);
    assert!(out.receipts.is_empty());
    let backing = rig.tile.cell_store.as_ref().unwrap().availability(&root, 3).unwrap();
    assert_eq!(backing.available, 1);
    assert_eq!(backing.full.unwrap().0.seq(), good.seq());
    assert!(backing.assembly.is_none(), "full backing does not wait for allocation");
}

#[test]
fn fulu_unresolved_proposer_cannot_authorize_serving() {
    let blob = BlockBlob::counting();
    for (slot, eligible) in [(7, true), (65, false)] {
        let mut rig = Rig::with_spec(CUSTODY_COLUMNS, SpecConfig {
            fulu_fork_epoch: 0,
            ..SpecConfig::mainnet()
        });
        let mut allocator = rig.attach_cell_store(slot, CUSTODY_COLUMNS);
        let block = block_around(slot, &fulu_body(&blob.commitment));
        let root = util::block_root_fulu(&block);
        let bytes = blob.fulu_sidecar(3, &block);
        rig.follow(*SignedBeaconBlockView::parent_root(&block));
        rig.tile.tracker.set_signature(root, *DataColumnSidecarFuluView::block_signature(&bytes));
        let domain = rig.tile.validator.domain_at(slot).unwrap();
        let read = tcache_write(allocator.producer_mut(), &bytes);
        rig.cached_gossip(read, 3, domain);
        rig.turn();
        assert_eq!(rig.tile.cell_store.as_ref().unwrap().context(&root).is_some(), eligible);
        assert_eq!(!rig.drain().publications.is_empty(), eligible);
    }
}

#[test]
fn gloas_context_needs_approval_in_either_arrival_order_and_is_revocable() {
    const SLOT: u64 = 7;
    let blob = BlockBlob::counting();
    let block = block_around(SLOT, &gloas_body(&blob.commitment));
    let root = util::block_root_gloas(&block);
    for approval_first in [false, true] {
        let mut rig = Rig::gloas(CUSTODY_COLUMNS);
        let mut allocator = rig.attach_cell_store(SLOT, CUSTODY_COLUMNS);
        if approval_first {
            rig.tile.note_staged_block(root, SLOT, &mut rig.conn.producers);
        } else {
            rig.block(&block);
        }
        assert!(rig.tile.cell_store.as_ref().unwrap().context(&root).is_none());
        if approval_first {
            rig.block(&block);
        } else {
            rig.tile.note_staged_block(root, SLOT, &mut rig.conn.producers);
        }
        assert!(rig.tile.cell_store.as_ref().unwrap().context(&root).is_some());
        rig.allocate_cells(&mut allocator);
        rig.tile.handle_beacon_state_event(
            BeaconStateEvent::BlockRejected { block_root: root, source: BlockSource::Gossip },
            &mut rig.conn.producers,
        );
        assert!(rig.tile.cell_store.as_ref().unwrap().context(&root).is_none());
        assert!(rig.tile.validator.gloas_commitments(&root).is_none());
        rig.inj.consume(|event: CellStoreEvent, _| {
            if let CellStoreEvent::RejectedContext { block_root } = event {
                allocator.reject(&block_root);
            }
        });
        assert!(allocator.column(CellKey { block_root: root, column: 3, row: 0 }).is_none());
    }
}

#[test]
fn gloas_commitment_capacity_covers_the_retention_window() {
    let blob = BlockBlob::counting();
    let body = gloas_body(&blob.commitment);
    let mut rig = Rig::gloas(CUSTODY_COLUMNS);
    for slot in 1..=4 * SLOTS_PER_EPOCH {
        let block = block_around(slot, &body);
        let root = util::block_root_gloas(&block);
        rig.tile.validator.cache_gloas_commitments(root, &block);
        rig.tile.validator.note_validated(root, slot);
        assert_eq!(rig.tile.validator.gloas_commitments(&root), Some(blob.commitment.as_slice()));
    }
}

#[test]
fn verified_assemblies_complete_da_persist_and_publish_once_in_both_forks() {
    const SLOT: u64 = 7;
    let blob = BlockBlob::counting();
    for format in [ForkName::Fulu, ForkName::Gloas] {
        let mut rig = Rig::with_spec(CUSTODY_COLUMNS, SpecConfig {
            fulu_fork_epoch: 0,
            gloas_fork_epoch: if format == ForkName::Gloas { 0 } else { u64::MAX },
            ..SpecConfig::mainnet()
        });
        let mut allocator = rig.attach_cell_store(SLOT, CUSTODY_COLUMNS);
        rig.follow([0; 32]);
        let body = if format == ForkName::Fulu {
            fulu_body(&blob.commitment)
        } else {
            gloas_body(&blob.commitment)
        };
        let block = block_around(SLOT, &body);
        let root = util::block_root(&block, format == ForkName::Gloas);
        let domain = rig.tile.validator.domain_at(SLOT).unwrap();
        if format == ForkName::Gloas {
            rig.block(&block);
            rig.tile.note_staged_block(root, SLOT, &mut rig.conn.producers);
        } else {
            let bytes = blob.fulu_sidecar(3, &block);
            rig.tile
                .tracker
                .set_signature(root, *DataColumnSidecarFuluView::block_signature(&bytes));
            let read = tcache_write(allocator.producer_mut(), &bytes);
            rig.cached_gossip(read, 3, domain);
            rig.turn();
            assert!(rig.drain().persisted(root, 3));
        }
        rig.allocate_cells(&mut allocator);
        rig.drain();
        for column in [3usize, 7] {
            let key = CellKey { block_root: root, column, row: 0 };
            let cell = blob.cells[column].to_bytes();
            let proof = blob.proofs[column].to_bytes().into_inner();
            let pending = allocator.stage(key, &cell, &proof).unwrap().unwrap();
            assert!(allocator.stage(key, &[0; c_kzg::BYTES_PER_CELL], &proof).unwrap().is_none());
            let request = CellValidationRequest {
                pending,
                domain,
                deadline: rig.tile.cell_store.as_ref().unwrap().slot_end(),
                origin: CellOrigin::El { request_id: 0 },
            };
            assert!(matches!(
                rig.tile.validate_cell(request, Instant::now()),
                CellValidationOutcome::Accepted
            ));
        }
        rig.tile.flush_cell_updates(&mut rig.conn.producers);
        let out = rig.drain();
        assert_eq!(out.available, 1);
        assert_eq!(out.custody_complete, 1);
        let completed = if format == ForkName::Fulu { 1 } else { 2 };
        assert_eq!(out.receipts.len(), completed);
        assert!(out.publications.is_empty(), "assemblies publish through Persist in Control");
        for event in out.receipts {
            let DataColumnsEvent::Persist {
                source: ColumnSource::Assembly,
                ssz_source: SszSource::DataColumns,
                ssz,
                domain: published_domain,
                column_index,
                ..
            } = event
            else {
                panic!("expected an assembled column")
            };
            assert_eq!(published_domain, Some(domain));
            let read =
                rig.tile.data_columns_consumer.as_mut().unwrap().acquire_strict(ssz).unwrap();
            let expected = if format == ForkName::Fulu {
                blob.fulu_sidecar(column_index, &block)
            } else {
                blob.gloas_sidecar(column_index, SLOT, &root)
            };
            assert_eq!(read.buffer().unwrap().0, expected);
        }
        rig.tile.flush_cell_updates(&mut rig.conn.producers);
        let out = rig.drain();
        assert_eq!(out.available, 0);
        assert_eq!(out.custody_complete, 0);
        assert!(out.receipts.is_empty());
        assert!(out.publications.is_empty());
    }
}

#[test]
fn strict_ingress_rejects_below_tail_and_expiry_releases_parked_columns() {
    const SLOT: u64 = 7;
    let blob = BlockBlob::counting();
    let mut rig = Rig::gloas(CUSTODY_COLUMNS);
    let mut allocator = rig.attach_cell_store(SLOT, CUSTODY_COLUMNS);
    let domain = rig.tile.validator.domain_at(SLOT).unwrap();
    let root = [9; 32];
    let read = tcache_write(allocator.producer_mut(), &blob.gloas_sidecar(3, SLOT, &root));
    rig.cached_gossip(read, 3, domain);
    assert!(rig.tile.gloas_pending_columns.contains(&root));
    tcache_write(allocator.producer_mut(), &[0; 32 * 1024]);
    rig.turn();
    rig.inj.produce(RetentionEvent {
        expired_slot: SLOT,
        retain_from: allocator.producer().next_seq(),
    });
    rig.turn();
    assert!(rig.tile.gloas_pending_columns.is_empty());
    rig.cached_gossip(read, 3, domain);
    assert!(rig.tile.gloas_pending_columns.is_empty());
    assert!(rig.tile.kzg_batch.is_empty());
    assert!(rig.drain().receipts.is_empty());
}

#[test]
fn gossip_columns_are_relayed_and_rpc_columns_only_persisted() {
    const SLOT: u64 = 40;
    let blob = BlockBlob::counting();
    let block = block_around(SLOT, &gloas_body(&blob.commitment));
    let block_root = util::block_root_gloas(&block);
    for (source, following, index) in [
        (ColumnSource::Gossip, true, 3),
        (ColumnSource::Gossip, true, 5),
        (ColumnSource::Rpc, true, 3),
        (ColumnSource::Rpc, true, 5),
        (ColumnSource::Rpc, false, 3),
    ] {
        let mut rig = Rig::gloas(CUSTODY_COLUMNS);
        if following {
            rig.follow([0xAA; 32]);
        }
        rig.block(&block);
        rig.tile.note_staged_block(block_root, SLOT, &mut rig.conn.producers);
        rig.drain();
        rig.receive_column(source, index, &blob.gloas_sidecar(index, SLOT, &block_root));
        rig.turn();
        let out = rig.drain();
        if source == ColumnSource::Gossip {
            let column = SidecarIdentity { slot: SLOT, block_root, column_index: index };
            assert_eq!(out.publications, [(source, GossipTopic::DataColumnSidecar(index), column)]);
            assert_eq!(out.domains, [rig.tile.validator.domain_at(SLOT).unwrap()]);
        } else {
            assert_eq!(
                out.persisted(block_root, index),
                CUSTODY_COLUMNS & (1 << index) != 0,
                "following={following}: custody columns persist"
            );
            assert!(
                out.publications.is_empty(),
                "following={following}: RPC columns are republished off `Persist`, not here"
            );
        }
    }
}

#[test]
fn fulu_column_publication_requires_a_resolved_proposer() {
    let blob = BlockBlob::counting();
    // The empty state's lookahead covers the current and next epochs.
    for (slot, relay_eligible) in [(7, true), (2 * SLOTS_PER_EPOCH + 1, false)] {
        let block = block_around(slot, &fulu_body(&blob.commitment));
        let block_root = util::block_root_fulu(&block);
        let mut rig = Rig::new(CUSTODY_COLUMNS);
        rig.follow(*SignedBeaconBlockView::parent_root(&block));
        let sidecar = blob.fulu_sidecar(3, &block);
        // Fixture bypass: the empty validator registry cannot verify signatures.
        // This isolates proposer eligibility; the staged-parent case uses signed data.
        rig.tile
            .tracker
            .set_signature(block_root, *DataColumnSidecarFuluView::block_signature(&sidecar));
        rig.gossip_sidecar(3, &sidecar);
        rig.turn();
        let out = rig.drain();
        if relay_eligible {
            let column = SidecarIdentity { slot, block_root, column_index: 3 };
            assert_eq!(out.publications, [(
                ColumnSource::Gossip,
                GossipTopic::DataColumnSidecar(3),
                column
            )]);
        } else {
            assert!(
                out.persisted(block_root, 3),
                "an unresolved proposer does not prevent storage"
            );
            assert!(out.publications.is_empty(), "an unresolved proposer prevents relay");
        }
    }
}

#[test]
fn held_columns_do_not_request_publication_again() {
    const SLOT: u64 = 40;
    let blob = BlockBlob::counting();
    let block = block_around(SLOT, &gloas_body(&blob.commitment));
    let block_root = util::block_root_gloas(&block);
    let mut rig = Rig::gloas(CUSTODY_COLUMNS);
    rig.follow([0xAA; 32]);
    rig.block(&block);
    rig.tile.note_staged_block(block_root, SLOT, &mut rig.conn.producers);
    rig.drain();
    let sidecar = blob.gloas_sidecar(3, SLOT, &block_root);
    rig.gossip_sidecar(3, &sidecar);
    rig.turn();
    let column = SidecarIdentity { slot: SLOT, block_root, column_index: 3 };
    assert_eq!(rig.drain().publications, [(
        ColumnSource::Gossip,
        GossipTopic::DataColumnSidecar(3),
        column
    )]);

    for source in [ColumnSource::Gossip, ColumnSource::Rpc] {
        rig.receive_column(source, 3, &sidecar);
        rig.turn();
        assert!(rig.drain().publications.is_empty(), "{source:?}: a held copy is not republished");
    }
}

#[test]
fn only_columns_with_valid_kzg_proofs_request_publication() {
    const SLOT: u64 = 40;
    let blob = BlockBlob::counting();
    let block = block_around(SLOT, &gloas_body(&blob.commitment));
    let block_root = util::block_root_gloas(&block);
    let mut rig = Rig::gloas(CUSTODY_COLUMNS);
    rig.follow([0xAA; 32]);
    rig.block(&block);
    rig.tile.note_staged_block(block_root, SLOT, &mut rig.conn.producers);
    rig.drain();
    rig.gossip_sidecar(3, &blob.gloas_sidecar(3, SLOT, &block_root));
    // Column 7 carries column 6's proofs: structural checks pass, KZG fails.
    rig.gossip_sidecar(7, &blob.gloas_sidecar_with_proofs(7, SLOT, &block_root, 6));
    rig.turn();
    let column = SidecarIdentity { slot: SLOT, block_root, column_index: 3 };
    assert_eq!(rig.drain().publications, [(
        ColumnSource::Gossip,
        GossipTopic::DataColumnSidecar(3),
        column
    )]);
}

#[test]
fn buffered_gloas_columns_are_processed_without_publication() {
    const SLOT: u64 = 40;
    let blob = BlockBlob::counting();
    let block = block_around(SLOT, &gloas_body(&blob.commitment));
    let block_root = util::block_root_gloas(&block);
    for source in [ColumnSource::Gossip, ColumnSource::Rpc] {
        let mut rig = Rig::gloas(CUSTODY_COLUMNS);
        rig.follow([0xAA; 32]);
        rig.receive_column(source, 3, &blob.gloas_sidecar(3, SLOT, &block_root));
        rig.turn();
        assert!(rig.drain().publications.is_empty());
        rig.block(&block);
        rig.tile.note_staged_block(block_root, SLOT, &mut rig.conn.producers);
        rig.turn();
        let out = rig.drain();
        assert!(out.persisted(block_root, 3), "the buffered column was processed");
        assert!(out.publications.is_empty(), "processing a buffered copy does not request relay");
    }
}

#[test]
fn reconstructed_columns_do_not_request_publication() {
    const SLOT: u64 = 40;
    let blob = BlockBlob::counting();
    let block = block_around(SLOT, &fulu_body(&blob.commitment));
    let block_root = util::block_root_fulu(&block);
    let mut rig = Rig::new(CUSTODY_COLUMNS);
    rig.turn();
    rig.follow([0xAA; 32]);
    rig.block(&block);
    rig.tile.note_staged_block(block_root, SLOT, &mut rig.conn.producers);
    rig.drain();
    rig.engine_blobs(block_root, SLOT, &blob.el_frame());
    rig.turn();
    let out = rig.drain();
    assert!(
        out.receipts.iter().any(|event| matches!(event,
            DataColumnsEvent::Persist { source: ColumnSource::El, block_root: root, .. }
                if *root == block_root
        )),
        "the EL response produced a reconstructed column"
    );
    assert!(out.publications.is_empty());
}

/// A column that arrives by gossip and by EL rebuild in one turn is validated
/// once, and the EL does not rebuild it.
#[test]
fn gossip_and_el_copies_validate_once() {
    const SLOT: u64 = 40;
    let blob = BlockBlob::counting();
    let block = block_around(SLOT, &fulu_body(&blob.commitment));
    let block_root = util::block_root_fulu(&block);
    let mut rig = Rig::new(CUSTODY_COLUMNS);
    rig.turn();
    rig.follow([0xAA; 32]);
    rig.block(&block);
    rig.drain();

    let sidecar = blob.fulu_sidecar(3, &block);
    // Fixture bypass: the empty validator registry cannot verify signatures.
    rig.tile
        .tracker
        .set_signature(block_root, *DataColumnSidecarFuluView::block_signature(&sidecar));
    rig.receive_column(ColumnSource::Gossip, 3, &sidecar);
    rig.engine_blobs(block_root, SLOT, &blob.el_frame());
    rig.turn();
    let out = rig.drain();

    assert_eq!(out.validated, CUSTODY_COLUMNS, "each custody column is validated once");
    let el_built = out.receipts.iter().fold(0u128, |mask, event| match event {
        DataColumnsEvent::Persist { source: ColumnSource::El, column_index, .. } => {
            mask | 1 << column_index
        }
        _ => mask,
    });
    assert_eq!(
        el_built,
        CUSTODY_COLUMNS & !(1 << 3),
        "the EL rebuilds only what gossip did not deliver"
    );
    assert!(out.persisted(block_root, 3), "the gossip copy reached storage");
}
