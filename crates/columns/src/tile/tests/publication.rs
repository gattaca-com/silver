use blst::min_pk::SecretKey;
use silver_beacon_state_data::{
    EpochStateFinalized, ValSeed,
    types::{EpochState, Fork},
};
use silver_common::{
    GossipDomain, TCacheId, TCacheTable, block_root_fulu, block_root_gloas, body_root,
    cell_store::{CellKey, CellOrigin, CellValidationRequest},
    merkle::hash_concat,
    ssz_hash::{hash_tree_root_fork_data, kzg_commitments_inclusion_proof},
    ssz_view::DATA_COLUMN_SIDECAR_GLOAS_MIN,
    test_util::{SynthBid, SynthBlock},
};
use silver_control::cell_allocator::CellAllocator;

use super::*;

mod el;
mod partial;

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
        Self::starting_at(0)
    }

    fn starting_at(start: u16) -> Self {
        let settings = c_kzg::ethereum_kzg_settings(0);
        let mut bytes = [0u8; c_kzg::BYTES_PER_BLOB];
        for (i, element) in bytes.chunks_exact_mut(32).enumerate() {
            element[30..32].copy_from_slice(&(start + i as u16).to_be_bytes());
        }
        let blob = c_kzg::Blob::new(bytes);
        let commitment = settings.blob_to_kzg_commitment(&blob).unwrap().to_bytes().into_inner();
        let (cells, proofs) = settings.compute_cells_and_kzg_proofs(&blob).unwrap();
        Self { commitment, blob, cells, proofs }
    }

    /// Matches the engine tile's `engine_getBlobsV3` tcache frame format.
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
        header[80..112].copy_from_slice(&body_root(body));
        header[112..].copy_from_slice(SignedBeaconBlockView::signature(block));

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

impl Rig {
    fn with_fulu_block(custody: u128, slot: u64, commitments: &[u8]) -> (Self, Vec<u8>) {
        let key = SecretKey::key_gen(&[42; 32], &[]).unwrap();
        let spec = fulu_from_genesis();
        let state = BeaconState::for_test(
            EpochStateFinalized::from_state(EpochState {
                fork: Fork { current_version: spec.fork_version_at(0), ..Default::default() },
                ..Default::default()
            }),
            &[ValSeed { pubkey: key.sk_to_pk().to_bytes(), ..Default::default() }],
            0,
        );
        let mut owner = BeaconStateOwner::new(state);
        let anchor = owner.roll_fresh();
        owner.publish_state_id(anchor);
        let mut block = SynthBlock::fulu(slot, commitments).into_bytes();
        let root = block_root_fulu(&block);
        let fork_root =
            hash_tree_root_fork_data(spec.fork_version_at(slot / SLOTS_PER_EPOCH), &[0; 32]);
        let mut domain = [0; 32];
        domain[4..].copy_from_slice(&fork_root[..28]);
        block[4..100].copy_from_slice(
            &key.sign(
                &hash_concat(&root, &domain),
                b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_",
                &[],
            )
            .to_bytes(),
        );
        (Self::with_state(custody, owner.reader(), spec), block)
    }

    fn attach_cell_store(&mut self, slot: u64, columns: u128) -> CellAllocator {
        let start = Instant::now();
        let config = CellStoreConfig::new(self.tile.spec.clone(), columns, Duration::ZERO).unwrap();
        let producer = TCache::producer(TCacheId::ControlSlot, config.cache_capacity());
        let tcaches = TCacheTable::from_iter([producer.cache_ref()]);
        let mut cells = CellHandler::new(config.clone(), tcaches, slot, start).unwrap();
        cells.open_tcaches().unwrap();
        self.tile.cells = Some(cells);
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
                ssz_cache: SszCache::DataColumns,
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
                self.tile.cells.as_mut().unwrap().handle_event(
                    CellStoreEvent::Allocated { request, set: Some(set) },
                    Instant::now(),
                    &mut self.conn.producers,
                );
            }
        });
    }

    fn receive_column(&mut self, origin: ColumnOrigin, index: u64, bytes: &[u8]) {
        match origin {
            ColumnOrigin::Gossip => self.gossip_sidecar(index, bytes),
            ColumnOrigin::Rpc => self.rpc_sidecar(bytes),
            ColumnOrigin::El | ColumnOrigin::Assembly => unreachable!(),
        }
    }
}

#[test]
fn rpc_first_requires_validation_of_the_exact_gossip_backing() {
    const SLOT: u64 = 7;
    let blob = BlockBlob::counting();
    let block = SynthBlock::gloas(SLOT, SynthBid::new(&blob.commitment)).into_bytes();
    let root = block_root_gloas(&block);
    let mut rig = Rig::gloas(CUSTODY_COLUMNS);
    let mut allocator = rig.attach_cell_store(SLOT, CUSTODY_COLUMNS);
    let domain = rig.tile.validator.domain_at(SLOT).unwrap();
    rig.follow([0; 32]);
    rig.block(&block);
    assert!(rig.tile.cells.as_ref().unwrap().store().context(&root).is_none());
    rig.tile.note_staged_block(root, SLOT, &mut rig.conn.producers);
    rig.rpc_sidecar(&blob.gloas_sidecar(3, SLOT, &root));
    rig.turn();
    let out = rig.drain();
    assert!(out.persisted(root, 3));
    assert_eq!(out.validated, 1 << 3);
    assert!(
        rig.tile.cells.as_ref().unwrap().store().availability(&root, 3).unwrap().full.is_none()
    );

    let bad =
        tcache_write(allocator.producer_mut(), &blob.gloas_sidecar_with_proofs(3, SLOT, &root, 7));
    rig.cached_gossip(bad, 3, domain);
    rig.turn();
    let out = rig.drain();
    assert_eq!(out.validated, 0);
    assert!(out.receipts.is_empty());
    assert!(out.publications.is_empty());
    assert!(
        rig.tile.cells.as_ref().unwrap().store().availability(&root, 3).unwrap().full.is_none()
    );

    let good = tcache_write(allocator.producer_mut(), &blob.gloas_sidecar(3, SLOT, &root));
    rig.cached_gossip(good, 3, domain);
    rig.turn();
    let out = rig.drain();
    assert_eq!(out.validated, 0, "revalidating a backing does not repeat the column event");
    assert_eq!(out.available, 0);
    assert!(out.receipts.is_empty());
    let backing = rig.tile.cells.as_ref().unwrap().store().availability(&root, 3).unwrap();
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
        let block = SynthBlock::fulu(slot, &blob.commitment).into_bytes();
        let root = block_root_fulu(&block);
        let bytes = blob.fulu_sidecar(3, &block);
        rig.follow(*SignedBeaconBlockView::parent_root(&block));
        rig.tile.tracker.set_signature(
            root,
            *DataColumnSidecarFuluView::block_signature(&bytes),
            [0; 4],
        );
        let domain = rig.tile.validator.domain_at(slot).unwrap();
        let read = tcache_write(allocator.producer_mut(), &bytes);
        rig.cached_gossip(read, 3, domain);
        rig.turn();
        assert_eq!(rig.tile.cells.as_ref().unwrap().store().context(&root).is_some(), eligible);
        assert_eq!(!rig.drain().publications.is_empty(), eligible);
    }
}

#[test]
fn gloas_context_needs_approval_in_either_arrival_order_and_is_revocable() {
    const SLOT: u64 = 7;
    let blob = BlockBlob::counting();
    let block = SynthBlock::gloas(SLOT, SynthBid::new(&blob.commitment)).into_bytes();
    let root = block_root_gloas(&block);
    for approval_first in [false, true] {
        let mut rig = Rig::gloas(CUSTODY_COLUMNS);
        let mut allocator = rig.attach_cell_store(SLOT, CUSTODY_COLUMNS);
        if approval_first {
            rig.tile.note_staged_block(root, SLOT, &mut rig.conn.producers);
        } else {
            rig.block(&block);
        }
        assert!(rig.tile.cells.as_ref().unwrap().store().context(&root).is_none());
        if approval_first {
            rig.block(&block);
        } else {
            rig.tile.note_staged_block(root, SLOT, &mut rig.conn.producers);
        }
        assert!(rig.tile.cells.as_ref().unwrap().store().context(&root).is_some());
        rig.allocate_cells(&mut allocator);
        rig.tile.handle_beacon_state_event(
            BeaconStateEvent::BlockRejected { block_root: root, source: BlockSource::Gossip },
            &mut rig.conn.producers,
        );
        assert!(rig.tile.cells.as_ref().unwrap().store().context(&root).is_none());
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
    let mut rig = Rig::gloas(CUSTODY_COLUMNS);
    for slot in 1..=4 * SLOTS_PER_EPOCH {
        let block = SynthBlock::gloas(slot, SynthBid::new(&blob.commitment)).into_bytes();
        let root = block_root_gloas(&block);
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
        let block = if format == ForkName::Fulu {
            SynthBlock::fulu(SLOT, &blob.commitment)
        } else {
            SynthBlock::gloas(SLOT, SynthBid::new(&blob.commitment))
        }
        .into_bytes();
        let root = block_root(&block, format == ForkName::Gloas);
        let domain = rig.tile.validator.domain_at(SLOT).unwrap();
        if format == ForkName::Gloas {
            rig.block(&block);
            rig.tile.note_staged_block(root, SLOT, &mut rig.conn.producers);
        } else {
            let bytes = blob.fulu_sidecar(3, &block);
            rig.tile.tracker.set_signature(
                root,
                *DataColumnSidecarFuluView::block_signature(&bytes),
                [0; 4],
            );
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
                slot: SLOT,
                domain,
                deadline: rig.tile.cells.as_ref().unwrap().store().slot_end(),
                origin: CellOrigin::El { request_id: 0 },
            };
            rig.tile.cells.as_mut().unwrap().handle_event(
                CellStoreEvent::Validate(request),
                Instant::now(),
                &mut rig.conn.producers,
            );
        }
        rig.tile.flush_kzg_batch(&mut rig.conn.producers);
        let mut outcomes = Vec::new();
        rig.inj.consume(|event: CellStoreEvent, _| {
            if let CellStoreEvent::Validation { request, outcome } = event {
                outcomes.push((request.pending.key.column, outcome));
            }
        });
        assert_eq!(outcomes.len(), 2);
        for (column, outcome) in outcomes {
            assert_eq!(
                outcome,
                if format == ForkName::Fulu && column == 3 {
                    CellValidationOutcome::Ignored
                } else {
                    CellValidationOutcome::Accepted
                }
            );
        }
        rig.tile
            .cells
            .as_mut()
            .unwrap()
            .flush_updates(&mut rig.tile.tracker, &mut rig.conn.producers);
        let out = rig.drain();
        assert_eq!(out.available, 1);
        assert_eq!(out.custody_complete, 1);
        let newly_validated = if format == ForkName::Fulu { 1 << 7 } else { CUSTODY_COLUMNS };
        assert_eq!(out.validated, newly_validated);
        let completed = if format == ForkName::Fulu { 1 } else { 2 };
        assert_eq!(out.receipts.len(), completed);
        assert!(out.publications.is_empty(), "assemblies publish through Persist in Control");
        for event in out.receipts {
            let DataColumnsEvent::Persist {
                origin: ColumnOrigin::Assembly,
                ssz_cache: SszCache::DataColumns,
                ssz,
                domain: published_domain,
                column_index,
                ..
            } = event
            else {
                panic!("expected an assembled column")
            };
            assert_eq!(published_domain, Some(domain));
            let read = rig.tile.cells.as_mut().unwrap().acquire(ssz).unwrap();
            let expected = if format == ForkName::Fulu {
                blob.fulu_sidecar(column_index, &block)
            } else {
                blob.gloas_sidecar(column_index, SLOT, &root)
            };
            assert_eq!(read.buffer().unwrap().0, expected);
        }
        rig.tile
            .cells
            .as_mut()
            .unwrap()
            .flush_updates(&mut rig.tile.tracker, &mut rig.conn.producers);
        let out = rig.drain();
        assert_eq!(out.available, 0);
        assert_eq!(out.custody_complete, 0);
        assert_eq!(out.validated, 0);
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
    // The tail follows the allocator's floor, not the event: it moves once
    // the reader has taken and applied a snapshot over its next passes.
    let boundary = allocator.producer().next_seq();
    allocator.producer_mut().retain_from(boundary);
    allocator.producer_mut().loop_start();
    rig.turn();
    assert!(rig.tile.gloas_pending_columns.is_empty());
    for _ in 0..3 {
        rig.turn();
    }
    rig.cached_gossip(read, 3, domain);
    assert!(rig.tile.gloas_pending_columns.is_empty());
    assert!(rig.tile.kzg_batch.is_empty());
    assert!(rig.drain().receipts.is_empty());
}

#[test]
fn gossip_columns_are_relayed_and_rpc_columns_only_persisted() {
    const SLOT: u64 = 40;
    let blob = BlockBlob::counting();
    let block = SynthBlock::gloas(SLOT, SynthBid::new(&blob.commitment)).into_bytes();
    let block_root = block_root_gloas(&block);
    for (origin, following, index) in [
        (ColumnOrigin::Gossip, true, 3),
        (ColumnOrigin::Gossip, true, 5),
        (ColumnOrigin::Rpc, true, 3),
        (ColumnOrigin::Rpc, true, 5),
        (ColumnOrigin::Rpc, false, 3),
    ] {
        let mut rig = Rig::gloas(CUSTODY_COLUMNS);
        if following {
            rig.follow([0xAA; 32]);
        }
        rig.block(&block);
        rig.tile.note_staged_block(block_root, SLOT, &mut rig.conn.producers);
        rig.drain();
        rig.receive_column(origin, index, &blob.gloas_sidecar(index, SLOT, &block_root));
        rig.turn();
        let out = rig.drain();
        if origin == ColumnOrigin::Gossip {
            let column = SidecarIdentity { slot: SLOT, block_root, column_index: index };
            assert_eq!(out.publications, [(origin, GossipTopic::DataColumnSidecar(index), column)]);
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
fn fulu_columns_are_not_accepted_at_or_after_gloas_activation() {
    let blob = BlockBlob::counting();
    let spec = SpecConfig { fulu_fork_epoch: 0, gloas_fork_epoch: 1, ..SpecConfig::mainnet() };
    let activation_slot = spec.gloas_fork_epoch * SLOTS_PER_EPOCH;
    for slot in [activation_slot - 1, activation_slot, activation_slot + 1] {
        for source in [ColumnOrigin::Gossip, ColumnOrigin::Rpc] {
            let block = SynthBlock::fulu(slot, &blob.commitment).into_bytes();
            let block_root = block_root_fulu(&block);
            let sidecar = blob.fulu_sidecar(3, &block);
            let mut rig = Rig::with_spec(CUSTODY_COLUMNS, spec.clone());
            rig.follow(*SignedBeaconBlockView::parent_root(&block));
            // The empty registry cannot verify signatures. Cache the signature to
            // isolate the layout gate while exercising shape, inclusion and KZG checks.
            rig.tile.tracker.set_signature(
                block_root,
                *DataColumnSidecarFuluView::block_signature(&sidecar),
                [0; 4],
            );

            rig.receive_column(source, 3, &sidecar);
            rig.turn();
            let out = rig.drain();
            if slot < activation_slot {
                assert!(out.persisted(block_root, 3), "{source:?} at slot {slot}");
                assert_eq!(out.validated, 1 << 3, "{source:?} at slot {slot}");
                assert_eq!(out.publications.is_empty(), source != ColumnOrigin::Gossip);
            } else {
                assert_eq!(out.validated, 0, "{source:?} at slot {slot}");
                assert!(out.receipts.is_empty(), "{source:?} at slot {slot}");
                assert!(out.publications.is_empty(), "{source:?} at slot {slot}");
            }
        }
    }
}

#[test]
fn fulu_column_publication_requires_a_resolved_proposer() {
    let blob = BlockBlob::counting();
    // The empty state's lookahead covers the current and next epochs.
    for (slot, relay_eligible) in [(7, true), (2 * SLOTS_PER_EPOCH + 1, false)] {
        let block = SynthBlock::fulu(slot, &blob.commitment).into_bytes();
        let block_root = block_root_fulu(&block);
        let mut rig = Rig::new(CUSTODY_COLUMNS);
        rig.follow(*SignedBeaconBlockView::parent_root(&block));
        let sidecar = blob.fulu_sidecar(3, &block);
        // Fixture bypass: the empty validator registry cannot verify signatures.
        // This isolates proposer eligibility; the staged-parent case uses signed data.
        rig.tile.tracker.set_signature(
            block_root,
            *DataColumnSidecarFuluView::block_signature(&sidecar),
            [0; 4],
        );
        rig.gossip_sidecar(3, &sidecar);
        rig.turn();
        let out = rig.drain();
        if relay_eligible {
            let column = SidecarIdentity { slot, block_root, column_index: 3 };
            assert_eq!(out.publications, [(
                ColumnOrigin::Gossip,
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
    let block = SynthBlock::gloas(SLOT, SynthBid::new(&blob.commitment)).into_bytes();
    let block_root = block_root_gloas(&block);
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
        ColumnOrigin::Gossip,
        GossipTopic::DataColumnSidecar(3),
        column
    )]);

    for origin in [ColumnOrigin::Gossip, ColumnOrigin::Rpc] {
        rig.receive_column(origin, 3, &sidecar);
        rig.turn();
        assert!(rig.drain().publications.is_empty(), "{origin:?}: a held copy is not republished");
    }
}

#[test]
fn only_columns_with_valid_kzg_proofs_request_publication() {
    const SLOT: u64 = 40;
    let blob = BlockBlob::counting();
    let block = SynthBlock::gloas(SLOT, SynthBid::new(&blob.commitment)).into_bytes();
    let block_root = block_root_gloas(&block);
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
        ColumnOrigin::Gossip,
        GossipTopic::DataColumnSidecar(3),
        column
    )]);
}

#[test]
fn buffered_gloas_columns_are_processed_without_publication() {
    const SLOT: u64 = 40;
    let blob = BlockBlob::counting();
    let block = SynthBlock::gloas(SLOT, SynthBid::new(&blob.commitment)).into_bytes();
    let block_root = block_root_gloas(&block);
    for origin in [ColumnOrigin::Gossip, ColumnOrigin::Rpc] {
        let mut rig = Rig::gloas(CUSTODY_COLUMNS);
        rig.follow([0xAA; 32]);
        rig.receive_column(origin, 3, &blob.gloas_sidecar(3, SLOT, &block_root));
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
    const SLOT: u64 = 7;
    let blob = BlockBlob::counting();
    let (mut rig, block) = Rig::with_fulu_block(CUSTODY_COLUMNS, SLOT, &blob.commitment);
    let mut allocator = rig.attach_cell_store(SLOT, CUSTODY_COLUMNS);
    let block_root = block_root_fulu(&block);
    rig.turn();
    rig.follow([0; 32]);
    rig.block(&block);
    rig.tile.note_staged_block(block_root, SLOT, &mut rig.conn.producers);
    rig.allocate_cells(&mut allocator);
    rig.drain();
    rig.engine_blobs(block_root, SLOT, &blob.el_frame());
    rig.turn();
    let out = rig.drain();
    assert!(
        out.receipts.iter().any(|event| matches!(event,
            DataColumnsEvent::Persist { origin: ColumnOrigin::Assembly, block_root: root, .. }
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
    const SLOT: u64 = 7;
    let blob = BlockBlob::counting();
    let (mut rig, block) = Rig::with_fulu_block(CUSTODY_COLUMNS, SLOT, &blob.commitment);
    let mut allocator = rig.attach_cell_store(SLOT, CUSTODY_COLUMNS);
    let block_root = block_root_fulu(&block);
    rig.turn();
    rig.follow([0; 32]);
    rig.block(&block);
    rig.tile.note_staged_block(block_root, SLOT, &mut rig.conn.producers);
    rig.allocate_cells(&mut allocator);
    rig.drain();

    let sidecar = blob.fulu_sidecar(3, &block);
    rig.receive_column(ColumnOrigin::Gossip, 3, &sidecar);
    rig.engine_blobs(block_root, SLOT, &blob.el_frame());
    rig.turn();
    let out = rig.drain();

    assert_eq!(out.validated, CUSTODY_COLUMNS, "each custody column is validated once");
    let el_built = out.receipts.iter().fold(0u128, |mask, event| match event {
        DataColumnsEvent::Persist { origin: ColumnOrigin::Assembly, column_index, .. } => {
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
