use silver_common::{
    ssz_hash::kzg_commitments_inclusion_proof,
    ssz_view::{BEACON_BLOCK_BODY_FIXED, DATA_COLUMN_SIDECAR_GLOAS_MIN, EXECUTION_PAYLOAD_BID_MIN},
};

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
    fn receive_column(&mut self, source: ColumnSource, index: u64, bytes: &[u8]) {
        match source {
            ColumnSource::Gossip => self.gossip_sidecar(index, bytes),
            ColumnSource::Rpc => self.rpc_sidecar(bytes),
            ColumnSource::El => unreachable!(),
        }
    }
}

#[test]
fn column_publications_carry_metadata_for_gossip_and_following_rpc() {
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
        rig.drain();
        rig.receive_column(source, index, &blob.gloas_sidecar(index, SLOT, &block_root));
        rig.turn();
        let out = rig.drain();
        if following {
            let column = GossipDataColumn { slot: SLOT, block_root, column_index: index };
            assert_eq!(out.column_publications(), [(
                source,
                GossipTopic::DataColumnSidecar(index),
                column
            )]);
        } else {
            assert!(out.persisted(block_root, index), "syncing still processes the column");
            assert!(out.publications.is_empty(), "syncing RPC columns do not request publication");
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
            let column = GossipDataColumn { slot, block_root, column_index: 3 };
            assert_eq!(out.column_publications(), [(
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
    rig.drain();
    let sidecar = blob.gloas_sidecar(3, SLOT, &block_root);
    rig.gossip_sidecar(3, &sidecar);
    rig.turn();
    let column = GossipDataColumn { slot: SLOT, block_root, column_index: 3 };
    assert_eq!(rig.drain().column_publications(), [(
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
    rig.drain();
    rig.gossip_sidecar(3, &blob.gloas_sidecar(3, SLOT, &block_root));
    // Column 7 carries column 6's proofs: structural checks pass, KZG fails.
    rig.gossip_sidecar(7, &blob.gloas_sidecar_with_proofs(7, SLOT, &block_root, 6));
    rig.turn();
    let column = GossipDataColumn { slot: SLOT, block_root, column_index: 3 };
    assert_eq!(rig.drain().column_publications(), [(
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
