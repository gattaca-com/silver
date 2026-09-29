use silver_common::column_util::{
    verify_data_column_sidecar_inclusion_proof, verify_data_column_sidecar_kzg_proofs_fulu,
};

use super::*;

const SLOT: u64 = 7;

/// `SignedBlockContents` carrying `blobs` for `block`.
fn contents(block: &[u8], blobs: &[BlockBlob]) -> Vec<u8> {
    let proofs_at = 12 + block.len();
    let blobs_at = proofs_at + blobs.len() * NUMBER_OF_COLUMNS * BYTES_PER_KZG_PROOF;
    let mut out = [12, proofs_at, blobs_at].map(|at| (at as u32).to_le_bytes()).concat();
    out.extend_from_slice(block);
    for blob in blobs {
        for proof in blob.proofs.iter() {
            out.extend_from_slice(&proof.to_bytes().into_inner());
        }
    }
    for blob in blobs {
        out.extend_from_slice(blob.blob.as_ref());
    }
    out
}

fn proposed_rig(blobs: &[BlockBlob]) -> (Rig, Vec<u8>) {
    let commitments: Vec<_> = blobs.iter().flat_map(|blob| blob.commitment).collect();
    let (mut rig, block) = Rig::with_fulu_block(CUSTODY_COLUMNS, SLOT, &commitments);
    rig.follow([0; 32]);
    rig.turn();
    let ssz = tcache_write(&mut rig.engine_p, &contents(&block, blobs));
    rig.inj.produce(BeaconApiRequest::LocalGossip {
        request_id: 1,
        topic: GossipTopic::BeaconBlock,
        ssz,
    });
    rig.turn();
    rig.drain();
    (rig, block)
}

#[test]
fn proposed_block_publishes_every_column_and_keeps_its_custody() {
    let blobs = [BlockBlob::counting(), BlockBlob::starting_at(4096)];
    let (mut rig, block) = proposed_rig(&blobs);
    let root = block_root_fulu(&block);

    rig.local_block(&block);

    let out = rig.drain();
    assert_eq!(out.published_only, !CUSTODY_COLUMNS);
    assert_eq!(out.receipts.len(), CUSTODY_COLUMNS.count_ones() as usize);
    for receipt in &out.receipts {
        let DataColumnsEvent::Persist { ssz, block_root, column_index, .. } = *receipt else {
            unreachable!()
        };
        assert_eq!(block_root, root);
        assert!(CUSTODY_COLUMNS & (1 << column_index) != 0);
        let sidecar = rig.tile.proposed.producer.read_buffer(ssz).unwrap();
        assert!(verify_data_column_sidecar_kzg_proofs_fulu(sidecar), "kzg, col {column_index}");
        assert!(
            verify_data_column_sidecar_inclusion_proof(sidecar),
            "inclusion, col {column_index}"
        );
    }
    assert_eq!(out.available, 1);
    assert!(out.missing.is_empty(), "nothing of our own block is chased");
    assert_eq!(out.engine, 0, "nor fetched from the EL");
}

#[test]
fn network_block_publishes_nothing_of_the_submitted_contents() {
    let blobs = [BlockBlob::counting()];
    let (mut rig, block) = proposed_rig(&blobs);

    rig.block(&block);

    let out = rig.drain();
    assert_eq!(out.published_only, 0);
    assert!(out.receipts.is_empty());
}
