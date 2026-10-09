use flux_profiler::timed;

use crate::{
    merkle::{B256, MerkleStack, hash_fixed_bytes, hash_list, merkleize},
    ssz_hash::{hash_execution_payload_header_fulu, hash_execution_requests_fulu},
    ssz_view::{BYTES_PER_KZG_COMMITMENT, BuilderBidFuluView, MAX_BLOB_COMMITMENTS_PER_BLOCK},
};

#[timed]
pub fn hash_builder_bid_fulu(bid: &[u8]) -> B256 {
    let commitments = hash_list(
        MerkleStack::new(MAX_BLOB_COMMITMENTS_PER_BLOCK),
        BuilderBidFuluView::blob_kzg_commitments(bid)
            .chunks_exact(BYTES_PER_KZG_COMMITMENT)
            .map(hash_fixed_bytes),
    );
    merkleize(&[
        hash_execution_payload_header_fulu(BuilderBidFuluView::header(bid)),
        commitments,
        hash_execution_requests_fulu(BuilderBidFuluView::execution_requests(bid)),
        *BuilderBidFuluView::value(bid),
        hash_fixed_bytes(BuilderBidFuluView::pubkey(bid)),
    ])
}
