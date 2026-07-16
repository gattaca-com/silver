use crate::{
    merkle::{B256, ZERO_HASH, hash_fixed_bytes, hash_list, merkleize, uint64_chunk},
    progressive::{ProgressiveContainer, ProgressiveHasher, packed_active_fields},
    ssz_view::{ExecutionPayloadBidView, SignedExecutionPayloadBidView},
};

impl ProgressiveContainer for ExecutionPayloadBidView {
    const ACTIVE_FIELDS: B256 = packed_active_fields(12);
}

impl ExecutionPayloadBidView {
    /// `blob_kzg_commitments` (field 10) is the only variable field, its
    /// ProgressiveList offset at byte 188.
    pub fn hash_tree_root(msg: &[u8]) -> B256 {
        if msg.len() < 224 {
            return ZERO_HASH;
        }
        let mut fee_recipient = [0u8; 32];
        fee_recipient[..20].copy_from_slice(Self::fee_recipient(msg));
        let blob_off = u32::from_le_bytes(msg[188..192].try_into().unwrap()) as usize;
        let blob_bytes = if blob_off <= msg.len() { &msg[blob_off..] } else { &[] };
        let blob_commitments =
            hash_list(ProgressiveHasher::new(), blob_bytes.chunks_exact(48).map(hash_fixed_bytes));

        let fields = [
            *Self::parent_block_hash(msg),
            *Self::parent_block_root(msg),
            *Self::block_hash(msg),
            *Self::prev_randao(msg),
            fee_recipient,
            uint64_chunk(Self::gas_limit(msg)),
            uint64_chunk(Self::builder_index(msg)),
            uint64_chunk(Self::slot(msg)),
            uint64_chunk(Self::value(msg)),
            uint64_chunk(Self::execution_payment(msg)),
            blob_commitments,
            *Self::execution_requests_root(msg),
        ];
        Self::progressive_root(&fields)
    }
}

impl SignedExecutionPayloadBidView {
    /// Plain Container { message: ExecutionPayloadBid, signature }; only the
    /// inner bid is progressive.
    pub fn hash_tree_root(d: &[u8]) -> B256 {
        if d.len() < 100 {
            return ZERO_HASH;
        }
        let message = ExecutionPayloadBidView::hash_tree_root(Self::message(d));
        let signature = hash_fixed_bytes(Self::signature(d));
        merkleize(&[message, signature])
    }
}
