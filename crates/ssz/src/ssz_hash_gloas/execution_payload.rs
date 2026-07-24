//! Gloas `ExecutionPayload` and `ExecutionPayloadEnvelope` hashers. The
//! payload extends fulu's byte layout (EIP-7928 / EIP-7843): the fixed part
//! grows 528 → 540 with the `block_access_list` offset and `slot_number`, and
//! `transactions` / `withdrawals` / `block_access_list` merkleize
//! progressively.

use flux_profiler::timed;

use crate::{
    merkle::{
        B256, FixedContainer, ZERO_HASH, hash_bytelist, hash_fixed_bytes, hash_variable_list,
        merkleize, merkleize_bytes, mix_in_length, uint64_chunk,
    },
    progressive::{ProgressiveContainer, ProgressiveHasher, packed_active_fields},
    ssz_hash_gloas::ExecutionRequestsView,
    ssz_view::{
        EXECUTION_PAYLOAD_FIXED_GLOAS, ExecutionPayloadEnvelopeView, ExecutionPayloadView,
        SignedExecutionPayloadEnvelopeView, WithdrawalView,
    },
};

impl ProgressiveContainer for ExecutionPayloadView {
    const ACTIVE_FIELDS: B256 = packed_active_fields(19);
}

impl ExecutionPayloadView {
    #[timed]
    pub fn hash_tree_root_gloas(d: &[u8]) -> B256 {
        if d.len() < EXECUTION_PAYLOAD_FIXED_GLOAS {
            return ZERO_HASH;
        }
        let extra_off = Self::extra_data_offset(d) as usize;
        let txs_off = Self::transactions_offset(d) as usize;
        let wd_off = Self::withdrawals_offset(d) as usize;
        let bal_off = Self::block_access_list_offset(d) as usize;
        let in_bounds = EXECUTION_PAYLOAD_FIXED_GLOAS <= extra_off &&
            extra_off <= txs_off &&
            txs_off <= wd_off &&
            wd_off <= bal_off &&
            bal_off <= d.len();
        if !in_bounds {
            return ZERO_HASH;
        }

        let extra_data = &d[extra_off..txs_off];
        // extra_data stays ByteList[MAX_EXTRA_DATA_BYTES=32] → 1 chunk.
        let extra_data_root = mix_in_length(&merkleize_bytes(extra_data, 1), extra_data.len());
        let transactions_root =
            hash_variable_list(ProgressiveHasher::new(), &d[txs_off..wd_off], |tx| {
                hash_bytelist(ProgressiveHasher::new(), tx)
            });
        let withdrawals_root =
            WithdrawalView::hash_list(ProgressiveHasher::new(), &d[wd_off..bal_off]);

        let mut fee_recipient = ZERO_HASH;
        fee_recipient[..20].copy_from_slice(Self::fee_recipient(d));

        let fields = [
            *Self::parent_hash(d),
            fee_recipient,
            *Self::state_root(d),
            *Self::receipts_root(d),
            hash_fixed_bytes(Self::logs_bloom(d)),
            *Self::prev_randao(d),
            uint64_chunk(Self::block_number(d)),
            uint64_chunk(Self::gas_limit(d)),
            uint64_chunk(Self::gas_used(d)),
            uint64_chunk(Self::timestamp(d)),
            extra_data_root,
            *Self::base_fee_per_gas(d),
            *Self::block_hash(d),
            transactions_root,
            withdrawals_root,
            uint64_chunk(Self::blob_gas_used(d)),
            uint64_chunk(Self::excess_blob_gas(d)),
            hash_bytelist(ProgressiveHasher::new(), &d[bal_off..]),
            uint64_chunk(Self::slot_number(d)),
        ];
        Self::progressive_root(&fields)
    }
}

impl ProgressiveContainer for ExecutionPayloadEnvelopeView {
    const ACTIVE_FIELDS: B256 = packed_active_fields(5);
}

impl ExecutionPayloadEnvelopeView {
    pub fn hash_tree_root(d: &[u8]) -> B256 {
        if !Self::check_size(d) {
            return ZERO_HASH;
        }
        let fields = [
            ExecutionPayloadView::hash_tree_root_gloas(Self::payload(d)),
            ExecutionRequestsView::hash_tree_root(Self::execution_requests(d)),
            uint64_chunk(Self::builder_index(d)),
            *Self::beacon_block_root(d),
            *Self::parent_beacon_block_root(d),
        ];
        Self::progressive_root(&fields)
    }
}

impl SignedExecutionPayloadEnvelopeView {
    /// Plain Container { message: ExecutionPayloadEnvelope, signature }.
    pub fn hash_tree_root(d: &[u8]) -> B256 {
        if !Self::check_size(d) {
            return ZERO_HASH;
        }
        let message = ExecutionPayloadEnvelopeView::hash_tree_root(Self::message(d));
        let signature = hash_fixed_bytes(Self::signature(d));
        merkleize(&[message, signature])
    }
}
