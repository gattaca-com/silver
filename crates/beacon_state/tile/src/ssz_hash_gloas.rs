//! Gloas state-root hashing: the EIP-7688 `BeaconState`
//! (`ProgressiveContainer(active_fields=[1] * 46)`) plus the gloas-only leaf
//! hashers over in-memory state types. Fulu state hashing and the shared
//! field builders stay in [`crate::ssz_hash`].

use silver_beacon_state_data::{
    BuilderPendingPayment, BuilderPendingWithdrawal, ExecutionPayloadBid, StateReadView,
    Withdrawal,
    gloas::{BUILDER_PENDING_PAYMENTS_LEN, PTC_WINDOW_LEN},
};
use silver_common::{
    progressive::{ProgressiveContainer, ProgressiveHasher, packed_active_fields},
    ssz_view::ExecutionPayloadBidView,
};

use crate::{
    merkle::{
        B256, MerkleStack, ZERO_HASH, hash_fixed_bytes, hash_list, hash_uint64_vector, hash_vector,
        merkleize, uint64_chunk,
    },
    ssz_hash::hash_common_fields,
};

/// The gloas `BeaconState` ProgressiveContainer; the in-memory state has no
/// wire-view type, so it owns its hashing and `active_fields` here.
pub(crate) enum BeaconStateGloas {}

impl ProgressiveContainer for BeaconStateGloas {
    const ACTIVE_FIELDS: B256 = packed_active_fields(46);
}

impl BeaconStateGloas {
    pub(crate) fn hash_tree_root(rv: &StateReadView) -> B256 {
        // [Modified in Gloas] `latest_block_hash` (Hash32) replaces the header.
        let slot = rv.slot.state();
        let common = hash_common_fields(rv, slot.latest_block_hash);

        let mut fields = [[0u8; 32]; 46];
        fields[..38].copy_from_slice(&common);
        fields[38..].copy_from_slice(&[
            rv.builders.hash_root(),
            uint64_chunk(slot.next_withdrawal_builder_index),
            hash_fixed_bytes(&slot.execution_payload_availability),
            hash_vector(
                MerkleStack::new(BUILDER_PENDING_PAYMENTS_LEN),
                slot.builder_pending_payments.iter().map(hash_builder_pending_payment),
            ),
            rv.pending.builder_withdrawals.hash_root(),
            hash_execution_payload_bid(&slot.latest_execution_payload_bid),
            hash_list(
                ProgressiveHasher::new(),
                slot.payload_expected_withdrawals.iter().map(hash_withdrawal),
            ),
            // `ptc_window`: each committee is a `Vector[ValidatorIndex, PTC_SIZE]`.
            hash_vector(
                MerkleStack::new(PTC_WINDOW_LEN),
                rv.epoch.ptc_window().iter().map(|c| hash_uint64_vector(c)),
            ),
        ]);

        Self::progressive_root(&fields)
    }
}

/// `ExecutionAddress` (20 B) right-padded into a 32-B chunk.
#[inline]
fn address_chunk(addr: &[u8; 20]) -> B256 {
    let mut c = ZERO_HASH;
    c[..20].copy_from_slice(addr);
    c
}

fn hash_builder_pending_withdrawal(w: &BuilderPendingWithdrawal) -> B256 {
    merkleize(&[
        address_chunk(&w.fee_recipient),
        uint64_chunk(w.amount),
        uint64_chunk(w.builder_index),
    ])
}

fn hash_builder_pending_payment(p: &BuilderPendingPayment) -> B256 {
    merkleize(&[
        uint64_chunk(p.weight),
        hash_builder_pending_withdrawal(&p.withdrawal),
        uint64_chunk(p.proposer_index),
    ])
}

fn hash_withdrawal(w: &Withdrawal) -> B256 {
    merkleize(&[
        uint64_chunk(w.index),
        uint64_chunk(w.validator_index),
        address_chunk(&w.address),
        uint64_chunk(w.amount),
    ])
}

/// `ExecutionPayloadBid` over the in-memory state type; must agree with the
/// byte-driven bid hasher (signing roots vs block hashing), both rooting
/// through `ExecutionPayloadBidView`.
pub(crate) fn hash_execution_payload_bid(bid: &ExecutionPayloadBid) -> B256 {
    let kzg_commitments_root = hash_list(
        ProgressiveHasher::new(),
        bid.blob_kzg_commitments.iter().map(|c| hash_fixed_bytes(c)),
    );
    let fields = [
        bid.parent_block_hash,
        bid.parent_block_root,
        bid.block_hash,
        bid.prev_randao,
        address_chunk(&bid.fee_recipient),
        uint64_chunk(bid.gas_limit),
        uint64_chunk(bid.builder_index),
        uint64_chunk(bid.slot),
        uint64_chunk(bid.value),
        uint64_chunk(bid.execution_payment),
        kzg_commitments_root,
        bid.execution_requests_root,
    ];
    ExecutionPayloadBidView::progressive_root(&fields)
}

#[cfg(test)]
mod tests {
    use silver_beacon_state_data::ExecutionPayloadBid;
    use silver_common::ssz_view::ExecutionPayloadBidView;

    use super::hash_execution_payload_bid;

    #[test]
    fn bid_twin_hashers_agree() {
        let bid = ExecutionPayloadBid {
            parent_block_hash: [1; 32],
            parent_block_root: [2; 32],
            block_hash: [3; 32],
            prev_randao: [4; 32],
            fee_recipient: [5; 20],
            gas_limit: 30_000_000,
            builder_index: 7,
            slot: 123_456,
            value: 42,
            execution_payment: 9,
            blob_kzg_commitments: (0..6u8).map(|i| [i; 48]).collect(),
            execution_requests_root: [8; 32],
        };
        let mut ssz = Vec::new();
        ssz.extend_from_slice(&bid.parent_block_hash);
        ssz.extend_from_slice(&bid.parent_block_root);
        ssz.extend_from_slice(&bid.block_hash);
        ssz.extend_from_slice(&bid.prev_randao);
        ssz.extend_from_slice(&bid.fee_recipient);
        ssz.extend_from_slice(&bid.gas_limit.to_le_bytes());
        ssz.extend_from_slice(&bid.builder_index.to_le_bytes());
        ssz.extend_from_slice(&bid.slot.to_le_bytes());
        ssz.extend_from_slice(&bid.value.to_le_bytes());
        ssz.extend_from_slice(&bid.execution_payment.to_le_bytes());
        ssz.extend_from_slice(&224u32.to_le_bytes()); // kzg list offset
        ssz.extend_from_slice(&bid.execution_requests_root);
        for c in &bid.blob_kzg_commitments {
            ssz.extend_from_slice(c);
        }
        assert_eq!(hash_execution_payload_bid(&bid), ExecutionPayloadBidView::hash_tree_root(&ssz),);
    }
}
