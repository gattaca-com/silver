use flux_profiler::timed;

use crate::{
    merkle::{
        B256, FixedContainer, MerkleStack, ZERO_HASH, hash_fixed_bytes, merkleize, uint64_chunk,
    },
    ssz_view::{
        CONSOLIDATION_REQUEST_SIZE, ConsolidationRequestView, DEPOSIT_REQUEST_SIZE,
        DepositRequestView, MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD,
        MAX_DEPOSIT_REQUESTS_PER_PAYLOAD, MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD,
        WITHDRAWAL_REQUEST_SIZE, WithdrawalRequestView,
    },
};

/// Fulu `ExecutionRequests` — a plain 3-field Container of bounded `List`s
/// (gloas widens it to five ProgressiveLists in [`crate::ssz_hash_gloas`]).
#[timed]
pub fn hash_execution_requests_fulu(data: &[u8]) -> B256 {
    if data.len() < 12 {
        return merkleize(&[ZERO_HASH, ZERO_HASH, ZERO_HASH]);
    }
    let off = |pos: usize| -> usize {
        u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize
    };
    let offsets = [off(0), off(4), off(8)];
    let var_field = |idx: usize| -> &[u8] {
        let start = offsets[idx];
        let end = if idx + 1 < offsets.len() { offsets[idx + 1] } else { data.len() };
        if start <= end && end <= data.len() { &data[start..end] } else { &[] }
    };

    let deposit_requests = DepositRequestView::hash_list(
        MerkleStack::new(MAX_DEPOSIT_REQUESTS_PER_PAYLOAD),
        var_field(0),
    );
    let withdrawal_requests = WithdrawalRequestView::hash_list(
        MerkleStack::new(MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD),
        var_field(1),
    );
    let consolidation_requests = ConsolidationRequestView::hash_list(
        MerkleStack::new(MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD),
        var_field(2),
    );

    merkleize(&[deposit_requests, withdrawal_requests, consolidation_requests])
}

impl FixedContainer for DepositRequestView {
    const SSZ_SIZE: usize = DEPOSIT_REQUEST_SIZE;
    #[timed]
    fn hash_tree_root(d: &[u8]) -> B256 {
        merkleize(&[
            hash_fixed_bytes(&d[..48]),
            <[u8; 32]>::try_from(&d[48..80]).unwrap(),
            uint64_chunk(u64::from_le_bytes(d[80..88].try_into().unwrap())),
            hash_fixed_bytes(&d[88..184]),
            uint64_chunk(u64::from_le_bytes(d[184..192].try_into().unwrap())),
        ])
    }
}

impl FixedContainer for WithdrawalRequestView {
    const SSZ_SIZE: usize = WITHDRAWAL_REQUEST_SIZE;
    #[timed]
    fn hash_tree_root(d: &[u8]) -> B256 {
        let mut addr = ZERO_HASH;
        addr[..20].copy_from_slice(&d[..20]);
        merkleize(&[
            addr,
            hash_fixed_bytes(&d[20..68]),
            uint64_chunk(u64::from_le_bytes(d[68..76].try_into().unwrap())),
        ])
    }
}

impl FixedContainer for ConsolidationRequestView {
    const SSZ_SIZE: usize = CONSOLIDATION_REQUEST_SIZE;
    #[timed]
    fn hash_tree_root(d: &[u8]) -> B256 {
        let mut addr = ZERO_HASH;
        addr[..20].copy_from_slice(&d[..20]);
        merkleize(&[addr, hash_fixed_bytes(&d[20..68]), hash_fixed_bytes(&d[68..116])])
    }
}
