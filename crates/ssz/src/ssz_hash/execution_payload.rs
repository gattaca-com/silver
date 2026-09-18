use flux_profiler::timed;

use crate::{
    body_offsets::Payload,
    merkle::{
        B256, FixedContainer, MerkleStack, ZERO_HASH, hash_bytelist, hash_fixed_bytes, merkleize,
        merkleize_bytes, mix_in_length, uint64_chunk,
    },
    ssz_view::{
        ExecutionPayloadView, MAX_BYTES_PER_TRANSACTION, MAX_TRANSACTIONS_PER_PAYLOAD,
        MAX_WITHDRAWALS_PER_PAYLOAD, WITHDRAWAL_SIZE, WithdrawalView,
    },
};

impl FixedContainer for WithdrawalView {
    const SSZ_SIZE: usize = WITHDRAWAL_SIZE;

    fn hash_tree_root(bytes: &[u8]) -> B256 {
        let w: &[u8; WITHDRAWAL_SIZE] = bytes.try_into().unwrap();
        let mut addr = ZERO_HASH;
        addr[..20].copy_from_slice(Self::address(w));
        merkleize(&[
            uint64_chunk(Self::index(w)),
            uint64_chunk(Self::validator_index(w)),
            addr,
            uint64_chunk(Self::amount(w)),
        ])
    }
}

/// Most of a payload's hashing cost; surfaced so the STF's payload header
/// reuses them instead of hashing the same bytes twice.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PayloadRoots {
    pub transactions: B256,
    pub withdrawals: B256,
}

impl PayloadRoots {
    pub fn of(payload: Payload<'_>) -> Self {
        let bytes = payload.bytes();
        Self {
            transactions: hash_transactions(ExecutionPayloadView::transactions(bytes)),
            withdrawals: hash_withdrawals(ExecutionPayloadView::withdrawals(bytes)),
        }
    }
}

/// hash_tree_root for ExecutionPayload from raw SSZ bytes.
/// 17 fields → 32 leaves.
#[timed]
pub fn hash_execution_payload_with_roots(payload: Payload<'_>) -> (B256, PayloadRoots) {
    let data = payload.bytes();

    let b256 = |off: usize| -> B256 { data[off..off + 32].try_into().unwrap() };
    let u64le = |off: usize| -> u64 { u64::from_le_bytes(data[off..off + 8].try_into().unwrap()) };

    let mut fee_recipient = ZERO_HASH;
    fee_recipient[..20].copy_from_slice(&data[32..52]);

    let extra_data_bytes = ExecutionPayloadView::extra_data(data);
    // ByteList[32] → max 1 chunk.
    let extra_data_root =
        mix_in_length(&merkleize_bytes(extra_data_bytes, 1), extra_data_bytes.len());

    let roots = PayloadRoots::of(payload);

    let fields: [B256; 17] = [
        b256(0),
        fee_recipient,
        b256(52),
        b256(84),
        hash_fixed_bytes(&data[116..372]),
        b256(372),
        uint64_chunk(u64le(404)),
        uint64_chunk(u64le(412)),
        uint64_chunk(u64le(420)),
        uint64_chunk(u64le(428)),
        extra_data_root,
        b256(440),
        b256(472),
        roots.transactions,
        roots.withdrawals,
        uint64_chunk(u64le(512)),
        uint64_chunk(u64le(520)),
    ];
    (merkleize(&fields), roots)
}

/// hash_tree_root for List[Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].
#[timed]
fn hash_transactions(data: &[u8]) -> B256 {
    const EMPTY_LIST_ROOT: B256 = MerkleStack::empty_root(MAX_TRANSACTIONS_PER_PAYLOAD);
    let tx_chunk_capacity = MAX_BYTES_PER_TRANSACTION.div_ceil(32);

    if data.is_empty() {
        return mix_in_length(&EMPTY_LIST_ROOT, 0);
    }

    let first_off = u32::from_le_bytes(data[..4].try_into().unwrap_or([0; 4])) as usize;
    if first_off == 0 || !first_off.is_multiple_of(4) || first_off > data.len() {
        return mix_in_length(&EMPTY_LIST_ROOT, 0);
    }
    let count = first_off / 4;

    let mut outer = MerkleStack::new(MAX_TRANSACTIONS_PER_PAYLOAD);
    for i in 0..count {
        let off_start = u32::from_le_bytes(data[i * 4..(i + 1) * 4].try_into().unwrap()) as usize;
        let off_end = if i + 1 < count {
            u32::from_le_bytes(data[(i + 1) * 4..(i + 2) * 4].try_into().unwrap()) as usize
        } else {
            data.len()
        };
        let tx_bytes = if off_start <= off_end && off_end <= data.len() {
            &data[off_start..off_end]
        } else {
            &[]
        };
        outer.push(hash_bytelist(MerkleStack::new(tx_chunk_capacity), tx_bytes));
    }

    let root = outer.finalize();
    mix_in_length(&root, count)
}

/// hash_tree_root for List[Withdrawal, 16].
#[timed]
fn hash_withdrawals(data: &[u8]) -> B256 {
    WithdrawalView::hash_list(MerkleStack::new(MAX_WITHDRAWALS_PER_PAYLOAD), data)
}
