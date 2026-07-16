use flux_profiler::timed;

use crate::{
    merkle::{
        B256, MerkleStack, ZERO_HASH, hash_fixed_bytes, merkleize, merkleize_bytes, mix_in_length,
        uint64_chunk,
    },
    ssz_view::{
        MAX_BYTES_PER_TRANSACTION, MAX_TRANSACTIONS_PER_PAYLOAD, MAX_WITHDRAWALS_PER_PAYLOAD,
    },
};

/// hash_tree_root for ExecutionPayload from raw SSZ bytes.
/// 17 fields → 32 leaves.
#[timed]
pub fn hash_execution_payload(data: &[u8]) -> B256 {
    if data.len() < 528 {
        return ZERO_HASH;
    }

    let b256 = |off: usize| -> B256 { data[off..off + 32].try_into().unwrap() };
    let u64le = |off: usize| -> u64 { u64::from_le_bytes(data[off..off + 8].try_into().unwrap()) };
    let off32 = |pos: usize| -> usize {
        u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize
    };

    let mut fee_recipient = ZERO_HASH;
    fee_recipient[..20].copy_from_slice(&data[32..52]);

    let extra_data_off = off32(436);
    let transactions_off = off32(504);
    let withdrawals_off = off32(508);

    let extra_data_bytes = if extra_data_off < transactions_off && transactions_off <= data.len() {
        &data[extra_data_off..transactions_off]
    } else {
        &[]
    };
    // ByteList[32] → max 1 chunk.
    let extra_data_root =
        mix_in_length(&merkleize_bytes(extra_data_bytes, 1), extra_data_bytes.len());

    let txns_bytes = if transactions_off < withdrawals_off && withdrawals_off <= data.len() {
        &data[transactions_off..withdrawals_off]
    } else {
        &[]
    };
    let transactions_root = hash_transactions(txns_bytes);

    let withdrawals_bytes =
        if withdrawals_off <= data.len() { &data[withdrawals_off..] } else { &[] };
    let withdrawals_root = hash_withdrawals(withdrawals_bytes);

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
        transactions_root,
        withdrawals_root,
        uint64_chunk(u64le(512)),
        uint64_chunk(u64le(520)),
    ];
    merkleize(&fields)
}

/// hash_tree_root for List[Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].
#[timed]
pub fn hash_transactions(data: &[u8]) -> B256 {
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
        let tx_root = mix_in_length(&merkleize_bytes(tx_bytes, tx_chunk_capacity), tx_bytes.len());
        outer.push(tx_root);
    }

    let root = outer.finalize();
    mix_in_length(&root, count)
}

/// hash_tree_root for List[Withdrawal, 16]. Withdrawal fixed 44 bytes.
#[timed]
pub fn hash_withdrawals(data: &[u8]) -> B256 {
    const WITHDRAWAL_SIZE: usize = 44;

    let count = data.len() / WITHDRAWAL_SIZE;
    let mut stack = MerkleStack::new(MAX_WITHDRAWALS_PER_PAYLOAD);
    for i in 0..count {
        let w = &data[i * WITHDRAWAL_SIZE..(i + 1) * WITHDRAWAL_SIZE];
        let u64at = |off: usize| -> u64 { u64::from_le_bytes(w[off..off + 8].try_into().unwrap()) };
        let mut addr = ZERO_HASH;
        addr[..20].copy_from_slice(&w[16..36]);
        let chunks =
            [uint64_chunk(u64at(0)), uint64_chunk(u64at(8)), addr, uint64_chunk(u64at(36))];
        stack.push(merkleize(&chunks));
    }
    let root = stack.finalize();
    mix_in_length(&root, count)
}

/// Extract and hash transactions from ExecutionPayload SSZ bytes.
#[timed]
pub fn hash_transactions_from_payload(payload: &[u8]) -> B256 {
    if payload.len() < 528 {
        return ZERO_HASH;
    }
    let off32 = |pos: usize| -> usize {
        u32::from_le_bytes(payload[pos..pos + 4].try_into().unwrap()) as usize
    };
    let txns_off = off32(504);
    let withdrawals_off = off32(508);
    if txns_off <= withdrawals_off && withdrawals_off <= payload.len() {
        hash_transactions(&payload[txns_off..withdrawals_off])
    } else {
        ZERO_HASH
    }
}

/// Extract and hash withdrawals from ExecutionPayload SSZ bytes.
#[timed]
pub fn hash_withdrawals_from_payload(payload: &[u8]) -> B256 {
    if payload.len() < 528 {
        return ZERO_HASH;
    }
    let off32 = |pos: usize| -> usize {
        u32::from_le_bytes(payload[pos..pos + 4].try_into().unwrap()) as usize
    };
    let withdrawals_off = off32(508);
    if withdrawals_off <= payload.len() {
        hash_withdrawals(&payload[withdrawals_off..])
    } else {
        ZERO_HASH
    }
}
