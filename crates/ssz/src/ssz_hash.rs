//! Eth2-shape hash-tree-root hashers over raw SSZ bytes: block bodies,
//! execution payloads, and the per-element helpers for attestations /
//! slashings / deposits / exits / bls-changes / execution-requests, plus the
//! freestanding `hash_tree_root_{fork_data, voluntary_exit, bls_change,
//! deposit_data, aggregate_and_proof}`. Built on the Merkleization core in
//! [`crate::merkle`].

use flux_profiler::timed;

use crate::{
    merkle::*,
    ssz_hash_gloas::{hash_attestation_gloas, hash_tree_root_body_gloas},
    ssz_view::{
        DEPOSIT_CONTRACT_TREE_DEPTH, DEPOSIT_DATA_SIZE, DEPOSIT_PROOF_SIZE,
        MAX_BYTES_PER_TRANSACTION, MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD,
        MAX_DEPOSIT_REQUESTS_PER_PAYLOAD, MAX_TRANSACTIONS_PER_PAYLOAD,
        MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD, MAX_WITHDRAWALS_PER_PAYLOAD,
    },
};

/// hash_tree_root(ForkData(current_version, genesis_validators_root)).
/// 2-chunk container → single sha256 of the concatenated chunks (the
/// 4-byte version is right-zero-padded into a 32-byte chunk per SSZ).
#[timed]
pub fn hash_tree_root_fork_data(version: [u8; 4], genesis_validators_root: &B256) -> B256 {
    let mut version_chunk = [0u8; 32];
    version_chunk[..4].copy_from_slice(&version);
    hash_concat(&version_chunk, genesis_validators_root)
}

/// The 13 field roots of a Fulu `BeaconBlockBody`, in field order. Returns
/// `None` when `body` is below the fixed prefix size.
///
/// `merkleize`-ing these yields `body_root` (see [`hash_tree_root_body_fulu`]);
/// the Merkle branch from field 11 (`blob_kzg_commitments`) up to that root is
/// the `kzg_commitments` inclusion proof (see
/// [`kzg_commitments_inclusion_proof`]). Both callers share this so the field
/// layout is defined once per fork.
#[inline]
fn beacon_block_body_field_roots_fulu(body: &[u8]) -> Option<[B256; 13]> {
    if body.len() < 396 {
        return None;
    }

    let randao = hash_fixed_bytes(&body[0..96]);
    let eth1 = hash_eth1_data_bytes(&body[96..168]);
    let graffiti: B256 = body[168..200].try_into().unwrap();
    let sync_agg = hash_sync_aggregate(&body[220..380]);

    let off = |pos: usize| -> usize {
        u32::from_le_bytes(body[pos..pos + 4].try_into().unwrap()) as usize
    };

    let offsets =
        [off(200), off(204), off(208), off(212), off(216), off(380), off(384), off(388), off(392)];

    let var_field = |idx: usize| -> &[u8] {
        let start = offsets[idx];
        let end = if idx + 1 < offsets.len() { offsets[idx + 1] } else { body.len() };
        if start <= end && end <= body.len() { &body[start..end] } else { &[] }
    };

    let proposer_slashings = hash_list_containers(var_field(0), 416, 16, hash_proposer_slashing);
    let attester_slashings = hash_list_variable_containers(var_field(1), 1, hash_attester_slashing);
    let attestations = hash_list_variable_containers(var_field(2), 8, hash_attestation);
    let deposits = hash_list_containers(var_field(3), 1240, 16, hash_deposit);
    let voluntary_exits = hash_list_containers(var_field(4), 112, 16, hash_signed_voluntary_exit);
    let execution_payload = hash_execution_payload(var_field(5));
    let bls_changes = hash_list_containers(var_field(6), 172, 16, hash_signed_bls_change);
    let blob_commitments = hash_list_fixed_elements(var_field(7), 48, 4096);
    let execution_requests = hash_execution_requests_fulu(var_field(8));

    Some([
        randao,
        eth1,
        graffiti,
        proposer_slashings,
        attester_slashings,
        attestations,
        deposits,
        voluntary_exits,
        sync_agg,
        execution_payload,
        bls_changes,
        blob_commitments,
        execution_requests,
    ])
}

pub fn hash_tree_root_body(body: &[u8], is_gloas: bool) -> B256 {
    if is_gloas { hash_tree_root_body_gloas(body) } else { hash_tree_root_body_fulu(body) }
}

/// Compute hash_tree_root of a BeaconBlockBody from raw SSZ bytes.
/// Fulu layout: 13 fields → 16 leaves.
#[timed]
pub fn hash_tree_root_body_fulu(body: &[u8]) -> B256 {
    match beacon_block_body_field_roots_fulu(body) {
        Some(field_hashes) => merkleize(&field_hashes),
        None => ZERO_HASH,
    }
}

/// Generate the `kzg_commitments_inclusion_proof` carried by a
/// `DataColumnSidecar`: the 4-node Merkle branch proving the block's
/// `blob_kzg_commitments` list root (field 11 of the 13-field → 16-leaf
/// `BeaconBlockBody` tree) sits under `body_root`. Generator inverse of the
/// verifier in
/// `silver_storage::util::verify_data_column_sidecar_inclusion_proof`.
///
/// Returns all-zero bytes when `body` is below the fixed prefix size (mirrors
/// `hash_tree_root_body_fulu`'s fallback).
#[timed]
pub fn kzg_commitments_inclusion_proof(body: &[u8]) -> [u8; 128] {
    let Some(field_roots) = beacon_block_body_field_roots_fulu(body) else {
        return [0u8; 128];
    };

    // The 16 leaves of the body tree (13 fields + 3 zero-padding).
    let mut layer = [ZERO_HASH; 16];
    layer[..13].copy_from_slice(&field_roots);

    // Walk up the 4 levels, recording the sibling on leaf 11's path.
    let mut proof = [0u8; 128];
    let mut idx = 11usize;
    let mut width = 16usize;
    for level in 0..4 {
        proof[level * 32..level * 32 + 32].copy_from_slice(&layer[idx ^ 1]);
        let half = width / 2;
        for i in 0..half {
            layer[i] = hash_concat(&layer[2 * i], &layer[2 * i + 1]);
        }
        idx >>= 1;
        width = half;
    }
    proof
}

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

    let deposit_requests = hash_list_containers(
        var_field(0),
        192,
        MAX_DEPOSIT_REQUESTS_PER_PAYLOAD,
        hash_deposit_request,
    );
    let withdrawal_requests = hash_list_containers(
        var_field(1),
        76,
        MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD,
        hash_withdrawal_request,
    );
    let consolidation_requests = hash_list_containers(
        var_field(2),
        116,
        MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD,
        hash_consolidation_request,
    );

    merkleize(&[deposit_requests, withdrawal_requests, consolidation_requests])
}

#[timed]
pub fn hash_eth1_data_bytes(data: &[u8]) -> B256 {
    let deposit_root: B256 = data[0..32].try_into().unwrap();
    let deposit_count = u64::from_le_bytes(data[32..40].try_into().unwrap());
    let block_hash: B256 = data[40..72].try_into().unwrap();
    let chunks = [deposit_root, uint64_chunk(deposit_count), block_hash];
    merkleize(&chunks)
}

#[timed]
pub fn hash_sync_aggregate(data: &[u8]) -> B256 {
    let bits_hash = hash_fixed_bytes(&data[0..64]);
    let sig_hash = hash_fixed_bytes(&data[64..160]);
    hash_concat(&bits_hash, &sig_hash)
}

#[timed]
pub fn hash_signed_beacon_block_header(d: &[u8]) -> B256 {
    let msg = hash_beacon_block_header_bytes(&d[..112]);
    let sig = hash_fixed_bytes(&d[112..208]);
    hash_concat(&msg, &sig)
}

#[timed]
pub fn hash_beacon_block_header_bytes(d: &[u8]) -> B256 {
    let u64c = |off: usize| uint64_chunk(u64::from_le_bytes(d[off..off + 8].try_into().unwrap()));
    let b = |off: usize| -> B256 { d[off..off + 32].try_into().unwrap() };
    merkleize(&[u64c(0), u64c(8), b(16), b(48), b(80)])
}

#[timed]
pub fn hash_proposer_slashing(d: &[u8]) -> B256 {
    hash_concat(
        &hash_signed_beacon_block_header(&d[..208]),
        &hash_signed_beacon_block_header(&d[208..416]),
    )
}

/// hash_tree_root(DepositData): merkleize 4 chunks
/// [pubkey_root, withdrawal_credentials, amount_chunk, signature_root].
#[timed]
pub fn hash_tree_root_deposit_data(dd: &[u8; 184]) -> B256 {
    merkleize(&[
        hash_fixed_bytes(&dd[..48]),
        <[u8; 32]>::try_from(&dd[48..80]).unwrap(),
        uint64_chunk(u64::from_le_bytes(dd[80..88].try_into().unwrap())),
        hash_fixed_bytes(&dd[88..184]),
    ])
}

#[timed]
pub fn hash_deposit(d: &[u8]) -> B256 {
    let proof_root = merkleize_bytes(&d[..DEPOSIT_PROOF_SIZE], DEPOSIT_CONTRACT_TREE_DEPTH + 1);

    let dd: &[u8; DEPOSIT_DATA_SIZE] =
        d[DEPOSIT_PROOF_SIZE..DEPOSIT_PROOF_SIZE + DEPOSIT_DATA_SIZE].try_into().unwrap();
    let dd_root = hash_tree_root_deposit_data(dd);
    hash_concat(&proof_root, &dd_root)
}

#[timed]
pub fn hash_signed_voluntary_exit(d: &[u8]) -> B256 {
    let msg = hash_concat(
        &uint64_chunk(u64::from_le_bytes(d[0..8].try_into().unwrap())),
        &uint64_chunk(u64::from_le_bytes(d[8..16].try_into().unwrap())),
    );
    hash_concat(&msg, &hash_fixed_bytes(&d[16..112]))
}

#[timed]
pub fn hash_signed_bls_change(d: &[u8]) -> B256 {
    let mut addr = ZERO_HASH;
    addr[..20].copy_from_slice(&d[56..76]);
    let msg = merkleize(&[
        uint64_chunk(u64::from_le_bytes(d[0..8].try_into().unwrap())),
        hash_fixed_bytes(&d[8..56]),
        addr,
    ]);
    hash_concat(&msg, &hash_fixed_bytes(&d[76..172]))
}

#[timed]
pub fn hash_attestation(d: &[u8]) -> B256 {
    if d.len() < 236 {
        return ZERO_HASH;
    }
    let agg_off = u32::from_le_bytes(d[0..4].try_into().unwrap()) as usize;
    let agg_bits = if agg_off <= d.len() { &d[agg_off..] } else { &[] };

    let max_bits: usize = 64 * 2048;
    let bit_len = bitlist_len(agg_bits);
    let agg_root = hash_bitlist(agg_bits, bit_len, max_bits);

    let data_root = hash_attestation_data(&d[4..132]);
    let sig_root = hash_fixed_bytes(&d[132..228]);
    let mut cb = ZERO_HASH;
    cb[..8].copy_from_slice(&d[228..236]);

    merkleize(&[agg_root, data_root, sig_root, cb])
}

/// SSZ root of `AggregateAndProof { aggregator_index, aggregate,
/// selection_proof }` — itself a plain 3-field container in both forks; only
/// the inner `aggregate` switches shape at the EIP-7688 boundary.
#[timed]
pub fn hash_tree_root_aggregate_and_proof(
    aggregator_index: u64,
    aggregate: &[u8],
    selection_proof: &[u8; 96],
    is_gloas: bool,
) -> B256 {
    let idx_root = uint64_chunk(aggregator_index);
    let agg_root =
        if is_gloas { hash_attestation_gloas(aggregate) } else { hash_attestation(aggregate) };
    let sp_root = hash_fixed_bytes(selection_proof);
    merkleize(&[idx_root, agg_root, sp_root])
}

/// SSZ root of the 128-byte AttestationData container. Used both for block
/// hashing and for signature signing-roots (attestations + IndexedAttestations
/// inside AttesterSlashing).
#[timed]
pub fn hash_attestation_data(d: &[u8]) -> B256 {
    let u64c = |off: usize| uint64_chunk(u64::from_le_bytes(d[off..off + 8].try_into().unwrap()));
    let b = |off: usize| -> B256 { d[off..off + 32].try_into().unwrap() };
    let cp = |off: usize| hash_concat(&u64c(off), &b(off + 8));
    merkleize(&[u64c(0), u64c(8), b(16), cp(48), cp(88)])
}

/// SSZ root of `VoluntaryExit { epoch, validator_index }`. Two uint64 fields
/// merkleized in order.
#[timed]
pub fn hash_tree_root_voluntary_exit(epoch: u64, validator_index: u64) -> B256 {
    merkleize(&[uint64_chunk(epoch), uint64_chunk(validator_index)])
}

/// SSZ root of `BLSToExecutionChange { validator_index, from_bls_pubkey,
/// to_execution_address }`. The pubkey is a 48-byte vector → packed into two
/// 32-byte chunks (`pad_to_64(pubkey)` then sha256). The address is 20 bytes
/// in the low end of a 32-byte chunk.
#[timed]
pub fn hash_tree_root_bls_change(
    validator_index: u64,
    from_pubkey: &[u8; 48],
    to_address: &[u8; 20],
) -> B256 {
    let mut pk_chunk = [0u8; 64];
    pk_chunk[..48].copy_from_slice(from_pubkey);
    let pk_root = sha256(&pk_chunk);

    let mut addr_chunk = [0u8; 32];
    addr_chunk[..20].copy_from_slice(to_address);

    merkleize(&[uint64_chunk(validator_index), pk_root, addr_chunk])
}

#[timed]
pub fn hash_indexed_attestation(d: &[u8]) -> B256 {
    const INDEX_CAPACITY: usize = (64 * 2048usize).div_ceil(4);
    if d.len() < 228 {
        // Empty IA: zero attesting_indices, zero AttestationData, zero sig.
        const EMPTY_INDICES_ROOT: B256 = MerkleStack::empty_root(INDEX_CAPACITY);
        let indices_root = mix_in_length(&EMPTY_INDICES_ROOT, 0);
        let data_root = hash_attestation_data(&[0u8; 128]);
        let sig_root = hash_fixed_bytes(&[0u8; 96]);
        return merkleize(&[indices_root, data_root, sig_root]);
    }
    let indices_off = u32::from_le_bytes(d[0..4].try_into().unwrap()) as usize;
    let indices_data = if indices_off <= d.len() { &d[indices_off..] } else { &[] };
    let idx_count = indices_data.len() / 8;

    let indices_root =
        mix_in_length(&merkleize_bytes(&indices_data[..idx_count * 8], INDEX_CAPACITY), idx_count);

    let data_root = hash_attestation_data(&d[4..132]);
    let sig_root = hash_fixed_bytes(&d[132..228]);
    merkleize(&[indices_root, data_root, sig_root])
}

#[timed]
pub fn hash_attester_slashing(d: &[u8]) -> B256 {
    if d.len() < 8 {
        // Empty AttesterSlashing root: two empty-IA roots concatenated.
        let empty_ia = hash_indexed_attestation(&[]);
        return hash_concat(&empty_ia, &empty_ia);
    }
    let off1 = u32::from_le_bytes(d[0..4].try_into().unwrap()) as usize;
    let off2 = u32::from_le_bytes(d[4..8].try_into().unwrap()) as usize;
    let ia1 = if off1 <= off2 && off2 <= d.len() { &d[off1..off2] } else { &[] };
    let ia2 = if off2 <= d.len() { &d[off2..] } else { &[] };
    hash_concat(&hash_indexed_attestation(ia1), &hash_indexed_attestation(ia2))
}

#[timed]
pub fn hash_deposit_request(d: &[u8]) -> B256 {
    merkleize(&[
        hash_fixed_bytes(&d[..48]),
        <[u8; 32]>::try_from(&d[48..80]).unwrap(),
        uint64_chunk(u64::from_le_bytes(d[80..88].try_into().unwrap())),
        hash_fixed_bytes(&d[88..184]),
        uint64_chunk(u64::from_le_bytes(d[184..192].try_into().unwrap())),
    ])
}

#[timed]
pub fn hash_withdrawal_request(d: &[u8]) -> B256 {
    let mut addr = ZERO_HASH;
    addr[..20].copy_from_slice(&d[..20]);
    merkleize(&[
        addr,
        hash_fixed_bytes(&d[20..68]),
        uint64_chunk(u64::from_le_bytes(d[68..76].try_into().unwrap())),
    ])
}

#[timed]
pub fn hash_consolidation_request(d: &[u8]) -> B256 {
    let mut addr = ZERO_HASH;
    addr[..20].copy_from_slice(&d[..20]);
    merkleize(&[addr, hash_fixed_bytes(&d[20..68]), hash_fixed_bytes(&d[68..116])])
}

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
