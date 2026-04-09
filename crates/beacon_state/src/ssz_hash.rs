use flux::utils::ArrayVec;
use ring::digest;

use crate::types::{
    self, B256, BeaconBlockHeader, Checkpoint, EpochData, Eth1Data, HISTORICAL_ROOTS_LIMIT,
    HistoricalLongtail, Immutable, PendingQueues, SYNC_COMMITTEE_SIZE, SlotData, SlotRoots,
    VALIDATOR_REGISTRY_LIMIT, ValidatorIdentity,
};

pub fn sha256(data: &[u8]) -> B256 {
    let d = digest::digest(&digest::SHA256, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

fn hash_concat(a: &B256, b: &B256) -> B256 {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(a);
    buf[32..].copy_from_slice(b);
    sha256(&buf)
}

fn uint64_chunk(v: u64) -> B256 {
    let mut chunk = [0u8; 32];
    chunk[..8].copy_from_slice(&v.to_le_bytes());
    chunk
}

fn usize_chunk(v: usize) -> B256 {
    uint64_chunk(v as u64)
}

pub const ZERO_HASH: B256 = [0u8; 32];

/// Max SSZ depth we ever hit is 40 (VALIDATOR_REGISTRY_LIMIT = 2^40);
pub const ZERO_HASHES_LEN: usize = 48;

/// Stack of parked subtree roots keyed by height. Heights strictly decrease
/// from bottom to top.
type MerkleStack = ArrayVec<(u8, B256), ZERO_HASHES_LEN>;

/// Absorb a leaf, combining upward with any left-sibling already parked at
/// the same height.
fn merkle_push(stack: &mut MerkleStack, leaf: B256) {
    let mut cur = leaf;
    let mut h: u8 = 0;
    while let Some(&(top_h, top_root)) = stack.as_slice().last() {
        if top_h != h {
            break;
        }
        stack.pop();
        cur = hash_concat(&top_root, &cur);
        h += 1;
    }
    stack.push((h, cur));
}

/// Walk the parked stack up to `target_depth`, padding with zero subtrees
/// where no right-sibling is available.
fn merkle_finalize(mut stack: MerkleStack, target_depth: u8, zh: &[B256]) -> B256 {
    if stack.is_empty() {
        return zh[target_depth as usize];
    }
    let (first_h, first_root) = stack.pop().unwrap();
    let mut cur = first_root;
    let mut h = first_h;
    while h < target_depth {
        match stack.as_slice().last() {
            Some(&(top_h, top_root)) if top_h == h => {
                stack.pop();
                cur = hash_concat(&top_root, &cur);
            }
            _ => {
                cur = hash_concat(&cur, &zh[h as usize]);
            }
        }
        h += 1;
    }
    cur
}

/// zh[0] = ZERO_HASH; zh[i+1] = hash(zh[i] || zh[i]). Precompute once; pass
/// as a slice into the hash functions.
pub fn compute_zero_hashes() -> [B256; ZERO_HASHES_LEN] {
    let mut zh = [ZERO_HASH; ZERO_HASHES_LEN];
    for i in 1..ZERO_HASHES_LEN {
        zh[i] = hash_concat(&zh[i - 1], &zh[i - 1]);
    }
    zh
}

/// Push raw bytes packed as 32-byte chunks (tail zero-padded). The aligned
/// prefix is cast as `&[B256]` (B256 has alignment 1, safe for any byte ptr).
fn push_bytes_as_chunks(data: &[u8], stack: &mut MerkleStack) {
    let aligned = data.len() & !31;
    let chunks: &[B256] =
        unsafe { core::slice::from_raw_parts(data.as_ptr().cast::<B256>(), aligned / 32) };
    for c in chunks {
        merkle_push(stack, *c);
    }
    let tail = data.len() - aligned;
    if tail != 0 {
        let mut last = [0u8; 32];
        last[..tail].copy_from_slice(&data[aligned..]);
        merkle_push(stack, last);
    }
}

/// Merkleize a slice of 32-byte chunks, padding to the next power of two.
pub fn merkleize(chunks: &[B256], zh: &[B256]) -> B256 {
    let n = chunks.len().next_power_of_two().max(1);
    merkleize_padded(chunks, n, zh)
}

/// Merkleize with a fixed leaf count (power of two, for list limits).
pub fn merkleize_padded(chunks: &[B256], leaf_count: usize, zh: &[B256]) -> B256 {
    debug_assert!(leaf_count.is_power_of_two());
    debug_assert!(chunks.len() <= leaf_count);

    let target_depth = leaf_count.trailing_zeros() as u8;
    let mut stack = MerkleStack::new();
    for c in chunks {
        merkle_push(&mut stack, *c);
    }
    merkle_finalize(stack, target_depth, zh)
}

pub fn mix_in_length(root: &B256, length: usize) -> B256 {
    hash_concat(root, &usize_chunk(length))
}

/// hash_tree_root of a fixed-size byte vector (e.g. BLSSignature, Bitvector).
fn hash_fixed_bytes(data: &[u8], zh: &[B256]) -> B256 {
    if data.is_empty() {
        return ZERO_HASH;
    }
    let chunk_count = data.len().div_ceil(32);
    let target_depth = chunk_count.next_power_of_two().trailing_zeros() as u8;
    let mut stack = MerkleStack::new();
    push_bytes_as_chunks(data, &mut stack);
    merkle_finalize(stack, target_depth, zh)
}

pub fn hash_uint64_list(values: &[u64], count: usize, limit: usize, zh: &[B256]) -> B256 {
    let limit_chunks = limit.div_ceil(4);
    let target_depth = limit_chunks.next_power_of_two().trailing_zeros() as u8;

    let mut stack = MerkleStack::new();
    let mut chunk = [0u8; 32];
    let mut slot = 0usize;
    for &v in &values[..count] {
        let off = slot * 8;
        chunk[off..off + 8].copy_from_slice(&v.to_le_bytes());
        slot += 1;
        if slot == 4 {
            merkle_push(&mut stack, chunk);
            chunk = [0u8; 32];
            slot = 0;
        }
    }
    if slot != 0 {
        merkle_push(&mut stack, chunk);
    }
    let root = merkle_finalize(stack, target_depth, zh);
    mix_in_length(&root, count)
}

pub fn hash_uint8_list(values: &[u8], count: usize, limit: usize, zh: &[B256]) -> B256 {
    let limit_chunks = limit.div_ceil(32);
    let target_depth = limit_chunks.next_power_of_two().trailing_zeros() as u8;
    let mut stack = MerkleStack::new();
    push_bytes_as_chunks(&values[..count], &mut stack);
    let root = merkle_finalize(stack, target_depth, zh);
    mix_in_length(&root, count)
}

pub fn hash_b256_vector(values: &[B256], zh: &[B256]) -> B256 {
    merkleize(values, zh)
}

pub fn hash_tree_root_block_header(hdr: &BeaconBlockHeader, zh: &[B256]) -> B256 {
    let chunks = [
        uint64_chunk(hdr.slot),
        uint64_chunk(hdr.proposer_index),
        hdr.parent_root,
        hdr.state_root,
        hdr.body_root,
    ];
    merkleize(&chunks, zh)
}

pub fn hash_checkpoint(cp: &Checkpoint) -> B256 {
    hash_concat(&uint64_chunk(cp.epoch), &cp.root)
}

pub fn hash_eth1_data(e: &Eth1Data, zh: &[B256]) -> B256 {
    let chunks = [e.deposit_root, uint64_chunk(e.deposit_count), e.block_hash];
    merkleize(&chunks, zh)
}

/// Compute hash_tree_root of a BeaconBlockBody from raw SSZ bytes.
/// Electra layout: 13 fields → 16 leaves.
pub fn hash_tree_root_body(body: &[u8], zh: &[B256]) -> B256 {
    if body.len() < 396 {
        return ZERO_HASH;
    }

    let randao = hash_fixed_bytes(&body[0..96], zh);
    let eth1 = hash_eth1_data_bytes(&body[96..168], zh);
    let graffiti: B256 = body[168..200].try_into().unwrap();
    let sync_agg = hash_sync_aggregate(&body[220..380], zh);

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

    let proposer_slashings =
        hash_list_containers(var_field(0), 416, 16, hash_proposer_slashing, zh);
    let attester_slashings =
        hash_list_variable_containers(var_field(1), 1, hash_attester_slashing, zh);
    let attestations = hash_list_variable_containers(var_field(2), 8, hash_attestation, zh);
    let deposits = hash_list_containers(var_field(3), 1240, 16, hash_deposit, zh);
    let voluntary_exits =
        hash_list_containers(var_field(4), 112, 16, hash_signed_voluntary_exit, zh);
    let execution_payload = hash_execution_payload(var_field(5), zh);
    let bls_changes = hash_list_containers(var_field(6), 172, 16, hash_signed_bls_change, zh);
    let blob_commitments = hash_list_fixed_elements(var_field(7), 48, 4096, zh);
    let execution_requests = hash_execution_requests(var_field(8), zh);

    let field_hashes = [
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
    ];

    merkleize(&field_hashes, zh)
}

fn hash_execution_requests(data: &[u8], zh: &[B256]) -> B256 {
    if data.len() < 12 {
        return merkleize(&[ZERO_HASH, ZERO_HASH, ZERO_HASH], zh);
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

    use types::{
        MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD, MAX_DEPOSIT_REQUESTS_PER_PAYLOAD,
        MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD,
    };
    let deposit_requests = hash_list_containers(
        var_field(0),
        192,
        MAX_DEPOSIT_REQUESTS_PER_PAYLOAD,
        hash_deposit_request,
        zh,
    );
    let withdrawal_requests = hash_list_containers(
        var_field(1),
        76,
        MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD,
        hash_withdrawal_request,
        zh,
    );
    let consolidation_requests = hash_list_containers(
        var_field(2),
        116,
        MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD,
        hash_consolidation_request,
        zh,
    );

    merkleize(&[deposit_requests, withdrawal_requests, consolidation_requests], zh)
}

fn hash_eth1_data_bytes(data: &[u8], zh: &[B256]) -> B256 {
    let deposit_root: B256 = data[0..32].try_into().unwrap();
    let deposit_count = u64::from_le_bytes(data[32..40].try_into().unwrap());
    let block_hash: B256 = data[40..72].try_into().unwrap();
    let chunks = [deposit_root, uint64_chunk(deposit_count), block_hash];
    merkleize(&chunks, zh)
}

fn hash_sync_aggregate(data: &[u8], zh: &[B256]) -> B256 {
    let bits_hash = hash_fixed_bytes(&data[0..64], zh);
    let sig_hash = hash_fixed_bytes(&data[64..160], zh);
    hash_concat(&bits_hash, &sig_hash)
}

fn hash_list_containers(
    data: &[u8],
    element_size: usize,
    limit: usize,
    hash_fn: fn(&[u8], &[B256]) -> B256,
    zh: &[B256],
) -> B256 {
    if element_size == 0 {
        return mix_in_length(&ZERO_HASH, 0);
    }
    let count = data.len() / element_size;
    let target_depth = limit.next_power_of_two().trailing_zeros() as u8;

    let mut stack = MerkleStack::new();
    for i in 0..count {
        merkle_push(&mut stack, hash_fn(&data[i * element_size..(i + 1) * element_size], zh));
    }
    let root = merkle_finalize(stack, target_depth, zh);
    mix_in_length(&root, count)
}

fn hash_list_variable_containers(
    data: &[u8],
    limit: usize,
    hash_fn: fn(&[u8], &[B256]) -> B256,
    zh: &[B256],
) -> B256 {
    let target_depth = limit.next_power_of_two().trailing_zeros() as u8;
    if data.is_empty() {
        return mix_in_length(&merkle_finalize(MerkleStack::new(), target_depth, zh), 0);
    }
    let first_offset = u32::from_le_bytes(data[0..4].try_into().unwrap_or([0; 4])) as usize;
    if first_offset == 0 || !first_offset.is_multiple_of(4) {
        return mix_in_length(&merkle_finalize(MerkleStack::new(), target_depth, zh), 0);
    }
    let count = first_offset / 4;

    let mut stack = MerkleStack::new();
    for i in 0..count {
        let start = u32::from_le_bytes(data[i * 4..(i + 1) * 4].try_into().unwrap()) as usize;
        let end = if i + 1 < count {
            u32::from_le_bytes(data[(i + 1) * 4..(i + 2) * 4].try_into().unwrap()) as usize
        } else {
            data.len()
        };
        let elem = if start <= end && end <= data.len() {
            hash_fn(&data[start..end], zh)
        } else {
            ZERO_HASH
        };
        merkle_push(&mut stack, elem);
    }
    let root = merkle_finalize(stack, target_depth, zh);
    mix_in_length(&root, count)
}

fn hash_signed_beacon_block_header(d: &[u8], zh: &[B256]) -> B256 {
    let msg = hash_beacon_block_header_bytes(&d[..112], zh);
    let sig = hash_fixed_bytes(&d[112..208], zh);
    hash_concat(&msg, &sig)
}

fn hash_beacon_block_header_bytes(d: &[u8], zh: &[B256]) -> B256 {
    let u64c = |off: usize| uint64_chunk(u64::from_le_bytes(d[off..off + 8].try_into().unwrap()));
    let b = |off: usize| -> B256 { d[off..off + 32].try_into().unwrap() };
    merkleize(&[u64c(0), u64c(8), b(16), b(48), b(80)], zh)
}

fn hash_proposer_slashing(d: &[u8], zh: &[B256]) -> B256 {
    hash_concat(
        &hash_signed_beacon_block_header(&d[..208], zh),
        &hash_signed_beacon_block_header(&d[208..416], zh),
    )
}

fn hash_deposit(d: &[u8], zh: &[B256]) -> B256 {
    let mut proof_stack = MerkleStack::new();
    for i in 0..33 {
        let chunk: B256 = d[i * 32..(i + 1) * 32].try_into().unwrap();
        merkle_push(&mut proof_stack, chunk);
    }
    let proof_root = merkle_finalize(proof_stack, 6, zh);

    let data = &d[1056..];
    let dd_root = merkleize(
        &[
            hash_fixed_bytes(&data[..48], zh),
            <[u8; 32]>::try_from(&data[48..80]).unwrap(),
            uint64_chunk(u64::from_le_bytes(data[80..88].try_into().unwrap())),
            hash_fixed_bytes(&data[88..184], zh),
        ],
        zh,
    );
    hash_concat(&proof_root, &dd_root)
}

fn hash_signed_voluntary_exit(d: &[u8], zh: &[B256]) -> B256 {
    let msg = hash_concat(
        &uint64_chunk(u64::from_le_bytes(d[0..8].try_into().unwrap())),
        &uint64_chunk(u64::from_le_bytes(d[8..16].try_into().unwrap())),
    );
    hash_concat(&msg, &hash_fixed_bytes(&d[16..112], zh))
}

fn hash_signed_bls_change(d: &[u8], zh: &[B256]) -> B256 {
    let mut addr = ZERO_HASH;
    addr[..20].copy_from_slice(&d[56..76]);
    let msg = merkleize(
        &[
            uint64_chunk(u64::from_le_bytes(d[0..8].try_into().unwrap())),
            hash_fixed_bytes(&d[8..56], zh),
            addr,
        ],
        zh,
    );
    hash_concat(&msg, &hash_fixed_bytes(&d[76..172], zh))
}

fn hash_attestation(d: &[u8], zh: &[B256]) -> B256 {
    if d.len() < 236 {
        return ZERO_HASH;
    }
    let agg_off = u32::from_le_bytes(d[0..4].try_into().unwrap()) as usize;
    let agg_bits = if agg_off <= d.len() { &d[agg_off..] } else { &[] };

    let max_bits: usize = 64 * 2048;
    let bit_len = bitlist_len(agg_bits);
    let agg_root = hash_bitlist(agg_bits, bit_len, max_bits, zh);

    let data_root = hash_attestation_data(&d[4..132], zh);
    let sig_root = hash_fixed_bytes(&d[132..228], zh);
    let mut cb = ZERO_HASH;
    cb[..8].copy_from_slice(&d[228..236]);

    merkleize(&[agg_root, data_root, sig_root, cb], zh)
}

pub(crate) fn hash_attestation_data(d: &[u8], zh: &[B256]) -> B256 {
    let u64c = |off: usize| uint64_chunk(u64::from_le_bytes(d[off..off + 8].try_into().unwrap()));
    let b = |off: usize| -> B256 { d[off..off + 32].try_into().unwrap() };
    let cp = |off: usize| hash_concat(&u64c(off), &b(off + 8));
    merkleize(&[u64c(0), u64c(8), b(16), cp(48), cp(88)], zh)
}

fn hash_indexed_attestation(d: &[u8], zh: &[B256]) -> B256 {
    let max_indices: usize = 64 * 2048;
    let target_depth = max_indices.div_ceil(4).next_power_of_two().trailing_zeros() as u8;
    if d.len() < 228 {
        // Empty IA: zero attesting_indices, zero AttestationData, zero sig.
        let indices_root = mix_in_length(&zh[target_depth as usize], 0);
        let data_root = hash_attestation_data(&[0u8; 128], zh);
        let sig_root = hash_fixed_bytes(&[0u8; 96], zh);
        return merkleize(&[indices_root, data_root, sig_root], zh);
    }
    let indices_off = u32::from_le_bytes(d[0..4].try_into().unwrap()) as usize;
    let indices_data = if indices_off <= d.len() { &d[indices_off..] } else { &[] };
    let idx_count = indices_data.len() / 8;

    let mut stack = MerkleStack::new();
    let mut chunk = [0u8; 32];
    let mut slot = 0usize;
    for i in 0..idx_count {
        let off = slot * 8;
        chunk[off..off + 8].copy_from_slice(&indices_data[i * 8..i * 8 + 8]);
        slot += 1;
        if slot == 4 {
            merkle_push(&mut stack, chunk);
            chunk = [0u8; 32];
            slot = 0;
        }
    }
    if slot != 0 {
        merkle_push(&mut stack, chunk);
    }
    let indices_root = mix_in_length(&merkle_finalize(stack, target_depth, zh), idx_count);

    let data_root = hash_attestation_data(&d[4..132], zh);
    let sig_root = hash_fixed_bytes(&d[132..228], zh);
    merkleize(&[indices_root, data_root, sig_root], zh)
}

fn hash_attester_slashing(d: &[u8], zh: &[B256]) -> B256 {
    if d.len() < 8 {
        // Empty AttesterSlashing root: two empty-IA roots concatenated.
        let empty_ia = hash_indexed_attestation(&[], zh);
        return hash_concat(&empty_ia, &empty_ia);
    }
    let off1 = u32::from_le_bytes(d[0..4].try_into().unwrap()) as usize;
    let off2 = u32::from_le_bytes(d[4..8].try_into().unwrap()) as usize;
    let ia1 = if off1 <= off2 && off2 <= d.len() { &d[off1..off2] } else { &[] };
    let ia2 = if off2 <= d.len() { &d[off2..] } else { &[] };
    hash_concat(&hash_indexed_attestation(ia1, zh), &hash_indexed_attestation(ia2, zh))
}

/// hash_tree_root for a Bitlist. Streams content bytes into 32-byte chunks,
/// masking the delimiter bit on the last content byte.
fn hash_bitlist(data: &[u8], bit_len: usize, max_bits: usize, zh: &[B256]) -> B256 {
    let limit_chunks = max_bits.div_ceil(256).next_power_of_two();
    let target_depth = limit_chunks.trailing_zeros() as u8;
    if bit_len == 0 {
        return mix_in_length(&merkle_finalize(MerkleStack::new(), target_depth, zh), 0);
    }
    let content_bytes = bit_len.div_ceil(8);
    let delim_byte = bit_len / 8;
    let delim_bit = bit_len % 8;

    let mut stack = MerkleStack::new();
    let mut chunk = [0u8; 32];
    let mut slot = 0usize;
    for (i, &raw) in data[..content_bytes].iter().enumerate() {
        let b = if i == delim_byte { raw & !(1u8 << delim_bit) } else { raw };
        chunk[slot] = b;
        slot += 1;
        if slot == 32 {
            merkle_push(&mut stack, chunk);
            chunk = [0u8; 32];
            slot = 0;
        }
    }
    if slot != 0 {
        merkle_push(&mut stack, chunk);
    }
    mix_in_length(&merkle_finalize(stack, target_depth, zh), bit_len)
}

pub fn bitlist_len(data: &[u8]) -> usize {
    if data.is_empty() {
        return 0;
    }
    let last = data[data.len() - 1];
    if last == 0 {
        return 0;
    }
    let bits_before_last = (data.len() - 1) * 8;
    bits_before_last + 7 - last.leading_zeros() as usize
}

fn hash_deposit_request(d: &[u8], zh: &[B256]) -> B256 {
    merkleize(
        &[
            hash_fixed_bytes(&d[..48], zh),
            <[u8; 32]>::try_from(&d[48..80]).unwrap(),
            uint64_chunk(u64::from_le_bytes(d[80..88].try_into().unwrap())),
            hash_fixed_bytes(&d[88..184], zh),
            uint64_chunk(u64::from_le_bytes(d[184..192].try_into().unwrap())),
        ],
        zh,
    )
}

fn hash_withdrawal_request(d: &[u8], zh: &[B256]) -> B256 {
    let mut addr = ZERO_HASH;
    addr[..20].copy_from_slice(&d[..20]);
    merkleize(
        &[
            addr,
            hash_fixed_bytes(&d[20..68], zh),
            uint64_chunk(u64::from_le_bytes(d[68..76].try_into().unwrap())),
        ],
        zh,
    )
}

fn hash_consolidation_request(d: &[u8], zh: &[B256]) -> B256 {
    let mut addr = ZERO_HASH;
    addr[..20].copy_from_slice(&d[..20]);
    merkleize(&[addr, hash_fixed_bytes(&d[20..68], zh), hash_fixed_bytes(&d[68..116], zh)], zh)
}

fn hash_list_fixed_elements(data: &[u8], element_size: usize, limit: usize, zh: &[B256]) -> B256 {
    if element_size == 0 {
        return mix_in_length(&ZERO_HASH, 0);
    }
    let count = data.len() / element_size;
    let target_depth = limit.next_power_of_two().trailing_zeros() as u8;
    let mut stack = MerkleStack::new();
    for i in 0..count {
        let elem = &data[i * element_size..(i + 1) * element_size];
        merkle_push(&mut stack, hash_fixed_bytes(elem, zh));
    }
    let root = merkle_finalize(stack, target_depth, zh);
    mix_in_length(&root, count)
}

/// hash_tree_root for ExecutionPayload from raw SSZ bytes.
/// 17 fields → 32 leaves.
fn hash_execution_payload(data: &[u8], zh: &[B256]) -> B256 {
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
    let extra_data_root = {
        // ByteList[32] → max 1 chunk.
        let mut stack = MerkleStack::new();
        push_bytes_as_chunks(extra_data_bytes, &mut stack);
        let root = merkle_finalize(stack, 0, zh);
        mix_in_length(&root, extra_data_bytes.len())
    };

    let txns_bytes = if transactions_off < withdrawals_off && withdrawals_off <= data.len() {
        &data[transactions_off..withdrawals_off]
    } else {
        &[]
    };
    let transactions_root = hash_transactions(txns_bytes, zh);

    let withdrawals_bytes =
        if withdrawals_off <= data.len() { &data[withdrawals_off..] } else { &[] };
    let withdrawals_root = hash_withdrawals(withdrawals_bytes, zh);

    let fields: [B256; 17] = [
        b256(0),
        fee_recipient,
        b256(52),
        b256(84),
        hash_fixed_bytes(&data[116..372], zh),
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
    merkleize(&fields, zh)
}

/// hash_tree_root for List[Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].
fn hash_transactions(data: &[u8], zh: &[B256]) -> B256 {
    use types::{MAX_BYTES_PER_TRANSACTION, MAX_TRANSACTIONS_PER_PAYLOAD};

    let outer_depth = MAX_TRANSACTIONS_PER_PAYLOAD.next_power_of_two().trailing_zeros() as u8;
    let tx_chunk_limit = MAX_BYTES_PER_TRANSACTION.div_ceil(32).next_power_of_two();
    let tx_chunk_depth = tx_chunk_limit.trailing_zeros() as u8;

    if data.is_empty() {
        return mix_in_length(&merkle_finalize(MerkleStack::new(), outer_depth, zh), 0);
    }

    let first_off = u32::from_le_bytes(data[..4].try_into().unwrap_or([0; 4])) as usize;
    if first_off == 0 || !first_off.is_multiple_of(4) || first_off > data.len() {
        return mix_in_length(&merkle_finalize(MerkleStack::new(), outer_depth, zh), 0);
    }
    let count = first_off / 4;

    let mut outer = MerkleStack::new();
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
        let mut inner = MerkleStack::new();
        push_bytes_as_chunks(tx_bytes, &mut inner);
        let tx_root = mix_in_length(&merkle_finalize(inner, tx_chunk_depth, zh), tx_bytes.len());
        merkle_push(&mut outer, tx_root);
    }

    let root = merkle_finalize(outer, outer_depth, zh);
    mix_in_length(&root, count)
}

/// hash_tree_root for List[Withdrawal, 16]. Withdrawal fixed 44 bytes.
fn hash_withdrawals(data: &[u8], zh: &[B256]) -> B256 {
    const WITHDRAWAL_SIZE: usize = 44;

    let count = data.len() / WITHDRAWAL_SIZE;
    let target_depth =
        types::MAX_WITHDRAWALS_PER_PAYLOAD.next_power_of_two().trailing_zeros() as u8;
    let mut stack = MerkleStack::new();
    for i in 0..count {
        let w = &data[i * WITHDRAWAL_SIZE..(i + 1) * WITHDRAWAL_SIZE];
        let u64at = |off: usize| -> u64 { u64::from_le_bytes(w[off..off + 8].try_into().unwrap()) };
        let mut addr = ZERO_HASH;
        addr[..20].copy_from_slice(&w[16..36]);
        let chunks =
            [uint64_chunk(u64at(0)), uint64_chunk(u64at(8)), addr, uint64_chunk(u64at(36))];
        merkle_push(&mut stack, merkleize(&chunks, zh));
    }
    let root = merkle_finalize(stack, target_depth, zh);
    mix_in_length(&root, count)
}

/// hash_tree_root of the full BeaconState from tiered data.
/// Fulu state: 38 fields → 64 leaves.
// TODO(perf): full re-merkleization every block + every process_slot
// (state_root snapshot + apply_block verification). At 2M validators
// hash_validators alone is ~8M sha256s per call. Lighthouse uses milhouse
// persistent trees that only re-hash dirty subtrees. Add per-leaf dirty bits
// per tier + a layered cache for: validators, balances, inactivity_scores,
// randao_mixes (see hash_randao_mixes), participation lists.
#[allow(clippy::too_many_arguments)]
pub fn hash_tree_root_state(
    imm: &Immutable,
    vid: &ValidatorIdentity,
    longtail: &HistoricalLongtail,
    epoch: &EpochData,
    roots: &SlotRoots,
    sd: &SlotData,
    pq: &PendingQueues,
    zh: &[B256],
) -> B256 {
    let n = vid.validator_cnt;

    let fields: [B256; 38] = [
        uint64_chunk(imm.genesis_time),
        imm.genesis_validators_root,
        uint64_chunk(sd.slot),
        hash_fork(&imm.fork, zh),
        hash_tree_root_block_header(&sd.latest_block_header, zh),
        hash_b256_vector(&roots.block_roots, zh),
        hash_b256_vector(&roots.state_roots, zh),
        imm.historical_roots_hash,
        hash_eth1_data(&sd.eth1_data, zh),
        hash_eth1_votes(sd, zh),
        uint64_chunk(sd.eth1_deposit_index),
        hash_validators(vid, epoch, zh),
        hash_uint64_list(&sd.balances, n, VALIDATOR_REGISTRY_LIMIT, zh),
        hash_randao_mixes(epoch, sd, zh),
        hash_uint64_vector(&epoch.slashings, zh),
        hash_uint8_list(&sd.previous_epoch_participation, n, VALIDATOR_REGISTRY_LIMIT, zh),
        hash_uint8_list(&sd.current_epoch_participation, n, VALIDATOR_REGISTRY_LIMIT, zh),
        uint64_chunk(sd.justification_bits as u64),
        hash_checkpoint(&sd.previous_justified_checkpoint),
        hash_checkpoint(&sd.current_justified_checkpoint),
        hash_checkpoint(&sd.finalized_checkpoint),
        hash_uint64_list(&epoch.inactivity_scores, n, VALIDATOR_REGISTRY_LIMIT, zh),
        hash_sync_committee(&longtail.current_sync_committee, zh),
        hash_sync_committee(&longtail.next_sync_committee, zh),
        hash_execution_payload_header(&sd.latest_execution_payload_header, zh),
        uint64_chunk(sd.next_withdrawal_index),
        uint64_chunk(sd.next_withdrawal_validator_index),
        hash_historical_summaries(longtail, zh),
        uint64_chunk(sd.deposit_requests_start_index),
        uint64_chunk(sd.deposit_balance_to_consume),
        uint64_chunk(sd.exit_balance_to_consume),
        uint64_chunk(sd.earliest_exit_epoch),
        uint64_chunk(sd.consolidation_balance_to_consume),
        uint64_chunk(sd.earliest_consolidation_epoch),
        hash_pending_deposits(pq, zh),
        hash_pending_partial_withdrawals(pq, zh),
        hash_pending_consolidations(pq, zh),
        hash_uint64_vector(&sd.proposer_lookahead, zh),
    ];

    merkleize(&fields, zh)
}

/// Hash randao_mixes with the per-block accumulator override from SlotData.
// TODO(perf): rebuilds the full 65536-leaf tree every block (~65k sha256s).
// Only one leaf changes per slot (current_idx); cache 2N-1 nodes (~4 MB) on
// EpochData and update the log2(N)=16 path on mutation. Replay must rebuild
// the cache from leaves on load.
pub fn hash_randao_mixes(epoch: &EpochData, sd: &SlotData, zh: &[B256]) -> B256 {
    use types::{EPOCHS_PER_HISTORICAL_VECTOR, SLOTS_PER_EPOCH};
    let current_epoch = sd.slot / SLOTS_PER_EPOCH;
    let current_idx = current_epoch as usize % EPOCHS_PER_HISTORICAL_VECTOR;
    let target_depth = EPOCHS_PER_HISTORICAL_VECTOR.trailing_zeros() as u8;

    let mut stack = MerkleStack::new();
    for (i, mix) in epoch.randao_mixes.iter().enumerate() {
        let m = if i == current_idx { sd.randao_mix_current } else { *mix };
        merkle_push(&mut stack, m);
    }
    merkle_finalize(stack, target_depth, zh)
}

pub fn hash_uint64_vector(values: &[u64], zh: &[B256]) -> B256 {
    let chunk_count = values.len().div_ceil(4);
    let target_depth = chunk_count.next_power_of_two().trailing_zeros() as u8;
    let mut stack = MerkleStack::new();
    let mut chunk = [0u8; 32];
    let mut slot = 0usize;
    for &v in values.iter() {
        let off = slot * 8;
        chunk[off..off + 8].copy_from_slice(&v.to_le_bytes());
        slot += 1;
        if slot == 4 {
            merkle_push(&mut stack, chunk);
            chunk = [0u8; 32];
            slot = 0;
        }
    }
    if slot != 0 {
        merkle_push(&mut stack, chunk);
    }
    merkle_finalize(stack, target_depth, zh)
}

pub fn hash_validators(vid: &ValidatorIdentity, epoch: &EpochData, zh: &[B256]) -> B256 {
    let n = vid.validator_cnt;
    let target_depth = VALIDATOR_REGISTRY_LIMIT.next_power_of_two().trailing_zeros() as u8;
    let mut stack = MerkleStack::new();
    for i in 0..n {
        merkle_push(&mut stack, hash_single_validator(vid, epoch, i, zh));
    }
    let root = merkle_finalize(stack, target_depth, zh);
    mix_in_length(&root, n)
}

fn hash_single_validator(
    vid: &ValidatorIdentity,
    epoch: &EpochData,
    i: usize,
    zh: &[B256],
) -> B256 {
    let pubkey_hash = hash_fixed_bytes(&vid.val_pubkey[i], zh);
    let chunks = [
        pubkey_hash,
        vid.val_withdrawal_credentials[i],
        uint64_chunk(epoch.val_effective_balance[i]),
        uint64_chunk(epoch.val_slashed(i) as u64),
        uint64_chunk(epoch.val_activation_eligibility_epoch[i]),
        uint64_chunk(epoch.val_activation_epoch[i]),
        uint64_chunk(epoch.val_exit_epoch[i]),
        uint64_chunk(epoch.val_withdrawable_epoch[i]),
    ];
    merkleize(&chunks, zh)
}

pub fn hash_sync_committee(sc: &types::SyncCommittee, zh: &[B256]) -> B256 {
    let target_depth = SYNC_COMMITTEE_SIZE.next_power_of_two().trailing_zeros() as u8;
    let mut stack = MerkleStack::new();
    for pk in &sc.pubkeys {
        merkle_push(&mut stack, hash_fixed_bytes(pk, zh));
    }
    let pubkeys_root = merkle_finalize(stack, target_depth, zh);
    let agg_root = hash_fixed_bytes(&sc.aggregate_pubkey, zh);
    hash_concat(&pubkeys_root, &agg_root)
}

pub fn hash_eth1_votes(sd: &SlotData, zh: &[B256]) -> B256 {
    let n = sd.eth1_votes.len();
    let target_depth = types::MAX_ETH1_VOTES.next_power_of_two().trailing_zeros() as u8;
    let mut stack = MerkleStack::new();
    for i in 0..n {
        merkle_push(&mut stack, hash_eth1_data(&sd.eth1_votes[i], zh));
    }
    let root = merkle_finalize(stack, target_depth, zh);
    mix_in_length(&root, n)
}

pub fn hash_fork(f: &types::Fork, zh: &[B256]) -> B256 {
    let mut pv = ZERO_HASH;
    pv[..4].copy_from_slice(&f.previous_version);
    let mut cv = ZERO_HASH;
    cv[..4].copy_from_slice(&f.current_version);
    merkleize(&[pv, cv, uint64_chunk(f.epoch)], zh)
}

pub fn hash_execution_payload_header(h: &types::ExecutionPayloadHeader, zh: &[B256]) -> B256 {
    let mut fee_recipient_chunk = ZERO_HASH;
    fee_recipient_chunk[..20].copy_from_slice(&h.fee_recipient);

    let extra_data_root = {
        let mut stack = MerkleStack::new();
        push_bytes_as_chunks(&h.extra_data[..h.extra_data_len as usize], &mut stack);
        let root = merkle_finalize(stack, 0, zh);
        mix_in_length(&root, h.extra_data_len as usize)
    };

    let fields: [B256; 17] = [
        h.parent_hash,
        fee_recipient_chunk,
        h.state_root,
        h.receipts_root,
        hash_fixed_bytes(&h.logs_bloom, zh),
        h.prev_randao,
        uint64_chunk(h.block_number),
        uint64_chunk(h.gas_limit),
        uint64_chunk(h.gas_used),
        uint64_chunk(h.timestamp),
        extra_data_root,
        h.base_fee_per_gas,
        h.block_hash,
        h.transactions_root,
        h.withdrawals_root,
        uint64_chunk(h.blob_gas_used),
        uint64_chunk(h.excess_blob_gas),
    ];
    merkleize(&fields, zh)
}

pub fn hash_pending_deposits(pq: &PendingQueues, zh: &[B256]) -> B256 {
    let n = pq.pending_deposits.len();
    let target_depth = types::PENDING_DEPOSITS_LIMIT.next_power_of_two().trailing_zeros() as u8;
    let mut stack = MerkleStack::new();
    for i in 0..n {
        let d = &pq.pending_deposits[i];
        let chunks = [
            hash_fixed_bytes(&d.pubkey, zh),
            d.withdrawal_credentials,
            uint64_chunk(d.amount),
            hash_fixed_bytes(&d.signature, zh),
            uint64_chunk(d.slot),
        ];
        merkle_push(&mut stack, merkleize(&chunks, zh));
    }
    let root = merkle_finalize(stack, target_depth, zh);
    mix_in_length(&root, n)
}

pub fn hash_pending_partial_withdrawals(pq: &PendingQueues, zh: &[B256]) -> B256 {
    let n = pq.pending_partial_withdrawals.len();
    let target_depth =
        types::PENDING_PARTIAL_WITHDRAWALS_LIMIT.next_power_of_two().trailing_zeros() as u8;
    let mut stack = MerkleStack::new();
    for i in 0..n {
        let w = &pq.pending_partial_withdrawals[i];
        let chunks =
            [uint64_chunk(w.index), uint64_chunk(w.amount), uint64_chunk(w.withdrawable_epoch)];
        merkle_push(&mut stack, merkleize(&chunks, zh));
    }
    let root = merkle_finalize(stack, target_depth, zh);
    mix_in_length(&root, n)
}

pub fn hash_pending_consolidations(pq: &PendingQueues, zh: &[B256]) -> B256 {
    let n = pq.pending_consolidations.len();
    let target_depth =
        types::PENDING_CONSOLIDATIONS_LIMIT.next_power_of_two().trailing_zeros() as u8;
    let mut stack = MerkleStack::new();
    for i in 0..n {
        let c = &pq.pending_consolidations[i];
        merkle_push(
            &mut stack,
            hash_concat(&uint64_chunk(c.source_index), &uint64_chunk(c.target_index)),
        );
    }
    let root = merkle_finalize(stack, target_depth, zh);
    mix_in_length(&root, n)
}

pub fn hash_historical_summaries(longtail: &HistoricalLongtail, zh: &[B256]) -> B256 {
    let n = longtail.historical_summaries.len();
    let target_depth = HISTORICAL_ROOTS_LIMIT.trailing_zeros() as u8;
    let mut stack = MerkleStack::new();
    for i in 0..n {
        let s = &longtail.historical_summaries[i];
        merkle_push(&mut stack, hash_concat(&s.block_summary_root, &s.state_summary_root));
    }
    let root = merkle_finalize(stack, target_depth, zh);
    mix_in_length(&root, n)
}

/// Extract and hash transactions from ExecutionPayload SSZ bytes.
pub fn hash_transactions_from_payload(payload: &[u8], zh: &[B256]) -> B256 {
    if payload.len() < 528 {
        return ZERO_HASH;
    }
    let off32 = |pos: usize| -> usize {
        u32::from_le_bytes(payload[pos..pos + 4].try_into().unwrap()) as usize
    };
    let txns_off = off32(504);
    let withdrawals_off = off32(508);
    if txns_off <= withdrawals_off && withdrawals_off <= payload.len() {
        hash_transactions(&payload[txns_off..withdrawals_off], zh)
    } else {
        ZERO_HASH
    }
}

/// Extract and hash withdrawals from ExecutionPayload SSZ bytes.
pub fn hash_withdrawals_from_payload(payload: &[u8], zh: &[B256]) -> B256 {
    if payload.len() < 528 {
        return ZERO_HASH;
    }
    let off32 = |pos: usize| -> usize {
        u32::from_le_bytes(payload[pos..pos + 4].try_into().unwrap()) as usize
    };
    let withdrawals_off = off32(508);
    if withdrawals_off <= payload.len() {
        hash_withdrawals(&payload[withdrawals_off..], zh)
    } else {
        ZERO_HASH
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zh_table() -> [B256; ZERO_HASHES_LEN] {
        compute_zero_hashes()
    }

    fn hex_b32(s: &str) -> B256 {
        assert_eq!(s.len(), 64);
        let b = s.as_bytes();
        let n = |c: u8| -> u8 {
            match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                _ => panic!(),
            }
        };
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = (n(b[i * 2]) << 4) | n(b[i * 2 + 1]);
        }
        out
    }

    /// Anchor against the spec-published zero-subtree roots. Values below
    /// are the canonical zero-hashes generated by the recurrence
    /// `zh[i+1] = sha256(zh[i] || zh[i])`, zh[0] = [0u8; 32].
    /// Reproducible locally:
    ///   python3 -c 'import hashlib;x=bytes(32)
    ///   for _ in range(10): x=hashlib.sha256(x+x).digest(); print(x.hex())'
    #[test]
    fn zero_hashes_match_spec() {
        let zh = compute_zero_hashes();
        assert_eq!(zh[0], [0u8; 32]);
        let expected: &[(usize, &str)] = &[
            (1, "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b"),
            (2, "db56114e00fdd4c1f85c892bf35ac9a89289aaecb1ebd0a96cde606a748b5d71"),
            (3, "c78009fdf07fc56a11f122370658a353aaa542ed63e44c4bc15ff4cd105ab33c"),
            (4, "536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c"),
            (5, "9efde052aa15429fae05bad4d0b1d7c64da64d03d7a1854a588c2cb8430c0d30"),
            (6, "d88ddfeed400a8755596b21942c1497e114c302e6118290f91e6772976041fa1"),
            (7, "87eb0ddba57e35f6d286673802a4af5975e22506c7cf4c64bb6be5ee11527f2c"),
            (8, "26846476fd5fc54a5d43385167c95144f2643f533cc85bb9d16b782f8d7db193"),
            (9, "506d86582d252405b840018792cad2bf1259f1ef5aa5f887e13cb2f0094f51e1"),
            (10, "ffff0ad7e659772f9534c195c815efc4014ef1e1daed4404c06385d11192e92b"),
        ];
        for &(i, hex) in expected {
            assert_eq!(zh[i], hex_b32(hex), "zh[{i}]");
        }
    }

    #[test]
    fn uint64_chunk_encoding() {
        let c = uint64_chunk(0x0102030405060708);
        assert_eq!(c[0], 0x08);
        assert_eq!(c[7], 0x01);
        assert_eq!(c[8..], [0u8; 24]);
    }

    /// Element: 28 bytes of 0xFF + 4-byte LE int. Matches spec's e(v).
    fn e(v: u32) -> B256 {
        let mut chunk = [0xFF; 32];
        chunk[28..32].copy_from_slice(&v.to_le_bytes());
        chunk
    }

    fn z(i: usize) -> B256 {
        compute_zero_hashes()[i]
    }

    fn h(a: B256, b: B256) -> B256 {
        hash_concat(&a, &b)
    }

    #[test]
    fn spec_merkleize_vectors() {
        let zh = zh_table();
        let cases: Vec<(usize, usize, B256)> = vec![
            (0, 0, z(0)),
            (0, 1, z(0)),
            (1, 1, e(0)),
            (0, 2, h(z(0), z(0))),
            (1, 2, h(e(0), z(0))),
            (2, 2, h(e(0), e(1))),
            (0, 4, h(h(z(0), z(0)), z(1))),
            (1, 4, h(h(e(0), z(0)), z(1))),
            (2, 4, h(h(e(0), e(1)), z(1))),
            (3, 4, h(h(e(0), e(1)), h(e(2), z(0)))),
            (4, 4, h(h(e(0), e(1)), h(e(2), e(3)))),
            (0, 8, h(h(h(z(0), z(0)), z(1)), z(2))),
            (1, 8, h(h(h(e(0), z(0)), z(1)), z(2))),
            (2, 8, h(h(h(e(0), e(1)), z(1)), z(2))),
            (3, 8, h(h(h(e(0), e(1)), h(e(2), z(0))), z(2))),
            (4, 8, h(h(h(e(0), e(1)), h(e(2), e(3))), z(2))),
            (5, 8, h(h(h(e(0), e(1)), h(e(2), e(3))), h(h(e(4), z(0)), z(1)))),
            (6, 8, h(h(h(e(0), e(1)), h(e(2), e(3))), h(h(e(4), e(5)), h(z(0), z(0))))),
            (7, 8, h(h(h(e(0), e(1)), h(e(2), e(3))), h(h(e(4), e(5)), h(e(6), z(0))))),
            (8, 8, h(h(h(e(0), e(1)), h(e(2), e(3))), h(h(e(4), e(5)), h(e(6), e(7))))),
            (0, 16, h(h(h(h(z(0), z(0)), z(1)), z(2)), z(3))),
            (1, 16, h(h(h(h(e(0), z(0)), z(1)), z(2)), z(3))),
            (4, 16, h(h(h(h(e(0), e(1)), h(e(2), e(3))), z(2)), z(3))),
            (
                9,
                16,
                h(
                    h(h(h(e(0), e(1)), h(e(2), e(3))), h(h(e(4), e(5)), h(e(6), e(7)))),
                    h(h(h(e(8), z(0)), z(1)), z(2)),
                ),
            ),
        ];

        for (i, (count, limit, expected)) in cases.iter().enumerate() {
            let chunks: Vec<B256> = (0..*count as u32).map(e).collect();
            let limit_pow2 = if *limit == 0 { 1 } else { limit.next_power_of_two() };
            let result = merkleize_padded(&chunks, limit_pow2, &zh);
            assert_eq!(result, *expected, "case {i}: count={count} limit={limit}");
        }
    }
}
