//! SSZ hash-tree-root primitives and byte-slice-driven container/list
//! hashers. Spec-compliant Merkleization built on
//! `merkle_push`/`merkle_finalize` with a precomputed zero-hash table.
//!
//! Functions split into three layers:
//! 1. Primitives: `sha256`, `hash_concat`, `uint64_chunk`, `merkleize*`,
//!    `mix_in_length`, `ZERO_HASHES`, `is_valid_merkle_branch`.
//! 2. Generic list/vector hashers over byte slices: `hash_fixed_bytes`,
//!    `hash_uint64_list/vector`, `hash_uint8_list`, `hash_b256_vector`,
//!    `hash_list_containers`, `hash_list_variable_containers`,
//!    `hash_list_fixed_elements`, `hash_bitlist`.
//! 3. Eth2-shape hashers over raw SSZ bytes: `hash_tree_root_body`,
//!    `hash_execution_payload`, the per-element helpers for attestations /
//!    slashings / deposits / exits / bls-changes / execution-requests, and the
//!    freestanding `hash_tree_root_{fork_data, voluntary_exit, bls_change,
//!    deposit_data, aggregate_and_proof}`.
//!
//! Struct-based hashers that consume in-memory beacon-state types
//! (validators, sync committee, eth1 votes, full beacon state, etc.)
//! live in `silver_beacon_state::ssz_hash` and reuse the primitives
//! re-exported from here.

use std::sync::LazyLock;

use flux::utils::ArrayVec;
use sha2::{Digest, Sha256};
use silver_common_macros::timed;

/// One-time hashtree backend selection (SHA-NI / AVX-512 / AVX2 / SSE).
/// Forced on the first `hash_concat` call; result is `1` on success.
static HASHTREE_READY: LazyLock<()> = LazyLock::new(|| {
    let rc = hashtree_rs::init();
    debug_assert_eq!(rc, 1, "hashtree_rs::init() failed");
});

use crate::ssz_view::{
    MAX_BYTES_PER_TRANSACTION, MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD,
    MAX_DEPOSIT_REQUESTS_PER_PAYLOAD, MAX_TRANSACTIONS_PER_PAYLOAD,
    MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD, MAX_WITHDRAWALS_PER_PAYLOAD,
};

pub type B256 = [u8; 32];

#[inline]
pub fn sha256(data: &[u8]) -> B256 {
    Sha256::digest(data).into()
}

#[inline]
pub fn hash_concat(a: &B256, b: &B256) -> B256 {
    LazyLock::force(&HASHTREE_READY);
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(a);
    buf[32..].copy_from_slice(b);
    let mut out = [0u8; 32];
    hashtree_rs::hash(&mut out, &buf, 1);
    out
}

#[inline]
pub fn hash_concat_many(out: &mut [B256], pairs: &[B256]) {
    debug_assert_eq!(pairs.len(), 2 * out.len());
    LazyLock::force(&HASHTREE_READY);
    let n = out.len();
    let out_bytes = unsafe { std::slice::from_raw_parts_mut(out.as_mut_ptr() as *mut u8, n * 32) };
    let in_bytes = unsafe { std::slice::from_raw_parts(pairs.as_ptr() as *const u8, n * 64) };
    hashtree_rs::hash(out_bytes, in_bytes, n);
}

/// Spec: is_valid_merkle_branch. `branch` is `depth * 32` bytes of siblings,
/// ascending from leaf-level. Bit `i` of `index` selects which side the
/// running hash takes at level `i`.
#[timed]
pub fn is_valid_merkle_branch(
    leaf: &B256,
    branch: &[u8],
    depth: u32,
    index: u64,
    root: &B256,
) -> bool {
    if branch.len() < (depth as usize) * 32 {
        return false;
    }
    let mut value = *leaf;
    for i in 0..depth {
        let sib: &B256 = branch[(i as usize) * 32..((i + 1) as usize) * 32].try_into().unwrap();
        value =
            if (index >> i) & 1 == 0 { hash_concat(&value, sib) } else { hash_concat(sib, &value) };
    }
    value == *root
}

#[inline]
pub fn uint64_chunk(v: u64) -> B256 {
    let mut chunk = [0u8; 32];
    chunk[..8].copy_from_slice(&v.to_le_bytes());
    chunk
}

#[inline]
fn usize_chunk(v: usize) -> B256 {
    uint64_chunk(v as u64)
}

pub const ZERO_HASH: B256 = [0u8; 32];

/// Max SSZ depth we ever hit is 40 (VALIDATOR_REGISTRY_LIMIT = 2^40);
pub const ZERO_HASHES_LEN: usize = 48;

/// Stack of parked subtree roots keyed by height. Heights strictly decrease
/// from bottom to top.
pub type MerkleStack = ArrayVec<(u8, B256), ZERO_HASHES_LEN>;

/// Absorb a leaf, combining upward with any left-sibling already parked at
/// the same height.
pub fn merkle_push(stack: &mut MerkleStack, leaf: B256) {
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
pub fn merkle_finalize(mut stack: MerkleStack, target_depth: u8) -> B256 {
    if stack.is_empty() {
        return ZERO_HASHES[target_depth as usize];
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
                cur = hash_concat(&cur, &ZERO_HASHES[h as usize]);
            }
        }
        h += 1;
    }
    cur
}

pub const ZERO_HASHES: [B256; ZERO_HASHES_LEN] = {
    let mut zh = [ZERO_HASH; ZERO_HASHES_LEN];
    let mut i = 1;
    while i < ZERO_HASHES_LEN {
        zh[i] = const_hash_concat(&zh[i - 1], &zh[i - 1]);
        i += 1;
    }
    zh
};

const fn const_hash_concat(a: &B256, b: &B256) -> B256 {
    sha2_const_stable::Sha256::new().update(a).update(b).finalize()
}

/// Push raw bytes packed as 32-byte chunks (tail zero-padded). The aligned
/// prefix is cast as `&[B256]` (B256 has alignment 1, safe for any byte ptr).
pub fn push_bytes_as_chunks(data: &[u8], stack: &mut MerkleStack) {
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

/// Upper bound for `merkleize`'s stack-based fast path (covers small fixed
/// containers like the 8-field `Validator`).
const MERKLE_INLINE_CHUNKS: usize = 32;

/// Merkleize a slice of 32-byte chunks, padding to the next power of two.
#[timed]
pub fn merkleize(chunks: &[B256]) -> B256 {
    let leaf_count = chunks.len().next_power_of_two().max(1);
    if leaf_count <= MERKLE_INLINE_CHUNKS {
        merkleize_inline(chunks, leaf_count)
    } else {
        merkleize_padded(chunks, leaf_count)
    }
}

/// Merkleize `chunks` into a `leaf_count`-leaf tree, zero-padding missing leaves
/// and reducing a layer at a time with batched hashing. Ping-pongs `a` and `b`
/// so each `hash_concat_many` has disjoint in/out.
fn merkleize_inline(chunks: &[B256], leaf_count: usize) -> B256 {
    debug_assert!(leaf_count.is_power_of_two() && leaf_count <= MERKLE_INLINE_CHUNKS);
    debug_assert!(chunks.len() <= leaf_count);
    let mut a = [ZERO_HASH; MERKLE_INLINE_CHUNKS];
    a[..chunks.len()].copy_from_slice(chunks);
    if leaf_count == 1 {
        return a[0];
    }
    let mut b = [ZERO_HASH; MERKLE_INLINE_CHUNKS / 2];
    let mut width = leaf_count;
    let mut in_a = true; // current layer lives in `a` (else `b`)
    while width > 1 {
        let half = width / 2;
        if in_a {
            hash_concat_many(&mut b[..half], &a[..width]);
        } else {
            hash_concat_many(&mut a[..half], &b[..width]);
        }
        in_a = !in_a;
        width = half;
    }
    if in_a { a[0] } else { b[0] }
}

/// Merkleize with a fixed leaf count (power of two, for list limits).
pub fn merkleize_padded(chunks: &[B256], leaf_count: usize) -> B256 {
    debug_assert!(leaf_count.is_power_of_two());
    debug_assert!(chunks.len() <= leaf_count);

    let target_depth = leaf_count.trailing_zeros() as u8;
    let mut stack = MerkleStack::new();
    for c in chunks {
        merkle_push(&mut stack, *c);
    }
    merkle_finalize(stack, target_depth)
}

#[inline]
pub fn mix_in_length(root: &B256, length: usize) -> B256 {
    hash_concat(root, &usize_chunk(length))
}

/// hash_tree_root of a fixed-size byte vector (e.g. BLSSignature, Bitvector).
pub fn hash_fixed_bytes(data: &[u8]) -> B256 {
    if data.is_empty() {
        return ZERO_HASH;
    }
    let chunk_count = data.len().div_ceil(32);
    let target_depth = chunk_count.next_power_of_two().trailing_zeros() as u8;
    let mut stack = MerkleStack::new();
    push_bytes_as_chunks(data, &mut stack);
    merkle_finalize(stack, target_depth)
}

/// Hash `List[uint64, limit]`. `values` yields exactly `count` items (the
/// list length); taking an iterator lets callers stream a delta-merged
/// column without materialising it.
#[timed]
pub fn hash_uint64_list(values: impl Iterator<Item = u64>, count: usize, limit: usize) -> B256 {
    let limit_chunks = limit.div_ceil(4);
    let target_depth = limit_chunks.next_power_of_two().trailing_zeros() as u8;

    let mut stack = MerkleStack::new();
    let mut chunk = [0u8; 32];
    let mut slot = 0usize;
    for v in values {
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
    let root = merkle_finalize(stack, target_depth);
    mix_in_length(&root, count)
}

/// Hash `List[uint8, limit]` (e.g. participation flags) from an iterator.
#[timed]
pub fn hash_uint8_list(values: impl Iterator<Item = u8>, count: usize, limit: usize) -> B256 {
    let limit_chunks = limit.div_ceil(32);
    let target_depth = limit_chunks.next_power_of_two().trailing_zeros() as u8;
    let mut stack = MerkleStack::new();
    let mut chunk = [0u8; 32];
    let mut slot = 0usize;
    for b in values {
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
    let root = merkle_finalize(stack, target_depth);
    mix_in_length(&root, count)
}

#[timed]
pub fn hash_b256_vector(values: &[B256]) -> B256 {
    merkleize(values)
}

#[timed]
pub fn hash_uint64_vector(values: &[u64]) -> B256 {
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
    merkle_finalize(stack, target_depth)
}

/// hash_tree_root(ForkData(current_version, genesis_validators_root)).
/// 2-chunk container → single sha256 of the concatenated chunks (the
/// 4-byte version is right-zero-padded into a 32-byte chunk per SSZ).
#[timed]
pub fn hash_tree_root_fork_data(version: [u8; 4], genesis_validators_root: &B256) -> B256 {
    let mut version_chunk = [0u8; 32];
    version_chunk[..4].copy_from_slice(&version);
    hash_concat(&version_chunk, genesis_validators_root)
}

/// Compute hash_tree_root of a BeaconBlockBody from raw SSZ bytes.
/// Fulu layout: 13 fields → 16 leaves.
#[timed]
pub fn hash_tree_root_body(body: &[u8]) -> B256 {
    if body.len() < 396 {
        return ZERO_HASH;
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
    let execution_requests = hash_execution_requests(var_field(8));

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

    merkleize(&field_hashes)
}

#[timed]
pub fn hash_execution_requests(data: &[u8]) -> B256 {
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
pub fn hash_list_containers(
    data: &[u8],
    element_size: usize,
    limit: usize,
    hash_fn: fn(&[u8]) -> B256,
) -> B256 {
    if element_size == 0 {
        return mix_in_length(&ZERO_HASH, 0);
    }
    let count = data.len() / element_size;
    let target_depth = limit.next_power_of_two().trailing_zeros() as u8;

    let mut stack = MerkleStack::new();
    for i in 0..count {
        merkle_push(&mut stack, hash_fn(&data[i * element_size..(i + 1) * element_size]));
    }
    let root = merkle_finalize(stack, target_depth);
    mix_in_length(&root, count)
}

#[timed]
pub fn hash_list_variable_containers(
    data: &[u8],
    limit: usize,
    hash_fn: fn(&[u8]) -> B256,
) -> B256 {
    let target_depth = limit.next_power_of_two().trailing_zeros() as u8;
    if data.is_empty() {
        return mix_in_length(&merkle_finalize(MerkleStack::new(), target_depth), 0);
    }
    let first_offset = u32::from_le_bytes(data[0..4].try_into().unwrap_or([0; 4])) as usize;
    if first_offset == 0 || !first_offset.is_multiple_of(4) {
        return mix_in_length(&merkle_finalize(MerkleStack::new(), target_depth), 0);
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
        let elem =
            if start <= end && end <= data.len() { hash_fn(&data[start..end]) } else { ZERO_HASH };
        merkle_push(&mut stack, elem);
    }
    let root = merkle_finalize(stack, target_depth);
    mix_in_length(&root, count)
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
    let mut proof_stack = MerkleStack::new();
    for i in 0..33 {
        let chunk: B256 = d[i * 32..(i + 1) * 32].try_into().unwrap();
        merkle_push(&mut proof_stack, chunk);
    }
    let proof_root = merkle_finalize(proof_stack, 6);

    let dd: &[u8; 184] = d[1056..1240].try_into().unwrap();
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
/// selection_proof }`. 3-field container; the variable `aggregate`
/// is hashed via the internal `hash_attestation`.
#[timed]
pub fn hash_tree_root_aggregate_and_proof(
    aggregator_index: u64,
    aggregate: &[u8],
    selection_proof: &[u8; 96],
) -> B256 {
    let idx_root = uint64_chunk(aggregator_index);
    let agg_root = hash_attestation(aggregate);
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
    let max_indices: usize = 64 * 2048;
    let target_depth = max_indices.div_ceil(4).next_power_of_two().trailing_zeros() as u8;
    if d.len() < 228 {
        // Empty IA: zero attesting_indices, zero AttestationData, zero sig.
        let indices_root = mix_in_length(&ZERO_HASHES[target_depth as usize], 0);
        let data_root = hash_attestation_data(&[0u8; 128]);
        let sig_root = hash_fixed_bytes(&[0u8; 96]);
        return merkleize(&[indices_root, data_root, sig_root]);
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
    let indices_root = mix_in_length(&merkle_finalize(stack, target_depth), idx_count);

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

/// hash_tree_root for a Bitlist. Streams content bytes into 32-byte chunks,
/// masking the delimiter bit on the last content byte.
#[timed]
pub fn hash_bitlist(data: &[u8], bit_len: usize, max_bits: usize) -> B256 {
    let limit_chunks = max_bits.div_ceil(256).next_power_of_two();
    let target_depth = limit_chunks.trailing_zeros() as u8;
    if bit_len == 0 {
        return mix_in_length(&merkle_finalize(MerkleStack::new(), target_depth), 0);
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
    mix_in_length(&merkle_finalize(stack, target_depth), bit_len)
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

#[timed]
pub fn hash_list_fixed_elements(data: &[u8], element_size: usize, limit: usize) -> B256 {
    if element_size == 0 {
        return mix_in_length(&ZERO_HASH, 0);
    }
    let count = data.len() / element_size;
    let target_depth = limit.next_power_of_two().trailing_zeros() as u8;
    let mut stack = MerkleStack::new();
    for i in 0..count {
        let elem = &data[i * element_size..(i + 1) * element_size];
        merkle_push(&mut stack, hash_fixed_bytes(elem));
    }
    let root = merkle_finalize(stack, target_depth);
    mix_in_length(&root, count)
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
    let extra_data_root = {
        // ByteList[32] → max 1 chunk.
        let mut stack = MerkleStack::new();
        push_bytes_as_chunks(extra_data_bytes, &mut stack);
        let root = merkle_finalize(stack, 0);
        mix_in_length(&root, extra_data_bytes.len())
    };

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
    let outer_depth = MAX_TRANSACTIONS_PER_PAYLOAD.next_power_of_two().trailing_zeros() as u8;
    let tx_chunk_limit = MAX_BYTES_PER_TRANSACTION.div_ceil(32).next_power_of_two();
    let tx_chunk_depth = tx_chunk_limit.trailing_zeros() as u8;

    if data.is_empty() {
        return mix_in_length(&merkle_finalize(MerkleStack::new(), outer_depth), 0);
    }

    let first_off = u32::from_le_bytes(data[..4].try_into().unwrap_or([0; 4])) as usize;
    if first_off == 0 || !first_off.is_multiple_of(4) || first_off > data.len() {
        return mix_in_length(&merkle_finalize(MerkleStack::new(), outer_depth), 0);
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
        let tx_root = mix_in_length(&merkle_finalize(inner, tx_chunk_depth), tx_bytes.len());
        merkle_push(&mut outer, tx_root);
    }

    let root = merkle_finalize(outer, outer_depth);
    mix_in_length(&root, count)
}

/// hash_tree_root for List[Withdrawal, 16]. Withdrawal fixed 44 bytes.
#[timed]
pub fn hash_withdrawals(data: &[u8]) -> B256 {
    const WITHDRAWAL_SIZE: usize = 44;

    let count = data.len() / WITHDRAWAL_SIZE;
    let target_depth = MAX_WITHDRAWALS_PER_PAYLOAD.next_power_of_two().trailing_zeros() as u8;
    let mut stack = MerkleStack::new();
    for i in 0..count {
        let w = &data[i * WITHDRAWAL_SIZE..(i + 1) * WITHDRAWAL_SIZE];
        let u64at = |off: usize| -> u64 { u64::from_le_bytes(w[off..off + 8].try_into().unwrap()) };
        let mut addr = ZERO_HASH;
        addr[..20].copy_from_slice(&w[16..36]);
        let chunks =
            [uint64_chunk(u64at(0)), uint64_chunk(u64at(8)), addr, uint64_chunk(u64at(36))];
        merkle_push(&mut stack, merkleize(&chunks));
    }
    let root = merkle_finalize(stack, target_depth);
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

#[cfg(test)]
mod tests {
    use super::*;

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

    /// Anchor against the spec-published zero-subtree roots.
    #[test]
    fn zero_hashes_match_spec() {
        assert_eq!(ZERO_HASHES[0], [0u8; 32]);
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
            assert_eq!(ZERO_HASHES[i], hex_b32(hex), "zh[{i}]");
        }
    }

    /// The inline fast path must match the general stack-machine merkleize for
    /// every chunk count it handles (full power-of-two and padded alike).
    #[test]
    fn merkleize_inline_matches_stack_machine() {
        for n in 0..=40usize {
            let chunks: Vec<B256> = (0..n).map(|i| uint64_chunk(i as u64 + 1)).collect();
            let leaf_count = n.next_power_of_two().max(1);
            let expected = merkleize_padded(&chunks, leaf_count);
            assert_eq!(merkleize(&chunks), expected, "n={n}");
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
        ZERO_HASHES[i]
    }

    fn h(a: B256, b: B256) -> B256 {
        hash_concat(&a, &b)
    }

    #[test]
    fn spec_merkleize_vectors() {
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
            let result = merkleize_padded(&chunks, limit_pow2);
            assert_eq!(result, *expected, "case {i}: count={count} limit={limit}");
        }
    }

    /// Build a depth-D balanced Merkle tree over `leaves` (zero-padded to
    /// 2^D), returning (root, per-leaf-proof-bytes). Each proof is D*32 bytes
    /// of siblings ascending from leaf level.
    fn build_tree(leaves: &[B256], depth: u32) -> (B256, Vec<Vec<u8>>) {
        let cap = 1usize << depth;
        assert!(leaves.len() <= cap);
        let mut level: Vec<B256> = leaves.to_vec();
        level.resize(cap, ZERO_HASH);

        let mut layers: Vec<Vec<B256>> = Vec::with_capacity(depth as usize + 1);
        layers.push(level);
        for _ in 0..depth {
            let prev = layers.last().unwrap();
            let mut next = Vec::with_capacity(prev.len() / 2);
            for pair in prev.chunks_exact(2) {
                next.push(hash_concat(&pair[0], &pair[1]));
            }
            layers.push(next);
        }
        let root = layers.last().unwrap()[0];

        let mut proofs: Vec<Vec<u8>> = Vec::with_capacity(cap);
        for idx in 0..cap {
            let mut proof = Vec::with_capacity((depth as usize) * 32);
            for d in 0..depth as usize {
                let sib = (idx >> d) ^ 1;
                proof.extend_from_slice(&layers[d][sib]);
            }
            proofs.push(proof);
        }
        (root, proofs)
    }

    #[test]
    fn merkle_branch_valid_at_every_leaf() {
        let depth: u32 = 4;
        let cap = 1usize << depth;
        let leaves: Vec<B256> = (0..cap as u32).map(e).collect();
        let (root, proofs) = build_tree(&leaves, depth);
        for i in 0..cap {
            assert!(is_valid_merkle_branch(&leaves[i], &proofs[i], depth, i as u64, &root));
        }
    }

    #[test]
    fn merkle_branch_rejects_corrupted_proof() {
        let depth: u32 = 5;
        let leaves: Vec<B256> = (0..(1u32 << depth)).map(e).collect();
        let (root, proofs) = build_tree(&leaves, depth);
        let idx = 7usize;
        let mut bad = proofs[idx].clone();
        bad[0] ^= 0x01;
        assert!(!is_valid_merkle_branch(&leaves[idx], &bad, depth, idx as u64, &root));
    }

    #[test]
    fn merkle_branch_rejects_wrong_root() {
        let depth: u32 = 3;
        let leaves: Vec<B256> = (0..(1u32 << depth)).map(e).collect();
        let (mut root, proofs) = build_tree(&leaves, depth);
        let idx = 2usize;
        root[0] ^= 0xFF;
        assert!(!is_valid_merkle_branch(&leaves[idx], &proofs[idx], depth, idx as u64, &root));
    }

    #[test]
    fn merkle_branch_index_sensitive() {
        let depth: u32 = 3;
        let leaves: Vec<B256> = (0..(1u32 << depth)).map(e).collect();
        let (root, proofs) = build_tree(&leaves, depth);
        let idx = 3usize;
        assert!(is_valid_merkle_branch(&leaves[idx], &proofs[idx], depth, idx as u64, &root));
        assert!(!is_valid_merkle_branch(
            &leaves[idx],
            &proofs[idx],
            depth,
            (idx as u64) + 1,
            &root
        ));
    }

    #[test]
    fn merkle_branch_rejects_short_branch() {
        let depth: u32 = 4;
        let leaf = e(0);
        let branch = vec![0u8; (depth as usize - 1) * 32];
        assert!(!is_valid_merkle_branch(&leaf, &branch, depth, 0, &ZERO_HASH));
    }
}
