use flux_profiler::timed;

use crate::{
    merkle::{
        B256, MerkleStack, ZERO_HASH, bitlist_len, hash_bitlist, hash_concat, hash_fixed_bytes,
        merkleize, merkleize_bytes, mix_in_length, uint64_chunk,
    },
    ssz_view::AttestationView,
};

#[timed]
pub fn hash_attestation(d: &[u8]) -> B256 {
    if d.len() < 236 {
        return ZERO_HASH;
    }
    let agg_off = u32::from_le_bytes(d[0..4].try_into().unwrap()) as usize;
    let agg_bits = if agg_off <= d.len() { &d[agg_off..] } else { &[] };

    let max_bits: usize = 64 * 2048;
    let bit_len = bitlist_len(agg_bits);
    let agg_root = hash_bitlist(
        MerkleStack::new(max_bits.div_ceil(256).next_power_of_two()),
        agg_bits,
        bit_len,
    );

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
    let agg_root = if is_gloas {
        AttestationView::hash_tree_root_gloas(aggregate)
    } else {
        hash_attestation(aggregate)
    };
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
