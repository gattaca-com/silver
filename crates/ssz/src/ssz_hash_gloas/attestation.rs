use flux_profiler::timed;

use crate::{
    merkle::{
        B256, ZERO_HASH, bitlist_len, hash_bitlist, hash_concat, hash_fixed_bytes,
        hash_uint64_list, mix_in_length,
    },
    progressive::{ProgressiveContainer, ProgressiveHasher, packed_active_fields},
    ssz_hash::hash_attestation_data,
    ssz_view::{AttestationView, AttesterSlashingView, IndexedAttestationView},
};

impl ProgressiveContainer for AttestationView {
    const ACTIVE_FIELDS: B256 = packed_active_fields(4);
}

impl AttestationView {
    /// Gloas `Attestation` with `aggregation_bits: ProgressiveBitlist`. Byte
    /// layout identical to the fulu [`crate::ssz_hash::hash_attestation`].
    #[timed]
    pub fn hash_tree_root_gloas(d: &[u8]) -> B256 {
        if d.len() < 236 {
            return ZERO_HASH;
        }
        Self::hash_tree_root_gloas_with_data_root(d, hash_attestation_data(&d[4..132]))
    }

    pub(crate) fn hash_tree_root_gloas_with_data_root(d: &[u8], data_root: B256) -> B256 {
        debug_assert_eq!(data_root, hash_attestation_data(&d[4..132]));
        let agg_off = u32::from_le_bytes(d[0..4].try_into().unwrap()) as usize;
        let agg_bits = if agg_off <= d.len() { &d[agg_off..] } else { &[] };

        let bit_len = bitlist_len(agg_bits);
        let agg_root = hash_bitlist(ProgressiveHasher::new(), agg_bits, bit_len);

        let sig_root = hash_fixed_bytes(&d[132..228]);
        let mut cb = ZERO_HASH;
        cb[..8].copy_from_slice(&d[228..236]);

        Self::progressive_root(&[agg_root, data_root, sig_root, cb])
    }
}

impl ProgressiveContainer for IndexedAttestationView {
    const ACTIVE_FIELDS: B256 = packed_active_fields(3);
}

impl IndexedAttestationView {
    /// Gloas `IndexedAttestation` with `attesting_indices:
    /// ProgressiveList[uint64]`.
    #[timed]
    pub fn hash_tree_root_gloas(d: &[u8]) -> B256 {
        if d.len() < 228 {
            // Empty IA: zero attesting_indices, zero AttestationData, zero sig.
            let indices_root = mix_in_length(&ZERO_HASH, 0);
            let data_root = hash_attestation_data(&[0u8; 128]);
            let sig_root = hash_fixed_bytes(&[0u8; 96]);
            return Self::progressive_root(&[indices_root, data_root, sig_root]);
        }
        let indices_off = u32::from_le_bytes(d[0..4].try_into().unwrap()) as usize;
        let indices_data = if indices_off <= d.len() { &d[indices_off..] } else { &[] };
        let idx_count = indices_data.len() / 8;

        let indices_root = hash_uint64_list(ProgressiveHasher::new(), indices_data, idx_count);

        let data_root = hash_attestation_data(&d[4..132]);
        let sig_root = hash_fixed_bytes(&d[132..228]);
        Self::progressive_root(&[indices_root, data_root, sig_root])
    }
}

impl AttesterSlashingView {
    /// Plain Container; only its two inner IndexedAttestations are progressive.
    #[timed]
    pub fn hash_tree_root_gloas(d: &[u8]) -> B256 {
        if d.len() < 8 {
            let empty_ia = IndexedAttestationView::hash_tree_root_gloas(&[]);
            return hash_concat(&empty_ia, &empty_ia);
        }
        let off1 = u32::from_le_bytes(d[0..4].try_into().unwrap()) as usize;
        let off2 = u32::from_le_bytes(d[4..8].try_into().unwrap()) as usize;
        let ia1 = if off1 <= off2 && off2 <= d.len() { &d[off1..off2] } else { &[] };
        let ia2 = if off2 <= d.len() { &d[off2..] } else { &[] };
        hash_concat(
            &IndexedAttestationView::hash_tree_root_gloas(ia1),
            &IndexedAttestationView::hash_tree_root_gloas(ia2),
        )
    }
}
