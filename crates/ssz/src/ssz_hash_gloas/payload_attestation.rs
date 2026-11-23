use crate::{
    merkle::{B256, FixedContainer, hash_fixed_bytes, merkleize, uint64_chunk},
    progressive::{ProgressiveContainer, packed_active_fields},
    ssz_view::{
        PAYLOAD_ATTESTATION_DATA_SIZE, PAYLOAD_ATTESTATION_SIZE, PTC_AGGREGATION_BITS_SIZE,
        PayloadAttestationDataView, PayloadAttestationView,
    },
};

impl ProgressiveContainer for PayloadAttestationView {
    const ACTIVE_FIELDS: B256 = packed_active_fields(3);
}

impl FixedContainer for PayloadAttestationView {
    const SSZ_SIZE: usize = PAYLOAD_ATTESTATION_SIZE;

    /// aggregation_bits(Bitvector[PTC_SIZE]) + data(42B) + signature(96B).
    fn hash_tree_root(d: &[u8]) -> B256 {
        const DATA_END: usize = PTC_AGGREGATION_BITS_SIZE + PAYLOAD_ATTESTATION_DATA_SIZE;
        let aggregation_bits = hash_fixed_bytes(&d[..PTC_AGGREGATION_BITS_SIZE]);
        let data =
            PayloadAttestationDataView::hash_tree_root(&d[PTC_AGGREGATION_BITS_SIZE..DATA_END]);
        let signature = hash_fixed_bytes(&d[DATA_END..PAYLOAD_ATTESTATION_SIZE]);
        Self::progressive_root(&[aggregation_bits, data, signature])
    }
}

impl PayloadAttestationDataView {
    /// Plain Container: beacon_block_root(32) + slot(8) + payload_present(bool)
    /// + blob_data_available(bool).
    pub fn hash_tree_root(d: &[u8]) -> B256 {
        let bool_chunk = |b: u8| {
            let mut c = [0u8; 32];
            c[0] = b;
            c
        };
        merkleize(&[
            d[0..32].try_into().unwrap(),
            uint64_chunk(u64::from_le_bytes(d[32..40].try_into().unwrap())),
            bool_chunk(d[40]),
            bool_chunk(d[41]),
        ])
    }
}
