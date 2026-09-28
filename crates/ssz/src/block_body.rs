use crate::ssz_view::{BEACON_BLOCK_BODY_FIXED, BLOCK_SYNC_AGGREGATE_SIZE};

/// Zero participation bits and the G2 point at infinity.
pub const EMPTY_SYNC_AGGREGATE: [u8; BLOCK_SYNC_AGGREGATE_SIZE] = {
    let mut aggregate = [0; BLOCK_SYNC_AGGREGATE_SIZE];
    aggregate[64] = 0xc0;
    aggregate
};

pub struct BeaconBlockBodyFulu<'a> {
    pub randao_reveal: &'a [u8; 96],
    pub eth1_data: &'a [u8; 72],
    pub graffiti: &'a [u8; 32],
    pub proposer_slashings: &'a [u8],
    pub attester_slashings: &'a [u8],
    pub attestations: &'a [u8],
    pub deposits: &'a [u8],
    pub voluntary_exits: &'a [u8],
    pub sync_aggregate: &'a [u8; BLOCK_SYNC_AGGREGATE_SIZE],
    pub execution_payload: &'a [u8],
    pub bls_to_execution_changes: &'a [u8],
    pub blob_kzg_commitments: &'a [u8],
    pub execution_requests: &'a [u8],
}

impl BeaconBlockBodyFulu<'_> {
    fn variable_fields(&self) -> [&[u8]; 9] {
        [
            self.proposer_slashings,
            self.attester_slashings,
            self.attestations,
            self.deposits,
            self.voluntary_exits,
            self.execution_payload,
            self.bls_to_execution_changes,
            self.blob_kzg_commitments,
            self.execution_requests,
        ]
    }

    pub fn ssz_len(&self) -> usize {
        BEACON_BLOCK_BODY_FIXED +
            self.variable_fields().iter().map(|field| field.len()).sum::<usize>()
    }

    /// `out` is exactly [`Self::ssz_len`] bytes.
    pub fn encode(&self, out: &mut [u8]) {
        debug_assert_eq!(out.len(), self.ssz_len());
        let fields = self.variable_fields();
        let mut offsets = [0u32; 9];
        let mut at = BEACON_BLOCK_BODY_FIXED;
        for (offset, field) in offsets.iter_mut().zip(fields) {
            *offset = at as u32;
            out[at..at + field.len()].copy_from_slice(field);
            at += field.len();
        }

        let (fixed, _) = out.split_at_mut(BEACON_BLOCK_BODY_FIXED);
        let mut cursor = 0;
        let mut put = |bytes: &[u8]| {
            fixed[cursor..cursor + bytes.len()].copy_from_slice(bytes);
            cursor += bytes.len();
        };
        put(self.randao_reveal);
        put(self.eth1_data);
        put(self.graffiti);
        for offset in &offsets[..5] {
            put(&offset.to_le_bytes());
        }
        put(self.sync_aggregate);
        for offset in &offsets[5..] {
            put(&offset.to_le_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssz_view::{BeaconBlockBodyFuluView, EXECUTION_PAYLOAD_FIXED};

    /// Extra data, transactions and withdrawals all empty.
    fn empty_payload() -> [u8; EXECUTION_PAYLOAD_FIXED] {
        let mut payload = [0; EXECUTION_PAYLOAD_FIXED];
        for at in [436, 504, 508] {
            payload[at..at + 4].copy_from_slice(&(EXECUTION_PAYLOAD_FIXED as u32).to_le_bytes());
        }
        payload
    }

    #[test]
    fn empty_operations_body_passes_the_canonical_check() {
        let payload = empty_payload();
        let body = BeaconBlockBodyFulu {
            randao_reveal: &[1; 96],
            eth1_data: &[2; 72],
            graffiti: &[3; 32],
            proposer_slashings: &[],
            attester_slashings: &[],
            attestations: &[],
            deposits: &[],
            voluntary_exits: &[],
            sync_aggregate: &EMPTY_SYNC_AGGREGATE,
            execution_payload: &payload,
            bls_to_execution_changes: &[],
            blob_kzg_commitments: &[4; 48],
            execution_requests: &12u32.to_le_bytes().repeat(3),
        };
        let mut out = vec![0; body.ssz_len()];
        body.encode(&mut out);

        assert_eq!(BeaconBlockBodyFuluView::graffiti(&out), &[3; 32]);
        assert_eq!(BeaconBlockBodyFuluView::sync_aggregate(&out), &EMPTY_SYNC_AGGREGATE);
        assert!(BeaconBlockBodyFuluView::check_canonical(&out));
    }
}
