use silver_common::ssz_view::{BeaconBlockBodyFuluView, SignedBeaconBlockView};

const SYNC_COMMITTEE_BITS_BYTES: usize = 512 / 8;

/// Two STF cost drivers on mainnet: attestation count, sync-committee
/// participation.
#[derive(Debug, Clone, Copy, Default)]
pub struct BlockWorkload {
    pub slot: u64,
    pub attestations: usize,
    pub sync_bits_set: usize,
}

impl BlockWorkload {
    pub fn from_block_ssz(block: &[u8]) -> Self {
        let body = SignedBeaconBlockView::body(block);
        let attestations_offset = BeaconBlockBodyFuluView::attestations_offset(body) as usize;
        let deposits_offset = BeaconBlockBodyFuluView::deposits_offset(body) as usize;
        let sync = BeaconBlockBodyFuluView::sync_aggregate(body);
        Self {
            slot: SignedBeaconBlockView::slot(block),
            attestations: ssz_list_len(body, attestations_offset, deposits_offset),
            sync_bits_set: sync
                .get(..SYNC_COMMITTEE_BITS_BYTES)
                .map(|bs| bs.iter().map(|b| b.count_ones() as usize).sum())
                .unwrap_or(0),
        }
    }
}

/// `/ 4`: the front offset table is `u32`-wide and points past itself, so
/// the first entry divided by 4 is the element count.
fn ssz_list_len(body: &[u8], start: usize, end: usize) -> usize {
    if end <= start + 4 || end > body.len() {
        return 0;
    }
    let first = u32::from_le_bytes(body[start..start + 4].try_into().unwrap()) as usize;
    if first == 0 { 0 } else { first / 4 }
}
