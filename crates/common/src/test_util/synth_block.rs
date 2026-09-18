use crate::{
    merkle::B256,
    ssz_view::{
        BEACON_BLOCK_BODY_FIXED, EXECUTION_PAYLOAD_BID_MIN, EXECUTION_PAYLOAD_FIXED,
        SIGNED_BEACON_BLOCK_MIN, SIGNED_EXECUTION_PAYLOAD_BID_MIN,
    },
};

const MESSAGE_AT: usize = 100;
const SIGNED_BID_PREFIX: usize = SIGNED_EXECUTION_PAYLOAD_BID_MIN - EXECUTION_PAYLOAD_BID_MIN;

fn write_offset(buf: &mut [u8], at: usize, offset: usize) {
    buf[at..at + 4].copy_from_slice(&(offset as u32).to_le_bytes());
}

/// `ExecutionPayloadBid` bytes: a zeroed fixed prefix, then
/// `blob_kzg_commitments`. Setters name the fields a test cares about.
pub struct SynthBid(Vec<u8>);

impl SynthBid {
    pub fn new(commitments: &[u8]) -> Self {
        let mut bid = vec![0u8; EXECUTION_PAYLOAD_BID_MIN + commitments.len()];
        write_offset(&mut bid, 188, EXECUTION_PAYLOAD_BID_MIN);
        bid[EXECUTION_PAYLOAD_BID_MIN..].copy_from_slice(commitments);
        Self(bid)
    }

    pub fn parent_block_hash(mut self, hash: B256) -> Self {
        self.0[0..32].copy_from_slice(&hash);
        self
    }

    pub fn block_hash(mut self, hash: B256) -> Self {
        self.0[64..96].copy_from_slice(&hash);
        self
    }

    pub fn prev_randao(mut self, randao: B256) -> Self {
        self.0[96..128].copy_from_slice(&randao);
        self
    }

    pub fn gas_limit(mut self, limit: u64) -> Self {
        self.0[148..156].copy_from_slice(&limit.to_le_bytes());
        self
    }

    pub fn builder_index(mut self, index: u64) -> Self {
        self.0[156..164].copy_from_slice(&index.to_le_bytes());
        self
    }

    fn signed(self) -> Vec<u8> {
        let mut signed = vec![0u8; SIGNED_BID_PREFIX];
        write_offset(&mut signed, 0, SIGNED_BID_PREFIX);
        signed.extend_from_slice(&self.0);
        signed
    }
}

/// `SignedBeaconBlock` bytes for layout-level tests: every field zero but the
/// ones set here, so a `body_root` and its inclusion proof stay
/// self-consistent with the encoded commitments.
pub struct SynthBlock(Vec<u8>);

impl SynthBlock {
    pub fn fulu(slot: u64, commitments: &[u8]) -> Self {
        Self::around(slot, &fulu_body(commitments))
    }

    pub fn gloas(slot: u64, bid: SynthBid) -> Self {
        Self::around(slot, &gloas_body(bid))
    }

    pub fn parent_root(mut self, root: B256) -> Self {
        self.0[116..148].copy_from_slice(&root);
        self
    }

    pub fn body(&self) -> &[u8] {
        &self.0[SIGNED_BEACON_BLOCK_MIN..]
    }

    pub fn bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    fn around(slot: u64, body: &[u8]) -> Self {
        let mut block = vec![0u8; SIGNED_BEACON_BLOCK_MIN];
        write_offset(&mut block, 0, MESSAGE_AT);
        block[100..108].copy_from_slice(&slot.to_le_bytes());
        write_offset(&mut block, 180, SIGNED_BEACON_BLOCK_MIN - MESSAGE_AT);
        block.extend_from_slice(body);
        Self(block)
    }
}

/// Empty operation lists, a payload holding only its fixed prefix (itself with
/// empty `extra_data`, `transactions` and `withdrawals`), then the commitments.
fn fulu_body(commitments: &[u8]) -> Vec<u8> {
    const FIXED: usize = BEACON_BLOCK_BODY_FIXED;
    let payload_end = FIXED + EXECUTION_PAYLOAD_FIXED;
    let mut body = vec![0u8; payload_end + commitments.len()];
    let body_end = body.len();
    for at in [200usize, 204, 208, 212, 216, 380] {
        write_offset(&mut body, at, FIXED);
    }
    for at in [384usize, 388] {
        write_offset(&mut body, at, payload_end);
    }
    write_offset(&mut body, 392, body_end);
    for at in [436usize, 504, 508] {
        write_offset(&mut body, FIXED + at, EXECUTION_PAYLOAD_FIXED);
    }
    body[payload_end..].copy_from_slice(commitments);
    body
}

/// Empty operation lists, then the signed bid as the only populated field.
fn gloas_body(bid: SynthBid) -> Vec<u8> {
    const FIXED: usize = BEACON_BLOCK_BODY_FIXED;
    let signed_bid = bid.signed();
    let mut body = vec![0u8; FIXED + signed_bid.len()];
    let body_end = body.len();
    for at in [200usize, 204, 208, 212, 216, 380, 384] {
        write_offset(&mut body, at, FIXED);
    }
    for at in [388usize, 392] {
        write_offset(&mut body, at, body_end);
    }
    body[FIXED..].copy_from_slice(&signed_bid);
    body
}
