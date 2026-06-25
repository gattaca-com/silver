use crate::types::{
    B256, BLSPubkey, Epoch, ExecutionAddress, Immutable, MIN_SEED_LOOKAHEAD, SLOTS_PER_EPOCH,
    SLOTS_PER_HISTORICAL_ROOT, Slot, Version,
};

pub const GLOAS_FORK_VERSION: Version = [0x07, 0, 0, 0];
pub const PTC_SIZE: usize = 512;
pub const PTC_WINDOW_LEN: usize = (2 + MIN_SEED_LOOKAHEAD as usize) * SLOTS_PER_EPOCH as usize;
pub const BUILDER_PENDING_PAYMENTS_LEN: usize = 2 * SLOTS_PER_EPOCH as usize;
pub const BUILDER_REGISTRY_LIMIT: usize = 1 << 40;
pub const BUILDER_PENDING_WITHDRAWALS_LIMIT: usize = 1 << 20;
pub const MAX_BLOB_COMMITMENTS_PER_BLOCK: usize = 4096;
pub const MAX_WITHDRAWALS_PER_PAYLOAD: usize = 16;

/// `execution_payload_availability: Bitvector[SLOTS_PER_HISTORICAL_ROOT]`.
pub const EXECUTION_PAYLOAD_AVAILABILITY_BYTES: usize = SLOTS_PER_HISTORICAL_ROOT / 8;

/// One PTC committee: `Vector[ValidatorIndex, PTC_SIZE]`.
pub type PtcCommittee = [u64; PTC_SIZE];

/// All-zero `ptc_window`, allocated flat on the heap and reinterpreted. Both
/// `Box::new([[..]; ..])` (393 KB stack temp) and `vec![[0u64; PTC_SIZE]; ..]`
/// (a `PTC_SIZE`-wide 4 KB stack element temp) put a wide array on the stack —
/// enough, layered under `decompose_gloas`, to overflow a test thread.
pub fn zeroed_ptc_window() -> Box<[PtcCommittee; PTC_WINDOW_LEN]> {
    let flat: Box<[u64]> = vec![0u64; PTC_SIZE * PTC_WINDOW_LEN].into_boxed_slice();
    // SAFETY: `[[u64; PTC_SIZE]; PTC_WINDOW_LEN]` is layout-identical to the
    // flat `[u64; PTC_SIZE * PTC_WINDOW_LEN]` (row-major, no padding), and the
    // length matches.
    unsafe { Box::from_raw(Box::into_raw(flat) as *mut [PtcCommittee; PTC_WINDOW_LEN]) }
}

impl Immutable {
    #[inline]
    pub fn is_gloas(&self) -> bool {
        self.fork.current_version == self.gloas_fork_version
    }
}

#[derive(Clone)]
pub struct Builder {
    pub pubkey: BLSPubkey,
    pub version: u8,
    pub execution_address: ExecutionAddress,
    pub balance: u64,
    pub deposit_epoch: Epoch,
    pub withdrawable_epoch: Epoch,
}

#[derive(Clone, Copy, Default)]
pub struct BuilderPendingWithdrawal {
    pub fee_recipient: ExecutionAddress,
    pub amount: u64,
    pub builder_index: u64,
}

#[derive(Clone, Copy, Default)]
pub struct BuilderPendingPayment {
    pub weight: u64,
    pub withdrawal: BuilderPendingWithdrawal,
    pub proposer_index: u64,
}

#[derive(Clone, Copy, Default)]
pub struct Withdrawal {
    pub index: u64,
    pub validator_index: u64,
    pub address: ExecutionAddress,
    pub amount: u64,
}

#[derive(Clone, Default)]
pub struct ExecutionPayloadBid {
    pub parent_block_hash: B256,
    pub parent_block_root: B256,
    pub block_hash: B256,
    pub prev_randao: B256,
    pub fee_recipient: ExecutionAddress,
    pub gas_limit: u64,
    pub builder_index: u64,
    pub slot: Slot,
    pub value: u64,
    pub execution_payment: u64,
    /// `List[KZGCommitment, MAX_BLOB_COMMITMENTS_PER_BLOCK]`.
    pub blob_kzg_commitments: Vec<[u8; 48]>,
    pub execution_requests_root: B256,
}
