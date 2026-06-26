use crate::{
    DecomposeError,
    decompose::common::{b256, u32_le, u64_le},
    types::{
        B256, BLSPubkey, Epoch, ExecutionAddress, Immutable, MIN_SEED_LOOKAHEAD, SLOTS_PER_EPOCH,
        SLOTS_PER_HISTORICAL_ROOT, Slot, Version,
    },
};

const EXECUTION_PAYLOAD_BID_FIXED: usize = 224;
const KZG_COMMITMENT_SSZ: usize = 48;

pub const GLOAS_FORK_VERSION: Version = [0x07, 0, 0, 0];
pub const PTC_SIZE: usize = 512;
pub const PTC_WINDOW_LEN: usize = (2 + MIN_SEED_LOOKAHEAD as usize) * SLOTS_PER_EPOCH as usize;
pub const BUILDER_PENDING_PAYMENTS_LEN: usize = 2 * SLOTS_PER_EPOCH as usize;
pub const BUILDER_REGISTRY_LIMIT: usize = 1 << 40;
const MIN_BUILDER_HEADROOM: usize = 64;

pub fn builder_capacity(count: usize) -> usize {
    count + (count / 5).max(MIN_BUILDER_HEADROOM)
}
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

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Builder {
    pub pubkey: BLSPubkey,
    pub version: u8,
    pub execution_address: ExecutionAddress,
    pub balance: u64,
    pub deposit_epoch: Epoch,
    pub withdrawable_epoch: Epoch,
}

impl Default for Builder {
    fn default() -> Self {
        Self {
            pubkey: [0u8; 48],
            version: 0,
            execution_address: ExecutionAddress::default(),
            balance: 0,
            deposit_epoch: 0,
            withdrawable_epoch: 0,
        }
    }
}

#[derive(Clone, Copy, Default)]
pub struct BuilderPendingWithdrawal {
    pub fee_recipient: ExecutionAddress,
    pub amount: u64,
    pub builder_index: u64,
}

impl BuilderPendingWithdrawal {
    pub(crate) fn from_ssz(s: &[u8]) -> Self {
        Self {
            fee_recipient: s[0..20].try_into().unwrap(),
            amount: u64_le(s, 20),
            builder_index: u64_le(s, 28),
        }
    }
}

#[derive(Clone, Copy, Default)]
pub struct BuilderPendingPayment {
    pub weight: u64,
    pub withdrawal: BuilderPendingWithdrawal,
    pub proposer_index: u64,
}

impl BuilderPendingPayment {
    pub(crate) fn from_ssz(s: &[u8]) -> Self {
        Self {
            weight: u64_le(s, 0),
            withdrawal: BuilderPendingWithdrawal::from_ssz(&s[8..]),
            proposer_index: u64_le(s, 44),
        }
    }
}

#[derive(Clone, Copy, Default)]
pub struct Withdrawal {
    pub index: u64,
    pub validator_index: u64,
    pub address: ExecutionAddress,
    pub amount: u64,
}

impl Withdrawal {
    pub(crate) fn from_ssz(s: &[u8]) -> Self {
        Self {
            index: u64_le(s, 0),
            validator_index: u64_le(s, 8),
            address: s[16..36].try_into().unwrap(),
            amount: u64_le(s, 36),
        }
    }
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

impl ExecutionPayloadBid {
    pub(crate) fn from_ssz(body: &[u8]) -> Result<Self, DecomposeError> {
        if body.len() < EXECUTION_PAYLOAD_BID_FIXED {
            return Err(DecomposeError::GloasFieldLen {
                field: "latest_execution_payload_bid",
                len: body.len(),
                size: EXECUTION_PAYLOAD_BID_FIXED,
            });
        }
        let kzg = &body[u32_le(body, 188) as usize..];
        if !kzg.len().is_multiple_of(KZG_COMMITMENT_SSZ) {
            return Err(DecomposeError::GloasFieldLen {
                field: "blob_kzg_commitments",
                len: kzg.len(),
                size: KZG_COMMITMENT_SSZ,
            });
        }
        let count = kzg.len() / KZG_COMMITMENT_SSZ;
        if count > MAX_BLOB_COMMITMENTS_PER_BLOCK {
            return Err(DecomposeError::GloasTooMany {
                field: "blob_kzg_commitments",
                n: count,
                max: MAX_BLOB_COMMITMENTS_PER_BLOCK,
            });
        }
        Ok(Self {
            parent_block_hash: b256(body, 0),
            parent_block_root: b256(body, 32),
            block_hash: b256(body, 64),
            prev_randao: b256(body, 96),
            fee_recipient: body[128..148].try_into().unwrap(),
            gas_limit: u64_le(body, 148),
            builder_index: u64_le(body, 156),
            slot: u64_le(body, 164),
            value: u64_le(body, 172),
            execution_payment: u64_le(body, 180),
            blob_kzg_commitments: (0..count)
                .map(|i| {
                    let o = i * KZG_COMMITMENT_SSZ;
                    kzg[o..o + 48].try_into().unwrap()
                })
                .collect(),
            execution_requests_root: b256(body, 192),
        })
    }
}
