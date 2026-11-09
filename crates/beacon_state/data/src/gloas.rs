use std::{
    array::IntoIter as ArrayIntoIter,
    io::{self, Write},
    iter::Take,
    mem,
    ops::Deref,
};

use flux::type_hash_derive::TypeHash;
use silver_state_memory::RetainedVec;

use crate::{
    DecomposeError,
    decompose::common::{b256, u32_le, u64_le},
    types::{
        B256, BLSPubkey, Epoch, ExecutionAddress, FAR_FUTURE_EPOCH, MIN_SEED_LOOKAHEAD,
        SLOTS_PER_EPOCH, SLOTS_PER_HISTORICAL_ROOT, Slot, Version,
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

impl Builder {
    pub fn is_active(&self, finalized_epoch: Epoch) -> bool {
        self.deposit_epoch < finalized_epoch && self.withdrawable_epoch == FAR_FUTURE_EPOCH
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

    pub(crate) fn write_ssz<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(&self.weight.to_le_bytes())?;
        // BuilderPendingWithdrawal: fee_recipient(20) + amount(8) + builder_index(8)
        w.write_all(&self.withdrawal.fee_recipient)?;
        w.write_all(&self.withdrawal.amount.to_le_bytes())?;
        w.write_all(&self.withdrawal.builder_index.to_le_bytes())?;
        w.write_all(&self.proposer_index.to_le_bytes())
    }
}

#[derive(Clone, Copy, Debug, Default, TypeHash)]
pub struct Withdrawal {
    pub index: u64,
    pub validator_index: u64,
    pub address: ExecutionAddress,
    pub amount: u64,
}

#[derive(Clone, Copy, Debug, TypeHash)]
pub struct PayloadWithdrawals {
    items: [Withdrawal; MAX_WITHDRAWALS_PER_PAYLOAD],
    len: usize,
}

impl PayloadWithdrawals {
    pub fn new() -> Self {
        Self { items: [Withdrawal::default(); MAX_WITHDRAWALS_PER_PAYLOAD], len: 0 }
    }

    pub fn push(&mut self, withdrawal: Withdrawal) {
        self.items[self.len] = withdrawal;
        self.len += 1;
    }

    pub fn clear(&mut self) {
        self.len = 0;
    }
}

impl Default for PayloadWithdrawals {
    fn default() -> Self {
        Self::new()
    }
}

impl Deref for PayloadWithdrawals {
    type Target = [Withdrawal];

    fn deref(&self) -> &[Withdrawal] {
        &self.items[..self.len]
    }
}

impl IntoIterator for PayloadWithdrawals {
    type Item = Withdrawal;

    type IntoIter = Take<ArrayIntoIter<Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD>>;

    fn into_iter(self) -> Self::IntoIter {
        self.items.into_iter().take(self.len)
    }
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

    pub fn write_ssz<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(&self.index.to_le_bytes())?;
        w.write_all(&self.validator_index.to_le_bytes())?;
        w.write_all(&self.address)?;
        w.write_all(&self.amount.to_le_bytes())
    }
}

#[derive(Default)]
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
    pub blob_kzg_commitments: RetainedVec<[u8; 48]>,
    pub execution_requests_root: B256,
}

impl Clone for ExecutionPayloadBid {
    fn clone(&self) -> Self {
        Self { blob_kzg_commitments: self.blob_kzg_commitments.clone(), ..*self }
    }

    fn clone_from(&mut self, source: &Self) {
        self.blob_kzg_commitments.clone_from(&source.blob_kzg_commitments);
        let blob_kzg_commitments = mem::take(&mut self.blob_kzg_commitments);
        *self = Self { blob_kzg_commitments, ..*source };
    }
}

impl ExecutionPayloadBid {
    pub fn from_ssz(body: &[u8]) -> Result<Self, DecomposeError> {
        if body.len() < EXECUTION_PAYLOAD_BID_FIXED {
            return Err(DecomposeError::GloasFieldLen {
                field: "latest_execution_payload_bid",
                len: body.len(),
                size: EXECUTION_PAYLOAD_BID_FIXED,
            });
        }
        let off = u32_le(body, 188) as usize;
        if off != EXECUTION_PAYLOAD_BID_FIXED {
            return Err(DecomposeError::GloasOffset {
                field: "latest_execution_payload_bid",
                off,
                fixed: EXECUTION_PAYLOAD_BID_FIXED,
            });
        }
        let kzg = &body[off..];
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

    /// SSZ-serialised length: the 224-byte fixed part plus the variable
    /// `blob_kzg_commitments` list.
    pub(crate) fn ssz_len(&self) -> usize {
        EXECUTION_PAYLOAD_BID_FIXED + self.blob_kzg_commitments.len() * KZG_COMMITMENT_SSZ
    }

    /// SSZ-encode the bid (checkpoint encoding) — inverse of
    /// [`Self::from_ssz`]. `blob_kzg_commitments` is the sole variable
    /// field; its offset slot at byte 188 is the fixed-part size.
    pub fn write_ssz<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(&self.parent_block_hash)?; // [0..32]
        w.write_all(&self.parent_block_root)?; // [32..64]
        w.write_all(&self.block_hash)?; // [64..96]
        w.write_all(&self.prev_randao)?; // [96..128]
        w.write_all(&self.fee_recipient)?; // [128..148]
        w.write_all(&self.gas_limit.to_le_bytes())?; // [148..156]
        w.write_all(&self.builder_index.to_le_bytes())?; // [156..164]
        w.write_all(&self.slot.to_le_bytes())?; // [164..172]
        w.write_all(&self.value.to_le_bytes())?; // [172..180]
        w.write_all(&self.execution_payment.to_le_bytes())?; // [180..188]
        w.write_all(&(EXECUTION_PAYLOAD_BID_FIXED as u32).to_le_bytes())?; // [188..192] offset
        w.write_all(&self.execution_requests_root)?; // [192..224]
        for c in &self.blob_kzg_commitments {
            w.write_all(c)?;
        }
        Ok(())
    }

    /// The `SignedExecutionPayloadBid` of this bid and `signature`.
    pub fn write_signed_ssz(&self, signature: &[u8; 96], out: &mut Vec<u8>) {
        out.extend_from_slice(&((4 + signature.len()) as u32).to_le_bytes());
        out.extend_from_slice(signature);
        self.write_ssz(out).expect("writes to a Vec");
    }
}

#[cfg(test)]
mod tests {
    use super::{
        EXECUTION_PAYLOAD_BID_FIXED, ExecutionPayloadBid, KZG_COMMITMENT_SSZ,
        MAX_WITHDRAWALS_PER_PAYLOAD, PayloadWithdrawals, Withdrawal,
    };

    fn bid_with_offset(off: u32) -> Vec<u8> {
        let mut body = vec![0u8; EXECUTION_PAYLOAD_BID_FIXED + 2 * KZG_COMMITMENT_SSZ];
        body[188..192].copy_from_slice(&off.to_le_bytes());
        body[EXECUTION_PAYLOAD_BID_FIXED] = 0xAA;
        body
    }

    #[test]
    fn bid_decodes_its_commitments_after_the_fixed_part() {
        let bid = ExecutionPayloadBid::from_ssz(&bid_with_offset(224)).unwrap();
        assert_eq!(bid.blob_kzg_commitments.len(), 2);
        assert_eq!(bid.blob_kzg_commitments[0][0], 0xAA);
    }

    /// 999 is past the end; 128 lands inside the fixed part yet leaves a
    /// whole number of commitments, so only the exact offset is safe.
    #[test]
    fn bid_rejects_any_offset_but_the_fixed_part() {
        for off in [999, 128] {
            assert!(ExecutionPayloadBid::from_ssz(&bid_with_offset(off)).is_err(), "offset {off}");
        }
    }

    #[test]
    fn payload_withdrawals_owned_iteration_respects_length() {
        for len in [0, 1, MAX_WITHDRAWALS_PER_PAYLOAD] {
            let mut withdrawals = PayloadWithdrawals::new();
            for index in 1..=len as u64 {
                withdrawals.push(Withdrawal { index, ..Default::default() });
            }

            let indices: Vec<_> = withdrawals.into_iter().map(|w| w.index).collect();
            assert_eq!(indices, (1..=len as u64).collect::<Vec<_>>());
        }
    }

    #[test]
    fn payload_withdrawals_owned_iteration_excludes_cleared_entries() {
        let mut withdrawals = PayloadWithdrawals::new();
        withdrawals.push(Withdrawal { index: 1, ..Default::default() });
        withdrawals.push(Withdrawal { index: 2, ..Default::default() });
        withdrawals.clear();
        assert_eq!(withdrawals.into_iter().count(), 0);

        withdrawals.push(Withdrawal { index: 3, ..Default::default() });
        let indices: Vec<_> = withdrawals.into_iter().map(|w| w.index).collect();
        assert_eq!(indices, [3]);
    }
}
