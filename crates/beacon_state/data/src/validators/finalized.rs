use std::{
    convert::Infallible,
    io::{self, Write},
};

use blst::min_pk::PublicKey;
use flux_profiler::timed;
use parking_lot::RwLock;
use rustc_hash::FxHashMap;

use super::{hash_shape::VersionedFinalizedHash, validator_hash};
use crate::{
    Withdrawals,
    hash_tree::FinalizedHashTree,
    types::{BLSPubkey, Epoch, FAR_FUTURE_EPOCH, validator_capacity},
};

pub type PubkeyIndex = FxHashMap<BLSPubkey, u32>;

/// Initial values for one validator passed to
/// [`FinalizedValidators::with_validators`]. Test-fixture input (reaches other
/// crates' tests through `for_test`), hidden from the public API.
#[doc(hidden)]
pub struct ValSeed {
    pub pubkey: BLSPubkey,
    pub withdrawal_credentials: Withdrawals,
    pub effective_balance: u64,
    pub balance: u64,
    pub activation_epoch: Epoch,
    pub exit_epoch: Epoch,
}

impl Default for ValSeed {
    fn default() -> Self {
        Self {
            pubkey: [0u8; 48],
            withdrawal_credentials: Withdrawals::default(),
            effective_balance: 0,
            balance: 0,
            activation_epoch: FAR_FUTURE_EPOCH,
            exit_epoch: FAR_FUTURE_EPOCH,
        }
    }
}

/// Full per-validator field set, used only to construct or grow the finalized
/// base (SSZ decode, genesis seeds). The fork delta's [`AppendedValidator`] is
/// leaner — its mutable fields are always spec-defaults at append time.
pub(super) struct ValidatorInit {
    pub pubkey: BLSPubkey,
    pub pubkey_decompressed: PublicKey,
    pub credentials: Withdrawals,
    pub effective_balance: u64,
    pub slashed: bool,
    pub activation_eligibility_epoch: Epoch,
    pub activation_epoch: Epoch,
    pub exit_epoch: Epoch,
    pub withdrawable_epoch: Epoch,
}

/// SSZ-serialised size of a single `Validator` container (Fulu).
const VALIDATOR_SSZ_SIZE: usize = 121;

/// Byte offset of each field within a 121-byte SSZ `Validator` record. Fixed
/// layout, packed contiguously: `pubkey[48] | withdrawal_credentials[32] |
/// effective_balance:u64 | slashed:bool | 4 × epoch:u64`, ending at
/// [`VALIDATOR_SSZ_SIZE`]. Shared by the decode (`try_new`) and encode
/// (`write_ssz_range`) paths so the layout lives in one place.
mod offset {
    pub const PUBKEY: usize = 0;
    pub const CREDENTIALS: usize = 48;
    pub const EFFECTIVE_BALANCE: usize = 80;
    pub const SLASHED: usize = 88;
    pub const ACTIVATION_ELIGIBILITY_EPOCH: usize = 89;
    pub const ACTIVATION_EPOCH: usize = 97;
    pub const EXIT_EPOCH: usize = 105;
    pub const WITHDRAWABLE_EPOCH: usize = 113;
}

#[derive(Debug, thiserror::Error)]
pub enum ValidatorsDecodeError {
    #[error("validators bytes {len} not a multiple of {VALIDATOR_SSZ_SIZE}")]
    LenNotMultiple { len: usize },
    #[error("validator {idx} pubkey failed BLS decompression")]
    InvalidPubkey { idx: usize },
    #[error("pubkey sidecar count {sidecar} != validator count {validators}")]
    PubkeyCountMismatch { sidecar: usize, validators: usize },
    #[error("validator {idx} sidecar pubkey does not match the canonical compressed pubkey")]
    PubkeyMismatch { idx: usize },
}

#[inline]
fn u64_at(s: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(s[off..off + 8].try_into().unwrap())
}

#[inline]
fn put(buf: &mut [u8], off: usize, src: &[u8]) {
    buf[off..off + src.len()].copy_from_slice(src);
}

pub struct FinalizedValidators {
    pub(super) val_pubkey: Box<[BLSPubkey]>,
    pub(super) val_pubkey_decompressed: Box<[PublicKey]>,
    pub(super) val_withdrawal_credentials: Box<[Withdrawals]>,
    pub(super) effective_balance: Box<[u64]>,
    /// Bitset: validator `i` is slashed iff
    /// `slashed[i / 8] & (1 << (i % 8)) != 0`. Length = `capacity / 8`.
    pub(super) slashed: Box<[u8]>,
    pub(super) activation_eligibility_epoch: Box<[Epoch]>,
    pub(super) activation_epoch: Box<[Epoch]>,
    pub(super) exit_epoch: Box<[Epoch]>,
    pub(super) withdrawable_epoch: Box<[Epoch]>,
    pub(super) validator_count: usize,
    pub(super) index: RwLock<PubkeyIndex>,
    pub(super) hash: VersionedFinalizedHash,
}

impl FinalizedValidators {
    fn build<E>(
        capacity: usize,
        n: usize,
        mut field_at: impl FnMut(usize) -> Result<ValidatorInit, E>,
    ) -> Result<Self, E> {
        debug_assert!(n <= capacity);
        let mut val_pubkey = vec![[0u8; 48]; capacity].into_boxed_slice();
        let mut val_pubkey_decompressed = vec![PublicKey::default(); capacity].into_boxed_slice();
        let mut val_withdrawal_credentials =
            vec![Withdrawals::default(); capacity].into_boxed_slice();
        let mut effective_balance = vec![0u64; capacity].into_boxed_slice();
        let mut slashed = vec![0u8; capacity.div_ceil(8)].into_boxed_slice();
        let mut activation_eligibility_epoch = vec![FAR_FUTURE_EPOCH; capacity].into_boxed_slice();
        let mut activation_epoch = vec![FAR_FUTURE_EPOCH; capacity].into_boxed_slice();
        let mut exit_epoch = vec![FAR_FUTURE_EPOCH; capacity].into_boxed_slice();
        let mut withdrawable_epoch = vec![FAR_FUTURE_EPOCH; capacity].into_boxed_slice();
        let mut index = PubkeyIndex::with_capacity_and_hasher(n, Default::default());

        for i in 0..n {
            let f = field_at(i)?;
            val_pubkey[i] = f.pubkey;
            val_pubkey_decompressed[i] = f.pubkey_decompressed;
            val_withdrawal_credentials[i] = f.credentials;
            effective_balance[i] = f.effective_balance;
            if f.slashed {
                slashed[i / 8] |= 1u8 << (i % 8);
            }
            activation_eligibility_epoch[i] = f.activation_eligibility_epoch;
            activation_epoch[i] = f.activation_epoch;
            exit_epoch[i] = f.exit_epoch;
            withdrawable_epoch[i] = f.withdrawable_epoch;
            index.insert(f.pubkey, i as u32);
        }

        let hash = VersionedFinalizedHash::Fulu(FinalizedHashTree::from_leaves(
            (0..n).map(|i| {
                validator_hash(
                    &val_pubkey[i],
                    &val_withdrawal_credentials[i],
                    effective_balance[i],
                    slashed[i / 8] & (1 << (i % 8)) != 0,
                    activation_eligibility_epoch[i],
                    activation_epoch[i],
                    exit_epoch[i],
                    withdrawable_epoch[i],
                )
            }),
            capacity,
        ));

        Ok(Self {
            val_pubkey,
            val_pubkey_decompressed,
            val_withdrawal_credentials,
            effective_balance,
            slashed,
            activation_eligibility_epoch,
            activation_epoch,
            exit_epoch,
            withdrawable_epoch,
            validator_count: n,
            index: RwLock::new(index),
            hash,
        })
    }
}

impl FinalizedValidators {
    /// Decode the SSZ `validators` byte range (layout per [`offset`]); capacity
    /// is derived from the count, and `try_new(&[], None)` is the empty base.
    /// With `Some(decompressed)`, each sidecar key is bound to its record's
    /// canonical compressed pubkey; with `None`, pubkeys are decompressed from
    /// the records (which rejects non-canonical points).
    #[timed]
    pub fn try_new(
        val_bytes: &[u8],
        decompressed: Option<&[PublicKey]>,
    ) -> Result<Self, ValidatorsDecodeError> {
        if !val_bytes.len().is_multiple_of(VALIDATOR_SSZ_SIZE) {
            return Err(ValidatorsDecodeError::LenNotMultiple { len: val_bytes.len() });
        }
        let n = val_bytes.len() / VALIDATOR_SSZ_SIZE;
        if let Some(d) = decompressed {
            if d.len() != n {
                return Err(ValidatorsDecodeError::PubkeyCountMismatch {
                    sidecar: d.len(),
                    validators: n,
                });
            }
        }

        Self::build(validator_capacity(n), n, |i| {
            let v = &val_bytes[i * VALIDATOR_SSZ_SIZE..];
            let pubkey: BLSPubkey = v[offset::PUBKEY..offset::CREDENTIALS].try_into().unwrap();
            let pubkey_decompressed = match decompressed {
                Some(d) if d[i].compress() != pubkey => {
                    return Err(ValidatorsDecodeError::PubkeyMismatch { idx: i });
                }
                Some(d) => d[i],
                None => PublicKey::from_bytes(&pubkey)
                    .map_err(|_| ValidatorsDecodeError::InvalidPubkey { idx: i })?,
            };
            Ok(ValidatorInit {
                pubkey,
                pubkey_decompressed,
                credentials: Withdrawals(
                    v[offset::CREDENTIALS..offset::EFFECTIVE_BALANCE].try_into().unwrap(),
                ),
                effective_balance: u64_at(v, offset::EFFECTIVE_BALANCE),
                slashed: v[offset::SLASHED] != 0,
                activation_eligibility_epoch: u64_at(v, offset::ACTIVATION_ELIGIBILITY_EPOCH),
                activation_epoch: u64_at(v, offset::ACTIVATION_EPOCH),
                exit_epoch: u64_at(v, offset::EXIT_EPOCH),
                withdrawable_epoch: u64_at(v, offset::WITHDRAWABLE_EPOCH),
            })
        })
    }

    #[inline]
    /// SSZ-encode validators `[start, end)` (one 121-B record each) — the
    /// checkpoint persist's section body, called in bounded slices.
    pub(crate) fn write_ssz_range<W: Write>(
        &self,
        start: usize,
        end: usize,
        w: &mut W,
    ) -> io::Result<()> {
        let mut buf = [0u8; VALIDATOR_SSZ_SIZE];
        for i in start..end {
            put(&mut buf, offset::PUBKEY, &self.val_pubkey[i]);
            put(&mut buf, offset::CREDENTIALS, &self.val_withdrawal_credentials[i].0);
            put(&mut buf, offset::EFFECTIVE_BALANCE, &self.effective_balance[i].to_le_bytes());
            buf[offset::SLASHED] = self.is_slashed(i) as u8;
            let elig = self.activation_eligibility_epoch[i].to_le_bytes();
            put(&mut buf, offset::ACTIVATION_ELIGIBILITY_EPOCH, &elig);
            put(&mut buf, offset::ACTIVATION_EPOCH, &self.activation_epoch[i].to_le_bytes());
            put(&mut buf, offset::EXIT_EPOCH, &self.exit_epoch[i].to_le_bytes());
            put(&mut buf, offset::WITHDRAWABLE_EPOCH, &self.withdrawable_epoch[i].to_le_bytes());
            w.write_all(&buf)?;
        }
        Ok(())
    }

    /// Write the decompressed (96-B serialized) pubkeys `[start, end)` — the
    /// checkpoint sidecar's body, called in bounded slices.
    pub(crate) fn write_pubkeys_range<W: Write>(
        &self,
        start: usize,
        end: usize,
        w: &mut W,
    ) -> io::Result<()> {
        for i in start..end {
            w.write_all(&self.val_pubkey_decompressed[i].serialize())?;
        }
        Ok(())
    }

    pub fn validator_count(&self) -> usize {
        self.validator_count
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.val_pubkey.len()
    }

    /// `slashed` is a bitset (validator `i` at bit `i % 8` of byte `i / 8`), so
    /// it keeps a reader rather than callers open-coding the mask. Every other
    /// column is read directly through its `pub(super)` field.
    #[inline]
    pub(super) fn is_slashed(&self, i: usize) -> bool {
        self.slashed[i / 8] & (1u8 << (i % 8)) != 0
    }

    #[inline]
    pub fn find_by_pubkey(&self, pubkey: &BLSPubkey) -> Option<usize> {
        self.index.read().get(pubkey).map(|&idx| idx as usize)
    }

    /// Number of entries in the pubkey → idx index. Should equal
    /// `validator_count` post-`decompose` / `promote_into_base`.
    #[inline]
    pub fn index_len(&self) -> usize {
        self.index.read().len()
    }

    #[inline]
    pub(super) fn hash(&self) -> &VersionedFinalizedHash {
        &self.hash
    }

    /// Harness-seeding constructor: builds a registry from `ValSeed`s whose
    /// pubkeys need not be valid BLS points (decompression falls back to
    /// default), which `try_new` would reject. Crate-internal test use only —
    /// the one bridge from test seeds to the private `build`; reached from
    /// other crates' tests only through `for_test`.
    pub(crate) fn with_validators(seeds: &[ValSeed]) -> Self {
        Self::build(validator_capacity(seeds.len()), seeds.len(), |i| {
            let s = &seeds[i];
            Ok::<_, Infallible>(ValidatorInit {
                pubkey: s.pubkey,
                pubkey_decompressed: PublicKey::from_bytes(&s.pubkey).unwrap_or_default(),
                credentials: s.withdrawal_credentials,
                effective_balance: s.effective_balance,
                slashed: false,
                activation_eligibility_epoch: FAR_FUTURE_EPOCH,
                activation_epoch: s.activation_epoch,
                exit_epoch: s.exit_epoch,
                withdrawable_epoch: FAR_FUTURE_EPOCH,
            })
        })
        .unwrap()
    }
}
