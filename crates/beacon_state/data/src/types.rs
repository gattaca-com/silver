use crate::{
    BalancesId, BuildersId, CurrentParticipationId, DecomposeError, EpochId, Eth1Id, InactivityId,
    LongtailId, PendingId, PreviousParticipationId, SlotStateId, ValidatorsId,
    decompose::common::{b256, u32_le, u64_le},
    gloas::{
        BUILDER_PENDING_PAYMENTS_LEN, BuilderPendingPayment, BuilderPendingWithdrawal,
        EXECUTION_PAYLOAD_AVAILABILITY_BYTES, ExecutionPayloadBid, GLOAS_FORK_VERSION, Withdrawal,
    },
};

const EPH_FIXED_PART: usize = 584;

// Epoch-tier (`EpochStateFinalized`/`EpochStateDelta`) and longtail-tier
// (`LongtailState`) types live in the `epoch`/`longtail` group modules; the
// immutable block rides `BeaconState.immutable` directly.

pub type B256 = [u8; 32];
pub type BLSPubkey = [u8; 48];
pub type BLSSignature = [u8; 96];
pub type Slot = u64;
pub type Epoch = u64;
pub type Version = [u8; 4];
pub type ExecutionAddress = [u8; 20];

pub const VALIDATOR_REGISTRY_LIMIT: usize = 1 << 40;

pub const MIN_VALIDATOR_HEADROOM: usize = 64 * 1024;

pub fn validator_capacity(count: usize) -> usize {
    let headroom = (count / 5).max(MIN_VALIDATOR_HEADROOM);
    count + headroom
}

/// SSZ spec sentinel for "not yet activated / exited / withdrawable".
pub const FAR_FUTURE_EPOCH: Epoch = u64::MAX;
pub const SLOTS_PER_HISTORICAL_ROOT: usize = 8192;
pub const EPOCHS_PER_HISTORICAL_VECTOR: usize = 65536;
pub const EPOCHS_PER_SLASHINGS_VECTOR: usize = 8192;
/// In-memory cap for the `historical_summaries` list. Mainnet grows by 1 entry
/// per 256 epochs (~27h); 8192 covers ~25 years.
pub const HISTORICAL_SUMMARIES_CAP: usize = 8192;
pub const HISTORICAL_ROOTS_LIMIT: usize = 1 << 24;

pub const PENDING_DEPOSITS_LIMIT: usize = 1 << 27;
pub const PENDING_PARTIAL_WITHDRAWALS_LIMIT: usize = 1 << 27;
pub const PENDING_CONSOLIDATIONS_LIMIT: usize = 1 << 18;

pub const SLOTS_PER_EPOCH: u64 = 32;
pub const SYNC_COMMITTEE_SIZE: usize = 512;
pub const MAX_ETH1_VOTES: usize = 2048;
pub const MIN_SEED_LOOKAHEAD: u64 = 1;
pub const PROPOSER_LOOKAHEAD_SIZE: usize =
    (MIN_SEED_LOOKAHEAD as usize + 1) * SLOTS_PER_EPOCH as usize;
pub const BYTES_PER_LOGS_BLOOM: usize = 256;
pub const MAX_EXTRA_DATA_BYTES: usize = 32;

// Finalize reanchors by fresh roll, so a ring must hold the old ids plus one
// fresh slot per distinct survivor at once — sized for forks crossing a
// rotation / epoch boundary under delayed finality, not just the steady state.
pub const LONGTAILS_RING_N: usize = 8;
pub const EPOCHS_RING_N: usize = 16;
/// Bounds the number of simultaneously live forks; sizes the per-tier rings.
pub const SLOTS_RING_N: usize = 256;

// No `Default`: a bundle must not exist before its per-tier
// entries do — ids surface only from a writer's `commit`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct StateId {
    pub epoch_idx: Option<EpochId>,
    pub longtail_idx: Option<LongtailId>,
    /// Per-tier ring seqs this fork reads (balances and below). Unlike
    /// `epoch_idx`/`longtail_idx`, these tiers change every slot, so they are
    /// always present — set by whoever rolls the fork (mirrors how `epoch_idx`
    /// is set at an epoch boundary).
    pub balances_idx: BalancesId,
    pub eth1_idx: Eth1Id,
    pub validators_idx: ValidatorsId,
    pub pending_idx: PendingId,
    pub previous_participation_idx: PreviousParticipationId,
    pub current_participation_idx: CurrentParticipationId,
    pub inactivity_idx: InactivityId,
    pub slot_idx: SlotStateId,
    /// Empty until the Gloas fork.
    pub builders_idx: BuildersId,
}

// size: ~5.5 KB of plain data — the vote list lives in its own tier
// ([`crate::Eth1Group`]).
#[derive(Clone)]
pub struct SlotState {
    pub randao_mix_current: B256,
    pub current_epoch_slashings: u64,
    pub eth1_data: Eth1Data,
    pub eth1_deposit_index: u64,
    pub slot: Slot,
    pub latest_block_header: BeaconBlockHeader,
    pub latest_execution_payload_header: ExecutionPayloadHeader,
    pub next_withdrawal_index: u64,
    pub next_withdrawal_validator_index: u64,
    pub deposit_requests_start_index: u64,
    pub exit_balance_to_consume: u64,
    pub earliest_exit_epoch: Epoch,
    pub consolidation_balance_to_consume: u64,
    pub earliest_consolidation_epoch: Epoch,

    // [New in Gloas]
    pub latest_block_hash: B256,
    pub next_withdrawal_builder_index: u64,
    pub execution_payload_availability: [u8; EXECUTION_PAYLOAD_AVAILABILITY_BYTES],
    pub builder_pending_payments: [BuilderPendingPayment; BUILDER_PENDING_PAYMENTS_LEN],
    pub builder_pending_withdrawals: Vec<BuilderPendingWithdrawal>,
    pub latest_execution_payload_bid: ExecutionPayloadBid,
    pub payload_expected_withdrawals: Vec<Withdrawal>,
}

impl Default for SlotState {
    fn default() -> Self {
        Self {
            randao_mix_current: B256::default(),
            current_epoch_slashings: 0,
            eth1_data: Eth1Data::default(),
            eth1_deposit_index: 0,
            slot: 0,
            latest_block_header: BeaconBlockHeader::default(),
            latest_execution_payload_header: ExecutionPayloadHeader::default(),
            next_withdrawal_index: 0,
            next_withdrawal_validator_index: 0,
            deposit_requests_start_index: 0,
            exit_balance_to_consume: 0,
            earliest_exit_epoch: 0,
            consolidation_balance_to_consume: 0,
            earliest_consolidation_epoch: 0,
            latest_block_hash: B256::default(),
            next_withdrawal_builder_index: 0,
            execution_payload_availability: [0u8; EXECUTION_PAYLOAD_AVAILABILITY_BYTES],
            builder_pending_payments: [BuilderPendingPayment::default();
                BUILDER_PENDING_PAYMENTS_LEN],
            builder_pending_withdrawals: Vec::new(),
            latest_execution_payload_bid: ExecutionPayloadBid::default(),
            payload_expected_withdrawals: Vec::new(),
        }
    }
}

#[derive(Clone, Copy)]
pub struct EpochState {
    pub proposer_lookahead: [u64; PROPOSER_LOOKAHEAD_SIZE],
    pub justification_bits: u8,
    pub previous_justified_checkpoint: Checkpoint,
    pub current_justified_checkpoint: Checkpoint,
    pub finalized_checkpoint: Checkpoint,
    pub deposit_balance_to_consume: u64,
}

impl Default for EpochState {
    fn default() -> Self {
        Self {
            proposer_lookahead: [0u64; PROPOSER_LOOKAHEAD_SIZE],
            justification_bits: Default::default(),
            previous_justified_checkpoint: Default::default(),
            current_justified_checkpoint: Default::default(),
            finalized_checkpoint: Default::default(),
            deposit_balance_to_consume: Default::default(),
        }
    }
}

// Spec parallel SSZ lists (`previous/current_epoch_participation`,
// `inactivity_scores`; `balances` lives in the `balances` module). Each is its
// own `List[T, VALIDATOR_REGISTRY_LIMIT]`
// in the BeaconState and will eventually carry its own hash tree (not yet
// implemented). Length is whatever the validators layer reports; reading
// past `base_count` with no edit returns the spec default (0 / false).

#[derive(Clone)]
pub struct Immutable {
    pub genesis_time: u64,
    pub genesis_validators_root: B256,
    /// Frozen since Capella (appends go to `historical_summaries`); kept raw
    /// for checkpoint re-encoding alongside the precomputed list hash below.
    pub historical_roots: Box<[B256]>,
    pub historical_roots_hash: B256,
    pub fork: Fork,
    pub genesis_fork_version: Version,
    pub capella_fork_version: Version,
    pub gloas_fork_version: Version,
}

impl Default for Immutable {
    fn default() -> Self {
        Self {
            genesis_time: 0,
            genesis_validators_root: B256::default(),
            historical_roots: Box::default(),
            historical_roots_hash: B256::default(),
            fork: Fork::default(),
            genesis_fork_version: Version::default(),
            capella_fork_version: Version::default(),
            gloas_fork_version: GLOAS_FORK_VERSION,
        }
    }
}

impl Immutable {
    /// `(fork_epoch, previous_version, current_version,
    /// genesis_validators_root)` — the four inputs every BLS signing-root
    /// needs together.
    #[inline]
    pub fn fork_descriptor(&self) -> (Epoch, [u8; 4], [u8; 4], B256) {
        let f = &self.fork;
        (f.epoch, f.previous_version, f.current_version, self.genesis_validators_root)
    }

    #[inline]
    pub fn fork_version_at(&self, block_epoch: Epoch) -> ([u8; 4], B256) {
        let fv = if block_epoch >= self.fork.epoch {
            self.fork.current_version
        } else {
            self.fork.previous_version
        };
        (fv, self.genesis_validators_root)
    }
}

#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub epoch: Epoch,
    pub root: B256,
}

#[derive(Clone, Copy, Default)]
pub struct Fork {
    pub previous_version: Version,
    pub current_version: Version,
    pub epoch: Epoch,
}

#[derive(Clone, Copy, Default)]
pub struct Eth1Data {
    pub deposit_root: B256,
    pub deposit_count: u64,
    pub block_hash: B256,
}

impl Eth1Data {
    pub(crate) fn from_ssz(s: &[u8]) -> Self {
        Self { deposit_root: b256(s, 0), deposit_count: u64_le(s, 32), block_hash: b256(s, 40) }
    }
}

#[derive(Clone, Copy, Default, Debug)]
pub struct BeaconBlockHeader {
    pub slot: Slot,
    pub proposer_index: u64,
    pub parent_root: B256,
    pub state_root: B256,
    pub body_root: B256,
}

impl BeaconBlockHeader {
    pub(crate) fn from_ssz(s: &[u8]) -> Self {
        Self {
            slot: u64_le(s, 0),
            proposer_index: u64_le(s, 8),
            parent_root: b256(s, 16),
            state_root: b256(s, 48),
            body_root: b256(s, 80),
        }
    }
}

#[derive(Clone, Copy)]
pub struct ExecutionPayloadHeader {
    pub parent_hash: B256,
    pub fee_recipient: ExecutionAddress,
    pub state_root: B256,
    pub receipts_root: B256,
    pub logs_bloom: [u8; BYTES_PER_LOGS_BLOOM],
    pub prev_randao: B256,
    pub block_number: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub timestamp: u64,
    pub extra_data_len: u8,
    pub extra_data: [u8; MAX_EXTRA_DATA_BYTES],
    pub base_fee_per_gas: [u8; 32],
    pub block_hash: B256,
    pub transactions_root: B256,
    pub withdrawals_root: B256,
    pub blob_gas_used: u64,
    pub excess_blob_gas: u64,
}

impl Default for ExecutionPayloadHeader {
    fn default() -> Self {
        Self {
            parent_hash: Default::default(),
            fee_recipient: Default::default(),
            state_root: Default::default(),
            receipts_root: Default::default(),
            logs_bloom: [0u8; BYTES_PER_LOGS_BLOOM],
            prev_randao: Default::default(),
            block_number: Default::default(),
            gas_limit: Default::default(),
            gas_used: Default::default(),
            timestamp: Default::default(),
            extra_data_len: Default::default(),
            extra_data: Default::default(),
            base_fee_per_gas: Default::default(),
            block_hash: Default::default(),
            transactions_root: Default::default(),
            withdrawals_root: Default::default(),
            blob_gas_used: Default::default(),
            excess_blob_gas: Default::default(),
        }
    }
}

impl ExecutionPayloadHeader {
    pub(crate) fn from_ssz(eph: &[u8]) -> Result<Self, DecomposeError> {
        if eph.len() < EPH_FIXED_PART {
            return Err(DecomposeError::EphTruncated { len: eph.len(), need: EPH_FIXED_PART });
        }

        let mut out = Self {
            parent_hash: b256(eph, 0),
            state_root: b256(eph, 52),
            receipts_root: b256(eph, 84),
            prev_randao: b256(eph, 372),
            block_number: u64_le(eph, 404),
            gas_limit: u64_le(eph, 412),
            gas_used: u64_le(eph, 420),
            timestamp: u64_le(eph, 428),
            base_fee_per_gas: b256(eph, 440),
            block_hash: b256(eph, 472),
            transactions_root: b256(eph, 504),
            withdrawals_root: b256(eph, 536),
            blob_gas_used: u64_le(eph, 568),
            excess_blob_gas: u64_le(eph, 576),
            ..Default::default()
        };
        out.fee_recipient.copy_from_slice(&eph[32..52]);
        out.logs_bloom.copy_from_slice(&eph[116..372]);

        let extra_off = u32_le(eph, 436) as usize;
        if extra_off < EPH_FIXED_PART || extra_off > eph.len() {
            return Err(DecomposeError::EphExtraDataOffsetInvalid {
                off: extra_off,
                fixed: EPH_FIXED_PART,
                len: eph.len(),
            });
        }
        let extra_len = eph.len() - extra_off;
        if extra_len > 32 {
            return Err(DecomposeError::EphExtraDataTooLong { len: extra_len });
        }
        out.extra_data_len = extra_len as u8;
        out.extra_data[..extra_len].copy_from_slice(&eph[extra_off..]);

        Ok(out)
    }
}

#[derive(Clone, Copy)]
pub struct PendingDeposit {
    pub pubkey: BLSPubkey,
    pub withdrawal_credentials: Withdrawals,
    pub amount: u64,
    pub signature: BLSSignature,
    pub slot: Slot,
}

#[derive(Clone, Copy, Default)]
pub struct PendingPartialWithdrawal {
    pub index: u64,
    pub amount: u64,
    pub withdrawable_epoch: Epoch,
}

#[derive(Clone, Copy, Default)]
pub struct PendingConsolidation {
    pub source_index: u64,
    pub target_index: u64,
}

#[derive(Clone, Copy, Default)]
pub struct HistoricalSummary {
    pub block_summary_root: B256,
    pub state_summary_root: B256,
}

// size: ~24 KB (48 B × 512 + 48 B)
#[derive(Clone, Copy)]
pub struct SyncCommittee {
    pub pubkeys: [BLSPubkey; SYNC_COMMITTEE_SIZE],
    pub aggregate_pubkey: BLSPubkey,
}

impl Default for SyncCommittee {
    fn default() -> Self {
        Self { pubkeys: [[0u8; 48]; SYNC_COMMITTEE_SIZE], aggregate_pubkey: [0u8; 48] }
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub struct Withdrawals(pub B256);

impl Withdrawals {
    pub const ZERO: Self = Self([0u8; 32]);
    pub const ETH1_ADDRESS_PREFIX: u8 = 0x01;
    pub const COMPOUNDING_PREFIX: u8 = 0x02;
    /// Gloas (EIP-7732) `BUILDER_WITHDRAWAL_PREFIX`.
    pub const BUILDER_PREFIX: u8 = 0x03;

    /// Build eth1-prefixed credentials (`0x01 || 11 zero bytes || addr`).
    #[inline]
    pub fn eth1(execution_address: &[u8; 20]) -> Self {
        let mut bytes = [0u8; 32];
        bytes[0] = Self::ETH1_ADDRESS_PREFIX;
        bytes[12..32].copy_from_slice(execution_address);
        Self(bytes)
    }

    #[inline]
    pub fn prefix(&self) -> u8 {
        self.0[0]
    }

    #[inline]
    pub fn has_eth1_credential(&self) -> bool {
        self.prefix() == Self::ETH1_ADDRESS_PREFIX
    }

    #[inline]
    pub fn has_compounding_credential(&self) -> bool {
        self.prefix() == Self::COMPOUNDING_PREFIX
    }

    #[inline]
    pub fn has_builder_credential(&self) -> bool {
        self.prefix() == Self::BUILDER_PREFIX
    }

    #[inline]
    pub fn has_execution_credential(&self) -> bool {
        self.has_eth1_credential() || self.has_compounding_credential()
    }

    /// Bytes [12..32] — the 20-byte execution address for `0x01` / `0x02`.
    #[inline]
    pub fn execution_address(&self) -> &[u8; 20] {
        (&self.0[12..32]).try_into().unwrap()
    }

    /// Spec MAX_EFFECTIVE_BALANCE depends on credential type: compounding
    /// caps at 2048 ETH, eth1/bls cap at 32 ETH.
    #[inline]
    pub fn max_effective_balance(&self) -> u64 {
        const MIN_ACTIVATION_BALANCE: u64 = 32_000_000_000;
        const MAX_EFFECTIVE_BALANCE_COMPOUNDING: u64 = 2048 * 1_000_000_000;
        if self.has_compounding_credential() {
            MAX_EFFECTIVE_BALANCE_COMPOUNDING
        } else {
            MIN_ACTIVATION_BALANCE
        }
    }
}

/// A sparse column's SSZ byte length disagrees with the expected registry
/// count — surfaced by the column constructors so construction = validation.
#[derive(Debug, thiserror::Error)]
#[error("column bytes {bytes} don't match expected count {expected}")]
pub struct ColumnLenMismatch {
    pub bytes: usize,
    pub expected: usize,
}
