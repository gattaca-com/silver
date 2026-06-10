use crate::{
    BalancesId, CurrentParticipationId, EpochId, InactivityId, LongtailId, PendingId,
    PreviousParticipationId, SlotStateId, ValidatorsId,
};

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

pub const LONGTAILS_RING_N: usize = 2;
pub const EPOCHS_RING_N: usize = 8;
/// Bounds the number of simultaneously live forks; sizes the per-tier rings.
pub const SLOTS_RING_N: usize = 256;

// size: ~72 B. No `Default`: a bundle must not exist before its per-tier
// entries do — ids surface only from a writer's `commit`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct StateId {
    pub epoch_idx: Option<EpochId>,
    pub longtail_idx: Option<LongtailId>,
    /// Balances ring seq this fork reads. Unlike `epoch_idx`/`longtail_idx`,
    /// balances change every slot, so this is always present — set by whoever
    /// rolls the fork (mirrors how `epoch_idx` is set at an epoch boundary).
    pub balances_idx: BalancesId,
    /// Validators ring seq this fork reads — always present, rolled every slot
    /// like `balances_idx`.
    pub validators_idx: ValidatorsId,
    /// Pending + participation + inactivity ring seqs this fork reads — always
    /// present, rolled every slot like `balances_idx`.
    pub pending_idx: PendingId,
    pub previous_participation_idx: PreviousParticipationId,
    pub current_participation_idx: CurrentParticipationId,
    pub inactivity_idx: InactivityId,
    pub slot_idx: SlotStateId,
}

// size: ~1 KB. `eth1_votes` is a heap-backed `Vec` (bounded at MAX_ETH1_VOTES
// on push, reset each voting period) rather than an inline 144 KB ArrayVec, so
// `SlotState` is no longer `Copy` — it lives in its own ring
// (`SlotStateGroup`), is mutated in place through the write view, and
// value-copying it (ring fill, `from_ssz` returns, `promote`) must not cost a
// 144 KB stack frame. See [`crate::slot_state`]; `eth1_votes` is write-path +
// checkpoint-persist only, never read on the seqlock path, so the heap buffer
// is safe there.
#[derive(Default)]
pub struct SlotState {
    pub randao_mix_current: B256,
    pub current_epoch_slashings: u64,
    pub eth1_data: Eth1Data,
    pub eth1_votes: Vec<Eth1Data>,
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
}

// Manual Clone: the derived impl would leave `clone_from` at its default
// (`*self = src.clone()`), replacing the `eth1_votes` heap allocation. The
// checkpoint persist reads the finalized base's `eth1_votes` cross-thread and
// relies on `promote` keeping that allocation stable, so `clone_from` must
// reuse it (`Vec::clone_from` does, given reserved capacity).
impl Clone for SlotState {
    fn clone(&self) -> Self {
        let mut new = Self::default();
        new.clone_from(self);
        new
    }

    fn clone_from(&mut self, src: &Self) {
        self.randao_mix_current = src.randao_mix_current;
        self.current_epoch_slashings = src.current_epoch_slashings;
        self.eth1_data = src.eth1_data;
        self.eth1_votes.clone_from(&src.eth1_votes);
        self.eth1_deposit_index = src.eth1_deposit_index;
        self.slot = src.slot;
        self.latest_block_header = src.latest_block_header;
        self.latest_execution_payload_header = src.latest_execution_payload_header;
        self.next_withdrawal_index = src.next_withdrawal_index;
        self.next_withdrawal_validator_index = src.next_withdrawal_validator_index;
        self.deposit_requests_start_index = src.deposit_requests_start_index;
        self.exit_balance_to_consume = src.exit_balance_to_consume;
        self.earliest_exit_epoch = src.earliest_exit_epoch;
        self.consolidation_balance_to_consume = src.consolidation_balance_to_consume;
        self.earliest_consolidation_epoch = src.earliest_consolidation_epoch;
    }
}

// size: ~648 B (proposer_lookahead 512 + 3 × Checkpoint 120 + scalars + pad)
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

// size: ~120 B inline + the frozen historical_roots heap block
#[derive(Clone, Default)]
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

// size: ~40 B
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub epoch: Epoch,
    pub root: B256,
}

// size: ~16 B
#[derive(Clone, Copy, Default)]
pub struct Fork {
    pub previous_version: Version,
    pub current_version: Version,
    pub epoch: Epoch,
}

// size: ~72 B
#[derive(Clone, Copy, Default)]
pub struct Eth1Data {
    pub deposit_root: B256,
    pub deposit_count: u64,
    pub block_hash: B256,
}

// size: ~112 B
#[derive(Clone, Copy, Default, Debug)]
pub struct BeaconBlockHeader {
    pub slot: Slot,
    pub proposer_index: u64,
    pub parent_root: B256,
    pub state_root: B256,
    pub body_root: B256,
}

// size: ~616 B (logs_bloom 256 + base_fee 32 + roots/hashes)
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

// size: ~192 B (sig 96 + pubkey 48 + creds 32 + 2 × u64)
#[derive(Clone, Copy)]
pub struct PendingDeposit {
    pub pubkey: BLSPubkey,
    pub withdrawal_credentials: Withdrawals,
    pub amount: u64,
    pub signature: BLSSignature,
    pub slot: Slot,
}

// size: ~24 B
#[derive(Clone, Copy, Default)]
pub struct PendingPartialWithdrawal {
    pub index: u64,
    pub amount: u64,
    pub withdrawable_epoch: Epoch,
}

// size: ~16 B
#[derive(Clone, Copy, Default)]
pub struct PendingConsolidation {
    pub source_index: u64,
    pub target_index: u64,
}

// size: ~64 B
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

// size: ~32 B
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub struct Withdrawals(pub B256);

impl Withdrawals {
    pub const ZERO: Self = Self([0u8; 32]);
    pub const ETH1_ADDRESS_PREFIX: u8 = 0x01;
    pub const COMPOUNDING_PREFIX: u8 = 0x02;

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
