use blst::min_pk::PublicKey;
use flux::utils::ArrayVec;
use rustc_hash::FxHashMap;

pub type B256 = [u8; 32];
pub type BLSPubkey = [u8; 48];
pub type BLSSignature = [u8; 96];
pub type Slot = u64;
pub type Epoch = u64;
pub type Version = [u8; 4];
pub type ExecutionAddress = [u8; 20];

pub const SLOTS_PER_EPOCH: u64 = 32;
pub const SYNC_COMMITTEE_SIZE: usize = 512;
pub const MAX_ETH1_VOTES: usize = 2048;
pub const MIN_SEED_LOOKAHEAD: u64 = 1;
pub const PROPOSER_LOOKAHEAD_SIZE: usize =
    (MIN_SEED_LOOKAHEAD as usize + 1) * SLOTS_PER_EPOCH as usize;
pub const BYTES_PER_LOGS_BLOOM: usize = 256;
pub const MAX_EXTRA_DATA_BYTES: usize = 32;

pub struct Finalised {
    pub immutable: Immutable,
    pub longtail: LongtailState,
    pub pending: PendingQueues,
    pub validators: Validators,
    pub epoch: EpochState,
    pub slot: SlotState,
}

#[derive(Clone, Default)]
pub struct StateDelta {
    pub epoch_idx: Option<u32>,
    pub longtail_idx: Option<u32>,
    pub pending: PendingQueuesDelta,
    pub validators: ValidatorsDelta,
    pub slot: SlotState,
}

#[derive(Clone, Default)]
pub struct SlotState {
    pub randao_mix_current: B256,
    pub current_epoch_slashings: u64,
    pub eth1_data: Eth1Data,
    pub eth1_votes: ArrayVec<Eth1Data, MAX_ETH1_VOTES>,
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
    // For deltas: appended root since finalisation
    // For finalised: last SLOTS_PER_HISTORICAL_ROOT (8192) (circular buffer indexed by
    // `slot % HR`)
    pub block_roots: Vec<B256>,
    pub state_roots: Vec<B256>,
}

#[derive(Clone)]
pub struct EpochState {
    // For deltas: appended
    // For finalised: last EPOCHS_PER_HISTORICAL_VECTOR (circular buffer indexed by `epoch % HV`)
    pub randao_mixes: Vec<B256>,
    // For deltas: one entry per completed epoch since finalisation
    // For finalised: last EPOCHS_PER_SLASHINGS_VECTOR (circular buffer indexed by `epoch % SV`)
    pub slashings: Vec<u64>,
    pub proposer_lookahead: [u64; PROPOSER_LOOKAHEAD_SIZE],
    pub justification_bits: u8,
    pub previous_justified_checkpoint: Checkpoint,
    pub current_justified_checkpoint: Checkpoint,
    pub finalized_checkpoint: Checkpoint,
    pub deposit_balance_to_consume: u64,
}

#[derive(Clone)]
pub struct LongtailState {
    pub current_sync_committee: SyncCommittee,
    pub next_sync_committee: SyncCommittee,
    pub sync_committee_indices: [u32; SYNC_COMMITTEE_SIZE],
    // For deltas: entries appended since finalisation
    // For finalised: full list
    pub historical_summaries: Vec<HistoricalSummary>,
}

#[derive(Clone, Default)]
pub struct PendingQueues {
    pub pending_deposits: Vec<PendingDeposit>,
    pub pending_partial_withdrawals: Vec<PendingPartialWithdrawal>,
    pub pending_consolidations: Vec<PendingConsolidation>,
}

/// Per-fork delta on `PendingQueues`. Each queue: drop the first
/// `drain_offset` entries of the base, then read the remainder followed by
/// `appended`.
#[derive(Clone, Default)]
pub struct PendingQueuesDelta {
    pub deposits_drain_offset: u32,
    pub deposits_appended: Vec<PendingDeposit>,
    pub partial_withdrawals_drain_offset: u32,
    pub partial_withdrawals_appended: Vec<PendingPartialWithdrawal>,
    pub consolidations_drain_offset: u32,
    pub consolidations_appended: Vec<PendingConsolidation>,
}

pub struct ValidatorsData {
    pub val_pubkey: Vec<BLSPubkey>,
    pub val_pubkey_decompressed: Vec<PublicKey>,
    pub val_withdrawal_credentials: Vec<Withdrawals>,
    pub balances: Vec<u64>,
    pub current_epoch_participation: Vec<u8>,
    pub previous_epoch_participation: Vec<u8>,
    pub effective_balance: Vec<u64>,
    pub activation_epoch: Vec<Epoch>,
    pub exit_epoch: Vec<Epoch>,
    pub activation_eligibility_epoch: Vec<Epoch>,
    pub withdrawable_epoch: Vec<Epoch>,
    pub inactivity_scores: Vec<u64>,
    pub slashed: Vec<bool>,
}

pub type PubkeyIndex = FxHashMap<BLSPubkey, u32>;

pub struct Validators {
    pub data: ValidatorsData,
    pub index: PubkeyIndex,
}

#[derive(Clone)]
pub struct AppendedValidator {
    pub pubkey: BLSPubkey,
    pub pubkey_decompressed: PublicKey,
    pub credentials: Withdrawals,
}

#[derive(Clone, Copy, Default)]
pub struct Immutable {
    pub genesis_time: u64,
    pub genesis_validators_root: B256,
    pub historical_roots_hash: B256,
    pub fork: Fork,
    pub genesis_fork_version: Version,
    pub capella_fork_version: Version,
}

/// Per-fork delta on top of the finalized base. `appended[p]`'s absolute
/// validator index is `base_cnt + p`; the `_edits` vectors are sparse,
/// keyed by absolute validator index.
#[derive(Default, Clone)]
pub struct ValidatorsDelta {
    pub base_cnt: usize,
    pub appended: Vec<AppendedValidator>,
    pub credentials_edits: Vec<(u32, Withdrawals)>,
    pub balance_edits: Vec<(u32, u64)>,
    pub current_participation_edits: Vec<(u32, u8)>,
    pub previous_participation_edits: Vec<(u32, u8)>,
    pub effective_balance_edits: Vec<(u32, u64)>,
    pub activation_epoch_edits: Vec<(u32, Epoch)>,
    pub exit_epoch_edits: Vec<(u32, Epoch)>,
    pub activation_eligibility_epoch_edits: Vec<(u32, Epoch)>,
    pub withdrawable_epoch_edits: Vec<(u32, Epoch)>,
    pub slashed_edits: Vec<(u32, bool)>,
    pub inactivity_score_edits: Vec<(u32, u64)>,
}

impl ValidatorsDelta {
    pub fn new_at(base_cnt: usize) -> Self {
        Self { base_cnt, ..Self::default() }
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

#[derive(Clone, Copy, Default, Debug)]
pub struct BeaconBlockHeader {
    pub slot: Slot,
    pub proposer_index: u64,
    pub parent_root: B256,
    pub state_root: B256,
    pub body_root: B256,
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

#[derive(Clone, Copy)]
pub struct SyncCommittee {
    pub pubkeys: [BLSPubkey; SYNC_COMMITTEE_SIZE],
    pub aggregate_pubkey: BLSPubkey,
}

#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct Withdrawals(pub B256);
