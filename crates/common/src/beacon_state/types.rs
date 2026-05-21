use std::{
    alloc::{Layout, alloc_zeroed},
    collections::VecDeque,
};

use blst::min_pk::PublicKey;
use flux::utils::ArrayVec;
use rustc_hash::FxHashMap;

pub fn box_zeroed<T>() -> Box<T> {
    let layout = Layout::new::<T>();
    unsafe {
        let ptr = alloc_zeroed(layout);
        assert!(!ptr.is_null(), "allocation failed");
        Box::from_raw(ptr.cast::<T>())
    }
}

pub type B256 = [u8; 32];
pub type BLSPubkey = [u8; 48];
pub type BLSSignature = [u8; 96];
pub type Slot = u64;
pub type Epoch = u64;
pub type Version = [u8; 4];
pub type ExecutionAddress = [u8; 20];

pub const VALIDATOR_REGISTRY_LIMIT: usize = 1 << 40;
pub const SLOTS_PER_HISTORICAL_ROOT: usize = 8192;
pub const SLOTS_PER_EPOCH: u64 = 32;
pub const EPOCHS_PER_HISTORICAL_VECTOR: usize = 65536;
pub const EPOCHS_PER_SLASHINGS_VECTOR: usize = 8192;
pub const SYNC_COMMITTEE_SIZE: usize = 512;
pub const MAX_ETH1_VOTES: usize = 2048;
pub const HISTORICAL_ROOTS_LIMIT: usize = 1 << 24;
pub const MIN_SEED_LOOKAHEAD: u64 = 1;
pub const PROPOSER_LOOKAHEAD_SIZE: usize =
    (MIN_SEED_LOOKAHEAD as usize + 1) * SLOTS_PER_EPOCH as usize;
pub const BYTES_PER_LOGS_BLOOM: usize = 256;
pub const MAX_EXTRA_DATA_BYTES: usize = 32;

pub const PENDING_DEPOSITS_LIMIT: usize = 1 << 27;
pub const PENDING_PARTIAL_WITHDRAWALS_LIMIT: usize = 1 << 27;
pub const PENDING_CONSOLIDATIONS_LIMIT: usize = 1 << 18;

pub const MAX_WITHDRAWALS_PER_PAYLOAD: usize = 16;
pub const MAX_DEPOSIT_REQUESTS_PER_PAYLOAD: usize = 8192;
pub const MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD: usize = 16;
pub const MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD: usize = 2;
pub const EPOCHS_PER_ETH1_VOTING_PERIOD: u64 = 64;
pub const EPOCHS_PER_SYNC_COMMITTEE_PERIOD: u64 = 256;

pub struct Finalised {
    pub immutable: Immutable,
    pub longtail: HistoricalLongtail,
    pub pending: PendingQueues,
    pub validators: FinalizedValidators,
    pub epoch: FinalisedEpoch,
    pub slot: SlotDelta,
}

pub struct StateDelta<'a> {
    // one for 256 epochs
    // both of these could reference the fields in finalised state if equal
    // TODO move into arcs? then the finalised state has to have arcs too
    pub longtail: &'a HistoricalLongtail,
    pub epoch: &'a EpochDelta,
    pub pending: PendingQueuesDelta,
    pub validators: ValidatorsDelta,
    pub slot: SlotDelta,
}

#[derive(Clone)]
pub struct SlotDelta {
    pub randao_mix_current: B256,
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

    pub block_roots: Vec<B256>,
    pub state_roots: Vec<B256>,
}

#[derive(Clone)]
pub struct EpochDelta {
    pub randao_mixes: Vec<B256>,
    pub slashings: Vec<u64>,
    pub proposer_lookahead: [u64; PROPOSER_LOOKAHEAD_SIZE],
    pub justification_bits: u8,
    pub previous_justified_checkpoint: Checkpoint,
    pub current_justified_checkpoint: Checkpoint,
    pub finalized_checkpoint: Checkpoint,
    pub deposit_balance_to_consume: u64,
    /// Only mutated every 256 epochs (~27 h) on
    /// `process_historical_summaries_update`.
    pub historical_summaries_appended: Vec<HistoricalSummary>,
}

impl Default for EpochDelta {
    fn default() -> Self {
        Self {
            randao_mixes: Vec::new(),
            slashings: Vec::new(),
            proposer_lookahead: [0u64; PROPOSER_LOOKAHEAD_SIZE],
            justification_bits: 0,
            previous_justified_checkpoint: Checkpoint::default(),
            current_justified_checkpoint: Checkpoint::default(),
            finalized_checkpoint: Checkpoint::default(),
            deposit_balance_to_consume: 0,
            historical_summaries_appended: Vec::new(),
        }
    }
}

/// Per-fork delta on `PendingQueues`. Each queue: drop the first
/// `drain_offset` entries of the base, then read the remainder followed by
/// `appended`.
#[derive(Default, Clone)]
pub struct PendingQueuesDelta {
    pub deposits_drain_offset: u32,
    pub deposits_appended: Vec<PendingDeposit>,
    pub partial_withdrawals_drain_offset: u32,
    pub partial_withdrawals_appended: Vec<PendingPartialWithdrawal>,
    pub consolidations_drain_offset: u32,
    pub consolidations_appended: Vec<PendingConsolidation>,
}

pub struct FinalisedEpoch {
    pub randao_mixes: [B256; EPOCHS_PER_HISTORICAL_VECTOR],
    pub slashings: [u64; EPOCHS_PER_SLASHINGS_VECTOR],
    pub proposer_lookahead: [u64; PROPOSER_LOOKAHEAD_SIZE],
    pub justification_bits: u8,
    pub previous_justified_checkpoint: Checkpoint,
    pub current_justified_checkpoint: Checkpoint,
    pub finalized_checkpoint: Checkpoint,
    pub deposit_balance_to_consume: u64,
    pub historical_summaries: Vec<HistoricalSummary>,
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

#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub epoch: Epoch,
    pub root: B256,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Fork {
    pub previous_version: Version,
    pub current_version: Version,
    pub epoch: Epoch,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Immutable {
    pub genesis_time: u64,
    pub genesis_validators_root: B256,
    pub historical_roots_hash: B256,
    pub fork: Fork,
    pub genesis_fork_version: Version,
    pub capella_fork_version: Version,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Eth1Data {
    pub deposit_root: B256,
    pub deposit_count: u64,
    pub block_hash: B256,
}

#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct BeaconBlockHeader {
    pub slot: Slot,
    pub proposer_index: u64,
    pub parent_root: B256,
    pub state_root: B256,
    pub body_root: B256,
}

#[repr(C)]
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

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PendingDeposit {
    pub pubkey: BLSPubkey,
    pub withdrawal_credentials: Withdrawals,
    pub amount: u64,
    pub signature: BLSSignature,
    pub slot: Slot,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct PendingPartialWithdrawal {
    pub index: u64,
    pub amount: u64,
    pub withdrawable_epoch: Epoch,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct PendingConsolidation {
    pub source_index: u64,
    pub target_index: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct HistoricalSummary {
    pub block_summary_root: B256,
    pub state_summary_root: B256,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SyncCommittee {
    pub pubkeys: [BLSPubkey; SYNC_COMMITTEE_SIZE],
    pub aggregate_pubkey: BLSPubkey,
}

/// 32-byte validator withdrawal credentials. `#[repr(transparent)]` over
/// `B256` so `[Withdrawals; N]` shares the layout of `[B256; N]`.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct Withdrawals(pub B256);

#[repr(C)]
pub struct ValidatorsData {
    pub validator_cnt: usize,
    pub val_pubkey: Vec<BLSPubkey>,
    pub val_pubkey_decompressed: Vec<PublicKey>,
    pub val_withdrawal_credentials: Vec<Withdrawals>,
}

pub type PubkeyIndex = FxHashMap<BLSPubkey, u32>;

pub struct FinalizedValidators {
    pub data: ValidatorsData,
    pub index: PubkeyIndex,
}

#[derive(Clone, PartialEq)]
pub struct AppendedValidator {
    pub pubkey: BLSPubkey,
    pub pubkey_decompressed: PublicKey,
    pub credentials: Withdrawals,
}

pub struct HistoricalLongtail {
    pub current_sync_committee: SyncCommittee,
    pub next_sync_committee: SyncCommittee,
    pub sync_committee_indices: [u32; SYNC_COMMITTEE_SIZE],
}

#[derive(Clone, Default)]
pub struct PendingQueues {
    pub pending_deposits: Vec<PendingDeposit>,
    pub pending_partial_withdrawals: VecDeque<PendingPartialWithdrawal>,
    pub pending_consolidations: Vec<PendingConsolidation>,
}
