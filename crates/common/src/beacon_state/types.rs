use blst::min_pk::PublicKey;
use flux::utils::ArrayVec;
use rustc_hash::FxHashMap;

use crate::beacon_state::buffer::Reset;

pub type B256 = [u8; 32];
pub type BLSPubkey = [u8; 48];
pub type BLSSignature = [u8; 96];
pub type Slot = u64;
pub type Epoch = u64;
pub type Version = [u8; 4];
pub type ExecutionAddress = [u8; 20];

#[cfg(not(test))]
// Physical cap on validator-indexed columnar arrays. Spec limit is
// `VALIDATOR_REGISTRY_LIMIT = 1 << 40`; we size for real registry growth.
// Live count crossed 2.0M during 2025; 2.75 Mi = 2,883,584 sits just below 3M
// and gives ~600k headroom (~26%) over the current registry.
pub const MAX_VALIDATORS: usize = 11 << 18;
#[cfg(test)]
// Mainnet caps ~2M validators. Tests don't need that much and parallel
// `cargo test` would otherwise OOM (~3–4 GB per `BeaconStateTile::new_heap`
// at full cap × N parallel test threads). EF spec test fixtures use ≤ a few
// hundred validators each, well within the test-time cap.
pub const MAX_VALIDATORS: usize = 64 * 1024;
pub const VALIDATOR_REGISTRY_LIMIT: usize = 1 << 40;
pub const SLOTS_PER_HISTORICAL_ROOT: usize = 8192;
pub const EPOCHS_PER_HISTORICAL_VECTOR: usize = 65536;
pub const EPOCHS_PER_SLASHINGS_VECTOR: usize = 8192;
/// In-memory cap for the `historical_summaries` list. Mainnet grows by 1 entry
/// per 256 epochs (~27h); 8192 covers ~25 years.
pub const HISTORICAL_SUMMARIES_CAP: usize = 8192;
pub const HISTORICAL_ROOTS_LIMIT: usize = 1 << 24;

pub const SLOTS_PER_EPOCH: u64 = 32;
pub const SYNC_COMMITTEE_SIZE: usize = 512;
pub const MAX_ETH1_VOTES: usize = 2048;
pub const MIN_SEED_LOOKAHEAD: u64 = 1;
pub const PROPOSER_LOOKAHEAD_SIZE: usize =
    (MIN_SEED_LOOKAHEAD as usize + 1) * SLOTS_PER_EPOCH as usize;
pub const BYTES_PER_LOGS_BLOOM: usize = 256;
pub const MAX_EXTRA_DATA_BYTES: usize = 32;

#[derive(Default)]
pub struct Finalised {
    pub immutable: Immutable,
    pub longtail: LongtailState,
    pub pending: PendingQueues,
    pub validators: Validators,
    pub epoch: EpochStateFinalised,
    pub slot: SlotStateFinalised,
}

impl Finalised {
    pub fn view(&self) -> FinalisedView<'_> {
        FinalisedView {
            immutable: &self.immutable,
            validators: &self.validators,
            epoch: &self.epoch,
            slot: &self.slot,
        }
    }
}

pub struct FinalisedView<'a> {
    pub immutable: &'a Immutable,
    pub validators: &'a Validators,
    pub epoch: &'a EpochStateFinalised,
    pub slot: &'a SlotStateFinalised,
}

#[derive(Clone, Default)]
pub struct StateDelta {
    pub epoch_idx: Option<usize>,
    pub longtail_idx: Option<usize>,
    pub pending: PendingQueuesDelta,
    pub validators: ValidatorsDelta,
    pub slot: SlotStateDelta,
}

impl Reset for StateDelta {
    fn reset(&mut self) {
        self.epoch_idx = None;
        self.longtail_idx = None;
        self.pending.reset();
        self.validators.reset();
        self.slot.reset();
    }

    fn reset_from(&mut self, other: &Self) {
        self.epoch_idx = other.epoch_idx;
        self.longtail_idx = other.longtail_idx;
        self.pending.reset_from(&other.pending);
        self.validators.reset_from(&other.validators);
        self.slot.reset_from(&other.slot);
    }
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
}

#[derive(Clone, Default)]
pub struct SlotStateDelta {
    pub slot: SlotState,
    // Appended roots since finalisation
    // For finalised: last SLOTS_PER_HISTORICAL_ROOT (8192) (circular buffer indexed by
    // `slot % HR`)
    pub block_roots: Vec<B256>,
    pub state_roots: Vec<B256>,
}

#[derive(Clone)]
pub struct SlotStateFinalised {
    pub slot: SlotState,
    // Finalised: last SLOTS_PER_HISTORICAL_ROOT (8192) (circular buffer indexed by
    // `slot % HR`)
    pub block_roots: Box<[B256]>,
    pub state_roots: Box<[B256]>,
}

impl Default for SlotStateFinalised {
    fn default() -> Self {
        Self {
            slot: Default::default(),
            block_roots: vec![[0u8; 32]; SLOTS_PER_HISTORICAL_ROOT].into_boxed_slice(),
            state_roots: vec![[0u8; 32]; SLOTS_PER_HISTORICAL_ROOT].into_boxed_slice(),
        }
    }
}

impl Reset for SlotStateDelta {
    fn reset(&mut self) {
        self.slot = Default::default();
        self.block_roots.clear();
        self.state_roots.clear();
    }

    fn reset_from(&mut self, other: &Self) {
        self.slot.randao_mix_current = other.slot.randao_mix_current;
        self.slot.current_epoch_slashings = other.slot.current_epoch_slashings;
        self.slot = other.slot.clone();
        self.block_roots.clone_from(&other.block_roots);
        self.state_roots.clone_from(&other.state_roots);
    }
}

#[derive(Clone)]
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

#[derive(Clone, Default)]
pub struct EpochStateDelta {
    // For deltas: appended
    pub randao_mixes: Vec<B256>,
    // For deltas: one entry per completed epoch since finalisation
    pub slashings: Vec<u64>,
    pub state: EpochState,
}

impl Reset for EpochStateDelta {
    fn reset(&mut self) {
        self.randao_mixes.clear();
        self.slashings.clear();
        self.state = Default::default();
    }

    fn reset_from(&mut self, other: &Self) {
        self.randao_mixes.clone_from(&other.randao_mixes);
        self.slashings.clone_from(&other.slashings);
        self.state = other.state.clone();
    }
}

#[derive(Clone)]
pub struct EpochStateFinalised {
    // For finalised: last EPOCHS_PER_HISTORICAL_VECTOR (circular buffer indexed by `epoch % HV`)
    pub randao_mixes: Box<[B256]>,
    // For finalised: last EPOCHS_PER_SLASHINGS_VECTOR (circular buffer indexed by `epoch % SV`)
    pub slashings: Box<[u64]>,
    pub state: EpochState,
}

impl Default for EpochStateFinalised {
    fn default() -> Self {
        Self {
            randao_mixes: vec![[0u8; 32]; EPOCHS_PER_HISTORICAL_VECTOR].into_boxed_slice(),
            slashings: vec![0; EPOCHS_PER_SLASHINGS_VECTOR].into_boxed_slice(),
            state: Default::default(),
        }
    }
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

impl Default for LongtailState {
    fn default() -> Self {
        Self {
            current_sync_committee: Default::default(),
            next_sync_committee: Default::default(),
            sync_committee_indices: [0u32; SYNC_COMMITTEE_SIZE],
            historical_summaries: Default::default(),
        }
    }
}

impl Reset for LongtailState {
    fn reset(&mut self) {
        self.current_sync_committee = SyncCommittee::default();
        self.next_sync_committee = SyncCommittee::default();
        self.sync_committee_indices = [0u32; SYNC_COMMITTEE_SIZE];
        self.historical_summaries.clear();
    }

    fn reset_from(&mut self, other: &Self) {
        self.current_sync_committee = other.current_sync_committee;
        self.next_sync_committee = other.next_sync_committee;
        self.sync_committee_indices = other.sync_committee_indices;
        self.historical_summaries.clone_from(&other.historical_summaries);
    }
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

impl Reset for PendingQueuesDelta {
    fn reset(&mut self) {
        self.deposits_drain_offset = 0;
        self.deposits_appended.clear();
        self.partial_withdrawals_drain_offset = 0;
        self.partial_withdrawals_appended.clear();
        self.consolidations_drain_offset = 0;
        self.consolidations_appended.clear();
    }

    fn reset_from(&mut self, other: &Self) {
        self.deposits_drain_offset = other.deposits_drain_offset;
        self.deposits_appended.clone_from(&other.deposits_appended);
        self.partial_withdrawals_drain_offset = other.partial_withdrawals_drain_offset;
        self.partial_withdrawals_appended.clone_from(&other.partial_withdrawals_appended);
        self.consolidations_drain_offset = other.consolidations_drain_offset;
        self.consolidations_appended.clone_from(&other.consolidations_appended);
    }
}

/// All slices are MAX_VALIDATORS long
pub struct ValidatorsData {
    pub validator_count: usize,
    pub val_pubkey: Box<[BLSPubkey]>,
    pub val_pubkey_decompressed: Box<[PublicKey]>,
    pub val_withdrawal_credentials: Box<[Withdrawals]>,
    pub balances: Box<[u64]>,
    pub current_epoch_participation: Box<[u8]>,
    pub previous_epoch_participation: Box<[u8]>,
    pub effective_balance: Box<[u64]>,
    pub activation_epoch: Box<[Epoch]>,
    pub exit_epoch: Box<[Epoch]>,
    pub activation_eligibility_epoch: Box<[Epoch]>,
    pub withdrawable_epoch: Box<[Epoch]>,
    pub inactivity_scores: Box<[u64]>,
    pub slashed: Box<[bool]>,
}

impl Default for ValidatorsData {
    fn default() -> Self {
        Self {
            validator_count: 0,
            val_pubkey: vec![[0u8; 48]; MAX_VALIDATORS].into_boxed_slice(),
            val_pubkey_decompressed: vec![Default::default(); MAX_VALIDATORS].into_boxed_slice(),
            val_withdrawal_credentials: vec![Default::default(); MAX_VALIDATORS].into_boxed_slice(),
            balances: vec![Default::default(); MAX_VALIDATORS].into_boxed_slice(),
            current_epoch_participation: vec![Default::default(); MAX_VALIDATORS]
                .into_boxed_slice(),
            previous_epoch_participation: vec![Default::default(); MAX_VALIDATORS]
                .into_boxed_slice(),
            effective_balance: vec![Default::default(); MAX_VALIDATORS].into_boxed_slice(),
            activation_epoch: vec![Default::default(); MAX_VALIDATORS].into_boxed_slice(),
            exit_epoch: vec![Default::default(); MAX_VALIDATORS].into_boxed_slice(),
            activation_eligibility_epoch: vec![Default::default(); MAX_VALIDATORS]
                .into_boxed_slice(),
            withdrawable_epoch: vec![Default::default(); MAX_VALIDATORS].into_boxed_slice(),
            inactivity_scores: vec![Default::default(); MAX_VALIDATORS].into_boxed_slice(),
            slashed: vec![Default::default(); MAX_VALIDATORS].into_boxed_slice(),
        }
    }
}

pub type PubkeyIndex = FxHashMap<BLSPubkey, u32>;

#[derive(Default)]
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

impl Reset for ValidatorsDelta {
    fn reset(&mut self) {
        self.base_cnt = 0;
        self.appended.clear();
        self.credentials_edits.clear();
        self.balance_edits.clear();
        self.current_participation_edits.clear();
        self.previous_participation_edits.clear();
        self.effective_balance_edits.clear();
        self.activation_epoch_edits.clear();
        self.exit_epoch_edits.clear();
        self.activation_eligibility_epoch_edits.clear();
        self.withdrawable_epoch_edits.clear();
        self.slashed_edits.clear();
        self.inactivity_score_edits.clear();
    }

    fn reset_from(&mut self, other: &Self) {
        self.base_cnt = other.base_cnt;
        self.appended.clone_from(&other.appended);
        self.credentials_edits.clone_from(&other.credentials_edits);
        self.balance_edits.clone_from(&other.balance_edits);
        self.current_participation_edits.clone_from(&other.current_participation_edits);
        self.previous_participation_edits.clone_from(&other.previous_participation_edits);
        self.effective_balance_edits.clone_from(&other.effective_balance_edits);
        self.activation_epoch_edits.clone_from(&other.activation_epoch_edits);
        self.exit_epoch_edits.clone_from(&other.exit_epoch_edits);
        self.activation_eligibility_epoch_edits
            .clone_from(&other.activation_eligibility_epoch_edits);
        self.withdrawable_epoch_edits.clone_from(&other.withdrawable_epoch_edits);
        self.slashed_edits.clone_from(&other.slashed_edits);
        self.inactivity_score_edits.clone_from(&other.inactivity_score_edits);
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

impl Default for SyncCommittee {
    fn default() -> Self {
        Self { pubkeys: [[0u8; 48]; SYNC_COMMITTEE_SIZE], aggregate_pubkey: [0u8; 48] }
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct Withdrawals(pub B256);
