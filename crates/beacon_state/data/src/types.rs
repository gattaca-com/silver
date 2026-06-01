use flux::utils::ArrayVec;

use crate::{
    buffer::Reset,
    validators::{FinalizedValidators, ValSeed, ValidatorsDelta},
};

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
pub const SLOTS_RING_N: usize = 256;

// size: ~195 KB stack (slot 145 KB + longtail 50 KB + rest); heap at default-
// init ~2.6 MB (slot+epoch rings).
pub struct Finalized {
    pub immutable: Immutable,
    pub longtail: LongtailState,
    pub pending: PendingQueues,
    pub validators: FinalizedValidators,
    pub balances: FinalizedBalances,
    pub previous_participation: FinalizedPreviousParticipation,
    pub current_participation: FinalizedCurrentParticipation,
    pub inactivity_scores: FinalizedInactivityScores,
    pub epoch: EpochStateFinalized,
    pub slot: SlotStateFinalized,
}

impl Finalized {
    /// Zero-validator stub at floor capacity (pre-bootstrap / tests); no
    /// `Default`, so the base's capacity is always a conscious choice.
    pub fn empty() -> Self {
        let cap = validator_capacity(0);
        Self {
            immutable: Immutable::default(),
            longtail: LongtailState::default(),
            pending: PendingQueues::default(),
            validators: FinalizedValidators::with_capacity(cap),
            balances: FinalizedBalances::with_capacity(cap),
            previous_participation: FinalizedPreviousParticipation::with_capacity(cap),
            current_participation: FinalizedCurrentParticipation::with_capacity(cap),
            inactivity_scores: FinalizedInactivityScores::with_capacity(cap),
            epoch: EpochStateFinalized::default(),
            slot: SlotStateFinalized::default(),
        }
    }
}

impl Finalized {
    #[inline]
    pub fn epoch(&self) -> Epoch {
        self.slot.slot.slot / SLOTS_PER_EPOCH
    }

    pub fn new(seeds: &[ValSeed]) -> Box<Self> {
        let mut f = Box::new(Self::empty());
        f.validators = FinalizedValidators::with_validators(seeds);
        let balances = f.balances.slice_mut();
        for (i, s) in seeds.iter().enumerate() {
            balances[i] = s.balance;
        }
        f
    }
}

// size: 32 B (4 × pointer)
pub struct FinalizedView<'a> {
    pub immutable: &'a Immutable,
    pub validators: &'a FinalizedValidators,
    pub epoch: &'a EpochStateFinalized,
    pub slot: &'a SlotStateFinalized,
}

// size: ~145 KB (dominated by SlotState)
#[derive(Clone, Default)]
pub struct StateDelta {
    pub epoch_idx: Option<usize>,
    pub longtail_idx: Option<usize>,
    pub pending: PendingQueuesDelta,
    pub validators: ValidatorsDelta,
    pub balances: BalancesDelta,
    pub previous_participation: PreviousParticipationDelta,
    pub current_participation: CurrentParticipationDelta,
    pub inactivity_scores: InactivityScoresDelta,
    pub slot: SlotStateDelta,
}

impl StateDelta {
    pub fn prune_to_base(
        &mut self,
        base: &Finalized,
        promoted: &StateDelta,
        old_pending_lens: &PendingQueuesOldBaseLens,
    ) {
        let new_base_count = base.validators.validator_count();
        self.validators.prune_to_base(&base.validators);
        self.balances.prune_to_base(&base.balances, new_base_count);
        self.previous_participation.prune_to_base(&base.previous_participation, new_base_count);
        self.current_participation.prune_to_base(&base.current_participation, new_base_count);
        self.inactivity_scores.prune_to_base(&base.inactivity_scores, new_base_count);
        self.pending.prune_to_base(&base.pending, &promoted.pending, old_pending_lens);
        self.slot.prune_to_base(&promoted.slot);
    }
}

impl Reset for StateDelta {
    fn reset(&mut self) {
        self.epoch_idx = None;
        self.longtail_idx = None;
        self.pending.reset();
        self.validators.reset();
        self.balances.reset();
        self.previous_participation.reset();
        self.current_participation.reset();
        self.inactivity_scores.reset();
        self.slot.reset();
    }

    fn reset_from(&mut self, other: &Self) {
        self.epoch_idx = other.epoch_idx;
        self.longtail_idx = other.longtail_idx;
        self.pending.reset_from(&other.pending);
        self.validators.reset_from(&other.validators);
        self.balances.reset_from(&other.balances);
        self.previous_participation.reset_from(&other.previous_participation);
        self.current_participation.reset_from(&other.current_participation);
        self.inactivity_scores.reset_from(&other.inactivity_scores);
        self.slot.reset_from(&other.slot);
    }
}

// size: ~145 KB — eth1_votes ArrayVec is inline 72 B × 2048 (~144 KB)
#[derive(Clone, Copy, Default)]
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

// size: ~145 KB (SlotState 145 KB + 2 × Vec header)
#[derive(Clone, Default)]
pub struct SlotStateDelta {
    pub slot: SlotState,
    // Appended roots since finalization
    // For finalized: last SLOTS_PER_HISTORICAL_ROOT (8192) (circular buffer indexed by
    // `slot % HR`)
    pub block_roots: Vec<B256>,
    pub state_roots: Vec<B256>,
}

// size: ~145 KB stack (SlotState inline); heap 512 KB at default-init
// (2 × SLOTS_PER_HISTORICAL_ROOT × 32 B rings).
#[derive(Clone)]
pub struct SlotStateFinalized {
    pub slot: SlotState,
    // Finalized: last SLOTS_PER_HISTORICAL_ROOT (8192) (circular buffer indexed by
    // `slot % HR`)
    pub block_roots: Box<[B256]>,
    pub state_roots: Box<[B256]>,
}

impl Default for SlotStateFinalized {
    fn default() -> Self {
        Self {
            slot: Default::default(),
            block_roots: vec![[0u8; 32]; SLOTS_PER_HISTORICAL_ROOT].into_boxed_slice(),
            state_roots: vec![[0u8; 32]; SLOTS_PER_HISTORICAL_ROOT].into_boxed_slice(),
        }
    }
}

impl SlotStateDelta {
    pub fn prune_to_base(&mut self, promoted: &SlotStateDelta) {
        let drop_b = promoted.block_roots.len().min(self.block_roots.len());
        self.block_roots.drain(..drop_b);
        let drop_s = promoted.state_roots.len().min(self.state_roots.len());
        self.state_roots.drain(..drop_s);
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
        self.slot = other.slot;
        self.block_roots.clone_from(&other.block_roots);
        self.state_roots.clone_from(&other.state_roots);
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

// size: ~696 B stack (2 × Vec header + EpochState ~648 B)
#[derive(Clone, Default)]
pub struct EpochStateDelta {
    // For deltas: appended
    pub randao_mixes: Vec<B256>,
    // For deltas: one entry per completed epoch since finalization
    pub slashings: Vec<u64>,
    pub state: EpochState,
}

impl EpochStateDelta {
    pub fn prune_to_base(&mut self, promoted: &EpochStateDelta) {
        let drop_r = promoted.randao_mixes.len().min(self.randao_mixes.len());
        self.randao_mixes.drain(..drop_r);
        let drop_s = promoted.slashings.len().min(self.slashings.len());
        self.slashings.drain(..drop_s);
    }
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
        self.state = other.state;
    }
}

// size: ~680 B stack (2 × Box<[T]> header + EpochState); heap at default-init
// ~2.064 MB (randao_mixes 2 MB + slashings 64 KB rings).
#[derive(Clone)]
pub struct EpochStateFinalized {
    // For finalized: last EPOCHS_PER_HISTORICAL_VECTOR (circular buffer indexed by `epoch % HV`)
    pub randao_mixes: Box<[B256]>,
    // For finalized: last EPOCHS_PER_SLASHINGS_VECTOR (circular buffer indexed by `epoch % SV`)
    pub slashings: Box<[u64]>,
    pub state: EpochState,
}

impl Default for EpochStateFinalized {
    fn default() -> Self {
        Self {
            randao_mixes: vec![[0u8; 32]; EPOCHS_PER_HISTORICAL_VECTOR].into_boxed_slice(),
            slashings: vec![0; EPOCHS_PER_SLASHINGS_VECTOR].into_boxed_slice(),
            state: Default::default(),
        }
    }
}

// size: ~50 KB (two SyncCommittees + sync_committee_indices)
#[derive(Clone)]
pub struct LongtailState {
    pub current_sync_committee: SyncCommittee,
    pub next_sync_committee: SyncCommittee,
    pub sync_committee_indices: [u32; SYNC_COMMITTEE_SIZE],
    // For deltas: entries appended since finalization
    // For finalized: full list
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

impl LongtailState {
    /// Re-base a survivor longtail entry after `promoted` was folded into the
    /// base. Sync committees are absolute (replace, no re-base); only the
    /// cumulative `historical_summaries` log drops the promoted prefix.
    pub fn prune_to_base(&mut self, promoted: &LongtailState) {
        let drop = promoted.historical_summaries.len().min(self.historical_summaries.len());
        self.historical_summaries.drain(..drop);
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

// size: ~72 B (3 × Vec header)
#[derive(Clone, Default)]
pub struct PendingQueues {
    pub pending_deposits: Vec<PendingDeposit>,
    pub pending_partial_withdrawals: Vec<PendingPartialWithdrawal>,
    pub pending_consolidations: Vec<PendingConsolidation>,
}

/// Per-fork delta on `PendingQueues`. Each queue: drop the first
/// `drain_offset` entries of the base, then read the remainder followed by
/// `appended`.
// size: ~88 B
#[derive(Clone, Default)]
pub struct PendingQueuesDelta {
    pub deposits_drain_offset: u32,
    pub deposits_appended: Vec<PendingDeposit>,
    pub partial_withdrawals_drain_offset: u32,
    pub partial_withdrawals_appended: Vec<PendingPartialWithdrawal>,
    pub consolidations_drain_offset: u32,
    pub consolidations_appended: Vec<PendingConsolidation>,
}

pub struct PendingQueuesOldBaseLens {
    pub deposits: usize,
    pub partial_withdrawals: usize,
    pub consolidations: usize,
}

impl PendingQueuesOldBaseLens {
    #[inline]
    pub fn snapshot(base: &PendingQueues) -> Self {
        Self {
            deposits: base.pending_deposits.len(),
            partial_withdrawals: base.pending_partial_withdrawals.len(),
            consolidations: base.pending_consolidations.len(),
        }
    }
}

impl PendingQueuesDelta {
    pub fn prune_to_base(
        &mut self,
        _base: &PendingQueues,
        promoted: &PendingQueuesDelta,
        old_base_lens: &PendingQueuesOldBaseLens,
    ) {
        prune_queue_delta(
            &mut self.deposits_drain_offset,
            &mut self.deposits_appended,
            old_base_lens.deposits,
            promoted.deposits_drain_offset,
            promoted.deposits_appended.len(),
        );
        prune_queue_delta(
            &mut self.partial_withdrawals_drain_offset,
            &mut self.partial_withdrawals_appended,
            old_base_lens.partial_withdrawals,
            promoted.partial_withdrawals_drain_offset,
            promoted.partial_withdrawals_appended.len(),
        );
        prune_queue_delta(
            &mut self.consolidations_drain_offset,
            &mut self.consolidations_appended,
            old_base_lens.consolidations,
            promoted.consolidations_drain_offset,
            promoted.consolidations_appended.len(),
        );
    }
}

/// Re-base one queue's delta onto a freshly-promoted fin: subtract
/// `promoted_drain` from `drain_offset` (now folded into fin), and drop
/// the inherited promoted-`appended` prefix the descendant hasn't
/// already drained from its own copy.
fn prune_queue_delta<T>(
    drain_offset: &mut u32,
    appended: &mut Vec<T>,
    old_base_len: usize,
    promoted_drain: u32,
    promoted_app_len: usize,
) {
    debug_assert!(
        *drain_offset >= promoted_drain,
        "descendant must not drain less than the promoted delta",
    );
    let cur_drain = *drain_offset as usize;
    let drained_from_pf = cur_drain.saturating_sub(old_base_len).min(promoted_app_len);
    let drop_n = (promoted_app_len - drained_from_pf).min(appended.len());
    appended.drain(..drop_n);
    *drain_offset = (cur_drain - promoted_drain as usize) as u32;
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

// Spec parallel SSZ lists (`balances`, `previous/current_epoch_participation`,
// `inactivity_scores`). Each is its own `List[T, VALIDATOR_REGISTRY_LIMIT]`
// in the BeaconState and will eventually carry its own hash tree (not yet
// implemented). Length is whatever the validators layer reports; reading
// past `base_count` with no edit returns the spec default (0 / false).

/// `balances: List[Gwei, VALIDATOR_REGISTRY_LIMIT]` — finalized side.
pub struct FinalizedBalances {
    pub data: Box<[u64]>,
}

impl FinalizedBalances {
    pub fn with_capacity(cap: usize) -> Self {
        Self { data: vec![0u64; cap].into_boxed_slice() }
    }

    #[inline]
    pub fn get(&self, i: usize) -> u64 {
        self.data[i]
    }

    #[inline]
    pub fn slice_mut(&mut self) -> &mut [u64] {
        &mut self.data
    }
}

#[derive(Default, Clone)]
pub struct BalancesDelta {
    pub edits: Vec<(u32, u64)>,
}

impl BalancesDelta {
    pub fn prune_to_base(&mut self, base: &FinalizedBalances, new_base_count: usize) {
        self.edits
            .retain(|(idx, v)| (*idx as usize) >= new_base_count || base.get(*idx as usize) != *v);
    }
}

impl Reset for BalancesDelta {
    fn reset(&mut self) {
        self.edits.clear();
    }
    fn reset_from(&mut self, other: &Self) {
        self.edits.clone_from(&other.edits);
    }
}

/// `previous_epoch_participation: List[ParticipationFlags,
/// VALIDATOR_REGISTRY_LIMIT]`.
pub struct FinalizedPreviousParticipation {
    pub data: Box<[u8]>,
}

impl FinalizedPreviousParticipation {
    pub fn with_capacity(cap: usize) -> Self {
        Self { data: vec![0u8; cap].into_boxed_slice() }
    }

    #[inline]
    pub fn get(&self, i: usize) -> u8 {
        self.data[i]
    }

    #[inline]
    pub fn slice_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

#[derive(Default, Clone)]
pub struct PreviousParticipationDelta {
    pub edits: Vec<(u32, u8)>,
}

impl PreviousParticipationDelta {
    pub fn prune_to_base(&mut self, base: &FinalizedPreviousParticipation, new_base_count: usize) {
        self.edits
            .retain(|(idx, v)| (*idx as usize) >= new_base_count || base.get(*idx as usize) != *v);
    }
}

impl Reset for PreviousParticipationDelta {
    fn reset(&mut self) {
        self.edits.clear();
    }
    fn reset_from(&mut self, other: &Self) {
        self.edits.clone_from(&other.edits);
    }
}

/// `current_epoch_participation: List[ParticipationFlags,
/// VALIDATOR_REGISTRY_LIMIT]`.
pub struct FinalizedCurrentParticipation {
    pub data: Box<[u8]>,
}

impl FinalizedCurrentParticipation {
    pub fn with_capacity(cap: usize) -> Self {
        Self { data: vec![0u8; cap].into_boxed_slice() }
    }

    #[inline]
    pub fn get(&self, i: usize) -> u8 {
        self.data[i]
    }

    #[inline]
    pub fn slice_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

#[derive(Default, Clone)]
pub struct CurrentParticipationDelta {
    pub edits: Vec<(u32, u8)>,
}

impl CurrentParticipationDelta {
    pub fn prune_to_base(&mut self, base: &FinalizedCurrentParticipation, new_base_count: usize) {
        self.edits
            .retain(|(idx, v)| (*idx as usize) >= new_base_count || base.get(*idx as usize) != *v);
    }
}

impl Reset for CurrentParticipationDelta {
    fn reset(&mut self) {
        self.edits.clear();
    }
    fn reset_from(&mut self, other: &Self) {
        self.edits.clone_from(&other.edits);
    }
}

/// `inactivity_scores: List[u64, VALIDATOR_REGISTRY_LIMIT]`.
pub struct FinalizedInactivityScores {
    pub data: Box<[u64]>,
}

impl FinalizedInactivityScores {
    pub fn with_capacity(cap: usize) -> Self {
        Self { data: vec![0u64; cap].into_boxed_slice() }
    }

    #[inline]
    pub fn get(&self, i: usize) -> u64 {
        self.data[i]
    }

    #[inline]
    pub fn slice_mut(&mut self) -> &mut [u64] {
        &mut self.data
    }
}

#[derive(Default, Clone)]
pub struct InactivityScoresDelta {
    pub edits: Vec<(u32, u64)>,
}

impl InactivityScoresDelta {
    pub fn prune_to_base(&mut self, base: &FinalizedInactivityScores, new_base_count: usize) {
        self.edits
            .retain(|(idx, v)| (*idx as usize) >= new_base_count || base.get(*idx as usize) != *v);
    }
}

impl Reset for InactivityScoresDelta {
    fn reset(&mut self) {
        self.edits.clear();
    }
    fn reset_from(&mut self, other: &Self) {
        self.edits.clone_from(&other.edits);
    }
}

// size: ~96 B
#[derive(Clone, Copy, Default)]
pub struct Immutable {
    pub genesis_time: u64,
    pub genesis_validators_root: B256,
    pub historical_roots_hash: B256,
    pub fork: Fork,
    pub genesis_fork_version: Version,
    pub capella_fork_version: Version,
}

impl Immutable {
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

    #[inline]
    pub fn set_compounding_prefix(&mut self) {
        self.0[0] = Self::COMPOUNDING_PREFIX;
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
