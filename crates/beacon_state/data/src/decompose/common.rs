use flux_profiler::timed;
use silver_ssz::ssz_view::BEACON_BLOCK_HEADER_SIZE;

use crate::{
    BalancesGroup, BeaconState, BlockRootsGroup, BuildersGroup, CurrentParticipationGroup,
    EPOCHS_PER_HISTORICAL_VECTOR, EPOCHS_PER_SLASHINGS_VECTOR, EpochGroup, EpochStateFinalized,
    Eth1Group, Eth1Votes, FinalizedBuilders, FinalizedValidators, InactivityScoresGroup,
    LongtailGroup, LongtailState, PendingGroup, PreviousParticipationGroup, QueueItem,
    RandaoMixesGroup, SLOTS_PER_HISTORICAL_ROOT, SlashingsGroup, SlotStateFinalized,
    SlotStateGroup, SpecConfig, StateRootsGroup, TreeLenMismatch, ValidatorsDecodeError,
    ValidatorsGroup,
    gloas::BuilderPendingWithdrawal,
    merkle,
    types::{
        self, B256, BLSPubkey, Checkpoint, HISTORICAL_ROOTS_LIMIT, HashFormat, Immutable,
        PROPOSER_LOOKAHEAD_SIZE, PendingConsolidation, PendingDeposit, PendingPartialWithdrawal,
        SLOTS_PER_EPOCH, SYNC_COMMITTEE_SIZE,
    },
};

pub(crate) const ETH1_DATA_SSZ_SIZE: usize = 72;
pub(crate) const HISTORICAL_SUMMARY_SSZ_SIZE: usize = 64;
const PENDING_DEPOSIT_SSZ_SIZE: usize = 192;
const PENDING_PARTIAL_WITHDRAWAL_SSZ_SIZE: usize = 24;
const PENDING_CONSOLIDATION_SSZ_SIZE: usize = 16;
const ROOT_RING_SSZ: usize = SLOTS_PER_HISTORICAL_ROOT * size_of::<B256>();
const RANDAO_RING_SSZ: usize = EPOCHS_PER_HISTORICAL_VECTOR * size_of::<B256>();
const SLASHINGS_SSZ: usize = EPOCHS_PER_SLASHINGS_VECTOR * size_of::<u64>();
const CHECKPOINT_SSZ: usize = 40;
const SYNC_COMMITTEE_SSZ: usize = (SYNC_COMMITTEE_SIZE + 1) * size_of::<BLSPubkey>();
pub(super) const OFFSET: usize = 4;

// Fixed-part byte offsets (Fulu). Each names the field that starts there.
pub(super) const F0: usize = 0; // genesis_time
pub(super) const F1: usize = F0 + 8; // genesis_validators_root
pub(crate) const F2: usize = F1 + 32; // slot
pub(super) const F3: usize = F2 + 8; // fork
pub(crate) const F4: usize = F3 + 16; // latest_block_header
pub(crate) const F5: usize = F4 + BEACON_BLOCK_HEADER_SIZE; // block_roots
pub(crate) const F6: usize = F5 + ROOT_RING_SSZ; // state_roots
pub(super) const F7_OFF: usize = F6 + ROOT_RING_SSZ; // historical_roots
pub(crate) const F8: usize = F7_OFF + OFFSET; // eth1_data
pub(super) const F9_OFF: usize = F8 + ETH1_DATA_SSZ_SIZE; // eth1_data_votes
pub(crate) const F10: usize = F9_OFF + OFFSET; // eth1_deposit_index
pub(super) const F11_OFF: usize = F10 + 8; // validators
pub(super) const F12_OFF: usize = F11_OFF + OFFSET; // balances
pub(crate) const F13: usize = F12_OFF + OFFSET; // randao_mixes
pub(crate) const F14: usize = F13 + RANDAO_RING_SSZ; // slashings
pub(super) const F15_OFF: usize = F14 + SLASHINGS_SSZ; // previous_epoch_participation
pub(super) const F16_OFF: usize = F15_OFF + OFFSET; // current_epoch_participation
pub(crate) const F17: usize = F16_OFF + OFFSET; // justification_bits
pub(crate) const F18: usize = F17 + 1; // previous_justified_checkpoint
pub(crate) const F19: usize = F18 + CHECKPOINT_SSZ; // current_justified_checkpoint
pub(crate) const F20: usize = F19 + CHECKPOINT_SSZ; // finalized_checkpoint
pub(super) const F21_OFF: usize = F20 + CHECKPOINT_SSZ; // inactivity_scores
pub(crate) const F22: usize = F21_OFF + OFFSET; // current_sync_committee
pub(crate) const F23: usize = F22 + SYNC_COMMITTEE_SSZ; // next_sync_committee
pub(super) const F24_OFF: usize = F23 + SYNC_COMMITTEE_SSZ; // latest_execution_payload_header
pub(crate) const F25: usize = F24_OFF + OFFSET; // next_withdrawal_index
pub(crate) const F26: usize = F25 + 8; // next_withdrawal_validator_index
pub(super) const F27_OFF: usize = F26 + 8; // historical_summaries
pub(crate) const F28: usize = F27_OFF + OFFSET; // deposit_requests_start_index
pub(crate) const F29: usize = F28 + 8; // deposit_balance_to_consume
pub(crate) const F30: usize = F29 + 8; // exit_balance_to_consume
pub(crate) const F31: usize = F30 + 8; // earliest_exit_epoch
pub(crate) const F32: usize = F31 + 8; // consolidation_balance_to_consume
pub(crate) const F33: usize = F32 + 8; // earliest_consolidation_epoch
pub(super) const F34_OFF: usize = F33 + 8; // pending_deposits
pub(super) const F35_OFF: usize = F34_OFF + OFFSET; // pending_partial_withdrawals
pub(super) const F36_OFF: usize = F35_OFF + OFFSET; // pending_consolidations
pub(crate) const F37: usize = F36_OFF + OFFSET; // proposer_lookahead
pub(crate) const FULU_FIXED_PART: usize = F37 + PROPOSER_LOOKAHEAD_SIZE * size_of::<u64>();

// The alignment assumption behind the `&[B256]` raw-slice casts below.
const _: () = assert!(std::mem::align_of::<B256>() == 1);

#[derive(Debug, thiserror::Error)]
pub enum DecomposeError {
    #[error("ssz shorter than fixed part: len={len} need={need}")]
    TruncatedFixedPart { len: usize, need: usize },
    #[error("first variable-field offset {off} < FIXED_PART {fixed}")]
    FirstOffsetBeforeFixedPart { off: usize, fixed: usize },
    #[error("non-monotonic variable-field offsets at pair {i}: {a} > {b}")]
    NonMonotonicOffsets { i: usize, a: usize, b: usize },
    #[error("variable-field offset {off} past end {len}")]
    OffsetPastEnd { off: usize, len: usize },
    #[error("{which}_sync_committee out of bounds: off={off} end={end} len={len}")]
    SyncCommitteeOutOfBounds { which: &'static str, off: usize, end: usize, len: usize },
    #[error(transparent)]
    Validators(#[from] ValidatorsDecodeError),
    #[error(transparent)]
    Column(#[from] TreeLenMismatch),
    #[error("eth1_votes bytes {len} not a multiple of {ETH1_DATA_SSZ_SIZE}")]
    Eth1VotesLenNotMultiple { len: usize },
    #[error("too many eth1_votes: {n} > MAX_ETH1_VOTES {max}")]
    TooManyEth1Votes { n: usize, max: usize },
    #[error("historical_roots bytes {len} not a multiple of 32")]
    HistoricalRootsLenNotMultiple { len: usize },
    #[error("too many historical_roots: {n} > {max}")]
    TooManyHistoricalRoots { n: usize, max: usize },
    #[error("historical_summaries bytes {len} not a multiple of {HISTORICAL_SUMMARY_SSZ_SIZE}")]
    HistoricalSummariesLenNotMultiple { len: usize },
    #[error("too many historical_summaries: {n} > {max}")]
    TooManyHistoricalSummaries { n: usize, max: usize },
    #[error("pending_deposits bytes {len} not a multiple of {PENDING_DEPOSIT_SSZ_SIZE}")]
    PendingDepositsLenNotMultiple { len: usize },
    #[error("too many pending_deposits: {n} > {max}")]
    TooManyPendingDeposits { n: usize, max: usize },
    #[error(
        "pending_partial_withdrawals bytes {len} not a multiple of {PENDING_PARTIAL_WITHDRAWAL_SSZ_SIZE}"
    )]
    PendingWithdrawalsLenNotMultiple { len: usize },
    #[error("too many pending_partial_withdrawals: {n} > {max}")]
    TooManyPendingWithdrawals { n: usize, max: usize },
    #[error(
        "pending_consolidations bytes {len} not a multiple of {PENDING_CONSOLIDATION_SSZ_SIZE}"
    )]
    PendingConsolidationsLenNotMultiple { len: usize },
    #[error("too many pending_consolidations: {n} > {max}")]
    TooManyPendingConsolidations { n: usize, max: usize },
    #[error("execution_payload_header truncated: len={len} need={need}")]
    EphTruncated { len: usize, need: usize },
    #[error(
        "execution_payload_header extra_data offset invalid: off={off} fixed={fixed} len={len}"
    )]
    EphExtraDataOffsetInvalid { off: usize, fixed: usize, len: usize },
    #[error("execution_payload_header extra_data too long: {len} > 32")]
    EphExtraDataTooLong { len: usize },
    #[error("gloas {field} bytes {len} not a multiple of {size}")]
    GloasFieldLen { field: &'static str, len: usize, size: usize },
    #[error("gloas {field} variable-field offset {off} != fixed part {fixed}")]
    GloasOffset { field: &'static str, off: usize, fixed: usize },
    #[error("too many gloas {field}: {n} > {max}")]
    GloasTooMany { field: &'static str, n: usize, max: usize },
    #[error("{field} {index} out of range: count {count}")]
    IndexOutOfRange { field: &'static str, index: u64, count: usize },
}

#[inline]
pub(crate) fn u32_le(s: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(s[off..off + 4].try_into().unwrap())
}

#[inline]
pub(crate) fn u64_le(s: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(s[off..off + 8].try_into().unwrap())
}

#[inline]
pub(crate) fn b256(s: &[u8], off: usize) -> B256 {
    s[off..off + 32].try_into().unwrap()
}

pub(crate) fn read_checkpoint(s: &[u8], off: usize) -> Checkpoint {
    Checkpoint { epoch: u64_le(s, off), root: b256(s, off + 8) }
}

pub(crate) fn read_fork(s: &[u8]) -> types::Fork {
    types::Fork {
        previous_version: s[F3..F3 + 4].try_into().unwrap(),
        current_version: s[F3 + 4..F3 + 8].try_into().unwrap(),
        epoch: u64_le(s, F3 + 8),
    }
}

/// Validated variable-field offsets, monotonic and within `ssz`.
pub(crate) struct Offsets {
    pub(crate) historical_roots: usize,
    pub(crate) eth1_votes: usize,
    pub(crate) validators: usize,
    pub(crate) balances: usize,
    pub(crate) prev_participation: usize,
    pub(crate) cur_participation: usize,
    pub(crate) inactivity: usize,
    pub(crate) eph: usize,
    pub(crate) hist_summaries: usize,
    pub(crate) pending_deposits: usize,
    pub(crate) pending_withdrawals: usize,
    pub(crate) pending_consolidations: usize,
}

impl BeaconState {
    /// Build the fork-agnostic tiers from validated `offsets` — eth1,
    /// validators, the per-validator columns, longtail, pending, and the
    /// immutable historical-roots hash — and assemble the `BeaconState` with
    /// the fork-specific pieces (`immutable`/`epoch`/`slot`/`builders`).
    /// `consolidations_end` bounds the `pending_consolidations` body (the end
    /// of the buffer for Fulu; the `builders` body start for Gloas).
    #[allow(clippy::too_many_arguments)]
    pub(super) fn assemble(
        ssz: &[u8],
        offsets: &Offsets,
        pubkeys: Option<&[blst::min_pk::PublicKey]>,
        consolidations_end: usize,
        builder_withdrawals: &[u8],
        epoch: EpochStateFinalized,
        slot: SlotStateFinalized,
        builders: FinalizedBuilders,
        cfg: &SpecConfig,
    ) -> Result<Self, DecomposeError> {
        let is_gloas = epoch.state().fork.current_version == cfg.gloas_fork_version;
        let format = if is_gloas { HashFormat::Progressive } else { HashFormat::Fixed };

        let eth1 = Eth1Group::new(Eth1Votes::from_ssz(ssz, offsets)?);

        let val_bytes = &ssz[offsets.validators..offsets.balances];
        let validators =
            ValidatorsGroup::new(FinalizedValidators::try_new(val_bytes, pubkeys)?, format);

        // Per-validator columns size to the validators' capacity/count; each
        // constructor length-checks against the count (construction =
        // validation).
        let (cap, n) =
            (validators.finalized().capacity(), validators.finalized().validator_count());
        let balances =
            BalancesGroup::new(cap, n, &ssz[offsets.balances..offsets.prev_participation], format)?;

        let prev_participation_bytes = &ssz[offsets.prev_participation..offsets.cur_participation];
        let previous_participation =
            PreviousParticipationGroup::new(cap, n, prev_participation_bytes, format)?;
        let curr_participation_bytes = &ssz[offsets.cur_participation..offsets.inactivity];
        let current_participation =
            CurrentParticipationGroup::new(cap, n, curr_participation_bytes, format)?;

        let inactivity =
            InactivityScoresGroup::new(cap, n, &ssz[offsets.inactivity..offsets.eph], format)?;

        let mut immutable = Immutable::default();
        immutable.fill_from_ssz(ssz, cfg);
        immutable.fill_historical_roots_hash(ssz, offsets)?;

        // Longtail's sync-committee → validator-index resolution reads the
        // registry.
        let longtail =
            LongtailGroup::new(LongtailState::from_ssz(ssz, offsets, validators.finalized())?);

        let mut pending = decode_pending(ssz, offsets, consolidations_end, builder_withdrawals)?;
        if is_gloas {
            pending.mark_gloas_base();
        }

        let current_epoch = slot.state().slot / SLOTS_PER_EPOCH;
        let epoch_balances = validators.finalized().sweep_epoch_balances(
            prev_participation_bytes,
            curr_participation_bytes,
            current_epoch,
        );
        let slot = slot.with_epoch_balances(epoch_balances);

        let epoch = epoch.with_increments(validators.finalized().effective_balances());
        let state = Self {
            immutable,
            validators,
            balances,
            eth1,
            pending,
            previous_participation,
            current_participation,
            inactivity,
            slashings: SlashingsGroup::vector(
                &ssz[F14..F14 + EPOCHS_PER_SLASHINGS_VECTOR * size_of::<u64>()],
            )?,
            block_roots: BlockRootsGroup::vector(&ssz[F5..F5 + ROOT_RING_SSZ])?,
            state_roots: StateRootsGroup::vector(&ssz[F6..F6 + ROOT_RING_SSZ])?,
            randao_mixes: RandaoMixesGroup::vector(&ssz[F13..F13 + RANDAO_RING_SSZ])?,
            slot_states: SlotStateGroup::new(slot),
            epoch: EpochGroup::new(epoch),
            longtail,
            builders: BuildersGroup::new(builders),
        };
        debug_assert_eq!(state.is_finalized_post_gloas(), is_gloas);
        Ok(state)
    }
}

impl Immutable {
    #[timed]
    pub(super) fn fill_from_ssz(&mut self, ssz: &[u8], cfg: &SpecConfig) {
        self.genesis_time = u64_le(ssz, F0);
        self.genesis_validators_root = b256(ssz, F1);
        self.genesis_fork_version = cfg.genesis_fork_version;
        self.capella_fork_version = cfg.capella_fork_version;
        self.gloas_fork_version = cfg.gloas_fork_version;
    }

    #[timed]
    fn fill_historical_roots_hash(
        &mut self,
        ssz: &[u8],
        o: &Offsets,
    ) -> Result<(), DecomposeError> {
        let hr_bytes = &ssz[o.historical_roots..o.eth1_votes];
        if !hr_bytes.len().is_multiple_of(32) {
            return Err(DecomposeError::HistoricalRootsLenNotMultiple { len: hr_bytes.len() });
        }
        let hr_count = hr_bytes.len() / 32;
        if hr_count > HISTORICAL_ROOTS_LIMIT {
            return Err(DecomposeError::TooManyHistoricalRoots {
                n: hr_count,
                max: HISTORICAL_ROOTS_LIMIT,
            });
        }
        let hr_chunks: &[B256] =
            unsafe { std::slice::from_raw_parts(hr_bytes.as_ptr().cast::<B256>(), hr_count) };
        let hr_root = merkle::merkleize_padded(hr_chunks, HISTORICAL_ROOTS_LIMIT);
        self.historical_roots = hr_chunks.into();
        self.historical_roots_hash = merkle::mix_in_length(&hr_root, hr_count);
        Ok(())
    }
}

/// Decode the three pending queues from their SSZ byte ranges into isolated
/// groups. Each range must be a whole number of fixed-size records within its
/// `List` limit; the per-element codec lives on [`QueueItem`].
fn decode_pending(
    ssz: &[u8],
    o: &Offsets,
    consolidations_end: usize,
    builder_withdrawals: &[u8],
) -> Result<PendingGroup, DecomposeError> {
    let pd = validate_queue::<PendingDeposit>(
        &ssz[o.pending_deposits..o.pending_withdrawals],
        |len| DecomposeError::PendingDepositsLenNotMultiple { len },
        |n, max| DecomposeError::TooManyPendingDeposits { n, max },
    )?;
    let pw = validate_queue::<PendingPartialWithdrawal>(
        &ssz[o.pending_withdrawals..o.pending_consolidations],
        |len| DecomposeError::PendingWithdrawalsLenNotMultiple { len },
        |n, max| DecomposeError::TooManyPendingWithdrawals { n, max },
    )?;
    // `pending_consolidations` is the last section in Fulu (`consolidations_end
    // == ssz.len()`) but is followed by `builders` in Gloas.
    let pc = validate_queue::<PendingConsolidation>(
        &ssz[o.pending_consolidations..consolidations_end],
        |len| DecomposeError::PendingConsolidationsLenNotMultiple { len },
        |n, max| DecomposeError::TooManyPendingConsolidations { n, max },
    )?;
    // Gloas-only; Fulu passes `&[]`, which validates to an empty queue.
    let bpw = validate_queue::<BuilderPendingWithdrawal>(
        builder_withdrawals,
        |len| DecomposeError::GloasFieldLen {
            field: "builder_pending_withdrawals",
            len,
            size: BuilderPendingWithdrawal::SSZ_SIZE,
        },
        |n, max| DecomposeError::GloasTooMany { field: "builder_pending_withdrawals", n, max },
    )?;
    Ok(PendingGroup::from_ssz(pd, pw, pc, bpw))
}

/// Validate a pending-queue byte range: whole records, count within limit.
fn validate_queue<Q: QueueItem>(
    bytes: &[u8],
    len_err: impl Fn(usize) -> DecomposeError,
    many_err: impl Fn(usize, usize) -> DecomposeError,
) -> Result<&[u8], DecomposeError> {
    if !bytes.len().is_multiple_of(Q::SSZ_SIZE) {
        return Err(len_err(bytes.len()));
    }
    let n = bytes.len() / Q::SSZ_SIZE;
    if n > Q::SSZ_LIMIT {
        return Err(many_err(n, Q::SSZ_LIMIT));
    }
    Ok(bytes)
}
