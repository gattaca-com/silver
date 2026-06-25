use silver_common_macros::timed;

use crate::{
    BalancesGroup, BeaconState, BuildersGroup, ColumnLenMismatch, CurrentParticipationGroup,
    EpochGroup, EpochStateFinalized, Eth1Group, Eth1Votes, FinalizedBuilders, FinalizedValidators,
    InactivityScoresGroup, LongtailGroup, LongtailState, PendingGroup, PreviousParticipationGroup,
    QueueItem, SlotStateFinalized, SlotStateGroup, SpecConfig, ValidatorsDecodeError,
    ValidatorsGroup, ssz_hash,
    types::{
        B256, Checkpoint, Eth1Data, HISTORICAL_ROOTS_LIMIT, HistoricalSummary, Immutable,
        MAX_ETH1_VOTES, PROPOSER_LOOKAHEAD_SIZE, PendingConsolidation, PendingDeposit,
        PendingPartialWithdrawal, SYNC_COMMITTEE_SIZE, SyncCommittee,
    },
};

const ETH1_DATA_SSZ_SIZE: usize = 72;
const HISTORICAL_SUMMARY_SSZ_SIZE: usize = 64;
const PENDING_DEPOSIT_SSZ_SIZE: usize = 192;
const PENDING_PARTIAL_WITHDRAWAL_SSZ_SIZE: usize = 24;
const PENDING_CONSOLIDATION_SSZ_SIZE: usize = 16;
pub(super) const EPH_FIXED_PART: usize = 584;

const HISTORICAL_SUMMARIES_LIMIT: usize = 1 << 24;

// Fixed-part byte offsets (Fulu).
pub(super) const F0: usize = 0; // genesis_time: 8
pub(super) const F1: usize = 8; // genesis_validators_root: 32
pub(super) const F2: usize = 40; // slot: 8
pub(super) const F3: usize = 48; // fork: 16
pub(super) const F4: usize = 64; // latest_block_header: 112
pub(super) const F5: usize = 176; // block_roots: 8192 × 32 = 262144
pub(super) const F6: usize = 262_320; // state_roots: 262144
pub(super) const F7_OFF: usize = 524_464; // historical_roots offset: 4
pub(super) const F8: usize = 524_468; // eth1_data: 72
pub(super) const F9_OFF: usize = 524_540; // eth1_data_votes offset: 4
pub(super) const F10: usize = 524_544; // eth1_deposit_index: 8
pub(super) const F11_OFF: usize = 524_552; // validators offset: 4
pub(super) const F12_OFF: usize = 524_556; // balances offset: 4
pub(super) const F13: usize = 524_560; // randao_mixes: 65536 × 32 = 2097152
pub(super) const F14: usize = 2_621_712; // slashings: 8192 × 8 = 65536
pub(super) const F15_OFF: usize = 2_687_248; // previous_epoch_participation offset
pub(super) const F16_OFF: usize = 2_687_252; // current_epoch_participation offset
pub(super) const F17: usize = 2_687_256; // justification_bits: 1
pub(super) const F18: usize = 2_687_257; // previous_justified_checkpoint: 40
pub(super) const F19: usize = 2_687_297; // current_justified_checkpoint
pub(super) const F20: usize = 2_687_337; // finalized_checkpoint
pub(super) const F21_OFF: usize = 2_687_377; // inactivity_scores offset
pub(super) const F22: usize = 2_687_381; // current_sync_committee: 24624
pub(super) const F23: usize = 2_712_005; // next_sync_committee: 24624
pub(super) const F24_OFF: usize = 2_736_629; // latest_execution_payload_header offset
pub(super) const F25: usize = 2_736_633; // next_withdrawal_index: 8
pub(super) const F26: usize = 2_736_641; // next_withdrawal_validator_index: 8
pub(super) const F27_OFF: usize = 2_736_649; // historical_summaries offset
pub(super) const F28: usize = 2_736_653; // deposit_requests_start_index: 8
pub(super) const F29: usize = 2_736_661; // deposit_balance_to_consume: 8
pub(super) const F30: usize = 2_736_669; // exit_balance_to_consume: 8
pub(super) const F31: usize = 2_736_677; // earliest_exit_epoch: 8
pub(super) const F32: usize = 2_736_685; // consolidation_balance_to_consume: 8
pub(super) const F33: usize = 2_736_693; // earliest_consolidation_epoch: 8
pub(super) const F34_OFF: usize = 2_736_701; // pending_deposits offset
pub(super) const F35_OFF: usize = 2_736_705; // pending_partial_withdrawals offset
pub(super) const F36_OFF: usize = 2_736_709; // pending_consolidations offset
pub(super) const F37: usize = 2_736_713; // proposer_lookahead: 64 × 8 = 512
pub(crate) const FIXED_PART: usize = 2_737_225;

// Compile-time sanity for the hand-rolled offset table and the alignment
// assumption behind the `&[B256]` raw-slice casts below.
const _: () = assert!(F37 + PROPOSER_LOOKAHEAD_SIZE * 8 == FIXED_PART);
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
    Column(#[from] ColumnLenMismatch),
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
    #[error("too many gloas {field}: {n} > {max}")]
    GloasTooMany { field: &'static str, n: usize, max: usize },
}

#[inline]
pub(super) fn u32_le(s: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(s[off..off + 4].try_into().unwrap())
}

#[inline]
pub(crate) fn u64_le(s: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(s[off..off + 8].try_into().unwrap())
}

#[inline]
pub(super) fn b256(s: &[u8], off: usize) -> B256 {
    s[off..off + 32].try_into().unwrap()
}

pub(super) fn read_checkpoint(s: &[u8], off: usize) -> Checkpoint {
    Checkpoint { epoch: u64_le(s, off), root: b256(s, off + 8) }
}

fn read_sync_committee(
    s: &[u8],
    off: usize,
    which: &'static str,
    sc: &mut SyncCommittee,
) -> Result<(), DecomposeError> {
    const SC_SIZE: usize = SYNC_COMMITTEE_SIZE * 48 + 48;
    let end = off.checked_add(SC_SIZE).ok_or(DecomposeError::SyncCommitteeOutOfBounds {
        which,
        off,
        end: 0,
        len: s.len(),
    })?;
    let bytes = s.get(off..end).ok_or(DecomposeError::SyncCommitteeOutOfBounds {
        which,
        off,
        end,
        len: s.len(),
    })?;
    for i in 0..SYNC_COMMITTEE_SIZE {
        sc.pubkeys[i].copy_from_slice(&bytes[i * 48..(i + 1) * 48]);
    }
    sc.aggregate_pubkey
        .copy_from_slice(&bytes[SYNC_COMMITTEE_SIZE * 48..SYNC_COMMITTEE_SIZE * 48 + 48]);
    Ok(())
}

/// Validated variable-field offsets, monotonic and within `ssz`.
pub(super) struct Offsets {
    pub(super) historical_roots: usize,
    pub(super) eth1_votes: usize,
    pub(super) validators: usize,
    pub(super) balances: usize,
    pub(super) prev_participation: usize,
    pub(super) cur_participation: usize,
    pub(super) inactivity: usize,
    pub(super) eph: usize,
    pub(super) hist_summaries: usize,
    pub(super) pending_deposits: usize,
    pub(super) pending_withdrawals: usize,
    pub(super) pending_consolidations: usize,
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
        mut immutable: Immutable,
        epoch: EpochStateFinalized,
        slot: SlotStateFinalized,
        builders: FinalizedBuilders,
    ) -> Result<Self, DecomposeError> {
        let eth1 = Eth1Group::new(Eth1Votes::from_ssz(ssz, offsets)?);

        let val_bytes = &ssz[offsets.validators..offsets.balances];
        let validators = ValidatorsGroup::new(FinalizedValidators::try_new(val_bytes, pubkeys)?);

        // Per-validator columns size to the validators' capacity/count; each
        // constructor length-checks against the count (construction =
        // validation).
        let (cap, n) =
            (validators.finalized().capacity(), validators.finalized().validator_count());
        let balances =
            BalancesGroup::new(cap, n, &ssz[offsets.balances..offsets.prev_participation])?;
        let previous_participation = PreviousParticipationGroup::new(
            cap,
            n,
            &ssz[offsets.prev_participation..offsets.cur_participation],
        )?;
        let current_participation = CurrentParticipationGroup::new(
            cap,
            n,
            &ssz[offsets.cur_participation..offsets.inactivity],
        )?;
        let inactivity = InactivityScoresGroup::new(cap, n, &ssz[offsets.inactivity..offsets.eph])?;

        immutable.fill_historical_roots_hash(ssz, offsets)?;

        // Longtail's sync-committee → validator-index resolution reads the
        // registry.
        let longtail =
            LongtailGroup::new(LongtailState::from_ssz(ssz, offsets, validators.finalized())?);

        let pending = decode_pending(ssz, offsets, consolidations_end)?;

        Ok(Self {
            immutable,
            validators,
            balances,
            eth1,
            pending,
            previous_participation,
            current_participation,
            inactivity,
            slot_states: SlotStateGroup::new(slot),
            epoch: EpochGroup::new(epoch),
            longtail,
            builders: BuildersGroup::new(builders),
        })
    }
}

impl Immutable {
    #[timed]
    pub(super) fn fill_from_ssz(&mut self, ssz: &[u8], cfg: &SpecConfig) {
        self.genesis_time = u64_le(ssz, F0);
        self.genesis_validators_root = b256(ssz, F1);
        self.fork = crate::types::Fork {
            previous_version: ssz[F3..F3 + 4].try_into().unwrap(),
            current_version: ssz[F3 + 4..F3 + 8].try_into().unwrap(),
            epoch: u64_le(ssz, F3 + 8),
        };
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
        let hr_root = ssz_hash::merkleize_padded(hr_chunks, HISTORICAL_ROOTS_LIMIT);
        self.historical_roots = hr_chunks.into();
        self.historical_roots_hash = ssz_hash::mix_in_length(&hr_root, hr_count);
        Ok(())
    }
}

// `validators` resolves the sync-committee → validator indices.
impl LongtailState {
    #[timed]
    pub(crate) fn from_ssz(
        ssz: &[u8],
        o: &Offsets,
        validators: &FinalizedValidators,
    ) -> Result<Self, DecomposeError> {
        let mut lt = Self::default();

        read_sync_committee(ssz, F22, "current", &mut lt.current_sync_committee)?;
        read_sync_committee(ssz, F23, "next", &mut lt.next_sync_committee)?;

        let hs_bytes = &ssz[o.hist_summaries..o.pending_deposits];
        if !hs_bytes.len().is_multiple_of(HISTORICAL_SUMMARY_SSZ_SIZE) {
            return Err(DecomposeError::HistoricalSummariesLenNotMultiple { len: hs_bytes.len() });
        }
        let hs_count = hs_bytes.len() / HISTORICAL_SUMMARY_SSZ_SIZE;
        if hs_count > HISTORICAL_SUMMARIES_LIMIT {
            return Err(DecomposeError::TooManyHistoricalSummaries {
                n: hs_count,
                max: HISTORICAL_SUMMARIES_LIMIT,
            });
        }
        lt.historical_summaries.reserve_exact(hs_count);
        for i in 0..hs_count {
            let s = &hs_bytes[i * HISTORICAL_SUMMARY_SSZ_SIZE..];
            lt.historical_summaries.push(HistoricalSummary {
                block_summary_root: b256(s, 0),
                state_summary_root: b256(s, 32),
            });
        }

        for i in 0..SYNC_COMMITTEE_SIZE {
            let pk = lt.current_sync_committee.pubkeys[i];
            lt.sync_committee_indices[i] =
                validators.find_by_pubkey(&pk).map(|i| i as u32).unwrap_or(u32::MAX);
        }

        Ok(lt)
    }
}

fn read_eth1_data(s: &[u8]) -> Eth1Data {
    Eth1Data { deposit_root: b256(s, 0), deposit_count: u64_le(s, 32), block_hash: b256(s, 40) }
}

// `epoch` must already be filled — the derived `randao_mix_current` /
// `current_epoch_slashings` read the current bucket from its rings.
impl Eth1Votes {
    fn from_ssz(ssz: &[u8], o: &Offsets) -> Result<Self, DecomposeError> {
        let votes_bytes = &ssz[o.eth1_votes..o.validators];
        if !votes_bytes.len().is_multiple_of(ETH1_DATA_SSZ_SIZE) {
            return Err(DecomposeError::Eth1VotesLenNotMultiple { len: votes_bytes.len() });
        }
        let vote_count = votes_bytes.len() / ETH1_DATA_SSZ_SIZE;
        if vote_count > MAX_ETH1_VOTES {
            return Err(DecomposeError::TooManyEth1Votes { n: vote_count, max: MAX_ETH1_VOTES });
        }
        let mut votes = Self::default();
        for i in 0..vote_count {
            votes.push(read_eth1_data(&votes_bytes[i * ETH1_DATA_SSZ_SIZE..]));
        }
        Ok(votes)
    }
}

/// Decode the three pending queues from their SSZ byte ranges into isolated
/// groups. Each range must be a whole number of fixed-size records within its
/// `List` limit; the per-element codec lives on [`QueueItem`].
fn decode_pending(
    ssz: &[u8],
    o: &Offsets,
    consolidations_end: usize,
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
    Ok(PendingGroup::from_ssz(pd, pw, pc))
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
