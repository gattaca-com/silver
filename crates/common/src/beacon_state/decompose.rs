use silver_common_macros::timed;

use crate::{
    SpecConfig,
    beacon_state::{
        FinalizedValidators, ValidatorsDecodeError,
        types::{
            B256, Checkpoint, EPOCHS_PER_HISTORICAL_VECTOR, EPOCHS_PER_SLASHINGS_VECTOR,
            EpochStateDelta, Eth1Data, ExecutionPayloadHeader, Finalized, HISTORICAL_ROOTS_LIMIT,
            HistoricalSummary, LongtailState, MAX_ETH1_VOTES, PENDING_CONSOLIDATIONS_LIMIT,
            PENDING_DEPOSITS_LIMIT, PENDING_PARTIAL_WITHDRAWALS_LIMIT, PROPOSER_LOOKAHEAD_SIZE,
            PendingConsolidation, PendingDeposit, PendingPartialWithdrawal, SLOTS_PER_EPOCH,
            SLOTS_PER_HISTORICAL_ROOT, SYNC_COMMITTEE_SIZE, StateDelta, SyncCommittee, Withdrawals,
        },
    },
    ssz_hash,
};

// ── SSZ checkpoint decompose ────────────────────────────────────────────────
//
// Fulu BeaconState layout. Variable-length fields store a 4-byte offset in
// the fixed part; their bodies sit contiguously past `FIXED_PART` in
// SSZ-declared order.

const ETH1_DATA_SSZ_SIZE: usize = 72;
const HISTORICAL_SUMMARY_SSZ_SIZE: usize = 64;
const PENDING_DEPOSIT_SSZ_SIZE: usize = 192;
const PENDING_PARTIAL_WITHDRAWAL_SSZ_SIZE: usize = 24;
const PENDING_CONSOLIDATION_SSZ_SIZE: usize = 16;
const EPH_FIXED_PART: usize = 584;

const HISTORICAL_SUMMARIES_LIMIT: usize = 1 << 24;

// Fixed-part byte offsets (Fulu).
const F0: usize = 0; // genesis_time: 8
const F1: usize = 8; // genesis_validators_root: 32
const F2: usize = 40; // slot: 8
const F3: usize = 48; // fork: 16
const F4: usize = 64; // latest_block_header: 112
const F5: usize = 176; // block_roots: 8192 × 32 = 262144
const F6: usize = 262_320; // state_roots: 262144
const F7_OFF: usize = 524_464; // historical_roots offset: 4
const F8: usize = 524_468; // eth1_data: 72
const F9_OFF: usize = 524_540; // eth1_data_votes offset: 4
const F10: usize = 524_544; // eth1_deposit_index: 8
const F11_OFF: usize = 524_552; // validators offset: 4
const F12_OFF: usize = 524_556; // balances offset: 4
const F13: usize = 524_560; // randao_mixes: 65536 × 32 = 2097152
const F14: usize = 2_621_712; // slashings: 8192 × 8 = 65536
const F15_OFF: usize = 2_687_248; // previous_epoch_participation offset
const F16_OFF: usize = 2_687_252; // current_epoch_participation offset
const F17: usize = 2_687_256; // justification_bits: 1
const F18: usize = 2_687_257; // previous_justified_checkpoint: 40
const F19: usize = 2_687_297; // current_justified_checkpoint
const F20: usize = 2_687_337; // finalized_checkpoint
const F21_OFF: usize = 2_687_377; // inactivity_scores offset
const F22: usize = 2_687_381; // current_sync_committee: 24624
const F23: usize = 2_712_005; // next_sync_committee: 24624
const F24_OFF: usize = 2_736_629; // latest_execution_payload_header offset
const F25: usize = 2_736_633; // next_withdrawal_index: 8
const F26: usize = 2_736_641; // next_withdrawal_validator_index: 8
const F27_OFF: usize = 2_736_649; // historical_summaries offset
const F28: usize = 2_736_653; // deposit_requests_start_index: 8
const F29: usize = 2_736_661; // deposit_balance_to_consume: 8
const F30: usize = 2_736_669; // exit_balance_to_consume: 8
const F31: usize = 2_736_677; // earliest_exit_epoch: 8
const F32: usize = 2_736_685; // consolidation_balance_to_consume: 8
const F33: usize = 2_736_693; // earliest_consolidation_epoch: 8
const F34_OFF: usize = 2_736_701; // pending_deposits offset
const F35_OFF: usize = 2_736_705; // pending_partial_withdrawals offset
const F36_OFF: usize = 2_736_709; // pending_consolidations offset
const F37: usize = 2_736_713; // proposer_lookahead: 64 × 8 = 512
const FIXED_PART: usize = 2_737_225;

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
    #[error("balances bytes {bytes} doesn't match validator count {validators} (×8)")]
    BalancesLenMismatch { bytes: usize, validators: usize },
    #[error("previous_epoch_participation bytes {bytes} != validator count {validators}")]
    PrevParticipationLenMismatch { bytes: usize, validators: usize },
    #[error("current_epoch_participation bytes {bytes} != validator count {validators}")]
    CurParticipationLenMismatch { bytes: usize, validators: usize },
    #[error("inactivity_scores bytes {bytes} doesn't match validator count {validators} (×8)")]
    InactivityLenMismatch { bytes: usize, validators: usize },
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
}

#[inline]
fn u32_le(s: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(s[off..off + 4].try_into().unwrap())
}

#[inline]
fn u64_le(s: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(s[off..off + 8].try_into().unwrap())
}

#[inline]
fn b256(s: &[u8], off: usize) -> B256 {
    s[off..off + 32].try_into().unwrap()
}

fn read_checkpoint(s: &[u8], off: usize) -> Checkpoint {
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

fn read_execution_payload_header(
    ssz: &[u8],
    start: usize,
    end: usize,
    out: &mut ExecutionPayloadHeader,
) -> Result<(), DecomposeError> {
    let eph = &ssz[start..end];
    if eph.len() < EPH_FIXED_PART {
        return Err(DecomposeError::EphTruncated { len: eph.len(), need: EPH_FIXED_PART });
    }

    out.parent_hash = b256(eph, 0);
    out.fee_recipient.copy_from_slice(&eph[32..52]);
    out.state_root = b256(eph, 52);
    out.receipts_root = b256(eph, 84);
    out.logs_bloom.copy_from_slice(&eph[116..372]);
    out.prev_randao = b256(eph, 372);
    out.block_number = u64_le(eph, 404);
    out.gas_limit = u64_le(eph, 412);
    out.gas_used = u64_le(eph, 420);
    out.timestamp = u64_le(eph, 428);
    out.base_fee_per_gas = b256(eph, 440);
    out.block_hash = b256(eph, 472);
    out.transactions_root = b256(eph, 504);
    out.withdrawals_root = b256(eph, 536);
    out.blob_gas_used = u64_le(eph, 568);
    out.excess_blob_gas = u64_le(eph, 576);

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

    Ok(())
}

/// Validated variable-field offsets, monotonic and within `ssz`.
struct Offsets {
    historical_roots: usize,
    eth1_votes: usize,
    validators: usize,
    balances: usize,
    prev_participation: usize,
    cur_participation: usize,
    inactivity: usize,
    eph: usize,
    hist_summaries: usize,
    pending_deposits: usize,
    pending_withdrawals: usize,
    pending_consolidations: usize,
}

impl Offsets {
    fn read_and_validate(ssz: &[u8]) -> Result<Self, DecomposeError> {
        let raw = [
            u32_le(ssz, F7_OFF) as usize,
            u32_le(ssz, F9_OFF) as usize,
            u32_le(ssz, F11_OFF) as usize,
            u32_le(ssz, F12_OFF) as usize,
            u32_le(ssz, F15_OFF) as usize,
            u32_le(ssz, F16_OFF) as usize,
            u32_le(ssz, F21_OFF) as usize,
            u32_le(ssz, F24_OFF) as usize,
            u32_le(ssz, F27_OFF) as usize,
            u32_le(ssz, F34_OFF) as usize,
            u32_le(ssz, F35_OFF) as usize,
            u32_le(ssz, F36_OFF) as usize,
        ];

        if raw[0] < FIXED_PART {
            return Err(DecomposeError::FirstOffsetBeforeFixedPart {
                off: raw[0],
                fixed: FIXED_PART,
            });
        }
        for (i, w) in raw.windows(2).enumerate() {
            if w[0] > w[1] {
                return Err(DecomposeError::NonMonotonicOffsets { i, a: w[0], b: w[1] });
            }
        }
        if *raw.last().unwrap() > ssz.len() {
            return Err(DecomposeError::OffsetPastEnd { off: *raw.last().unwrap(), len: ssz.len() });
        }

        Ok(Self {
            historical_roots: raw[0],
            eth1_votes: raw[1],
            validators: raw[2],
            balances: raw[3],
            prev_participation: raw[4],
            cur_participation: raw[5],
            inactivity: raw[6],
            eph: raw[7],
            hist_summaries: raw[8],
            pending_deposits: raw[9],
            pending_withdrawals: raw[10],
            pending_consolidations: raw[11],
        })
    }
}

impl Finalized {
    /// Decompose a Fulu-encoded BeaconState SSZ blob into `self`.
    #[timed]
    pub fn decompose(&mut self, ssz: &[u8], cfg: &SpecConfig) -> Result<(), DecomposeError> {
        if ssz.len() < FIXED_PART {
            return Err(DecomposeError::TruncatedFixedPart { len: ssz.len(), need: FIXED_PART });
        }
        let offsets = Offsets::read_and_validate(ssz)?;

        self.clear_variable_buffers();

        self.fill_immutable(ssz, cfg);
        self.fill_slot_scalars(ssz);
        self.fill_block_state_roots(ssz);
        self.fill_epoch_state(ssz);
        self.fill_derived_caches();

        read_sync_committee(ssz, F22, "current", &mut self.longtail.current_sync_committee)?;
        read_sync_committee(ssz, F23, "next", &mut self.longtail.next_sync_committee)?;

        self.fill_validator_layers(ssz, &offsets)?;

        read_execution_payload_header(
            ssz,
            offsets.eph,
            offsets.hist_summaries,
            &mut self.slot.slot.latest_execution_payload_header,
        )?;

        self.fill_eth1_votes(ssz, &offsets)?;
        self.fill_historical_roots_hash(ssz, &offsets)?;
        self.fill_historical_summaries(ssz, &offsets)?;
        self.fill_pending_deposits(ssz, &offsets)?;
        self.fill_pending_partial_withdrawals(ssz, &offsets)?;
        self.fill_pending_consolidations(ssz, &offsets)?;

        self.fill_sync_committee_indices();

        Ok(())
    }

    fn clear_variable_buffers(&mut self) {
        self.slot.slot.eth1_votes.clear();
        self.longtail.historical_summaries.clear();
        self.pending.pending_deposits.clear();
        self.pending.pending_partial_withdrawals.clear();
        self.pending.pending_consolidations.clear();
    }

    #[timed]
    fn fill_immutable(&mut self, ssz: &[u8], cfg: &SpecConfig) {
        self.immutable.genesis_time = u64_le(ssz, F0);
        self.immutable.genesis_validators_root = b256(ssz, F1);
        self.immutable.fork = crate::beacon_state::types::Fork {
            previous_version: ssz[F3..F3 + 4].try_into().unwrap(),
            current_version: ssz[F3 + 4..F3 + 8].try_into().unwrap(),
            epoch: u64_le(ssz, F3 + 8),
        };
        self.immutable.genesis_fork_version = cfg.genesis_fork_version;
        self.immutable.capella_fork_version = cfg.capella_fork_version;
    }

    #[timed]
    fn fill_slot_scalars(&mut self, ssz: &[u8]) {
        let sl = &mut self.slot.slot;
        sl.slot = u64_le(ssz, F2);
        sl.latest_block_header.slot = u64_le(ssz, F4);
        sl.latest_block_header.proposer_index = u64_le(ssz, F4 + 8);
        sl.latest_block_header.parent_root = b256(ssz, F4 + 16);
        sl.latest_block_header.state_root = b256(ssz, F4 + 48);
        sl.latest_block_header.body_root = b256(ssz, F4 + 80);
        sl.eth1_data = Eth1Data {
            deposit_root: b256(ssz, F8),
            deposit_count: u64_le(ssz, F8 + 32),
            block_hash: b256(ssz, F8 + 40),
        };
        sl.eth1_deposit_index = u64_le(ssz, F10);
        sl.next_withdrawal_index = u64_le(ssz, F25);
        sl.next_withdrawal_validator_index = u64_le(ssz, F26);
        sl.deposit_requests_start_index = u64_le(ssz, F28);
        sl.exit_balance_to_consume = u64_le(ssz, F30);
        sl.earliest_exit_epoch = u64_le(ssz, F31);
        sl.consolidation_balance_to_consume = u64_le(ssz, F32);
        sl.earliest_consolidation_epoch = u64_le(ssz, F33);
    }

    #[timed]
    fn fill_block_state_roots(&mut self, ssz: &[u8]) {
        // Alignment-1 bulk copy (B256 has align 1, see assertion above).
        let block_src: &[B256] = unsafe {
            std::slice::from_raw_parts(ssz[F5..].as_ptr().cast::<B256>(), SLOTS_PER_HISTORICAL_ROOT)
        };
        self.slot.block_roots.copy_from_slice(block_src);
        let state_src: &[B256] = unsafe {
            std::slice::from_raw_parts(ssz[F6..].as_ptr().cast::<B256>(), SLOTS_PER_HISTORICAL_ROOT)
        };
        self.slot.state_roots.copy_from_slice(state_src);
    }

    #[timed]
    fn fill_epoch_state(&mut self, ssz: &[u8]) {
        let randao_src: &[B256] = unsafe {
            std::slice::from_raw_parts(
                ssz[F13..].as_ptr().cast::<B256>(),
                EPOCHS_PER_HISTORICAL_VECTOR,
            )
        };
        self.epoch.randao_mixes.copy_from_slice(randao_src);

        for i in 0..EPOCHS_PER_SLASHINGS_VECTOR {
            self.epoch.slashings[i] = u64_le(ssz, F14 + i * 8);
        }

        let est = &mut self.epoch.state;
        for i in 0..PROPOSER_LOOKAHEAD_SIZE {
            est.proposer_lookahead[i] = u64_le(ssz, F37 + i * 8);
        }
        est.justification_bits = ssz[F17] & 0x0F;
        est.previous_justified_checkpoint = read_checkpoint(ssz, F18);
        est.current_justified_checkpoint = read_checkpoint(ssz, F19);
        est.finalized_checkpoint = read_checkpoint(ssz, F20);
        est.deposit_balance_to_consume = u64_le(ssz, F29);
    }

    #[timed]
    fn fill_derived_caches(&mut self) {
        let current_epoch = self.slot.slot.slot / SLOTS_PER_EPOCH;
        self.slot.slot.randao_mix_current =
            self.epoch.randao_mixes[current_epoch as usize % EPOCHS_PER_HISTORICAL_VECTOR];
        self.slot.slot.current_epoch_slashings =
            self.epoch.slashings[current_epoch as usize % EPOCHS_PER_SLASHINGS_VECTOR];
    }

    #[timed]
    fn fill_validator_layers(&mut self, ssz: &[u8], o: &Offsets) -> Result<(), DecomposeError> {
        self.validators = FinalizedValidators::try_new(&ssz[o.validators..o.balances])?;
        let n = self.validators.validator_count();

        let bal_bytes = &ssz[o.balances..o.prev_participation];
        if !bal_bytes.len().is_multiple_of(8) || bal_bytes.len() / 8 != n {
            return Err(DecomposeError::BalancesLenMismatch {
                bytes: bal_bytes.len(),
                validators: n,
            });
        }
        let balances = self.balances.slice_mut();
        for (i, b) in balances.iter_mut().enumerate().take(n) {
            *b = u64_le(bal_bytes, i * 8);
        }

        let prev_part = &ssz[o.prev_participation..o.cur_participation];
        if prev_part.len() != n {
            return Err(DecomposeError::PrevParticipationLenMismatch {
                bytes: prev_part.len(),
                validators: n,
            });
        }
        self.previous_participation.slice_mut()[..n].copy_from_slice(prev_part);

        let cur_part = &ssz[o.cur_participation..o.inactivity];
        if cur_part.len() != n {
            return Err(DecomposeError::CurParticipationLenMismatch {
                bytes: cur_part.len(),
                validators: n,
            });
        }
        self.current_participation.slice_mut()[..n].copy_from_slice(cur_part);

        let inact_bytes = &ssz[o.inactivity..o.eph];
        if !inact_bytes.len().is_multiple_of(8) || inact_bytes.len() / 8 != n {
            return Err(DecomposeError::InactivityLenMismatch {
                bytes: inact_bytes.len(),
                validators: n,
            });
        }
        let inact = self.inactivity_scores.slice_mut();
        for (i, s) in inact.iter_mut().enumerate().take(n) {
            *s = u64_le(inact_bytes, i * 8);
        }

        Ok(())
    }

    #[timed]
    fn fill_eth1_votes(&mut self, ssz: &[u8], o: &Offsets) -> Result<(), DecomposeError> {
        let votes_bytes = &ssz[o.eth1_votes..o.validators];
        if !votes_bytes.len().is_multiple_of(ETH1_DATA_SSZ_SIZE) {
            return Err(DecomposeError::Eth1VotesLenNotMultiple { len: votes_bytes.len() });
        }
        let vote_count = votes_bytes.len() / ETH1_DATA_SSZ_SIZE;
        if vote_count > MAX_ETH1_VOTES {
            return Err(DecomposeError::TooManyEth1Votes { n: vote_count, max: MAX_ETH1_VOTES });
        }
        for i in 0..vote_count {
            let v = &votes_bytes[i * ETH1_DATA_SSZ_SIZE..];
            self.slot.slot.eth1_votes.push(read_eth1_data(v));
        }
        Ok(())
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
        self.immutable.historical_roots_hash = ssz_hash::mix_in_length(&hr_root, hr_count);
        Ok(())
    }

    #[timed]
    fn fill_historical_summaries(&mut self, ssz: &[u8], o: &Offsets) -> Result<(), DecomposeError> {
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
        self.longtail.historical_summaries.reserve_exact(hs_count);
        for i in 0..hs_count {
            let s = &hs_bytes[i * HISTORICAL_SUMMARY_SSZ_SIZE..];
            self.longtail.historical_summaries.push(HistoricalSummary {
                block_summary_root: b256(s, 0),
                state_summary_root: b256(s, 32),
            });
        }
        Ok(())
    }

    #[timed]
    fn fill_pending_deposits(&mut self, ssz: &[u8], o: &Offsets) -> Result<(), DecomposeError> {
        let pd_bytes = &ssz[o.pending_deposits..o.pending_withdrawals];
        if !pd_bytes.len().is_multiple_of(PENDING_DEPOSIT_SSZ_SIZE) {
            return Err(DecomposeError::PendingDepositsLenNotMultiple { len: pd_bytes.len() });
        }
        let pd_count = pd_bytes.len() / PENDING_DEPOSIT_SSZ_SIZE;
        if pd_count > PENDING_DEPOSITS_LIMIT {
            return Err(DecomposeError::TooManyPendingDeposits {
                n: pd_count,
                max: PENDING_DEPOSITS_LIMIT,
            });
        }
        self.pending.pending_deposits.reserve_exact(pd_count);
        for i in 0..pd_count {
            let d = &pd_bytes[i * PENDING_DEPOSIT_SSZ_SIZE..];
            self.pending.pending_deposits.push(read_pending_deposit(d));
        }
        Ok(())
    }

    #[timed]
    fn fill_pending_partial_withdrawals(
        &mut self,
        ssz: &[u8],
        o: &Offsets,
    ) -> Result<(), DecomposeError> {
        let pw_bytes = &ssz[o.pending_withdrawals..o.pending_consolidations];
        if !pw_bytes.len().is_multiple_of(PENDING_PARTIAL_WITHDRAWAL_SSZ_SIZE) {
            return Err(DecomposeError::PendingWithdrawalsLenNotMultiple { len: pw_bytes.len() });
        }
        let pw_count = pw_bytes.len() / PENDING_PARTIAL_WITHDRAWAL_SSZ_SIZE;
        if pw_count > PENDING_PARTIAL_WITHDRAWALS_LIMIT {
            return Err(DecomposeError::TooManyPendingWithdrawals {
                n: pw_count,
                max: PENDING_PARTIAL_WITHDRAWALS_LIMIT,
            });
        }
        self.pending.pending_partial_withdrawals.reserve_exact(pw_count);
        for i in 0..pw_count {
            let w = &pw_bytes[i * PENDING_PARTIAL_WITHDRAWAL_SSZ_SIZE..];
            self.pending.pending_partial_withdrawals.push(PendingPartialWithdrawal {
                index: u64_le(w, 0),
                amount: u64_le(w, 8),
                withdrawable_epoch: u64_le(w, 16),
            });
        }
        Ok(())
    }

    #[timed]
    fn fill_pending_consolidations(
        &mut self,
        ssz: &[u8],
        o: &Offsets,
    ) -> Result<(), DecomposeError> {
        let pc_bytes = &ssz[o.pending_consolidations..];
        if !pc_bytes.len().is_multiple_of(PENDING_CONSOLIDATION_SSZ_SIZE) {
            return Err(DecomposeError::PendingConsolidationsLenNotMultiple { len: pc_bytes.len() });
        }
        let pc_count = pc_bytes.len() / PENDING_CONSOLIDATION_SSZ_SIZE;
        if pc_count > PENDING_CONSOLIDATIONS_LIMIT {
            return Err(DecomposeError::TooManyPendingConsolidations {
                n: pc_count,
                max: PENDING_CONSOLIDATIONS_LIMIT,
            });
        }
        self.pending.pending_consolidations.reserve_exact(pc_count);
        for i in 0..pc_count {
            let c = &pc_bytes[i * PENDING_CONSOLIDATION_SSZ_SIZE..];
            self.pending.pending_consolidations.push(PendingConsolidation {
                source_index: u64_le(c, 0),
                target_index: u64_le(c, 8),
            });
        }
        Ok(())
    }

    #[timed]
    fn fill_sync_committee_indices(&mut self) {
        for (i, pk) in self.longtail.current_sync_committee.pubkeys.iter().enumerate() {
            self.longtail.sync_committee_indices[i] =
                self.validators.find_by_pubkey(pk).map(|i| i as u32).unwrap_or(u32::MAX);
        }
    }
}

fn read_eth1_data(s: &[u8]) -> Eth1Data {
    Eth1Data { deposit_root: b256(s, 0), deposit_count: u64_le(s, 32), block_hash: b256(s, 40) }
}

fn read_pending_deposit(d: &[u8]) -> PendingDeposit {
    let mut pubkey = [0u8; 48];
    pubkey.copy_from_slice(&d[..48]);
    let mut signature = [0u8; 96];
    signature.copy_from_slice(&d[88..184]);
    PendingDeposit {
        pubkey,
        withdrawal_credentials: Withdrawals(b256(d, 48)),
        amount: u64_le(d, 80),
        signature,
        slot: u64_le(d, 184),
    }
}

impl Finalized {
    /// Fold `delta` into the base. `delta.slot.slot` becomes the new
    /// finalized slot.
    ///
    /// Entry args supply the per-tier delta state when the fork has crossed
    /// a boundary; the caller resolves `epoch_idx` / `longtail_idx` against
    /// the ring buffers before invoking. When the fork is anchored, pass
    /// `None` for the corresponding tier — it is unchanged from this base.
    #[timed]
    pub fn apply_delta(
        &mut self,
        delta: &StateDelta,
        epoch_entry: Option<&EpochStateDelta>,
        longtail_entry: Option<&LongtailState>,
    ) {
        let old_fin_slot = self.slot.slot.slot as usize;
        let old_fin_epoch = old_fin_slot / SLOTS_PER_EPOCH as usize;

        self.apply_slot_tier(delta, old_fin_slot);
        self.apply_epoch_tier(delta, epoch_entry, old_fin_epoch);
        self.apply_longtail_tier(delta, longtail_entry);
        self.apply_validator_layers(delta);
        self.apply_pending_queues(delta);
    }

    #[timed]
    fn apply_slot_tier(&mut self, delta: &StateDelta, old_fin_slot: usize) {
        // SlotState is Copy; bulk-copy then handle circular buffers.
        self.slot.slot = delta.slot.slot;

        let block_cap = self.slot.block_roots.len();
        debug_assert!(
            delta.slot.block_roots.len() <= block_cap,
            "delta block_roots ({}) exceeds ring cap ({})",
            delta.slot.block_roots.len(),
            block_cap
        );
        for (i, r) in delta.slot.block_roots.iter().enumerate() {
            self.slot.block_roots[(old_fin_slot + i) % block_cap] = *r;
        }
        let state_cap = self.slot.state_roots.len();
        debug_assert!(
            delta.slot.state_roots.len() <= state_cap,
            "delta state_roots ({}) exceeds ring cap ({})",
            delta.slot.state_roots.len(),
            state_cap
        );
        for (i, r) in delta.slot.state_roots.iter().enumerate() {
            self.slot.state_roots[(old_fin_slot + i) % state_cap] = *r;
        }
    }

    /// Apply only when the fork crossed an epoch boundary.
    #[timed]
    fn apply_epoch_tier(
        &mut self,
        delta: &StateDelta,
        epoch_entry: Option<&EpochStateDelta>,
        old_fin_epoch: usize,
    ) {
        debug_assert_eq!(
            epoch_entry.is_some(),
            delta.epoch_idx.is_some(),
            "epoch_entry and delta.epoch_idx must agree",
        );
        let Some(e) = epoch_entry else { return };

        let hv = self.epoch.randao_mixes.len();
        debug_assert!(e.randao_mixes.len() <= hv, "epoch randao_mixes exceeds ring cap");
        for (i, m) in e.randao_mixes.iter().enumerate() {
            self.epoch.randao_mixes[(old_fin_epoch + i) % hv] = *m;
        }
        let sv = self.epoch.slashings.len();
        debug_assert!(e.slashings.len() <= sv, "epoch slashings exceeds ring cap");
        for (i, sl) in e.slashings.iter().enumerate() {
            self.epoch.slashings[(old_fin_epoch + i) % sv] = *sl;
        }
        self.epoch.state = e.state;
    }

    /// Apply only when the fork crossed a 256-epoch sync-committee rotation.
    #[timed]
    fn apply_longtail_tier(&mut self, delta: &StateDelta, longtail_entry: Option<&LongtailState>) {
        debug_assert_eq!(
            longtail_entry.is_some(),
            delta.longtail_idx.is_some(),
            "longtail_entry and delta.longtail_idx must agree",
        );
        let Some(lt) = longtail_entry else { return };

        self.longtail.current_sync_committee = lt.current_sync_committee;
        self.longtail.next_sync_committee = lt.next_sync_committee;
        self.longtail.sync_committee_indices = lt.sync_committee_indices;
        self.longtail.historical_summaries.extend_from_slice(&lt.historical_summaries);
    }

    #[timed]
    fn apply_validator_layers(&mut self, delta: &StateDelta) {
        // Identity (append + sparse edits + hash overlay).
        delta.validators.promote_into_base(&mut self.validators);

        // Sibling columns (sparse edits only).
        for &(idx, val) in &delta.balances.edits {
            self.balances.slice_mut()[idx as usize] = val;
        }
        for &(idx, val) in &delta.previous_participation.edits {
            self.previous_participation.slice_mut()[idx as usize] = val;
        }
        for &(idx, val) in &delta.current_participation.edits {
            self.current_participation.slice_mut()[idx as usize] = val;
        }
        for &(idx, val) in &delta.inactivity_scores.edits {
            self.inactivity_scores.slice_mut()[idx as usize] = val;
        }
    }

    /// Drain promoted prefix, append new entries.
    #[timed]
    fn apply_pending_queues(&mut self, delta: &StateDelta) {
        let pq = &delta.pending;

        let n = (pq.deposits_drain_offset as usize).min(self.pending.pending_deposits.len());
        self.pending.pending_deposits.drain(..n);
        self.pending.pending_deposits.extend_from_slice(&pq.deposits_appended);

        let n = (pq.partial_withdrawals_drain_offset as usize)
            .min(self.pending.pending_partial_withdrawals.len());
        self.pending.pending_partial_withdrawals.drain(..n);
        self.pending
            .pending_partial_withdrawals
            .extend_from_slice(&pq.partial_withdrawals_appended);

        let n = (pq.consolidations_drain_offset as usize)
            .min(self.pending.pending_consolidations.len());
        self.pending.pending_consolidations.drain(..n);
        self.pending.pending_consolidations.extend_from_slice(&pq.consolidations_appended);
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::SpecConfig;

    // EF fixture: a known-valid Fulu pre-state from sanity/blocks tests.
    // Path is relative to `crates/common/`; gracefully skipped when the
    // consensus-spec-tests checkout is missing.
    const EF_PRE_STATE: &str = concat!(
        "../beacon_state/consensus-spec-tests/tests/mainnet/fulu/sanity/blocks/",
        "pyspec_tests/deposit_top_up/pre.ssz_snappy",
    );

    #[test]
    fn decompose_ef_sanity_pre_state() {
        let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), EF_PRE_STATE].iter().collect();
        let Ok(compressed) = std::fs::read(&path) else {
            eprintln!("skipping: {} not found", path.display());
            return;
        };
        let ssz = snap::raw::Decoder::new().decompress_vec(&compressed).expect("snappy decode");
        assert!(ssz.len() >= FIXED_PART);

        let cfg = SpecConfig::mainnet();
        let mut fin = Box::<Finalized>::default();
        fin.decompose(&ssz, &cfg).expect("decompose");

        // Re-read the raw slot from the SSZ fixed part to cross-check.
        let raw_slot = u64_le(&ssz, F2);
        assert_eq!(fin.slot.slot.slot, raw_slot);
        let cur_epoch = raw_slot / SLOTS_PER_EPOCH;

        // Validator columnar arrays should be populated and consistent.
        let n = fin.validators.validator_count();
        assert!(n > 0, "no validators decoded");
        assert_eq!(fin.validators.index_len(), n);

        // Spec invariant: finalized ≤ previous_justified ≤ current_justified
        //                          ≤ current_epoch.
        let est = &fin.epoch.state;
        assert!(est.finalized_checkpoint.epoch <= est.previous_justified_checkpoint.epoch);
        assert!(est.previous_justified_checkpoint.epoch <= est.current_justified_checkpoint.epoch);
        assert!(est.current_justified_checkpoint.epoch <= cur_epoch);

        // Derived caches match the resolved circular-buffer entries.
        let hv = fin.epoch.randao_mixes.len();
        assert_eq!(
            fin.slot.slot.randao_mix_current,
            fin.epoch.randao_mixes[cur_epoch as usize % hv]
        );
        let sv = fin.epoch.slashings.len();
        assert_eq!(
            fin.slot.slot.current_epoch_slashings,
            fin.epoch.slashings[cur_epoch as usize % sv]
        );

        // Sync-committee indices either resolve to a real validator or are
        // sentinel u32::MAX (committee pubkey not in the registry).
        for (i, idx) in fin.longtail.sync_committee_indices.iter().enumerate() {
            if *idx != u32::MAX {
                assert!((*idx as usize) < n);
                let pk = &fin.longtail.current_sync_committee.pubkeys[i];
                assert_eq!(fin.validators.find_by_pubkey(pk).map(|i| i as u32), Some(*idx));
            }
        }

        // Decompose is deterministic.
        let mut fin2 = Box::<Finalized>::default();
        fin2.decompose(&ssz, &cfg).expect("decompose 2");
        assert_eq!(fin2.slot.slot.slot, fin.slot.slot.slot);
        assert_eq!(fin2.validators.validator_count(), n);
        assert_eq!(fin2.immutable.genesis_validators_root, fin.immutable.genesis_validators_root);
        assert_eq!(fin2.immutable.historical_roots_hash, fin.immutable.historical_roots_hash);
    }
}
