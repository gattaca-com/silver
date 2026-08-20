//! Canonical SSZ re-encoding of the finalized base — the checkpoint persist's
//! write half. Mirrors `decompose` (which owns the read half): the SSZ layout
//! constants stay private to these two modules, and every section reads one
//! group's finalized base. Growth-prone Vec bases (pending, longtail
//! `historical_summaries`) are read under their group's promote barrier; all
//! other bases are allocation-stable and rely on the checkpoint version
//! protocol (`CheckpointCursor`) to discard torn bytes.

use std::io::{self, Write};

use blst::min_pk::PublicKey;

use crate::{
    BeaconState,
    decompose::{FULU_FIXED_PART, gloas::GLOAS_FIXED_PART},
    types::{B256, Checkpoint, Eth1Data, SyncCommittee},
};

// SSZ-serialised sizes of the fixed-width records (Fulu); mirror `decompose`.
const ETH1_DATA_SSZ: usize = 72;
const VALIDATOR_SSZ: usize = 121;
const HIST_SUMMARY_SSZ: usize = 64;
const PENDING_DEPOSIT_SSZ: usize = 192;
const PENDING_WITHDRAWAL_SSZ: usize = 24;
const PENDING_CONSOLIDATION_SSZ: usize = 16;
/// `ExecutionPayloadHeader` fixed part; `extra_data` (≤32 B) follows at this
/// offset.
const EPH_FIXED: usize = 584;

/// Number of variable-length fields in the Fulu `BeaconState`.
pub(crate) const FULU_VAR_LEN_SECTIONS: usize = 12;

/// Number of checkpoint sections: the fixed part + the 12 variable bodies.
pub const FULU_CHECKPOINT_SECTIONS: usize = 1 + FULU_VAR_LEN_SECTIONS;

/// Variable-length fields in the Gloas `BeaconState`: Fulu's 12 minus the
/// (now fixed) `execution_payload_header`, plus `builders`,
/// `builder_pending_withdrawals`, `latest_execution_payload_bid`,
/// `payload_expected_withdrawals`.
pub(crate) const GLOAS_VAR_LEN_SECTIONS: usize = 15;

/// Number of checkpoint sections for Gloas: the fixed part + the 15 var bodies.
pub const GLOAS_CHECKPOINT_SECTIONS: usize = 1 + GLOAS_VAR_LEN_SECTIONS;

const BUILDER_PENDING_WITHDRAWAL_SSZ: usize = 36;
const WITHDRAWAL_SSZ: usize = 44;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Section {
    FixedPart,
    HistoricalRoots,
    Eth1Votes,
    Validators,
    Balances,
    PreviousParticipation,
    CurrentParticipation,
    InactivityScores,
    ExecutionPayloadHeader,
    HistoricalSummaries,
    PendingDeposits,
    PendingPartialWithdrawals,
    PendingConsolidations,
    Builders,
    BuilderPendingWithdrawals,
    LatestExecutionPayloadBid,
    PayloadExpectedWithdrawals,
}

impl Section {
    pub(crate) const FULU: [Section; FULU_CHECKPOINT_SECTIONS] = [
        Section::FixedPart,
        Section::HistoricalRoots,
        Section::Eth1Votes,
        Section::Validators,
        Section::Balances,
        Section::PreviousParticipation,
        Section::CurrentParticipation,
        Section::InactivityScores,
        Section::ExecutionPayloadHeader,
        Section::HistoricalSummaries,
        Section::PendingDeposits,
        Section::PendingPartialWithdrawals,
        Section::PendingConsolidations,
    ];

    pub(crate) const GLOAS: [Section; GLOAS_CHECKPOINT_SECTIONS] = [
        Section::FixedPart,
        Section::HistoricalRoots,
        Section::Eth1Votes,
        Section::Validators,
        Section::Balances,
        Section::PreviousParticipation,
        Section::CurrentParticipation,
        Section::InactivityScores,
        Section::HistoricalSummaries,
        Section::PendingDeposits,
        Section::PendingPartialWithdrawals,
        Section::PendingConsolidations,
        Section::Builders,
        Section::BuilderPendingWithdrawals,
        Section::LatestExecutionPayloadBid,
        Section::PayloadExpectedWithdrawals,
    ];
}

/// Validators emitted per checkpoint chunk: `131_072 * 121 B ≈ 15 MiB`, on par
/// with the largest single-turn sections (balances/inactivity), so the
/// validators section no longer dominates a `file_io` turn.
const VALIDATORS_PER_CHUNK: usize = 1 << 17;

#[inline]
fn w_u64<W: Write>(w: &mut W, v: u64) -> io::Result<()> {
    w.write_all(&v.to_le_bytes())
}

#[inline]
fn w_u32<W: Write>(w: &mut W, v: u32) -> io::Result<()> {
    w.write_all(&v.to_le_bytes())
}

/// Bulk-write a contiguous `[B256]` as raw bytes. `B256` is `[u8; 32]`
/// (align 1), so the reinterpret is sound and endianness-agnostic — matching
/// the inverse casts in `decompose`.
#[inline]
pub(crate) fn write_b256_slice<W: Write>(w: &mut W, s: &[B256]) -> io::Result<()> {
    let bytes = unsafe { std::slice::from_raw_parts(s.as_ptr().cast::<u8>(), s.len() * 32) };
    w.write_all(bytes)
}

impl BeaconState {
    /// Byte lengths of the 12 variable-length fields, in SSZ-declared order.
    pub(crate) fn var_len_section_lens_fulu(&self) -> [usize; FULU_VAR_LEN_SECTIONS] {
        let n = self.validators.finalized().validator_count();
        let dep = self.pending.deposits.with_finalized_locked(|q| q.len());
        let wdr = self.pending.partial_withdrawals.with_finalized_locked(|q| q.len());
        let con = self.pending.consolidations.with_finalized_locked(|q| q.len());
        let summaries = self.longtail.with_finalized_locked(|lt| lt.historical_summaries_len());
        let sl = self.slot_states.finalized().state();
        [
            self.immutable.historical_roots.len() * 32,
            self.eth1.finalized().len() * ETH1_DATA_SSZ,
            n * VALIDATOR_SSZ,
            n * 8,
            n,
            n,
            n * 8,
            EPH_FIXED + sl.latest_execution_payload_header.extra_data_len as usize,
            summaries * HIST_SUMMARY_SSZ,
            dep * PENDING_DEPOSIT_SSZ,
            wdr * PENDING_WITHDRAWAL_SSZ,
            con * PENDING_CONSOLIDATION_SSZ,
        ]
    }

    /// Byte lengths of the 15 Gloas variable-length fields, in SSZ-declared
    /// order (offset-slot order): the 11 Fulu-shared bodies (no
    /// `execution_payload_header`) then the four Gloas-only bodies.
    pub(crate) fn var_len_section_lens_gloas(&self) -> [usize; GLOAS_VAR_LEN_SECTIONS] {
        let n = self.validators.finalized().validator_count();
        let dep = self.pending.deposits.with_finalized_locked(|q| q.len());
        let wdr = self.pending.partial_withdrawals.with_finalized_locked(|q| q.len());
        let con = self.pending.consolidations.with_finalized_locked(|q| q.len());
        let bpw = self.pending.builder_withdrawals.with_finalized_locked(|q| q.len());
        let summaries = self.longtail.with_finalized_locked(|lt| lt.historical_summaries_len());
        let sl = self.slot_states.finalized().state();
        [
            self.immutable.historical_roots.len() * 32,
            self.eth1.finalized().len() * ETH1_DATA_SSZ,
            n * VALIDATOR_SSZ,
            n * 8,
            n,
            n,
            n * 8,
            summaries * HIST_SUMMARY_SSZ,
            dep * PENDING_DEPOSIT_SSZ,
            wdr * PENDING_WITHDRAWAL_SSZ,
            con * PENDING_CONSOLIDATION_SSZ,
            self.builders.finalized().ssz_len(),
            bpw * BUILDER_PENDING_WITHDRAWAL_SSZ,
            sl.latest_execution_payload_bid.ssz_len(),
            sl.payload_expected_withdrawals.len() * WITHDRAWAL_SSZ,
        ]
    }

    /// Absolute byte offsets of the variable bodies (the values written into
    /// the fixed part's offset slots), derived from a section-length snapshot.
    pub(crate) fn offsets_from_lens_fulu(
        lens: &[usize; FULU_VAR_LEN_SECTIONS],
    ) -> [u32; FULU_VAR_LEN_SECTIONS] {
        Self::offsets_with_base(lens, FULU_FIXED_PART)
    }

    fn offsets_from_lens_gloas(
        lens: &[usize; GLOAS_VAR_LEN_SECTIONS],
    ) -> [u32; GLOAS_VAR_LEN_SECTIONS] {
        Self::offsets_with_base(lens, GLOAS_FIXED_PART)
    }

    fn offsets_with_base<const N: usize>(lens: &[usize; N], base: usize) -> [u32; N] {
        let mut offs = [0u32; N];
        let mut acc = base;
        for (o, len) in offs.iter_mut().zip(lens) {
            *o = u32::try_from(acc).expect("ssz variable offset exceeds u32");
            acc += len;
        }
        offs
    }

    /// Total SSZ length of the encoded state.
    pub fn ssz_len(&self) -> usize {
        if self.is_finalized_post_gloas() {
            GLOAS_FIXED_PART + self.var_len_section_lens_gloas().iter().sum::<usize>()
        } else {
            FULU_FIXED_PART + self.var_len_section_lens_fulu().iter().sum::<usize>()
        }
    }

    /// Fork-selected checkpoint section list for the streaming cursor.
    pub(crate) fn checkpoint_sections(&self) -> &'static [Section] {
        if self.is_finalized_post_gloas() { &Section::GLOAS } else { &Section::FULU }
    }

    /// Variable-body offsets for the streaming checkpoint cursor, widened to
    /// the Gloas array; Fulu fills only the leading [`VAR_LEN_SECTIONS`].
    pub(crate) fn checkpoint_offsets(&self) -> [u32; GLOAS_VAR_LEN_SECTIONS] {
        let mut out = [0u32; GLOAS_VAR_LEN_SECTIONS];
        if self.is_finalized_post_gloas() {
            out = Self::offsets_from_lens_gloas(&self.var_len_section_lens_gloas());
        } else {
            out[..FULU_VAR_LEN_SECTIONS]
                .copy_from_slice(&Self::offsets_from_lens_fulu(&self.var_len_section_lens_fulu()));
        }
        out
    }

    #[cfg(test)]
    pub(crate) fn var_offsets_fulu(&self) -> [u32; FULU_VAR_LEN_SECTIONS] {
        Self::offsets_from_lens_fulu(&self.var_len_section_lens_fulu())
    }

    pub fn encode_ssz(&self, w: &mut Vec<u8>) -> io::Result<()> {
        if self.is_finalized_post_gloas() {
            self.encode_ssz_gloas(w)
        } else {
            self.encode_ssz_fulu(w)
        }
    }

    fn encode_ssz_fulu(&self, w: &mut Vec<u8>) -> io::Result<()> {
        let lens = self.var_len_section_lens_fulu();
        w.reserve(FULU_FIXED_PART + lens.iter().sum::<usize>());
        let offsets = Self::offsets_from_lens_fulu(&lens);
        for section in Section::FULU {
            self.write_section(section, &offsets, w)?;
        }
        Ok(())
    }

    fn encode_ssz_gloas(&self, w: &mut Vec<u8>) -> io::Result<()> {
        let lens = self.var_len_section_lens_gloas();
        w.reserve(GLOAS_FIXED_PART + lens.iter().sum::<usize>());
        let offsets = Self::offsets_from_lens_gloas(&lens);
        for section in Section::GLOAS {
            self.write_section(section, &offsets, w)?;
        }
        Ok(())
    }

    pub(crate) fn write_section<W: Write>(
        &self,
        section: Section,
        offsets: &[u32],
        w: &mut W,
    ) -> io::Result<()> {
        match section {
            Section::FixedPart => {
                if self.is_finalized_post_gloas() {
                    self.write_fixed_part_gloas(w, offsets)
                } else {
                    self.write_fixed_part_fulu(w, offsets)
                }
            }
            Section::HistoricalRoots => write_b256_slice(w, &self.immutable.historical_roots),
            Section::Eth1Votes => self.eth1.finalized().write_ssz(w),
            Section::Validators => {
                let v = self.validators.finalized();
                v.write_ssz_range(0, v.validator_count(), w)
            }
            Section::Balances => self.balances.write_ssz(w),
            Section::PreviousParticipation => self.previous_participation.write_ssz(w),
            Section::CurrentParticipation => self.current_participation.write_ssz(w),
            Section::InactivityScores => self.inactivity.write_ssz(w),
            Section::ExecutionPayloadHeader => self.write_eph(w),
            Section::HistoricalSummaries => {
                self.longtail.with_finalized_locked(|lt| lt.write_historical_summaries_ssz(w))
            }
            Section::PendingDeposits => {
                self.pending.deposits.with_finalized_locked(|q| q.write_ssz(w))
            }
            Section::PendingPartialWithdrawals => {
                self.pending.partial_withdrawals.with_finalized_locked(|q| q.write_ssz(w))
            }
            Section::PendingConsolidations => {
                self.pending.consolidations.with_finalized_locked(|q| q.write_ssz(w))
            }
            Section::Builders => self.builders.finalized().write_ssz(w),
            Section::BuilderPendingWithdrawals => {
                self.pending.builder_withdrawals.with_finalized_locked(|q| q.write_ssz(w))
            }
            Section::LatestExecutionPayloadBid => {
                self.slot_states.finalized().state().latest_execution_payload_bid.write_ssz(w)
            }
            Section::PayloadExpectedWithdrawals => {
                for wd in &self.slot_states.finalized().state().payload_expected_withdrawals {
                    wd.write_ssz(w)?;
                }
                Ok(())
            }
        }
    }

    /// Write chunk `chunk` of `section` to `w`, returning `true` when the
    /// section is complete. Every section is single-chunk except
    /// [`Section::Validators`] (~265 MB), which is split into
    /// `VALIDATORS_PER_CHUNK`-record chunks so the streamed persist emits a
    /// bounded slice per turn.
    pub(crate) fn write_section_chunk<W: Write>(
        &self,
        section: Section,
        chunk: usize,
        offsets: &[u32],
        w: &mut W,
    ) -> io::Result<bool> {
        if section == Section::Validators {
            let v = self.validators.finalized();
            let n = v.validator_count();
            let start = chunk * VALIDATORS_PER_CHUNK;
            let end = (start + VALIDATORS_PER_CHUNK).min(n);
            v.write_ssz_range(start, end, w)?;
            Ok(end >= n)
        } else {
            debug_assert_eq!(chunk, 0, "only the validators section is chunked");
            self.write_section(section, offsets, w)?;
            Ok(true)
        }
    }

    /// Fixed-part fields F0..F23 (genesis_time through next_sync_committee),
    /// byte-identical across Fulu and Gloas. `off[0..=6]` are the seven leading
    /// variable offsets (historical_roots..inactivity_scores).
    fn write_fixed_prefix<W: Write>(&self, w: &mut W, off: &[u32]) -> io::Result<()> {
        let imm = &self.immutable;
        let sl = self.slot_states.finalized().state();
        let epoch_base = self.epoch.finalized();
        let est = epoch_base.state();
        let lt = self.longtail.finalized();

        // F0..F4
        w_u64(w, imm.genesis_time)?;
        w.write_all(&imm.genesis_validators_root)?;
        w_u64(w, sl.slot)?;
        w.write_all(&est.fork.previous_version)?;
        w.write_all(&est.fork.current_version)?;
        w_u64(w, est.fork.epoch)?;
        let h = &sl.latest_block_header;
        w_u64(w, h.slot)?;
        w_u64(w, h.proposer_index)?;
        w.write_all(&h.parent_root)?;
        w.write_all(&h.state_root)?;
        w.write_all(&h.body_root)?;

        // F5/F6 block_roots, state_roots.
        self.block_roots.write_ssz(w)?;
        self.state_roots.write_ssz(w)?;

        // F7_OFF historical_roots
        w_u32(w, off[0])?;
        // F8 eth1_data
        write_eth1_data(w, &sl.eth1_data)?;
        // F9_OFF eth1_data_votes
        w_u32(w, off[1])?;
        // F10 eth1_deposit_index
        w_u64(w, sl.eth1_deposit_index)?;
        // F11_OFF/F12_OFF validators, balances
        w_u32(w, off[2])?;
        w_u32(w, off[3])?;

        // F13 randao_mixes.
        self.randao_mixes.write_ssz(w)?;
        // F14 slashings.
        self.slashings.write_ssz(w)?;

        // F15_OFF/F16_OFF previous/current participation
        w_u32(w, off[4])?;
        w_u32(w, off[5])?;
        // F17 justification_bits (Bitvector[4], single byte; upper bits 0)
        w.write_all(&[est.justification_bits & 0x0F])?;
        // F18/F19/F20 checkpoints
        write_checkpoint(w, &est.previous_justified_checkpoint)?;
        write_checkpoint(w, &est.current_justified_checkpoint)?;
        write_checkpoint(w, &est.finalized_checkpoint)?;
        // F21_OFF inactivity_scores
        w_u32(w, off[6])?;
        // F22/F23 sync committees
        write_sync_committee(w, lt.sync_committees().current())?;
        write_sync_committee(w, lt.sync_committees().next())
    }

    /// Fixed-part fields shared by both forks' tails.
    fn write_summaries_scalars_pending<W: Write>(
        &self,
        w: &mut W,
        hist_summaries: u32,
        pending_deposits: u32,
        pending_partial_withdrawals: u32,
        pending_consolidations: u32,
    ) -> io::Result<()> {
        let sl = self.slot_states.finalized().state();
        let est = self.epoch.finalized().state();

        w_u64(w, sl.next_withdrawal_index)?;
        w_u64(w, sl.next_withdrawal_validator_index)?;
        w_u32(w, hist_summaries)?;
        w_u64(w, sl.deposit_requests_start_index)?;
        w_u64(w, est.deposit_balance_to_consume)?;
        w_u64(w, sl.exit_balance_to_consume)?;
        w_u64(w, sl.earliest_exit_epoch)?;
        w_u64(w, sl.consolidation_balance_to_consume)?;
        w_u64(w, sl.earliest_consolidation_epoch)?;
        w_u32(w, pending_deposits)?;
        w_u32(w, pending_partial_withdrawals)?;
        w_u32(w, pending_consolidations)?;
        for v in est.proposer_lookahead.iter() {
            w_u64(w, *v)?;
        }
        Ok(())
    }

    fn write_fixed_part_fulu<W: Write>(&self, w: &mut W, offs: &[u32]) -> io::Result<()> {
        self.write_fixed_prefix(w, offs)?;
        // F24_OFF execution_payload_header
        w_u32(w, offs[7])?;
        // F25/F26 withdrawal indices, F27_OFF historical_summaries, F28..F33
        // scalars, F34..F36 pending offsets, F37 proposer_lookahead
        self.write_summaries_scalars_pending(w, offs[8], offs[9], offs[10], offs[11])
    }

    fn write_fixed_part_gloas<W: Write>(&self, w: &mut W, offs: &[u32]) -> io::Result<()> {
        self.write_fixed_prefix(w, offs)?;
        let epoch_base = self.epoch.finalized();
        let sl = self.slot_states.finalized().state();

        // latest_block_hash
        w.write_all(&sl.latest_block_hash)?;
        // withdrawal indices, historical_summaries offset, scalars, pending
        // offsets, proposer_lookahead
        self.write_summaries_scalars_pending(w, offs[7], offs[8], offs[9], offs[10])?;
        // builders offset
        w_u32(w, offs[11])?;
        // next_withdrawal_builder_index
        w_u64(w, sl.next_withdrawal_builder_index)?;
        // execution_payload_availability (Bitvector[SLOTS_PER_HISTORICAL_ROOT])
        w.write_all(&sl.execution_payload_availability)?;
        // builder_pending_payments (Vector[BuilderPendingPayment, 2*SPE])
        for p in sl.builder_pending_payments.iter() {
            p.write_ssz(w)?;
        }
        // builder_pending_withdrawals / latest_execution_payload_bid /
        // payload_expected_withdrawals offsets
        w_u32(w, offs[12])?;
        w_u32(w, offs[13])?;
        w_u32(w, offs[14])?;
        // ptc_window (Vector[Vector[ValidatorIndex, PTC_SIZE], PTC_WINDOW_LEN])
        for committee in epoch_base.ptc_window.committees().iter() {
            for v in committee.iter() {
                w_u64(w, *v)?;
            }
        }
        Ok(())
    }

    fn write_eph<W: Write>(&self, w: &mut W) -> io::Result<()> {
        let eph = &self.slot_states.finalized().state().latest_execution_payload_header;
        w.write_all(&eph.parent_hash)?; // [0..32]
        w.write_all(&eph.fee_recipient)?; // [32..52]
        w.write_all(&eph.state_root)?; // [52..84]
        w.write_all(&eph.receipts_root)?; // [84..116]
        w.write_all(&eph.logs_bloom)?; // [116..372]
        w.write_all(&eph.prev_randao)?; // [372..404]
        w_u64(w, eph.block_number)?; // [404..412]
        w_u64(w, eph.gas_limit)?; // [412..420]
        w_u64(w, eph.gas_used)?; // [420..428]
        w_u64(w, eph.timestamp)?; // [428..436]
        w_u32(w, EPH_FIXED as u32)?; // [436..440] extra_data offset
        w.write_all(&eph.base_fee_per_gas)?; // [440..472]
        w.write_all(&eph.block_hash)?; // [472..504]
        w.write_all(&eph.transactions_root)?; // [504..536]
        w.write_all(&eph.withdrawals_root)?; // [536..568]
        w_u64(w, eph.blob_gas_used)?; // [568..576]
        w_u64(w, eph.excess_blob_gas)?; // [576..584]
        w.write_all(&eph.extra_data[..eph.extra_data_len as usize]) // [584..]
    }

    // A `<slot>.pubkeys` file written next to `<slot>.ssz` holding the
    // validators' decompressed pubkeys (96-B uncompressed G1 points). Reloading
    // from it skips the per-validator decompression sqrt (`from_bytes` on the
    // 48-B compressed form), the dominant cost of a checkpoint load. Layout:
    // `PUBKEYS_HEADER` (magic + version + count) then `count × 96 B` in
    // validator-index order.
    pub(crate) fn write_pubkeys_chunk<W: Write>(
        &self,
        chunk: usize,
        w: &mut W,
    ) -> io::Result<bool> {
        let v = self.validators.finalized();
        let n = v.validator_count();
        if chunk == 0 {
            w.write_all(&PUBKEYS_MAGIC)?;
            w_u32(w, PUBKEYS_VERSION)?;
            w_u64(w, n as u64)?;
        }
        let start = chunk * PUBKEYS_PER_CHUNK;
        let end = (start + PUBKEYS_PER_CHUNK).min(n);
        v.write_pubkeys_range(start, end, w)?;
        Ok(end >= n)
    }

    #[cfg(test)]
    pub(crate) fn pubkeys_sidecar_len(&self) -> usize {
        PUBKEYS_HEADER + self.validators.finalized().validator_count() * PUBKEY_SER
    }
}

#[inline]
pub(crate) fn write_eth1_data<W: Write>(w: &mut W, d: &Eth1Data) -> io::Result<()> {
    w.write_all(&d.deposit_root)?;
    w_u64(w, d.deposit_count)?;
    w.write_all(&d.block_hash)
}

#[inline]
fn write_checkpoint<W: Write>(w: &mut W, c: &Checkpoint) -> io::Result<()> {
    w_u64(w, c.epoch)?;
    w.write_all(&c.root)
}

#[inline]
fn write_sync_committee<W: Write>(w: &mut W, sc: &SyncCommittee) -> io::Result<()> {
    for pk in &sc.pubkeys {
        w.write_all(pk)?;
    }
    w.write_all(&sc.aggregate_pubkey)
}

const PUBKEYS_MAGIC: [u8; 4] = *b"SVPK";
const PUBKEYS_VERSION: u32 = 1;
const PUBKEY_SER: usize = 96;
/// Header: magic[4] + version: u32 + validator_count: u64.
const PUBKEYS_HEADER: usize = 4 + 4 + 8;
/// Records per sidecar chunk — aligned with the validators-section chunking so
/// chunk `k` covers the same validator indices (~12.6 MiB at 96 B).
const PUBKEYS_PER_CHUNK: usize = VALIDATORS_PER_CHUNK;

#[derive(Debug, thiserror::Error)]
pub enum PubkeysDecodeError {
    #[error("pubkeys sidecar shorter than header: {len} < {PUBKEYS_HEADER}")]
    Truncated { len: usize },
    #[error("pubkeys sidecar bad magic")]
    BadMagic,
    #[error("pubkeys sidecar version {got} != {PUBKEYS_VERSION}")]
    BadVersion { got: u32 },
    #[error("pubkeys body {body} != count {count} × {PUBKEY_SER}")]
    LenMismatch { body: usize, count: usize },
    #[error("pubkey {idx} failed to deserialize (not on curve)")]
    InvalidPubkey { idx: usize },
}

pub fn decode_checkpoint_pubkeys(bytes: &[u8]) -> Result<Vec<PublicKey>, PubkeysDecodeError> {
    if bytes.len() < PUBKEYS_HEADER {
        return Err(PubkeysDecodeError::Truncated { len: bytes.len() });
    }
    if bytes[..4] != PUBKEYS_MAGIC {
        return Err(PubkeysDecodeError::BadMagic);
    }
    let version = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    if version != PUBKEYS_VERSION {
        return Err(PubkeysDecodeError::BadVersion { got: version });
    }
    let count = u64::from_le_bytes(bytes[8..16].try_into().unwrap()) as usize;
    let body = &bytes[PUBKEYS_HEADER..];
    if body.len() != count * PUBKEY_SER {
        return Err(PubkeysDecodeError::LenMismatch { body: body.len(), count });
    }
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let pk = PublicKey::deserialize(&body[i * PUBKEY_SER..][..PUBKEY_SER])
            .map_err(|_| PubkeysDecodeError::InvalidPubkey { idx: i })?;
        out.push(pk);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use crate::{
        BeaconState, EpochGroup, EpochStateFinalized, SpecConfig, decode_checkpoint_pubkeys,
        encode::Section,
    };

    /// `encode → decompose → encode` must be a byte-exact fixed point, and the
    /// chunked streaming path must match the one-pass path. The empty state is
    /// a valid state, so it round-trips with no fixture.
    #[test]
    fn encode_decompose_fixed_point() {
        let bs = BeaconState::empty_test(0);

        let mut once = Vec::with_capacity(bs.ssz_len());
        bs.encode_ssz(&mut once).expect("encode");

        let reloaded = BeaconState::decompose(&once, &SpecConfig::mainnet(), None)
            .expect("decompose of self-encoded state");
        let mut twice = Vec::with_capacity(reloaded.ssz_len());
        reloaded.encode_ssz(&mut twice).expect("re-encode");
        assert_eq!(once, twice, "encode → decompose → encode is not a fixed point");

        // Chunk-streamed path must produce the same bytes.
        let offsets = bs.var_offsets_fulu();
        let mut streamed = Vec::with_capacity(bs.ssz_len());
        for section in Section::FULU {
            let mut chunk = 0;
            while !bs.write_section_chunk(section, chunk, &offsets, &mut streamed).expect("chunk") {
                chunk += 1;
            }
        }
        assert_eq!(once, streamed, "chunk-streamed SSZ differs from one-pass");
    }

    /// Gloas counterpart: an empty Gloas state (fork forced) must be a
    /// byte-exact `encode → decompose → encode` fixed point, and the
    /// chunk-streamed path must match the one-pass path over the 16 Gloas
    /// sections.
    #[test]
    fn encode_decompose_gloas_fixed_point() {
        let cfg = SpecConfig::mainnet();
        let mut bs = BeaconState::empty_test(0);
        // `is_finalized_post_gloas` compares the finalized epoch fork against
        // `immutable.gloas_fork_version`; hold both at the cfg version so decode
        // routes to Gloas too.
        bs.immutable.gloas_fork_version = cfg.gloas_fork_version;
        let mut epoch = EpochStateFinalized::default();
        epoch.state.fork.current_version = cfg.gloas_fork_version;
        bs.epoch = EpochGroup::new(epoch);
        assert!(bs.is_finalized_post_gloas());

        let mut once = Vec::with_capacity(bs.ssz_len());
        bs.encode_ssz(&mut once).expect("encode");
        assert_eq!(once.len(), bs.ssz_len(), "ssz_len disagrees with encoded length");

        let reloaded = BeaconState::decompose(&once, &cfg, None)
            .expect("decompose of self-encoded gloas state");
        assert!(reloaded.is_finalized_post_gloas());
        let mut twice = Vec::with_capacity(reloaded.ssz_len());
        reloaded.encode_ssz(&mut twice).expect("re-encode");
        assert_eq!(once, twice, "gloas encode → decompose → encode is not a fixed point");

        let offsets = bs.checkpoint_offsets();
        let mut streamed = Vec::with_capacity(bs.ssz_len());
        for section in Section::GLOAS {
            let mut chunk = 0;
            while !bs.write_section_chunk(section, chunk, &offsets, &mut streamed).expect("chunk") {
                chunk += 1;
            }
        }
        assert_eq!(once, streamed, "gloas chunk-streamed SSZ differs from one-pass");
    }

    /// Write the decompressed-pubkey sidecar, decode it, rebuild the validators
    /// from SSZ + sidecar, and confirm the pubkeys match. Also that a corrupted
    /// sidecar is rejected (never silently accepted).
    #[test]
    fn pubkeys_sidecar_round_trip() {
        let bs = BeaconState::empty_test(0);
        let mut sidecar = Vec::with_capacity(bs.pubkeys_sidecar_len());
        let mut chunk = 0;
        while !bs.write_pubkeys_chunk(chunk, &mut sidecar).expect("pubkeys chunk") {
            chunk += 1;
        }
        let decoded = decode_checkpoint_pubkeys(&sidecar).expect("decode");
        assert_eq!(decoded.len(), bs.validators.finalized().validator_count());
    }
}
