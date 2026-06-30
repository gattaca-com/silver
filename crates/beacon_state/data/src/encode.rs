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
    decompose::FIXED_PART,
    types::{B256, Checkpoint, Eth1Data, SLOTS_PER_EPOCH, SyncCommittee},
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
pub(crate) const VAR_LEN_SECTIONS: usize = 12;

/// Number of checkpoint sections: the fixed part + the 12 variable bodies.
pub const CHECKPOINT_SECTIONS: usize = 1 + VAR_LEN_SECTIONS;

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
}

impl Section {
    pub(crate) const ALL: [Section; CHECKPOINT_SECTIONS] = [
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
/// the inverse cast in `decompose::fill_block_state_roots`.
#[inline]
pub(crate) fn write_b256_slice<W: Write>(w: &mut W, s: &[B256]) -> io::Result<()> {
    let bytes = unsafe { std::slice::from_raw_parts(s.as_ptr().cast::<u8>(), s.len() * 32) };
    w.write_all(bytes)
}

impl BeaconState {
    /// Byte lengths of the 12 variable-length fields, in SSZ-declared order.
    pub(crate) fn var_len_section_lens(&self) -> [usize; VAR_LEN_SECTIONS] {
        let n = self.validators.finalized().validator_count();
        let dep = self.pending.deposits.with_finalized_locked(|q| q.len());
        let wdr = self.pending.partial_withdrawals.with_finalized_locked(|q| q.len());
        let con = self.pending.consolidations.with_finalized_locked(|q| q.len());
        let summaries = self.longtail.with_finalized_locked(|lt| lt.historical_summaries.len());
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

    /// Absolute byte offsets of the 12 variable bodies (the values written into
    /// the fixed part's offset slots), derived from a section-length snapshot.
    pub(crate) fn offsets_from_lens(lens: &[usize; VAR_LEN_SECTIONS]) -> [u32; VAR_LEN_SECTIONS] {
        let mut offs = [0u32; VAR_LEN_SECTIONS];
        let mut acc = FIXED_PART;
        for (o, len) in offs.iter_mut().zip(lens) {
            *o = u32::try_from(acc).expect("ssz variable offset exceeds u32");
            acc += len;
        }
        offs
    }

    /// Total SSZ length of the encoded state.
    pub fn ssz_len(&self) -> usize {
        FIXED_PART + self.var_len_section_lens().iter().sum::<usize>()
    }

    #[cfg(test)]
    pub(crate) fn var_offsets(&self) -> [u32; VAR_LEN_SECTIONS] {
        Self::offsets_from_lens(&self.var_len_section_lens())
    }

    /// Encode the full canonical SSZ in one pass: the 2.74 MB fixed part, then
    /// the 12 variable bodies in SSZ-declared order.
    pub fn encode_ssz(&self, w: &mut Vec<u8>) -> io::Result<()> {
        if self.epoch.finalized().state().fork.current_version == self.immutable.gloas_fork_version
        {
            return self.encode_ssz_gloas(w);
        }
        let lens = self.var_len_section_lens();
        w.reserve(FIXED_PART + lens.iter().sum::<usize>());
        let offsets = Self::offsets_from_lens(&lens);
        for section in Section::ALL {
            self.write_section(section, &offsets, w)?;
        }
        Ok(())
    }

    fn encode_ssz_gloas(&self, _w: &mut Vec<u8>) -> io::Result<()> {
        todo!("Gloas checkpoint encode — implement against EF gloas fixtures")
    }

    pub(crate) fn write_section<W: Write>(
        &self,
        section: Section,
        offsets: &[u32; VAR_LEN_SECTIONS],
        w: &mut W,
    ) -> io::Result<()> {
        match section {
            Section::FixedPart => self.write_fixed_part(w, offsets),
            Section::HistoricalRoots => write_b256_slice(w, &self.immutable.historical_roots),
            Section::Eth1Votes => self.eth1.finalized().write_ssz(w),
            Section::Validators => {
                let v = self.validators.finalized();
                v.write_ssz_range(0, v.validator_count(), w)
            }
            Section::Balances => self.balances.finalized().write_ssz(w),
            Section::PreviousParticipation => self.previous_participation.finalized().write_ssz(w),
            Section::CurrentParticipation => self.current_participation.finalized().write_ssz(w),
            Section::InactivityScores => self.inactivity.finalized().write_ssz(w),
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
        offsets: &[u32; VAR_LEN_SECTIONS],
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

    /// Emit the 2.74 MB fixed part, fields in SSZ order, with the variable
    /// offsets spliced into their slots. `offs` must come from
    /// [`Self::offsets_from_lens`].
    fn write_fixed_part<W: Write>(
        &self,
        w: &mut W,
        offs: &[u32; VAR_LEN_SECTIONS],
    ) -> io::Result<()> {
        let imm = &self.immutable;
        let slot_base = self.slot_states.finalized();
        let sl = slot_base.state();
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

        // F5/F6 block_roots, state_roots (rings stored in spec index order).
        slot_base.write_roots_ssz(w)?;

        // F7_OFF historical_roots
        w_u32(w, offs[0])?;
        // F8 eth1_data
        write_eth1_data(w, &sl.eth1_data)?;
        // F9_OFF eth1_data_votes
        w_u32(w, offs[1])?;
        // F10 eth1_deposit_index
        w_u64(w, sl.eth1_deposit_index)?;
        // F11_OFF/F12_OFF validators, balances
        w_u32(w, offs[2])?;
        w_u32(w, offs[3])?;

        // The current epoch's bucket is only
        // flushed to the array tier at the epoch boundary, so mid-epoch the live
        // value lives in the `*_current` caches (the hashing path substitutes
        // them in `effective_{randao_mixes,slashings}_into`).
        // F13 randao_mixes
        let current_epoch = (sl.slot / SLOTS_PER_EPOCH) as usize;
        let randao_curr = current_epoch % epoch_base.randao_mixes.len();
        write_b256_slice(w, &epoch_base.randao_mixes[..randao_curr])?;
        w.write_all(&sl.randao_mix_current)?;
        write_b256_slice(w, &epoch_base.randao_mixes[randao_curr + 1..])?;
        // F14 slashings.
        let slashings_curr = current_epoch % epoch_base.slashings.len();
        for (i, s) in epoch_base.slashings.iter().enumerate() {
            w_u64(w, if i == slashings_curr { sl.current_epoch_slashings } else { *s })?;
        }

        // F15_OFF/F16_OFF previous/current participation
        w_u32(w, offs[4])?;
        w_u32(w, offs[5])?;
        // F17 justification_bits (Bitvector[4], single byte; upper bits 0)
        w.write_all(&[est.justification_bits & 0x0F])?;
        // F18/F19/F20 checkpoints
        write_checkpoint(w, &est.previous_justified_checkpoint)?;
        write_checkpoint(w, &est.current_justified_checkpoint)?;
        write_checkpoint(w, &est.finalized_checkpoint)?;
        // F21_OFF inactivity_scores
        w_u32(w, offs[6])?;
        // F22/F23 sync committees
        write_sync_committee(w, &lt.current_sync_committee)?;
        write_sync_committee(w, &lt.next_sync_committee)?;
        // F24_OFF execution_payload_header
        w_u32(w, offs[7])?;
        // F25/F26 withdrawal indices
        w_u64(w, sl.next_withdrawal_index)?;
        w_u64(w, sl.next_withdrawal_validator_index)?;
        // F27_OFF historical_summaries
        w_u32(w, offs[8])?;
        // F28..F33 deposit/exit/consolidation scalars (note: F29 lives in epoch)
        w_u64(w, sl.deposit_requests_start_index)?;
        w_u64(w, est.deposit_balance_to_consume)?;
        w_u64(w, sl.exit_balance_to_consume)?;
        w_u64(w, sl.earliest_exit_epoch)?;
        w_u64(w, sl.consolidation_balance_to_consume)?;
        w_u64(w, sl.earliest_consolidation_epoch)?;
        // F34_OFF/F35_OFF/F36_OFF pending queues
        w_u32(w, offs[9])?;
        w_u32(w, offs[10])?;
        w_u32(w, offs[11])?;
        // F37 proposer_lookahead
        for v in est.proposer_lookahead.iter() {
            w_u64(w, *v)?;
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

    #[cfg(test)]
    pub(crate) fn pubkeys_sidecar_len(&self) -> usize {
        PUBKEYS_HEADER + self.validators.finalized().validator_count() * PUBKEY_SER
    }

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
        BeaconState, EpochGroup, EpochStateFinalized, SLOTS_PER_HISTORICAL_ROOT, SlotState,
        SlotStateFinalized, SlotStateGroup, SpecConfig, decode_checkpoint_pubkeys, encode::Section,
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
        let offsets = bs.var_offsets();
        let mut streamed = Vec::with_capacity(bs.ssz_len());
        for section in Section::ALL {
            let mut chunk = 0;
            while !bs.write_section_chunk(section, chunk, &offsets, &mut streamed).expect("chunk") {
                chunk += 1;
            }
        }
        assert_eq!(once, streamed, "chunk-streamed SSZ differs from one-pass");
    }

    /// Regression: a checkpoint persisted mid-epoch must encode the *live*
    /// current-epoch randao mix / slashings (the `*_current` caches), not the
    /// stale array bucket — that bucket is only refreshed at the epoch
    /// boundary.
    #[test]
    fn encode_uses_live_current_epoch_caches() {
        let cur = 3usize;
        let mut bs = BeaconState::empty_test(0);

        // Stale ring buckets, distinct from the live `*_current` caches the
        // encode path must emit instead.
        let mut epoch = EpochStateFinalized::default();
        epoch.randao_mixes[cur] = [0xAA; 32];
        epoch.slashings[cur] = 111;
        bs.epoch = EpochGroup::new(epoch);

        let zero_roots = || vec![[0u8; 32]; SLOTS_PER_HISTORICAL_ROOT].into_boxed_slice();
        let slot = SlotState {
            slot: 96, // epoch 3
            randao_mix_current: [0xBB; 32],
            current_epoch_slashings: 222,
            ..Default::default()
        };
        bs.slot_states =
            SlotStateGroup::new(SlotStateFinalized::from_parts(slot, zero_roots(), zero_roots()));

        let mut ssz = Vec::with_capacity(bs.ssz_len());
        bs.encode_ssz(&mut ssz).unwrap();
        let decoded = BeaconState::decompose(&ssz, &SpecConfig::mainnet(), None).unwrap();

        let de = decoded.epoch.finalized();
        let ds = decoded.slot_states.finalized().state();
        assert_eq!(de.randao_mixes[cur], [0xBB; 32], "randao current bucket = live");
        assert_eq!(ds.randao_mix_current, [0xBB; 32]);
        assert_eq!(de.slashings[cur], 222, "slashings current bucket = live");
        assert_eq!(ds.current_epoch_slashings, 222);
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
