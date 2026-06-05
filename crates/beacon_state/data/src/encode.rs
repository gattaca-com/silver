use std::io::{self, Write};

use crate::{
    decompose::FIXED_PART,
    types::{B256, Checkpoint, Eth1Data, Finalized, SyncCommittee},
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
pub const VAR_LEN_SECTIONS: usize = 12;

/// Number of checkpoint sections: the fixed part + the 12 variable bodies.
pub const CHECKPOINT_SECTIONS: usize = 1 + VAR_LEN_SECTIONS;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Section {
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
    pub const ALL: [Section; CHECKPOINT_SECTIONS] = [
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
fn w_b256_slice<W: Write>(w: &mut W, s: &[B256]) -> io::Result<()> {
    let bytes = unsafe { std::slice::from_raw_parts(s.as_ptr().cast::<u8>(), s.len() * 32) };
    w.write_all(bytes)
}

impl Finalized {
    /// Byte lengths of the 12 variable-length fields, in SSZ-declared order.
    pub fn var_len_section_lens(&self) -> [usize; VAR_LEN_SECTIONS] {
        let n = self.validators.validator_count();
        let pending = self.pending.read();
        [
            self.immutable.historical_roots.len() * 32,
            self.slot.slot.eth1_votes.len() * ETH1_DATA_SSZ,
            n * VALIDATOR_SSZ,
            n * 8,
            n,
            n,
            n * 8,
            EPH_FIXED + self.slot.slot.latest_execution_payload_header.extra_data_len as usize,
            self.longtail.historical_summaries.read().len() * HIST_SUMMARY_SSZ,
            pending.pending_deposits.len() * PENDING_DEPOSIT_SSZ,
            pending.pending_partial_withdrawals.len() * PENDING_WITHDRAWAL_SSZ,
            pending.pending_consolidations.len() * PENDING_CONSOLIDATION_SSZ,
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

    /// Encode the full canonical SSZ in one pass: the 2.74 MB fixed part, then
    /// the 12 variable bodies in SSZ-declared order.
    pub fn encode_ssz(&self, w: &mut Vec<u8>) -> io::Result<()> {
        let lens = self.var_len_section_lens();
        w.reserve(FIXED_PART + lens.iter().sum::<usize>());
        self.write_fixed_part(w, &Self::offsets_from_lens(&lens))?;
        self.write_historical_roots(w)?;
        self.write_eth1_votes(w)?;
        self.write_validators(w)?;
        self.write_balances(w)?;
        self.write_previous_participation(w)?;
        self.write_current_participation(w)?;
        self.write_inactivity_scores(w)?;
        self.write_eph(w)?;
        self.write_historical_summaries(w)?;
        self.write_pending_deposits(w)?;
        self.write_pending_partial_withdrawals(w)?;
        self.write_pending_consolidations(w)?;
        Ok(())
    }

    pub fn write_section<W: Write>(
        &self,
        section: Section,
        offsets: &[u32; VAR_LEN_SECTIONS],
        w: &mut W,
    ) -> io::Result<()> {
        match section {
            Section::FixedPart => self.write_fixed_part(w, offsets),
            Section::HistoricalRoots => self.write_historical_roots(w),
            Section::Eth1Votes => self.write_eth1_votes(w),
            Section::Validators => self.write_validators(w),
            Section::Balances => self.write_balances(w),
            Section::PreviousParticipation => self.write_previous_participation(w),
            Section::CurrentParticipation => self.write_current_participation(w),
            Section::InactivityScores => self.write_inactivity_scores(w),
            Section::ExecutionPayloadHeader => self.write_eph(w),
            Section::HistoricalSummaries => self.write_historical_summaries(w),
            Section::PendingDeposits => self.write_pending_deposits(w),
            Section::PendingPartialWithdrawals => self.write_pending_partial_withdrawals(w),
            Section::PendingConsolidations => self.write_pending_consolidations(w),
        }
    }

    /// Write chunk `chunk` of `section` to `w`, returning `true` when the
    /// section is complete. Every section is single-chunk except
    /// [`Section::Validators`] (~265 MB), which is split into
    /// `VALIDATORS_PER_CHUNK`-record chunks so the streamed persist emits a
    /// bounded slice per `file_io` turn.
    pub fn write_section_chunk<W: Write>(
        &self,
        section: Section,
        chunk: usize,
        offsets: &[u32; VAR_LEN_SECTIONS],
        w: &mut W,
    ) -> io::Result<bool> {
        if section == Section::Validators {
            let n = self.validators.validator_count();
            let start = chunk * VALIDATORS_PER_CHUNK;
            let end = (start + VALIDATORS_PER_CHUNK).min(n);
            self.write_validators_range(start, end, w)?;
            Ok(end >= n)
        } else {
            debug_assert_eq!(chunk, 0, "only the validators section is chunked");
            self.write_section(section, offsets, w)?;
            Ok(true)
        }
    }

    // historical_roots (frozen).
    fn write_historical_roots<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w_b256_slice(w, &self.immutable.historical_roots)
    }

    // eth1_votes (inline ArrayVec).
    fn write_eth1_votes<W: Write>(&self, w: &mut W) -> io::Result<()> {
        for e in self.slot.slot.eth1_votes.iter() {
            write_eth1_data(w, e)?;
        }
        Ok(())
    }

    fn write_validators<W: Write>(&self, w: &mut W) -> io::Result<()> {
        self.write_validators_range(0, self.validators.validator_count(), w)
    }

    /// Encode validators `[start, end)` (one 121-B record at a time). The
    /// streamed persist calls this in `VALIDATORS_PER_CHUNK` slices.
    fn write_validators_range<W: Write>(
        &self,
        start: usize,
        end: usize,
        w: &mut W,
    ) -> io::Result<()> {
        let mut val = [0u8; VALIDATOR_SSZ];
        for i in start..end {
            self.encode_validator(i, &mut val);
            w.write_all(&val)?;
        }
        Ok(())
    }

    fn write_balances<W: Write>(&self, w: &mut W) -> io::Result<()> {
        for b in &self.balances.as_slice()[..self.validators.validator_count()] {
            w_u64(w, *b)?;
        }
        Ok(())
    }

    fn write_previous_participation<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(&self.previous_participation.data[..self.validators.validator_count()])
    }

    fn write_current_participation<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(&self.current_participation.data[..self.validators.validator_count()])
    }

    fn write_inactivity_scores<W: Write>(&self, w: &mut W) -> io::Result<()> {
        for s in &self.inactivity_scores.data[..self.validators.validator_count()] {
            w_u64(w, *s)?;
        }
        Ok(())
    }

    fn write_historical_summaries<W: Write>(&self, w: &mut W) -> io::Result<()> {
        for hs in self.longtail.historical_summaries.read().iter() {
            w.write_all(&hs.block_summary_root)?;
            w.write_all(&hs.state_summary_root)?;
        }
        Ok(())
    }

    fn write_pending_deposits<W: Write>(&self, w: &mut W) -> io::Result<()> {
        let mut buf = [0u8; PENDING_DEPOSIT_SSZ];
        for d in &self.pending.read().pending_deposits {
            buf[0..48].copy_from_slice(&d.pubkey);
            buf[48..80].copy_from_slice(&d.withdrawal_credentials.0);
            buf[80..88].copy_from_slice(&d.amount.to_le_bytes());
            buf[88..184].copy_from_slice(&d.signature);
            buf[184..192].copy_from_slice(&d.slot.to_le_bytes());
            w.write_all(&buf)?;
        }
        Ok(())
    }

    fn write_pending_partial_withdrawals<W: Write>(&self, w: &mut W) -> io::Result<()> {
        for pw in &self.pending.read().pending_partial_withdrawals {
            w_u64(w, pw.index)?;
            w_u64(w, pw.amount)?;
            w_u64(w, pw.withdrawable_epoch)?;
        }
        Ok(())
    }

    fn write_pending_consolidations<W: Write>(&self, w: &mut W) -> io::Result<()> {
        for pc in &self.pending.read().pending_consolidations {
            w_u64(w, pc.source_index)?;
            w_u64(w, pc.target_index)?;
        }
        Ok(())
    }

    /// Emit the 2.74 MB fixed part, fields in SSZ order, with the variable
    /// offsets spliced into their slots. `offs` must come from
    /// `offsets_from_lens`.
    pub fn write_fixed_part<W: Write>(
        &self,
        w: &mut W,
        offs: &[u32; VAR_LEN_SECTIONS],
    ) -> io::Result<()> {
        let sl = &self.slot.slot;
        let est = &self.epoch.state;

        // F0..F4
        w_u64(w, self.immutable.genesis_time)?;
        w.write_all(&self.immutable.genesis_validators_root)?;
        w_u64(w, sl.slot)?;
        w.write_all(&self.immutable.fork.previous_version)?;
        w.write_all(&self.immutable.fork.current_version)?;
        w_u64(w, self.immutable.fork.epoch)?;
        let h = &sl.latest_block_header;
        w_u64(w, h.slot)?;
        w_u64(w, h.proposer_index)?;
        w.write_all(&h.parent_root)?;
        w.write_all(&h.state_root)?;
        w.write_all(&h.body_root)?;

        // F5/F6 block_roots, state_roots (rings stored in spec index order).
        w_b256_slice(w, &self.slot.block_roots)?;
        w_b256_slice(w, &self.slot.state_roots)?;

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
        // F13 randao_mixes, F14 slashings
        w_b256_slice(w, &self.epoch.randao_mixes)?;
        for s in self.epoch.slashings.iter() {
            w_u64(w, *s)?;
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
        write_sync_committee(w, &self.longtail.current_sync_committee)?;
        write_sync_committee(w, &self.longtail.next_sync_committee)?;
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

    fn encode_validator(&self, i: usize, buf: &mut [u8; VALIDATOR_SSZ]) {
        let v = &self.validators;
        buf[0..48].copy_from_slice(v.pubkey(i));
        buf[48..80].copy_from_slice(&v.withdrawal_credentials(i).0);
        buf[80..88].copy_from_slice(&v.effective_balance(i).to_le_bytes());
        buf[88] = v.is_slashed(i) as u8;
        buf[89..97].copy_from_slice(&v.activation_eligibility_epoch(i).to_le_bytes());
        buf[97..105].copy_from_slice(&v.activation_epoch(i).to_le_bytes());
        buf[105..113].copy_from_slice(&v.exit_epoch(i).to_le_bytes());
        buf[113..121].copy_from_slice(&v.withdrawable_epoch(i).to_le_bytes());
    }

    fn write_eph<W: Write>(&self, w: &mut W) -> io::Result<()> {
        let eph = &self.slot.slot.latest_execution_payload_header;
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
}

#[inline]
fn write_eth1_data<W: Write>(w: &mut W, d: &Eth1Data) -> io::Result<()> {
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

#[cfg(test)]
mod tests {
    use blst::min_pk::SecretKey;

    use crate::{
        Section, SpecConfig, ValSeed,
        types::{
            Checkpoint, Eth1Data, FAR_FUTURE_EPOCH, Finalized, HistoricalSummary,
            PendingConsolidation, PendingDeposit, PendingPartialWithdrawal, Withdrawals,
        },
    };

    fn valid_pubkey(seed: u8) -> [u8; 48] {
        SecretKey::key_gen(&[seed; 32], &[]).expect("key_gen").sk_to_pk().to_bytes()
    }

    /// `encode → decompose → encode` must be a byte-exact fixed point with the
    /// variable sections non-empty. Fixture-free, so it runs in any checkout;
    /// the byte-equality against a real mainnet state lives in
    /// `e2e/tests/checkpoint_load.rs`.
    #[test]
    fn encode_decompose_fixed_point() {
        let seeds: Vec<ValSeed> = (0..5u8)
            .map(|i| ValSeed {
                pubkey: valid_pubkey(i),
                withdrawal_credentials: Withdrawals::eth1(&[i; 20]),
                effective_balance: 32_000_000_000,
                balance: 31_000_000_000 + i as u64,
                activation_epoch: 0,
                exit_epoch: FAR_FUTURE_EPOCH,
            })
            .collect();

        let mut fin = Finalized::new_test(&seeds);
        fin.slot.slot.slot = 320; // epoch 10
        fin.immutable.historical_roots = vec![[1u8; 32], [2u8; 32]].into_boxed_slice();
        fin.slot.slot.eth1_votes.push(Eth1Data {
            deposit_root: [3; 32],
            deposit_count: 7,
            block_hash: [4; 32],
        });
        fin.longtail
            .historical_summaries
            .write()
            .push(HistoricalSummary { block_summary_root: [5; 32], state_summary_root: [6; 32] });
        {
            let mut pending = fin.pending.write();
            pending.pending_deposits.push(PendingDeposit {
                pubkey: seeds[0].pubkey,
                withdrawal_credentials: Withdrawals::ZERO,
                amount: 1,
                signature: [7; 96],
                slot: 9,
            });
            pending.pending_partial_withdrawals.push(PendingPartialWithdrawal {
                index: 1,
                amount: 2,
                withdrawable_epoch: 3,
            });
            pending
                .pending_consolidations
                .push(PendingConsolidation { source_index: 0, target_index: 1 });
        }
        let eph = &mut fin.slot.slot.latest_execution_payload_header;
        eph.extra_data_len = 3;
        eph.extra_data[..3].copy_from_slice(&[9, 9, 9]);
        fin.epoch.state.finalized_checkpoint = Checkpoint { epoch: 8, root: [8; 32] };

        let mut b1 = Vec::with_capacity(fin.ssz_len());
        fin.encode_ssz(&mut b1).unwrap();
        assert_eq!(b1.len(), fin.ssz_len());

        // The streamed section-by-section path (Phase 2) must produce the
        // exact same bytes as the one-shot encode.
        let offsets = Finalized::offsets_from_lens(&fin.var_len_section_lens());
        let mut streamed = Vec::new();
        for section in Section::ALL {
            fin.write_section(section, &offsets, &mut streamed).unwrap();
        }
        assert_eq!(streamed, b1, "section-streamed encode differs from one-shot");

        // The chunked path (validators may span multiple turns) also matches.
        let mut chunked = Vec::new();
        for section in Section::ALL {
            let mut chunk = 0;
            while !fin.write_section_chunk(section, chunk, &offsets, &mut chunked).unwrap() {
                chunk += 1;
            }
        }
        assert_eq!(chunked, b1, "chunk-streamed encode differs from one-shot");

        // Splitting the validators section at an arbitrary boundary is
        // byte-identical to writing it whole.
        let mut whole = Vec::new();
        fin.write_validators(&mut whole).unwrap();
        let mut split = Vec::new();
        fin.write_validators_range(0, 2, &mut split).unwrap();
        fin.write_validators_range(2, fin.validators.validator_count(), &mut split).unwrap();
        assert_eq!(split, whole, "validator range split differs from whole section");

        let cfg = SpecConfig::mainnet();
        let mut fin2 = Box::new(Finalized::empty());
        fin2.decompose(&b1, &cfg).expect("decompose encoded synthetic state");

        let mut b2 = Vec::with_capacity(fin2.ssz_len());
        fin2.encode_ssz(&mut b2).unwrap();
        assert!(b1 == b2, "encode∘decompose∘encode is not a fixed point");

        assert_eq!(fin2.validators.validator_count(), 5);
        assert_eq!(&*fin2.immutable.historical_roots, &[[1u8; 32], [2u8; 32]]);
        let pending = fin2.pending.read();
        assert_eq!(pending.pending_deposits.len(), 1);
        assert_eq!(pending.pending_partial_withdrawals.len(), 1);
        assert_eq!(pending.pending_consolidations.len(), 1);
        assert_eq!(fin2.slot.slot.eth1_votes.len(), 1);
        assert_eq!(fin2.longtail.historical_summaries.read().len(), 1);
    }
}
