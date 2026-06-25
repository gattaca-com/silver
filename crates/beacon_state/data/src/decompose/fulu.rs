use silver_common_macros::timed;

use super::common::{
    DecomposeError, EPH_FIXED_PART, F2, F4, F5, F6, F7_OFF, F8, F9_OFF, F10, F11_OFF, F12_OFF, F13,
    F14, F15_OFF, F16_OFF, F17, F18, F19, F20, F21_OFF, F24_OFF, F25, F26, F27_OFF, F28, F29, F30,
    F31, F32, F33, F34_OFF, F35_OFF, F36_OFF, F37, FIXED_PART, Offsets, b256, read_checkpoint,
    u32_le, u64_le,
};
use crate::{
    BeaconState, EpochStateFinalized, FinalizedBuilders, SlotStateFinalized, SpecConfig,
    types::{
        B256, BeaconBlockHeader, EPOCHS_PER_HISTORICAL_VECTOR, EPOCHS_PER_SLASHINGS_VECTOR,
        Eth1Data, ExecutionPayloadHeader, Immutable, PROPOSER_LOOKAHEAD_SIZE, SLOTS_PER_EPOCH,
        SLOTS_PER_HISTORICAL_ROOT, SlotState,
    },
};

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

impl EpochStateFinalized {
    #[timed]
    pub(crate) fn from_ssz(ssz: &[u8]) -> Self {
        let mut fin = Self::default();

        let randao_src: &[B256] = unsafe {
            std::slice::from_raw_parts(
                ssz[F13..].as_ptr().cast::<B256>(),
                EPOCHS_PER_HISTORICAL_VECTOR,
            )
        };
        fin.randao_mixes.copy_from_slice(randao_src);

        for i in 0..EPOCHS_PER_SLASHINGS_VECTOR {
            fin.slashings[i] = u64_le(ssz, F14 + i * 8);
        }

        let est = &mut fin.state;
        for i in 0..PROPOSER_LOOKAHEAD_SIZE {
            est.proposer_lookahead[i] = u64_le(ssz, F37 + i * 8);
        }
        est.justification_bits = ssz[F17] & 0x0F;
        est.previous_justified_checkpoint = read_checkpoint(ssz, F18);
        est.current_justified_checkpoint = read_checkpoint(ssz, F19);
        est.finalized_checkpoint = read_checkpoint(ssz, F20);
        est.deposit_balance_to_consume = u64_le(ssz, F29);

        fin
    }
}

impl SlotStateFinalized {
    pub(super) fn from_ssz(
        ssz: &[u8],
        o: &Offsets,
        epoch: &EpochStateFinalized,
    ) -> Result<Self, DecomposeError> {
        let mut slot = SlotState {
            slot: u64_le(ssz, F2),
            latest_block_header: BeaconBlockHeader {
                slot: u64_le(ssz, F4),
                proposer_index: u64_le(ssz, F4 + 8),
                parent_root: b256(ssz, F4 + 16),
                state_root: b256(ssz, F4 + 48),
                body_root: b256(ssz, F4 + 80),
            },
            eth1_data: Eth1Data {
                deposit_root: b256(ssz, F8),
                deposit_count: u64_le(ssz, F8 + 32),
                block_hash: b256(ssz, F8 + 40),
            },
            eth1_deposit_index: u64_le(ssz, F10),
            next_withdrawal_index: u64_le(ssz, F25),
            next_withdrawal_validator_index: u64_le(ssz, F26),
            deposit_requests_start_index: u64_le(ssz, F28),
            exit_balance_to_consume: u64_le(ssz, F30),
            earliest_exit_epoch: u64_le(ssz, F31),
            consolidation_balance_to_consume: u64_le(ssz, F32),
            earliest_consolidation_epoch: u64_le(ssz, F33),
            ..Default::default()
        };

        read_execution_payload_header(
            ssz,
            o.eph,
            o.hist_summaries,
            &mut slot.latest_execution_payload_header,
        )?;

        // Derived per-block accumulators: seed from the current epoch's bucket.
        let current_epoch = slot.slot / SLOTS_PER_EPOCH;
        slot.randao_mix_current =
            epoch.randao_mixes[current_epoch as usize % EPOCHS_PER_HISTORICAL_VECTOR];
        slot.current_epoch_slashings =
            epoch.slashings[current_epoch as usize % EPOCHS_PER_SLASHINGS_VECTOR];

        // block/state roots (alignment-1 bulk copy; B256 has align 1).
        let mut block_roots = vec![[0u8; 32]; SLOTS_PER_HISTORICAL_ROOT].into_boxed_slice();
        let block_src: &[B256] = unsafe {
            std::slice::from_raw_parts(ssz[F5..].as_ptr().cast::<B256>(), SLOTS_PER_HISTORICAL_ROOT)
        };
        block_roots.copy_from_slice(block_src);
        let mut state_roots = vec![[0u8; 32]; SLOTS_PER_HISTORICAL_ROOT].into_boxed_slice();
        let state_src: &[B256] = unsafe {
            std::slice::from_raw_parts(ssz[F6..].as_ptr().cast::<B256>(), SLOTS_PER_HISTORICAL_ROOT)
        };
        state_roots.copy_from_slice(state_src);

        Ok(Self::from_parts(slot, block_roots, state_roots))
    }
}

impl BeaconState {
    #[timed]
    pub(super) fn decompose_fulu(
        ssz: &[u8],
        cfg: &SpecConfig,
        pubkeys: Option<&[blst::min_pk::PublicKey]>,
    ) -> Result<Self, DecomposeError> {
        if ssz.len() < FIXED_PART {
            return Err(DecomposeError::TruncatedFixedPart { len: ssz.len(), need: FIXED_PART });
        }
        let offsets = Offsets::read_and_validate(ssz)?;
        let mut immutable = Immutable::default();
        immutable.fill_from_ssz(ssz, cfg);
        let epoch = EpochStateFinalized::from_ssz(ssz);
        // The slot tier derives its per-block accumulators from the epoch rings.
        let slot = SlotStateFinalized::from_ssz(ssz, &offsets, &epoch)?;
        // Fulu has no `builders`; `pending_consolidations` is the last section,
        // so its body runs to the end of the buffer (`ssz.len()`).
        Self::assemble(
            ssz,
            &offsets,
            pubkeys,
            ssz.len(),
            immutable,
            epoch,
            slot,
            FinalizedBuilders::default(),
        )
    }
}
