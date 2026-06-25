use silver_common_macros::timed;

use super::common::{
    DecomposeError, F7_OFF, F9_OFF, F11_OFF, F12_OFF, F15_OFF, F16_OFF, F21_OFF, F24_OFF, F27_OFF,
    F34_OFF, F35_OFF, F36_OFF, FIXED_PART, Offsets, u32_le,
};
use crate::{
    BeaconState, EpochStateFinalized, FinalizedBuilders, SlotStateFinalized, SpecConfig,
    types::Immutable,
};

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
