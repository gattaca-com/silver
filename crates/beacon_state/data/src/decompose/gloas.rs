use blst::min_pk::PublicKey;

use super::common::{
    DecomposeError, F7_OFF, F9_OFF, F11_OFF, F12_OFF, F15_OFF, F16_OFF, F21_OFF, F24_OFF, OFFSET,
    Offsets, u32_le,
};
use crate::{
    BeaconState, EpochStateFinalized, FinalizedBuilders, PROPOSER_LOOKAHEAD_SIZE, PTC_SIZE,
    SlotStateFinalized, SpecConfig,
    gloas::{
        BUILDER_PENDING_PAYMENT_SSZ, BUILDER_PENDING_PAYMENTS_LEN,
        EXECUTION_PAYLOAD_AVAILABILITY_BYTES, PTC_WINDOW_LEN,
    },
};

// Gloas fixed-part byte offsets, from field 24 on (≤ F23 shares Fulu's
// positions). Each names the field that starts there; `*_OFF` are 4-byte
// variable-field offsets.
pub(crate) const G_LATEST_BLOCK_HASH: usize = F24_OFF;
pub(crate) const G_NEXT_WITHDRAWAL_INDEX: usize = G_LATEST_BLOCK_HASH + 32;
pub(crate) const G_NEXT_WITHDRAWAL_VALIDATOR_INDEX: usize = G_NEXT_WITHDRAWAL_INDEX + 8;
const G_HIST_SUMMARIES_OFF: usize = G_NEXT_WITHDRAWAL_VALIDATOR_INDEX + 8;
pub(crate) const G_DEPOSIT_REQUESTS_START_INDEX: usize = G_HIST_SUMMARIES_OFF + OFFSET;
pub(crate) const G_DEPOSIT_BALANCE_TO_CONSUME: usize = G_DEPOSIT_REQUESTS_START_INDEX + 8;
pub(crate) const G_EXIT_BALANCE_TO_CONSUME: usize = G_DEPOSIT_BALANCE_TO_CONSUME + 8;
pub(crate) const G_EARLIEST_EXIT_EPOCH: usize = G_EXIT_BALANCE_TO_CONSUME + 8;
pub(crate) const G_CONSOLIDATION_BALANCE_TO_CONSUME: usize = G_EARLIEST_EXIT_EPOCH + 8;
pub(crate) const G_EARLIEST_CONSOLIDATION_EPOCH: usize = G_CONSOLIDATION_BALANCE_TO_CONSUME + 8;
const G_PENDING_DEPOSITS_OFF: usize = G_EARLIEST_CONSOLIDATION_EPOCH + 8;
const G_PENDING_PARTIAL_OFF: usize = G_PENDING_DEPOSITS_OFF + OFFSET;
const G_PENDING_CONSOLIDATIONS_OFF: usize = G_PENDING_PARTIAL_OFF + OFFSET;
pub(crate) const G_PROPOSER_LOOKAHEAD: usize = G_PENDING_CONSOLIDATIONS_OFF + OFFSET;
const G_BUILDERS_OFF: usize = G_PROPOSER_LOOKAHEAD + PROPOSER_LOOKAHEAD_SIZE * size_of::<u64>();
pub(crate) const G_NEXT_WITHDRAWAL_BUILDER_INDEX: usize = G_BUILDERS_OFF + OFFSET;
pub(crate) const G_EXECUTION_PAYLOAD_AVAILABILITY: usize = G_NEXT_WITHDRAWAL_BUILDER_INDEX + 8;
pub(crate) const G_BUILDER_PENDING_PAYMENTS: usize =
    G_EXECUTION_PAYLOAD_AVAILABILITY + EXECUTION_PAYLOAD_AVAILABILITY_BYTES;
const G_BUILDER_PENDING_WITHDRAWALS_OFF: usize =
    G_BUILDER_PENDING_PAYMENTS + BUILDER_PENDING_PAYMENTS_LEN * BUILDER_PENDING_PAYMENT_SSZ;
const G_LATEST_EXECUTION_PAYLOAD_BID_OFF: usize = G_BUILDER_PENDING_WITHDRAWALS_OFF + OFFSET;
const G_PAYLOAD_EXPECTED_WITHDRAWALS_OFF: usize = G_LATEST_EXECUTION_PAYLOAD_BID_OFF + OFFSET;
pub(crate) const G_PTC_WINDOW: usize = G_PAYLOAD_EXPECTED_WITHDRAWALS_OFF + OFFSET;
pub(crate) const GLOAS_FIXED_PART: usize =
    G_PTC_WINDOW + PTC_WINDOW_LEN * PTC_SIZE * size_of::<u64>();

/// Validated Gloas variable-field offsets: the Fulu-shaped `shared` set (with
/// `eph` repurposed as the inactivity/historical_summaries boundary) plus the
/// four Gloas-only var bodies.
pub(crate) struct GloasOffsets {
    pub(crate) shared: Offsets,
    pub(crate) builders: usize,
    pub(crate) builder_pending_withdrawals: usize,
    pub(crate) latest_execution_payload_bid: usize,
    pub(crate) payload_expected_withdrawals: usize,
}

pub(super) fn decompose(
    ssz: &[u8],
    cfg: &SpecConfig,
    pubkeys: Option<&[PublicKey]>,
) -> Result<BeaconState, DecomposeError> {
    if ssz.len() < GLOAS_FIXED_PART {
        return Err(DecomposeError::TruncatedFixedPart { len: ssz.len(), need: GLOAS_FIXED_PART });
    }
    let off = read_offsets(ssz)?;
    let epoch = EpochStateFinalized::from_ssz_gloas(ssz);
    let slot = SlotStateFinalized::from_ssz_gloas(ssz, &off)?;
    let builders =
        FinalizedBuilders::from_ssz(&ssz[off.builders..off.builder_pending_withdrawals])?;

    // The shared tiers (eth1, validators, columns, longtail, pending) are
    // identical to Fulu given the offsets; `builders` bounds the
    // `pending_consolidations` body in place of the end of the buffer
    // (`ssz.len()`).
    BeaconState::assemble(
        ssz,
        &off.shared,
        pubkeys,
        off.builders,
        &ssz[off.builder_pending_withdrawals..off.latest_execution_payload_bid],
        epoch,
        slot,
        builders,
        cfg,
    )
}

fn read_offsets(ssz: &[u8]) -> Result<GloasOffsets, DecomposeError> {
    let historical_roots = u32_le(ssz, F7_OFF) as usize;
    let eth1_votes = u32_le(ssz, F9_OFF) as usize;
    let validators = u32_le(ssz, F11_OFF) as usize;
    let balances = u32_le(ssz, F12_OFF) as usize;
    let prev_participation = u32_le(ssz, F15_OFF) as usize;
    let cur_participation = u32_le(ssz, F16_OFF) as usize;
    let inactivity = u32_le(ssz, F21_OFF) as usize;
    let hist_summaries = u32_le(ssz, G_HIST_SUMMARIES_OFF) as usize;
    let pending_deposits = u32_le(ssz, G_PENDING_DEPOSITS_OFF) as usize;
    let pending_withdrawals = u32_le(ssz, G_PENDING_PARTIAL_OFF) as usize;
    let pending_consolidations = u32_le(ssz, G_PENDING_CONSOLIDATIONS_OFF) as usize;
    let builders = u32_le(ssz, G_BUILDERS_OFF) as usize;
    let builder_pending_withdrawals = u32_le(ssz, G_BUILDER_PENDING_WITHDRAWALS_OFF) as usize;
    let latest_execution_payload_bid = u32_le(ssz, G_LATEST_EXECUTION_PAYLOAD_BID_OFF) as usize;
    let payload_expected_withdrawals = u32_le(ssz, G_PAYLOAD_EXPECTED_WITHDRAWALS_OFF) as usize;

    let raw = [
        historical_roots,
        eth1_votes,
        validators,
        balances,
        prev_participation,
        cur_participation,
        inactivity,
        hist_summaries,
        pending_deposits,
        pending_withdrawals,
        pending_consolidations,
        builders,
        builder_pending_withdrawals,
        latest_execution_payload_bid,
        payload_expected_withdrawals,
    ];
    if raw[0] < GLOAS_FIXED_PART {
        return Err(DecomposeError::FirstOffsetBeforeFixedPart {
            off: raw[0],
            fixed: GLOAS_FIXED_PART,
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

    Ok(GloasOffsets {
        // `eph` (Fulu's EPH offset) is unused in Gloas; set to `hist_summaries`
        // so the reused `inactivity..eph` slice bounds the inactivity body at
        // the historical_summaries start — its true Gloas end.
        shared: Offsets {
            historical_roots,
            eth1_votes,
            validators,
            balances,
            prev_participation,
            cur_participation,
            inactivity,
            eph: hist_summaries,
            hist_summaries,
            pending_deposits,
            pending_withdrawals,
            pending_consolidations,
        },
        builders,
        builder_pending_withdrawals,
        latest_execution_payload_bid,
        payload_expected_withdrawals,
    })
}
