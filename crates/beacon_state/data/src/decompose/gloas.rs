use blst::min_pk::PublicKey;

use super::common::{
    DecomposeError, F2, F4, F5, F6, F7_OFF, F8, F9_OFF, F10, F11_OFF, F12_OFF, F13, F14, F15_OFF,
    F16_OFF, F17, F18, F19, F20, F21_OFF, Offsets, b256, read_checkpoint, u32_le, u64_le,
};
use crate::{
    BeaconState, BuilderPendingPayment, BuilderPendingWithdrawal, EpochStateFinalized,
    ExecutionPayloadBid, FinalizedBuilders, SlotStateFinalized, SpecConfig, Withdrawal,
    gloas::{
        BUILDER_PENDING_PAYMENTS_LEN, BUILDER_PENDING_WITHDRAWALS_LIMIT,
        EXECUTION_PAYLOAD_AVAILABILITY_BYTES, MAX_BLOB_COMMITMENTS_PER_BLOCK,
        MAX_WITHDRAWALS_PER_PAYLOAD, PTC_SIZE, PTC_WINDOW_LEN,
    },
    types::{
        B256, BeaconBlockHeader, EPOCHS_PER_HISTORICAL_VECTOR, EPOCHS_PER_SLASHINGS_VECTOR,
        EpochState, Eth1Data, Immutable, PROPOSER_LOOKAHEAD_SIZE, SLOTS_PER_EPOCH,
        SLOTS_PER_HISTORICAL_ROOT, SlotState,
    },
};

// Gloas fixed-part byte offsets, from field 24 on (≤ F23 shares Fulu's
// positions). Running offset shown; `*_OFF` are 4-byte variable-field offsets.
const G_LATEST_BLOCK_HASH: usize = 2_736_629; // 32  (Fulu's F24_OFF slot)
const G_NEXT_WITHDRAWAL_INDEX: usize = 2_736_661; // 8
const G_NEXT_WITHDRAWAL_VALIDATOR_INDEX: usize = 2_736_669; // 8
const G_HIST_SUMMARIES_OFF: usize = 2_736_677; // 4
const G_DEPOSIT_REQUESTS_START_INDEX: usize = 2_736_681; // 8
const G_DEPOSIT_BALANCE_TO_CONSUME: usize = 2_736_689; // 8
const G_EXIT_BALANCE_TO_CONSUME: usize = 2_736_697; // 8
const G_EARLIEST_EXIT_EPOCH: usize = 2_736_705; // 8
const G_CONSOLIDATION_BALANCE_TO_CONSUME: usize = 2_736_713; // 8
const G_EARLIEST_CONSOLIDATION_EPOCH: usize = 2_736_721; // 8
const G_PENDING_DEPOSITS_OFF: usize = 2_736_729; // 4
const G_PENDING_PARTIAL_OFF: usize = 2_736_733; // 4
const G_PENDING_CONSOLIDATIONS_OFF: usize = 2_736_737; // 4
const G_PROPOSER_LOOKAHEAD: usize = 2_736_741; // 512
const G_BUILDERS_OFF: usize = 2_737_253; // 4
const G_NEXT_WITHDRAWAL_BUILDER_INDEX: usize = 2_737_257; // 8
const G_EXECUTION_PAYLOAD_AVAILABILITY: usize = 2_737_265; // 1024
const G_BUILDER_PENDING_PAYMENTS: usize = 2_738_289; // 64 × 52 = 3328
const G_BUILDER_PENDING_WITHDRAWALS_OFF: usize = 2_741_617; // 4
const G_LATEST_EXECUTION_PAYLOAD_BID_OFF: usize = 2_741_621; // 4
const G_PAYLOAD_EXPECTED_WITHDRAWALS_OFF: usize = 2_741_625; // 4
const G_PTC_WINDOW: usize = 2_741_629; // 96 × 512 × 8 = 393216
const GLOAS_FIXED_PART: usize = 3_134_845;

const _: () = assert!(G_PTC_WINDOW + PTC_WINDOW_LEN * PTC_SIZE * 8 == GLOAS_FIXED_PART);

// SSZ-serialised sizes of the new fixed-width records.
const BUILDER_PENDING_WITHDRAWAL_SSZ: usize = 36;
const BUILDER_PENDING_PAYMENT_SSZ: usize = 52;
const WITHDRAWAL_SSZ: usize = 44;
const KZG_COMMITMENT_SSZ: usize = 48;
/// `ExecutionPayloadBid` fixed part; `blob_kzg_commitments` follow at this
/// offset (its 4-byte offset slot sits at +188 within the bid body).
const EXECUTION_PAYLOAD_BID_FIXED: usize = 224;

/// Validated Gloas variable-field offsets: the Fulu-shaped `shared` set (with
/// `eph` repurposed as the inactivity/historical_summaries boundary) plus the
/// four Gloas-only var bodies.
struct GloasOffsets {
    shared: Offsets,
    builders: usize,
    builder_pending_withdrawals: usize,
    latest_execution_payload_bid: usize,
    payload_expected_withdrawals: usize,
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
    let mut immutable = Immutable::default();
    immutable.fill_from_ssz(ssz, cfg);
    let epoch = epoch_finalized(ssz);
    let slot = slot_finalized(ssz, &off, &epoch)?;
    let builders =
        FinalizedBuilders::from_ssz(&ssz[off.builders..off.builder_pending_withdrawals])?;

    // The shared tiers (eth1, validators, columns, longtail, pending) are
    // identical to Fulu given the offsets; `builders` bounds the
    // `pending_consolidations` body in place of the end of the buffer
    // (`ssz.len()`).
    BeaconState::assemble(ssz, &off.shared, pubkeys, off.builders, immutable, epoch, slot, builders)
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

fn epoch_finalized(ssz: &[u8]) -> EpochStateFinalized {
    let mut randao_mixes = vec![[0u8; 32]; EPOCHS_PER_HISTORICAL_VECTOR].into_boxed_slice();
    let randao_src: &[B256] = unsafe {
        std::slice::from_raw_parts(ssz[F13..].as_ptr().cast::<B256>(), EPOCHS_PER_HISTORICAL_VECTOR)
    };
    randao_mixes.copy_from_slice(randao_src);

    let mut slashings = vec![0u64; EPOCHS_PER_SLASHINGS_VECTOR].into_boxed_slice();
    for (i, s) in slashings.iter_mut().enumerate() {
        *s = u64_le(ssz, F14 + i * 8);
    }

    let mut est = EpochState::default();
    for (i, p) in est.proposer_lookahead.iter_mut().enumerate() {
        *p = u64_le(ssz, G_PROPOSER_LOOKAHEAD + i * 8);
    }
    debug_assert_eq!(est.proposer_lookahead.len(), PROPOSER_LOOKAHEAD_SIZE);
    est.justification_bits = ssz[F17] & 0x0F;
    est.previous_justified_checkpoint = read_checkpoint(ssz, F18);
    est.current_justified_checkpoint = read_checkpoint(ssz, F19);
    est.finalized_checkpoint = read_checkpoint(ssz, F20);
    est.deposit_balance_to_consume = u64_le(ssz, G_DEPOSIT_BALANCE_TO_CONSUME);
    for (c, committee) in est.ptc_window.iter_mut().enumerate() {
        for (j, v) in committee.iter_mut().enumerate() {
            *v = u64_le(ssz, G_PTC_WINDOW + (c * PTC_SIZE + j) * 8);
        }
    }

    EpochStateFinalized::from_parts(est, randao_mixes, slashings)
}

fn slot_finalized(
    ssz: &[u8],
    off: &GloasOffsets,
    epoch: &EpochStateFinalized,
) -> Result<SlotStateFinalized, DecomposeError> {
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
        latest_block_hash: b256(ssz, G_LATEST_BLOCK_HASH),
        next_withdrawal_index: u64_le(ssz, G_NEXT_WITHDRAWAL_INDEX),
        next_withdrawal_validator_index: u64_le(ssz, G_NEXT_WITHDRAWAL_VALIDATOR_INDEX),
        deposit_requests_start_index: u64_le(ssz, G_DEPOSIT_REQUESTS_START_INDEX),
        exit_balance_to_consume: u64_le(ssz, G_EXIT_BALANCE_TO_CONSUME),
        earliest_exit_epoch: u64_le(ssz, G_EARLIEST_EXIT_EPOCH),
        consolidation_balance_to_consume: u64_le(ssz, G_CONSOLIDATION_BALANCE_TO_CONSUME),
        earliest_consolidation_epoch: u64_le(ssz, G_EARLIEST_CONSOLIDATION_EPOCH),
        next_withdrawal_builder_index: u64_le(ssz, G_NEXT_WITHDRAWAL_BUILDER_INDEX),
        execution_payload_availability: read_availability(ssz),
        builder_pending_payments: read_pending_payments(ssz),
        builder_pending_withdrawals: read_pending_withdrawals(ssz, off)?,
        latest_execution_payload_bid: read_bid(ssz, off)?,
        payload_expected_withdrawals: read_expected_withdrawals(ssz, off)?,
        // `latest_execution_payload_header` has no Gloas SSZ field (default);
        // the two `*_current` accumulators seed from the epoch base below.
        ..Default::default()
    };

    let current_epoch = (slot.slot / SLOTS_PER_EPOCH) as usize;
    slot.randao_mix_current = epoch.randao_mixes[current_epoch % EPOCHS_PER_HISTORICAL_VECTOR];
    slot.current_epoch_slashings = epoch.slashings[current_epoch % EPOCHS_PER_SLASHINGS_VECTOR];

    Ok(SlotStateFinalized::from_parts(slot, read_roots(ssz, F5), read_roots(ssz, F6)))
}

fn read_pending_withdrawals(
    ssz: &[u8],
    off: &GloasOffsets,
) -> Result<Vec<BuilderPendingWithdrawal>, DecomposeError> {
    let body = &ssz[off.builder_pending_withdrawals..off.latest_execution_payload_bid];
    let count = checked_count(
        body.len(),
        BUILDER_PENDING_WITHDRAWAL_SSZ,
        "builder_pending_withdrawals",
        BUILDER_PENDING_WITHDRAWALS_LIMIT,
    )?;
    Ok((0..count)
        .map(|i| read_pending_withdrawal(&body[i * BUILDER_PENDING_WITHDRAWAL_SSZ..]))
        .collect())
}

fn read_expected_withdrawals(
    ssz: &[u8],
    off: &GloasOffsets,
) -> Result<Vec<Withdrawal>, DecomposeError> {
    // payload_expected_withdrawals is the last variable body.
    let body = &ssz[off.payload_expected_withdrawals..];
    let count = checked_count(
        body.len(),
        WITHDRAWAL_SSZ,
        "payload_expected_withdrawals",
        MAX_WITHDRAWALS_PER_PAYLOAD,
    )?;
    Ok((0..count)
        .map(|i| {
            let s = &body[i * WITHDRAWAL_SSZ..];
            Withdrawal {
                index: u64_le(s, 0),
                validator_index: u64_le(s, 8),
                address: addr20(s, 16),
                amount: u64_le(s, 36),
            }
        })
        .collect())
}

fn read_bid(ssz: &[u8], off: &GloasOffsets) -> Result<ExecutionPayloadBid, DecomposeError> {
    let body = &ssz[off.latest_execution_payload_bid..off.payload_expected_withdrawals];
    if body.len() < EXECUTION_PAYLOAD_BID_FIXED {
        return Err(DecomposeError::GloasFieldLen {
            field: "latest_execution_payload_bid",
            len: body.len(),
            size: EXECUTION_PAYLOAD_BID_FIXED,
        });
    }
    let kzg = &body[u32_le(body, 188) as usize..];
    let count = checked_count(
        kzg.len(),
        KZG_COMMITMENT_SSZ,
        "blob_kzg_commitments",
        MAX_BLOB_COMMITMENTS_PER_BLOCK,
    )?;
    Ok(ExecutionPayloadBid {
        parent_block_hash: b256(body, 0),
        parent_block_root: b256(body, 32),
        block_hash: b256(body, 64),
        prev_randao: b256(body, 96),
        fee_recipient: addr20(body, 128),
        gas_limit: u64_le(body, 148),
        builder_index: u64_le(body, 156),
        slot: u64_le(body, 164),
        value: u64_le(body, 172),
        execution_payment: u64_le(body, 180),
        blob_kzg_commitments: (0..count).map(|i| bytes48(kzg, i * KZG_COMMITMENT_SSZ)).collect(),
        execution_requests_root: b256(body, 192),
    })
}

fn read_pending_payments(ssz: &[u8]) -> [BuilderPendingPayment; BUILDER_PENDING_PAYMENTS_LEN] {
    let mut payments = [BuilderPendingPayment::default(); BUILDER_PENDING_PAYMENTS_LEN];
    for (i, p) in payments.iter_mut().enumerate() {
        let s = &ssz[G_BUILDER_PENDING_PAYMENTS + i * BUILDER_PENDING_PAYMENT_SSZ..];
        *p = BuilderPendingPayment {
            weight: u64_le(s, 0),
            withdrawal: read_pending_withdrawal(&s[8..]),
            proposer_index: u64_le(s, 44),
        };
    }
    payments
}

fn read_pending_withdrawal(s: &[u8]) -> BuilderPendingWithdrawal {
    BuilderPendingWithdrawal {
        fee_recipient: addr20(s, 0),
        amount: u64_le(s, 20),
        builder_index: u64_le(s, 28),
    }
}

fn read_availability(ssz: &[u8]) -> [u8; EXECUTION_PAYLOAD_AVAILABILITY_BYTES] {
    let mut bits = [0u8; EXECUTION_PAYLOAD_AVAILABILITY_BYTES];
    bits.copy_from_slice(
        &ssz[G_EXECUTION_PAYLOAD_AVAILABILITY..
            G_EXECUTION_PAYLOAD_AVAILABILITY + EXECUTION_PAYLOAD_AVAILABILITY_BYTES],
    );
    bits
}

fn read_roots(ssz: &[u8], at: usize) -> Box<[B256]> {
    let mut roots = vec![[0u8; 32]; SLOTS_PER_HISTORICAL_ROOT].into_boxed_slice();
    let src: &[B256] = unsafe {
        std::slice::from_raw_parts(ssz[at..].as_ptr().cast::<B256>(), SLOTS_PER_HISTORICAL_ROOT)
    };
    roots.copy_from_slice(src);
    roots
}

/// List length / cap check shared by the Gloas variable-list readers.
fn checked_count(
    bytes: usize,
    size: usize,
    field: &'static str,
    limit: usize,
) -> Result<usize, DecomposeError> {
    if !bytes.is_multiple_of(size) {
        return Err(DecomposeError::GloasFieldLen { field, len: bytes, size });
    }
    let n = bytes / size;
    if n > limit {
        return Err(DecomposeError::GloasTooMany { field, n, max: limit });
    }
    Ok(n)
}

#[inline]
fn addr20(s: &[u8], off: usize) -> [u8; 20] {
    s[off..off + 20].try_into().unwrap()
}

#[inline]
fn bytes48(s: &[u8], off: usize) -> [u8; 48] {
    s[off..off + 48].try_into().unwrap()
}
