use super::{delta::SlotStateDelta, epoch_balances::EpochBalances};
use crate::{
    DecomposeError, EpochStateFinalized,
    decompose::{
        common::{F2, F4, F8, F10, F25, F26, F28, F30, F31, F32, F33, Offsets, b256, u64_le},
        gloas::{
            G_BUILDER_PENDING_PAYMENTS, G_CONSOLIDATION_BALANCE_TO_CONSUME,
            G_DEPOSIT_REQUESTS_START_INDEX, G_EARLIEST_CONSOLIDATION_EPOCH, G_EARLIEST_EXIT_EPOCH,
            G_EXECUTION_PAYLOAD_AVAILABILITY, G_EXIT_BALANCE_TO_CONSUME, G_LATEST_BLOCK_HASH,
            G_NEXT_WITHDRAWAL_BUILDER_INDEX, G_NEXT_WITHDRAWAL_INDEX,
            G_NEXT_WITHDRAWAL_VALIDATOR_INDEX, GloasOffsets,
        },
    },
    gloas::{
        BUILDER_PENDING_PAYMENTS_LEN, BuilderPendingPayment, EXECUTION_PAYLOAD_AVAILABILITY_BYTES,
        ExecutionPayloadBid, MAX_WITHDRAWALS_PER_PAYLOAD, Withdrawal,
    },
    types::{
        BeaconBlockHeader, EPOCHS_PER_HISTORICAL_VECTOR, Eth1Data, ExecutionPayloadHeader,
        SLOTS_PER_EPOCH, SlotState,
    },
};

// SSZ-serialised sizes of the Gloas fixed-width records.
const WITHDRAWAL_SSZ: usize = 44;
const BUILDER_PENDING_PAYMENT_SSZ: usize = 52;

// size: ~1 KB inline — the `SlotState` scalars.
#[derive(Clone, Default)]
pub struct SlotStateFinalized {
    pub(super) slot: SlotState,
    pub(super) epoch_balances: EpochBalances,
}

impl SlotStateFinalized {
    pub fn new(slot: SlotState) -> Self {
        Self { slot, epoch_balances: Default::default() }
    }

    #[inline]
    pub(crate) fn state(&self) -> &SlotState {
        &self.slot
    }

    pub(crate) fn with_epoch_balances(mut self, epoch_balances: EpochBalances) -> Self {
        self.epoch_balances = epoch_balances;
        self
    }

    /// Adopt a fork's delta as the base — the data half of finalization.
    pub(super) fn promote(&mut self, delta: &SlotStateDelta) {
        self.slot.clone_from(&delta.slot);
        self.epoch_balances = delta.epoch_balances;
    }

    pub(crate) fn from_ssz_fulu(
        ssz: &[u8],
        o: &Offsets,
        epoch: &EpochStateFinalized,
    ) -> Result<Self, DecomposeError> {
        let mut slot = SlotState {
            slot: u64_le(ssz, F2),
            latest_block_header: BeaconBlockHeader::from_ssz(&ssz[F4..]),
            eth1_data: Eth1Data::from_ssz(&ssz[F8..]),
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

        slot.latest_execution_payload_header =
            ExecutionPayloadHeader::from_ssz(&ssz[o.eph..o.hist_summaries])?;

        // Derived per-block accumulator: seed from the current epoch's bucket.
        let current_epoch = slot.slot / SLOTS_PER_EPOCH;
        slot.randao_mix_current =
            epoch.randao_mixes[current_epoch as usize % EPOCHS_PER_HISTORICAL_VECTOR];

        Ok(Self::new(slot))
    }

    pub(crate) fn from_ssz_gloas(
        ssz: &[u8],
        off: &GloasOffsets,
        epoch: &EpochStateFinalized,
    ) -> Result<Self, DecomposeError> {
        let mut slot = SlotState {
            slot: u64_le(ssz, F2),
            latest_block_header: BeaconBlockHeader::from_ssz(&ssz[F4..]),
            eth1_data: Eth1Data::from_ssz(&ssz[F8..]),
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
            latest_execution_payload_bid: ExecutionPayloadBid::from_ssz(
                &ssz[off.latest_execution_payload_bid..off.payload_expected_withdrawals],
            )?,
            payload_expected_withdrawals: read_expected_withdrawals(ssz, off)?,
            // `latest_execution_payload_header` has no Gloas SSZ field (default);
            // the two `*_current` accumulators seed from the epoch base below.
            ..Default::default()
        };

        let current_epoch = (slot.slot / SLOTS_PER_EPOCH) as usize;
        slot.randao_mix_current = epoch.randao_mixes[current_epoch % EPOCHS_PER_HISTORICAL_VECTOR];

        Ok(Self::new(slot))
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

fn read_pending_payments(ssz: &[u8]) -> [BuilderPendingPayment; BUILDER_PENDING_PAYMENTS_LEN] {
    let mut payments = [BuilderPendingPayment::default(); BUILDER_PENDING_PAYMENTS_LEN];
    for (i, p) in payments.iter_mut().enumerate() {
        *p = BuilderPendingPayment::from_ssz(
            &ssz[G_BUILDER_PENDING_PAYMENTS + i * BUILDER_PENDING_PAYMENT_SSZ..],
        );
    }
    payments
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
    Ok((0..count).map(|i| Withdrawal::from_ssz(&body[i * WITHDRAWAL_SSZ..])).collect())
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
