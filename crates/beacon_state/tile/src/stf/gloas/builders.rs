use silver_beacon_state_data::{
    Builder, BuilderPendingPayment, Epoch, FAR_FUTURE_EPOCH, SLOTS_PER_EPOCH, StateWriterView,
    Withdrawals,
};
use silver_common::ssz_view::{
    BUILDER_DEPOSIT_REQUEST_SIZE, BUILDER_EXIT_REQUEST_SIZE, BuilderDepositRequestView,
    BuilderExitRequestView,
};

use crate::stf::is_valid_builder_deposit_signature;

/// Delay from exit initiation to a builder's balance becoming withdrawable.
const MIN_BUILDER_WITHDRAWABILITY_DELAY: u64 = 1 << 6;
/// `UINT64_MAX` — the proposer self-built the payload (no builder, no payment).
pub(crate) const BUILDER_INDEX_SELF_BUILD: u64 = u64::MAX;
/// `uint8(0)` — the only builder version permitted to submit bids.
pub(crate) const PAYLOAD_BUILDER_VERSION: u8 = 0;
/// 1 ETH — collateral floor a builder must keep above its pending obligations.
const MIN_DEPOSIT_AMOUNT: u64 = 1_000_000_000;
/// `2**40` — tags a `ValidatorIndex` as referring to the builder registry.
const BUILDER_INDEX_FLAG: u64 = 1 << 40;

#[inline]
pub(crate) fn is_builder_index(validator_index: u64) -> bool {
    validator_index & BUILDER_INDEX_FLAG != 0
}

#[inline]
pub(crate) fn convert_builder_index_to_validator_index(builder_index: u64) -> u64 {
    builder_index | BUILDER_INDEX_FLAG
}

#[inline]
pub(crate) fn convert_validator_index_to_builder_index(validator_index: u64) -> u64 {
    validator_index & !BUILDER_INDEX_FLAG
}
/// A builder payment settles at the epoch boundary only if its
/// accrued same-slot attestation weight reaches this fraction of the per-slot
/// stake.
const BUILDER_PAYMENT_THRESHOLD_NUMERATOR: u64 = 6;
const BUILDER_PAYMENT_THRESHOLD_DENOMINATOR: u64 = 10;
const SPE: usize = SLOTS_PER_EPOCH as usize;

pub(crate) const BUILDER_DEPOSIT_SSZ: usize = BUILDER_DEPOSIT_REQUEST_SIZE;
pub(crate) const BUILDER_EXIT_SSZ: usize = BUILDER_EXIT_REQUEST_SIZE;

#[inline]
pub(crate) fn is_active_builder(builder: &Builder, finalized_epoch: u64) -> bool {
    builder.deposit_epoch < finalized_epoch && builder.withdrawable_epoch == FAR_FUTURE_EPOCH
}

pub(crate) fn get_pending_balance_to_withdraw_for_builder(
    view: &StateWriterView,
    builder_index: u64,
) -> u64 {
    let mut total = 0u64;
    let withdrawals = view.pending.builder_withdrawals.reader();
    for i in 0..withdrawals.len() {
        let w = withdrawals.get(i);
        if w.builder_index == builder_index {
            total += w.amount;
        }
    }
    for payment in view.slot.state().builder_pending_payments.iter() {
        if payment.withdrawal.builder_index == builder_index {
            total += payment.withdrawal.amount;
        }
    }
    total
}

pub(crate) fn can_builder_cover_bid(
    view: &StateWriterView,
    builder_index: u64,
    bid_amount: u64,
) -> bool {
    let balance = view.builders.reader().get(builder_index as usize).map_or(0, |b| b.balance);
    let min_balance =
        MIN_DEPOSIT_AMOUNT + get_pending_balance_to_withdraw_for_builder(view, builder_index);
    balance >= min_balance && balance - min_balance >= bid_amount
}

pub fn get_builder_payment_quorum_threshold(view: &StateWriterView, current_epoch: Epoch) -> u64 {
    let per_slot = view.slot.total_active_balance(current_epoch) / SLOTS_PER_EPOCH;
    per_slot * BUILDER_PAYMENT_THRESHOLD_NUMERATOR / BUILDER_PAYMENT_THRESHOLD_DENOMINATOR
}

pub(crate) fn settle_builder_payment(view: &mut StateWriterView, payment_index: usize) {
    let payment = view.slot.state().builder_pending_payments[payment_index];
    if payment.withdrawal.amount > 0 {
        view.pending.builder_withdrawals.push(payment.withdrawal);
    }
    view.slot.state_mut().builder_pending_payments[payment_index] =
        BuilderPendingPayment::default();
}

/// Settle the previous epoch's builder payments (weight ≥ quorum) into
/// `builder_pending_withdrawals`, then shift the two-epoch payment window
/// forward by one epoch and clear the now-current half.
pub fn process_builder_pending_payments(view: &mut StateWriterView, current_epoch: Epoch) {
    let quorum = get_builder_payment_quorum_threshold(view, current_epoch);

    for i in 0..SPE {
        let payment = view.slot.state().builder_pending_payments[i];
        if payment.weight >= quorum {
            view.pending.builder_withdrawals.push(payment.withdrawal);
        }
    }

    let payments = &mut view.slot.state_mut().builder_pending_payments;
    payments.copy_within(SPE.., 0);
    payments[SPE..].fill(BuilderPendingPayment::default());
}

pub fn process_builder_deposit_request(view: &mut StateWriterView, request: &[u8]) {
    let request: &[u8; BUILDER_DEPOSIT_REQUEST_SIZE] = request.try_into().unwrap();
    let pubkey = *BuilderDepositRequestView::pubkey(request);
    let credentials = Withdrawals(*BuilderDepositRequestView::withdrawal_credentials(request));
    let amount = BuilderDepositRequestView::amount(request);
    let signature = *BuilderDepositRequestView::signature(request);

    // Deposits with unexpected withdrawal credential prefixes are ignored.
    if !credentials.has_builder_credential() {
        return;
    }

    let current_epoch = view.slot.state().slot / SLOTS_PER_EPOCH;

    match view.builders.reader().find_by_pubkey(&pubkey) {
        None => {
            if is_valid_builder_deposit_signature(&pubkey, &credentials, amount, &signature) {
                add_builder_to_registry(view, pubkey, &credentials, amount, current_epoch);
            }
        }
        Some(builder_index) => {
            // An exited-and-swept builder re-enters the withdrawal sweep.
            let b = *view.builders.reader().get(builder_index).unwrap();
            if b.withdrawable_epoch != FAR_FUTURE_EPOCH && b.balance == 0 {
                view.builders.set_withdrawable_epoch(
                    builder_index,
                    current_epoch + MIN_BUILDER_WITHDRAWABILITY_DELAY,
                );
            }
            view.builders.add_balance(builder_index, amount);
        }
    }
}

fn add_builder_to_registry(
    view: &mut StateWriterView,
    pubkey: [u8; 48],
    credentials: &Withdrawals,
    amount: u64,
    current_epoch: u64,
) {
    let builder = Builder {
        pubkey,
        version: PAYLOAD_BUILDER_VERSION,
        execution_address: *credentials.execution_address(),
        balance: amount,
        deposit_epoch: current_epoch,
        withdrawable_epoch: FAR_FUTURE_EPOCH,
    };
    match get_index_for_new_builder(view, current_epoch) {
        Some(builder_index) => view.builders.set_builder(builder_index, builder),
        None => view.builders.push(builder),
    }
}

fn get_index_for_new_builder(view: &StateWriterView, current_epoch: u64) -> Option<usize> {
    let builders = view.builders.reader();
    (0..builders.len()).find(|&i| {
        let b = builders.get(i).unwrap();
        b.withdrawable_epoch <= current_epoch && b.balance == 0
    })
}

pub fn process_builder_exit_request(
    view: &mut StateWriterView,
    finalized_epoch: u64,
    request: &[u8],
) {
    let request: &[u8; BUILDER_EXIT_REQUEST_SIZE] = request.try_into().unwrap();
    let source_address = *BuilderExitRequestView::source_address(request);
    let pubkey = *BuilderExitRequestView::pubkey(request);

    let Some(builder_index) = view.builders.reader().find_by_pubkey(&pubkey) else {
        return;
    };
    let builder = *view.builders.reader().get(builder_index).unwrap();
    if !is_active_builder(&builder, finalized_epoch) {
        return;
    }
    if builder.execution_address != source_address {
        return;
    }
    if get_pending_balance_to_withdraw_for_builder(view, builder_index as u64) != 0 {
        return;
    }
    initiate_builder_exit(view, builder_index);
}

fn initiate_builder_exit(view: &mut StateWriterView, builder_index: usize) {
    let current_epoch = view.slot.state().slot / SLOTS_PER_EPOCH;
    view.builders
        .set_withdrawable_epoch(builder_index, current_epoch + MIN_BUILDER_WITHDRAWABILITY_DELAY);
}
