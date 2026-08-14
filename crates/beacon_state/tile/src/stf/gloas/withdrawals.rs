use core::cmp::min;

use silver_beacon_state_data::{SLOTS_PER_EPOCH, StateWriterView, Withdrawal};

use super::builders::{
    convert_builder_index_to_validator_index, convert_validator_index_to_builder_index,
    is_builder_index,
};
use crate::stf::{
    get_pending_partial_withdrawals, get_validators_sweep_withdrawals,
    update_next_withdrawal_index, update_next_withdrawal_validator_index,
};

const MAX_WITHDRAWALS_PER_PAYLOAD: usize = 16;
const MAX_BUILDERS_PER_WITHDRAWALS_SWEEP: u64 = 16384;

/// Computes the expected withdrawal set — builder pending → validator partials
/// → builders sweep → validators sweep — applies it, and advances every cursor.
pub fn process_withdrawals(view: &mut StateWriterView) {
    // The parent was EMPTY: no payload, so no withdrawals this block.
    if view.slot.state().latest_block_hash !=
        view.slot.state().latest_execution_payload_bid.block_hash
    {
        return;
    }

    let current_epoch = view.slot.state().slot / SLOTS_PER_EPOCH;
    let mut withdrawals: Vec<Withdrawal> = Vec::new();
    let mut wi = view.slot.state().next_withdrawal_index;

    let processed_builder = get_builder_withdrawals(view, &mut withdrawals, &mut wi);
    let processed_partial =
        get_pending_partial_withdrawals(view, current_epoch, &mut withdrawals, &mut wi);
    let processed_builders_sweep =
        get_builders_sweep_withdrawals(view, current_epoch, &mut withdrawals, &mut wi);
    get_validators_sweep_withdrawals(view, current_epoch, &mut withdrawals, &mut wi);

    apply_withdrawals(view, &withdrawals);

    update_next_withdrawal_index(view, &withdrawals);
    update_next_withdrawal_validator_index(view, &withdrawals);
    if processed_builder > 0 {
        view.pending.builder_withdrawals.drain(processed_builder);
    }
    if processed_partial > 0 {
        view.pending.partial_withdrawals.drain(processed_partial);
    }
    update_next_withdrawal_builder_index(view, processed_builders_sweep);
    view.slot.state_mut().payload_expected_withdrawals = withdrawals;
}

/// Drain `builder_pending_withdrawals` into payouts to each builder's recorded
/// fee recipient, reserving one slot for the validator sweep.
fn get_builder_withdrawals(
    view: &StateWriterView,
    out: &mut Vec<Withdrawal>,
    wi: &mut u64,
) -> usize {
    let limit = MAX_WITHDRAWALS_PER_PAYLOAD - 1;
    let bpw = view.pending.builder_withdrawals.reader();
    let mut processed = 0;
    for i in 0..bpw.len() {
        if out.len() >= limit {
            break;
        }
        let w = *bpw.get(i);
        out.push(Withdrawal {
            index: *wi,
            validator_index: convert_builder_index_to_validator_index(w.builder_index),
            address: w.fee_recipient,
            amount: w.amount,
        });
        *wi += 1;
        processed += 1;
    }
    processed
}

/// Round-robin sweep of exited builders' collateral to their execution address.
fn get_builders_sweep_withdrawals(
    view: &StateWriterView,
    current_epoch: u64,
    out: &mut Vec<Withdrawal>,
    wi: &mut u64,
) -> usize {
    let builders = view.builders.reader();
    let n = builders.len() as u64;
    if n == 0 {
        return 0;
    }
    let bound = min(n, MAX_BUILDERS_PER_WITHDRAWALS_SWEEP);
    let withdrawals_limit = MAX_WITHDRAWALS_PER_PAYLOAD - 1;
    let mut bi = view.slot.state().next_withdrawal_builder_index;
    let mut processed = 0;
    for _ in 0..bound {
        if out.len() >= withdrawals_limit {
            break;
        }
        let b = builders.get(bi as usize).unwrap();
        if b.withdrawable_epoch <= current_epoch && b.balance > 0 {
            out.push(Withdrawal {
                index: *wi,
                validator_index: convert_builder_index_to_validator_index(bi),
                address: b.execution_address,
                amount: b.balance,
            });
            *wi += 1;
        }
        bi = (bi + 1) % n;
        processed += 1;
    }
    processed
}

fn apply_withdrawals(view: &mut StateWriterView, withdrawals: &[Withdrawal]) {
    for w in withdrawals {
        if is_builder_index(w.validator_index) {
            let bi = convert_validator_index_to_builder_index(w.validator_index) as usize;
            view.builders.sub_balance(bi, w.amount);
        } else {
            let vi = w.validator_index as u32;
            let balance = view.balances.get(vi as usize);
            view.balances.set(vi, balance.saturating_sub(w.amount));
        }
    }
}

fn update_next_withdrawal_builder_index(view: &mut StateWriterView, processed_sweep: usize) {
    let n = view.builders.reader().len() as u64;
    if n > 0 {
        let next = view.slot.state().next_withdrawal_builder_index + processed_sweep as u64;
        view.slot.state_mut().next_withdrawal_builder_index = next % n;
    }
}
