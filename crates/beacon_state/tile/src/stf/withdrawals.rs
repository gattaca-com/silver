use core::cmp::min;

use silver_beacon_state_data::{
    ExecutionPayloadHeader, FAR_FUTURE_EPOCH, SLOTS_PER_EPOCH, Slot, SpecConfig, StateWriterView,
    Withdrawal,
};
use silver_common::ssz_view::{ExecutionPayloadView, WITHDRAWAL_SIZE, WithdrawalView};

use crate::{
    error::{ExecutionPayloadError, Result, WithdrawalRecord, WithdrawalsError},
    ssz_hash,
    stf::MIN_ACTIVATION_BALANCE,
    validate,
};

pub(crate) const MAX_WITHDRAWALS_PER_PAYLOAD: usize = 16;
pub(crate) const MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP: u64 = 16384;
const MAX_PENDING_PARTIALS_PER_WITHDRAWALS_SWEEP: usize = 8;

/// Validate header sanity then cache the execution payload header.
/// No BLS sigs; everything happens in pass 2.
pub fn process_execution_payload(
    view: &mut StateWriterView,
    cfg: &SpecConfig,
    payload_bytes: &[u8],
    block_slot: Slot,
) -> Result<(), ExecutionPayloadError> {
    if payload_bytes.len() < 528 {
        return Err(ExecutionPayloadError::TooShort { len: payload_bytes.len(), min: 528 });
    }

    validate::validate_execution_payload(cfg, view, payload_bytes, block_slot)?;

    let slot = &mut view.slot;

    let extra_data_off = ExecutionPayloadView::extra_data_offset(payload_bytes) as usize;
    let transactions_off = ExecutionPayloadView::transactions_offset(payload_bytes) as usize;
    let extra_data_len = if extra_data_off < transactions_off {
        (transactions_off - extra_data_off).min(32)
    } else {
        0
    };

    let mut extra_data = [0u8; 32];
    if extra_data_len > 0 && extra_data_off + extra_data_len <= payload_bytes.len() {
        extra_data[..extra_data_len]
            .copy_from_slice(&payload_bytes[extra_data_off..extra_data_off + extra_data_len]);
    }

    slot.state_mut().latest_execution_payload_header = ExecutionPayloadHeader {
        parent_hash: *ExecutionPayloadView::parent_hash(payload_bytes),
        fee_recipient: *ExecutionPayloadView::fee_recipient(payload_bytes),
        state_root: *ExecutionPayloadView::state_root(payload_bytes),
        receipts_root: *ExecutionPayloadView::receipts_root(payload_bytes),
        logs_bloom: *ExecutionPayloadView::logs_bloom(payload_bytes),
        prev_randao: *ExecutionPayloadView::prev_randao(payload_bytes),
        block_number: ExecutionPayloadView::block_number(payload_bytes),
        gas_limit: ExecutionPayloadView::gas_limit(payload_bytes),
        gas_used: ExecutionPayloadView::gas_used(payload_bytes),
        timestamp: ExecutionPayloadView::timestamp(payload_bytes),
        extra_data_len: extra_data_len as u8,
        extra_data,
        base_fee_per_gas: *ExecutionPayloadView::base_fee_per_gas(payload_bytes),
        block_hash: *ExecutionPayloadView::block_hash(payload_bytes),
        transactions_root: ssz_hash::hash_transactions_from_payload(payload_bytes),
        withdrawals_root: ssz_hash::hash_withdrawals_from_payload(payload_bytes),
        blob_gas_used: ExecutionPayloadView::blob_gas_used(payload_bytes),
        excess_blob_gas: ExecutionPayloadView::excess_blob_gas(payload_bytes),
    };

    Ok(())
}

/// Electra pending-partial-withdrawal sweep. Appends eligible partials to
/// `out`, advancing `wi`; returns the number of queue entries consumed.
pub(crate) fn get_pending_partial_withdrawals(
    view: &StateWriterView,
    current_epoch: u64,
    out: &mut Vec<Withdrawal>,
    wi: &mut u64,
) -> usize {
    let limit = min(
        out.len() + MAX_PENDING_PARTIALS_PER_WITHDRAWALS_SWEEP,
        MAX_WITHDRAWALS_PER_PAYLOAD - 1,
    );
    let validators = &view.validators;
    let ppw = view.pending.partial_withdrawals.reader();
    let mut processed = 0;
    for i in 0..ppw.len() {
        let pw = *ppw.get(i);
        if pw.withdrawable_epoch > current_epoch || out.len() >= limit {
            break;
        }
        let vi = pw.index;
        let balance = balance_after(view, out, vi);
        if validators.exit_epoch(vi as usize) == FAR_FUTURE_EPOCH &&
            validators.effective_balance(vi as usize) >= MIN_ACTIVATION_BALANCE &&
            balance > MIN_ACTIVATION_BALANCE
        {
            out.push(Withdrawal {
                index: *wi,
                validator_index: vi,
                address: *validators.credentials(vi as usize).execution_address(),
                amount: min(balance - MIN_ACTIVATION_BALANCE, pw.amount),
            });
            *wi += 1;
        }
        processed += 1;
    }
    processed
}

/// Electra validator sweep: round-robin from `next_withdrawal_validator_index`,
/// emitting full or partial withdrawals.
pub(crate) fn get_validators_sweep_withdrawals(
    view: &StateWriterView,
    current_epoch: u64,
    out: &mut Vec<Withdrawal>,
    wi: &mut u64,
) {
    let validators = &view.validators;
    let n = validators.count() as u64;
    if n == 0 {
        return;
    }
    let bound = min(n, MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP);
    let mut vi = view.slot.state().next_withdrawal_validator_index;
    for _ in 0..bound {
        if out.len() >= MAX_WITHDRAWALS_PER_PAYLOAD {
            break;
        }
        let creds = *validators.credentials(vi as usize);
        if creds.has_execution_credential() {
            let balance = balance_after(view, out, vi);
            let max_eb = creds.max_effective_balance();
            let amount =
                if validators.withdrawable_epoch(vi as usize) <= current_epoch && balance > 0 {
                    Some(balance)
                } else if validators.effective_balance(vi as usize) == max_eb && balance > max_eb {
                    Some(balance - max_eb)
                } else {
                    None
                };
            if let Some(amount) = amount {
                out.push(Withdrawal {
                    index: *wi,
                    validator_index: vi,
                    address: *creds.execution_address(),
                    amount,
                });
                *wi += 1;
            }
        }
        vi = (vi + 1) % n;
    }
}

/// Balance net of withdrawals already queued for `vi` this block.
pub(crate) fn balance_after(view: &StateWriterView, out: &[Withdrawal], vi: u64) -> u64 {
    let mut balance = view.balances.get(vi as usize);
    for w in out {
        if w.validator_index == vi {
            balance = balance.saturating_sub(w.amount);
        }
    }
    balance
}

pub(crate) fn update_next_withdrawal_index(view: &mut StateWriterView, withdrawals: &[Withdrawal]) {
    if let Some(last) = withdrawals.last() {
        view.slot.state_mut().next_withdrawal_index = last.index + 1;
    }
}

/// Capella `update_next_withdrawal_validator_index`: resume the sweep after the
/// last withdrawal when the payload filled, else advance by the sweep bound.
pub(crate) fn update_next_withdrawal_validator_index(
    view: &mut StateWriterView,
    withdrawals: &[Withdrawal],
) {
    let n = view.validators.count() as u64;
    if n == 0 {
        return;
    }
    let next = if withdrawals.len() == MAX_WITHDRAWALS_PER_PAYLOAD {
        (withdrawals.last().unwrap().validator_index + 1) % n
    } else {
        (view.slot.state().next_withdrawal_validator_index + MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP) %
            n
    };
    view.slot.state_mut().next_withdrawal_validator_index = next;
}

fn payload_record(withdrawals_data: &[u8], i: usize) -> WithdrawalRecord {
    let count = withdrawals_data.len() / WITHDRAWAL_SIZE;
    if i >= count {
        return WithdrawalRecord::default();
    }
    let w: &[u8; WITHDRAWAL_SIZE] =
        withdrawals_data[i * WITHDRAWAL_SIZE..(i + 1) * WITHDRAWAL_SIZE].try_into().unwrap();
    WithdrawalRecord {
        index: WithdrawalView::index(w),
        validator_index: WithdrawalView::validator_index(w),
        address: *WithdrawalView::address(w),
        amount: WithdrawalView::amount(w),
    }
}

/// Compute the expected withdrawals, assert the payload carries exactly them,
/// then apply and advance the cursors.
pub fn process_withdrawals_fulu(
    view: &mut StateWriterView,
    payload_bytes: &[u8],
) -> Result<(), WithdrawalsError> {
    if payload_bytes.len() < 528 {
        return Err(WithdrawalsError::PayloadTooShort { len: payload_bytes.len(), min: 528 });
    }
    let withdrawals_off = ExecutionPayloadView::withdrawals_offset(payload_bytes) as usize;
    if withdrawals_off > payload_bytes.len() {
        return Err(WithdrawalsError::BadOffsets {
            withdrawals_off,
            payload_len: payload_bytes.len(),
        });
    }
    let withdrawals_data = &payload_bytes[withdrawals_off..];
    let payload_count = withdrawals_data.len() / WITHDRAWAL_SIZE;
    if payload_count > MAX_WITHDRAWALS_PER_PAYLOAD {
        return Err(WithdrawalsError::TooMany {
            count: payload_count,
            max: MAX_WITHDRAWALS_PER_PAYLOAD,
        });
    }

    let current_epoch = view.slot.state().slot / SLOTS_PER_EPOCH;
    let mut expected: Vec<Withdrawal> = Vec::new();
    let mut wi = view.slot.state().next_withdrawal_index;
    let processed_partial =
        get_pending_partial_withdrawals(view, current_epoch, &mut expected, &mut wi);
    get_validators_sweep_withdrawals(view, current_epoch, &mut expected, &mut wi);

    if expected.len() != payload_count {
        return Err(WithdrawalsError::CountMismatch {
            expected: expected.len(),
            actual: payload_count,
        });
    }
    for (i, w) in expected.iter().enumerate() {
        let exp = WithdrawalRecord {
            index: w.index,
            validator_index: w.validator_index,
            address: w.address,
            amount: w.amount,
        };
        let got = payload_record(withdrawals_data, i);
        if got != exp {
            return Err(WithdrawalsError::Mismatch { payload_index: i, expected: exp, got });
        }
    }

    for w in &expected {
        let balance = view.balances.get(w.validator_index as usize);
        view.balances.set(w.validator_index as u32, balance.saturating_sub(w.amount));
    }
    update_next_withdrawal_index(view, &expected);
    if processed_partial > 0 {
        view.pending.partial_withdrawals.drain(processed_partial);
    }
    update_next_withdrawal_validator_index(view, &expected);
    Ok(())
}
