use core::cmp::min;

use silver_beacon_state_data::{
    BalancesWriteView, ExecutionPayloadHeader, PendingWriteView, SLOTS_PER_EPOCH, Slot,
    SlotStateWriteView, SpecConfig, StateWriterView, ValidatorsWriteView,
};
use silver_common::ssz_view::{ExecutionPayloadView, WITHDRAWAL_SIZE, WithdrawalView};

use crate::{
    error::{ExecutionPayloadError, Result, WithdrawalRecord, WithdrawalsError},
    ssz_hash,
    stf::MIN_ACTIVATION_BALANCE,
    validate,
};

const MAX_WITHDRAWALS_PER_PAYLOAD: usize = 16;

/// Validate header sanity then cache the execution payload header.
/// No BLS sigs; everything happens in pass 2.
pub fn process_execution_payload(
    view: &mut StateWriterView,
    cfg: &SpecConfig,
    payload_bytes: &[u8],
    block_slot: Slot,
) -> Result<(), ExecutionPayloadError> {
    let imm = view.imm;
    let slot = &mut view.slot;
    if payload_bytes.len() < 528 {
        return Err(ExecutionPayloadError::TooShort { len: payload_bytes.len(), min: 528 });
    }

    validate::validate_execution_payload(
        cfg,
        &slot.reader(),
        imm.genesis_time,
        payload_bytes,
        block_slot,
    )?;

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

const MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP: u64 = 16384;

const MAX_PENDING_PARTIALS_PER_SWEEP: usize = 8;

/// Cursor and accumulators tracked across the two withdrawal phases.
struct WithdrawalsCursor {
    /// (validator_index, amount) selected in the partials phase, used by the
    /// sweep to discount already-debited balance.
    selected: [(u64, u64); MAX_PENDING_PARTIALS_PER_SWEEP],
    partials_emitted: usize,
    processed_partial_count: usize,
    expected_count: usize,
    withdrawal_index: u64,
    last_emitted_vi: u64,
}

impl WithdrawalsCursor {
    fn new(withdrawal_index: u64) -> Self {
        Self {
            selected: [(0, 0); MAX_PENDING_PARTIALS_PER_SWEEP],
            partials_emitted: 0,
            processed_partial_count: 0,
            expected_count: 0,
            withdrawal_index,
            last_emitted_vi: 0,
        }
    }
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

/// Process withdrawals from the execution payload.
/// Withdrawal SSZ: index(8) + validator_index(8) + address(20) + amount(8) = 44
/// bytes.
pub fn process_withdrawals(
    view: &mut StateWriterView,
    payload_bytes: &[u8],
) -> Result<(), WithdrawalsError> {
    let slot = &mut view.slot;
    let validators = &view.validators;
    let balances = &mut view.balances;
    let pending = &mut view.pending;
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

    let count = validators.count();
    let n_validators = count as u64;
    let current_epoch = slot.state().slot / SLOTS_PER_EPOCH;
    let mut cursor = WithdrawalsCursor::new(slot.state().next_withdrawal_index);

    process_partial_withdrawals(
        validators,
        balances,
        pending,
        withdrawals_data,
        current_epoch,
        count,
        &mut cursor,
    )?;
    process_sweep_withdrawals(
        slot,
        validators,
        balances,
        withdrawals_data,
        current_epoch,
        count,
        n_validators,
        &mut cursor,
    )?;

    if cursor.expected_count != payload_count {
        return Err(WithdrawalsError::CountMismatch {
            expected: cursor.expected_count,
            actual: payload_count,
        });
    }

    apply_withdrawals(
        slot,
        balances,
        pending,
        withdrawals_data,
        payload_count,
        count,
        n_validators,
        &cursor,
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn process_partial_withdrawals(
    validators: &ValidatorsWriteView,
    balances: &BalancesWriteView,
    pending: &PendingWriteView,
    withdrawals_data: &[u8],
    current_epoch: u64,
    count: usize,
    cursor: &mut WithdrawalsCursor,
) -> Result<(), WithdrawalsError> {
    let partial_limit = min(MAX_PENDING_PARTIALS_PER_SWEEP, MAX_WITHDRAWALS_PER_PAYLOAD - 1);
    let ppw_len = pending.partial_withdrawals.reader().len();

    for qi in 0..ppw_len {
        let pw = *pending.partial_withdrawals.reader().get(qi);
        if pw.withdrawable_epoch > current_epoch || cursor.partials_emitted >= partial_limit {
            break;
        }
        let vi = pw.index as u32;
        if (vi as usize) < count {
            let total_withdrawn =
                sum_selected_for(&cursor.selected[..cursor.partials_emitted], pw.index);
            let balance = balances.get(vi as usize).saturating_sub(total_withdrawn);
            let eligible = validators.exit_epoch(vi as usize) == u64::MAX &&
                validators.effective_balance(vi as usize) >= MIN_ACTIVATION_BALANCE &&
                balance > MIN_ACTIVATION_BALANCE;
            if eligible {
                let amount = min(balance - MIN_ACTIVATION_BALANCE, pw.amount);
                let creds = validators.credentials(vi as usize);
                let expected = WithdrawalRecord {
                    index: cursor.withdrawal_index,
                    validator_index: pw.index,
                    address: *creds.execution_address(),
                    amount,
                };
                let got = payload_record(withdrawals_data, cursor.expected_count);
                if got != expected {
                    return Err(WithdrawalsError::PartialMismatch {
                        payload_index: cursor.expected_count,
                        expected,
                        got,
                    });
                }
                cursor.selected[cursor.partials_emitted] = (pw.index, amount);
                cursor.partials_emitted += 1;
                cursor.expected_count += 1;
                cursor.withdrawal_index += 1;
                cursor.last_emitted_vi = pw.index;
            }
        }
        cursor.processed_partial_count += 1;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn process_sweep_withdrawals(
    slot: &SlotStateWriteView,
    validators: &ValidatorsWriteView,
    balances: &BalancesWriteView,
    withdrawals_data: &[u8],
    current_epoch: u64,
    count: usize,
    n_validators: u64,
    cursor: &mut WithdrawalsCursor,
) -> Result<(), WithdrawalsError> {
    if n_validators == 0 {
        return Ok(());
    }
    let mut sweep_vi = slot.state().next_withdrawal_validator_index;
    let bound = min(n_validators, MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP);

    for _ in 0..bound {
        let vi = sweep_vi as u32;
        if (vi as usize) < count {
            sweep_one_validator(
                validators,
                balances,
                withdrawals_data,
                sweep_vi,
                current_epoch,
                cursor,
            )?;
        }
        if cursor.expected_count >= MAX_WITHDRAWALS_PER_PAYLOAD {
            break;
        }
        sweep_vi = (sweep_vi + 1) % n_validators;
    }
    Ok(())
}

fn sweep_one_validator(
    validators: &ValidatorsWriteView,
    balances: &BalancesWriteView,
    withdrawals_data: &[u8],
    sweep_vi: u64,
    current_epoch: u64,
    cursor: &mut WithdrawalsCursor,
) -> Result<(), WithdrawalsError> {
    let vi = sweep_vi as u32;
    let creds = *validators.credentials(vi as usize);
    if !creds.has_execution_credential() {
        return Ok(());
    }

    let partial_drawn = sum_selected_for(&cursor.selected[..cursor.partials_emitted], sweep_vi);
    let balance = balances.get(vi as usize).saturating_sub(partial_drawn);
    let max_eb = creds.max_effective_balance();
    let address = *creds.execution_address();
    let wd_epoch = validators.withdrawable_epoch(vi as usize);
    let effective_balance = validators.effective_balance(vi as usize);

    let (expected_amount, kind) = if wd_epoch <= current_epoch && balance > 0 {
        (balance, SweepKind::Full)
    } else if effective_balance == max_eb && balance > max_eb {
        (balance - max_eb, SweepKind::Excess)
    } else {
        return Ok(());
    };

    let expected = WithdrawalRecord {
        index: cursor.withdrawal_index,
        validator_index: sweep_vi,
        address,
        amount: expected_amount,
    };
    let got = payload_record(withdrawals_data, cursor.expected_count);
    if got != expected {
        let pubkey = *validators.pubkey(vi as usize);
        return Err(match kind {
            SweepKind::Full => {
                WithdrawalsError::SweepMismatchFull { vi: sweep_vi, pubkey, expected, got }
            }
            SweepKind::Excess => {
                WithdrawalsError::SweepMismatchExcess { vi: sweep_vi, pubkey, expected, got }
            }
        });
    }
    cursor.expected_count += 1;
    cursor.withdrawal_index += 1;
    cursor.last_emitted_vi = sweep_vi;
    Ok(())
}

enum SweepKind {
    Full,
    Excess,
}

fn sum_selected_for(selected: &[(u64, u64)], vi: u64) -> u64 {
    let mut total = 0u64;
    for &(svi, samt) in selected {
        if svi == vi {
            total = total.saturating_add(samt);
        }
    }
    total
}

#[allow(clippy::too_many_arguments)]
fn apply_withdrawals(
    slot: &mut SlotStateWriteView,
    balances: &mut BalancesWriteView,
    pending: &mut PendingWriteView,
    withdrawals_data: &[u8],
    payload_count: usize,
    count: usize,
    n_validators: u64,
    cursor: &WithdrawalsCursor,
) {
    for i in 0..payload_count {
        let w: &[u8; WITHDRAWAL_SIZE] =
            withdrawals_data[i * WITHDRAWAL_SIZE..(i + 1) * WITHDRAWAL_SIZE].try_into().unwrap();
        let validator_index = WithdrawalView::validator_index(w) as u32;
        let amount = WithdrawalView::amount(w);
        debug_assert!((validator_index as usize) < count);
        let balance = balances.get(validator_index as usize);
        balances.set(validator_index, balance.saturating_sub(amount));
    }
    if cursor.expected_count > 0 {
        slot.state_mut().next_withdrawal_index = cursor.withdrawal_index;
    }
    if cursor.processed_partial_count > 0 {
        pending.partial_withdrawals.drain(cursor.processed_partial_count);
    }
    if n_validators > 0 {
        if cursor.expected_count == MAX_WITHDRAWALS_PER_PAYLOAD {
            slot.state_mut().next_withdrawal_validator_index =
                (cursor.last_emitted_vi + 1) % n_validators;
        } else {
            let next_idx = slot.state().next_withdrawal_validator_index;
            slot.state_mut().next_withdrawal_validator_index =
                (next_idx + MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP) % n_validators;
        }
    }
}
