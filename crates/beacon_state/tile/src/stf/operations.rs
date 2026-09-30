use core::cmp::min;

use blst::min_pk::PublicKey;
use flux_profiler::timed;
use silver_beacon_state_data::{
    BalancesWriteView, Epoch, Immutable, PENDING_CONSOLIDATIONS_LIMIT,
    PENDING_PARTIAL_WITHDRAWALS_LIMIT, PendingConsolidation, PendingDeposit,
    PendingPartialWithdrawal, PendingWriteView, SLOTS_PER_EPOCH, SpecConfig, StateWriterView,
    ValidatorsView, ValidatorsWriteView, Withdrawals,
};
use silver_common::ssz_view::{
    CONSOLIDATION_REQUEST_SIZE, ConsolidationRequestView, DEPOSIT_REQUEST_SIZE, DepositRequestView,
    SIGNED_BLS_CHANGE_SIZE, SIGNED_VOLUNTARY_EXIT_SIZE, SignedBlsToExecutionChangeView,
    SignedVoluntaryExitView, WITHDRAWAL_REQUEST_SIZE, WithdrawalRequestView,
};

use crate::{
    bls::{self, SigBatch},
    error::{BlsToExecutionChangeError, Result, VoluntaryExitError},
    ssz_hash,
    stf::{
        MIN_ACTIVATION_BALANCE, compute_consolidation_epoch_and_update_churn,
        compute_exit_epoch_and_update_churn, get_consolidation_churn_limit,
        get_pending_balance_to_withdraw, initiate_validator_exit, is_active,
    },
    validate,
};

const FULL_EXIT_REQUEST_AMOUNT: u64 = 0;

const COMPOUNDING_WITHDRAWAL_PREFIX: u8 = 0x02;

// BLS G2 point at infinity (compressed): 0xc0 followed by 95 zero bytes.
const G2_POINT_AT_INFINITY: [u8; 96] = {
    let mut buf = [0u8; 96];
    buf[0] = 0xc0;
    buf
};

/// Pass 1 — push voluntary-exit sigs. Each exit's signing root is the
/// `(epoch, validator_index)` pair under `DOMAIN_VOLUNTARY_EXIT` pinned to
/// `CAPELLA_FORK_VERSION`. Returns false on out-of-range vi (early reject).
#[timed]
pub fn collect_sigs_voluntary_exits(
    imm: &Immutable,
    validators: &ValidatorsView,
    data: &[u8],
    sig_batch: &mut SigBatch,
) {
    let domain = bls::compute_domain(
        bls::DOMAIN_VOLUNTARY_EXIT,
        imm.capella_fork_version,
        &imm.genesis_validators_root,
    );
    let count = data.len() / SIGNED_VOLUNTARY_EXIT_SIZE;
    let validator_count = validators.count();
    for i in 0..count {
        let exit: &[u8; SIGNED_VOLUNTARY_EXIT_SIZE] = data
            [i * SIGNED_VOLUNTARY_EXIT_SIZE..(i + 1) * SIGNED_VOLUNTARY_EXIT_SIZE]
            .try_into()
            .unwrap();
        let exit_epoch_msg = SignedVoluntaryExitView::epoch(exit);
        let vi_u = SignedVoluntaryExitView::validator_index(exit);
        let vi = vi_u as u32;
        if (vi as usize) >= validator_count {
            sig_batch.poison();
            return;
        }
        let object_root = ssz_hash::hash_tree_root_voluntary_exit(exit_epoch_msg, vi_u);
        let signing_root = bls::compute_signing_root(&object_root, &domain);
        let sig = SignedVoluntaryExitView::signature(exit);
        let pk = validators.pubkey_decompressed(vi as usize);
        sig_batch.push_one(pk, sig, signing_root);
    }
}

/// Pass 2 — validate state-dependent preconditions (post-block-mutation
/// state evolution may change `is_slashable` / pending-balance), apply
/// `initiate_validator_exit` per accepted entry. BLS already verified.
#[timed]
pub fn process_voluntary_exits(
    view: &mut StateWriterView,
    cfg: &SpecConfig,
    data: &[u8],
) -> Result<(), VoluntaryExitError> {
    let count = data.len() / SIGNED_VOLUNTARY_EXIT_SIZE;
    let current_epoch = view.slot.state().slot / SLOTS_PER_EPOCH;
    for i in 0..count {
        let exit: &[u8; SIGNED_VOLUNTARY_EXIT_SIZE] = data
            [i * SIGNED_VOLUNTARY_EXIT_SIZE..(i + 1) * SIGNED_VOLUNTARY_EXIT_SIZE]
            .try_into()
            .unwrap();
        let exit_epoch_msg = SignedVoluntaryExitView::epoch(exit);
        let vi = SignedVoluntaryExitView::validator_index(exit) as u32;
        validate::validate_voluntary_exit(
            cfg,
            &view.validators.reader(),
            vi,
            exit_epoch_msg,
            current_epoch,
        )?;
        if get_pending_balance_to_withdraw(&view.pending.reader(), vi) != 0 {
            return Err(VoluntaryExitError::HasPendingBalance {
                vi: vi as usize,
                pubkey: *view.validators.pubkey(vi as usize),
            });
        }
        initiate_validator_exit(cfg, view, vi, current_epoch);
    }
    Ok(())
}

#[timed]
pub(crate) fn process_execution_requests(
    view: &mut StateWriterView,
    cfg: &SpecConfig,
    data: &[u8],
) {
    if data.len() < 12 {
        return;
    }
    let off = |pos: usize| -> usize {
        u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize
    };
    let offsets = [off(0), off(4), off(8)];
    let field = |idx: usize| -> &[u8] {
        let start = offsets[idx];
        let end = if idx + 1 < offsets.len() { offsets[idx + 1] } else { data.len() };
        if start <= end && end <= data.len() { &data[start..end] } else { &[] }
    };
    let f0 = field(0);
    let f1 = field(1);
    let f2 = field(2);
    process_deposit_requests(&mut *view, f0);
    process_withdrawal_requests(&mut *view, cfg, f1);
    process_consolidation_requests(&mut *view, cfg, f2);
}

#[timed]
pub fn process_deposit_requests(view: &mut StateWriterView, data: &[u8]) {
    let slot = &mut view.slot;
    let pending = &mut view.pending;
    let count = data.len() / DEPOSIT_REQUEST_SIZE;
    let cur_slot = slot.state().slot;

    for i in 0..count {
        let d: &[u8; DEPOSIT_REQUEST_SIZE] =
            data[i * DEPOSIT_REQUEST_SIZE..(i + 1) * DEPOSIT_REQUEST_SIZE].try_into().unwrap();
        let pubkey = *DepositRequestView::pubkey(d);
        let credentials = Withdrawals(*DepositRequestView::withdrawal_credentials(d));
        let amount = DepositRequestView::amount(d);
        let signature = *DepositRequestView::signature(d);

        pending.deposits.push(PendingDeposit {
            pubkey,
            withdrawal_credentials: credentials,
            amount,
            signature,
            slot: cur_slot,
        });
    }
}

#[timed]
pub fn process_withdrawal_requests(view: &mut StateWriterView, cfg: &SpecConfig, data: &[u8]) {
    let count = data.len() / WITHDRAWAL_REQUEST_SIZE;
    let current_epoch = view.slot.state().slot / SLOTS_PER_EPOCH;
    for i in 0..count {
        let r: &[u8; WITHDRAWAL_REQUEST_SIZE] = data
            [i * WITHDRAWAL_REQUEST_SIZE..(i + 1) * WITHDRAWAL_REQUEST_SIZE]
            .try_into()
            .unwrap();
        process_withdrawal_request(view, cfg, current_epoch, r);
    }
}

/// One EL withdrawal request: validate source address / credentials /
/// eligibility, then queue either a full exit or a partial (excess) withdrawal.
/// Any failed precondition silently drops the request (spec: no-op).
#[timed]
fn process_withdrawal_request(
    view: &mut StateWriterView,
    cfg: &SpecConfig,
    current_epoch: Epoch,
    r: &[u8; WITHDRAWAL_REQUEST_SIZE],
) {
    let source_address = WithdrawalRequestView::source_address(r);
    let validator_pubkey = WithdrawalRequestView::validator_pubkey(r);
    let amount = WithdrawalRequestView::amount(r);
    let is_full_exit = amount == FULL_EXIT_REQUEST_AMOUNT;

    let ppw_len = view.pending.partial_withdrawals.reader().len();
    if ppw_len >= PENDING_PARTIAL_WITHDRAWALS_LIMIT && !is_full_exit {
        return;
    }

    let vi = match view.validators.find_by_pubkey(validator_pubkey) {
        Some(idx) => idx,
        None => return,
    };

    let creds = *view.validators.credentials(vi as usize);
    if !creds.has_execution_credential() {
        return;
    }
    if creds.execution_address() != source_address {
        return;
    }
    if !is_active(&view.validators.reader(), vi, current_epoch) {
        return;
    }
    if view.validators.exit_epoch(vi as usize) != u64::MAX {
        return;
    }
    let act = view.validators.activation_epoch(vi as usize);
    if current_epoch < act + cfg.shard_committee_period {
        return;
    }

    let pending_balance = get_pending_balance_to_withdraw(&view.pending.reader(), vi);

    if is_full_exit {
        if pending_balance == 0 {
            initiate_validator_exit(cfg, view, vi, current_epoch);
        }
        return;
    }

    let effective_balance = view.validators.effective_balance(vi as usize);
    let balance = view.balances.get(vi as usize);
    let has_sufficient_eff = effective_balance >= MIN_ACTIVATION_BALANCE;
    let has_excess = balance > MIN_ACTIVATION_BALANCE + pending_balance;

    if creds.has_compounding_credential() && has_sufficient_eff && has_excess {
        let to_withdraw = min(balance - MIN_ACTIVATION_BALANCE - pending_balance, amount);
        let exit_queue_epoch =
            compute_exit_epoch_and_update_churn(cfg, &mut view.slot, to_withdraw, current_epoch);
        let withdrawable_epoch = exit_queue_epoch + cfg.min_validator_withdrawability_delay;
        view.pending.partial_withdrawals.push(PendingPartialWithdrawal {
            index: vi as u64,
            amount: to_withdraw,
            withdrawable_epoch,
        });
    }
}

#[timed]
pub fn process_consolidation_requests(view: &mut StateWriterView, cfg: &SpecConfig, data: &[u8]) {
    let count = data.len() / CONSOLIDATION_REQUEST_SIZE;
    let current_epoch = view.slot.state().slot / SLOTS_PER_EPOCH;
    for i in 0..count {
        let r: &[u8; CONSOLIDATION_REQUEST_SIZE] = data
            [i * CONSOLIDATION_REQUEST_SIZE..(i + 1) * CONSOLIDATION_REQUEST_SIZE]
            .try_into()
            .unwrap();
        process_consolidation_request(view, cfg, current_epoch, r);
    }
}

/// One EL consolidation request. A source==target request switches the source
/// validator to compounding credentials; otherwise validate both validators and
/// queue a full consolidation. Failed preconditions drop the request (no-op).
#[timed]
fn process_consolidation_request(
    view: &mut StateWriterView,
    cfg: &SpecConfig,
    current_epoch: Epoch,
    r: &[u8; CONSOLIDATION_REQUEST_SIZE],
) {
    let slot = &mut view.slot;
    let validators = &mut view.validators;
    let balances = &mut view.balances;
    let pending = &mut view.pending;

    let source_address = ConsolidationRequestView::source_address(r);
    let source_pubkey = ConsolidationRequestView::source_pubkey(r);
    let target_pubkey = ConsolidationRequestView::target_pubkey(r);

    if source_pubkey == target_pubkey {
        if let Some(src) = validators.find_by_pubkey(source_pubkey) {
            let creds = *validators.credentials(src as usize);
            if creds.execution_address() == source_address &&
                creds.has_eth1_credential() &&
                is_active(&validators.reader(), src, current_epoch) &&
                validators.exit_epoch(src as usize) == u64::MAX
            {
                switch_to_compounding_validator(validators, balances, pending, src);
            }
        }
        return;
    }

    // Full consolidation.
    let pc_len = pending.consolidations.reader().len();
    if pc_len >= PENDING_CONSOLIDATIONS_LIMIT {
        return;
    }
    let churn_limit = get_consolidation_churn_limit(cfg, slot, current_epoch);
    if churn_limit <= MIN_ACTIVATION_BALANCE {
        return;
    }

    let source_idx = match validators.find_by_pubkey(source_pubkey) {
        Some(idx) => idx,
        None => return,
    };
    let target_idx = match validators.find_by_pubkey(target_pubkey) {
        Some(idx) => idx,
        None => return,
    };

    let source_creds = *validators.credentials(source_idx as usize);
    if !source_creds.has_execution_credential() {
        return;
    }
    if source_creds.execution_address() != source_address {
        return;
    }
    if !validators.credentials(target_idx as usize).has_compounding_credential() {
        return;
    }
    if !is_active(&validators.reader(), source_idx, current_epoch) ||
        !is_active(&validators.reader(), target_idx, current_epoch)
    {
        return;
    }
    if validators.exit_epoch(source_idx as usize) != u64::MAX ||
        validators.exit_epoch(target_idx as usize) != u64::MAX
    {
        return;
    }
    let src_act = validators.activation_epoch(source_idx as usize);
    if current_epoch < src_act + cfg.shard_committee_period {
        return;
    }
    if get_pending_balance_to_withdraw(&pending.reader(), source_idx) > 0 {
        return;
    }

    let src_eff = validators.effective_balance(source_idx as usize);
    let exit_epoch =
        compute_consolidation_epoch_and_update_churn(cfg, slot, src_eff, current_epoch);
    validators.set_exit_epoch(source_idx, exit_epoch);
    validators
        .set_withdrawable_epoch(source_idx, exit_epoch + cfg.min_validator_withdrawability_delay);
    pending.consolidations.push(PendingConsolidation {
        source_index: source_idx as u64,
        target_index: target_idx as u64,
    });
}

/// Pass 1 — push bls_to_execution_change sigs. Signer is the validator's
/// BLS withdrawal key (the `from_bls_pubkey` in the message itself) — not
/// the signing key cached on `ValidatorsState` (`pubkey_decompressed`), so we
/// decompress inline.
///
/// Cred-prefix check (`creds[0] == 0x00 && creds[1..] == hash(from_pk)[1..]`)
/// runs here BEFORE BLS — cheap (one sha256) and avoids burning a
/// multi-pairing on a structurally-doomed block. Skipped when the validator
/// doesn't exist yet. Pass
/// 2's `process_bls_to_execution_changes` re-runs the full cred check
/// against post-deposit / post-prior-change state, so a same-block
/// duplicate still rejects.
#[timed]
pub fn collect_sigs_bls_to_execution_changes(
    imm: &Immutable,
    validators: &ValidatorsView,
    data: &[u8],
    sig_batch: &mut SigBatch,
) -> Result<(), BlsToExecutionChangeError> {
    let domain = bls::compute_domain(
        bls::DOMAIN_BLS_TO_EXECUTION_CHANGE,
        imm.genesis_fork_version,
        &imm.genesis_validators_root,
    );
    let count = data.len() / SIGNED_BLS_CHANGE_SIZE;
    let validator_count = validators.count();
    for i in 0..count {
        let c: &[u8; SIGNED_BLS_CHANGE_SIZE] =
            data[i * SIGNED_BLS_CHANGE_SIZE..(i + 1) * SIGNED_BLS_CHANGE_SIZE].try_into().unwrap();
        let validator_index_u = SignedBlsToExecutionChangeView::validator_index(c);
        let from_bls_pubkey = SignedBlsToExecutionChangeView::from_bls_pubkey(c);
        let to_execution_address = SignedBlsToExecutionChangeView::to_execution_address(c);
        let sig = SignedBlsToExecutionChangeView::signature(c);

        if (validator_index_u as usize) < validator_count {
            validate::validate_bls_to_execution_change(
                validators,
                validator_index_u as u32,
                from_bls_pubkey,
            )?;
        }

        let object_root = ssz_hash::hash_tree_root_bls_change(
            validator_index_u,
            from_bls_pubkey,
            to_execution_address,
        );
        let signing_root = bls::compute_signing_root(&object_root, &domain);
        let Ok(from_pk) = PublicKey::from_bytes(from_bls_pubkey) else {
            return Err(BlsToExecutionChangeError::BadPubkey { from_pubkey: *from_bls_pubkey });
        };
        sig_batch.push_one(&from_pk, sig, signing_root);
    }
    Ok(())
}

/// Pass 2 — validate creds-prefix invariant against current state and
/// rewrite credentials. Same-block duplicate change for the same vi: the
/// first one flips the prefix to 0x01, the second's `validate` call sees
/// the now-non-BLS prefix and rejects → block invalid.
#[timed]
pub fn process_bls_to_execution_changes(
    validators: &mut ValidatorsWriteView,
    data: &[u8],
) -> Result<(), BlsToExecutionChangeError> {
    let count = data.len() / SIGNED_BLS_CHANGE_SIZE;
    for i in 0..count {
        let c: &[u8; SIGNED_BLS_CHANGE_SIZE] =
            data[i * SIGNED_BLS_CHANGE_SIZE..(i + 1) * SIGNED_BLS_CHANGE_SIZE].try_into().unwrap();
        let validator_index = SignedBlsToExecutionChangeView::validator_index(c) as u32;
        let from_bls_pubkey = SignedBlsToExecutionChangeView::from_bls_pubkey(c);
        let to_execution_address = SignedBlsToExecutionChangeView::to_execution_address(c);

        validate::validate_bls_to_execution_change(
            &validators.reader(),
            validator_index,
            from_bls_pubkey,
        )?;
        let creds = Withdrawals::eth1(to_execution_address);
        validators.set_credentials(validator_index, creds);
    }
    Ok(())
}

fn switch_to_compounding_validator(
    validators: &mut ValidatorsWriteView,
    balances: &mut BalancesWriteView,
    pending: &mut PendingWriteView,
    vi: u32,
) {
    let mut bytes = validators.credentials(vi as usize).0;
    bytes[0] = COMPOUNDING_WITHDRAWAL_PREFIX;
    let creds = Withdrawals(bytes);
    validators.set_credentials(vi, creds);

    let balance = balances.get(vi as usize);
    if balance > MIN_ACTIVATION_BALANCE {
        let excess = balance - MIN_ACTIVATION_BALANCE;
        balances.set(vi, MIN_ACTIVATION_BALANCE);
        let pubkey = *validators.pubkey(vi as usize);
        pending.deposits.push(PendingDeposit {
            pubkey,
            withdrawal_credentials: creds,
            amount: excess,
            signature: G2_POINT_AT_INFINITY,
            slot: 0, // GENESIS_SLOT
        });
    }
}
