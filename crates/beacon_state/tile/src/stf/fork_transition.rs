use silver_beacon_state_data::{
    Builder, EpochWriteView, ExecutionPayloadBid, FAR_FUTURE_EPOCH, Fork, MIN_SEED_LOOKAHEAD,
    PendingDeposit, SLOTS_PER_EPOCH, StateWriterView,
    gloas::{
        EXECUTION_PAYLOAD_AVAILABILITY_BYTES, PTC_WINDOW_LEN, PtcCommittee, zeroed_ptc_window,
    },
};
use silver_common::ssz_hash_gloas::EMPTY_EXECUTION_REQUESTS_ROOT;

use super::{
    epoch::is_valid_deposit_signature,
    gloas::{PAYLOAD_BUILDER_VERSION, fill_epoch_ptc},
};

/// Initialise the Gloas-only state on a fork view that has just advanced to the
/// first slot of `GLOAS_FORK_EPOCH`.
pub fn upgrade_to_gloas(view: &mut StateWriterView, epoch: &mut EpochWriteView) {
    let current_epoch = view.slot.state().slot / SLOTS_PER_EPOCH;
    let previous_version = epoch.reader().fork().current_version;
    epoch.state_mut().fork = Fork {
        previous_version,
        current_version: view.imm.gloas_fork_version,
        epoch: current_epoch,
    };

    // `latest_block_hash` and the placeholder bid derive from the Fulu
    // execution payload header (kept on the slot tier for Fulu hashing).
    let (block_hash, gas_limit) = {
        let eph = &view.slot.state().latest_execution_payload_header;
        (eph.block_hash, eph.gas_limit)
    };
    {
        let s = view.slot.state_mut();
        s.latest_block_hash = block_hash;
        s.execution_payload_availability = [0xFF; EXECUTION_PAYLOAD_AVAILABILITY_BYTES];
        s.latest_execution_payload_bid = ExecutionPayloadBid {
            block_hash,
            gas_limit,
            execution_requests_root: *EMPTY_EXECUTION_REQUESTS_ROOT,
            ..Default::default()
        };
        // The remaining Gloas slot fields (`next_withdrawal_builder_index`,
        // `builder_pending_payments`, `builder_pending_withdrawals`,
        // `payload_expected_withdrawals`) match the spec's empty/zero init,
        // which is the inherited slot state's default.
    }

    let window = build_ptc_window(view);
    epoch.set_ptc_window(window);

    onboard_builders_from_pending_deposits(view);

    view.adopt_gloas();
}

/// `initialize_ptc_window`: the empty previous epoch followed by the PTCs for
/// the current and lookahead epochs.
fn build_ptc_window(view: &StateWriterView) -> Box<[PtcCommittee; PTC_WINDOW_LEN]> {
    let mut window = zeroed_ptc_window();
    let randao = view.randao_mixes.reader();
    let validators = view.validators.reader();
    let current_epoch = view.slot.state().slot / SLOTS_PER_EPOCH;

    // window[0..SLOTS_PER_EPOCH] is the empty previous epoch (left zero); the
    // current + lookahead epochs follow.
    let mut active = Vec::new();
    for e in 0..=MIN_SEED_LOOKAHEAD {
        let out = SLOTS_PER_EPOCH as usize * (1 + e as usize);
        fill_epoch_ptc(
            &mut window[out..out + SLOTS_PER_EPOCH as usize],
            &validators,
            &randao,
            current_epoch + e,
            &mut active,
        );
    }
    window
}

/// `onboard_builders_from_pending_deposits`: the one-time deposit path that
/// seeds the builder registry at the fork. Rebuilds `pending_deposits`, keeping
/// validator and non-onboarded deposits; the registry starts empty, so every
/// builder is appended this pass (top-ups hit `add_balance`).
fn onboard_builders_from_pending_deposits(view: &mut StateWriterView) {
    let count = view.pending.deposits.reader().len();
    let snapshot: Vec<PendingDeposit> =
        (0..count).map(|i| *view.pending.deposits.reader().get(i)).collect();
    view.pending.deposits.drain(count);

    for d in snapshot {
        // Deposits for existing validators stay in the queue.
        if view.validators.find_by_pubkey(&d.pubkey).is_some() {
            view.pending.deposits.push(d);
            continue;
        }
        // Top up an already-onboarded builder (recomputed each iteration).
        let existing = view.builders.reader().find_by_pubkey(&d.pubkey);
        if let Some(bi) = existing {
            view.builders.add_balance(bi, d.amount);
            continue;
        }
        // New builder candidate: must carry a builder credential, must not be a
        // pending validator, and must have a valid deposit signature.
        if !d.withdrawal_credentials.has_builder_credential() {
            view.pending.deposits.push(d);
            continue;
        }
        if pending_deposit_has_valid_sig(view, &d.pubkey) {
            view.pending.deposits.push(d);
            continue;
        }
        if !is_valid_deposit_signature(&d.pubkey, &d.withdrawal_credentials, d.amount, &d.signature)
        {
            continue;
        }
        view.builders.push(Builder {
            pubkey: d.pubkey,
            version: PAYLOAD_BUILDER_VERSION,
            execution_address: *d.withdrawal_credentials.execution_address(),
            balance: d.amount,
            deposit_epoch: d.slot / SLOTS_PER_EPOCH,
            withdrawable_epoch: FAR_FUTURE_EPOCH,
        });
    }
}

/// `is_pending_validator`: a kept deposit for `pubkey` with a valid signature
/// is already queued.
fn pending_deposit_has_valid_sig(view: &StateWriterView, pubkey: &[u8; 48]) -> bool {
    let q = view.pending.deposits.reader();
    (0..q.len()).any(|i| {
        let pd = q.get(i);
        pd.pubkey == *pubkey &&
            is_valid_deposit_signature(
                &pd.pubkey,
                &pd.withdrawal_credentials,
                pd.amount,
                &pd.signature,
            )
    })
}
