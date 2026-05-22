use super::*;
use crate::types::{BLSPubkey, box_zeroed};

fn pk(seed: u8) -> BLSPubkey {
    let mut p = [0u8; 48];
    // Spread the seed across the first 8 bytes so two different
    // seeds never accidentally share a u64 prefix.
    for (i, b) in p.iter_mut().take(8).enumerate() {
        *b = seed.wrapping_add(i as u8 * 17);
    }
    p
}

fn wc(first_byte: u8) -> Withdrawals {
    let mut c = [0u8; 32];
    c[0] = first_byte;
    Withdrawals(c)
}

/// N pre-existing validators with `pk(0)..pk(N-1)`.
fn populated_base(n: u32) -> FinalizedValidators {
    let pubkeys: Vec<BLSPubkey> = (0..n).map(|i| pk(i as u8)).collect();
    let credentials = vec![Withdrawals::ZERO; n as usize];
    FinalizedValidators::new(&pubkeys, &credentials)
}

// Group A — find_by_pubkey

#[test]
fn find_by_pubkey_existing_returns_index() {
    let fv = populated_base(2);
    assert_eq!(fv.find_by_pubkey(&pk(1)), Some(1));
}

#[test]
fn find_by_pubkey_missing_returns_none() {
    let fv = FinalizedValidators::new(&[], &[]);
    let state = ValidatorsState::with_empty_delta(&fv);
    assert_eq!(state.find_by_pubkey(&pk(42)), None);
}

#[test]
fn find_by_pubkey_after_many_appends_returns_correct_index() {
    let fv = populated_base(100);
    let state = ValidatorsState::with_empty_delta(&fv);
    for i in 0..100u8 {
        assert_eq!(state.find_by_pubkey(&pk(i)), Some(i as usize));
    }
    assert_eq!(state.find_by_pubkey(&pk(200)), None);
}

#[test]
fn find_by_pubkey_after_populated_base_finds_every_validator() {
    let fv = populated_base(256);
    for i in 0..256u32 {
        assert_eq!(fv.find_by_pubkey(&pk(i as u8)), Some(i as usize));
    }
}

// Group B — overlay semantics

#[test]
fn append_in_delta_visible_via_find() {
    let fv = FinalizedValidators::new(&[], &[]);
    let mut state = ValidatorsState::with_empty_delta(&fv);
    state.append(&pk(9), &Withdrawals::ZERO);

    assert_eq!(state.find_by_pubkey(&pk(9)), Some(0));
    assert_eq!(state.validator_cnt(), 1);
    assert_eq!(state.pubkey(0), &pk(9));
}

#[test]
fn append_in_delta_then_finalize_visible_via_base() {
    let mut fv = FinalizedValidators::new(&[], &[]);

    let mut state = ValidatorsState::with_empty_delta(&fv);
    state.append(&pk(9), &Withdrawals::ZERO);
    // Lookup hits delta path.
    assert_eq!(state.find_by_pubkey(&pk(9)), Some(0));

    // Finalize folds delta into base.
    state.promote_into_base(&mut fv);
    let state_post = ValidatorsState::with_empty_delta(&fv);

    // Same answer, now via the base index.
    assert_eq!(state_post.find_by_pubkey(&pk(9)), Some(0));
    assert_eq!(state_post.validator_cnt(), 1);
    assert_eq!(fv.validator_cnt(), 1);
}

#[test]
fn validator_cnt_includes_delta() {
    let fv = populated_base(3);
    let mut state = ValidatorsState::with_empty_delta(&fv);
    state.append(&pk(50), &Withdrawals::ZERO);
    state.append(&pk(51), &Withdrawals::ZERO);

    assert_eq!(state.validator_cnt(), 5);
}

#[test]
fn pubkey_decompressed_overlay_returns_delta_entry() {
    let fv = FinalizedValidators::new(&[], &[]);
    let mut state = ValidatorsState::with_empty_delta(&fv);
    state.append(&pk(9), &Withdrawals::ZERO);

    // Default PublicKey isn't comparable, but the call should not
    // panic and must address the delta entry (idx 0 >= base_cnt 0).
    let _ = state.pubkey_decompressed(0);
}

#[test]
fn withdrawal_credentials_cred_edit_overrides_base() {
    let fv = FinalizedValidators::new(
        &[pk(0), pk(1)],
        &[Withdrawals::ZERO, Withdrawals([0xAA; 32])],
    );

    let overridden = wc(0xCC);
    let mut state = ValidatorsState::with_empty_delta(&fv);
    state.set_withdrawal_credentials(1, overridden);

    assert_eq!(state.withdrawal_credentials(1), &overridden);
    // Base untouched.
    assert_eq!(fv.withdrawal_credentials(1), &Withdrawals([0xAA; 32]));
}

#[test]
fn withdrawal_credentials_repeated_edits_keep_newest() {
    let fv = populated_base(1);
    let mut state = ValidatorsState::with_empty_delta(&fv);

    let a = wc(0xAA);
    let b = wc(0xBB);
    state.set_withdrawal_credentials(0, a);
    state.set_withdrawal_credentials(0, b);

    assert_eq!(state.withdrawal_credentials(0), &b);
    // Replace-by-index: only one entry per idx.
    assert_eq!(state.delta().credentials_edits.len(), 1);
}

#[test]
fn cred_edit_on_appended_validator_logs_to_cred_edits() {
    let fv = FinalizedValidators::new(&[], &[]);
    let mut state = ValidatorsState::with_empty_delta(&fv);

    let pk0 = pk(7);
    let idx = state.append(&pk0, &Withdrawals::ZERO);
    assert_eq!(idx, 0);

    let new_creds = wc(0x02);
    state.set_withdrawal_credentials(idx as usize, new_creds);

    // Edit goes to cred_edits — the appended entry's at-append
    // credentials are preserved.
    assert_eq!(state.delta().credentials_edits.len(), 1);
    assert_eq!(state.delta().credentials_edits[0], (0, new_creds));
    assert_eq!(state.delta().appended[0].credentials, Withdrawals::ZERO);
    // Reader merges cred_edits over appended → new value wins.
    assert_eq!(state.withdrawal_credentials(0), &new_creds);
}

// Group C — fork divergence

#[test]
fn two_forks_different_appended_return_different_indices() {
    let fv = populated_base(3);

    let mut state_a = ValidatorsState::with_empty_delta(&fv);
    state_a.append(&pk(30), &Withdrawals::ZERO);

    let mut state_b = ValidatorsState::with_empty_delta(&fv);
    state_b.append(&pk(31), &Withdrawals::ZERO);

    assert_eq!(state_a.find_by_pubkey(&pk(30)), Some(3));
    assert_eq!(state_a.find_by_pubkey(&pk(31)), None);
    assert_eq!(state_b.find_by_pubkey(&pk(30)), None);
    assert_eq!(state_b.find_by_pubkey(&pk(31)), Some(3));
}

// Group F — overflow & robustness

#[test]
fn delta_grows_beyond_initial_capacity() {
    let fv = FinalizedValidators::new(&[], &[]);
    let mut state = ValidatorsState::with_empty_delta(&fv);

    for i in 0..128u8 {
        state.append(&pk(i), &Withdrawals::ZERO);
    }

    for i in 0..128u8 {
        assert_eq!(state.find_by_pubkey(&pk(i)), Some(i as usize));
    }
    assert_eq!(state.validator_cnt(), 128);
}

#[test]
fn pubkeys_with_identical_prefix_bytes_stored_separately() {
    // Two pubkeys that share the first 8 bytes must both be resolvable.
    let mut a = [0u8; 48];
    let mut b = [0u8; 48];
    for (i, byte) in a.iter_mut().take(8).enumerate() {
        *byte = i as u8;
    }
    for (i, byte) in b.iter_mut().take(8).enumerate() {
        *byte = i as u8;
    }
    a[40] = 0xAA;
    b[40] = 0xBB;
    assert_ne!(a, b);

    let fv = FinalizedValidators::new(&[a, b], &[Withdrawals::ZERO, Withdrawals::ZERO]);

    assert_eq!(fv.find_by_pubkey(&a), Some(0));
    assert_eq!(fv.find_by_pubkey(&b), Some(1));
}

// Group G — append-via-view contracts

#[test]
fn append_via_view_grows_delta_not_base() {
    let fv = FinalizedValidators::new(&[], &[]);
    let mut state = ValidatorsState::with_empty_delta(&fv);

    state.append(&pk(11), &Withdrawals::ZERO);
    state.append(&pk(12), &Withdrawals::ZERO);

    assert_eq!(fv.validator_cnt(), 0); // base untouched
    assert_eq!(state.delta().base_cnt, 0);
    assert_eq!(state.delta().appended.len(), 2);
    // Absolute indices implicit: base_cnt + position → 0 and 1.
    assert_eq!(state.find_by_pubkey(&pk(11)), Some(0));
    assert_eq!(state.find_by_pubkey(&pk(12)), Some(1));
}

// Group D — hash invariance under rebase

#[test]
fn hash_validators_invariant_under_rebase() {
    use crate::{
        ssz_hash::{compute_zero_hashes, hash_validators},
        types::EpochData,
    };

    let zh = compute_zero_hashes();

    let eth1_creds = wc(0x01);
    let init_pubkeys: Vec<BLSPubkey> = (0..8u32).map(|i| pk(i as u8)).collect();
    let init_creds = vec![eth1_creds; 8];
    let mut fv = FinalizedValidators::new(&init_pubkeys, &init_creds);
    let mut epoch: Box<EpochData> = box_zeroed();
    for i in 0..8u32 {
        epoch.val_effective_balance[i as usize] = (i as u64 + 1) * 1_000_000_000;
        epoch.val_activation_epoch[i as usize] = 1;
        epoch.val_exit_epoch[i as usize] = u64::MAX;
    }

    epoch.val_effective_balance[8] = 32_000_000_000;
    epoch.val_activation_epoch[8] = 1;
    epoch.val_exit_epoch[8] = u64::MAX;

    let new_creds = wc(0x02);

    // Hash with delta in play, then rebase.
    let mut state = ValidatorsState::with_empty_delta(&fv);
    state.append(&pk(100), &wc(0x02));
    state.set_withdrawal_credentials(3, new_creds);
    let root_pre = hash_validators(&state, &epoch, &zh);

    // Rebase: fold delta into base.
    state.promote_into_base(&mut fv);
    let state_post = ValidatorsState::with_empty_delta(&fv);
    let root_post = hash_validators(&state_post, &epoch, &zh);

    assert_eq!(root_pre, root_post, "hash_validators must be invariant under rebase");
}

#[test]
fn owned_registry_chains_through_append() {
    let fv = FinalizedValidators::new(&[], &[]);
    let mut state = ValidatorsState::with_empty_delta(&fv);
    let pk0 = pk(7);

    assert_eq!(state.validator_cnt(), 0);
    state.append(&pk0, &Withdrawals::ZERO);

    assert_eq!(state.validator_cnt(), 1);
    assert_eq!(state.find_by_pubkey(&pk0), Some(0));
    // Mutation landed in the delta, not the base.
    assert_eq!(fv.validator_cnt(), 0);
    assert_eq!(state.delta().appended.len(), 1);
}

#[test]
fn finalize_into_base_promotes_appended_and_cred_edits() {
    let mut fv = FinalizedValidators::new(
        &[pk(0), pk(1)],
        &[Withdrawals::ZERO, Withdrawals([0xAA; 32])],
    );

    let new_creds = wc(0xBB);
    let mut state = ValidatorsState::with_empty_delta(&fv);
    state.append(&pk(50), &wc(0xCC));
    state.set_withdrawal_credentials(1, new_creds);

    state.promote_into_base(&mut fv);

    assert_eq!(fv.validator_cnt(), 3);
    assert_eq!(fv.pubkey(2), &pk(50));
    assert_eq!(fv.withdrawal_credentials(2).prefix(), 0xCC);
    assert_eq!(fv.withdrawal_credentials(1), &new_creds);
    assert_eq!(fv.find_by_pubkey(&pk(50)), Some(2));
}

/// `prune_to_base` drains promoted-prefix entries, rolls `base_cnt`
/// forward to match the advanced base, and drops redundant cred_edits
/// whose target now lives in base with a matching value. This is the
/// mid-finalize state: a sibling fork promoted into base, leaving this
/// fork's delta anchored at the pre-finalize count.
#[test]
fn prune_to_base_drains_stale_prefix_and_redundant_cred_edits() {
    let mut base = populated_base(100);

    let diff = wc(0xCC);
    let mut state = ValidatorsState::with_empty_delta(&base);
    state.append(&pk(200), &Withdrawals::ZERO);
    state.append(&pk(201), &Withdrawals::ZERO);
    // Redundant: idx 50, value matches base.
    state.set_withdrawal_credentials(50, Withdrawals::ZERO);
    // Kept: idx 60, value differs from base.
    state.set_withdrawal_credentials(60, diff);
    // Kept: idx 101 lives in `appended` and ends up >= new_base_cnt
    // after sibling promotion, so it can't be redundant.
    state.set_withdrawal_credentials(101, diff);

    // Sibling fork finalized: base grows by one (which absorbs this
    // fork's first appended entry at abs idx 100).
    base.append(&pk(100), &Withdrawals::ZERO);

    state.prune_to_base(&base);

    assert_eq!(state.delta().base_cnt, 101, "anchor rolls forward to new base count");
    assert_eq!(state.delta().appended.len(), 1, "one promoted entry was drained");
    assert_eq!(state.delta().credentials_edits.len(), 2);
    assert!(state.delta().credentials_edits.iter().any(|(i, _)| *i == 60));
    assert!(state.delta().credentials_edits.iter().any(|(i, _)| *i == 101));
}
