use blst::min_pk::PublicKey;

use super::{FinalizedValidators, ValidatorsDelta, validator_hash};
use crate::{
    Withdrawals,
    beacon_state::types::{BLSPubkey, FAR_FUTURE_EPOCH, MAX_VALIDATORS},
    ssz_hash::{hash_concat, hash_fixed_bytes, merkleize, uint64_chunk},
};

fn pk(b: u8) -> BLSPubkey {
    [b; 48]
}

fn creds(b: u8) -> Withdrawals {
    Withdrawals([b; 32])
}

// ── Base-swap invariance harness ────────────────────────────────────────────
//
// Migration target (design-base-swap-invariant-deltas): a delta `d` that
// descends from a finalized delta `Δ` must read identically against the old
// base `f1` and the new base `f2 = f1 + Δ`, so finalization can swap the base
// under a survivor without re-anchoring it. These tests exercise that property
// directly on `ValidatorsDelta`, ahead of the read path being decoupled from
// `base_count == fin.validator_count()`.

/// Every mutable effective_* field at one index, bundled for f1-vs-f2 compare.
#[derive(PartialEq, Debug)]
struct ValRead {
    pubkey: BLSPubkey,
    credentials: Withdrawals,
    effective_balance: u64,
    slashed: bool,
    activation_eligibility_epoch: u64,
    activation_epoch: u64,
    exit_epoch: u64,
    withdrawable_epoch: u64,
}

fn read_all(d: &ValidatorsDelta, base: &FinalizedValidators, idx: u32) -> ValRead {
    ValRead {
        pubkey: *d.effective_pubkey(base, idx),
        credentials: *d.effective_credentials(base, idx),
        effective_balance: d.effective_balance(base, idx),
        slashed: d.is_slashed(base, idx),
        activation_eligibility_epoch: d.activation_eligibility_epoch(base, idx),
        activation_epoch: d.activation_epoch(base, idx),
        exit_epoch: d.exit_epoch(base, idx),
        withdrawable_epoch: d.withdrawable_epoch(base, idx),
    }
}

/// Append `n` deterministic validators. Same sequence each call, so two
/// independently-built bases are byte-identical.
fn seed_base(base: &mut FinalizedValidators, n: u8) {
    for i in 0..n {
        base.append(
            &pk(i),
            &PublicKey::default(),
            &creds(i),
            32_000_000_000 + i as u64,
            false,
            i as u64,
            i as u64 + 1,
            FAR_FUTURE_EPOCH,
            FAR_FUTURE_EPOCH,
        );
    }
}

/// Assert `read(d, f1, idx) == read(d, f2, idx)` for every logical index.
fn assert_base_swap_invariant(
    d: &ValidatorsDelta,
    f1: &FinalizedValidators,
    f2: &FinalizedValidators,
) {
    let count = d.base_count + d.appended.len();
    for idx in 0..count as u32 {
        assert_eq!(read_all(d, f1, idx), read_all(d, f2, idx), "base-swap mismatch at idx {idx}");
    }
}

#[test]
fn descendant_reads_are_base_swap_invariant_common_case() {
    // f1 and f2 start identical; Δ is promoted into f2.
    let mut f1 = FinalizedValidators::default();
    let mut f2 = FinalizedValidators::default();
    seed_base(&mut f1, 4);
    seed_base(&mut f2, 4);

    // Δ: append a validator, edit it, edit a base validator.
    let mut delta = ValidatorsDelta::new_at(&f1);
    delta.append(&f1, pk(10), PublicKey::default(), creds(10)); // idx 4
    delta.set_effective_balance(&f1, 4, 50_000);
    delta.set_exit_epoch(&f1, 1, 7);

    // D descends from Δ: append more, diverge on its own indices — but never
    // sets a field back to f1's base value (no elision-to-base; see the
    // ignored test for that case).
    let mut d = delta.clone();
    d.append(&f1, pk(11), PublicKey::default(), creds(11)); // idx 5
    d.set_activation_epoch(&f1, 4, 9);
    d.set_effective_balance(&f1, 2, 123);

    delta.promote_into_base(&mut f2);
    assert_eq!(f2.validator_count(), 5);

    assert_base_swap_invariant(&d, &f1, &f2);
}

#[test]
#[ignore = "RED until base-swap migration: write_or_elide elides against the \
            mutable base, so a descendant that sets a field back to f1's value \
            drops the edit and then reads f2's promoted value. Fix: keep \
            base-targeting edits as absolute overrides. See \
            design-base-swap-invariant-deltas."]
fn elision_to_base_value_violates_base_swap_invariance() {
    let mut f1 = FinalizedValidators::default();
    let mut f2 = FinalizedValidators::default();
    seed_base(&mut f1, 4);
    seed_base(&mut f2, 4);
    let f1_eb0 = f1.effective_balance(0); // 32_000_000_000

    // Δ changes base validator 0's effective_balance.
    let mut delta = ValidatorsDelta::new_at(&f1);
    delta.set_effective_balance(&f1, 0, 99);

    // D descends from Δ but, on its own branch, sets idx 0 back to f1's
    // original value. write_or_elide sees v == base_val(f1) and drops the
    // edit, so D now relies on base == f1.
    let mut d = delta.clone();
    d.set_effective_balance(&f1, 0, f1_eb0);
    assert!(d.effective_balance_edits.is_empty(), "edit elided against f1");

    delta.promote_into_base(&mut f2); // f2.effective_balance[0] = 99

    // D's branch value for idx 0 is f1_eb0; the invariant requires the read to
    // be independent of which base we swap in. Today it is NOT: over f2 the
    // elided delta reads 99.
    assert_base_swap_invariant(&d, &f1, &f2);
}

/// Independent reference impl of `validator_hash`: merkleize 8 chunks
/// following SSZ Validator container layout. This duplicates `merkleize`
/// but builds the chunks inline (no shared chunk helpers) so it catches
/// chunk-order or packing bugs.
fn reference_validator_hash(
    pubkey: &BLSPubkey,
    credentials: &Withdrawals,
    effective_balance: u64,
    slashed: bool,
    activation_eligibility_epoch: u64,
    activation_epoch: u64,
    exit_epoch: u64,
    withdrawable_epoch: u64,
) -> [u8; 32] {
    // pubkey: 48 B → 2 32-byte chunks (second chunk zero-padded), merkleized.
    let mut pk_chunks = [[0u8; 32]; 2];
    pk_chunks[0].copy_from_slice(&pubkey[..32]);
    pk_chunks[1][..16].copy_from_slice(&pubkey[32..48]);
    let pk_leaf = hash_concat(&pk_chunks[0], &pk_chunks[1]);

    // basic-type chunks: value left-aligned in low bytes, rest zero.
    let mut eff_balance_chunk = [0u8; 32];
    eff_balance_chunk[..8].copy_from_slice(&effective_balance.to_le_bytes());

    let mut slashed_chunk = [0u8; 32];
    slashed_chunk[0] = u8::from(slashed);

    let mut eligibility_chunk = [0u8; 32];
    eligibility_chunk[..8].copy_from_slice(&activation_eligibility_epoch.to_le_bytes());

    let mut activation_chunk = [0u8; 32];
    activation_chunk[..8].copy_from_slice(&activation_epoch.to_le_bytes());

    let mut exit_chunk = [0u8; 32];
    exit_chunk[..8].copy_from_slice(&exit_epoch.to_le_bytes());

    let mut withdrawable_chunk = [0u8; 32];
    withdrawable_chunk[..8].copy_from_slice(&withdrawable_epoch.to_le_bytes());

    // 8 chunks → 3 levels of pair-hash.
    let lvl1_0 = hash_concat(&pk_leaf, &credentials.0);
    let lvl1_1 = hash_concat(&eff_balance_chunk, &slashed_chunk);
    let lvl1_2 = hash_concat(&eligibility_chunk, &activation_chunk);
    let lvl1_3 = hash_concat(&exit_chunk, &withdrawable_chunk);

    let lvl2_0 = hash_concat(&lvl1_0, &lvl1_1);
    let lvl2_1 = hash_concat(&lvl1_2, &lvl1_3);

    hash_concat(&lvl2_0, &lvl2_1)
}

#[test]
fn validator_hash_matches_reference_impl() {
    // Several field combinations to catch chunk-order or packing bugs.
    let cases: &[(BLSPubkey, Withdrawals, u64, bool, u64, u64, u64, u64)] = &[
        ([0u8; 48], Withdrawals([0u8; 32]), 0, false, 0, 0, 0, 0),
        ([0xAA; 48], Withdrawals([0xBB; 32]), 32_000_000_000, false, 100, 200, u64::MAX, u64::MAX),
        ([1u8; 48], Withdrawals([2u8; 32]), 1, true, 3, 4, 5, 6),
        (
            [0xFF; 48],
            Withdrawals([0xFF; 32]),
            u64::MAX,
            true,
            u64::MAX,
            u64::MAX,
            u64::MAX,
            u64::MAX,
        ),
    ];
    for (i, &(pk, cr, effective_balance, slashed, elig, act, exit, withdr)) in
        cases.iter().enumerate()
    {
        let got = validator_hash(&pk, &cr, effective_balance, slashed, elig, act, exit, withdr);
        let want =
            reference_validator_hash(&pk, &cr, effective_balance, slashed, elig, act, exit, withdr);
        assert_eq!(got, want, "case {i}");
    }
}

#[test]
fn validator_hash_uses_pubkey_two_chunk_layout() {
    // The pubkey field root must merkleize 2 chunks (pubkey[0..32],
    // pubkey[32..48] padded to 32). Catches a "merkleize raw 48 bytes
    // as a single chunk" mistake.
    let pk_all_ff = [0xFF; 48];
    let other = [0u8; 32];

    // Reference: merkleize the SSZ field-encoded pubkey: 2 chunks where
    // chunk1 = [0xFF; 32] and chunk2 = first 16 = 0xFF, last 16 = 0x00.
    let mut chunk2 = [0u8; 32];
    chunk2[..16].copy_from_slice(&[0xFF; 16]);
    let want_pk_field = hash_concat(&[0xFF; 32], &chunk2);

    // Cross-check against the ssz_hash primitive.
    assert_eq!(want_pk_field, hash_fixed_bytes(&pk_all_ff));

    let want_leaf = merkleize(&[
        want_pk_field,
        other, // credentials
        uint64_chunk(0),
        other, // slashed
        uint64_chunk(0),
        uint64_chunk(0),
        uint64_chunk(0),
        uint64_chunk(0),
    ]);
    let got = validator_hash(&pk_all_ff, &Withdrawals(other), 0, false, 0, 0, 0, 0);
    assert_eq!(got, want_leaf);
}

#[test]
fn validator_hash_each_field_distinguishable() {
    // Flipping any single field must produce a different leaf hash.
    let base = validator_hash(&pk(0), &creds(0), 0, false, 0, 0, 0, 0);
    assert_ne!(base, validator_hash(&pk(1), &creds(0), 0, false, 0, 0, 0, 0));
    assert_ne!(base, validator_hash(&pk(0), &creds(1), 0, false, 0, 0, 0, 0));
    assert_ne!(base, validator_hash(&pk(0), &creds(0), 1, false, 0, 0, 0, 0));
    assert_ne!(base, validator_hash(&pk(0), &creds(0), 0, true, 0, 0, 0, 0));
    assert_ne!(base, validator_hash(&pk(0), &creds(0), 0, false, 1, 0, 0, 0));
    assert_ne!(base, validator_hash(&pk(0), &creds(0), 0, false, 0, 1, 0, 0));
    assert_ne!(base, validator_hash(&pk(0), &creds(0), 0, false, 0, 0, 1, 0));
    assert_ne!(base, validator_hash(&pk(0), &creds(0), 0, false, 0, 0, 0, 1));
}

#[test]
fn finalized_default_is_empty_and_well_formed() {
    let f = FinalizedValidators::default();
    assert_eq!(f.validator_count(), 0);
    assert!(f.find_by_pubkey(&pk(7)).is_none());
    assert_eq!(f.hash().max_elements(), MAX_VALIDATORS);
    // Default-init: slashed bitset is all zeros, epochs are FAR_FUTURE.
    assert!(!f.is_slashed(0));
    assert_eq!(f.activation_epoch(0), FAR_FUTURE_EPOCH);
}

#[test]
fn append_then_read_returns_baked_defaults() {
    let f = FinalizedValidators::default();
    let mut d = ValidatorsDelta::new_at(&f);
    let pk = pk(7);
    let creds = creds(0x42);
    let idx = d.append(&f, pk, PublicKey::default(), creds);
    assert_eq!(idx, 0);

    // Identity from appended record.
    assert_eq!(d.effective_pubkey(&f, 0), &pk);
    assert_eq!(d.effective_credentials(&f, 0), &creds);

    // Baked-in spec defaults.
    assert_eq!(d.effective_balance(&f, 0), 0);
    assert!(!d.is_slashed(&f, 0));
    assert_eq!(d.activation_eligibility_epoch(&f, 0), FAR_FUTURE_EPOCH);
    assert_eq!(d.activation_epoch(&f, 0), FAR_FUTURE_EPOCH);
    assert_eq!(d.exit_epoch(&f, 0), FAR_FUTURE_EPOCH);
    assert_eq!(d.withdrawable_epoch(&f, 0), FAR_FUTURE_EPOCH);
}

#[test]
fn set_credentials_inserts_then_updates_then_elides() {
    let f = FinalizedValidators::default();
    let mut d = ValidatorsDelta::new_at(&f);
    d.append(&f, pk(0), PublicKey::default(), creds(1));
    d.append(&f, pk(1), PublicKey::default(), creds(2));

    // Set an edit at idx 0.
    let new_cr = creds(0xFF);
    d.set_credentials(&f, 0, new_cr);
    assert_eq!(d.effective_credentials(&f, 0), &new_cr);
    assert_eq!(d.credentials_edits.len(), 1);

    // Update in place.
    let newer = creds(0x55);
    d.set_credentials(&f, 0, newer);
    assert_eq!(d.effective_credentials(&f, 0), &newer);
    assert_eq!(d.credentials_edits.len(), 1);

    // Setting back to the appended record's value elides the edit.
    d.set_credentials(&f, 0, creds(1));
    assert!(d.credentials_edits.is_empty());
    assert_eq!(d.effective_credentials(&f, 0), &creds(1));
}

#[test]
fn set_slashed_round_trips() {
    let f = FinalizedValidators::default();
    let mut d = ValidatorsDelta::new_at(&f);
    d.append(&f, pk(0), PublicKey::default(), creds(0));

    assert!(!d.is_slashed(&f, 0));
    d.set_slashed(&f, 0, true);
    assert!(d.is_slashed(&f, 0));
    assert_eq!(d.slashed_edits, vec![(0, true)]);

    d.set_slashed(&f, 0, false);
    assert!(!d.is_slashed(&f, 0));
    assert!(d.slashed_edits.is_empty(), "elides back to base default");
}

#[test]
fn set_effective_balance_updates_hash_overlay() {
    // Sanity check: a set_* on a Validator-container field must update
    // both the edit vec AND the hash overlay's leaf for that idx.
    let f = FinalizedValidators::default();
    let mut d = ValidatorsDelta::new_at(&f);
    d.append(&f, pk(0), PublicKey::default(), creds(0));

    let root_before = f.hash().delta_root(&d.hash_overlay);
    d.set_effective_balance(&f, 0, 32_000_000_000);
    let root_after = f.hash().delta_root(&d.hash_overlay);
    assert_ne!(root_before, root_after, "writing effective_balance changes the merged root");

    // Match the value we'd get from recomputing the leaf by hand.
    let want_leaf = validator_hash(
        &pk(0),
        &creds(0),
        32_000_000_000,
        false,
        FAR_FUTURE_EPOCH,
        FAR_FUTURE_EPOCH,
        FAR_FUTURE_EPOCH,
        FAR_FUTURE_EPOCH,
    );
    let recomputed = d.recompute_leaf(&f, 0);
    assert_eq!(recomputed, want_leaf);
}

#[test]
fn promote_then_prune_reanchors_delta() {
    let mut f = FinalizedValidators::default();
    let mut d = ValidatorsDelta::new_at(&f);
    let pk_a = pk(0xAA);
    d.append(&f, pk_a, PublicKey::default(), creds(0xA1));
    d.set_effective_balance(&f, 0, 100_000_000);
    d.set_activation_epoch(&f, 0, 7);

    let root_pre = f.hash().delta_root(&d.hash_overlay);

    d.promote_into_base(&mut f);
    assert_eq!(f.validator_count(), 1);
    assert_eq!(*f.pubkey(0), pk_a);
    assert_eq!(f.effective_balance(0), 100_000_000);
    assert_eq!(f.activation_epoch(0), 7);

    // The promoted base's root equals the pre-promote merged root.
    assert_eq!(f.hash().root_hash(), &root_pre);

    d.prune_to_base(&f);
    assert_eq!(d.base_count, 1);
    assert!(d.appended.is_empty());
    assert!(d.effective_balance_edits.is_empty(), "edit matches base after promote");
    assert!(d.activation_epoch_edits.is_empty(), "edit matches base after promote");
    // After prune, the overlay should be Base(root) — empty.
    assert_eq!(f.hash().delta_root(&d.hash_overlay), root_pre);
}

#[test]
fn descendant_view_survives_promote_via_prune() {
    // Standard fork-tree topology: parent → child. Promote parent's delta
    // into base; child re-anchors via prune and its merged view stays
    // identical to its pre-promote root.
    let mut f = FinalizedValidators::default();
    let mut parent = ValidatorsDelta::new_at(&f);
    parent.append(&f, pk(1), PublicKey::default(), creds(1));
    parent.set_effective_balance(&f, 0, 1_000);

    let mut child = parent.clone();
    child.set_activation_epoch(&f, 0, 42);

    let child_root_pre = f.hash().delta_root(&child.hash_overlay);

    parent.promote_into_base(&mut f);
    parent.prune_to_base(&f);
    child.prune_to_base(&f);

    assert_eq!(child.base_count, 1);
    // Child should still see activation_epoch = 42 (its own divergence
    // from parent's promoted state).
    assert_eq!(child.activation_epoch(&f, 0), 42);
    assert_eq!(f.hash().delta_root(&child.hash_overlay), child_root_pre);
}
