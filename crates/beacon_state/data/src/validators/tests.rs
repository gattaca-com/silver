use blst::min_pk::PublicKey;

use super::{FinalizedValidators, ValSeed, ValidatorsGroup, validator_hash};
use crate::{
    B256, Withdrawals,
    merkle::{MerkleStack, hash_concat, hash_fixed_bytes, hash_list, merkleize, uint64_chunk},
    progressive::ProgressiveHasher,
    types::{BLSPubkey, FAR_FUTURE_EPOCH, HashFormat, VALIDATOR_REGISTRY_LIMIT},
};

fn pk(b: u8) -> BLSPubkey {
    [b; 48]
}

fn creds(b: u8) -> Withdrawals {
    Withdrawals([b; 32])
}

fn empty_validators() -> FinalizedValidators {
    FinalizedValidators::try_new(&[], None).unwrap()
}

/// A registry group over an empty base — the entry point for all delta tests,
/// which drive through [`ValidatorsWriteView`] / [`ValidatorsView`] only.
fn group() -> ValidatorsGroup {
    ValidatorsGroup::new(empty_validators(), HashFormat::Fulu)
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
fn empty_validators_is_empty_and_well_formed() {
    let f = empty_validators();
    assert_eq!(f.validator_count(), 0);
    assert!(f.find_by_pubkey(&pk(7)).is_none());
    // Default-init: slashed bitset is all zeros, epochs are FAR_FUTURE.
    assert!(!f.is_slashed(0));
    assert_eq!(f.activation_epoch[0], FAR_FUTURE_EPOCH);
}

#[test]
fn append_then_read_returns_baked_defaults() {
    let mut g = group();
    let mut wv = g.roll_fresh();
    let pk = pk(7);
    let creds = creds(0x42);
    let idx = wv.append(pk, PublicKey::default(), creds);
    assert_eq!(idx, 0);

    // Identity from the appended record.
    assert_eq!(wv.pubkey(0), &pk);
    assert_eq!(wv.credentials(0), &creds);

    // Baked-in spec defaults.
    assert_eq!(wv.effective_balance(0), 0);
    assert!(!wv.is_slashed(0));
    assert_eq!(wv.activation_eligibility_epoch(0), FAR_FUTURE_EPOCH);
    assert_eq!(wv.activation_epoch(0), FAR_FUTURE_EPOCH);
    assert_eq!(wv.exit_epoch(0), FAR_FUTURE_EPOCH);
    assert_eq!(wv.withdrawable_epoch(0), FAR_FUTURE_EPOCH);
}

#[test]
fn set_credentials_inserts_then_updates_in_place() {
    let mut g = group();
    let mut wv = g.roll_fresh();
    wv.append(pk(0), PublicKey::default(), creds(1));
    wv.append(pk(1), PublicKey::default(), creds(2));

    let new_cr = creds(0xFF);
    wv.set_credentials(0, new_cr);
    assert_eq!(wv.credentials(0), &new_cr);

    // Update in place.
    let newer = creds(0x55);
    wv.set_credentials(0, newer);
    assert_eq!(wv.credentials(0), &newer);

    // Setting back to the appended record's value still reads back correctly.
    wv.set_credentials(0, creds(1));
    assert_eq!(wv.credentials(0), &creds(1));
}

#[test]
fn set_slashed_round_trips() {
    let mut g = group();
    let mut wv = g.roll_fresh();
    wv.append(pk(0), PublicKey::default(), creds(0));

    assert!(!wv.is_slashed(0));
    wv.set_slashed(0, true);
    assert!(wv.is_slashed(0));
    wv.set_slashed(0, false);
    assert!(!wv.is_slashed(0));
}

#[test]
fn set_effective_balance_reproduces_independent_root() {
    // A `set_*` must refresh the hash overlay to the SSZ-correct leaf. Verify it
    // both changes the registry root and reproduces the root of the same
    // validator built straight into a finalized base (independent of the overlay
    // path) — the cross-check `column/tests.rs` makes for single columns.
    let mut g = group();
    let mut wv = g.roll_fresh();
    wv.append(pk(0), PublicKey::default(), creds(0));
    let before = wv.hash_root();
    wv.set_effective_balance(0, 32_000_000_000);
    assert_ne!(before, wv.hash_root(), "writing effective_balance changes the registry root");

    // Same validator decoded straight into a base; a fresh fork over it reads the
    // base's registry root with no edits.
    let base = FinalizedValidators::with_validators(&[ValSeed {
        pubkey: pk(0),
        effective_balance: 32_000_000_000,
        ..ValSeed::default()
    }]);
    let mut g2 = ValidatorsGroup::new(base, HashFormat::Fulu);
    assert_eq!(wv.hash_root(), g2.roll_fresh().hash_root());
}

#[test]
fn finalize_promotes_and_reanchors_winner() {
    // Finalizing the sole fork promotes its appended validator + edits into the
    // base and re-anchors it; a fresh fork over the result reads the promoted
    // values and reproduces the pre-finalize root.
    let mut g = group();
    let winner = {
        let mut w = g.roll_fresh();
        w.append(pk(0xAA), PublicKey::default(), creds(0xA1));
        w.set_effective_balance(0, 100_000_000);
        w.set_activation_epoch(0, 7);
        w.commit()
    };
    let before = g.view(winner).hash_root();

    let live = g.finalize(winner, &[winner]);
    assert_eq!(g.finalized().validator_count(), 1);

    let mut wv = g.roll_from(live[0]);
    assert_eq!(wv.pubkey(0), &pk(0xAA));
    assert_eq!(wv.effective_balance(0), 100_000_000);
    assert_eq!(wv.activation_epoch(0), 7);
    assert_eq!(wv.hash_root(), before);
}

#[test]
fn descendant_view_survives_finalize() {
    // Fork-tree: parent → child. Finalizing the parent (winner) promotes it and
    // re-anchors the child; the child keeps its own divergence and root.
    let mut g = group();
    let parent = {
        let mut w = g.roll_fresh();
        w.append(pk(1), PublicKey::default(), creds(1));
        w.set_effective_balance(0, 1_000);
        w.commit()
    };
    let child = {
        let mut w = g.roll_from(parent);
        w.set_activation_epoch(0, 42);
        w.commit()
    };
    let child_before = g.view(child).hash_root();

    let live = g.finalize(parent, &[parent, child]); // [reanchored parent, child]
    assert_eq!(g.finalized().validator_count(), 1);

    let mut wv = g.roll_from(live[1]);
    // Child still sees activation_epoch = 42 (its divergence) and the balance
    // from the promoted base.
    assert_eq!(wv.activation_epoch(0), 42);
    assert_eq!(wv.effective_balance(0), 1_000);
    assert_eq!(wv.hash_root(), child_before);
}

/// Spec-default leaf of an appended-then-maybe-edited validator.
fn default_leaf(pk_byte: u8, effective_balance: u64) -> B256 {
    validator_hash(
        &pk(pk_byte),
        &creds(pk_byte),
        effective_balance,
        false,
        FAR_FUTURE_EPOCH,
        FAR_FUTURE_EPOCH,
        FAR_FUTURE_EPOCH,
        FAR_FUTURE_EPOCH,
    )
}

fn gloas_reference_root(leaves: &[B256]) -> B256 {
    hash_list(ProgressiveHasher::new(), leaves.iter().copied())
}

fn fulu_reference_root(leaves: &[B256]) -> B256 {
    hash_list(MerkleStack::new(VALIDATOR_REGISTRY_LIMIT), leaves.iter().copied())
}

#[test]
fn gloas_construction() {
    let mut g = ValidatorsGroup::new(empty_validators(), HashFormat::Gloas);
    let a = {
        let mut w = g.roll_fresh();
        for i in 0..5u8 {
            w.append(pk(i), PublicKey::default(), creds(i));
        }
        w.commit()
    };
    let leaves: Vec<_> = (0..5u8).map(|i| default_leaf(i, 0)).collect();
    assert_eq!(g.view(a).hash_root(), gloas_reference_root(&leaves));

    let live = g.finalize(a, &[a]);
    assert_eq!(g.view(live[0]).hash_root(), gloas_reference_root(&leaves));
}

#[test]
fn gloas_hash_transition_migrates_and_closes() {
    let mut g = group();
    let a = {
        let mut w = g.roll_fresh();
        for i in 0..5u8 {
            w.append(pk(i), PublicKey::default(), creds(i));
        }
        w.commit()
    };
    let fulu_leaves: Vec<_> = (0..5u8).map(|i| default_leaf(i, 0)).collect();
    assert_eq!(g.view(a).hash_root(), fulu_reference_root(&fulu_leaves));

    // Fork B crosses the fork: its root flips to the gloas shape; the
    // pre-fork sibling A keeps producing the fulu root off its own snapshot.
    let b = {
        let mut w = g.roll_from(a);
        w.adopt_gloas();
        w.set_effective_balance(1, 777);
        w.append(pk(9), PublicKey::default(), creds(9));
        w.commit()
    };
    let mut gloas_leaves = fulu_leaves.clone();
    gloas_leaves[1] = default_leaf(1, 777);
    gloas_leaves.push(default_leaf(9, 0));
    assert_eq!(g.view(b).hash_root(), gloas_reference_root(&gloas_leaves));
    assert_eq!(g.view(a).hash_root(), fulu_reference_root(&fulu_leaves));

    // Finalizing the crossing fork adopts its gloas-format snapshot; the
    // reanchored survivor and every later fork are gloas-shaped.
    let live = g.finalize(b, &[b]);
    assert_eq!(g.view(live[0]).hash_root(), gloas_reference_root(&gloas_leaves));

    let mut w = g.roll_fresh();
    w.set_effective_balance(0, 111);
    gloas_leaves[0] = default_leaf(0, 111);
    assert_eq!(w.hash_root(), gloas_reference_root(&gloas_leaves));
}

#[test]
fn transition_survives_pre_fork_winner_finalization() {
    let mut g = group();
    let a = {
        let mut w = g.roll_fresh();
        for i in 0..4u8 {
            w.append(pk(i), PublicKey::default(), creds(i));
        }
        w.commit()
    };

    let b = {
        let mut w = g.roll_from(a);
        w.adopt_gloas();
        w.set_effective_balance(2, 555);
        w.commit()
    };

    // Winner A never crossed: the finalized snapshot stays fulu-shaped while
    // the crossed survivor B keeps its own gloas-format snapshot.
    let live = g.finalize(a, &[a, b]);
    let fulu_leaves: Vec<_> = (0..4u8).map(|i| default_leaf(i, 0)).collect();
    let mut gloas_leaves = fulu_leaves.clone();
    gloas_leaves[2] = default_leaf(2, 555);
    assert_eq!(g.view(live[0]).hash_root(), fulu_reference_root(&fulu_leaves));
    assert_eq!(g.view(live[1]).hash_root(), gloas_reference_root(&gloas_leaves));

    // A later crossing finalization flips the finalized snapshot to gloas.
    let live = g.finalize(live[1], &[live[1]]);
    assert_eq!(g.view(live[0]).hash_root(), gloas_reference_root(&gloas_leaves));
    let mut w = g.roll_fresh();
    assert_eq!(w.hash_root(), gloas_reference_root(&gloas_leaves));
}
