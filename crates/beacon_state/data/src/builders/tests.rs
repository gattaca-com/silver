use silver_ssz::{merkle::hash_list, progressive::ProgressiveHasher};

use super::{BuildersGroup, BuildersView, FinalizedBuilders, builder_hash};
use crate::{B256, gloas::Builder};

fn builder(seed: u8) -> Builder {
    Builder {
        pubkey: [seed; 48],
        version: seed,
        execution_address: [seed; 20],
        balance: seed as u64 * 1_000_000,
        deposit_epoch: seed as u64,
        withdrawable_epoch: u64::MAX,
    }
}

/// Independent full-recompute over the same effective builders — the gloas
/// `ProgressiveList` shape (the registry is gloas-born, never fulu).
fn naive_root(view: &BuildersView) -> B256 {
    hash_list(ProgressiveHasher::new(), view.iter().map(|b| builder_hash(&b)))
}

fn ssz_bytes(builders: &[Builder]) -> Vec<u8> {
    let mut out = Vec::new();
    for b in builders {
        out.extend_from_slice(&b.pubkey);
        out.push(b.version);
        out.extend_from_slice(&b.execution_address);
        out.extend_from_slice(&b.balance.to_le_bytes());
        out.extend_from_slice(&b.deposit_epoch.to_le_bytes());
        out.extend_from_slice(&b.withdrawable_epoch.to_le_bytes());
    }
    out
}

fn base_with(builders: &[Builder]) -> FinalizedBuilders {
    FinalizedBuilders::from_ssz(&ssz_bytes(builders)).unwrap()
}

#[test]
fn empty_registry_root_matches_naive() {
    let mut g = BuildersGroup::new(FinalizedBuilders::default());
    let wv = g.roll_fresh();
    assert_eq!(wv.len(), 0);
    assert_eq!(wv.hash_root(), naive_root(&wv.reader()));
}

#[test]
fn base_root_matches_naive() {
    let base: Vec<_> = (0..10).map(builder).collect();
    let mut g = BuildersGroup::new(base_with(&base));
    let wv = g.roll_fresh();
    assert_eq!(wv.len(), 10);
    assert_eq!(wv.hash_root(), naive_root(&wv.reader()));
}

#[test]
fn mutations_track_naive_recompute() {
    let base: Vec<_> = (0..10).map(builder).collect();
    let mut g = BuildersGroup::new(base_with(&base));
    let mut wv = g.roll_fresh();

    wv.push(builder(100));
    wv.push(builder(101));
    wv.push(builder(102));
    assert_eq!(wv.len(), 13);
    assert_eq!(wv.hash_root(), naive_root(&wv.reader()));

    // Credit a base index and an appended index.
    wv.add_balance(3, 5_000);
    assert_eq!(wv.hash_root(), naive_root(&wv.reader()));
    wv.add_balance(11, 7_000);
    assert_eq!(wv.hash_root(), naive_root(&wv.reader()));

    // Replace (slot reuse) a base index.
    wv.set_builder(2, builder(200));
    assert_eq!(wv.reader().get(2).unwrap().pubkey, [200; 48]);
    assert_eq!(wv.hash_root(), naive_root(&wv.reader()));
}

#[test]
fn finalize_promotes_and_matches_naive() {
    let base: Vec<_> = (0..10).map(builder).collect();
    let mut g = BuildersGroup::new(base_with(&base));

    let winner = {
        let mut wv = g.roll_fresh();
        wv.push(builder(100));
        wv.push(builder(101));
        wv.add_balance(4, 9_000);
        wv.set_builder(1, builder(201));
        wv.commit()
    };
    let before = g.view(winner).hash_root();

    let live = g.finalize(winner, &[winner]);
    assert_eq!(g.finalized().len(), 12);

    let wv = g.roll_from(live[0]);
    assert_eq!(wv.len(), 12);
    assert_eq!(wv.reader().get(1).unwrap().pubkey, [201; 48]);
    assert_eq!(wv.reader().get(4).unwrap().balance, builder(4).balance + 9_000);
    assert_eq!(wv.reader().get(10).unwrap().pubkey, [100; 48]);
    assert_eq!(wv.hash_root(), before);
    assert_eq!(wv.hash_root(), naive_root(&wv.reader()));
}

#[test]
fn growth_past_initial_headroom() {
    // A gloas-fork-born registry starts empty: builder_capacity(0) = 64. Real
    // onboarding can exceed that between two finalizations, and 85+ builders
    // cross the progressive segment-3 boundary (chunk 85) — both must regrow
    // the base and its hash forest instead of panicking.
    let mut g = BuildersGroup::new(FinalizedBuilders::default());

    let winner = {
        let mut wv = g.roll_fresh();
        for i in 0..100u8 {
            wv.push(builder(i));
        }
        assert_eq!(wv.hash_root(), naive_root(&wv.reader()));
        wv.commit()
    };
    let before = g.view(winner).hash_root();

    let live = g.finalize(winner, &[winner]);
    assert_eq!(g.finalized().len(), 100);

    let mut wv = g.roll_from(live[0]);
    assert_eq!(wv.hash_root(), before);

    // Keep growing past the regrown capacity in the next window.
    for i in 100..200u8 {
        wv.push(builder(i));
    }
    assert_eq!(wv.len(), 200);
    assert_eq!(wv.hash_root(), naive_root(&wv.reader()));
}

#[test]
fn descendant_survives_finalize() {
    let base: Vec<_> = (0..10).map(builder).collect();
    let mut g = BuildersGroup::new(base_with(&base));

    let parent = {
        let mut wv = g.roll_fresh();
        wv.push(builder(100));
        wv.add_balance(3, 1_000);
        wv.commit()
    };
    let child = {
        let mut wv = g.roll_from(parent);
        wv.set_builder(5, builder(205));
        wv.add_balance(10, 2_000);
        wv.commit()
    };
    let child_before = g.view(child).hash_root();

    let live = g.finalize(parent, &[parent, child]);
    assert_eq!(g.finalized().len(), 11);

    let wv = g.roll_from(live[1]);
    assert_eq!(wv.reader().get(5).unwrap().pubkey, [205; 48]);
    assert_eq!(wv.reader().get(3).unwrap().balance, builder(3).balance + 1_000);
    assert_eq!(wv.reader().get(10).unwrap().balance, builder(100).balance + 2_000);
    assert_eq!(wv.hash_root(), child_before);
    assert_eq!(wv.hash_root(), naive_root(&wv.reader()));
}
