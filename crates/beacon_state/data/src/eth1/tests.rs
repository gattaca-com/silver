use super::{Eth1Group, Eth1View, Eth1Votes};
use crate::{
    merkle::{MerkleStack, hash_list},
    types::{B256, Eth1Data, MAX_ETH1_VOTES},
};

fn vote(i: u8) -> Eth1Data {
    Eth1Data { deposit_root: [i; 32], deposit_count: i as u64, block_hash: [i; 32] }
}

fn base(votes: &[Eth1Data]) -> Eth1Votes {
    let mut b = Eth1Votes::default();
    for v in votes {
        b.push(*v);
    }
    b
}

#[test]
fn reads_chain_base_then_appended() {
    let mut g = Eth1Group::new(base(&[vote(1), vote(2)]));
    let mut wv = g.roll_fresh();
    wv.push(vote(3));

    assert_eq!(wv.len(), 3);
    let got: Vec<u64> = wv.iter().map(|v| v.deposit_count).collect();
    assert_eq!(got, vec![1, 2, 3]);
}

#[test]
fn clear_drops_base_and_appended() {
    let mut g = Eth1Group::new(base(&[vote(1)]));
    let mut wv = g.roll_fresh();
    wv.push(vote(2));
    wv.clear();
    assert_eq!(wv.len(), 0);

    wv.push(vote(3));
    let got: Vec<u64> = wv.iter().map(|v| v.deposit_count).collect();
    assert_eq!(got, vec![3]);
}

/// Finalize folds the winner's votes into the base and the rebased survivor
/// keeps only its own appends on top.
#[test]
fn finalize_promotes_and_rebases_survivor() {
    let mut g = Eth1Group::new(base(&[vote(1)]));
    let winner = {
        let mut wv = g.roll_fresh();
        wv.push(vote(2));
        wv.commit()
    };
    let survivor = {
        let mut wv = g.roll_from(winner);
        wv.push(vote(3));
        wv.commit()
    };

    let fresh = g.finalize(winner, &[winner, survivor]);

    assert_eq!(g.finalized().len(), 2);
    let got: Vec<u64> = g.view(fresh[1]).iter().map(|v| v.deposit_count).collect();
    assert_eq!(got, vec![1, 2, 3]);
}

/// A survivor that crossed a voting-period boundary after the winner ignores
/// the promoted base entirely.
#[test]
fn finalize_keeps_survivor_clear_standing() {
    let mut g = Eth1Group::new(base(&[vote(1)]));
    let winner = {
        let mut wv = g.roll_fresh();
        wv.push(vote(2));
        wv.commit()
    };
    let survivor = {
        let mut wv = g.roll_from(winner);
        wv.clear();
        wv.push(vote(3));
        wv.commit()
    };

    let fresh = g.finalize(winner, &[winner, survivor]);

    assert_eq!(g.finalized().len(), 2); // base: [1, 2]
    let got: Vec<u64> = g.view(fresh[1]).iter().map(|v| v.deposit_count).collect();
    assert_eq!(got, vec![3]);
}

/// A winner that cleared replaces the base; a survivor sharing the clear
/// drops the inherited prefix.
#[test]
fn finalize_with_winner_clear_replaces_base() {
    let mut g = Eth1Group::new(base(&[vote(1)]));
    let winner = {
        let mut wv = g.roll_fresh();
        wv.clear();
        wv.push(vote(2));
        wv.commit()
    };
    let survivor = {
        let mut wv = g.roll_from(winner);
        wv.push(vote(3));
        wv.commit()
    };

    let fresh = g.finalize(winner, &[winner, survivor]);

    let promoted: Vec<u64> = g.finalized().as_slice().iter().map(|v| v.deposit_count).collect();
    assert_eq!(promoted, vec![2]);
    let got: Vec<u64> = g.view(fresh[1]).iter().map(|v| v.deposit_count).collect();
    assert_eq!(got, vec![2, 3]);
}

/// The spec cap holds in release: the push that would overflow panics
/// instead of growing the finalized list past its structural bound later.
#[test]
#[should_panic(expected = "eth1_votes exceeded MAX_ETH1_VOTES")]
fn push_past_cap_panics() {
    let mut g = Eth1Group::new(Eth1Votes::default());
    let mut wv = g.roll_fresh();
    for i in 0..=MAX_ETH1_VOTES {
        wv.push(vote((i % 251) as u8));
    }
}

/// Re-merkleize the effective votes from scratch — what `hash_root` replaces.
fn oracle_root(v: Eth1View) -> B256 {
    hash_list(MerkleStack::new(MAX_ETH1_VOTES), v.iter().map(Eth1Data::leaf))
}

/// The incremental hasher tracks appends, a voting-period clear, and appends
/// after the clear.
#[test]
fn hash_root_matches_oracle_through_push_and_clear() {
    let mut g = Eth1Group::new(base(&[vote(1), vote(2)]));
    let mut wv = g.roll_fresh();
    assert_eq!(wv.reader().hash_root(), oracle_root(wv.reader()));

    for i in 3..40 {
        wv.push(vote(i));
        assert_eq!(wv.reader().hash_root(), oracle_root(wv.reader()));
    }

    wv.clear();
    assert_eq!(wv.reader().hash_root(), oracle_root(wv.reader()));

    for i in 40..50 {
        wv.push(vote(i));
        assert_eq!(wv.reader().hash_root(), oracle_root(wv.reader()));
    }
}

/// A fork derived from a parent inherits its hasher, and both keep hashing
/// their own effective sequences.
#[test]
fn hash_root_matches_oracle_across_roll_from() {
    let mut g = Eth1Group::new(base(&[vote(1)]));
    let parent = {
        let mut wv = g.roll_fresh();
        wv.push(vote(2));
        wv.push(vote(3));
        wv.commit()
    };
    let child = {
        let mut wv = g.roll_from(parent);
        wv.push(vote(4));
        wv.commit()
    };

    assert_eq!(g.view(parent).hash_root(), oracle_root(g.view(parent)));
    assert_eq!(g.view(child).hash_root(), oracle_root(g.view(child)));
}

/// Finalization swaps the base under every fork: the winner's promoted list
/// and each re-anchored survivor still hash their unchanged effective votes.
#[test]
fn hash_root_survives_finalize() {
    for survivor_clears in [false, true] {
        let mut g = Eth1Group::new(base(&[vote(1)]));
        let winner = {
            let mut wv = g.roll_fresh();
            wv.push(vote(2));
            wv.push(vote(3));
            wv.commit()
        };
        let survivor = {
            let mut wv = g.roll_from(winner);
            if survivor_clears {
                wv.clear();
            }
            wv.push(vote(4));
            wv.commit()
        };
        let before: Vec<_> = [winner, survivor].iter().map(|&id| g.view(id).hash_root()).collect();

        let fresh = g.finalize(winner, &[winner, survivor]);

        for (id, was) in fresh.iter().zip(before) {
            assert_eq!(g.view(*id).hash_root(), oracle_root(g.view(*id)));
            assert_eq!(g.view(*id).hash_root(), was);
        }
        // A fresh fork on the promoted base hashes it without re-folding.
        let after = g.roll_fresh();
        assert_eq!(after.reader().hash_root(), oracle_root(after.reader()));
    }
}

/// A winner that cleared replaces the base, hasher included.
#[test]
fn hash_root_after_winner_clear() {
    let mut g = Eth1Group::new(base(&[vote(1), vote(2)]));
    let winner = {
        let mut wv = g.roll_fresh();
        wv.clear();
        wv.push(vote(3));
        wv.commit()
    };
    let survivor = {
        let mut wv = g.roll_from(winner);
        wv.push(vote(4));
        wv.commit()
    };

    let fresh = g.finalize(winner, &[winner, survivor]);

    for id in fresh {
        assert_eq!(g.view(id).hash_root(), oracle_root(g.view(id)));
    }
}
