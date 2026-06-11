use super::{Eth1Group, Eth1Votes};
use crate::types::{Eth1Data, MAX_ETH1_VOTES};

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
