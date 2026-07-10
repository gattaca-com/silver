use super::InactivityScoresGroup;

fn le_bytes(values: &[u64]) -> Vec<u8> {
    values.iter().flat_map(|v| v.to_le_bytes()).collect()
}

/// The sparse column runs the value machinery over base + delta: set_many /
/// append / finalize round-trip for inactivity scores.
#[test]
fn set_many_append_and_finalize() {
    let mut g = InactivityScoresGroup::new(8, 3, &le_bytes(&[5, 6, 7])).unwrap();

    let mut wv = g.roll_fresh();
    wv.set_many(&[(0, 50), (2, 70)]);
    wv.append(9);
    let winner = wv.commit();

    let survivor = g.roll_from(winner).commit();
    let live = g.finalize(winner, &[winner, survivor]);

    assert_eq!(g.roll_from(live[1]).iter().collect::<Vec<_>>(), vec![50, 6, 70, 9]);
}
