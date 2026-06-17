use std::io::{self, Write};

use super::{PendingGroup, QueueItem, delta::QueueView, group::QueueGroup};
use crate::{
    buffer::Id,
    ssz_hash::uint64_chunk,
    types::{B256, PendingConsolidation},
};

/// A lightweight `QueueItem` for the drain/rebase arithmetic tests — a 4-byte
/// LE element with a shallow list limit, so the tests assert on queue contents
/// (and frontier-root consistency) without a real 192-byte container.
impl QueueItem for u32 {
    const SSZ_LIMIT: usize = 1 << 10;
    const SSZ_SIZE: usize = 4;

    fn leaf(&self) -> B256 {
        uint64_chunk(*self as u64)
    }

    fn read_ssz(s: &[u8]) -> Self {
        u32::from_le_bytes(s[..4].try_into().unwrap())
    }

    fn write_ssz<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(&self.to_le_bytes())
    }
}

fn pc(i: u64) -> PendingConsolidation {
    PendingConsolidation { source_index: i, target_index: i }
}

/// End-to-end through the holder: a survivor that drained into the winner's
/// appended entries keeps its own appends across finalization (regression:
/// they were dropped and the drained entry resurrected).
#[test]
fn finalize_preserves_survivor_queue_after_inherited_drain() {
    let mut g = PendingGroup::from_ssz(&[], &[], &[]);

    let winner = {
        let mut wv = g.roll_fresh();
        wv.consolidations.push(pc(1));
        wv.consolidations.push(pc(2));
        wv.commit()
    };
    let survivor = {
        let mut wv = g.roll_from(winner);
        wv.consolidations.drain(1); // consumes inherited `1`
        wv.consolidations.push(pc(3));
        wv.commit()
    };

    let fresh = g.finalize(winner, &[winner, survivor]);

    let v = g.view(fresh[1]);
    assert_eq!(v.consolidations.len(), 2);
    assert_eq!(v.consolidations.get(0).source_index, 2);
    assert_eq!(v.consolidations.get(1).source_index, 3);
}

// ---- QueueGroup drain/rebase arithmetic, on a `u32` queue ----

type U32Group = QueueGroup<u32>;
type U32Id = Id<U32Group>;

/// A `u32` queue group whose finalized base is `base`, seeded via the SSZ
/// codec (4 LE bytes per element).
fn group_from(base: &[u32]) -> U32Group {
    let bytes: Vec<u8> = base.iter().flat_map(|v| v.to_le_bytes()).collect();
    QueueGroup::from_ssz(&bytes)
}

fn effective(v: &QueueView<'_, u32>) -> Vec<u32> {
    (0..v.len()).map(|i| *v.get(i)).collect()
}

/// The reanchored fork's effective queue equals an independent group seeded
/// with those same elements — i.e. the cached frontier root stays honest
/// across rebase + promote.
fn assert_consistent(g: &U32Group, id: U32Id) {
    let got = effective(&g.view(id));
    let mut fresh = group_from(&got);
    assert_eq!(g.view(id).hash_root(), fresh.roll_fresh().reader().hash_root());
}

#[test]
fn drain_accumulates_past_base() {
    let mut g = group_from(&[10, 11]);
    let mut wv = g.roll_fresh();
    wv.push(20);
    wv.push(21);
    wv.drain(3); // both base entries + appended[0]
    assert_eq!(effective(&wv.reader()), vec![21]);
    wv.drain(1);
    assert_eq!(effective(&wv.reader()), Vec::<u32>::new());
}

/// Regression: a survivor that drained into the winner's appended entries
/// lost its own appends at rebase (and resurrected the drained entry).
#[test]
fn rebase_keeps_own_appends_after_draining_inherited() {
    let mut g = group_from(&[]); // e.g. an empty consolidations queue
    let winner = {
        let mut wv = g.roll_fresh();
        wv.push(1);
        wv.push(2);
        wv.commit()
    };
    let survivor = {
        let mut wv = g.roll_from(winner);
        wv.drain(1); // consumes inherited `1`
        wv.push(3);
        wv.commit()
    };

    let fresh = g.finalize(winner, &[winner, survivor]);
    assert_eq!(effective(&g.view(fresh[0])), vec![1, 2]); // promoted base
    assert_eq!(effective(&g.view(fresh[1])), vec![2, 3]);
    assert_consistent(&g, fresh[1]);
}

/// Regression: the winner's own past-base drain (it ate into its own
/// appends) must not count against the survivor's inherited prefix.
#[test]
fn rebase_subtracts_winner_overshoot() {
    let mut g = group_from(&[10]);
    let winner = {
        let mut wv = g.roll_fresh();
        wv.push(1);
        wv.push(2);
        wv.drain(2); // base entry + own `1`
        assert_eq!(effective(&wv.reader()), vec![2]);
        wv.commit()
    };
    let survivor = {
        let mut wv = g.roll_from(winner);
        wv.drain(1); // consumes inherited `2`
        wv.push(3);
        wv.commit()
    };

    let fresh = g.finalize(winner, &[winner, survivor]);
    assert_eq!(effective(&g.view(fresh[0])), vec![2]); // promoted base
    assert_eq!(effective(&g.view(fresh[1])), vec![3]);
    assert_consistent(&g, fresh[1]);
}

/// A survivor that drained past the whole inherited prefix into its own
/// appends has nothing left to drop at rebase.
#[test]
fn rebase_when_survivor_drained_past_inherited() {
    let mut g = group_from(&[]);
    let winner = {
        let mut wv = g.roll_fresh();
        wv.push(1);
        wv.commit()
    };
    let survivor = {
        let mut wv = g.roll_from(winner);
        wv.push(2);
        wv.drain(2); // inherited `1` + own `2`
        wv.push(3);
        wv.commit()
    };

    let fresh = g.finalize(winner, &[winner, survivor]);
    assert_eq!(effective(&g.view(fresh[0])), vec![1]); // promoted base
    assert_eq!(effective(&g.view(fresh[1])), vec![3]);
    assert_consistent(&g, fresh[1]);
}

/// The common shape: drains stay within the base; the survivor drops the
/// full inherited prefix and keeps a relative drain.
#[test]
fn rebase_plain_base_drains() {
    let mut g = group_from(&[10, 11, 12]);
    let winner = {
        let mut wv = g.roll_fresh();
        wv.push(1);
        wv.drain(1);
        wv.commit()
    };
    let survivor = {
        let mut wv = g.roll_from(winner);
        wv.drain(1);
        wv.push(2);
        assert_eq!(effective(&wv.reader()), vec![12, 1, 2]);
        wv.commit()
    };

    let fresh = g.finalize(winner, &[winner, survivor]);
    assert_eq!(effective(&g.view(fresh[0])), vec![11, 12, 1]); // promoted base
    assert_eq!(effective(&g.view(fresh[1])), vec![12, 1, 2]);
    assert_consistent(&g, fresh[1]);
}

/// Drain the whole base (and into appended): reads fall through to `appended`,
/// the frontier rebuild sees an empty base slice, and the root stays correct.
#[test]
fn drain_entire_base_then_appended() {
    let mut g = group_from(&[10, 11, 12]);
    let mut wv = g.roll_fresh();
    wv.push(1);
    wv.push(2); // effective: [10, 11, 12, 1, 2]

    wv.drain(3); // drop the whole base
    assert_eq!(effective(&wv.reader()), vec![1, 2]);
    wv.drain(1); // eat into appended, past the base
    assert_eq!(effective(&wv.reader()), vec![2]);
    wv.drain(1); // drain everything → empty list
    assert_eq!(effective(&wv.reader()), Vec::<u32>::new());
}
