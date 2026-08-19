use super::{
    vote::{Vote, branch_voted_for},
    *,
};

/// Opaque per-tier bundle for topology/weight tests that never resolve
/// state. Built field-by-field — `StateId` deliberately has no `Default`.
fn test_state_id() -> StateId {
    StateId {
        epoch_idx: None,
        longtail_idx: None,
        balances_idx: Default::default(),
        eth1_idx: Default::default(),
        validators_idx: Default::default(),
        pending_idx: Default::default(),
        previous_participation_idx: Default::default(),
        current_participation_idx: Default::default(),
        inactivity_idx: Default::default(),
        slashings_idx: Default::default(),
        slot_idx: Default::default(),
        builders_idx: Default::default(),
    }
}

fn root(b: u8) -> B256 {
    let mut r = [0u8; 32];
    r[0] = b;
    r
}

fn cp(epoch: Epoch, b: u8) -> Checkpoint {
    Checkpoint { epoch, root: root(b) }
}

// Fork choice nodes carry their post-state index bundle; the topology /
// weight tests don't read state, so a constant seq is fine.
fn block(
    slot: Slot,
    block_root: B256,
    parent_root: B256,
    jus: Checkpoint,
    fin: Checkpoint,
) -> BlockImport {
    BlockImport {
        slot,
        block_root,
        parent_root,
        execution_block_hash: [0u8; 32],
        justified: jus,
        finalized: fin,
        unrealized_justified: jus,
        unrealized_finalized: fin,
        state_id: test_state_id(),
        bid_block_hash: [0u8; 32],
        parent_payload_status: PayloadStatus::Full,
        payload_verified: true,
        is_gloas: false,
    }
}

/// Gloas-block import variant: marks the node payload-bearing and lets the
/// caller set the parent-payload edge + whether the envelope is verified.
fn gloas_block(
    slot: Slot,
    block_root: B256,
    parent_root: B256,
    jus: Checkpoint,
    fin: Checkpoint,
    parent_payload_status: PayloadStatus,
    payload_verified: bool,
) -> BlockImport {
    BlockImport {
        parent_payload_status,
        payload_verified,
        is_gloas: true,
        ..block(slot, block_root, parent_root, jus, fin)
    }
}

/// Stage synthetic votes/balances on `fc` and fold them into
/// `fc.weight_deltas`: `changed: None` is a full pass against `old`→`new`;
/// `Some(dirty)` folds only those votes against `new`.
fn compute_deltas(
    fc: &mut ForkChoice,
    votes: Vec<Vote>,
    old: &[u64],
    new: &[u64],
    changed: Option<&[u32]>,
) {
    fc.vote_tracker.votes = votes.into_boxed_slice();
    fc.prev_justified_balances = old.to_vec();
    fc.justified_balances = new.to_vec();
    fc.votes_dirty = changed.unwrap_or_default().to_vec();
    fc.justified_balances_full_pass = changed.is_none();
    fc.compute_weight_deltas();
}

#[test]
fn single_chain_head() {
    let fin = cp(0, 1);
    let jus = cp(0, 1);
    let mut fc = ForkChoice::init(fin, jus, 0, root(1), [0u8; 32], false, test_state_id(), 0);

    fc.on_block(block(1, root(2), root(1), jus, fin));
    fc.on_block(block(2, root(3), root(2), jus, fin));

    assert_eq!(fc.find_head(), root(3));
}

#[test]
fn fork_heavier_wins() {
    let fin = cp(0, 1);
    let jus = cp(0, 1);
    let mut fc = ForkChoice::init(fin, jus, 0, root(1), [0u8; 32], false, test_state_id(), 0);

    fc.on_block(block(1, root(2), root(1), jus, fin));
    fc.on_block(block(1, root(3), root(1), jus, fin));

    let mut deltas = vec![WeightDelta::default(); fc.nodes.len()];
    deltas[2].pending = 100; // root(3) is node index 2
    fc.weight_deltas = deltas;
    fc.apply_score_changes();

    assert_eq!(fc.find_head(), root(3));
}

#[test]
fn two_pass_weight_correctness() {
    // Regression: single-pass apply_score_changes could pick the wrong
    // child when a higher-index child gains weight and a lower-index
    // sibling loses weight.
    let fin = cp(0, 1);
    let jus = cp(0, 1);
    let mut fc = ForkChoice::init(fin, jus, 0, root(1), [0u8; 32], false, test_state_id(), 0);

    // root(1) → root(2) [idx 1] and root(3) [idx 2]
    fc.on_block(block(1, root(2), root(1), jus, fin));
    fc.on_block(block(1, root(3), root(1), jus, fin));

    // Give root(2) initial weight.
    let mut deltas = vec![WeightDelta::default(); fc.nodes.len()];
    deltas[1].pending = 200;
    fc.weight_deltas = deltas;
    fc.apply_score_changes();
    assert_eq!(fc.find_head(), root(2));

    // Now root(2) loses weight, root(3) gains → root(3) should win.
    let mut deltas = vec![WeightDelta::default(); fc.nodes.len()];
    deltas[1].pending = -150; // root(2): 200 - 150 = 50
    deltas[2].pending = 100; // root(3): 0 + 100 = 100
    fc.weight_deltas = deltas;
    fc.apply_score_changes();
    assert_eq!(fc.find_head(), root(3));
}

#[test]
fn prune_below_finalized() {
    let fin = cp(0, 1);
    let jus = cp(0, 1);
    let mut fc = ForkChoice::init(fin, jus, 0, root(1), [0u8; 32], false, test_state_id(), 0);

    fc.on_block(block(1, root(2), root(1), jus, fin));
    fc.on_block(block(2, root(3), root(2), jus, fin));
    assert_eq!(fc.nodes.len(), 3);

    fc.finalized_checkpoint = cp(1, 2);
    fc.prune();

    assert_eq!(fc.nodes.len(), 2);
    assert_eq!(fc.nodes[0].block_root, root(2));
    assert_eq!(fc.nodes[0].parent_ix, NULL);
    assert_eq!(fc.find_node_idx(&root(3)), Some(1));
}

#[test]
fn prune_drops_later_imported_siblings() {
    // Regression: index-order pruning kept branches imported after the
    // finalized block, handing finalization survivors that don't descend from
    // the promoted delta.
    let fin = cp(0, 1);
    let jus = cp(0, 1);
    let mut fc = ForkChoice::init(fin, jus, 0, root(1), [0u8; 32], false, test_state_id(), 0);

    fc.on_block(block(1, root(2), root(1), jus, fin)); // finalized-to-be
    fc.on_block(block(1, root(3), root(1), jus, fin)); // sibling, imported after
    fc.on_block(block(2, root(4), root(3), jus, fin)); // sibling's child
    fc.on_block(block(2, root(5), root(2), jus, fin)); // descendant

    fc.finalized_checkpoint = cp(1, 2);
    fc.prune();

    assert_eq!(fc.nodes.len(), 2);
    assert_eq!(fc.nodes[0].block_root, root(2));
    assert_eq!(fc.nodes[0].parent_ix, NULL);
    assert_eq!(fc.find_node_idx(&root(5)), Some(1));
    assert_eq!(fc.nodes[1].parent_ix, 0);
    assert_eq!(fc.find_node_idx(&root(3)), None);
    assert_eq!(fc.find_node_idx(&root(4)), None);
}

#[test]
fn deltas_moving_votes() {
    let fin = cp(0, 1);
    let jus = cp(0, 1);
    let mut fc = ForkChoice::init(fin, jus, 0, root(1), [0u8; 32], false, test_state_id(), 0);
    fc.on_block(block(1, root(2), root(1), jus, fin));

    let mut votes = vec![Vote::default(); 16];
    let mut balances = vec![0u64; 16];

    // 16 validators all move from root(1) to root(2).
    for i in 0..16 {
        votes[i] = Vote {
            applied_root: root(1),
            latest_root: root(2),
            latest_epoch: 0,
            ..Default::default()
        };
        balances[i] = 42;
    }

    compute_deltas(&mut fc, votes, &balances, &balances, None);

    let total = 42i64 * 16;
    assert_eq!(fc.weight_deltas[0].pending, -total);
    assert_eq!(fc.weight_deltas[1].pending, total);

    for i in 0..16 {
        assert_eq!(fc.vote_tracker.votes[i].applied_root, root(2));
    }
}

#[test]
fn deltas_different_votes() {
    // Each validator votes for a different block.
    let fin = cp(0, 100);
    let jus = cp(0, 100);
    let mut fc = ForkChoice::init(fin, jus, 0, root(100), [0u8; 32], false, test_state_id(), 0);

    for i in 1..=16u8 {
        fc.on_block(block(i as u64, root(i), root(100), jus, fin));
    }

    let mut votes = vec![Vote::default(); 16];
    let mut balances = vec![0u64; 16];

    for i in 0..16 {
        votes[i] = Vote {
            applied_root: [0u8; 32],
            latest_root: root((i + 1) as u8),
            latest_epoch: 0,
            ..Default::default()
        };
        balances[i] = 42;
    }

    compute_deltas(&mut fc, votes, &balances, &balances, None);

    // Each block should get exactly one validator's balance.
    for i in 1..=16 {
        assert_eq!(fc.weight_deltas[i].pending, 42);
    }
}

#[test]
fn deltas_move_out_of_tree() {
    let fin = cp(0, 1);
    let jus = cp(0, 1);
    let mut fc = ForkChoice::init(fin, jus, 0, root(1), [0u8; 32], false, test_state_id(), 0);

    let mut votes = vec![Vote::default(); 16];
    let mut balances = vec![0u64; 16];

    // Validator 0 moves from root(1) to zero hash (genesis alias).
    votes[0] = Vote {
        applied_root: root(1),
        latest_root: [0u8; 32],
        latest_epoch: 0,
        ..Default::default()
    };
    balances[0] = 42;

    // Validator 1 moves from root(1) to unknown root.
    votes[1] = Vote {
        applied_root: root(1),
        latest_root: root(99),
        latest_epoch: 0,
        ..Default::default()
    };
    balances[1] = 42;

    compute_deltas(&mut fc, votes, &balances[..2], &balances[..2], None);

    // root(1) should lose both balances.
    assert_eq!(fc.weight_deltas[0].pending, -(42 * 2));
}

#[test]
fn deltas_changing_balances() {
    let fin = cp(0, 1);
    let jus = cp(0, 1);
    let mut fc = ForkChoice::init(fin, jus, 0, root(1), [0u8; 32], false, test_state_id(), 0);
    fc.on_block(block(1, root(2), root(1), jus, fin));

    let mut votes = vec![Vote::default(); 16];
    let mut old_bal = vec![0u64; 16];
    let mut new_bal = vec![0u64; 16];

    // 16 validators move from root(1) to root(2), balance doubles.
    for i in 0..16 {
        votes[i] = Vote {
            applied_root: root(1),
            latest_root: root(2),
            latest_epoch: 0,
            ..Default::default()
        };
        old_bal[i] = 42;
        new_bal[i] = 84;
    }

    compute_deltas(&mut fc, votes, &old_bal, &new_bal, None);

    // Old balance subtracted from old target, new balance added to new.
    assert_eq!(fc.weight_deltas[0].pending, -(42i64 * 16));
    assert_eq!(fc.weight_deltas[1].pending, 84i64 * 16);
}

#[test]
fn deltas_balance_change_no_vote_change() {
    // Balances change but votes don't — still need deltas.
    let fin = cp(0, 1);
    let jus = cp(0, 1);
    let mut fc = ForkChoice::init(fin, jus, 0, root(1), [0u8; 32], false, test_state_id(), 0);

    let mut votes = vec![Vote::default(); 16];
    let mut old_bal = vec![0u64; 16];
    let mut new_bal = vec![0u64; 16];

    // Validator already voted for root(1), balance changes.
    votes[0] =
        Vote { applied_root: root(1), latest_root: root(1), latest_epoch: 0, ..Default::default() };
    old_bal[0] = 42;
    new_bal[0] = 84;

    compute_deltas(&mut fc, votes, &old_bal[..1], &new_bal[..1], None);

    // Net delta = new - old = +42.
    assert_eq!(fc.weight_deltas[0].pending, 42);
}

/// Tiebreaker: equal-weight siblings → higher block root wins (spec: >=).
#[test]
fn split_tie_breaker_no_attestations() {
    let fin = cp(0, 1);
    let jus = cp(0, 1);
    let mut fc = ForkChoice::init(fin, jus, 0, root(1), [0u8; 32], false, test_state_id(), 0);

    // Two blocks at slot 1 forking from genesis. root(2) < root(3).
    fc.on_block(block(1, root(2), root(1), jus, fin));
    fc.on_block(block(1, root(3), root(1), jus, fin));

    // No weight applied → both have weight 0. Higher root wins.
    assert_eq!(fc.find_head(), root(3));
}

/// Shorter chain with more attestation weight beats a longer chain.
#[test]
fn shorter_chain_but_heavier_weight() {
    let fin = cp(0, 1);
    let jus = cp(0, 1);
    let mut fc = ForkChoice::init(fin, jus, 0, root(1), [0u8; 32], false, test_state_id(), 0);

    // Long chain: root(1) → root(2) → root(3) → root(4).
    fc.on_block(block(1, root(2), root(1), jus, fin));
    fc.on_block(block(2, root(3), root(2), jus, fin));
    fc.on_block(block(3, root(4), root(3), jus, fin));

    // Short chain: root(1) → root(5).
    fc.on_block(block(1, root(5), root(1), jus, fin));

    // Without weight, long chain wins (deeper best_descendant, higher root
    // tiebreak). Give root(5) more weight to flip.
    let mut deltas = vec![WeightDelta::default(); fc.nodes.len()];
    deltas[4].pending = 1000; // root(5) is node 4
    fc.weight_deltas = deltas;
    fc.apply_score_changes();

    assert_eq!(fc.find_head(), root(5));
}

/// Duplicate block insertion is a no-op.
#[test]
fn on_block_duplicate() {
    let fin = cp(0, 1);
    let jus = cp(0, 1);
    let mut fc = ForkChoice::init(fin, jus, 0, root(1), [0u8; 32], false, test_state_id(), 0);

    fc.on_block(block(1, root(2), root(1), jus, fin));
    assert_eq!(fc.nodes.len(), 2);

    fc.on_block(block(1, root(2), root(1), jus, fin));
    assert_eq!(fc.nodes.len(), 2); // no change
}

/// Unknown parent → node still inserted (parent = NULL).
#[test]
fn on_block_unknown_parent() {
    let fin = cp(0, 1);
    let jus = cp(0, 1);
    let mut fc = ForkChoice::init(fin, jus, 0, root(1), [0u8; 32], false, test_state_id(), 0);

    // root(99) is not known.
    fc.on_block(block(1, root(2), root(99), jus, fin));
    assert_eq!(fc.nodes.len(), 2);
    assert_eq!(fc.nodes[1].parent_ix, NULL);
}

/// `NodeLookup` resolves every node, misses unknown/zero roots, and stays
/// correct after a prune rebuild.
#[test]
fn node_lookup_equivalence_and_prune() {
    let fin = cp(0, 1);
    let jus = cp(0, 1);
    let mut fc = ForkChoice::init(fin, jus, 0, root(1), [0u8; 32], false, test_state_id(), 0);
    for i in 2..=20u8 {
        fc.on_block(block(i as u64, root(i), root(i - 1), jus, fin));
    }
    for (i, n) in fc.nodes.iter().enumerate() {
        assert_eq!(fc.find_node_idx(&n.block_root), Some(i));
    }
    assert_eq!(fc.find_node_idx(&root(99)), None);
    assert_eq!(fc.find_node_idx(&[0u8; 32]), None);

    fc.finalized_checkpoint = cp(1, 10);
    fc.prune();
    assert_eq!(fc.nodes[0].block_root, root(10));
    for (i, n) in fc.nodes.iter().enumerate() {
        assert_eq!(fc.find_node_idx(&n.block_root), Some(i));
    }
}

/// Proposer boost flips the head onto a lighter sibling, then expires on
/// the next pass once `proposer_boost_root` is zeroed (boost netted
/// out).
#[test]
fn proposer_boost_flips_then_expires() {
    let fin = cp(0, 1);
    let jus = cp(0, 1);
    let mut fc = ForkChoice::init(fin, jus, 0, root(1), [0u8; 32], false, test_state_id(), 0);
    fc.on_block(block(1, root(2), root(1), jus, fin)); // idx 1
    fc.on_block(block(1, root(3), root(1), jus, fin)); // idx 2

    // root(3) is the heavier (vote-weighted) sibling.
    let mut deltas = vec![WeightDelta::default(); fc.nodes.len()];
    deltas[2].pending = 100;
    fc.weight_deltas = deltas;
    fc.apply_score_changes();
    assert_eq!(fc.find_head(), root(3));

    // Boost root(2) above root(3): head flips.
    fc.proposer_boost_root = root(2);
    fc.proposer_boost_score = 150;
    fc.weight_deltas = vec![WeightDelta::default(); fc.nodes.len()];
    fc.apply_score_changes();
    assert_eq!(fc.find_head(), root(2));

    // Next slot zeroes the boost root: the applied boost is subtracted and
    // the head reverts to the vote-heavier sibling.
    fc.proposer_boost_root = [0u8; 32];
    fc.weight_deltas = vec![WeightDelta::default(); fc.nodes.len()];
    fc.apply_score_changes();
    assert_eq!(fc.find_head(), root(3));
}

/// Dirty-only `compute_deltas` reproduces the full-pass result when the
/// balance snapshot is unchanged (stable votes contribute nothing either
/// way; only moved votes count).
#[test]
fn compute_deltas_dirty_matches_full() {
    let fin = cp(0, 1);
    let jus = cp(0, 1);
    let mut fc = ForkChoice::init(fin, jus, 0, root(1), [0u8; 32], false, test_state_id(), 0);
    for i in 2..=5u8 {
        fc.on_block(block(1, root(i), root(1), jus, fin));
    }

    let bal = vec![10u64; 32];
    let mut votes_full = vec![Vote::default(); 32];
    let mut dirty = Vec::new();
    for (i, v) in votes_full.iter_mut().enumerate() {
        let r = root(2 + (i % 4) as u8);
        if i % 2 == 0 {
            // Moved vote (dirty).
            *v = Vote {
                applied_root: [0u8; 32],
                latest_root: r,
                latest_epoch: 0,
                ..Default::default()
            };
            dirty.push(i as u32);
        } else {
            // Stable vote — full pass skips it (current == next, equal bal).
            *v = Vote { applied_root: r, latest_root: r, latest_epoch: 0, ..Default::default() };
        }
    }
    let votes_dirty = votes_full.clone();

    compute_deltas(&mut fc, votes_full, &bal, &bal, None);
    let d_full = fc.weight_deltas.clone();
    let applied_full: Vec<_> = fc.vote_tracker.votes.iter().map(|v| v.applied_root).collect();

    compute_deltas(&mut fc, votes_dirty, &bal, &bal, Some(&dirty));
    assert_eq!(d_full, fc.weight_deltas);
    for i in 0..32 {
        assert_eq!(applied_full[i], fc.vote_tracker.votes[i].applied_root);
    }
}

/// Genesis exception: while the store's justified checkpoint is at
/// GENESIS_EPOCH, any node is viable regardless of its (stale) voting
/// source — the `+2` rule would otherwise filter it.
#[test]
fn viability_genesis_exception() {
    let g = cp(0, 1);
    let mut fc = ForkChoice::init(g, g, 0, root(1), [0u8; 32], false, test_state_id(), 0);
    // Prior-epoch node with a stale (epoch 1) voting source.
    fc.on_block(block(64, root(2), root(1), cp(1, 9), g));
    let a = fc.find_node_idx(&root(2)).unwrap();
    fc.nodes[a].checkpoints.unrealized_justified = cp(1, 9);
    fc.set_current_slot(10 * SLOTS_PER_EPOCH); // +2 would filter cp(1, ..), but store is at genesis
    fc.weight_deltas = vec![WeightDelta::default(); fc.nodes.len()];
    fc.apply_score_changes();
    assert_eq!(fc.find_head(), root(2));
}

/// A prior-epoch node votes from its *unrealized* justified checkpoint, and
/// the `voting_source.epoch + 2 >= current_epoch` relaxation governs the
/// boundary.
#[test]
fn viability_unrealized_justified_and_plus_two() {
    // Genesis finalized isolates the justified rule; store justified
    // promoted to epoch 2 (node root(2) at slot 64).
    let g = cp(0, 1);
    let mut fc = ForkChoice::init(g, g, 0, root(1), [0u8; 32], false, test_state_id(), 0);
    fc.on_block(block(64, root(2), root(1), cp(2, 2), g)); // A @ epoch 2
    fc.justified_checkpoint = cp(2, 2);
    // C @ epoch 2, child of A, realized justified stale (epoch 1).
    fc.on_block(block(65, root(3), root(2), cp(1, 9), g));
    let c = fc.find_node_idx(&root(3)).unwrap();

    // current_epoch 4: C is prior-epoch -> voting source is its unrealized
    // justified. Caught up to epoch 2 -> viable -> head = C.
    fc.set_current_slot(4 * SLOTS_PER_EPOCH);
    fc.nodes[c].checkpoints.unrealized_justified = cp(2, 2);
    fc.weight_deltas = vec![WeightDelta::default(); fc.nodes.len()];
    fc.apply_score_changes();
    assert_eq!(fc.find_head(), root(3));

    // Stale unrealized (epoch 1): 1 != 2 and 1 + 2 < 4 -> filtered -> head
    // falls back to A.
    fc.nodes[c].checkpoints.unrealized_justified = cp(1, 9);
    fc.weight_deltas = vec![WeightDelta::default(); fc.nodes.len()];
    fc.apply_score_changes();
    assert_eq!(fc.find_head(), root(2));

    // +2 boundary: at current_epoch 3, 1 + 2 >= 3 -> viable again.
    fc.set_current_slot(3 * SLOTS_PER_EPOCH);
    fc.weight_deltas = vec![WeightDelta::default(); fc.nodes.len()];
    fc.apply_score_changes();
    assert_eq!(fc.find_head(), root(3));
}

// ---- [Gloas] payload-axis tests ----

/// `vote_branch` classifies a vote into a payload bucket: a past-block vote
/// on a Gloas block picks Full/Empty by the presence bit; same-slot or
/// pre-Gloas votes are block-level (Pending).
#[test]
fn gloas_vote_branch_classification() {
    let g = cp(0, 1);
    let mut fc = ForkChoice::init(g, g, 0, root(1), [0u8; 32], false, test_state_id(), 8);
    fc.on_block(gloas_block(5, root(2), root(1), g, g, PayloadStatus::Full, true));
    let gl = fc.node(fc.find_node_idx(&root(2)).unwrap());
    assert_eq!(branch_voted_for(gl, 6, true), PayloadStatus::Full);
    assert_eq!(branch_voted_for(gl, 6, false), PayloadStatus::Empty);
    assert_eq!(branch_voted_for(gl, 5, true), PayloadStatus::Pending); // same slot
    assert_eq!(branch_voted_for(gl, 5, false), PayloadStatus::Pending);

    fc.on_block(block(7, root(3), root(2), g, g)); // pre-Gloas node
    let pre = fc.node(fc.find_node_idx(&root(3)).unwrap());
    assert_eq!(branch_voted_for(pre, 8, true), PayloadStatus::Pending); // never picks a branch
}

/// A Gloas block resolves to the payload branch carrying more subtree weight,
/// and the head follows that branch's children.
#[test]
fn gloas_resolves_heavier_payload_branch() {
    let g = cp(0, 1);
    let mut fc = ForkChoice::init(g, g, 0, root(1), [0u8; 32], false, test_state_id(), 8);
    // A (idx1), then a FULL-edge child C_f (idx2) and EMPTY-edge child C_e (idx3).
    fc.on_block(gloas_block(1, root(2), root(1), g, g, PayloadStatus::Full, true));
    fc.on_block(gloas_block(2, root(3), root(2), g, g, PayloadStatus::Full, true));
    fc.on_block(gloas_block(2, root(4), root(2), g, g, PayloadStatus::Empty, true));

    // C_f heavier → A resolves FULL → head is C_f.
    let mut d = vec![WeightDelta::default(); fc.nodes.len()];
    d[2].pending = 100;
    d[3].pending = 50;
    fc.weight_deltas = d;
    fc.apply_score_changes();
    assert_eq!(fc.find_head(), root(3));

    // Flip: C_e now heavier → A resolves EMPTY → head is C_e.
    let mut d = vec![WeightDelta::default(); fc.nodes.len()];
    d[3].pending = 100;
    fc.weight_deltas = d;
    fc.apply_score_changes();
    assert_eq!(fc.find_head(), root(4));
}

/// On an exactly-tied payload split, `should_extend_payload` decides: with
/// no PTC votes and no conflicting proposer boost it extends (FULL); a
/// boost on the EMPTY-extending child flips the resolution to EMPTY.
#[test]
fn gloas_tie_broken_by_should_extend_payload() {
    let g = cp(0, 1);
    let mut fc = ForkChoice::init(g, g, 0, root(1), [0u8; 32], false, test_state_id(), 8);
    fc.on_block(gloas_block(1, root(2), root(1), g, g, PayloadStatus::Full, true));
    fc.on_block(gloas_block(2, root(3), root(2), g, g, PayloadStatus::Full, true)); // C_f
    fc.on_block(gloas_block(2, root(4), root(2), g, g, PayloadStatus::Empty, true)); // C_e
    // A (slot 1) is the previous-slot payload decision (current slot 2), where
    // `should_extend_payload` governs regardless of subtree weight.
    fc.set_current_slot(2);

    // Equal weight on both branchs → tie.
    let mut d = vec![WeightDelta::default(); fc.nodes.len()];
    d[2].pending = 100;
    d[3].pending = 100;
    fc.weight_deltas = d;
    fc.apply_score_changes();
    // No boost → extend FULL → C_f.
    assert_eq!(fc.find_head(), root(3));

    // Boost the EMPTY-extending child C_e (score 0: tiebreak only, no weight
    // shift) → should_extend false → A resolves EMPTY → C_e.
    fc.proposer_boost_root = root(4);
    fc.weight_deltas = vec![WeightDelta::default(); fc.nodes.len()];
    fc.apply_score_changes();
    assert_eq!(fc.find_head(), root(4));
}

/// An unverified payload (envelope not yet delivered) is never selectable
/// as FULL, even when its full branch would be heavier — the block
/// resolves EMPTY until `mark_payload_verified`.
#[test]
fn gloas_unverified_payload_forces_empty() {
    let g = cp(0, 1);
    let mut fc = ForkChoice::init(g, g, 0, root(1), [0u8; 32], false, test_state_id(), 8);
    fc.on_block(gloas_block(1, root(2), root(1), g, g, PayloadStatus::Full, false));
    fc.on_block(gloas_block(2, root(3), root(2), g, g, PayloadStatus::Full, true)); // C_f
    fc.on_block(gloas_block(2, root(4), root(2), g, g, PayloadStatus::Empty, true)); // C_e

    // C_f far heavier — but A's FULL branch is unverified, so head is C_e.
    let mut d = vec![WeightDelta::default(); fc.nodes.len()];
    d[2].pending = 100;
    d[3].pending = 1;
    fc.weight_deltas = d;
    fc.apply_score_changes();
    assert_eq!(fc.find_head(), root(4));

    // Once the envelope is verified, the heavier FULL branch wins.
    fc.mark_payload_verified(&root(2));
    fc.weight_deltas = vec![WeightDelta::default(); fc.nodes.len()];
    fc.apply_score_changes();
    assert_eq!(fc.find_head(), root(3));
}

/// EL full-branch asymmetry: an INVALID envelope kills only the block's FULL
/// resolution. The block survives as EMPTY (its empty-edge child is head),
/// and `head_payload_present` reports EMPTY.
#[test]
fn gloas_empty_survives_full_invalid() {
    let g = cp(0, 1);
    let mut fc = ForkChoice::init(g, g, 0, root(1), [0u8; 32], false, test_state_id(), 8);
    fc.on_block(gloas_block(1, root(2), root(1), g, g, PayloadStatus::Full, true));
    fc.on_block(gloas_block(2, root(3), root(2), g, g, PayloadStatus::Full, true)); // C_f
    fc.on_block(gloas_block(2, root(4), root(2), g, g, PayloadStatus::Empty, true)); // C_e

    // C_f heavier → A would resolve FULL → head C_f, present.
    let mut d = vec![WeightDelta::default(); fc.nodes.len()];
    d[2].pending = 100;
    d[3].pending = 50;
    fc.weight_deltas = d;
    fc.apply_score_changes();
    assert_eq!(fc.find_head(), root(3));
    assert!(fc.head_payload_present());

    // EL invalidates A's envelope → FULL branch dead → A resolves EMPTY → C_e,
    // and A itself stays viable (not sunk like a pre-Gloas invalid block).
    fc.on_payload_invalid(&root(2), &[0u8; 32]);
    fc.weight_deltas = vec![WeightDelta::default(); fc.nodes.len()];
    fc.apply_score_changes();
    assert_eq!(fc.find_head(), root(4));
}

/// Proposer boost on a (same-slot) Gloas block is a block-level PENDING
/// vote, not an EMPTY vote: it must not block the block from resolving FULL
/// once its envelope is verified. (Regression: routing boost to `empty`
/// pinned the head EMPTY after an envelope reveal.)
#[test]
fn gloas_boost_is_pending_not_empty() {
    let g = cp(0, 1);
    let mut fc = ForkChoice::init(g, g, 0, root(1), [0u8; 32], false, test_state_id(), 8);
    // Boosted current-slot block, envelope not yet revealed.
    fc.on_block(gloas_block(1, root(2), root(1), g, g, PayloadStatus::Full, false));
    fc.proposer_boost_root = root(2);
    fc.proposer_boost_score = 1000;
    fc.weight_deltas = vec![WeightDelta::default(); fc.nodes.len()];
    fc.apply_score_changes();
    // Unverified → EMPTY; the heavy boost (pending) does not force a branch.
    assert_eq!(fc.find_head(), root(2));
    assert!(!fc.head_payload_present());

    // Envelope verified → resolves FULL. With boost wrongly in `empty` this
    // would stay EMPTY.
    fc.mark_payload_verified(&root(2));
    fc.weight_deltas = vec![WeightDelta::default(); fc.nodes.len()];
    fc.apply_score_changes();
    assert!(fc.head_payload_present());
}
