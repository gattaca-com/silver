use super::*;

const SLOT: u64 = 7;
const UNSEEN_PARENT: BlockRoot = [0xab; 32];
const SIGNATURE_AT: usize = 4;
const PROPOSER_AT: usize = 4 + 96 + 8;

#[test]
fn held_gloas_root_keeps_the_first_copy_of_each_column() {
    let (honest, junk) = (BlockBlob::counting(), BlockBlob::starting_at(1));
    let mut rig = Rig::gloas(CUSTODY_COLUMNS);
    let root = [9; 32];

    rig.gossip_sidecar(3, &honest.gloas_sidecar(3, SLOT, &root));
    for _ in 0..NUMBER_OF_COLUMNS {
        rig.gossip_sidecar(3, &junk.gloas_sidecar(3, SLOT, &root));
    }
    rig.gossip_sidecar(7, &honest.gloas_sidecar(7, SLOT, &root));

    assert_eq!(rig.tile.gloas_pending_columns.len_of(&root), 2);
}

/// Range sync fetches columns beside their blocks, and those answers are this
/// node's own requests, outside gossip's share.
#[test]
fn rpc_sidecars_hold_beside_a_full_gossip_share() {
    let blob = BlockBlob::counting();
    let mut rig = Rig::gloas(CUSTODY_COLUMNS);
    for i in 0..2 * SLOTS_PER_EPOCH as u8 + 1 {
        rig.gossip_sidecar(3, &blob.gloas_sidecar(3, SLOT, &[i; 32]));
    }
    let gossip_overflow = [2 * SLOTS_PER_EPOCH as u8; 32];
    assert!(!rig.tile.gloas_pending_columns.contains(&gossip_overflow));

    let rpc_root = [0xF0; 32];
    rig.rpc_sidecar(&blob.gloas_sidecar(3, SLOT, &rpc_root));
    assert!(rig.tile.gloas_pending_columns.contains(&rpc_root));
}

#[test]
fn fulu_signed_sidecar_waits_for_its_unseen_parent() {
    let blob = BlockBlob::counting();
    let (mut rig, block) = unseen_parent_block(&blob);

    rig.gossip_sidecar(3, &blob.fulu_sidecar(3, &block));

    assert!(rig.tile.parent_pending_columns.contains(&UNSEEN_PARENT));
    assert_eq!(rig.drain().misbehaviours, 0);
}

#[test]
fn fulu_sidecar_with_a_forged_header_signature_is_rejected_not_held() {
    let blob = BlockBlob::counting();
    let (mut rig, mut block) = unseen_parent_block(&blob);
    block[SIGNATURE_AT] ^= 1;

    rig.gossip_sidecar(3, &blob.fulu_sidecar(3, &block));

    assert!(rig.tile.parent_pending_columns.is_empty());
    assert_eq!(rig.drain().misbehaviours, 1);
}

/// The head's registry may not yet hold a proposer another branch has.
#[test]
fn fulu_sidecar_from_an_unknown_proposer_is_ignored_not_held() {
    let blob = BlockBlob::counting();
    let (mut rig, mut block) = unseen_parent_block(&blob);
    block[PROPOSER_AT..PROPOSER_AT + 8].copy_from_slice(&1_000u64.to_le_bytes());

    rig.gossip_sidecar(3, &blob.fulu_sidecar(3, &block));

    assert!(rig.tile.parent_pending_columns.is_empty());
    assert_eq!(rig.drain().misbehaviours, 0);
}

/// The head's lookahead stands in for the unseen parent's.
#[test]
fn fulu_sidecar_from_another_proposer_than_the_head_lookahead_is_ignored_not_held() {
    let blob = BlockBlob::counting();
    let (mut rig, block) = unseen_parent_block_in_lookahead_of(&blob, 1);

    rig.gossip_sidecar(3, &blob.fulu_sidecar(3, &block));

    assert!(rig.tile.parent_pending_columns.is_empty());
    assert_eq!(rig.drain().misbehaviours, 0);
}

fn unseen_parent_block(blob: &BlockBlob) -> (Rig, Vec<u8>) {
    unseen_parent_block_in_lookahead_of(blob, 0)
}

fn unseen_parent_block_in_lookahead_of(blob: &BlockBlob, proposer: u64) -> (Rig, Vec<u8>) {
    Rig::with_fulu_block_on(
        CUSTODY_COLUMNS,
        SLOT,
        &blob.commitment,
        fulu_from_genesis().fork_version_at(0),
        UNSEEN_PARENT,
        proposer,
    )
}
