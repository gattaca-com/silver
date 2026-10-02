use silver_slashing::{DoubleProposals, Observation, SignedHeader};
use silver_ssz::ssz_view::{ProposerSlashingView, SIGNED_BEACON_BLOCK_MIN};

#[test]
fn proposals_remain_reportable_until_queued_and_prune_only_finalized_keys() {
    let mut proposals = DoubleProposals::default();
    for index in 0..65 {
        proposals.observe(header(index, 5, 1), true);
        proposals.observe(header(index, 5, 2), true);
    }
    let mut published = Vec::new();
    while let Some(proof) = proposals.next_proof(|_| true) {
        published.push(ProposerSlashingView::h1_proposer_index(proof));
        proposals.pop_proof();
    }
    published.sort();
    assert_eq!(published, (0..64).collect::<Vec<_>>());
    for index in 0..65 {
        proposals.observe(header(index, 5, 3), true);
    }
    assert_eq!(
        proposals.next_proof(|_| true).map(ProposerSlashingView::h1_proposer_index),
        Some(64)
    );
    proposals.pop_proof();
    assert!(proposals.next_proof(|_| true).is_none());
    proposals.observe(header(0, 6, 1), true);
    proposals.prune_finalized(5);
    assert_eq!(proposals.observe(header(0, 5, 2), true), Observation::First);
    assert_ne!(proposals.observe(header(0, 6, 2), true), Observation::First);
}

fn header(index: u64, slot: u64, tag: u8) -> SignedHeader {
    let mut block = [0; SIGNED_BEACON_BLOCK_MIN];
    block[100..108].copy_from_slice(&slot.to_le_bytes());
    block[108..116].copy_from_slice(&index.to_le_bytes());
    SignedHeader::of_block(&block, &[tag; 32])
}
