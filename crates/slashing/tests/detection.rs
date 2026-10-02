use silver_slashing::{DoubleProposals, Observation, Offence, SignedHeader, SlashingDetection};
use silver_ssz::ssz_view::{ProposerSlashingView, SIGNED_BEACON_BLOCK_MIN, SINGLE_ATT_SIZE};

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

const VERSION: [u8; 4] = [1, 0, 0, 0];

fn vote(index: u64, source: u64, target: u64) -> [u8; SINGLE_ATT_SIZE] {
    let mut ssz = [0; SINGLE_ATT_SIZE];
    ssz[8..16].copy_from_slice(&index.to_le_bytes());
    ssz[16..24].copy_from_slice(&(target * 32).to_le_bytes());
    ssz[64..72].copy_from_slice(&source.to_le_bytes());
    ssz[104..112].copy_from_slice(&target.to_le_bytes());
    ssz
}

#[test]
fn local_vote_conflicts_with_retained_public_votes() {
    let mut detection = SlashingDetection::default();
    let public = vote(7, 0, 2);
    let mut next_slot = vote(7, 1, 2);
    next_slot[16..24].copy_from_slice(&65u64.to_le_bytes());
    let conflict = |detection: &SlashingDetection, version| {
        detection.conflicts_with_public(&next_slot, |_| version)
    };
    detection.record_vote(&public, VERSION);
    assert_eq!(conflict(&detection, VERSION), Some(Offence::DoubleVote), "either slot");
    assert_eq!(detection.conflicts_with_public(&public, |_| VERSION), None, "a repeat");
    assert_eq!(conflict(&detection, [2; 4]), None, "another fork version");
    for slot in [66u64, 67] {
        let mut later = vote(8, 0, 2);
        later[16..24].copy_from_slice(&slot.to_le_bytes());
        detection.record_vote(&later, VERSION);
    }
    assert_eq!(conflict(&detection, VERSION), None, "two newer slots evict it");
}
