use silver_slashing::{DoubleProposals, Observation, Offence, SignedHeader, SlashingDetection};
use silver_ssz::ssz_view::{
    ATTESTATION_FIXED, AttesterSlashingView, ProposerSlashingView, SIGNED_BEACON_BLOCK_MIN,
    SINGLE_ATT_SIZE, SingleAttestationView,
};

const VERSION: [u8; 4] = [1, 0, 0, 0];

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

fn vote(index: u64, source: u64, target: u64) -> [u8; SINGLE_ATT_SIZE] {
    let mut ssz = [0; SINGLE_ATT_SIZE];
    ssz[8..16].copy_from_slice(&index.to_le_bytes());
    ssz[16..24].copy_from_slice(&(target * 32).to_le_bytes());
    ssz[64..72].copy_from_slice(&source.to_le_bytes());
    ssz[104..112].copy_from_slice(&target.to_le_bytes());
    ssz
}

fn header(index: u64, slot: u64, tag: u8) -> SignedHeader {
    let mut block = [0; SIGNED_BEACON_BLOCK_MIN];
    block[100..108].copy_from_slice(&slot.to_le_bytes());
    block[108..116].copy_from_slice(&index.to_le_bytes());
    SignedHeader::of_block(&block, &[tag; 32])
}

fn attestation(slot: u64, source_epoch: u64, signers: &[usize], len: usize) -> Vec<u8> {
    let mut ssz = vec![0; ATTESTATION_FIXED + (len + 1).div_ceil(8)];
    ssz[4..12].copy_from_slice(&slot.to_le_bytes());
    ssz[52..60].copy_from_slice(&source_epoch.to_le_bytes());
    ssz[92..100].copy_from_slice(&(slot / 32).to_le_bytes());
    ssz[228] = 1;
    for &at in signers.iter().chain([&len]) {
        ssz[ATTESTATION_FIXED + at / 8] |= 1 << (at % 8);
    }
    ssz
}

#[test]
fn proofs_publish_within_a_slot_budget() {
    let mut detection = SlashingDetection::new(0, 0);
    let budget = 16;
    let (old_version, unslashable) = (budget + 1, budget + 2);
    for validator_index in 0..=unslashable {
        let version = if validator_index == old_version { [2; 4] } else { VERSION };
        let committee = [validator_index as u32];
        detection.record_aggregate(&attestation(64, 0, &[0], 1), &committee, version);
        detection.record_aggregate(&attestation(64, 1, &[0], 1), &committee, VERSION);
    }
    let mut publish = |wall_slot| {
        let slashable = |index| index != unslashable;
        let proof = detection.next_attester_proof(wall_slot, slashable, |_| VERSION)?;
        let offender = proof.offenders().next();
        detection.pop_attester_proof();
        offender
    };

    let mut published: Vec<_> = std::iter::from_fn(|| publish(64)).collect();
    assert_eq!(published.len(), 16, "one slot's budget");
    published.push(publish(65).expect("the next slot's budget"));
    assert_eq!(publish(65), None);

    published.sort();
    assert_eq!(published, (0..=budget).collect::<Vec<_>>(), "skipped proofs spend no budget");
}

#[test]
fn full_queue_leaves_a_double_vote_provable() {
    let mut detection = SlashingDetection::new(0, 0);
    let committee: Vec<_> = (0..128).collect();
    let record = |detection: &mut SlashingDetection, source_epoch, signers: &[usize]| {
        let attestation = attestation(64, source_epoch, signers, committee.len());
        detection.record_aggregate(&attestation, &committee, VERSION);
    };
    let everyone: Vec<_> = (0..=64).collect();
    record(&mut detection, 0, &everyone);
    for offender in 0..=64 {
        record(&mut detection, 1, &[offender]);
    }
    assert_eq!(
        detection.next_attester_proof(64, |_| true, |_| VERSION).unwrap().offenders().next(),
        Some(63)
    );
    detection.pop_attester_proof();
    record(&mut detection, 1, &[64]);
    assert_eq!(
        detection.next_attester_proof(64, |_| true, |_| VERSION).unwrap().offenders().next(),
        Some(64)
    );
}

#[test]
fn local_vote_conflicts_with_retained_public_votes() {
    let mut detection = SlashingDetection::new(0, 0);
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

#[test]
fn surrounds_use_strict_bounds_and_preserve_evidence_before_lane_reuse() {
    for (index, first_span, second_span, found) in [
        (7, (1, 4), (2, 3), true),
        (7, (2, 3), (1, 4), true),
        (7, (2, 3), (1, 5), true),
        (3 * 65536 + 5, (2, 3), (1, 4), true),
        (7, (1, 0), (0, 1), true),
        (7, (1, 2), (2, 3), false),
        (7, (1, 2), (1, 3), false),
        (7, (1, 3), (2, 3), false),
        (7, (1, 5), (2, u64::from(u32::MAX) + 3), false),
    ] {
        let mut detection = SlashingDetection::new(1, 0);
        let first = vote(index, first_span.0, first_span.1);
        let second = vote(index, second_span.0, second_span.1);
        detection.record_vote(&first, VERSION);
        assert_eq!(
            detection.conflicts_with_public(&second, |_| VERSION) == Some(Offence::SurroundVote),
            found
        );
        assert_eq!(detection.conflicts_with_public(&second, |_| [2; 4]), None);
        assert_eq!(detection.conflicts_with_public(&vote(index + 1, 0, 6), |_| VERSION), None);
        detection.record_vote(&second, VERSION);
        let proof = detection.next_attester_proof(10, |_| true, |_| VERSION);
        assert_eq!(proof.is_some(), found);
        if let Some(proof) = proof {
            let [outer, inner] =
                if first_span.0 < second_span.0 { [first, second] } else { [second, first] };
            let slashing = proof.slashing();
            let data = [
                AttesterSlashingView::att1_data(&slashing),
                AttesterSlashingView::att2_data(&slashing),
            ];
            assert_eq!(
                data.map(|d| *d.as_bytes()),
                [&outer, &inner].map(|v| *SingleAttestationView::data(v).as_bytes())
            );
        }
    }
}

#[test]
fn double_vote_is_proven_within_one_committee_record() {
    let mut votes = SlashingDetection::new(0, 0);
    let (committee, reshuffled) = ([5, 9, 7, 3], [4, 9, 7, 3]);
    let mut record = |slot, source_epoch, signers: &[usize], committee: &[u32]| {
        let attestation = attestation(slot, source_epoch, signers, committee.len());
        votes.record_aggregate(&attestation, committee, VERSION);
        let proof = votes.next_attester_proof(64, |_| true, |_| VERSION);
        let offenders = proof.map(|p| p.offenders().collect::<Vec<_>>());
        if offenders.is_some() {
            votes.pop_attester_proof();
        }
        offenders
    };

    assert!(record(64, 0, &[0, 1], &committee).is_none());
    assert!(record(64, 1, &[0], &reshuffled).is_none(), "another committee");
    assert!(record(62, 0, &[0, 1], &reshuffled).is_none(), "a slot behind the window");
    let proof = record(64, 2, &[0, 2], &reshuffled).expect("a double vote");

    assert_eq!(proof, [4]);
}
