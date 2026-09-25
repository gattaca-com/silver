use serde::Deserialize;
use silver_common::{
    GossipTopic, SYNC_COMMITTEE_SUBNETS, ssz_view::SIGNED_CONTRIBUTION_AND_PROOF_SIZE,
};

use crate::{
    ctx::ApiCtx,
    http::{
        ids::{bytes, uint64},
        response::Response,
        router::Request,
    },
    submission::{SubmittedEntry, post_submission},
};

pub(crate) fn post_contribution_and_proofs(
    req: &Request<'_>,
    ctx: &ApiCtx,
    resp: &mut Response<'_>,
) {
    post_submission::<SignedSyncCommitteeContribution>(req, ctx, resp);
}

#[derive(Deserialize)]
struct SignedSyncCommitteeContribution {
    message: SyncCommitteeContributionAndProof,
    #[serde(deserialize_with = "bytes")]
    signature: [u8; 96],
}

#[derive(Deserialize)]
struct SyncCommitteeContributionAndProof {
    #[serde(deserialize_with = "uint64")]
    aggregator_index: u64,
    contribution: SyncCommitteeContribution,
    #[serde(deserialize_with = "bytes")]
    selection_proof: [u8; 96],
}

#[derive(Deserialize)]
struct SyncCommitteeContribution {
    #[serde(deserialize_with = "uint64")]
    slot: u64,
    #[serde(deserialize_with = "bytes")]
    beacon_block_root: [u8; 32],
    #[serde(deserialize_with = "uint64")]
    subcommittee_index: u64,
    #[serde(deserialize_with = "bytes")]
    aggregation_bits: [u8; 16],
    #[serde(deserialize_with = "bytes")]
    signature: [u8; 96],
}

impl SubmittedEntry for SignedSyncCommitteeContribution {
    fn accept(&self, _ctx: &ApiCtx) -> Result<GossipTopic, &'static str> {
        if self.message.contribution.subcommittee_index >= SYNC_COMMITTEE_SUBNETS as u64 {
            return Err("subcommittee_index is past the sync subcommittee count");
        }
        Ok(GossipTopic::SyncCommitteeContributionAndProof)
    }

    fn ssz_len(&self) -> usize {
        SIGNED_CONTRIBUTION_AND_PROOF_SIZE
    }

    fn encode(&self, ssz: &mut [u8]) {
        let message = &self.message;
        let contribution = &message.contribution;
        ssz[0..8].copy_from_slice(&message.aggregator_index.to_le_bytes());
        ssz[8..16].copy_from_slice(&contribution.slot.to_le_bytes());
        ssz[16..48].copy_from_slice(&contribution.beacon_block_root);
        ssz[48..56].copy_from_slice(&contribution.subcommittee_index.to_le_bytes());
        ssz[56..72].copy_from_slice(&contribution.aggregation_bits);
        ssz[72..168].copy_from_slice(&contribution.signature);
        ssz[168..264].copy_from_slice(&message.selection_proof);
        ssz[264..SIGNED_CONTRIBUTION_AND_PROOF_SIZE].copy_from_slice(&self.signature);
    }
}

#[cfg(test)]
mod tests {
    use silver_common::{TCacheProducer, ssz_view::SignedSyncCommitteeProofView};

    use super::*;
    use crate::{
        http::router::Outcome,
        submission::tests::{SLOT, ctx},
        testing::{body, dispatch, dispatch_into, posting, status_code, submissions},
    };

    const PATH: &str = "/eth/v1/validator/contribution_and_proofs";

    fn entry(subcommittee_index: u64) -> String {
        format!(
            "{{\"message\":{{\"aggregator_index\":\"7\",\"contribution\":{{\
             \"slot\":\"{SLOT}\",\"beacon_block_root\":\"0x{}\",\
             \"subcommittee_index\":\"{subcommittee_index}\",\"aggregation_bits\":\"0x{}\",\
             \"signature\":\"0x{}\"}},\"selection_proof\":\"0x{}\"}},\"signature\":\"0x{}\"}}",
            "11".repeat(32),
            "0f".repeat(16),
            "44".repeat(96),
            "55".repeat(96),
            "66".repeat(96),
        )
    }

    #[test]
    fn accepted_contribution_encodes_as_the_gossip_message() {
        let mut submissions = submissions();
        let entries = format!("[{}]", entry(2));
        let posted = posting(PATH, &entries);
        let Outcome::AwaitingVerdicts(submission) =
            dispatch_into(&ctx(), &posted, &mut submissions).0
        else {
            panic!("the contribution defers")
        };
        let [accepted] = submission.accepted.as_slice() else { panic!("one accepted") };
        assert_eq!(accepted.topic, GossipTopic::SyncCommitteeContributionAndProof);
        let ssz = submissions.read_buffer(accepted.ssz).unwrap();
        let ssz: &[u8; SIGNED_CONTRIBUTION_AND_PROOF_SIZE] = ssz.try_into().unwrap();
        assert_eq!(SignedSyncCommitteeProofView::aggregator_index(ssz), 7);
        assert_eq!(SignedSyncCommitteeProofView::slot(ssz), SLOT);
        assert_eq!(SignedSyncCommitteeProofView::beacon_block_root(ssz), &[0x11; 32]);
        assert_eq!(SignedSyncCommitteeProofView::subcommittee_index(ssz), 2);
        assert_eq!(SignedSyncCommitteeProofView::aggregation_bits(ssz), &[0x0f; 16]);
        assert_eq!(SignedSyncCommitteeProofView::contribution_signature(ssz), &[0x44; 96]);
        assert_eq!(SignedSyncCommitteeProofView::selection_proof(ssz), &[0x55; 96]);
        assert_eq!(SignedSyncCommitteeProofView::signature(ssz), &[0x66; 96]);
    }

    #[test]
    fn subcommittee_past_the_count_fails_by_index() {
        let ctx = ctx();
        let past = SYNC_COMMITTEE_SUBNETS as u64;
        let entries = format!("[{},{}]", entry(0), entry(past));
        let Outcome::AwaitingVerdicts(submission) = dispatch(&ctx, &posting(PATH, &entries)).0
        else {
            panic!("the well-formed entry defers")
        };
        assert_eq!(submission.accepted.len(), 1);
        let failed: Vec<_> =
            submission.failures.iter().map(|f| (f.body_index, f.message)).collect();
        assert_eq!(failed, [(1, "subcommittee_index is past the sync subcommittee count")]);

        let (outcome, response) = dispatch(&ctx, &posting(PATH, &format!("[{}]", entry(past))));
        assert_eq!(outcome, Outcome::Response);
        assert_eq!(status_code(&response), "400");
        let parsed: serde_json::Value = serde_json::from_slice(body(&response)).unwrap();
        assert_eq!(parsed["failures"][0]["index"], 0);
    }
}
