use serde::Deserialize;
use silver_beacon_state_data::SLOTS_PER_EPOCH;
use silver_common::{GossipTopic, compute_subnet_for_attestation, ssz_view::SINGLE_ATT_SIZE};

use crate::{
    ctx::ApiCtx,
    http::{
        ids::{Hex, Uint64},
        response::Response,
        router::Request,
    },
    submission::{SubmittedData, SubmittedEntry, post_submission},
};

pub(crate) fn post_attestations(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    post_submission::<SubmittedAttestation>(req, ctx, resp);
}

#[derive(Deserialize)]
struct SubmittedAttestation {
    committee_index: Uint64,
    attester_index: Uint64,
    data: SubmittedData,
    signature: Hex<96>,
}

impl SubmittedEntry for SubmittedAttestation {
    fn accept(&self, ctx: &ApiCtx) -> Result<GossipTopic, &'static str> {
        let slot = self.data.slot.0;
        let committees_per_slot = ctx
            .shufflings
            .committees_per_slot(slot / SLOTS_PER_EPOCH)
            .ok_or("no committee shuffling for the attestation's epoch")?;
        if self.committee_index.0 >= committees_per_slot {
            return Err("committee_index is past the epoch's committee count");
        }
        let subnet =
            compute_subnet_for_attestation(committees_per_slot, slot, self.committee_index.0);
        Ok(GossipTopic::BeaconAttestation(subnet))
    }

    fn ssz_len(&self) -> usize {
        SINGLE_ATT_SIZE
    }

    fn encode(&self, ssz: &mut [u8]) {
        debug_assert_eq!(ssz.len(), self.ssz_len());
        ssz[0..8].copy_from_slice(&self.committee_index.0.to_le_bytes());
        ssz[8..16].copy_from_slice(&self.attester_index.0.to_le_bytes());
        self.data.encode((&mut ssz[16..144]).try_into().expect("128 bytes"));
        ssz[144..240].copy_from_slice(&self.signature.0);
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use silver_common::{TCacheProducer, ssz_view::SingleAttestationView};
    use silver_httpcore::ParsedRequest;

    use super::*;
    use crate::{
        http::router::Outcome,
        submission::{
            SubmissionFailure,
            tests::{SLOT, ctx, posted_committees},
        },
        testing::{body, dispatch, dispatch_into, posting, status_code, submissions},
    };

    /// One entry of the array a validator client posts, spelled as the
    /// schemas do.
    pub(crate) fn entry(attester_index: u64, committee_index: u64) -> String {
        format!(
            "{{\"committee_index\":\"{committee_index}\",\"attester_index\":\"{attester_index}\",\
             \"data\":{{\"slot\":\"{SLOT}\",\"index\":\"0\",\
             \"beacon_block_root\":\"0x{}\",\
             \"source\":{{\"epoch\":\"298\",\"root\":\"0x{}\"}},\
             \"target\":{{\"epoch\":\"300\",\"root\":\"0x{}\"}}}},\
             \"signature\":\"0x{}\"}}",
            "11".repeat(32),
            "22".repeat(32),
            "33".repeat(32),
            "44".repeat(96),
        )
    }

    fn submit(ctx: &ApiCtx, body: &str) -> (Outcome, Vec<u8>) {
        dispatch(ctx, &posting("/eth/v2/beacon/pool/attestations", body))
    }

    fn json_failures(response: &[u8]) -> Vec<serde_json::Value> {
        assert_eq!(status_code(response), "400");
        let parsed: serde_json::Value = serde_json::from_slice(body(response)).unwrap();
        parsed["failures"].as_array().unwrap().clone()
    }

    #[test]
    fn accepted_attestation_carries_its_subnet_and_the_ssz() {
        let ctx = ctx();
        let body = format!("[{}]", entry(2, 0));
        let mut submissions = submissions();
        let posted = posting("/eth/v2/beacon/pool/attestations", &body);
        let Outcome::AwaitingVerdicts(submission) =
            dispatch_into(&ctx, &posted, &mut submissions).0
        else {
            panic!("the attestation defers")
        };
        let [attestation] = submission.accepted.as_slice() else { panic!("one accepted") };

        assert_eq!(attestation.body_index, 0);
        let subnet = compute_subnet_for_attestation(posted_committees(&ctx), SLOT, 0);
        assert_eq!(attestation.topic, GossipTopic::BeaconAttestation(subnet));

        let ssz: &[u8; SINGLE_ATT_SIZE] =
            submissions.read_buffer(attestation.ssz).unwrap().try_into().unwrap();
        assert_eq!(SingleAttestationView::committee_index(ssz), 0);
        assert_eq!(SingleAttestationView::attester_index(ssz), 2);
        assert_eq!(SingleAttestationView::slot(ssz), SLOT);
        assert_eq!(SingleAttestationView::data_index(ssz), 0);
        assert_eq!(SingleAttestationView::beacon_block_root(ssz), &[0x11; 32]);
        assert_eq!(SingleAttestationView::source_epoch(ssz), 298);
        assert_eq!(SingleAttestationView::source_root(ssz), &[0x22; 32]);
        assert_eq!(SingleAttestationView::target_epoch(ssz), 300);
        assert_eq!(SingleAttestationView::target_root(ssz), &[0x33; 32]);
        assert_eq!(SingleAttestationView::signature(ssz), &[0x44; 96]);
    }

    /// Entries the posted shuffling cannot place are reported by their place
    /// in the body, and the rest of the submission still goes out.
    #[test]
    fn unresolvable_entries_fail_by_index_while_the_others_are_published() {
        let ctx = ctx();
        let past_the_count = posted_committees(&ctx);
        let body =
            format!("[{},{},{}]", entry(1, past_the_count), entry(1, 0), entry(2, past_the_count),);
        let Outcome::AwaitingVerdicts(submission) = submit(&ctx, &body).0 else {
            panic!("the resolvable entry defers")
        };
        assert_eq!(submission.accepted.len(), 1);
        assert_eq!(submission.accepted[0].body_index, 1);
        let message = "committee_index is past the epoch's committee count";
        assert_eq!(submission.failures, [
            SubmissionFailure { body_index: 0, message },
            SubmissionFailure { body_index: 2, message },
        ]);
    }

    /// With nothing left to publish the 400 is written straight away, naming
    /// every entry and why it failed.
    #[test]
    fn submission_that_resolves_nothing_is_an_indexed_400() {
        let ctx = ctx();
        let body = format!("[{}]", entry(1, posted_committees(&ctx)));
        let (outcome, response) = submit(&ctx, &body);
        assert_eq!(outcome, Outcome::Response);
        assert_eq!(status_code(&response), "400");

        let failures = json_failures(&response);
        assert_eq!(failures[0]["index"], 0);
        assert_eq!(failures[0]["message"], "committee_index is past the epoch's committee count");
    }

    #[test]
    fn attestations_for_an_unposted_epoch_fail_by_index() {
        let mut ctx = ctx();
        ctx.shufflings = Default::default();
        let response = submit(&ctx, &format!("[{}]", entry(1, 0))).1;
        let failures = json_failures(&response);
        assert_eq!(failures[0]["message"], "no committee shuffling for the attestation's epoch");
    }

    #[test]
    fn malformed_empty_and_non_json_bodies_are_rejected() {
        let ctx = ctx();
        for body in ["", "{}", "[]", "[0]", &entry(1, 0)] {
            assert_eq!(status_code(&submit(&ctx, body).1), "400", "{body:?}");
        }

        let ssz_body = ParsedRequest {
            content_type: Some("application/octet-stream"),
            ..posting("/eth/v2/beacon/pool/attestations", "")
        };
        assert_eq!(status_code(&dispatch(&ctx, &ssz_body).1), "415");
    }
}
