use serde::Deserialize;
use silver_beacon_state_data::SLOTS_PER_EPOCH;
use silver_common::{
    GossipTopic, compute_subnet_for_attestation,
    ssz_view::{SIGNED_BLS_CHANGE_SIZE, SIGNED_VOLUNTARY_EXIT_SIZE, SINGLE_ATT_SIZE},
};

use crate::{
    ctx::ApiCtx,
    http::{
        ids::{bytes, uint64},
        response::Response,
        router::Request,
    },
    submission::{SubmittedEntry, post_single_submission, post_submission},
    validator::attestation_data::AttestationData,
};

pub(crate) fn post_attestations(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    post_submission::<SubmittedAttestation>(req, ctx, resp);
}

#[derive(Deserialize)]
struct SubmittedAttestation {
    #[serde(deserialize_with = "uint64")]
    committee_index: u64,
    #[serde(deserialize_with = "uint64")]
    attester_index: u64,
    data: AttestationData,
    #[serde(deserialize_with = "bytes")]
    signature: [u8; 96],
}

impl SubmittedEntry for SubmittedAttestation {
    fn accept(&self, ctx: &ApiCtx) -> Result<impl IntoIterator<Item = GossipTopic>, &'static str> {
        let slot = self.data.slot;
        let committees_per_slot = ctx
            .read_state(|view| ctx.shufflings.committees_per_slot(&view, slot / SLOTS_PER_EPOCH))
            .ok_or("no committee shuffling for the attestation's epoch")?;
        if self.committee_index >= committees_per_slot {
            return Err("committee_index is past the epoch's committee count");
        }
        let subnet =
            compute_subnet_for_attestation(committees_per_slot, slot, self.committee_index);
        Ok([GossipTopic::BeaconAttestation(subnet)])
    }

    fn ssz_len(&self) -> usize {
        SINGLE_ATT_SIZE
    }

    fn encode(&self, ssz: &mut [u8]) {
        debug_assert_eq!(ssz.len(), self.ssz_len());
        ssz[0..8].copy_from_slice(&self.committee_index.to_le_bytes());
        ssz[8..16].copy_from_slice(&self.attester_index.to_le_bytes());
        self.data.encode((&mut ssz[16..144]).try_into().expect("128 bytes"));
        ssz[144..240].copy_from_slice(&self.signature);
    }
}

pub(crate) fn post_voluntary_exit(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    post_single_submission::<SubmittedVoluntaryExit>(req, ctx, resp);
}

pub(crate) fn post_bls_to_execution_changes(
    req: &Request<'_>,
    ctx: &ApiCtx,
    resp: &mut Response<'_>,
) {
    post_submission::<SubmittedBlsChange>(req, ctx, resp);
}

#[derive(Deserialize)]
struct SubmittedVoluntaryExit {
    message: VoluntaryExit,
    #[serde(deserialize_with = "bytes")]
    signature: [u8; 96],
}

#[derive(Deserialize)]
struct VoluntaryExit {
    #[serde(deserialize_with = "uint64")]
    epoch: u64,
    #[serde(deserialize_with = "uint64")]
    validator_index: u64,
}

impl SubmittedEntry for SubmittedVoluntaryExit {
    fn accept(&self, _: &ApiCtx) -> Result<impl IntoIterator<Item = GossipTopic>, &'static str> {
        Ok([GossipTopic::VoluntaryExit])
    }

    fn ssz_len(&self) -> usize {
        SIGNED_VOLUNTARY_EXIT_SIZE
    }

    fn encode(&self, ssz: &mut [u8]) {
        debug_assert_eq!(ssz.len(), self.ssz_len());
        ssz[0..8].copy_from_slice(&self.message.epoch.to_le_bytes());
        ssz[8..16].copy_from_slice(&self.message.validator_index.to_le_bytes());
        ssz[16..112].copy_from_slice(&self.signature);
    }
}

#[derive(Deserialize)]
struct SubmittedBlsChange {
    message: BlsChange,
    #[serde(deserialize_with = "bytes")]
    signature: [u8; 96],
}

#[derive(Deserialize)]
struct BlsChange {
    #[serde(deserialize_with = "uint64")]
    validator_index: u64,
    #[serde(deserialize_with = "bytes")]
    from_bls_pubkey: [u8; 48],
    #[serde(deserialize_with = "bytes")]
    to_execution_address: [u8; 20],
}

impl SubmittedEntry for SubmittedBlsChange {
    fn accept(&self, _: &ApiCtx) -> Result<impl IntoIterator<Item = GossipTopic>, &'static str> {
        Ok([GossipTopic::BlsToExecutionChange])
    }

    fn ssz_len(&self) -> usize {
        SIGNED_BLS_CHANGE_SIZE
    }

    fn encode(&self, ssz: &mut [u8]) {
        debug_assert_eq!(ssz.len(), self.ssz_len());
        ssz[0..8].copy_from_slice(&self.message.validator_index.to_le_bytes());
        ssz[8..56].copy_from_slice(&self.message.from_bls_pubkey);
        ssz[56..76].copy_from_slice(&self.message.to_execution_address);
        ssz[76..172].copy_from_slice(&self.signature);
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use silver_common::{
        TCacheProducer,
        ssz_view::{
            SignedBlsToExecutionChangeView, SignedVoluntaryExitView, SingleAttestationView,
        },
    };
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
        assert_eq!(outcome, Outcome::Response(None));
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

    const EXITS: &str = "/eth/v1/beacon/pool/voluntary_exits";
    const BLS_CHANGES: &str = "/eth/v1/beacon/pool/bls_to_execution_changes";

    fn exit_body(validator_index: u64) -> String {
        format!(
            "{{\"message\":{{\"epoch\":\"7\",\"validator_index\":\"{validator_index}\"}},\
             \"signature\":\"0x{}\"}}",
            "44".repeat(96),
        )
    }

    fn bls_change(validator_index: u64) -> String {
        format!(
            "{{\"message\":{{\"validator_index\":\"{validator_index}\",\
             \"from_bls_pubkey\":\"0x{}\",\"to_execution_address\":\"0x{}\"}},\
             \"signature\":\"0x{}\"}}",
            "55".repeat(48),
            "66".repeat(20),
            "44".repeat(96),
        )
    }

    #[test]
    fn accepted_exit_carries_its_topic_and_the_ssz() {
        let ctx = ctx();
        let mut submissions = submissions();
        let body = exit_body(3);
        let posted = posting(EXITS, &body);
        let Outcome::AwaitingVerdicts(submission) =
            dispatch_into(&ctx, &posted, &mut submissions).0
        else {
            panic!("the exit defers")
        };
        let [exit] = submission.accepted.as_slice() else { panic!("one accepted") };
        assert_eq!((exit.body_index, exit.topic), (0, GossipTopic::VoluntaryExit));

        let ssz: &[u8; SIGNED_VOLUNTARY_EXIT_SIZE] =
            submissions.read_buffer(exit.ssz).unwrap().try_into().unwrap();
        assert_eq!(SignedVoluntaryExitView::epoch(ssz), 7);
        assert_eq!(SignedVoluntaryExitView::validator_index(ssz), 3);
        assert_eq!(SignedVoluntaryExitView::signature(ssz), &[0x44; 96]);
    }

    #[test]
    fn an_exit_is_posted_as_one_object() {
        let ctx = ctx();
        for body in ["", "[]", "{}", &format!("[{}]", exit_body(3))] {
            assert_eq!(status_code(&dispatch(&ctx, &posting(EXITS, body)).1), "400", "{body:?}");
        }
    }

    #[test]
    fn accepted_bls_changes_carry_their_index_topic_and_ssz() {
        let ctx = ctx();
        let mut submissions = submissions();
        let body = format!("[{},{}]", bls_change(1), bls_change(2));
        let posted = posting(BLS_CHANGES, &body);
        let Outcome::AwaitingVerdicts(submission) =
            dispatch_into(&ctx, &posted, &mut submissions).0
        else {
            panic!("the changes defer")
        };
        let [_, second] = submission.accepted.as_slice() else { panic!("two accepted") };
        assert_eq!((second.body_index, second.topic), (1, GossipTopic::BlsToExecutionChange));

        let ssz: &[u8; SIGNED_BLS_CHANGE_SIZE] =
            submissions.read_buffer(second.ssz).unwrap().try_into().unwrap();
        assert_eq!(SignedBlsToExecutionChangeView::validator_index(ssz), 2);
        assert_eq!(SignedBlsToExecutionChangeView::from_bls_pubkey(ssz), &[0x55; 48]);
        assert_eq!(SignedBlsToExecutionChangeView::to_execution_address(ssz), &[0x66; 20]);
        assert_eq!(SignedBlsToExecutionChangeView::signature(ssz), &[0x44; 96]);
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
