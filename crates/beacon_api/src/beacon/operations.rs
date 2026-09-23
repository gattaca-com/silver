use serde::Deserialize;
use silver_beacon_state_data::SLOTS_PER_EPOCH;
use silver_common::{
    BeaconApiRequest, LocalAttestationFailure, compute_subnet_for_attestation,
    ssz_view::SINGLE_ATT_SIZE,
};

use crate::{
    ctx::ApiCtx,
    http::{
        ids::{Hex, Uint64, body_entries},
        response::Response,
        router::Request,
    },
};

pub(crate) fn post_pool_attestations(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    if !req.body_is_json() {
        resp.error(415, "only application/json bodies are read");
        return;
    }
    if !ctx.follows_chain(resp) {
        return;
    }
    let Some(submitted) = body_entries::<SubmittedAttestation>(req.body, resp) else {
        return;
    };
    if submitted.is_empty() {
        resp.error(400, "the body must name at least one attestation");
        return;
    }

    let submission = AttestationSubmission::prepare(ctx, &submitted);
    if submission.accepted.is_empty() {
        resp.indexed_failures(&submission.failures);
        return;
    }

    resp.submit_attestations(submission);
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct AcceptedAttestation {
    pub(crate) body_index: usize,
    pub(crate) subnet: u64,
    pub(crate) ssz: [u8; SINGLE_ATT_SIZE],
}

impl AcceptedAttestation {
    pub(crate) fn request(&self, request_id: u64) -> BeaconApiRequest {
        BeaconApiRequest::LocalAttestation { request_id, subnet: self.subnet, ssz: self.ssz }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct SubmissionFailure {
    pub(crate) body_index: usize,
    pub(crate) message: &'static str,
}

/// A submission is not all-or-nothing: the endpoint publishes the entries it
/// can and answers a 400 listing the failed ones by their index in the body.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct AttestationSubmission {
    pub(crate) accepted: Vec<AcceptedAttestation>,
    pub(crate) failures: Vec<SubmissionFailure>,
}

impl AttestationSubmission {
    fn prepare(ctx: &ApiCtx, submitted: &[SubmittedAttestation]) -> Self {
        let mut accepted = Vec::with_capacity(submitted.len());
        let mut failures = Vec::with_capacity(submitted.len());
        for (body_index, attestation) in submitted.iter().enumerate() {
            match attestation.accept(ctx, body_index) {
                Ok(attestation) => accepted.push(attestation),
                Err(message) => failures.push(SubmissionFailure { body_index, message }),
            }
        }
        Self { accepted, failures }
    }
}

#[derive(Deserialize)]
struct SubmittedAttestation {
    committee_index: Uint64,
    attester_index: Uint64,
    data: SubmittedData,
    signature: Hex<96>,
}

#[derive(Deserialize)]
struct SubmittedData {
    slot: Uint64,
    index: Uint64,
    beacon_block_root: Hex<32>,
    source: SubmittedCheckpoint,
    target: SubmittedCheckpoint,
}

#[derive(Deserialize)]
struct SubmittedCheckpoint {
    epoch: Uint64,
    root: Hex<32>,
}

impl SubmittedAttestation {
    fn accept(&self, ctx: &ApiCtx, body_index: usize) -> Result<AcceptedAttestation, &'static str> {
        let slot = self.data.slot.0;
        let committees_per_slot = ctx
            .shufflings
            .committees_per_slot(slot / SLOTS_PER_EPOCH)
            .ok_or("no committee shuffling for the attestation's epoch")?;
        if self.committee_index.0 >= committees_per_slot {
            return Err("committee_index is past the epoch's committee count");
        }
        Ok(AcceptedAttestation {
            body_index,
            subnet: compute_subnet_for_attestation(
                committees_per_slot,
                slot,
                self.committee_index.0,
            ),
            ssz: self.encode(),
        })
    }

    fn encode(&self) -> [u8; SINGLE_ATT_SIZE] {
        let mut ssz = [0u8; SINGLE_ATT_SIZE];
        ssz[0..8].copy_from_slice(&self.committee_index.0.to_le_bytes());
        ssz[8..16].copy_from_slice(&self.attester_index.0.to_le_bytes());
        ssz[16..24].copy_from_slice(&self.data.slot.0.to_le_bytes());
        ssz[24..32].copy_from_slice(&self.data.index.0.to_le_bytes());
        ssz[32..64].copy_from_slice(&self.data.beacon_block_root.0);
        ssz[64..72].copy_from_slice(&self.data.source.epoch.0.to_le_bytes());
        ssz[72..104].copy_from_slice(&self.data.source.root.0);
        ssz[104..112].copy_from_slice(&self.data.target.epoch.0.to_le_bytes());
        ssz[112..144].copy_from_slice(&self.data.target.root.0);
        ssz[144..240].copy_from_slice(&self.signature.0);
        ssz
    }
}

pub(crate) fn failure_message(failure: LocalAttestationFailure) -> &'static str {
    match failure {
        LocalAttestationFailure::NotSynced => "the node is not synced",
        LocalAttestationFailure::BeforeStartupFloor => "older than the node's startup floor",
        LocalAttestationFailure::TooOld => "too old to publish",
        LocalAttestationFailure::Future => "too far in the future to publish",
        LocalAttestationFailure::ConflictingAttestation => {
            "this validator already attested to another block for the slot"
        }
        LocalAttestationFailure::TimedOut => "validation did not complete in time",
        LocalAttestationFailure::Invalid => "rejected as invalid",
        LocalAttestationFailure::Unverifiable => {
            "the node does not know the attested block, its target or the committee"
        }
        LocalAttestationFailure::Internal => "the node could not publish it",
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use silver_beacon_state_data::{BeaconStateOwner, SpecConfig};
    use silver_common::{SyncUpdate, ssz_view::SingleAttestationView};
    use silver_httpcore::ParsedRequest;

    use super::*;
    use crate::{
        ctx::test_ctx,
        http::router::Outcome,
        testing::{body, dispatch, posting, status_code},
    };

    const ACTIVE: usize = 4;
    const SLOT: u64 = 300 * SLOTS_PER_EPOCH + 5;

    /// A following node with the submitted slot's shuffling posted.
    pub(crate) fn ctx() -> ApiCtx {
        let owner = BeaconStateOwner::published_empty_test(SLOT);
        let mut ctx = test_ctx(&SpecConfig::mainnet(), owner.reader());
        ctx.node_status.target = Some(SyncUpdate::Following);
        ctx.shufflings.record(SLOT / SLOTS_PER_EPOCH, &[0u8; ACTIVE * size_of::<u32>()]);
        ctx
    }

    /// How many committees the posted active set shuffles into, which bounds
    /// the committee index a submission may name.
    fn posted_committees(ctx: &ApiCtx) -> u64 {
        ctx.shufflings
            .committees_per_slot(SLOT / SLOTS_PER_EPOCH)
            .expect("the fixture posts a shuffling")
    }

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

    fn accepted(ctx: &ApiCtx, body: &str) -> Vec<AcceptedAttestation> {
        match submit(ctx, body).0 {
            Outcome::AwaitingAttestations(submission) => submission.accepted,
            outcome => panic!("{outcome:?}"),
        }
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
        let [attestation] = accepted(&ctx, &body).try_into().expect("one accepted");

        assert_eq!(attestation.body_index, 0);
        assert_eq!(
            attestation.subnet,
            compute_subnet_for_attestation(posted_committees(&ctx), SLOT, 0)
        );

        let ssz = &attestation.ssz;
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
        let Outcome::AwaitingAttestations(submission) = submit(&ctx, &body).0 else {
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
