use serde::Deserialize;
use silver_common::{
    GossipTopic,
    ssz_view::{ATTESTATION_FIXED, MAX_VALIDATORS_PER_COMMITTEE, SIGNED_AGG_PROOF_MIN},
};

use crate::{
    ctx::ApiCtx,
    http::{
        ids::{BoundedHex, Hex, Uint64},
        response::Response,
        router::Request,
    },
    submission::{SubmittedData, SubmittedEntry, post_submission},
};

/// A bitlist over one committee: its members and the terminator.
const MAX_AGGREGATION_BITS_LEN: usize = MAX_VALIDATORS_PER_COMMITTEE / 8 + 1;

/// Past the message offset and the outer signature.
const MESSAGE_AT: usize = 4 + 96;
/// Past `aggregator_index`, the aggregate offset and `selection_proof`.
const AGGREGATE_IN_MESSAGE: usize = 8 + 4 + 96;
const _: () =
    assert!(MESSAGE_AT + AGGREGATE_IN_MESSAGE + ATTESTATION_FIXED == SIGNED_AGG_PROOF_MIN);

pub(crate) fn post_aggregate_and_proofs(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    post_submission::<SubmittedAggregate>(req, ctx, resp);
}

#[derive(Deserialize)]
struct SubmittedAggregate {
    message: SubmittedAggregateAndProof,
    signature: Hex<96>,
}

#[derive(Deserialize)]
struct SubmittedAggregateAndProof {
    aggregator_index: Uint64,
    aggregate: SubmittedAggregateAttestation,
    selection_proof: Hex<96>,
}

#[derive(Deserialize)]
struct SubmittedAggregateAttestation {
    aggregation_bits: BoundedHex<MAX_AGGREGATION_BITS_LEN>,
    data: SubmittedData,
    signature: Hex<96>,
    committee_bits: Hex<8>,
}

impl SubmittedEntry for SubmittedAggregate {
    fn accept(&self, _ctx: &ApiCtx) -> Result<GossipTopic, &'static str> {
        let aggregate = &self.message.aggregate;
        if u64::from_le_bytes(aggregate.committee_bits.0).count_ones() != 1 {
            return Err("committee_bits must name exactly one committee");
        }
        let bits = aggregate.aggregation_bits.as_bytes();
        if bits.last().is_none_or(|&last| last == 0) {
            return Err("aggregation_bits is not a bitlist over one committee");
        }
        Ok(GossipTopic::BeaconAggregateAndProof)
    }

    fn ssz_len(&self) -> usize {
        SIGNED_AGG_PROOF_MIN + self.message.aggregate.aggregation_bits.as_bytes().len()
    }

    fn encode(&self, ssz: &mut [u8]) {
        let aggregate = &self.message.aggregate;
        debug_assert_eq!(ssz.len(), self.ssz_len());
        ssz[0..4].copy_from_slice(&(MESSAGE_AT as u32).to_le_bytes());
        ssz[4..MESSAGE_AT].copy_from_slice(&self.signature.0);

        let message = &mut ssz[MESSAGE_AT..];
        message[0..8].copy_from_slice(&self.message.aggregator_index.0.to_le_bytes());
        message[8..12].copy_from_slice(&(AGGREGATE_IN_MESSAGE as u32).to_le_bytes());
        message[12..AGGREGATE_IN_MESSAGE].copy_from_slice(&self.message.selection_proof.0);

        let attestation = &mut message[AGGREGATE_IN_MESSAGE..];
        attestation[0..4].copy_from_slice(&(ATTESTATION_FIXED as u32).to_le_bytes());
        aggregate.data.encode((&mut attestation[4..132]).try_into().expect("128 bytes"));
        attestation[132..228].copy_from_slice(&aggregate.signature.0);
        attestation[228..ATTESTATION_FIXED].copy_from_slice(&aggregate.committee_bits.0);
        attestation[ATTESTATION_FIXED..].copy_from_slice(aggregate.aggregation_bits.as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use silver_beacon_state_data::ParsedAggregateAndProof;
    use silver_common::{TCacheProducer, ssz_view::SignedAggregateAndProofView};

    use super::*;
    use crate::{
        http::router::Outcome,
        submission::tests::{SLOT, ctx},
        testing::{body, dispatch, dispatch_into, posting, status_code, submissions},
    };

    /// One entry of the array a validator client posts, spelled as the
    /// schemas do.
    fn entry(aggregation_bits: &str, committee_bits: &str) -> String {
        format!(
            "{{\"message\":{{\"aggregator_index\":\"7\",\"aggregate\":{{\
             \"aggregation_bits\":\"0x{aggregation_bits}\",\
             \"data\":{{\"slot\":\"{SLOT}\",\"index\":\"0\",\
             \"beacon_block_root\":\"0x{}\",\
             \"source\":{{\"epoch\":\"298\",\"root\":\"0x{}\"}},\
             \"target\":{{\"epoch\":\"300\",\"root\":\"0x{}\"}}}},\
             \"signature\":\"0x{}\",\"committee_bits\":\"0x{committee_bits}\"}},\
             \"selection_proof\":\"0x{}\"}},\"signature\":\"0x{}\"}}",
            "11".repeat(32),
            "22".repeat(32),
            "33".repeat(32),
            "44".repeat(96),
            "55".repeat(96),
            "66".repeat(96),
        )
    }

    fn submit(ctx: &ApiCtx, body: &str) -> (Outcome, Vec<u8>) {
        dispatch(ctx, &posting("/eth/v2/validator/aggregate_and_proofs", body))
    }

    #[test]
    fn accepted_aggregate_encodes_as_the_gossip_message() {
        let entries = format!("[{}]", entry("1a05", "0400000000000000"));
        let mut submissions = submissions();
        let posted = posting("/eth/v2/validator/aggregate_and_proofs", &entries);
        let Outcome::AwaitingVerdicts(submission) =
            dispatch_into(&ctx(), &posted, &mut submissions).0
        else {
            panic!("the aggregate defers")
        };
        let [accepted] = submission.accepted.as_slice() else { panic!("one accepted") };
        assert_eq!(accepted.topic, GossipTopic::BeaconAggregateAndProof);
        let ssz = submissions.read_buffer(accepted.ssz).unwrap();
        assert_eq!(ssz.len(), SIGNED_AGG_PROOF_MIN + 2);
        let parsed = ParsedAggregateAndProof::try_from(ssz).expect("well formed");
        assert_eq!(parsed.outer_sig, &[0x66; 96]);
        assert_eq!(parsed.aggregator_index, 7);
        assert_eq!(parsed.selection_proof, &[0x55; 96]);
        assert_eq!(parsed.agg_slot, SLOT);
        assert_eq!(parsed.agg_data_index, 0);
        assert_eq!(parsed.committee_bits, 1 << 2);
        assert_eq!(parsed.agg_sig, &[0x44; 96]);
        assert_eq!(parsed.agg_data.beacon_block_root(), &[0x11; 32]);
        assert_eq!(parsed.agg_data.source_epoch(), 298);
        assert_eq!(parsed.agg_data.source_root(), &[0x22; 32]);
        assert_eq!(parsed.agg_data.target_epoch(), 300);
        assert_eq!(parsed.agg_data.target_root(), &[0x33; 32]);
        assert_eq!(parsed.aggregation_bits, &[0x1a, 0x05]);
        assert_eq!(SignedAggregateAndProofView::agg_slot(ssz), SLOT);
    }

    #[test]
    fn malformed_bitfields_fail_by_index() {
        let ctx = ctx();
        let entries = format!(
            "[{},{},{},{}]",
            entry("1a05", "0400000000000000"),
            entry("1a00", "0400000000000000"),
            entry("", "0400000000000000"),
            entry("1a05", "0600000000000000"),
        );
        let Outcome::AwaitingVerdicts(submission) = submit(&ctx, &entries).0 else {
            panic!("the well-formed entry defers")
        };
        assert_eq!(submission.accepted.len(), 1);
        assert_eq!(submission.accepted[0].body_index, 0);
        let failed: Vec<_> =
            submission.failures.iter().map(|f| (f.body_index, f.message)).collect();
        let bitlist = "aggregation_bits is not a bitlist over one committee";
        assert_eq!(failed, [
            (1, bitlist),
            (2, bitlist),
            (3, "committee_bits must name exactly one committee"),
        ]);

        let (outcome, response) = submit(&ctx, &format!("[{}]", entry("1a05", "0000000000000000")));
        assert_eq!(outcome, Outcome::Response);
        assert_eq!(status_code(&response), "400");
        let parsed: serde_json::Value = serde_json::from_slice(body(&response)).unwrap();
        assert_eq!(parsed["failures"][0]["index"], 0);
        assert_eq!(
            parsed["failures"][0]["message"],
            "committee_bits must name exactly one committee"
        );
    }

    /// A bitlist longer than any committee does not fit the fixed buffer the
    /// body is parsed into, so the body itself is malformed.
    #[test]
    fn bitlist_past_one_committee_is_a_malformed_body() {
        let too_long = "01".repeat(MAX_AGGREGATION_BITS_LEN + 1);
        let (outcome, response) =
            submit(&ctx(), &format!("[{}]", entry(&too_long, "0400000000000000")));
        assert_eq!(outcome, Outcome::Response);
        assert_eq!(status_code(&response), "400");
    }
}
