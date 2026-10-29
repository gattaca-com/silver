use serde::Deserialize;
use silver_common::{
    GossipTopic,
    json_fields::{bytes, uint64},
    ssz_view::PAYLOAD_ATTESTATION_MESSAGE_SIZE,
};

use crate::{
    ctx::ApiCtx,
    http::{response::Response, router::Request},
    submission::{SubmittedEntry, post_submission},
};

pub(crate) fn post_payload_attestation_messages(
    req: &Request<'_>,
    ctx: &ApiCtx,
    resp: &mut Response<'_>,
) {
    if !ctx.follows_chain(resp) {
        return;
    }
    if req.eth_consensus_version != Some("gloas") {
        resp.error(400, "Eth-Consensus-Version must name gloas");
        return;
    }
    post_submission::<SubmittedPayloadAttestationMessage>(req, ctx, resp);
}

#[derive(Deserialize)]
struct SubmittedPayloadAttestationMessage {
    #[serde(deserialize_with = "uint64")]
    validator_index: u64,
    data: PayloadAttestationData,
    #[serde(deserialize_with = "bytes")]
    signature: [u8; 96],
}

#[derive(Deserialize)]
struct PayloadAttestationData {
    #[serde(deserialize_with = "bytes")]
    beacon_block_root: [u8; 32],
    #[serde(deserialize_with = "uint64")]
    slot: u64,
    payload_present: bool,
    blob_data_available: bool,
}

impl SubmittedEntry for SubmittedPayloadAttestationMessage {
    fn accept(&self, _: &ApiCtx) -> Result<impl IntoIterator<Item = GossipTopic>, &'static str> {
        Ok([GossipTopic::PayloadAttestationMessage])
    }

    fn ssz_len(&self) -> usize {
        PAYLOAD_ATTESTATION_MESSAGE_SIZE
    }

    fn encode(&self, ssz: &mut [u8]) {
        debug_assert_eq!(ssz.len(), self.ssz_len());
        let data = &self.data;
        ssz[0..8].copy_from_slice(&self.validator_index.to_le_bytes());
        ssz[8..40].copy_from_slice(&data.beacon_block_root);
        ssz[40..48].copy_from_slice(&data.slot.to_le_bytes());
        ssz[48] = data.payload_present as u8;
        ssz[49] = data.blob_data_available as u8;
        ssz[50..146].copy_from_slice(&self.signature);
    }
}

#[cfg(test)]
mod tests {
    use silver_common::{
        TCacheProducer,
        ssz_view::{PayloadAttestationDataView, PayloadAttestationMessageView},
    };
    use silver_httpcore::ParsedRequest;

    use super::*;
    use crate::{
        http::router::Outcome,
        submission::tests::ctx,
        testing::{dispatch, dispatch_into, posting, status_code, submissions},
    };

    const PATH: &str = "/eth/v1/beacon/pool/payload_attestations";

    fn message(validator_index: u64) -> String {
        format!(
            "{{\"validator_index\":\"{validator_index}\",\"data\":{{\"beacon_block_root\":\"0x{}\",\
             \"slot\":\"40\",\"payload_present\":true,\"blob_data_available\":false}},\
             \"signature\":\"0x{}\"}}",
            "11".repeat(32),
            "44".repeat(96),
        )
    }

    fn versioned<'a>(body: &'a str, version: Option<&'a str>) -> ParsedRequest<'a> {
        ParsedRequest { eth_consensus_version: version, ..posting(PATH, body) }
    }

    #[test]
    fn accepted_messages_carry_their_index_topic_and_ssz() {
        let ctx = ctx();
        let mut submissions = submissions();
        let body = format!("[{},{}]", message(7), message(9));
        let posted = versioned(&body, Some("gloas"));
        let Outcome::AwaitingVerdicts(submission) =
            dispatch_into(&ctx, &posted, &mut submissions).0
        else {
            panic!("the messages defer")
        };
        let [_, second] = submission.accepted.as_slice() else { panic!("two accepted") };
        assert_eq!((second.body_index, second.topic), (1, GossipTopic::PayloadAttestationMessage));

        let ssz: &[u8; PAYLOAD_ATTESTATION_MESSAGE_SIZE] =
            submissions.read_buffer(second.ssz).unwrap().try_into().unwrap();
        assert_eq!(PayloadAttestationMessageView::validator_index(ssz), 9);
        let data = PayloadAttestationMessageView::data(ssz);
        assert_eq!(PayloadAttestationDataView::beacon_block_root(data), &[0x11; 32]);
        assert_eq!(PayloadAttestationDataView::slot(data), 40);
        assert!(PayloadAttestationDataView::payload_present(data));
        assert!(!PayloadAttestationDataView::blob_data_available(data));
        assert_eq!(PayloadAttestationMessageView::signature(ssz), &[0x44; 96]);
    }

    #[test]
    fn messages_name_gloas_and_come_as_a_non_empty_array() {
        let ctx = ctx();
        let body = format!("[{}]", message(7));
        for version in [None, Some("fulu")] {
            let response = dispatch(&ctx, &versioned(&body, version)).1;
            assert_eq!(status_code(&response), "400", "{version:?}");
        }
        for body in ["", "[]", "{}", &message(7)] {
            let response = dispatch(&ctx, &versioned(body, Some("gloas"))).1;
            assert_eq!(status_code(&response), "400", "{body:?}");
        }
    }

    #[test]
    fn an_ssz_body_is_a_415() {
        let ctx = ctx();
        let body = format!("[{}]", message(7));
        let posted = ParsedRequest {
            content_type: Some("application/octet-stream"),
            ..versioned(&body, Some("gloas"))
        };
        assert_eq!(status_code(&dispatch(&ctx, &posted).1), "415");
    }
}
