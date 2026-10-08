use serde::Deserialize;
use silver_common::{GossipTopic, ssz_view::SIGNED_PROPOSER_PREFERENCES_SIZE};

use crate::{
    ctx::ApiCtx,
    http::{
        ids::{bytes, uint64},
        response::Response,
        router::Request,
    },
    submission::{SubmittedEntry, post_submission},
};

pub(crate) fn post_proposer_preferences(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    if req.eth_consensus_version != Some("gloas") {
        resp.error(400, "Eth-Consensus-Version must name gloas");
        return;
    }
    post_submission::<SubmittedProposerPreferences>(req, ctx, resp);
}

#[derive(Deserialize)]
struct SubmittedProposerPreferences {
    message: ProposerPreferences,
    #[serde(deserialize_with = "bytes")]
    signature: [u8; 96],
}

#[derive(Deserialize)]
struct ProposerPreferences {
    #[serde(deserialize_with = "bytes")]
    dependent_root: [u8; 32],
    #[serde(deserialize_with = "uint64")]
    proposal_slot: u64,
    #[serde(deserialize_with = "uint64")]
    validator_index: u64,
    #[serde(deserialize_with = "bytes")]
    fee_recipient: [u8; 20],
    #[serde(deserialize_with = "uint64")]
    target_gas_limit: u64,
}

impl SubmittedEntry for SubmittedProposerPreferences {
    fn accept(&self, _: &ApiCtx) -> Result<impl IntoIterator<Item = GossipTopic>, &'static str> {
        Ok([GossipTopic::ProposerPreferences])
    }

    fn ssz_len(&self) -> usize {
        SIGNED_PROPOSER_PREFERENCES_SIZE
    }

    fn encode(&self, ssz: &mut [u8]) {
        debug_assert_eq!(ssz.len(), self.ssz_len());
        let message = &self.message;
        ssz[0..32].copy_from_slice(&message.dependent_root);
        ssz[32..40].copy_from_slice(&message.proposal_slot.to_le_bytes());
        ssz[40..48].copy_from_slice(&message.validator_index.to_le_bytes());
        ssz[48..68].copy_from_slice(&message.fee_recipient);
        ssz[68..76].copy_from_slice(&message.target_gas_limit.to_le_bytes());
        ssz[76..172].copy_from_slice(&self.signature);
    }
}

#[cfg(test)]
mod tests {
    use silver_common::{
        TCacheProducer,
        ssz_view::{ProposerPreferencesView, SignedProposerPreferencesView},
    };
    use silver_httpcore::ParsedRequest;

    use super::*;
    use crate::{
        http::router::Outcome,
        submission::tests::ctx,
        testing::{dispatch, dispatch_into, posting, status_code, submissions},
    };

    const PATH: &str = "/eth/v1/validator/proposer_preferences";

    fn preferences(proposal_slot: u64) -> String {
        format!(
            "{{\"message\":{{\"dependent_root\":\"0x{}\",\"proposal_slot\":\"{proposal_slot}\",\
             \"validator_index\":\"9\",\"fee_recipient\":\"0x{}\",\
             \"target_gas_limit\":\"60000000\"}},\"signature\":\"0x{}\"}}",
            "11".repeat(32),
            "22".repeat(20),
            "44".repeat(96),
        )
    }

    fn versioned<'a>(body: &'a str, version: Option<&'a str>) -> ParsedRequest<'a> {
        ParsedRequest { eth_consensus_version: version, ..posting(PATH, body) }
    }

    #[test]
    fn accepted_preferences_carry_their_index_topic_and_ssz() {
        let ctx = ctx();
        let mut submissions = submissions();
        let body = format!("[{},{}]", preferences(40), preferences(41));
        let posted = versioned(&body, Some("gloas"));
        let Outcome::AwaitingVerdicts(submission) =
            dispatch_into(&ctx, &posted, &mut submissions).0
        else {
            panic!("the preferences defer")
        };
        let [_, second] = submission.accepted.as_slice() else { panic!("two accepted") };
        assert_eq!((second.body_index, second.topic), (1, GossipTopic::ProposerPreferences));

        let ssz: &[u8; SIGNED_PROPOSER_PREFERENCES_SIZE] =
            submissions.read_buffer(second.ssz).unwrap().try_into().unwrap();
        let message = SignedProposerPreferencesView::message(ssz);
        assert_eq!(ProposerPreferencesView::dependent_root(message), &[0x11; 32]);
        assert_eq!(ProposerPreferencesView::proposal_slot(message), 41);
        assert_eq!(ProposerPreferencesView::validator_index(message), 9);
        assert_eq!(ProposerPreferencesView::fee_recipient(message), &[0x22; 20]);
        assert_eq!(ProposerPreferencesView::target_gas_limit(message), 60_000_000);
        assert_eq!(SignedProposerPreferencesView::signature(ssz), &[0x44; 96]);
    }

    #[test]
    fn preferences_name_gloas_and_come_as_a_non_empty_array() {
        let ctx = ctx();
        let body = format!("[{}]", preferences(40));
        for version in [None, Some("fulu")] {
            let response = dispatch(&ctx, &versioned(&body, version)).1;
            assert_eq!(status_code(&response), "400", "{version:?}");
        }
        for body in ["", "[]", "{}", &preferences(40)] {
            let response = dispatch(&ctx, &versioned(body, Some("gloas"))).1;
            assert_eq!(status_code(&response), "400", "{body:?}");
        }
    }
}
