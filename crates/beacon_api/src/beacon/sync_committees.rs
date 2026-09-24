use serde::Deserialize;
use silver_beacon_state_data::SyncSubcommittee;
use silver_common::{GossipTopic, SYNC_COMMITTEE_SUBNETS, ssz_view::SYNC_COMMITTEE_MSG_SIZE};

use crate::{
    ctx::ApiCtx,
    http::{
        ids::{bytes, uint64},
        response::Response,
        router::Request,
    },
    submission::{SubmittedEntry, post_submission},
};

pub(crate) fn post_sync_committee_messages(
    req: &Request<'_>,
    ctx: &ApiCtx,
    resp: &mut Response<'_>,
) {
    post_submission::<SubmittedSyncCommitteeMessage>(req, ctx, resp);
}

#[derive(Deserialize)]
struct SubmittedSyncCommitteeMessage {
    #[serde(deserialize_with = "uint64")]
    slot: u64,
    #[serde(deserialize_with = "bytes")]
    beacon_block_root: [u8; 32],
    #[serde(deserialize_with = "uint64")]
    validator_index: u64,
    #[serde(deserialize_with = "bytes")]
    signature: [u8; 96],
}

impl SubmittedEntry for SubmittedSyncCommitteeMessage {
    fn accept(&self, ctx: &ApiCtx) -> Result<impl IntoIterator<Item = GossipTopic>, &'static str> {
        let subnets = ctx.read_state(|view| {
            usize::try_from(self.validator_index)
                .map_or(0, |validator| SyncSubcommittee::subnets_of(&view, validator))
        });
        if subnets == 0 {
            return Err("the validator holds no seat in the sync committee");
        }
        Ok((0..SYNC_COMMITTEE_SUBNETS as u64)
            .filter(move |subnet| subnets >> subnet & 1 == 1)
            .map(GossipTopic::SyncCommittee))
    }

    fn ssz_len(&self) -> usize {
        SYNC_COMMITTEE_MSG_SIZE
    }

    fn encode(&self, ssz: &mut [u8]) {
        debug_assert_eq!(ssz.len(), self.ssz_len());
        ssz[0..8].copy_from_slice(&self.slot.to_le_bytes());
        ssz[8..40].copy_from_slice(&self.beacon_block_root);
        ssz[40..48].copy_from_slice(&self.validator_index.to_le_bytes());
        ssz[48..144].copy_from_slice(&self.signature);
    }
}

#[cfg(test)]
mod tests {
    use silver_common::{TCacheProducer, ssz_view::SyncCommitteeView};

    use super::*;
    use crate::{
        http::router::Outcome,
        testing::{dispatch, dispatch_into, posting, status_code, submissions},
        validator::sync_duties::tests::ctx,
    };

    const PATH: &str = "/eth/v1/beacon/pool/sync_committees";

    fn entry(validator_index: u64) -> String {
        format!(
            "[{{\"slot\":\"7\",\"beacon_block_root\":\"0x{}\",\
             \"validator_index\":\"{validator_index}\",\"signature\":\"0x{}\"}}]",
            "11".repeat(32),
            "22".repeat(96),
        )
    }

    #[test]
    fn message_is_encoded_once_and_published_on_every_subnet_the_validator_sits_in() {
        let mut submissions = submissions();
        let Outcome::AwaitingVerdicts(submission) =
            dispatch_into(&ctx(), &posting(PATH, &entry(0)), &mut submissions).0
        else {
            panic!("the seated validator's message defers")
        };
        let topics = submission.accepted.iter().map(|accepted| accepted.topic);
        assert!(topics.eq((0..4).map(GossipTopic::SyncCommittee)));
        assert!(submission.accepted.iter().all(|accepted| accepted.body_index == 0));
        assert!(
            submission.accepted.iter().all(|accepted| accepted.ssz == submission.accepted[0].ssz)
        );

        let ssz = submissions.read_buffer(submission.accepted[0].ssz).unwrap().try_into().unwrap();
        assert_eq!(SyncCommitteeView::slot(ssz), 7);
        assert_eq!(SyncCommitteeView::beacon_block_root(ssz), &[0x11; 32]);
        assert_eq!(SyncCommitteeView::validator_index(ssz), 0);
        assert_eq!(SyncCommitteeView::signature(ssz), &[0x22; 96]);
    }

    #[test]
    fn validator_outside_the_committee_fails_by_index() {
        let response = dispatch(&ctx(), &posting(PATH, &entry(5))).1;
        assert_eq!(status_code(&response), "400");
    }
}
