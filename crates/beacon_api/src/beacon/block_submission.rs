use silver_common::{
    GossipTopic, block_contents::SignedBlockContents, ssz_view::SignedBeaconBlockView,
};

use crate::{
    ctx::ApiCtx,
    http::{response::Response, router::Request},
};

pub(crate) fn post_block_v2(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    if !req.body_is_ssz() {
        return resp.error(415, "only application/octet-stream bodies are read");
    }
    if !ctx.follows_chain(resp) {
        return;
    }
    let Some(contents) = SignedBlockContents::parse(req.body) else {
        return resp.error(400, "invalid SignedBlockContents");
    };
    if ctx.spec.is_gloas_at_slot(SignedBeaconBlockView::slot(contents.signed_block)) {
        return resp.error(400, "only Fulu blocks are published");
    }

    let body = req.body;
    resp.await_verdicts(0, [GossipTopic::BeaconBlock], body.len(), |out| out.copy_from_slice(body));
}

#[cfg(test)]
mod tests {
    use silver_common::{
        TCache, TCacheId, TCacheProducer,
        ssz_view::{BEACON_BLOCK_BODY_FIXED, BYTES_PER_BLOB, BYTES_PER_KZG_COMMITMENT},
    };
    use silver_httpcore::ParsedRequest;

    use super::*;
    use crate::{
        http::router::{Outcome, SSZ_MEDIA_TYPE},
        submission::tests::ctx,
        testing::{dispatch, dispatch_into, posting, status_code},
    };

    const PATH: &str = "/eth/v2/beacon/blocks";

    /// Contents of a block that commits to one blob.
    fn contents() -> Vec<u8> {
        let mut block = vec![0; 184 + BEACON_BLOCK_BODY_FIXED + BYTES_PER_KZG_COMMITMENT];
        block[..4].copy_from_slice(&100u32.to_le_bytes());
        block[180..184].copy_from_slice(&84u32.to_le_bytes());
        let body = &mut block[184..];
        for at in [200, 204, 208, 212, 216, 380, 384, 388] {
            body[at..at + 4].copy_from_slice(&(BEACON_BLOCK_BODY_FIXED as u32).to_le_bytes());
        }
        let end = (BEACON_BLOCK_BODY_FIXED + BYTES_PER_KZG_COMMITMENT) as u32;
        body[392..396].copy_from_slice(&end.to_le_bytes());

        let proofs_at = 12 + block.len();
        let blobs_at = proofs_at + 128 * 48;
        let mut out = [12, proofs_at, blobs_at].map(|at| (at as u32).to_le_bytes()).concat();
        out.extend_from_slice(&block);
        out.resize(blobs_at + BYTES_PER_BLOB, 0);
        out
    }

    fn post(body: &[u8], content_type: &str) -> (Outcome, Vec<u8>) {
        dispatch(&ctx(), &ParsedRequest {
            body,
            content_type: Some(content_type),
            ..posting(PATH, "")
        })
    }

    #[test]
    fn contents_are_submitted_whole_on_the_block_topic() {
        let body = contents();
        let mut submissions = TCache::producer(TCacheId::BoundaryProcessing, 1 << 20);
        let (outcome, out) = dispatch_into(
            &ctx(),
            &ParsedRequest { body: &body, content_type: Some(SSZ_MEDIA_TYPE), ..posting(PATH, "") },
            &mut submissions,
        );
        assert!(out.is_empty());
        let Outcome::AwaitingVerdicts(submission) = outcome else { panic!("{outcome:?}") };
        let [entry] = &submission.accepted[..] else { panic!("one entry") };
        assert_eq!(entry.topic, GossipTopic::BeaconBlock);
        assert_eq!(submissions.read_buffer(entry.ssz).unwrap(), body);
    }

    #[test]
    fn json_body_is_a_415() {
        let (outcome, out) = post(b"{}", "application/json");
        assert_eq!(outcome, Outcome::Response(None));
        assert_eq!(status_code(&out), "415");
    }

    #[test]
    fn contents_that_disagree_with_the_block_are_a_400() {
        let mut body = contents();
        body.truncate(body.len() - 1);
        let (outcome, out) = post(&body, SSZ_MEDIA_TYPE);
        assert_eq!(outcome, Outcome::Response(None));
        assert_eq!(status_code(&out), "400");
    }
}
