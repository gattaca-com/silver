use std::time::Instant;

use silver_beacon_state_data::{BodyFork, BodyOffsets};
use silver_common::{
    block_contents::SignedBlockContents,
    ssz_view::{BeaconBlockBodyGloasView, ExecutionPayloadHeaderFuluView, SignedBeaconBlockView},
};

use crate::{
    ctx::ApiCtx,
    http::{response::Response, router::Request},
    submission::{Integration, requested_validation},
};

const MAX_BUILDER_URL_SIZE: usize = 2048;

pub(crate) fn post_block_v2(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    if !req.body_is_ssz() {
        return resp.error(415, "only application/octet-stream bodies are read");
    }
    let Some(validation) = requested_validation(req) else {
        return resp.error(400, "invalid broadcast_validation");
    };
    let body = req.body;
    // Gloas blocks are posted bare, Fulu blocks as `SignedBlockContents`; the
    // leading offset (100 or 12) tells the two apart.
    let slot = if SignedBeaconBlockView::check_size(body) {
        let slot = SignedBeaconBlockView::slot(body);
        if !ctx.spec.is_gloas_at_slot(slot) {
            return resp.error(400, "only Gloas blocks are published without their blobs");
        }
        let block_body = SignedBeaconBlockView::body(body);
        if !BeaconBlockBodyGloasView::check_canonical(block_body) ||
            BodyOffsets::validated(block_body, BodyFork::Gloas).is_err()
        {
            return resp.error(400, "invalid SignedBeaconBlock");
        }
        slot
    } else {
        let Some(contents) = SignedBlockContents::parse(body) else {
            return resp.error(400, "invalid SignedBlockContents");
        };
        let slot = SignedBeaconBlockView::slot(contents.signed_block);
        if ctx.spec.is_gloas_at_slot(slot) {
            return resp.error(400, "Gloas blocks are published without their blobs");
        }
        slot
    };
    if req.eth_consensus_version != Some(ctx.spec.fork_at_slot(slot).name()) {
        return resp.error(400, "Eth-Consensus-Version must name the block's fork");
    }

    resp.await_block(
        body,
        validation,
        Integration::import_of_block(slot, &ctx.spec, Instant::now()),
    );
    if let Some(url) = req.eth_builder_url.filter(|_| SignedBeaconBlockView::check_size(body)) {
        if url.starts_with("http://") && url.len() <= MAX_BUILDER_URL_SIZE {
            resp.forward_to_builder(url);
        } else {
            silver_log::warn!(url, "only http:// builder urls are served; block not forwarded");
        }
    }
}

pub(crate) fn post_blinded_block_v2(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    if !ctx.has_sidecar {
        return resp.error(500, "no sidecar is configured to reveal the payload");
    }
    if !req.body_is_ssz() {
        return resp.error(415, "only application/octet-stream bodies are read");
    }
    // The relay broadcasts the revealed block, so the level is checked but
    // not applied here.
    if requested_validation(req).is_none() {
        return resp.error(400, "invalid broadcast_validation");
    }
    let block = req.body;
    if !SignedBeaconBlockView::check_size(block) {
        return resp.error(400, "invalid SignedBlindedBeaconBlock");
    }
    let slot = SignedBeaconBlockView::slot(block);
    if ctx.spec.is_gloas_at_slot(slot) {
        return resp.error(400, "only Fulu blinded blocks are published");
    }
    if req.eth_consensus_version != Some(ctx.spec.fork_at_slot(slot).name()) {
        return resp.error(400, "Eth-Consensus-Version must name the block's fork");
    }
    let body = BodyOffsets::validated(SignedBeaconBlockView::body(block), BodyFork::FuluBlinded);
    if !body
        .is_ok_and(|body| ExecutionPayloadHeaderFuluView::check_canonical(body.payload_header()))
    {
        return resp.error(400, "invalid SignedBlindedBeaconBlock");
    }
    resp.await_blinded_block_lock(block);
}

#[cfg(test)]
pub(crate) mod tests {
    use silver_common::{
        BroadcastValidation, GossipTopic, TCache, TCacheId, TCacheProducer,
        ssz_hash_gloas::EMPTY_EXECUTION_REQUESTS,
        ssz_view::{
            BEACON_BLOCK_BODY_FIXED, BYTES_PER_BLOB, BYTES_PER_KZG_COMMITMENT,
            EXECUTION_PAYLOAD_HEADER_FIXED,
        },
        test_util::{SynthBid, SynthBlock},
    };
    use silver_httpcore::ParsedRequest;

    use super::*;
    use crate::{
        http::router::{Outcome, SSZ_MEDIA_TYPE},
        submission::tests::{SLOT, ctx},
        testing::{dispatch, dispatch_into, posting, status_code, submissions},
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

    fn publishing<'a>(body: &'a [u8], fork: &'static str) -> ParsedRequest<'a> {
        ParsedRequest {
            body,
            content_type: Some(SSZ_MEDIA_TYPE),
            eth_consensus_version: Some(fork),
            ..posting(PATH, "")
        }
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
        let ctx = ctx();
        let fork = ctx.spec.fork_at_slot(0).name();
        let (outcome, out) = dispatch_into(&ctx, &publishing(&body, fork), &mut submissions);
        assert!(out.is_empty());
        let Outcome::AwaitingVerdicts(submission) = outcome else { panic!("{outcome:?}") };
        let [entry] = &submission.accepted[..] else { panic!("one entry") };
        assert_eq!(entry.topic, GossipTopic::BeaconBlock);
        assert_eq!(submissions.read_buffer(entry.ssz).unwrap(), body);
    }

    /// `BeaconClient::publish_block` in helix: Fulu contents under
    /// `consensus_and_equivocation`, naming the block's fork.
    #[test]
    fn helix_publication_carries_its_validation_level() {
        let ctx = ctx();
        let body = contents();
        let fork = ctx.spec.fork_at_slot(0).name();
        let request = |query| ParsedRequest {
            body: &body,
            query,
            content_type: Some(SSZ_MEDIA_TYPE),
            eth_consensus_version: Some(fork),
            ..posting(PATH, "")
        };
        for (query, validation) in [
            (
                "broadcast_validation=consensus_and_equivocation",
                BroadcastValidation::ConsensusAndEquivocation,
            ),
            ("broadcast_validation=consensus", BroadcastValidation::Consensus),
            ("", BroadcastValidation::Gossip),
        ] {
            let mut submissions = TCache::producer(TCacheId::BoundaryProcessing, 1 << 20);
            let (outcome, _) = dispatch_into(&ctx, &request(query), &mut submissions);
            let Outcome::AwaitingVerdicts(submission) = outcome else {
                panic!("{query}: awaits its verdict")
            };
            assert_eq!(submission.validation, validation, "{query}");
        }
    }

    #[test]
    fn unknown_level_or_a_missing_or_wrong_version_is_a_400() {
        let ctx = ctx();
        let body = contents();
        let request = publishing(&body, ctx.spec.fork_at_slot(0).name());
        for refused in [
            ParsedRequest { query: "broadcast_validation=full", ..request },
            ParsedRequest { eth_consensus_version: Some("gloas"), ..request },
            ParsedRequest { eth_consensus_version: None, ..request },
        ] {
            assert_eq!(status_code(&dispatch(&ctx, &refused).1), "400");
        }
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

    fn gloas_ctx() -> ApiCtx {
        let mut ctx = ctx();
        ctx.spec.gloas_fork_epoch = 0;
        ctx
    }

    /// The synthetic block with an empty `parent_execution_requests`, which
    /// a canonical body still frames.
    pub(crate) fn gloas_block() -> Vec<u8> {
        let mut block = SynthBlock::gloas(SLOT + 1, SynthBid::new(&[])).into_bytes();
        block.extend_from_slice(&EMPTY_EXECUTION_REQUESTS);
        block
    }

    #[test]
    fn gloas_block_is_submitted_bare_on_the_block_topic() {
        let body = gloas_block();
        let mut submissions = submissions();
        let (outcome, out) =
            dispatch_into(&gloas_ctx(), &publishing(&body, "gloas"), &mut submissions);
        assert!(out.is_empty());
        let Outcome::AwaitingVerdicts(submission) = outcome else { panic!("{outcome:?}") };
        let [entry] = &submission.accepted[..] else { panic!("one entry") };
        assert_eq!(entry.topic, GossipTopic::BeaconBlock);
        assert_eq!(submissions.read_buffer(entry.ssz).unwrap(), body);
    }

    #[test]
    fn block_framed_for_another_fork_is_a_400() {
        let mut truncated = gloas_block();
        truncated.truncate(truncated.len() - 1);
        for (ctx, body) in
            [(ctx(), gloas_block()), (gloas_ctx(), contents()), (gloas_ctx(), truncated)]
        {
            let (outcome, out) = dispatch(&ctx, &ParsedRequest {
                body: &body,
                content_type: Some(SSZ_MEDIA_TYPE),
                ..posting(PATH, "")
            });
            assert_eq!(outcome, Outcome::Response(None));
            assert_eq!(status_code(&out), "400");
        }
    }

    #[test]
    fn gloas_bid_with_out_of_range_commitments_offset_is_a_400() {
        let mut block = gloas_block();
        let at = 184 + BEACON_BLOCK_BODY_FIXED + 100 + 188;
        block[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        let (outcome, out) = dispatch(&gloas_ctx(), &publishing(&block, "gloas"));
        assert_eq!(outcome, Outcome::Response(None));
        assert_eq!(status_code(&out), "400");
    }

    const BLINDED_PATH: &str = "/eth/v2/beacon/blinded_blocks";

    /// A Fulu `SignedBlindedBeaconBlock` with no operations: the header and
    /// three empty request lists.
    pub(crate) fn blinded_block() -> Vec<u8> {
        let header_end = BEACON_BLOCK_BODY_FIXED + EXECUTION_PAYLOAD_HEADER_FIXED;
        let mut block = vec![0; 184 + header_end];
        block[..4].copy_from_slice(&100u32.to_le_bytes());
        block[100..108].copy_from_slice(&(SLOT + 1).to_le_bytes());
        block[180..184].copy_from_slice(&84u32.to_le_bytes());
        let body = &mut block[184..];
        for at in [200, 204, 208, 212, 216, 380] {
            body[at..at + 4].copy_from_slice(&(BEACON_BLOCK_BODY_FIXED as u32).to_le_bytes());
        }
        for at in [384, 388, 392] {
            body[at..at + 4].copy_from_slice(&(header_end as u32).to_le_bytes());
        }
        let header = &mut body[BEACON_BLOCK_BODY_FIXED..];
        header[436..440].copy_from_slice(&(EXECUTION_PAYLOAD_HEADER_FIXED as u32).to_le_bytes());
        block.extend_from_slice(&[12, 0, 0, 0, 12, 0, 0, 0, 12, 0, 0, 0]);
        block
    }

    fn post_blinded(ctx: &ApiCtx, body: &[u8], content_type: &str) -> (Outcome, Vec<u8>) {
        dispatch(ctx, &ParsedRequest {
            body,
            content_type: Some(content_type),
            ..posting(BLINDED_PATH, "")
        })
    }

    fn sidecar_ctx() -> ApiCtx {
        let mut ctx = ctx();
        ctx.has_sidecar = true;
        ctx
    }

    #[test]
    fn blinded_block_waits_on_its_proposal_lock() {
        let body = blinded_block();
        let ctx = sidecar_ctx();
        let fork = ctx.spec.fork_at_slot(SignedBeaconBlockView::slot(&body)).name();
        let request = ParsedRequest {
            body: &body,
            content_type: Some(SSZ_MEDIA_TYPE),
            eth_consensus_version: Some(fork),
            ..posting(BLINDED_PATH, "")
        };
        let mut submissions = submissions();
        let (outcome, out) = dispatch_into(&ctx, &request, &mut submissions);
        assert!(out.is_empty(), "answered once the sidecar has");
        let Outcome::AwaitingBlindedBlockLock { ssz } = outcome else { panic!("{outcome:?}") };
        assert_eq!(submissions.read_buffer(ssz).unwrap(), body);

        for refused in [
            ParsedRequest { query: "broadcast_validation=full", ..request },
            ParsedRequest { eth_consensus_version: Some("gloas"), ..request },
            ParsedRequest { eth_consensus_version: None, ..request },
        ] {
            assert_eq!(status_code(&dispatch(&ctx, &refused).1), "400");
        }
    }

    #[test]
    fn blinded_block_is_refused_where_it_cannot_be_revealed() {
        let mut gloas = sidecar_ctx();
        gloas.spec.gloas_fork_epoch = 0;
        let mut short_header = blinded_block();
        short_header.truncate(short_header.len() - 13);
        for (ctx, body, content_type, code) in [
            (sidecar_ctx(), blinded_block(), "application/json", "415"),
            (ctx(), blinded_block(), SSZ_MEDIA_TYPE, "500"),
            (gloas, blinded_block(), SSZ_MEDIA_TYPE, "400"),
            (sidecar_ctx(), short_header, SSZ_MEDIA_TYPE, "400"),
            (sidecar_ctx(), contents(), SSZ_MEDIA_TYPE, "400"),
        ] {
            let (outcome, out) = post_blinded(&ctx, &body, content_type);
            assert_eq!(outcome, Outcome::Response(None), "{code}");
            assert_eq!(status_code(&out), code);
        }
    }
}
