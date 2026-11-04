use std::time::Instant;

use silver_beacon_state_data::{B256, BodyFork, BodyOffsets, SLOTS_PER_EPOCH, bls};
use silver_common::{
    ProducedBlock, TCacheReader, TRead,
    block_contents::SignedBlockContents,
    ssz_hash::HashedBody,
    ssz_view::{BeaconBlockBodyGloasView, ExecutionPayloadHeaderFuluView, SignedBeaconBlockView},
};
use silver_pbs::plain_http_url;

use crate::{
    ctx::ApiCtx,
    entry_signatures::signing_key,
    http::{response::Response, router::Request},
    submission::{Integration, requested_validation},
};

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
    let (signed_block, body_fork) = if SignedBeaconBlockView::check_size(body) {
        if !ctx.spec.is_gloas_at_slot(SignedBeaconBlockView::slot(body)) {
            return resp.error(400, "only Gloas blocks are published without their blobs");
        }
        if !BeaconBlockBodyGloasView::check_canonical(SignedBeaconBlockView::body(body)) {
            return resp.error(400, "invalid SignedBeaconBlock");
        }
        (body, BodyFork::Gloas)
    } else {
        let Some(contents) = SignedBlockContents::parse(body) else {
            return resp.error(400, "invalid SignedBlockContents");
        };
        if ctx.spec.is_gloas_at_slot(SignedBeaconBlockView::slot(contents.signed_block)) {
            return resp.error(400, "Gloas blocks are published without their blobs");
        }
        (contents.signed_block, BodyFork::Fulu)
    };
    let slot = SignedBeaconBlockView::slot(signed_block);
    if req.eth_consensus_version != Some(ctx.spec.fork_at_slot(slot).name()) {
        return resp.error(400, "Eth-Consensus-Version must name the block's fork");
    }
    let Ok(offsets) = BodyOffsets::validated(SignedBeaconBlockView::body(signed_block), body_fork)
    else {
        return resp.error(400, "invalid block body");
    };
    let hashed = match verify_proposer_signature(ctx, signed_block, &offsets) {
        Ok(hashed) => hashed,
        Err(message) => return resp.error(400, message),
    };

    resp.await_block(
        body,
        validation,
        Integration::import_of_block(slot, &ctx.spec, Instant::now()),
        hashed,
    );
    if let Some(url) = req.eth_builder_url.filter(|_| SignedBeaconBlockView::check_size(body)) {
        match plain_http_url(url.as_bytes()).filter(|url| url.starts_with("http://")) {
            Some(url) => resp.forward_to_builder(url),
            None => silver_log::warn!(
                url,
                "only plain http:// builder urls are served; block not forwarded"
            ),
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
    let Some(body) = body
        .ok()
        .filter(|body| ExecutionPayloadHeaderFuluView::check_canonical(body.payload_header()))
    else {
        return resp.error(400, "invalid SignedBlindedBeaconBlock");
    };
    if let Err(message) = verify_proposer_signature(ctx, block, &body) {
        return resp.error(400, message);
    }
    resp.await_blinded_block_lock(block);
}

/// The block this node last produced, pinned in the tcache for a slot.
/// Comparing a submitted body with it costs microseconds; hashing the body
/// costs about a millisecond.
#[derive(Default)]
pub(crate) struct ProducedBody(Option<HeldBlock>);

struct HeldBlock {
    block: ProducedBlock,
    header: TRead,
    payload: Option<TRead>,
    release_at: Instant,
}

impl ProducedBody {
    pub(crate) fn hold(
        &mut self,
        block: ProducedBlock,
        reader: &mut TCacheReader,
        release_at: Instant,
    ) {
        let header = reader.acquire(block.header);
        let payload = block.payload.map(|payload| reader.acquire(payload));
        self.0 = Some(HeldBlock { block, header, payload, release_at });
    }

    pub(crate) fn release_expired(&mut self, now: Instant) {
        if self.0.as_ref().is_some_and(|held| now >= held.release_at) {
            self.0 = None;
        }
    }

    fn root_of(&self, body: &[u8]) -> Option<B256> {
        let HeldBlock { block, header, payload, .. } = self.0.as_ref()?;
        let header = header.buffer().ok()?.0;
        let payload = payload.as_ref().map(TRead::buffer).transpose().ok()?;
        block.has_body(header, payload.map(|(payload, _)| payload), body).then_some(block.body_root)
    }
}

/// The hashed body, unless the body is the one this node produced.
fn verify_proposer_signature(
    ctx: &ApiCtx,
    signed_block: &[u8],
    body: &BodyOffsets<'_>,
) -> Result<Option<HashedBody>, &'static str> {
    let proposer = SignedBeaconBlockView::proposer_index(signed_block);
    let pubkey = ctx
        .read_state(|view| signing_key(&view, proposer))
        .ok_or("proposer_index is past the validator count")?;
    let epoch = SignedBeaconBlockView::slot(signed_block) / SLOTS_PER_EPOCH;
    let domain = ctx.domain(bls::DOMAIN_BEACON_PROPOSER, epoch);
    let (body_root, hashed) =
        match ctx.produced_body.root_of(SignedBeaconBlockView::body(signed_block)) {
            Some(root) => (root, None),
            None => {
                let hashed = HashedBody::of(body);
                (hashed.root, Some(hashed))
            }
        };
    if !bls::verify_block_signature(signed_block, &pubkey, &body_root, &domain) {
        return Err("invalid block signature");
    }
    Ok(hashed)
}

#[cfg(test)]
pub(crate) mod tests {
    use std::time::Duration;

    use silver_beacon_state_data::{BeaconBlockHeader, SpecConfig, hash_tree_root_block_header};
    use silver_common::{
        BroadcastValidation, GossipTopic, TCache, TCacheId, TCacheProducer, TCacheTable, TProducer,
        TReadMode,
        ssz_view::{
            BEACON_BLOCK_BODY_FIXED, BEACON_BLOCK_FIXED, BYTES_PER_BLOB, BYTES_PER_KZG_COMMITMENT,
            EXECUTION_PAYLOAD_HEADER_FIXED,
        },
        test_util::{SynthBid, SynthBlock},
    };
    use silver_httpcore::ParsedRequest;

    use super::*;
    use crate::{
        http::router::{Outcome, SSZ_MEDIA_TYPE},
        submission::tests::{SLOT, ctx, validator_signature},
        testing::{dispatch, dispatch_into, posting, status_code, submissions},
    };

    const PATH: &str = "/eth/v2/beacon/blocks";

    fn gloas_spec() -> SpecConfig {
        SpecConfig { gloas_fork_epoch: 0, ..SpecConfig::mainnet() }
    }

    fn signed_by_proposer(mut block: Vec<u8>, body_fork: BodyFork, spec: &SpecConfig) -> Vec<u8> {
        let body = SignedBeaconBlockView::body(&block);
        let header = BeaconBlockHeader {
            slot: SignedBeaconBlockView::slot(&block),
            proposer_index: SignedBeaconBlockView::proposer_index(&block),
            parent_root: *SignedBeaconBlockView::parent_root(&block),
            state_root: *SignedBeaconBlockView::state_root(&block),
            body_root: HashedBody::of(&BodyOffsets::validated(body, body_fork).unwrap()).root,
        };
        let signature = validator_signature(
            spec,
            header.proposer_index,
            bls::DOMAIN_BEACON_PROPOSER,
            header.slot / SLOTS_PER_EPOCH,
            &hash_tree_root_block_header(&header),
        );
        block[4..100].copy_from_slice(&signature);
        block
    }

    /// Contents of a block that commits to one blob.
    fn contents() -> Vec<u8> {
        let block = SynthBlock::fulu(0, &[0; BYTES_PER_KZG_COMMITMENT]).into_bytes();
        let block = signed_by_proposer(block, BodyFork::Fulu, &SpecConfig::mainnet());

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

    /// A cache holding `message`, an unsigned block, as this node's produced
    /// block with `body_root`.
    struct Production {
        reader: TCacheReader,
        block: ProducedBlock,
        _cache: TProducer,
    }

    impl Production {
        fn new(message: &[u8], body_root: B256) -> Self {
            let mut cache = TCache::producer(TCacheId::BeaconStateHandoff, 1 << 20);
            let mut reader = TCacheReader::new(TCacheTable::from_iter([cache.cache_ref()]));
            reader.open(TCacheId::BeaconStateHandoff, "test", TReadMode::Sliding).unwrap();
            let header = cache.write_with(message.len(), |out| out.copy_from_slice(message));
            cache.loop_start();
            let block = ProducedBlock {
                header: header.unwrap(),
                payload_at: message.len() as u32,
                payload: None,
                envelope_header: None,
                execution_payload_value: [0; 32],
                consensus_block_value: [0; 32],
                builder_entry: None,
                body_root,
            };
            Self { reader, block, _cache: cache }
        }

        fn held(&mut self, release_at: Instant) -> ProducedBody {
            let mut body = ProducedBody::default();
            body.hold(self.block, &mut self.reader, release_at);
            body
        }
    }

    #[test]
    fn held_block_names_its_root_until_released() {
        let block = gloas_block();
        let mut production = Production::new(&block[100..], [5; 32]);
        let now = Instant::now();
        let mut held = production.held(now + Duration::from_secs(1));

        let body = SignedBeaconBlockView::body(&block);
        assert_eq!(held.root_of(body), Some([5; 32]));
        assert_eq!(held.root_of(&body[1..]), None, "another body is hashed");
        held.release_expired(now);
        assert_eq!(held.root_of(body), Some([5; 32]));
        held.release_expired(now + Duration::from_secs(1));
        assert_eq!(held.root_of(body), None, "a released block is hashed");
    }

    /// The produced root stands in for the hash only when the bodies match,
    /// so a wrong root fails the check only then.
    #[test]
    fn produced_root_is_used_only_for_the_produced_body() {
        let body = contents();
        let block = SignedBlockContents::parse(&body).unwrap().signed_block;
        let slot = SignedBeaconBlockView::slot(block);
        let mut other = block[100..].to_vec();
        other[BEACON_BLOCK_FIXED] ^= 1;
        for (message, accepted) in [(&block[100..], false), (&other[..], true)] {
            let mut production = Production::new(message, [9; 32]);
            let mut ctx = ctx();
            ctx.produced_body = production.held(Instant::now() + Duration::from_secs(12));
            let fork = ctx.spec.fork_at_slot(slot).name();
            let mut submissions = TCache::producer(TCacheId::BoundaryProcessing, 1 << 20);
            let (outcome, _) = dispatch_into(&ctx, &publishing(&body, fork), &mut submissions);
            assert_eq!(matches!(outcome, Outcome::AwaitingVerdicts(_)), accepted, "{outcome:?}");
        }
    }

    /// A block another key signed never reaches its proposer's lock.
    #[test]
    fn block_not_signed_by_its_proposer_is_a_400() {
        let mut forged_contents = contents();
        forged_contents[12 + 4..12 + 100].copy_from_slice(&gloas_block()[4..100]);
        let mut forged_gloas = gloas_block();
        forged_gloas[4..100].copy_from_slice(&contents()[12 + 4..12 + 100]);
        for (ctx, body) in [(ctx(), forged_contents), (gloas_ctx(), forged_gloas)] {
            let block = SignedBlockContents::parse(&body).map_or(&body[..], |c| c.signed_block);
            let fork = ctx.spec.fork_at_slot(SignedBeaconBlockView::slot(block)).name();
            let (outcome, out) = dispatch(&ctx, &publishing(&body, fork));
            assert_eq!(outcome, Outcome::Response(None));
            assert_eq!(status_code(&out), "400");
        }

        let mut blinded = blinded_block();
        blinded[4..100].copy_from_slice(&gloas_block()[4..100]);
        let ctx = sidecar_ctx();
        let (outcome, out) = dispatch(&ctx, &ParsedRequest {
            body: &blinded,
            content_type: Some(SSZ_MEDIA_TYPE),
            eth_consensus_version: Some(ctx.spec.fork_at_slot(SLOT + 1).name()),
            ..posting(BLINDED_PATH, "")
        });
        assert_eq!(outcome, Outcome::Response(None));
        assert_eq!(status_code(&out), "400");
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
        ctx.spec = gloas_spec();
        ctx
    }

    pub(crate) fn gloas_block() -> Vec<u8> {
        let block = SynthBlock::gloas(SLOT + 1, SynthBid::new(&[])).into_bytes();
        signed_by_proposer(block, BodyFork::Gloas, &gloas_spec())
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
    fn only_a_plain_http_builder_url_is_forwarded() {
        let body = gloas_block();
        for (url, forwarded) in [
            ("http://b:18550/relay", true),
            ("http://b:18550/relay x", false),
            ("http://b:18550/relay\x0b", false),
            ("http://b:18550/relayé", false),
            ("http://", false),
            ("https://b:18550", false),
        ] {
            let request =
                ParsedRequest { eth_builder_url: Some(url), ..publishing(&body, "gloas") };
            let (outcome, _) = dispatch_into(&gloas_ctx(), &request, &mut submissions());
            let Outcome::AwaitingVerdicts(submission) = outcome else { panic!("{outcome:?}") };
            assert_eq!(submission.forward.is_some(), forwarded, "{url:?}");
        }
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
        signed_by_proposer(block, BodyFork::FuluBlinded, &SpecConfig::mainnet())
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
