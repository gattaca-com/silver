use flux_profiler::timed;
use silver_beacon_state_data::{Slot, SpecConfig};
use silver_common::{
    BeaconApiRequest, BidPolicy, PayloadFrame, ProduceBlockFailure, ProducedBlock, TCacheReader,
};

use crate::{
    ctx::ApiCtx,
    http::{
        ids::{parse_hex, parse_uint64},
        response::Response,
        router::{Outcome, Request, SSZ_MEDIA_TYPE},
    },
};

pub(crate) fn produce_block_v3(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    if !ctx.follows_chain(resp) {
        return;
    }
    let Some(slot) = proposal_slot(req, resp) else {
        return;
    };
    if ctx.spec.is_gloas_at_slot(slot) {
        return resp.error(400, "produceBlockV3 serves forks through Fulu; use produceBlockV4");
    }
    let Some((randao_reveal, graffiti)) = proposal_query(req, resp) else {
        return;
    };
    let bid_policy = BidPolicy::default();
    resp.defer(Outcome::AwaitingProducedBlock(ProduceBlockRequest {
        slot,
        randao_reveal,
        graffiti,
        bid_policy,
    }));
}

/// The block commits to a p2p bid; the local payload is not built yet, so
/// `include_payload` changes nothing.
pub(crate) fn produce_block_v4(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    if !ctx.follows_chain(resp) {
        return;
    }
    let Some(slot) = proposal_slot(req, resp) else {
        return;
    };
    if !ctx.spec.is_gloas_at_slot(slot) {
        return resp.error(400, "produceBlockV4 serves Gloas onward; use produceBlockV3");
    }
    if req.eth_consensus_version != Some(ctx.spec.fork_at_slot(slot).name()) {
        return resp.error(400, "Eth-Consensus-Version must name the slot's fork");
    }
    if !matches!(req.query_value("include_payload").as_deref(), Some("true" | "false")) {
        return resp.error(400, "include_payload is a required boolean query parameter");
    }
    let Some((randao_reveal, graffiti)) = proposal_query(req, resp) else {
        return;
    };
    if !req.body_is_ssz() {
        return resp.error(415, "only an SSZ BuilderConfig body is read");
    }
    let Some(bid_policy) = builder_config_bid_policy(req.body) else {
        return resp.error(400, "invalid BuilderConfig");
    };
    resp.defer(Outcome::AwaitingProducedBlock(ProduceBlockRequest {
        slot,
        randao_reveal,
        graffiti,
        bid_policy,
    }));
}

fn proposal_slot(req: &Request<'_>, resp: &mut Response<'_>) -> Option<Slot> {
    if !req.accepts_ssz() {
        resp.error(406, "only application/octet-stream is served");
        return None;
    }
    let slot = req.params.get("slot").expect("{slot} in the route pattern");
    let slot = parse_uint64(slot);
    if slot.is_none() {
        resp.error(400, "invalid slot");
    }
    slot
}

fn proposal_query(req: &Request<'_>, resp: &mut Response<'_>) -> Option<([u8; 96], [u8; 32])> {
    let Some(randao_reveal) = req.query_value("randao_reveal").and_then(|text| parse_hex(&text))
    else {
        resp.error(400, "randao_reveal is a required BLSSignature query parameter");
        return None;
    };
    let graffiti = match req.query_value("graffiti") {
        None => [0; 32],
        Some(text) => match parse_graffiti(&text) {
            Some(graffiti) => graffiti,
            None => {
                resp.error(400, "invalid graffiti");
                return None;
            }
        },
    };
    Some((randao_reveal, graffiti))
}

/// `min_bid` and `builder_boost_factor`, then the offset of `builders`.
const BUILDER_CONFIG_FIXED: usize = 8 + 8 + 4;
const MAX_BUILDER_ENTRIES: usize = 64;

/// The p2p terms of an SSZ `BuilderConfig`, or `None` when it does not decode.
fn builder_config_bid_policy(body: &[u8]) -> Option<BidPolicy> {
    let fixed = body.get(..BUILDER_CONFIG_FIXED)?;
    let u64_at = |at: usize| u64::from_le_bytes(fixed[at..at + 8].try_into().expect("8 bytes"));
    let builders_at = u32::from_le_bytes(fixed[16..20].try_into().expect("4 bytes")) as usize;
    if builders_at != BUILDER_CONFIG_FIXED {
        return None;
    }
    // TODO: request bids from `builders` over the builder API. Until then the
    // list is only checked to be framed, so a body that does not decode is
    // still refused.
    if !variable_list_is_framed(&body[BUILDER_CONFIG_FIXED..], MAX_BUILDER_ENTRIES) {
        return None;
    }
    Some(BidPolicy { min_bid: u64_at(0), builder_boost_factor: u64_at(8) })
}

/// An SSZ list of variable-size elements: an offset per element, each in
/// bounds and none before the last.
fn variable_list_is_framed(list: &[u8], max: usize) -> bool {
    if list.is_empty() {
        return true;
    }
    let offset_at = |at: usize| {
        list.get(at..at + 4).map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()) as usize)
    };
    let Some(first) = offset_at(0) else { return false };
    if first == 0 || !first.is_multiple_of(4) || first > list.len() || first / 4 > max {
        return false;
    }
    let mut previous = first;
    (1..first / 4).all(|i| {
        let offset = offset_at(i * 4).expect("inside the offset table");
        let ordered = previous <= offset && offset <= list.len();
        previous = offset;
        ordered
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProduceBlockRequest {
    slot: Slot,
    randao_reveal: [u8; 96],
    graffiti: [u8; 32],
    bid_policy: BidPolicy,
}

impl ProduceBlockRequest {
    pub(crate) fn state_request(self, request_id: u64) -> BeaconApiRequest {
        BeaconApiRequest::ProduceBlock {
            request_id,
            slot: self.slot,
            randao_reveal: self.randao_reveal,
            graffiti: self.graffiti,
            bid_policy: self.bid_policy,
        }
    }

    #[timed]
    pub(crate) fn respond(
        self,
        resp: &mut Response<'_>,
        block: Result<ProducedBlock, ProduceBlockFailure>,
        reader: &mut TCacheReader,
        spec: &SpecConfig,
    ) {
        let block = match block {
            Ok(block) => block,
            Err(ProduceBlockFailure::SlotNotProposable) => {
                return resp.error(400, "the slot does not follow the head");
            }
            Err(ProduceBlockFailure::InvalidRandaoReveal) => {
                return resp.error(400, "randao_reveal is not the proposer's signature");
            }
            Err(ProduceBlockFailure::NoFeeRecipient) => {
                return resp.error(400, "no fee recipient was prepared for the slot's proposer");
            }
            Err(ProduceBlockFailure::PayloadUnavailable) => {
                return resp.error(503, "the execution client built no payload");
            }
            Err(ProduceBlockFailure::NoAcceptableBid) => {
                return resp.error(503, "no p2p bid qualifies and self-building is not supported");
            }
            Err(ProduceBlockFailure::Invalid | ProduceBlockFailure::Internal) => {
                return resp.error(500, "the block could not be produced");
            }
        };
        let Some(payload) = block.payload else {
            return self.respond_without_payload(resp, &block, reader, spec);
        };
        let header = reader.acquire(block.header);
        let payload = reader.acquire(payload);
        let (Ok((head, _)), Ok((payload, _))) = (header.buffer(), payload.buffer()) else {
            silver_log::warn!(slot = self.slot, "produced block unavailable");
            return resp.error(500, "the block could not be read");
        };
        let Some(payload) = PayloadFrame::parse(payload) else {
            silver_log::error!(slot = self.slot, "produced block's payload frame is misframed");
            return resp.error(500, "the block could not be read");
        };
        let Some((before_payload, bls_changes)) = head.split_at_checked(block.payload_at as usize)
        else {
            silver_log::error!(
                slot = self.slot,
                "produced block is shorter than its payload offset"
            );
            return resp.error(500, "the block could not be read");
        };
        let payload_value = wei_decimal(&block.execution_payload_value);
        let block_value = wei_decimal(&block.consensus_block_value);
        let headers = [
            ("Eth-Consensus-Version", spec.fork_at_slot(self.slot).name()),
            ("Eth-Execution-Payload-Blinded", "false"),
            ("Eth-Execution-Payload-Value", payload_value.as_str()),
            ("Eth-Consensus-Block-Value", block_value.as_str()),
        ];
        let parts = [before_payload, payload.execution_payload, bls_changes, payload.after_payload];
        resp.send(200, Some(SSZ_MEDIA_TYPE), &headers, &parts);
    }
}

impl ProduceBlockRequest {
    /// A Gloas `BeaconBlock`: the bid commits to the payload, which is not
    /// included.
    fn respond_without_payload(
        self,
        resp: &mut Response<'_>,
        block: &ProducedBlock,
        reader: &mut TCacheReader,
        spec: &SpecConfig,
    ) {
        let acquired = reader.acquire(block.header);
        let Ok((beacon_block, _)) = acquired.buffer() else {
            silver_log::warn!(slot = self.slot, "produced block unavailable");
            return resp.error(500, "the block could not be read");
        };
        let payload_value = wei_decimal(&block.execution_payload_value);
        let block_value = wei_decimal(&block.consensus_block_value);
        let headers = [
            ("Eth-Consensus-Version", spec.fork_at_slot(self.slot).name()),
            ("Eth-Execution-Payload-Included", "false"),
            ("Eth-Execution-Payload-Value", payload_value.as_str()),
            ("Eth-Consensus-Block-Value", block_value.as_str()),
        ];
        resp.send(200, Some(SSZ_MEDIA_TYPE), &headers, &[beacon_block]);
    }
}

/// Prysm sends graffiti from proposer settings unpadded; the block carries
/// it zero-padded on the right.
fn parse_graffiti(text: &str) -> Option<[u8; 32]> {
    let hex = text.strip_prefix("0x")?;
    let mut graffiti = [0; 32];
    hex::decode_to_slice(hex, graffiti.get_mut(..hex.len() / 2)?).ok()?;
    Some(graffiti)
}

fn wei_decimal(little_endian: &[u8; 32]) -> String {
    let mut limbs = [0u64; 4];
    for (limb, bytes) in limbs.iter_mut().zip(little_endian.chunks_exact(8)) {
        *limb = u64::from_le_bytes(bytes.try_into().expect("8 bytes"));
    }
    let mut digits = Vec::new();
    loop {
        let mut remainder = 0u128;
        for limb in limbs.iter_mut().rev() {
            let current = (remainder << 64) | u128::from(*limb);
            *limb = (current / 10) as u64;
            remainder = current % 10;
        }
        digits.push(b'0' + remainder as u8);
        if limbs == [0; 4] {
            break;
        }
    }
    digits.reverse();
    String::from_utf8(digits).expect("ascii digits")
}

#[cfg(test)]
mod tests {
    use silver_httpcore::ParsedRequest;

    use super::*;
    use crate::{
        http::router::Outcome,
        submission::tests::{SLOT, ctx},
        testing::{dispatch, request, status_code},
    };

    fn get(query: &str, accept: Option<&str>) -> (Outcome, Vec<u8>) {
        let path = format!("/eth/v3/validator/blocks/{}", SLOT + 1);
        dispatch(&ctx(), &ParsedRequest { query, accept, ..request("GET", &path) })
    }

    fn randao() -> String {
        format!("randao_reveal=0x{}", "11".repeat(96))
    }

    #[test]
    fn request_defers_to_the_state_tile_with_the_query() {
        let query = format!("{}&graffiti=0x{}", randao(), "22".repeat(32));
        let (outcome, out) = get(&query, Some(SSZ_MEDIA_TYPE));
        assert!(out.is_empty());
        assert_eq!(
            outcome,
            Outcome::AwaitingProducedBlock(ProduceBlockRequest {
                slot: SLOT + 1,
                randao_reveal: [0x11; 96],
                graffiti: [0x22; 32],
                bid_policy: BidPolicy::default(),
            })
        );
    }

    #[test]
    fn graffiti_defaults_to_zero() {
        let (outcome, _) = get(&randao(), Some(SSZ_MEDIA_TYPE));
        let Outcome::AwaitingProducedBlock(request) = outcome else { panic!("{outcome:?}") };
        assert_eq!(request.graffiti, [0; 32]);
    }

    #[test]
    fn json_only_client_is_a_406() {
        let (outcome, out) = get(&randao(), Some("application/json"));
        assert_eq!(outcome, Outcome::Response(None));
        assert_eq!(status_code(&out), "406");
    }

    #[test]
    fn short_graffiti_is_zero_padded() {
        let (outcome, _) = get(&format!("{}&graffiti=0x6869", randao()), Some(SSZ_MEDIA_TYPE));
        let Outcome::AwaitingProducedBlock(request) = outcome else { panic!("{outcome:?}") };
        let mut expected = [0; 32];
        expected[..2].copy_from_slice(b"hi");
        assert_eq!(request.graffiti, expected);
    }

    #[test]
    fn missing_or_malformed_parameters_are_400() {
        for query in [
            String::new(),
            "randao_reveal=0x11".to_owned(),
            format!("{}&graffiti=0x222", randao()),
            format!("{}&graffiti=0x{}", randao(), "22".repeat(33)),
        ] {
            let (outcome, out) = get(&query, Some(SSZ_MEDIA_TYPE));
            assert_eq!(outcome, Outcome::Response(None), "{query}");
            assert_eq!(status_code(&out), "400", "{query}");
        }
    }

    /// A Gloas node: the submission fixture's slot, with Gloas active.
    fn gloas_ctx() -> ApiCtx {
        let mut ctx = ctx();
        ctx.spec.gloas_fork_epoch = 0;
        ctx
    }

    fn builder_config(min_bid: u64, boost: u64, builders: &[u8]) -> Vec<u8> {
        let mut ssz = min_bid.to_le_bytes().to_vec();
        ssz.extend_from_slice(&boost.to_le_bytes());
        ssz.extend_from_slice(&(BUILDER_CONFIG_FIXED as u32).to_le_bytes());
        ssz.extend_from_slice(builders);
        ssz
    }

    fn post_v4(
        ctx: &ApiCtx,
        query: &str,
        version: Option<&str>,
        content_type: Option<&str>,
        body: &[u8],
    ) -> (Outcome, Vec<u8>) {
        let path = format!("/eth/v4/validator/blocks/{}", SLOT + 1);
        let req = ParsedRequest {
            query,
            accept: Some(SSZ_MEDIA_TYPE),
            content_type,
            eth_consensus_version: version,
            body,
            ..request("POST", &path)
        };
        dispatch(ctx, &req)
    }

    fn v4_query() -> String {
        format!("{}&include_payload=false", randao())
    }

    #[test]
    fn v4_defers_with_the_p2p_terms_of_the_builder_config() {
        // Two entries' worth of offsets and opaque bytes: framed, then ignored.
        let builders = [8u32.to_le_bytes(), 10u32.to_le_bytes()].concat();
        let body = builder_config(7, 150, &[builders.as_slice(), &[0xAB; 4]].concat());
        let ctx = gloas_ctx();
        let (outcome, _) = post_v4(&ctx, &v4_query(), Some("gloas"), Some(SSZ_MEDIA_TYPE), &body);
        let Outcome::AwaitingProducedBlock(request) = outcome else { panic!("{outcome:?}") };
        assert_eq!(request.bid_policy, BidPolicy { min_bid: 7, builder_boost_factor: 150 });
        assert_eq!(request.slot, SLOT + 1);
    }

    #[test]
    fn v4_refuses_what_it_cannot_read() {
        let ctx = gloas_ctx();
        let ssz = Some(SSZ_MEDIA_TYPE);
        let body = builder_config(0, 100, &[]);
        let short = &body[..BUILDER_CONFIG_FIXED - 1];
        let misplaced = [&body[..16], &21u32.to_le_bytes()].concat();
        let unordered = builder_config(0, 100, &[8u32.to_le_bytes(), 4u32.to_le_bytes()].concat());
        let cases: [(&str, Option<&str>, Option<&str>, &[u8], &str); 8] = [
            (&v4_query(), Some("gloas"), ssz, short, "400"),
            (&v4_query(), Some("gloas"), ssz, &misplaced, "400"),
            (&v4_query(), Some("gloas"), ssz, &unordered, "400"),
            (&v4_query(), Some("gloas"), Some("application/json"), &body, "415"),
            (&v4_query(), None, ssz, &body, "400"),
            (&v4_query(), Some("fulu"), ssz, &body, "400"),
            (&randao(), Some("gloas"), ssz, &body, "400"),
            (&format!("{}&include_payload=yes", randao()), Some("gloas"), ssz, &body, "400"),
        ];
        for (query, version, content_type, body, code) in cases {
            let (outcome, out) = post_v4(&ctx, query, version, content_type, body);
            assert_eq!(outcome, Outcome::Response(None), "{query} {version:?} {content_type:?}");
            assert_eq!(status_code(&out), code, "{query} {version:?} {content_type:?}");
        }
    }

    #[test]
    fn each_version_serves_only_its_forks() {
        let body = builder_config(0, 100, &[]);
        let (_, out) = post_v4(&ctx(), &v4_query(), Some("fulu"), Some(SSZ_MEDIA_TYPE), &body);
        assert_eq!(status_code(&out), "400", "v4 before Gloas");

        let path = format!("/eth/v3/validator/blocks/{}", SLOT + 1);
        let req = ParsedRequest {
            query: &randao(),
            accept: Some(SSZ_MEDIA_TYPE),
            ..request("GET", &path)
        };
        assert_eq!(status_code(&dispatch(&gloas_ctx(), &req).1), "400", "v3 at Gloas");
    }

    #[test]
    fn wei_decimal_renders_every_limb() {
        assert_eq!(wei_decimal(&[0; 32]), "0");
        let mut two_ether = [0; 32];
        two_ether[..8].copy_from_slice(&2_000_000_000_000_000_000u64.to_le_bytes());
        assert_eq!(wei_decimal(&two_ether), "2000000000000000000");
        let mut two_to_64 = [0; 32];
        two_to_64[8] = 1;
        assert_eq!(wei_decimal(&two_to_64), "18446744073709551616");
    }
}
