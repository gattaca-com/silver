use std::slice;

use silver_beacon_state_data::{B256, BeaconBlockHeader, BeaconStateReader, EpochState};
use silver_common::{
    BeaconApiRequest, BlockLookup, ServedBlock, TCacheReader, body_root_at,
    json_fields::parse_uint64,
    ssz_view::{
        BeaconBlockBodyFuluView, SignedBeaconBlockView, SignedExecutionPayloadEnvelopeView,
    },
};

use crate::{
    ctx::ApiCtx,
    http::{
        ids::parse_root,
        json::{Json, ReadFlags, SignedHeader},
        response::Response,
        router::{Outcome, Request, SSZ_MEDIA_TYPE},
    },
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Ssz,
    Root,
    Header,
    HeaderList,
    Envelope,
    Attestations,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BlockRequest {
    pub(crate) lookup: BlockLookup,
    pub(crate) kind: Kind,
}

pub(crate) fn block(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    let Some(target) = requested_block(req, ctx, resp) else { return };
    if !req.accepts_ssz() {
        return resp.error(406, "only application/octet-stream is served");
    }
    serve(target, Kind::Ssz, ctx, resp);
}

pub(crate) fn payload_envelope(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    let Some(target) = requested_block(req, ctx, resp) else { return };
    if !req.accepts_ssz() {
        return resp.error(406, "only application/octet-stream is served");
    }
    serve(target, Kind::Envelope, ctx, resp);
}

pub(crate) fn block_attestations(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    if let Some(target) = requested_block(req, ctx, resp) {
        serve(target, Kind::Attestations, ctx, resp);
    }
}

pub(crate) fn block_root(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    if let Some(target) = requested_block(req, ctx, resp) {
        serve(target, Kind::Root, ctx, resp);
    }
}

pub(crate) fn block_header(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    if let Some(target) = requested_block(req, ctx, resp) {
        serve(target, Kind::Header, ctx, resp);
    }
}

/// Only the filterless form, which answers the head; Prysm's doppelganger check
/// reads it as `data[0]`.
pub(crate) fn head_headers(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    if !req.query.is_empty() {
        return resp.error(400, "slot and parent_root filters are not served");
    }
    serve(target(ctx, head_block(ctx)), Kind::HeaderList, ctx, resp);
}

fn head_block(ctx: &ApiCtx) -> BlockLookup {
    BlockLookup::Root(ctx.node_status.head_root)
}

#[derive(Clone, Copy)]
enum Target {
    Stored(BlockLookup),
    Genesis(GenesisBlock),
}

fn serve(target: Target, kind: Kind, ctx: &ApiCtx, resp: &mut Response<'_>) {
    match target {
        Target::Stored(lookup) => resp.defer(Outcome::AwaitingBlock(BlockRequest { lookup, kind })),
        Target::Genesis(genesis) => genesis.respond(kind, ctx, resp),
    }
}

fn target(ctx: &ApiCtx, lookup: BlockLookup) -> Target {
    match ctx.genesis_block {
        Some(genesis) if genesis.is(lookup) => Target::Genesis(genesis),
        _ => Target::Stored(lookup),
    }
}

fn requested_block(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) -> Option<Target> {
    let block_id = req.params.get("block_id").expect("{block_id} in the route pattern");
    let lookup = match block_id {
        "head" => head_block(ctx),
        "genesis" => BlockLookup::Slot(0),
        "finalized" => checkpoint_block(ctx, |epoch| epoch.finalized_checkpoint.root),
        "justified" => checkpoint_block(ctx, |epoch| epoch.current_justified_checkpoint.root),
        _ => match (parse_root(block_id), parse_uint64(block_id)) {
            (Some(root), _) => BlockLookup::Root(root),
            (_, Some(slot)) => BlockLookup::Slot(slot),
            _ => {
                resp.error(400, "invalid block_id");
                return None;
            }
        },
    };
    Some(target(ctx, lookup))
}

/// A checkpoint at the genesis epoch carries the zero root, which names the
/// genesis block.
fn checkpoint_block(ctx: &ApiCtx, root: impl Fn(&EpochState) -> B256) -> BlockLookup {
    let root = ctx.read_state(|view| root(view.epoch.state()));
    if root == B256::default() { BlockLookup::Slot(0) } else { BlockLookup::Root(root) }
}

/// Storage holds no genesis block, so a node anchored at genesis answers its
/// root and header from the anchor state.
#[derive(Clone, Copy, Debug)]
pub(crate) struct GenesisBlock {
    root: B256,
    header: BeaconBlockHeader,
}

impl GenesisBlock {
    pub(crate) fn at_anchor(root: B256, header: BeaconBlockHeader) -> Option<Self> {
        (header.slot == 0).then_some(Self { root, header })
    }

    /// The genesis state leaves the header's state root zero; `process_slot`
    /// of slot 0 writes it, and the root ring keeps it for only
    /// `SLOTS_PER_HISTORICAL_ROOT` slots.
    pub(crate) fn learn_state_root(&mut self, state: &BeaconStateReader) {
        if self.header.state_root != B256::default() {
            return;
        }
        let root = state.read(|view| (view.slot.state().slot > 0).then(|| view.state_roots.get(0)));
        if let Some(Some(root)) = root {
            self.header.state_root = root;
        }
    }

    fn is(&self, lookup: BlockLookup) -> bool {
        match lookup {
            BlockLookup::Root(root) => root == self.root,
            BlockLookup::Slot(slot) => slot == 0,
        }
    }

    fn respond(&self, kind: Kind, ctx: &ApiCtx, resp: &mut Response<'_>) {
        let flags = ReadFlags {
            execution_optimistic: ctx.node_status.execution_optimistic(),
            finalized: true,
        };
        if kind == Kind::Root {
            return resp
                .json_body(|json| json.flagged_envelope(flags, |json| json.root(&self.root)));
        }
        match kind {
            Kind::Ssz => return resp.error(404, "genesis block not stored"),
            Kind::Envelope => return resp.error(404, "execution payload envelope not found"),
            Kind::Attestations => {
                return respond_attestations(resp, ctx.spec.fork_at_slot(0).name(), flags, &[]);
            }
            _ => {}
        }
        if self.header.state_root == B256::default() {
            return resp.error(503, "genesis state root not yet known");
        }
        let signed = SignedHeader {
            root: self.root,
            canonical: true,
            header: self.header,
            signature: [0; 96],
        };
        resp.json_body(|json| {
            json.flagged_envelope(flags, |json| match kind {
                Kind::HeaderList => json.signed_headers(slice::from_ref(&signed)),
                _ => json.signed_header(&signed),
            })
        });
    }
}

impl BlockRequest {
    pub(crate) fn storage_request(self, request_id: u64) -> BeaconApiRequest {
        let lookup = self.lookup;
        match self.kind {
            Kind::Envelope => BeaconApiRequest::StoredEnvelope { request_id, lookup },
            kind => BeaconApiRequest::Block { request_id, lookup, with_bytes: kind != Kind::Root },
        }
    }
}

impl Kind {
    fn fits(self, bytes: &[u8]) -> bool {
        match self {
            Self::Envelope => SignedExecutionPayloadEnvelopeView::check_size(bytes),
            _ => SignedBeaconBlockView::check_size(bytes),
        }
    }

    pub(crate) fn respond(
        self,
        resp: &mut Response<'_>,
        block: Option<ServedBlock>,
        reader: &mut TCacheReader,
        ctx: &ApiCtx,
    ) {
        let Some(block) = block else {
            return match self {
                Self::Envelope => resp.error(404, "execution payload envelope not found"),
                _ => resp.error(404, "block not found"),
            };
        };
        let flags = ReadFlags {
            execution_optimistic: ctx.node_status.execution_optimistic(),
            finalized: block.finalized,
        };
        match self {
            Self::Root => {
                resp.json_body(|json| json.flagged_envelope(flags, |json| json.root(&block.root)))
            }
            Self::Ssz => with_bytes(resp, &block, reader, self, |resp, bytes| {
                let version = ctx.spec.fork_at_slot(block.slot).name();
                resp.send(200, Some(SSZ_MEDIA_TYPE), &[("Eth-Consensus-Version", version)], &[
                    bytes,
                ]);
            }),
            Self::Header => with_header(resp, &block, reader, ctx, |json, signed| {
                json.flagged_envelope(flags, |json| json.signed_header(signed))
            }),
            Self::HeaderList => with_header(resp, &block, reader, ctx, |json, signed| {
                json.flagged_envelope(flags, |json| json.signed_headers(slice::from_ref(signed)))
            }),
            Self::Attestations => with_bytes(resp, &block, reader, self, |resp, bytes| {
                let body = SignedBeaconBlockView::body(bytes);
                // Fulu and Gloas bodies both bound the list by these two offsets.
                let start = BeaconBlockBodyFuluView::attestations_offset(body) as usize;
                let end = BeaconBlockBodyFuluView::deposits_offset(body) as usize;
                let Some(list) = body.get(start..end) else {
                    return resp.error(500, "stored block is malformed");
                };
                respond_attestations(resp, ctx.spec.fork_at_slot(block.slot).name(), flags, list);
            }),
            Self::Envelope => with_bytes(resp, &block, reader, self, |resp, bytes| {
                let version = ctx.spec.fork_at_slot(block.slot).name();
                resp.send(200, Some(SSZ_MEDIA_TYPE), &[("Eth-Consensus-Version", version)], &[
                    bytes,
                ]);
            }),
        }
    }
}

fn with_header(
    resp: &mut Response<'_>,
    block: &ServedBlock,
    reader: &mut TCacheReader,
    ctx: &ApiCtx,
    render: impl FnOnce(&mut Json<'_>, &SignedHeader),
) {
    with_bytes(resp, block, reader, Kind::Header, |resp, bytes| {
        let signed = SignedHeader::read(block, bytes, ctx.spec.is_gloas_at_slot(block.slot));
        resp.json_body(|json| render(json, &signed));
    });
}

fn respond_attestations(resp: &mut Response<'_>, version: &str, flags: ReadFlags, list: &[u8]) {
    resp.json_body_with(&[("Eth-Consensus-Version", version)], |json| {
        json.versioned_flagged_envelope(version, flags, |json| {
            json.begin_array();
            for attestation in variable_items(list) {
                json.attestation(attestation);
            }
            json.end_array();
        })
    });
}

/// Items of an SSZ list of variable-size elements. A stored block passed
/// validation, so an offset out of order ends the walk instead of failing it.
fn variable_items(list: &[u8]) -> impl Iterator<Item = &[u8]> {
    let offset = |i: usize| -> Option<usize> {
        Some(u32::from_le_bytes(list.get(i * 4..i * 4 + 4)?.try_into().ok()?) as usize)
    };
    let count = offset(0).map_or(0, |first| first / 4);
    (0..count).map_while(move |i| {
        let start = offset(i)?;
        let end = if i + 1 < count { offset(i + 1)? } else { list.len() };
        list.get(start..end).filter(|item| !item.is_empty())
    })
}

fn with_bytes(
    resp: &mut Response<'_>,
    block: &ServedBlock,
    reader: &mut TCacheReader,
    kind: Kind,
    respond: impl FnOnce(&mut Response<'_>, &[u8]),
) {
    let Some(ssz) = block.ssz else {
        silver_log::error!(block.slot, ?kind, "storage answered a request without the bytes");
        return resp.error(500, "stored bytes missing");
    };
    let ssz = reader.acquire(ssz);
    match ssz.buffer() {
        Ok((bytes, _)) if kind.fits(bytes) => respond(resp, bytes),
        Ok(_) => {
            silver_log::error!(block.slot, ?kind, "stored bytes fit no layout for the request");
            resp.error(500, "stored object is malformed");
        }
        Err(e) => {
            silver_log::warn!(
                ?e,
                block.slot,
                ?kind,
                "served bytes overwritten before they were read"
            );
            resp.error(503, "stored object no longer available");
        }
    }
}

impl SignedHeader {
    fn read(block: &ServedBlock, bytes: &[u8], is_gloas: bool) -> Self {
        Self {
            root: block.root,
            canonical: block.canonical,
            header: BeaconBlockHeader {
                slot: block.slot,
                proposer_index: SignedBeaconBlockView::proposer_index(bytes),
                parent_root: *SignedBeaconBlockView::parent_root(bytes),
                state_root: *SignedBeaconBlockView::state_root(bytes),
                body_root: body_root_at(SignedBeaconBlockView::body(bytes), is_gloas),
            },
            signature: *SignedBeaconBlockView::signature(bytes),
        }
    }
}

#[cfg(test)]
mod tests {
    use silver_beacon_state_data::{
        BeaconState, BeaconStateOwner, Checkpoint, EpochStateFinalized, SpecConfig,
    };
    use silver_httpcore::ParsedRequest;

    use super::*;
    use crate::{
        ctx::{anchor_ctx, test_ctx},
        testing::{dispatch, request},
    };

    const ROOT: B256 = [0xab; 32];

    fn get(path: &str, accept: Option<&str>) -> (Outcome, Vec<u8>) {
        get_from(&anchor_ctx(), path, accept)
    }

    fn get_from(ctx: &ApiCtx, path: &str, accept: Option<&str>) -> (Outcome, Vec<u8>) {
        dispatch(ctx, &ParsedRequest { accept, ..request("GET", path) })
    }

    fn routes(block_id: &str) -> [(String, Kind); 3] {
        [
            (format!("/eth/v2/beacon/blocks/{block_id}"), Kind::Ssz),
            (format!("/eth/v1/beacon/blocks/{block_id}/root"), Kind::Root),
            (format!("/eth/v1/beacon/headers/{block_id}"), Kind::Header),
        ]
    }

    #[test]
    fn each_block_route_defers_to_storage_and_writes_nothing() {
        for (path, kind) in routes(&format!("0x{}", "ab".repeat(32))) {
            let (outcome, out) = get(&path, Some("application/octet-stream"));
            let lookup = BlockLookup::Root(ROOT);
            assert_eq!(outcome, Outcome::AwaitingBlock(BlockRequest { lookup, kind }), "{path}");
            assert!(out.is_empty(), "{path}");
        }
    }

    #[test]
    fn only_the_block_body_negotiates_ssz() {
        for accept in [None, Some("application/json")] {
            let [(body, _), (root, _), (header, _)] = routes(&format!("0x{}", "ab".repeat(32)));
            let (outcome, out) = get(&body, accept);
            assert_eq!(outcome, Outcome::Response(None));
            assert!(out.starts_with(b"HTTP/1.1 406 Not Acceptable\r\n"), "{accept:?}");
            for path in [root, header] {
                let (outcome, _) = get(&path, accept);
                assert!(matches!(outcome, Outcome::AwaitingBlock(_)), "{path} {accept:?}");
            }
        }
    }

    #[test]
    fn keyword_and_slot_ids_resolve_to_a_lookup() {
        let mut ctx = anchor_ctx();
        ctx.node_status.head_root = [0x11; 32];
        for (block_id, lookup) in
            [("head", BlockLookup::Root([0x11; 32])), ("12", BlockLookup::Slot(12))]
        {
            for (path, kind) in routes(block_id) {
                let (outcome, _) = get_from(&ctx, &path, Some("application/octet-stream"));
                assert_eq!(
                    outcome,
                    Outcome::AwaitingBlock(BlockRequest { lookup, kind }),
                    "{path}"
                );
            }
        }
    }

    #[test]
    fn filterless_header_list_defers_the_head_and_filters_are_a_400() {
        let mut ctx = anchor_ctx();
        ctx.node_status.head_root = [0x11; 32];
        let (outcome, _) = get_from(&ctx, "/eth/v1/beacon/headers", None);
        let lookup = BlockLookup::Root([0x11; 32]);
        assert_eq!(
            outcome,
            Outcome::AwaitingBlock(BlockRequest { lookup, kind: Kind::HeaderList })
        );

        for query in ["slot=12", "parent_root=0x00"] {
            let req = ParsedRequest { query, ..request("GET", "/eth/v1/beacon/headers") };
            let (outcome, out) = dispatch(&ctx, &req);
            assert_eq!(outcome, Outcome::Response(None), "{query}");
            assert!(out.starts_with(b"HTTP/1.1 400 Bad Request\r\n"), "{query}");
        }
    }

    fn genesis_ctx() -> ApiCtx {
        let mut ctx = anchor_ctx();
        ctx.node_status.head_root = [0x11; 32];
        let header = BeaconBlockHeader { state_root: [0x33; 32], ..Default::default() };
        ctx.genesis_block = Some(GenesisBlock { root: [0x22; 32], header });
        ctx
    }

    #[test]
    fn genesis_ids_answer_from_the_anchor() {
        let ctx = genesis_ctx();
        let root = format!("0x{}", "22".repeat(32));
        for block_id in ["genesis", "0", "finalized", "justified", root.as_str()] {
            let [(ssz, _), (root_path, _), (header, _)] = routes(block_id);
            let (outcome, out) = get_from(&ctx, &ssz, Some("application/octet-stream"));
            assert_eq!(outcome, Outcome::Response(None), "{ssz}");
            assert!(out.starts_with(b"HTTP/1.1 404 Not Found\r\n"), "{ssz}");

            let (_, out) = get_from(&ctx, &root_path, None);
            let text = String::from_utf8(out).unwrap();
            assert!(text.starts_with("HTTP/1.1 200 OK\r\n"), "{root_path}");
            assert!(text.contains(&root), "{root_path}");

            let (_, out) = get_from(&ctx, &header, None);
            let text = String::from_utf8(out).unwrap();
            assert!(text.starts_with("HTTP/1.1 200 OK\r\n"), "{header}");
            assert!(text.contains(&format!("\"state_root\":\"0x{}\"", "33".repeat(32))));
            assert!(text.contains("\"finalized\":true"), "{header}");
        }
    }

    #[test]
    fn genesis_header_waits_for_its_state_root() {
        let mut ctx = genesis_ctx();
        let genesis = ctx.genesis_block.as_mut().unwrap();
        genesis.header.state_root = B256::default();
        let [_, (root, _), (header, _)] = routes("genesis");
        assert!(get_from(&ctx, &root, None).1.starts_with(b"HTTP/1.1 200 OK\r\n"));
        let (_, out) = get_from(&ctx, &header, None);
        assert!(out.starts_with(b"HTTP/1.1 503 Service Unavailable\r\n"));
    }

    #[test]
    fn without_a_genesis_anchor_keywords_defer_to_storage() {
        let epoch = EpochState {
            current_justified_checkpoint: Checkpoint { epoch: 4, root: [0x55; 32] },
            finalized_checkpoint: Checkpoint { epoch: 3, root: [0x44; 32] },
            ..Default::default()
        };
        let state = BeaconState::for_test(EpochStateFinalized::from_state(epoch), &[], 160);
        let mut owner = BeaconStateOwner::new(state);
        let anchor = owner.roll_fresh();
        owner.publish_state_id(anchor);
        let mut ctx = test_ctx(&SpecConfig::mainnet(), owner.reader());
        ctx.genesis_block = None;

        for (block_id, lookup) in [
            ("genesis", BlockLookup::Slot(0)),
            ("finalized", BlockLookup::Root([0x44; 32])),
            ("justified", BlockLookup::Root([0x55; 32])),
        ] {
            for (path, kind) in routes(block_id) {
                let (outcome, _) = get_from(&ctx, &path, Some("application/octet-stream"));
                let expected = Outcome::AwaitingBlock(BlockRequest { lookup, kind });
                assert_eq!(outcome, expected, "{path}");
            }
        }
    }

    #[test]
    fn envelopes_defer_to_storage_by_block_and_serve_ssz_only() {
        let mut ctx = anchor_ctx();
        ctx.genesis_block = None;
        let path = format!("/eth/v1/beacon/execution_payload_envelopes/0x{}", "ab".repeat(32));
        let (outcome, _) = get_from(&ctx, &path, Some("application/octet-stream"));
        let request = BlockRequest { lookup: BlockLookup::Root(ROOT), kind: Kind::Envelope };
        assert_eq!(outcome, Outcome::AwaitingBlock(request));
        assert_eq!(request.storage_request(3), BeaconApiRequest::StoredEnvelope {
            request_id: 3,
            lookup: BlockLookup::Root(ROOT)
        });

        let (outcome, out) = get_from(&ctx, &path, Some("application/json"));
        assert_eq!(outcome, Outcome::Response(None));
        assert!(out.starts_with(b"HTTP/1.1 406 Not Acceptable\r\n"));

        let genesis = "/eth/v1/beacon/execution_payload_envelopes/genesis";
        let (_, out) = get_from(&genesis_ctx(), genesis, Some("application/octet-stream"));
        assert!(out.starts_with(b"HTTP/1.1 404 Not Found\r\n"));
    }

    #[test]
    fn variable_items_split_on_the_offset_table() {
        let mut list = [8u32.to_le_bytes(), 11u32.to_le_bytes()].concat();
        list.extend_from_slice(&[1, 2, 3, 4, 5]);
        assert_eq!(variable_items(&list).collect::<Vec<_>>(), [&[1, 2, 3][..], &[4, 5][..]]);
        assert_eq!(variable_items(&[]).count(), 0);

        let mut unordered = [8u32.to_le_bytes(), 4u32.to_le_bytes()].concat();
        unordered.extend_from_slice(&[1, 2]);
        assert_eq!(variable_items(&unordered).count(), 0, "a bad offset ends the walk");
    }

    #[test]
    fn genesis_attestations_are_an_empty_versioned_list() {
        let path = "/eth/v2/beacon/blocks/genesis/attestations";
        let (outcome, out) = get_from(&genesis_ctx(), path, None);
        assert_eq!(outcome, Outcome::Response(None));
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("Eth-Consensus-Version: phase0\r\n"), "{text}");
        assert!(text.ends_with(
            r#"{"version":"phase0","execution_optimistic":false,"finalized":true,"data":[]}"#
        ));

        let mut ctx = genesis_ctx();
        ctx.genesis_block = None;
        let (outcome, _) = get_from(&ctx, path, None);
        let lookup = BlockLookup::Slot(0);
        assert_eq!(
            outcome,
            Outcome::AwaitingBlock(BlockRequest { lookup, kind: Kind::Attestations })
        );
    }

    #[test]
    fn malformed_ids_are_a_400() {
        for block_id in ["0x1234", "latest", "-1"] {
            for (path, _) in routes(block_id) {
                let (_, out) = get(&path, Some("application/octet-stream"));
                assert!(out.starts_with(b"HTTP/1.1 400 Bad Request\r\n"), "{path}");
            }
        }
    }
}
