use silver_beacon_state_data::BeaconBlockHeader;
use silver_common::{
    BeaconApiRequest, BlockLookup, ServedBlock, TCacheReader, body_root_at,
    ssz_view::SignedBeaconBlockView,
};

use crate::{
    ctx::ApiCtx,
    http::{
        ids::{parse_root, parse_uint64},
        json::{ReadFlags, SignedHeader},
        response::Response,
        router::{Request, SSZ_MEDIA_TYPE},
    },
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Ssz,
    Root,
    Header,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BlockRequest {
    pub(crate) lookup: BlockLookup,
    pub(crate) kind: Kind,
}

pub(crate) fn block(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    let Some(lookup) = requested_block(req, ctx, resp) else { return };
    if !req.accepts_ssz() {
        return resp.error(406, "only application/octet-stream is served");
    }
    resp.request_block(BlockRequest { lookup, kind: Kind::Ssz });
}

pub(crate) fn block_root(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    if let Some(lookup) = requested_block(req, ctx, resp) {
        resp.request_block(BlockRequest { lookup, kind: Kind::Root });
    }
}

pub(crate) fn block_header(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    if let Some(lookup) = requested_block(req, ctx, resp) {
        resp.request_block(BlockRequest { lookup, kind: Kind::Header });
    }
}

fn requested_block(
    req: &Request<'_>,
    ctx: &ApiCtx,
    resp: &mut Response<'_>,
) -> Option<BlockLookup> {
    let block_id = req.params.get("block_id").expect("{block_id} in the route pattern");
    let lookup = match block_id {
        "head" => Some(BlockLookup::Root(ctx.node_status.head_root)),
        "genesis" | "finalized" | "justified" => None,
        _ => match (parse_root(block_id), parse_uint64(block_id)) {
            (Some(root), _) => Some(BlockLookup::Root(root)),
            (_, Some(slot)) => Some(BlockLookup::Slot(slot)),
            _ => {
                resp.error(400, "invalid block_id");
                return None;
            }
        },
    };
    if lookup.is_none() {
        resp.error(404, "block not found");
    }
    lookup
}

impl BlockRequest {
    pub(crate) fn storage_request(self, request_id: u64) -> BeaconApiRequest {
        let with_bytes = self.kind != Kind::Root;
        BeaconApiRequest::Block { request_id, lookup: self.lookup, with_bytes }
    }
}

impl Kind {
    pub(crate) fn respond(
        self,
        resp: &mut Response<'_>,
        block: Option<ServedBlock>,
        reader: &mut TCacheReader,
        ctx: &ApiCtx,
    ) {
        let Some(block) = block else {
            return resp.error(404, "block not found");
        };
        let flags = ReadFlags {
            execution_optimistic: ctx.node_status.execution_optimistic(),
            finalized: block.finalized,
        };
        match self {
            Self::Root => resp.json_body(|json| {
                json.flagged_envelope(flags, |json| json.block_root(&block.root))
            }),
            Self::Ssz => with_bytes(resp, &block, reader, |resp, bytes| {
                let version = ctx.spec.fork_at_slot(block.slot).name();
                resp.send(200, Some(SSZ_MEDIA_TYPE), &[("Eth-Consensus-Version", version)], bytes);
            }),
            Self::Header => with_bytes(resp, &block, reader, |resp, bytes| {
                let signed =
                    SignedHeader::read(&block, bytes, ctx.spec.is_gloas_at_slot(block.slot));
                resp.json_body(|json| {
                    json.flagged_envelope(flags, |json| json.signed_header(&signed))
                });
            }),
        }
    }
}

fn with_bytes(
    resp: &mut Response<'_>,
    block: &ServedBlock,
    reader: &mut TCacheReader,
    respond: impl FnOnce(&mut Response<'_>, &[u8]),
) {
    let Some(ssz) = block.ssz else {
        tracing::error!(block.slot, "storage answered a block request without the bytes");
        return resp.error(500, "block bytes missing");
    };
    let ssz = reader.acquire(ssz);
    match ssz.buffer() {
        Ok((bytes, _)) if SignedBeaconBlockView::check_size(bytes) => respond(resp, bytes),
        Ok(_) => {
            tracing::error!(block.slot, "stored block fits no SignedBeaconBlock layout");
            resp.error(500, "stored block is malformed");
        }
        Err(e) => {
            tracing::warn!(?e, block.slot, "served block overwritten before it was read");
            resp.error(503, "block no longer available");
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
    use silver_beacon_state_data::B256;
    use silver_httpcore::ParsedRequest;

    use super::*;
    use crate::{
        ctx::anchor_ctx,
        http::router::Outcome,
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
    fn ids_silver_cannot_resolve_are_answered_before_deferring() {
        for block_id in ["justified", "finalized", "genesis"] {
            for (path, _) in routes(block_id) {
                let (outcome, out) = get(&path, Some("application/octet-stream"));
                assert_eq!(outcome, Outcome::Response(None), "{path}");
                assert!(out.starts_with(b"HTTP/1.1 404 Not Found\r\n"), "{path}");
            }
        }
        for block_id in ["0x1234", "latest", "-1"] {
            for (path, _) in routes(block_id) {
                let (_, out) = get(&path, Some("application/octet-stream"));
                assert!(out.starts_with(b"HTTP/1.1 400 Bad Request\r\n"), "{path}");
            }
        }
    }
}
