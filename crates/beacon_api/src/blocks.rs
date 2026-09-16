use silver_beacon_state_data::{B256, BeaconBlockHeader};
use silver_common::{ServedBlock, TRandomAccess, column_util, ssz_view::SignedBeaconBlockView};

use crate::{
    ids::{is_recognized_id, parse_root},
    json::{ReadFlags, SignedHeader},
    response::Response,
    router::{Request, SSZ_MEDIA_TYPE},
    routes::ApiCtx,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Ssz,
    Root,
    Header,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BlockRequest {
    pub(crate) root: B256,
    pub(crate) kind: Kind,
}

/// Only SSZ: the JSON body is not rendered yet.
pub(crate) fn block(req: &Request<'_>, _ctx: &ApiCtx, resp: &mut Response<'_>) {
    let Some(root) = requested_root(req, resp) else { return };
    if !req.accepts_ssz() {
        return resp.error(406, "only application/octet-stream is served");
    }
    resp.request_block(BlockRequest { root, kind: Kind::Ssz });
}

pub(crate) fn block_root(req: &Request<'_>, _ctx: &ApiCtx, resp: &mut Response<'_>) {
    if let Some(root) = requested_root(req, resp) {
        resp.request_block(BlockRequest { root, kind: Kind::Root });
    }
}

pub(crate) fn block_header(req: &Request<'_>, _ctx: &ApiCtx, resp: &mut Response<'_>) {
    if let Some(root) = requested_root(req, resp) {
        resp.request_block(BlockRequest { root, kind: Kind::Header });
    }
}

/// The root `{block_id}` names. Only roots are served: the keyword and slot
/// forms answer 404 here, anything else 400.
fn requested_root(req: &Request<'_>, resp: &mut Response<'_>) -> Option<B256> {
    let block_id = req.params.get("block_id").expect("{block_id} in the route pattern");
    let root = parse_root(block_id);
    if root.is_none() {
        if is_recognized_id(block_id) {
            resp.error(404, "block not found");
        } else {
            resp.error(400, "invalid block_id");
        }
    }
    root
}

impl Kind {
    pub(crate) fn respond(
        self,
        resp: &mut Response<'_>,
        root: B256,
        block: Option<ServedBlock>,
        storage: &mut TRandomAccess,
        ctx: &ApiCtx,
    ) {
        let Some(ServedBlock { slot, finalized, canonical, ssz }) = block else {
            return resp.error(404, "block not found");
        };
        let ssz = storage.acquire(ssz);
        let bytes = match ssz.buffer() {
            Ok((bytes, _)) if SignedBeaconBlockView::check_size(bytes) => bytes,
            Ok(_) => {
                tracing::error!(slot, "stored block fits no SignedBeaconBlock layout");
                return resp.error(500, "stored block is malformed");
            }
            Err(e) => {
                tracing::warn!(?e, slot, "served block overwritten before it was read");
                return resp.error(503, "block no longer available");
            }
        };

        let flags =
            ReadFlags { execution_optimistic: ctx.node_status.execution_optimistic(), finalized };
        match self {
            Self::Ssz => {
                let version = ctx.spec.fork_at_slot(slot).name();
                resp.send(200, Some(SSZ_MEDIA_TYPE), &[("Eth-Consensus-Version", version)], bytes);
            }
            Self::Root => {
                resp.json_body(|json| json.flagged_envelope(flags, |json| json.block_root(&root)))
            }
            Self::Header => {
                let body = SignedBeaconBlockView::body(bytes);
                let signed = SignedHeader {
                    root,
                    canonical,
                    header: BeaconBlockHeader {
                        slot,
                        proposer_index: SignedBeaconBlockView::proposer_index(bytes),
                        parent_root: *SignedBeaconBlockView::parent_root(bytes),
                        state_root: *SignedBeaconBlockView::state_root(bytes),
                        body_root: column_util::body_root_at(body, ctx.spec.is_gloas_at_slot(slot)),
                    },
                    signature: *SignedBeaconBlockView::signature(bytes),
                };
                resp.json_body(|json| {
                    json.flagged_envelope(flags, |json| json.signed_header(&signed))
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use silver_httpcore::ParsedRequest;

    use super::*;
    use crate::{
        router::{Outcome, Router},
        routes::{ROUTES, anchor_ctx},
    };

    const ROOT: B256 = [0xab; 32];

    fn get(path: &str, accept: Option<&str>) -> (Outcome, Vec<u8>) {
        let req = ParsedRequest {
            method: "GET",
            path,
            query: "",
            body: b"",
            accept,
            content_type: None,
            eth_consensus_version: None,
            version: 1,
            keep_alive: true,
        };
        let mut out = Vec::new();
        let outcome = Router::new(ROUTES).dispatch(&req, &anchor_ctx(), &mut out);
        (outcome, out)
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
            assert_eq!(
                outcome,
                Outcome::AwaitingBlock(BlockRequest { root: ROOT, kind }),
                "{path}"
            );
            assert!(out.is_empty(), "{path}");
        }
    }

    #[test]
    fn only_the_block_body_negotiates_ssz() {
        for accept in [None, Some("application/json")] {
            let [(body, _), (root, _), (header, _)] = routes(&format!("0x{}", "ab".repeat(32)));
            let (outcome, out) = get(&body, accept);
            assert_eq!(outcome, Outcome::Response);
            assert!(out.starts_with(b"HTTP/1.1 406 Not Acceptable\r\n"), "{accept:?}");
            for path in [root, header] {
                let (outcome, _) = get(&path, accept);
                assert!(matches!(outcome, Outcome::AwaitingBlock(_)), "{path} {accept:?}");
            }
        }
    }

    #[test]
    fn ids_that_are_not_roots_are_answered_before_deferring() {
        for block_id in ["head", "finalized", "genesis", "justified", "12"] {
            for (path, _) in routes(block_id) {
                let (_, out) = get(&path, Some("application/octet-stream"));
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
