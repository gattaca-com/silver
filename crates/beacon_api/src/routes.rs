use crate::{
    beacon::{
        blocks::{block, block_header, block_root},
        operations::post_attestations,
        states::{genesis, state_finality_checkpoints, state_fork},
        validators::{get_state_validators, post_state_validators, state_validator},
    },
    config::{deposit_contract, fork_schedule, spec},
    ctx::ApiCtx,
    events::events,
    http::{
        response::Response,
        router::{Handler, Method, Request},
    },
    node::{
        identity::identity,
        peers::{peer_count, peers},
        status::{health, syncing, version},
    },
    validator::{
        aggregate_attestation::aggregate_attestation,
        aggregate_submission::post_aggregate_and_proofs,
        attestation_data::attestation_data,
        attester_duties::post_attester_duties,
        proposer_duties::{proposer_duties, proposer_duties_v2},
        registration::{
            post_beacon_committee_subscriptions, post_prepare_beacon_proposer,
            post_register_validator, post_sync_committee_subscriptions,
        },
        sync_duties::post_sync_duties,
    },
};

const METRICS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

pub(crate) const ROUTES: &[(Method, &str, Handler)] = &[
    (Method::Get, "/eth/v1/beacon/blocks/{block_id}/root", block_root),
    (Method::Get, "/eth/v1/beacon/genesis", genesis),
    (Method::Get, "/eth/v1/beacon/headers/{block_id}", block_header),
    (
        Method::Get,
        "/eth/v1/beacon/states/{state_id}/finality_checkpoints",
        state_finality_checkpoints,
    ),
    (Method::Get, "/eth/v1/beacon/states/{state_id}/fork", state_fork),
    (Method::Get, "/eth/v1/beacon/states/{state_id}/validators", get_state_validators),
    (Method::Post, "/eth/v1/beacon/states/{state_id}/validators", post_state_validators),
    (Method::Get, "/eth/v1/beacon/states/{state_id}/validators/{validator_id}", state_validator),
    (Method::Get, "/eth/v1/config/deposit_contract", deposit_contract),
    (Method::Get, "/eth/v1/config/fork_schedule", fork_schedule),
    (Method::Get, "/eth/v1/config/spec", spec),
    (Method::Get, "/eth/v1/events", events),
    (Method::Get, "/eth/v1/node/health", health),
    (Method::Get, "/eth/v1/node/identity", identity),
    (Method::Get, "/eth/v1/node/peer_count", peer_count),
    (Method::Get, "/eth/v1/node/peers", peers),
    (Method::Get, "/eth/v1/node/syncing", syncing),
    (Method::Get, "/eth/v1/node/version", version),
    (Method::Get, "/eth/v1/validator/attestation_data", attestation_data),
    (
        Method::Post,
        "/eth/v1/validator/beacon_committee_subscriptions",
        post_beacon_committee_subscriptions,
    ),
    (Method::Post, "/eth/v1/validator/duties/attester/{epoch}", post_attester_duties),
    (Method::Get, "/eth/v1/validator/duties/proposer/{epoch}", proposer_duties),
    (Method::Post, "/eth/v1/validator/duties/sync/{epoch}", post_sync_duties),
    (Method::Post, "/eth/v1/validator/liveness/{epoch}", not_implemented),
    (Method::Post, "/eth/v1/validator/prepare_beacon_proposer", post_prepare_beacon_proposer),
    (Method::Post, "/eth/v1/validator/register_validator", post_register_validator),
    (
        Method::Post,
        "/eth/v1/validator/sync_committee_subscriptions",
        post_sync_committee_subscriptions,
    ),
    (Method::Get, "/eth/v2/beacon/blocks/{block_id}", block),
    (Method::Post, "/eth/v2/beacon/pool/attestations", post_attestations),
    (Method::Post, "/eth/v2/validator/aggregate_and_proofs", post_aggregate_and_proofs),
    (Method::Get, "/eth/v2/validator/aggregate_attestation", aggregate_attestation),
    (Method::Get, "/eth/v2/validator/duties/proposer/{epoch}", proposer_duties_v2),
    (Method::Get, "/metrics", metrics),
];

/// The surface a request can name ahead of what silver serves: each of these
/// routes needs data the node does not yet keep (a block store, duty
/// shuffling, liveness tracking), so
/// the honest answer is the 501 that tells the client to look elsewhere,
/// rather than a partial answer assembled from the wrong data.
fn not_implemented(_req: &Request<'_>, _ctx: &ApiCtx, resp: &mut Response<'_>) {
    resp.error(501, "endpoint not implemented by this beacon node");
}

fn metrics(_req: &Request<'_>, _ctx: &ApiCtx, resp: &mut Response<'_>) {
    resp.empty(METRICS_CONTENT_TYPE);
}

#[cfg(test)]
mod tests {
    use silver_httpcore::ParsedRequest;

    use crate::{
        ctx::anchor_ctx,
        testing::{answer, body, posting, request},
    };

    #[test]
    fn metrics_response_valid_prometheus_format() {
        let resp = answer(&anchor_ctx(), &request("GET", "/metrics"));
        let s = std::str::from_utf8(&resp).unwrap();
        assert!(s.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(s.contains("text/plain; version=0.0.4; charset=utf-8"));
        assert_eq!(body(&resp), b"");
    }

    /// Every stubbed route answers 501 whatever the node's state: routed, so
    /// a client can tell "this node does not serve it" (501) from "no such
    /// endpoint exists" (404).
    #[test]
    fn stubbed_routes_answer_501_not_404() {
        let ctx = anchor_ctx();
        for (method, path) in [("POST", "/eth/v1/validator/liveness/0")] {
            let out = answer(&ctx, &ParsedRequest { method, ..posting(path, "[]") });
            assert!(out.starts_with(b"HTTP/1.1 501 Not Implemented\r\n"), "{method} {path}");
            assert_eq!(
                body(&out),
                br#"{"code":501,"message":"endpoint not implemented by this beacon node"}"#,
                "{method} {path}"
            );
        }
    }
}
