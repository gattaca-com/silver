use crate::{
    beacon::{
        block_submission::post_block_v2,
        blocks::{block, block_header, block_root},
        operations::{
            post_attestations, post_attester_slashing, post_bls_to_execution_changes,
            post_proposer_slashing, post_voluntary_exit,
        },
        pools::{
            get_attester_slashings, get_bls_to_execution_changes, get_proposer_slashings,
            get_voluntary_exits,
        },
        states::{genesis, state_finality_checkpoints, state_fork},
        sync_committees::post_sync_committee_messages,
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
        contribution_submission::post_contribution_and_proofs,
        liveness::post_liveness,
        produce_block::produce_block_v3,
        proposer_duties::{proposer_duties, proposer_duties_v2},
        registration::{post_prepare_beacon_proposer, post_register_validator},
        subnet_subscriptions::{
            post_beacon_committee_subscriptions, post_sync_committee_subscriptions,
        },
        sync_contribution::sync_committee_contribution,
        sync_duties::post_sync_duties,
    },
};

const METRICS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

pub(crate) const ROUTES: &[(Method, &str, Handler)] = &[
    (Method::Get, "/eth/v1/beacon/blocks/{block_id}/root", block_root),
    (Method::Get, "/eth/v1/beacon/genesis", genesis),
    (Method::Get, "/eth/v1/beacon/headers/{block_id}", block_header),
    (Method::Get, "/eth/v1/beacon/pool/bls_to_execution_changes", get_bls_to_execution_changes),
    (Method::Post, "/eth/v1/beacon/pool/bls_to_execution_changes", post_bls_to_execution_changes),
    (Method::Get, "/eth/v1/beacon/pool/proposer_slashings", get_proposer_slashings),
    (Method::Post, "/eth/v1/beacon/pool/proposer_slashings", post_proposer_slashing),
    (Method::Post, "/eth/v1/beacon/pool/sync_committees", post_sync_committee_messages),
    (Method::Get, "/eth/v1/beacon/pool/voluntary_exits", get_voluntary_exits),
    (Method::Post, "/eth/v1/beacon/pool/voluntary_exits", post_voluntary_exit),
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
    (Method::Post, "/eth/v1/validator/contribution_and_proofs", post_contribution_and_proofs),
    (Method::Post, "/eth/v1/validator/duties/attester/{epoch}", post_attester_duties),
    (Method::Get, "/eth/v1/validator/duties/proposer/{epoch}", proposer_duties),
    (Method::Post, "/eth/v1/validator/duties/sync/{epoch}", post_sync_duties),
    (Method::Post, "/eth/v1/validator/liveness/{epoch}", post_liveness),
    (Method::Post, "/eth/v1/validator/prepare_beacon_proposer", post_prepare_beacon_proposer),
    (Method::Post, "/eth/v1/validator/register_validator", post_register_validator),
    (Method::Get, "/eth/v1/validator/sync_committee_contribution", sync_committee_contribution),
    (
        Method::Post,
        "/eth/v1/validator/sync_committee_subscriptions",
        post_sync_committee_subscriptions,
    ),
    (Method::Get, "/eth/v2/beacon/blocks/{block_id}", block),
    (Method::Post, "/eth/v2/beacon/blocks", post_block_v2),
    (Method::Post, "/eth/v2/beacon/pool/attestations", post_attestations),
    (Method::Get, "/eth/v2/beacon/pool/attester_slashings", get_attester_slashings),
    (Method::Post, "/eth/v2/beacon/pool/attester_slashings", post_attester_slashing),
    (Method::Post, "/eth/v2/validator/aggregate_and_proofs", post_aggregate_and_proofs),
    (Method::Get, "/eth/v2/validator/aggregate_attestation", aggregate_attestation),
    (Method::Get, "/eth/v2/validator/duties/proposer/{epoch}", proposer_duties_v2),
    (Method::Get, "/eth/v3/validator/blocks/{slot}", produce_block_v3),
    (Method::Get, "/metrics", metrics),
];

fn metrics(_req: &Request<'_>, _ctx: &ApiCtx, resp: &mut Response<'_>) {
    resp.empty(METRICS_CONTENT_TYPE);
}

#[cfg(test)]
mod tests {
    use crate::{
        ctx::anchor_ctx,
        testing::{answer, body, request},
    };

    #[test]
    fn metrics_response_valid_prometheus_format() {
        let resp = answer(&anchor_ctx(), &request("GET", "/metrics"));
        let s = std::str::from_utf8(&resp).unwrap();
        assert!(s.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(s.contains("text/plain; version=0.0.4; charset=utf-8"));
        assert_eq!(body(&resp), b"");
    }
}
