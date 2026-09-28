use silver_beacon_state_data::{B256, SpecConfig};
use silver_common::{BeaconApiRequest, TCacheRead, TCacheReader};

use crate::{
    ctx::ApiCtx,
    http::{ids::parse_root, response::Response, router::Request},
    validator::attestation_data::CommitteeQuery,
};

pub(crate) fn aggregate_attestation(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    let Some(committee) = CommitteeQuery::parse(req, ctx, resp) else {
        return;
    };
    let Some(data_root) =
        req.query_value("attestation_data_root").and_then(|root| parse_root(&root))
    else {
        resp.error(400, "attestation_data_root is a required Root query parameter");
        return;
    };

    resp.request_aggregate(AggregateRequest { committee, data_root });
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AggregateRequest {
    pub(crate) committee: CommitteeQuery,
    pub(crate) data_root: B256,
}

impl AggregateRequest {
    pub(crate) fn state_request(self, request_id: u64) -> BeaconApiRequest {
        BeaconApiRequest::AggregateAttestation {
            request_id,
            slot: self.committee.slot,
            committee_index: self.committee.committee_index,
            data_root: self.data_root,
        }
    }

    pub(crate) fn respond(
        self,
        resp: &mut Response<'_>,
        ssz: Option<TCacheRead>,
        reader: &mut TCacheReader,
        spec: &SpecConfig,
    ) {
        let Some(ssz) = ssz else {
            return resp.error(404, "no matching aggregate found");
        };
        let posted = reader.acquire(ssz);
        match posted.buffer() {
            Ok((bytes, _)) => {
                let version = spec.fork_at_slot(self.committee.slot).name();
                resp.versioned_json(version, |json| json.attestation(bytes));
            }
            Err(e) => {
                tracing::warn!(?e, slot = self.committee.slot, "served aggregate unavailable");
                resp.error(500, "the aggregate could not be read");
            }
        }
    }
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

    fn get(ctx: &ApiCtx, query: &str) -> (Outcome, Vec<u8>) {
        dispatch(ctx, &ParsedRequest {
            query,
            ..request("GET", "/eth/v2/validator/aggregate_attestation")
        })
    }

    fn query(slot: u64, committee_index: u64) -> String {
        format!(
            "slot={slot}&attestation_data_root=0x{}&committee_index={committee_index}",
            "ab".repeat(32)
        )
    }

    #[test]
    fn request_defers_to_the_state_tile_with_what_the_query_names() {
        let (outcome, out) = get(&ctx(), &query(SLOT, 0));
        assert!(out.is_empty());
        assert_eq!(
            outcome,
            Outcome::AwaitingAggregate(AggregateRequest {
                committee: CommitteeQuery { slot: SLOT, committee_index: 0 },
                data_root: [0xab; 32],
            })
        );
    }

    #[test]
    fn missing_or_malformed_parameters_are_400() {
        let ctx = ctx();
        for query in [
            "",
            &format!("slot={SLOT}&committee_index=0"),
            &format!("slot={SLOT}&attestation_data_root=0x{}", "ab".repeat(32)),
            &format!("slot={SLOT}&attestation_data_root=0xab&committee_index=0"),
            &format!("slot=+1&attestation_data_root=0x{}&committee_index=0", "ab".repeat(32)),
        ] {
            let (outcome, out) = get(&ctx, query);
            assert_eq!(outcome, Outcome::Response(None), "{query}");
            assert_eq!(status_code(&out), "400", "{query}");
        }
    }
}
