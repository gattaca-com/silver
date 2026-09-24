use silver_beacon_state_data::{B256, Slot};
use silver_common::{BeaconApiRequest, SYNC_COMMITTEE_SUBNETS, TCacheRead, TCacheReader};

use crate::{
    ctx::ApiCtx,
    http::{ids::parse_root, response::Response, router::Request},
    validator::attestation_data::uint64_query,
};

pub(crate) fn sync_committee_contribution(
    req: &Request<'_>,
    ctx: &ApiCtx,
    resp: &mut Response<'_>,
) {
    if !ctx.follows_chain(resp) {
        return;
    }
    let (Some(slot), Some(subcommittee_index), Some(beacon_block_root)) = (
        uint64_query(req, "slot"),
        uint64_query(req, "subcommittee_index"),
        req.query_value("beacon_block_root").and_then(|root| parse_root(&root)),
    ) else {
        resp.error(
            400,
            "slot, subcommittee_index and beacon_block_root are required query parameters",
        );
        return;
    };
    if subcommittee_index >= SYNC_COMMITTEE_SUBNETS as u64 {
        resp.error(400, "subcommittee_index is past the sync subcommittee count");
        return;
    }

    resp.request_contribution(ContributionRequest { slot, subcommittee_index, beacon_block_root });
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ContributionRequest {
    pub(crate) slot: Slot,
    pub(crate) subcommittee_index: u64,
    pub(crate) beacon_block_root: B256,
}

impl ContributionRequest {
    pub(crate) fn state_request(self, request_id: u64) -> BeaconApiRequest {
        BeaconApiRequest::SyncCommitteeContribution {
            request_id,
            slot: self.slot,
            subcommittee_index: self.subcommittee_index,
            beacon_block_root: self.beacon_block_root,
        }
    }

    pub(crate) fn respond(
        self,
        resp: &mut Response<'_>,
        ssz: Option<TCacheRead>,
        reader: &mut TCacheReader,
    ) {
        let Some(ssz) = ssz else {
            return resp.error(404, "no matching contribution found");
        };
        let posted = reader.acquire(ssz);
        match posted.buffer() {
            Ok((bytes, _)) => {
                let contribution = bytes.try_into().expect("the pool serves whole contributions");
                resp.json_body(|json| {
                    json.data_envelope(|json| json.sync_committee_contribution(contribution))
                });
            }
            Err(e) => {
                tracing::warn!(?e, slot = self.slot, "served contribution unavailable");
                resp.error(500, "the contribution could not be read");
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
            ..request("GET", "/eth/v1/validator/sync_committee_contribution")
        })
    }

    fn query(slot: u64, subcommittee_index: u64) -> String {
        format!(
            "slot={slot}&subcommittee_index={subcommittee_index}&beacon_block_root=0x{}",
            "ab".repeat(32)
        )
    }

    #[test]
    fn request_defers_to_the_state_tile_with_what_the_query_names() {
        let (outcome, out) = get(&ctx(), &query(SLOT, 3));
        assert!(out.is_empty());
        assert_eq!(
            outcome,
            Outcome::AwaitingContribution(ContributionRequest {
                slot: SLOT,
                subcommittee_index: 3,
                beacon_block_root: [0xab; 32],
            })
        );
    }

    #[test]
    fn missing_or_malformed_parameters_are_400() {
        let ctx = ctx();
        for query in [
            "",
            &format!("slot={SLOT}&subcommittee_index=0"),
            &format!("slot={SLOT}&beacon_block_root=0x{}", "ab".repeat(32)),
            &format!("slot={SLOT}&subcommittee_index=0&beacon_block_root=0xab"),
            &query(SLOT, SYNC_COMMITTEE_SUBNETS as u64),
        ] {
            let (outcome, out) = get(&ctx, query);
            assert_eq!(outcome, Outcome::Response, "{query}");
            assert_eq!(status_code(&out), "400", "{query}");
        }
    }
}
