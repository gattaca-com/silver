use silver_beacon_state_data::Epoch;

use crate::http::{
    ids::{body_entries, parse_uint64},
    response::Response,
    router::Request,
};

pub(crate) fn epoch_param(req: &Request<'_>, resp: &mut Response<'_>) -> Option<Epoch> {
    let epoch = req.params.get("epoch").expect("{epoch} in the route pattern");
    let parsed = parse_uint64(epoch);
    if parsed.is_none() {
        resp.error(400, "invalid epoch");
    }
    parsed
}

pub(crate) fn requested_indices(req: &Request<'_>, resp: &mut Response<'_>) -> Option<Vec<u64>> {
    let entries: Vec<&str> = body_entries(req.body, resp)?;
    let Some(mut indices) = entries.into_iter().map(parse_uint64).collect::<Option<Vec<_>>>()
    else {
        resp.error(400, "invalid request body");
        return None;
    };
    if indices.is_empty() {
        resp.error(400, "the body must name at least one validator");
        return None;
    }
    indices.sort_unstable();
    indices.dedup();
    Some(indices)
}
