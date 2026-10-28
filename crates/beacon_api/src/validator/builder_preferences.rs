use silver_pbs::PreferencesBody;

use crate::{
    ctx::ApiCtx,
    http::{response::Response, router::Request},
    validator::registration::UNSUPPORTED_MEDIA_TYPE,
};

pub(crate) fn post_builder_preferences(req: &Request<'_>, _ctx: &ApiCtx, resp: &mut Response<'_>) {
    if req.eth_consensus_version != Some("gloas") {
        return resp.error(400, "Eth-Consensus-Version must name gloas");
    }
    let is_json = !req.body_is_ssz();
    if is_json && !req.body_is_json() {
        return resp.error(415, UNSUPPORTED_MEDIA_TYPE);
    }
    if PreferencesBody::parse(req.body, is_json).is_none() {
        return resp.error(400, "invalid BuilderPreferencesEntry list");
    }
    resp.await_builder_preferences(is_json);
}
