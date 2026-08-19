use silver_beacon_state_data::SpecConfig;
use silver_common::{AGENT_VERSION, Enr, Identify, Keypair};

use crate::{
    config::{deposit_contract_body, fork_schedule_body, spec_body},
    identity::build_identity_json,
    json::Json,
};

/// Bodies whose every input is known at boot. Rendering them once leaves
/// their handlers a buffer copy, and keeps the spec table — the largest body
/// silver serves — off the request path entirely.
pub(crate) struct StaticBodies {
    pub(crate) identity: Vec<u8>,
    pub(crate) version: Vec<u8>,
    pub(crate) spec: Vec<u8>,
    pub(crate) fork_schedule: Vec<u8>,
    pub(crate) deposit_contract: Vec<u8>,
}

impl StaticBodies {
    pub(crate) fn new(
        keypair: &Keypair,
        local_enr: &Enr,
        identify: &Identify,
        spec: &SpecConfig,
    ) -> Self {
        Self {
            identity: build_identity_json(keypair, local_enr, identify),
            version: version_body(),
            spec: spec_body(spec),
            fork_schedule: fork_schedule_body(spec),
            deposit_contract: deposit_contract_body(spec),
        }
    }
}

fn version_body() -> Vec<u8> {
    let mut out = Vec::new();
    let mut json = Json::new(&mut out);
    json.begin_object();
    json.key("data");
    json.begin_object();
    json.key("version");
    json.string(AGENT_VERSION);
    json.end_object();
    json.end_object();
    out
}
