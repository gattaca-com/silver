#[cfg(test)]
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[cfg(test)]
use silver_beacon_state_data::BeaconStateOwner;
use silver_beacon_state_data::{BeaconStateReader, SLOTS_PER_EPOCH, SpecConfig, StateReadView};
use silver_common::{Enr, Identify, Keypair};

use crate::{
    NodeStatus,
    config::spec_body,
    http::{
        ids::is_recognized_id,
        json::{Json, ReadFlags, deposit_contract_body, fork_schedule_body, version_body},
        response::Response,
        router::Request,
    },
    node::{identity::identity_body, peers::PeerTable},
    validator::attester_duties::PostedShufflings,
};

pub(crate) struct ApiCtx {
    pub(crate) statics: StaticBodies,
    pub(crate) spec: SpecConfig,
    pub(crate) state: BeaconStateReader,
    pub(crate) node_status: NodeStatus,
    pub(crate) peers: PeerTable,
    pub(crate) shufflings: PostedShufflings,
}

impl ApiCtx {
    pub(crate) fn new(
        keypair: &Keypair,
        local_enr: &Enr,
        identify: &Identify,
        spec: &SpecConfig,
        state: BeaconStateReader,
    ) -> Self {
        let (head_slot, anchor_root, anchor_epoch) = state
            .read(|view: StateReadView<'_>| {
                let slot = view.slot.state();
                (slot.latest_block_header.slot, slot.latest_block_root, slot.slot / SLOTS_PER_EPOCH)
            })
            .expect("beacon api needs the anchor state published");
        Self {
            statics: StaticBodies::new(keypair, local_enr, identify, spec),
            spec: spec.clone(),
            state,
            node_status: NodeStatus::at_anchor(head_slot, anchor_root, anchor_epoch),
            peers: PeerTable::new(),
            shufflings: PostedShufflings::default(),
        }
    }

    pub(crate) fn read_state<R>(&self, read: impl FnMut(StateReadView<'_>) -> R) -> R {
        self.state.read(read).expect("beacon api needs the anchor state published")
    }

    /// Resolves `{state_id}` and reads from the state it names, alongside the
    /// flags those schemas require beside `data`. `read` runs under the seqlock
    /// and is re-run whole on retry, so it lifts out what the body needs and
    /// rendering happens afterwards.
    pub(crate) fn state_read<R>(
        &self,
        req: &Request<'_>,
        resp: &mut Response<'_>,
        mut read: impl FnMut(StateReadView<'_>) -> R,
    ) -> Option<StateRead<R>> {
        if !self.serves_state(req, resp) {
            return None;
        }
        let node_status = self.node_status;
        let read = |view: StateReadView<'_>| StateRead {
            flags: read_flags(node_status, &view),
            data: read(view),
        };
        Some(self.read_state(read))
    }

    /// A `{state_id}` read whose body is the envelope around `render`, written
    /// under the read straight into the response. `render` runs again from an
    /// empty body on retry.
    pub(crate) fn state_response(
        &self,
        req: &Request<'_>,
        resp: &mut Response<'_>,
        mut render: impl FnMut(&StateReadView<'_>, &mut Json<'_>),
    ) {
        if !self.serves_state(req, resp) {
            return;
        }
        let node_status = self.node_status;
        resp.json_body(|json| {
            self.read_state(|view| {
                json.restart();
                json.flagged_envelope(read_flags(node_status, &view), |json| render(&view, json));
            });
        });
    }

    pub(crate) fn follows_chain(&self, resp: &mut Response<'_>) -> bool {
        if self.node_status.is_following() {
            return true;
        }
        resp.error(503, "api unavailable while the node is syncing");
        false
    }

    /// Whether `{state_id}` names the one state silver serves, having answered
    /// the request when it does not.
    fn serves_state(&self, req: &Request<'_>, resp: &mut Response<'_>) -> bool {
        let state_id = req.params.get("state_id").expect("{state_id} in the route pattern");
        if state_id == "head" {
            return true;
        }
        if is_recognized_id(state_id) {
            resp.error(404, "state not found");
        } else {
            resp.error(400, "invalid state_id");
        }
        false
    }
}

/// One state read: the flags describe the snapshot `data` came from.
pub(crate) struct StateRead<R> {
    pub(crate) flags: ReadFlags,
    pub(crate) data: R,
}

fn read_flags(node_status: NodeStatus, view: &StateReadView<'_>) -> ReadFlags {
    ReadFlags {
        execution_optimistic: node_status.execution_optimistic(),
        finalized: node_status.is_finalized(view.slot.state().latest_block_header.slot),
    }
}

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
            identity: identity_body(keypair, local_enr, identify),
            version: version_body(),
            spec: spec_body(spec),
            fork_schedule: fork_schedule_body(spec),
            deposit_contract: deposit_contract_body(spec),
        }
    }
}

/// A node right after bootstrap: an empty anchor published at slot 0.
#[cfg(test)]
pub(crate) fn anchor_ctx() -> ApiCtx {
    test_ctx(&SpecConfig::mainnet(), BeaconStateOwner::published_empty_test(0).reader())
}

#[cfg(test)]
pub(crate) fn test_ctx(spec: &SpecConfig, state: BeaconStateReader) -> ApiCtx {
    let keypair = Keypair::from_secret(&[1u8; 32]).unwrap();
    let enr = Enr::builder().build(keypair.secret_key()).unwrap();
    let mut identify = Identify::default();
    identify.tcp_ipv4 = Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 9000));
    ApiCtx::new(&keypair, &enr, &identify, spec, state)
}
