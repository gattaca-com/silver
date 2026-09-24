use serde::Deserialize;
use silver_beacon_state_data::{B256, Checkpoint, Epoch, SLOTS_PER_EPOCH, Slot, StateReadView};
use silver_common::{
    PayloadResolution,
    ssz_view::{ATTESTATION_DATA_SIZE, AttestationDataView},
};

use crate::{
    ctx::ApiCtx,
    http::{
        ids::{bytes, parse_uint64, uint64},
        response::Response,
        router::Request,
    },
};

#[derive(Deserialize)]
pub(crate) struct AttestationData {
    #[serde(deserialize_with = "uint64")]
    pub(crate) slot: Slot,
    #[serde(deserialize_with = "uint64")]
    pub(crate) index: u64,
    #[serde(deserialize_with = "bytes")]
    pub(crate) beacon_block_root: B256,
    #[serde(deserialize_with = "CheckpointJson::deserialize")]
    pub(crate) source: Checkpoint,
    #[serde(deserialize_with = "CheckpointJson::deserialize")]
    pub(crate) target: Checkpoint,
}

/// The `slot` and `committee_index` every attester-side GET names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CommitteeQuery {
    pub(crate) slot: Slot,
    pub(crate) committee_index: u64,
}

impl CommitteeQuery {
    pub(crate) fn parse(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) -> Option<Self> {
        if !ctx.follows_chain(resp) {
            return None;
        }
        let (Some(slot), Some(committee_index)) =
            (uint64_query(req, "slot"), uint64_query(req, "committee_index"))
        else {
            resp.error(400, "slot and committee_index are required Uint64 query parameters");
            return None;
        };
        if ctx.node_status.execution_optimistic() {
            resp.error(503, "the head is optimistic, and validators must not attest to it");
            return None;
        }
        let epoch = slot / SLOTS_PER_EPOCH;
        if ctx.shufflings.committees_per_slot(epoch).is_some_and(|count| committee_index >= count) {
            resp.error(400, "committee_index is past the epoch's committee count");
            return None;
        }
        Some(Self { slot, committee_index })
    }
}

pub(crate) fn attestation_data(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    let Some(CommitteeQuery { slot, .. }) = CommitteeQuery::parse(req, ctx, resp) else {
        return;
    };
    if slot > ctx.node_status.wall_slot {
        resp.error(400, "slot is past the current slot");
        return;
    }

    let head_root = ctx.node_status.head_root;
    let head_payload = ctx.node_status.head_payload;
    let is_gloas = ctx.spec.is_gloas_at_slot(slot);
    match ctx
        .read_state(|view| AttestationData::read(&view, slot, head_root, head_payload, is_gloas))
    {
        Ok(data) => resp.json_body(|json| json.data_envelope(|json| json.attestation_data(&data))),
        Err(Unserved { code, message }) => resp.error(code, message),
    }
}

struct Unserved {
    code: u16,
    message: &'static str,
}

impl AttestationData {
    fn read(
        view: &StateReadView<'_>,
        slot: Slot,
        head_root: B256,
        head_payload: PayloadResolution,
        is_gloas: bool,
    ) -> Result<Self, Unserved> {
        let epoch = slot / SLOTS_PER_EPOCH;
        if epoch != view.slot.current_epoch() {
            return Err(Unserved {
                code: 400,
                message: "attestation data is served for the head state's epoch only",
            });
        }
        let state = view.slot.state();
        if state.latest_block_root != head_root {
            return Err(Unserved { code: 503, message: "the head is changing" });
        }

        // The ring holds roots for slots before the state's own only, and none
        // of those slots after the head block has a block of its own.
        let root_at =
            |s: Slot| if s < state.slot { view.block_roots.at_slot(s) } else { head_root };
        let beacon_block_root = root_at(slot);
        let index = if !is_gloas {
            0
        } else if beacon_block_root == head_root {
            u64::from(
                state.latest_block_header.slot < slot && head_payload == PayloadResolution::Full,
            )
        } else if slot > 0 && root_at(slot - 1) != beacon_block_root {
            0
        } else {
            return Err(Unserved {
                code: 400,
                message: "the payload status of a block behind the head is not tracked",
            });
        };

        Ok(Self {
            slot,
            index,
            beacon_block_root,
            source: view.epoch.state().current_justified_checkpoint,
            target: Checkpoint { epoch, root: root_at(epoch * SLOTS_PER_EPOCH) },
        })
    }
}

impl AttestationData {
    pub(crate) fn encode(&self, out: &mut [u8; ATTESTATION_DATA_SIZE]) {
        out[0..8].copy_from_slice(&self.slot.to_le_bytes());
        out[8..16].copy_from_slice(&self.index.to_le_bytes());
        out[16..48].copy_from_slice(&self.beacon_block_root);
        out[48..56].copy_from_slice(&self.source.epoch.to_le_bytes());
        out[56..88].copy_from_slice(&self.source.root);
        out[88..96].copy_from_slice(&self.target.epoch.to_le_bytes());
        out[96..128].copy_from_slice(&self.target.root);
    }
}

impl From<AttestationDataView<'_>> for AttestationData {
    fn from(view: AttestationDataView<'_>) -> Self {
        Self {
            slot: view.slot(),
            index: view.index(),
            beacon_block_root: *view.beacon_block_root(),
            source: Checkpoint { epoch: view.source_epoch(), root: *view.source_root() },
            target: Checkpoint { epoch: view.target_epoch(), root: *view.target_root() },
        }
    }
}

#[derive(Deserialize)]
#[serde(remote = "Checkpoint")]
struct CheckpointJson {
    #[serde(deserialize_with = "uint64")]
    epoch: Epoch,
    #[serde(deserialize_with = "bytes")]
    root: B256,
}

pub(crate) fn uint64_query(req: &Request<'_>, name: &str) -> Option<u64> {
    parse_uint64(&req.query_value(name)?)
}

#[cfg(test)]
mod tests {
    use silver_beacon_state_data::{
        BeaconBlockHeader, BeaconState, BeaconStateOwner, EpochState, EpochStateFinalized,
        SlotState, SlotStateFinalized, SlotStateGroup, SpecConfig,
    };
    use silver_common::SyncUpdate;
    use silver_httpcore::ParsedRequest;

    use super::*;
    use crate::{
        HeadStatus,
        ctx::test_ctx,
        testing::{answer, block_roots_ring, json, request, ring_root, status_code},
        validator::attester_duties::PostedShufflings,
    };

    const STATE_EPOCH: u64 = 300;
    const EPOCH_START: u64 = STATE_EPOCH * SLOTS_PER_EPOCH;
    const STATE_SLOT: u64 = EPOCH_START + 5;
    const HEAD_ROOT: B256 = [0x11; 32];

    fn justified() -> Checkpoint {
        Checkpoint { epoch: STATE_EPOCH - 1, root: [0x22; 32] }
    }

    /// A following node whose head state sits at `state_slot`, with the ring
    /// filled so a boundary root and the head root cannot be confused.
    fn ctx_at(state_slot: u64, spec: &SpecConfig) -> ApiCtx {
        let epoch = EpochState { current_justified_checkpoint: justified(), ..Default::default() };
        let mut state =
            BeaconState::for_test(EpochStateFinalized::from_state(epoch), &[], state_slot);
        state.slot_states = SlotStateGroup::new(SlotStateFinalized::new(SlotState {
            slot: state_slot,
            latest_block_header: BeaconBlockHeader { slot: state_slot, ..Default::default() },
            latest_block_root: HEAD_ROOT,
            ..Default::default()
        }));
        state.block_roots = block_roots_ring(state_slot);

        let mut owner = BeaconStateOwner::new(state);
        let anchor = owner.roll_fresh();
        owner.publish_state_id(anchor);

        let mut ctx = test_ctx(spec, owner.reader());
        ctx.node_status.head = HeadStatus { slot: state_slot, optimistic: false };
        ctx.node_status.head_root = HEAD_ROOT;
        ctx.node_status.head_payload = PayloadResolution::Full;
        ctx.node_status.wall_slot = state_slot + 1;
        ctx.node_status.target = Some(SyncUpdate::Following);
        ctx.shufflings.record(STATE_EPOCH, &[0u8; 4 * size_of::<u32>()]);
        ctx
    }

    fn mainnet_ctx() -> ApiCtx {
        ctx_at(STATE_SLOT, &SpecConfig::mainnet())
    }

    fn get(ctx: &ApiCtx, query: &str) -> Vec<u8> {
        answer(ctx, &ParsedRequest {
            query,
            ..request("GET", "/eth/v1/validator/attestation_data")
        })
    }

    fn vote(ctx: &ApiCtx, slot: u64) -> serde_json::Value {
        json(&get(ctx, &format!("slot={slot}&committee_index=0")))["data"].clone()
    }

    fn hex_root(root: &B256) -> String {
        format!("0x{}", hex::encode(root))
    }

    #[test]
    fn vote_names_the_head_the_boundary_root_and_the_justified_checkpoint() {
        let data = vote(&mainnet_ctx(), STATE_SLOT);
        assert_eq!(data["slot"], STATE_SLOT.to_string());
        assert_eq!(data["index"], "0");
        assert_eq!(data["beacon_block_root"], hex_root(&HEAD_ROOT));
        assert_eq!(data["source"]["epoch"], justified().epoch.to_string());
        assert_eq!(data["source"]["root"], hex_root(&justified().root));
        assert_eq!(data["target"]["epoch"], STATE_EPOCH.to_string());
        assert_eq!(data["target"]["root"], hex_root(&ring_root(EPOCH_START)));
    }

    /// The ring holds no root at or past the head state's slot, so an epoch
    /// starting there votes the head itself as its boundary.
    #[test]
    fn target_is_the_head_when_the_epoch_starts_at_the_head_state_slot() {
        let ctx = ctx_at(EPOCH_START, &SpecConfig::mainnet());
        assert_eq!(vote(&ctx, EPOCH_START)["target"]["root"], hex_root(&HEAD_ROOT));
    }

    /// A vote for an earlier slot must name a block from at or before that
    /// slot, or fork choice discards it as a vote for a future block.
    #[test]
    fn vote_for_an_earlier_slot_names_the_block_at_that_slot() {
        let data = vote(&mainnet_ctx(), STATE_SLOT - 1);
        assert_eq!(data["beacon_block_root"], hex_root(&ring_root(STATE_SLOT - 1)));
        assert_eq!(data["target"]["root"], hex_root(&ring_root(EPOCH_START)));
    }

    /// The posted shuffling bounds the committee index; without one there is
    /// nothing to bound it against and the vote is served anyway.
    #[test]
    fn committee_index_past_the_posted_committees_is_400() {
        let mut ctx = mainnet_ctx();
        let past_the_count =
            ctx.shufflings.committees_per_slot(STATE_EPOCH).expect("the fixture posts a shuffling");
        let query = format!("slot={STATE_SLOT}&committee_index={past_the_count}");
        assert_eq!(status_code(&get(&ctx, &query)), "400");

        ctx.shufflings = PostedShufflings::default();
        assert_eq!(status_code(&get(&ctx, &query)), "200");
    }

    /// EIP-7732's payload-presence vote: the head's resolution decides it, and
    /// a head from the attested slot cannot carry one.
    #[test]
    fn gloas_votes_the_payload_present_only_for_a_resolved_earlier_head() {
        let gloas = SpecConfig { gloas_fork_epoch: 0, ..SpecConfig::mainnet() };
        let ctx = ctx_at(STATE_SLOT, &gloas);
        assert_eq!(vote(&ctx, STATE_SLOT + 1)["index"], "1");
        assert_eq!(vote(&ctx, STATE_SLOT)["index"], "0");

        let mut empty_payload = ctx_at(STATE_SLOT, &gloas);
        empty_payload.node_status.head_payload = PayloadResolution::Empty;
        assert_eq!(vote(&empty_payload, STATE_SLOT + 1)["index"], "0");
    }

    /// The state read and the announced head disagree while a new head is
    /// being published; the vote waits rather than mix the two.
    #[test]
    fn state_off_the_announced_head_is_503() {
        let mut ctx = mainnet_ctx();
        ctx.node_status.head_root = [0x99; 32];
        assert_eq!(status_code(&get(&ctx, &format!("slot={STATE_SLOT}&committee_index=0"))), "503");
    }
}
