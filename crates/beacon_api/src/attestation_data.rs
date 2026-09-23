use silver_beacon_state_data::{B256, Checkpoint, Epoch, SLOTS_PER_EPOCH, Slot, StateReadView};
use silver_common::PayloadResolution;

use crate::{
    ids::parse_uint64,
    response::Response,
    router::Request,
    routes::{ApiCtx, query_value},
};

pub(crate) struct AttestationData {
    pub(crate) slot: Slot,
    pub(crate) index: u64,
    pub(crate) beacon_block_root: B256,
    pub(crate) source: Checkpoint,
    pub(crate) target: Checkpoint,
}

pub(crate) fn attestation_data(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    let (Some(slot), Some(committee_index)) =
        (uint64_query(req.query, "slot"), uint64_query(req.query, "committee_index"))
    else {
        resp.error(400, "slot and committee_index are required Uint64 query parameters");
        return;
    };
    if !ctx.follows_chain(resp) {
        return;
    }

    let epoch = slot / SLOTS_PER_EPOCH;
    if ctx.shufflings.committees_per_slot(epoch).is_some_and(|count| committee_index >= count) {
        resp.error(400, "committee_index is past the epoch's committee count");
        return;
    }

    let index = payload_presence_vote(ctx, slot);
    let Some(data) = ctx.read_state(|view| AttestationData::read(&view, slot, epoch, index)) else {
        resp.error(400, "attestation data is served for the head state's epoch only");
        return;
    };

    resp.json_body(|json| json.data_envelope(|json| json.attestation_data(&data)));
}

impl AttestationData {
    fn read(view: &StateReadView<'_>, slot: Slot, epoch: Epoch, index: u64) -> Option<Self> {
        if epoch != view.slot.current_epoch() {
            return None;
        }
        let state = view.slot.state();
        // The ring holds no root at or above the state's slot, and no block
        // has been processed there either, so the head is the block there.
        let block_at = |at: Slot| {
            if at >= state.slot { state.latest_block_root } else { view.block_roots.at_slot(at) }
        };
        Some(Self {
            slot,
            index,
            beacon_block_root: block_at(slot),
            source: view.epoch.state().current_justified_checkpoint,
            target: Checkpoint { epoch, root: block_at(epoch * SLOTS_PER_EPOCH) },
        })
    }
}

fn payload_presence_vote(ctx: &ApiCtx, slot: Slot) -> u64 {
    let present = ctx.spec.is_gloas_at_slot(slot) &&
        ctx.node_status.head.slot < slot &&
        ctx.node_status.head_payload == PayloadResolution::Full &&
        !ctx.node_status.execution_optimistic();
    u64::from(present)
}

fn uint64_query(query: &str, name: &str) -> Option<u64> {
    parse_uint64(&query_value(query, name)?)
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
        attester_duties::PostedShufflings,
        routes::test_ctx,
        testing::{answer, block_roots_ring, json, request, ring_root, status_code},
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
        ctx.node_status.head_payload = PayloadResolution::Full;
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

        let mut optimistic = ctx_at(STATE_SLOT, &gloas);
        optimistic.node_status.head.optimistic = true;
        assert_eq!(vote(&optimistic, STATE_SLOT + 1)["index"], "0");
    }
}
