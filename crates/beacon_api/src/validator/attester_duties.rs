use silver_beacon_state_data::{
    BLSPubkey, Epoch, SLOTS_PER_EPOCH, ShufflingId, Slot, StateReadView, committee_at_position,
};

use crate::{
    ctx::ApiCtx,
    http::{response::Response, router::Request},
    validator::{
        duties::{epoch_param, requested_indices},
        shufflings::Shuffling,
    },
};

pub(crate) fn post_attester_duties(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    if !ctx.follows_chain(resp) {
        return;
    }
    let Some(epoch) = epoch_param(req, resp) else {
        return;
    };
    let Some(indices) = requested_indices(req, resp) else {
        return;
    };
    let result = resp.try_json_body(|json| {
        ctx.read_state(|view| {
            json.restart();
            let state_epoch = view.slot.current_epoch();
            if epoch < state_epoch || epoch > state_epoch + 1 {
                return Err((
                    400,
                    "attester duties cover the head state's epoch and the one after it",
                ));
            }
            if view.slot.state().latest_block_root != ctx.node_status.head_root {
                return Err((503, "the head is changing"));
            }
            let Some(id) = ShufflingId::from_state(&view, epoch) else {
                return Err((503, "the shuffling's dependent root is unavailable"));
            };
            let Some(shuffling) = ctx.shufflings.get(id) else {
                return Err((503, "the head state's shuffling for this epoch has not been posted"));
            };
            json.attester_duties(
                id.dependent_root,
                ctx.node_status.execution_optimistic(),
                indices.iter().filter_map(|&validator_index| {
                    AttesterDuty::read(&view, shuffling, epoch, validator_index)
                }),
            );
            Ok(())
        })
    });
    if let Err((code, message)) = result {
        resp.error(code, message);
    }
}

pub(crate) struct AttesterDuty {
    pub(crate) pubkey: BLSPubkey,
    pub(crate) validator_index: u64,
    pub(crate) committee_index: u64,
    pub(crate) committee_length: u64,
    pub(crate) committees_at_slot: u64,
    pub(crate) validator_committee_index: u64,
    pub(crate) slot: Slot,
}

impl AttesterDuty {
    /// `None` for an index the epoch's shuffling does not place, which is
    /// every index naming no active validator.
    fn read(
        view: &StateReadView<'_>,
        shuffling: &Shuffling,
        epoch: Epoch,
        validator_index: u64,
    ) -> Option<Self> {
        let committees_at_slot = shuffling.committees_per_slot();
        let position = shuffling.position(validator_index)? as usize;
        let index =
            usize::try_from(validator_index).ok().filter(|&ix| ix < view.validators.count())?;
        let committee =
            committee_at_position(shuffling.shuffled_len(), committees_at_slot, position);
        Some(Self {
            pubkey: *view.validators.pubkey(index),
            validator_index,
            committee_index: committee.committee_index as u64,
            committee_length: committee.members.len() as u64,
            committees_at_slot: committees_at_slot as u64,
            validator_committee_index: (position - committee.members.start) as u64,
            slot: epoch * SLOTS_PER_EPOCH + committee.slot_in_epoch,
        })
    }
}

#[cfg(test)]
mod tests {
    use silver_beacon_state_data::{
        BeaconBlockHeader, BeaconState, BeaconStateOwner, EpochStateFinalized, SlotState,
        SlotStateFinalized, SlotStateGroup, SpecConfig, StateId, ValSeed, committee_range,
        committees_per_slot,
    };
    use silver_common::SyncUpdate;

    use super::*;
    use crate::{
        ctx::test_ctx,
        testing::{
            answer, block_roots_ring, field, indices_body, json, posting, pubkey, ring_root,
            status_code,
        },
        validator::shufflings::PostedShufflings,
    };

    const ACTIVE: u64 = 8192;
    const STATE_EPOCH: u64 = 300;
    const STATE_SLOT: u64 = STATE_EPOCH * SLOTS_PER_EPOCH + 5;
    const HEAD_SLOT: u64 = STATE_SLOT - 2;

    /// The posted order for `epoch`: the active set reversed, rotated by the
    /// epoch so the two epochs differ.
    fn posted_order(epoch: u64) -> Vec<u32> {
        (0..ACTIVE as u32).rev().map(|i| (i + epoch as u32) % ACTIVE as u32).collect()
    }

    fn posted_bytes(epoch: u64) -> Vec<u8> {
        posted_order(epoch).iter().flat_map(|i| i.to_le_bytes()).collect()
    }

    /// `ACTIVE` validators plus one the request may name that no committee
    /// holds, with the shufflings of the state's epoch and the next posted.
    fn ctx() -> ApiCtx {
        ctx_with_owner().0
    }

    fn ctx_with_owner() -> (ApiCtx, BeaconStateOwner, StateId) {
        let seeds: Vec<_> =
            (0..=ACTIVE).map(|i| ValSeed { pubkey: pubkey(i), ..ValSeed::default() }).collect();
        let mut state = BeaconState::for_test(EpochStateFinalized::default(), &seeds, STATE_SLOT);
        state.slot_states = SlotStateGroup::new(SlotStateFinalized::new(SlotState {
            slot: STATE_SLOT,
            latest_block_header: BeaconBlockHeader { slot: HEAD_SLOT, ..Default::default() },
            ..Default::default()
        }));
        state.block_roots = block_roots_ring(STATE_SLOT);

        let mut owner = BeaconStateOwner::new(state);
        let anchor = owner.roll_fresh();
        owner.publish_state_id(anchor);
        let mut ctx = test_ctx(&SpecConfig::mainnet(), owner.reader());
        ctx.node_status.target = Some(SyncUpdate::Following);
        for epoch in [STATE_EPOCH, STATE_EPOCH + 1] {
            let id = ctx.read_state(|view| ShufflingId::from_state(&view, epoch).unwrap());
            ctx.shufflings.record(id, &posted_bytes(epoch));
        }
        (ctx, owner, anchor)
    }

    fn post(ctx: &ApiCtx, epoch: &str, body: &str) -> Vec<u8> {
        answer(ctx, &posting(&format!("/eth/v1/validator/duties/attester/{epoch}"), body))
    }

    /// Every posted validator sits in exactly one committee of the epoch, at
    /// the position the posted order gives it, and the unposted one in none.
    #[test]
    fn duties_follow_the_posted_shuffling_for_both_epochs() {
        let ctx = ctx();
        for epoch in [STATE_EPOCH, STATE_EPOCH + 1] {
            let body = json(&post(&ctx, &epoch.to_string(), &indices_body(0..=ACTIVE)));
            let duties = body["data"].as_array().unwrap();
            assert_eq!(duties.len(), ACTIVE as usize);

            let order = posted_order(epoch);
            let per_slot = committees_per_slot(order.len());
            let mut seen = vec![false; ACTIVE as usize];
            for duty in duties {
                let index = field(duty, "validator_index");
                let slot = field(duty, "slot");
                assert_eq!(slot / SLOTS_PER_EPOCH, epoch);
                let committee = &order[committee_range(
                    order.len(),
                    per_slot,
                    slot,
                    field(duty, "committee_index") as usize,
                )];
                assert_eq!(
                    committee[field(duty, "validator_committee_index") as usize],
                    index as u32
                );
                assert_eq!(field(duty, "committee_length") as usize, committee.len());
                assert_eq!(field(duty, "committees_at_slot") as usize, per_slot);
                assert_eq!(
                    duty["pubkey"].as_str().unwrap(),
                    format!("0x{}", hex::encode(pubkey(index)))
                );
                assert!(!std::mem::replace(&mut seen[index as usize], true), "{index} twice");
            }
            assert!(seen.iter().all(|&once| once));

            let expected = ring_root((epoch - 1) * SLOTS_PER_EPOCH - 1);
            assert_eq!(body["dependent_root"], format!("0x{}", hex::encode(expected)));
            assert_eq!(body["execution_optimistic"], false);
        }
    }

    #[test]
    fn only_the_requested_validators_answer_and_unknown_indices_are_dropped() {
        let ctx = ctx();
        let body = json(&post(&ctx, &STATE_EPOCH.to_string(), "[\"7\",\"7\",\"42\",\"9999\"]"));
        let mut indices: Vec<_> =
            body["data"].as_array().unwrap().iter().map(|d| field(d, "validator_index")).collect();
        indices.sort_unstable();
        assert_eq!(indices, [7, 42]);
    }

    /// An epoch the head state will never cover is a 400; one it covers but
    /// has not posted yet is the 503 that asks the client back.
    #[test]
    fn epochs_off_the_window_are_400_and_unposted_ones_503() {
        let ctx = ctx();
        for epoch in [STATE_EPOCH - 1, STATE_EPOCH + 2] {
            assert_eq!(status_code(&post(&ctx, &epoch.to_string(), "[\"0\"]")), "400", "{epoch}");
        }

        let mut unposted = ctx;
        unposted.shufflings = PostedShufflings::default();
        for epoch in [STATE_EPOCH, STATE_EPOCH + 1] {
            let response = post(&unposted, &epoch.to_string(), "[\"0\"]");
            assert_eq!(status_code(&response), "503", "{epoch}");
        }
    }

    #[test]
    fn duties_are_503_until_the_node_follows_the_chain() {
        let mut ctx = ctx();
        ctx.node_status.target = None;
        assert_eq!(status_code(&post(&ctx, &STATE_EPOCH.to_string(), "[\"0\"]")), "503");
    }

    #[test]
    fn duties_wait_for_the_selected_branch_shuffling() {
        let (mut ctx, mut owner, anchor) = ctx_with_owner();
        let epoch = STATE_EPOCH.to_string();
        assert_eq!(status_code(&post(&ctx, &epoch, "[\"0\"]")), "200");

        let mut fork = owner.apply_block_view(anchor);
        let decision_slot = (STATE_EPOCH - 1) * SLOTS_PER_EPOCH - 1;
        fork.view.block_roots.set((decision_slot % 8192) as u32, [0xBB; 32]);
        fork.view.randao_mixes.mix_in_reveal(STATE_EPOCH - 2, &[0xBB; 32]);
        fork.view.slot.state_mut().latest_block_root = [0xB0; 32];
        let branch = fork.commit();
        owner.publish_state_id(branch);
        ctx.node_status.head_root = [0xB0; 32];

        assert_eq!(status_code(&post(&ctx, &epoch, "[\"0\"]")), "503");
        let branch_id = ctx.read_state(|view| ShufflingId::from_state(&view, STATE_EPOCH).unwrap());
        ctx.shufflings.record(branch_id, &posted_bytes(STATE_EPOCH + 1));
        let response = post(&ctx, &epoch, "[\"0\"]");
        assert_eq!(status_code(&response), "200");
        assert_eq!(
            json(&response)["dependent_root"],
            format!("0x{}", hex::encode(branch_id.dependent_root))
        );

        owner.publish_state_id(anchor);
        ctx.node_status.head_root = [0; 32];
        assert_eq!(status_code(&post(&ctx, &epoch, "[\"0\"]")), "503");
        let original_id =
            ctx.read_state(|view| ShufflingId::from_state(&view, STATE_EPOCH).unwrap());
        ctx.shufflings.record(original_id, &posted_bytes(STATE_EPOCH));
        assert_eq!(status_code(&post(&ctx, &epoch, "[\"0\"]")), "200");

        ctx.node_status.head_root = [0xB0; 32];
        assert_eq!(
            status_code(&post(&ctx, &epoch, "[\"0\"]")),
            "503",
            "metadata from another head must not accompany duties"
        );
    }

    /// `attester.yaml` asks for `minItems: 1`, so an empty array is no more a
    /// request than a malformed one.
    #[test]
    fn malformed_and_empty_bodies_are_400() {
        let ctx = ctx();
        assert_eq!(status_code(&post(&ctx, "x", "[\"0\"]")), "400");
        for body in ["", "{}", "[]", "[0]", "[\"-1\"]", "[\"a\"]"] {
            assert_eq!(status_code(&post(&ctx, &STATE_EPOCH.to_string(), body)), "400", "{body:?}");
        }
    }
}
