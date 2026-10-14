use std::iter;

use silver_beacon_state_data::{
    BLSPubkey, Epoch, SLOTS_PER_EPOCH, ShufflingId, Slot, StateReadView, gloas::PtcCommittee,
};

use crate::{
    ctx::ApiCtx,
    http::{response::Response, router::Request},
    validator::duties::{epoch_param, requested_indices},
};

/// Lighthouse and Prysm VCs poll the current and the next epoch, from the
/// epoch before the Gloas fork on.
pub(crate) fn post_ptc_duties(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
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
                return Err((400, "PTC duties cover the head state's epoch and the one after it"));
            }
            if view.slot.state().latest_block_root != ctx.node_status.head_root {
                return Err((503, "the head is changing"));
            }
            let is_gloas_epoch = epoch >= ctx.spec.gloas_fork_epoch;
            // An empty answer here would be cached against a dependent root
            // the fork transition does not change.
            if is_gloas_epoch && !view.is_gloas() {
                return Err((503, "the fork epoch's PTC exists once the head state is Gloas"));
            }
            let Some(id) = ShufflingId::from_state(&view, epoch) else {
                return Err((503, "the duties' dependent root is unavailable"));
            };
            let optimistic = ctx.node_status.execution_optimistic();
            if !is_gloas_epoch {
                json.ptc_duties(id.dependent_root, optimistic, iter::empty());
                return Ok(());
            }
            let committees = view
                .epoch
                .ptc_window()
                .epoch_committees(state_epoch, epoch)
                .expect("the window holds the state's epoch and the next");
            json.ptc_duties(
                id.dependent_root,
                optimistic,
                PtcDuty::read_epoch(&view, committees, epoch, &indices).into_iter(),
            );
            Ok(())
        })
    });
    if let Err((code, message)) = result {
        resp.error(code, message);
    }
}

pub(crate) struct PtcDuty {
    pub(crate) pubkey: BLSPubkey,
    pub(crate) validator_index: u64,
    pub(crate) slot: Slot,
}

impl PtcDuty {
    /// One duty per slot whose PTC holds a requested validator, as Prysm and
    /// Nimbus answer: balance-weighted selection can seat a validator in
    /// several slots, and spec `get_ptc_assignment` names only the first.
    /// `indices` is sorted.
    fn read_epoch(
        view: &StateReadView<'_>,
        committees: &[PtcCommittee],
        epoch: Epoch,
        indices: &[u64],
    ) -> Vec<Self> {
        let mut duties = Vec::new();
        let mut members = Vec::new();
        for (slot_in_epoch, committee) in committees.iter().enumerate() {
            members.clear();
            members.extend(committee.iter().filter(|ix| indices.binary_search(ix).is_ok()));
            members.sort_unstable();
            members.dedup();
            let slot = epoch * SLOTS_PER_EPOCH + slot_in_epoch as u64;
            duties.extend(members.iter().filter_map(|&validator_index| {
                let ix = usize::try_from(validator_index)
                    .ok()
                    .filter(|&ix| ix < view.validators.count())?;
                Some(Self { pubkey: *view.validators.pubkey(ix), validator_index, slot })
            }));
        }
        duties
    }
}

#[cfg(test)]
mod tests {
    use silver_beacon_state_data::{
        BeaconBlockHeader, BeaconState, BeaconStateOwner, EpochState, EpochStateFinalized, Fork,
        SlotState, SlotStateFinalized, SlotStateGroup, SpecConfig, ValSeed,
        gloas::{GLOAS_FORK_VERSION, zeroed_ptc_window},
    };
    use silver_common::SyncUpdate;

    use super::*;
    use crate::{
        ctx::test_ctx,
        testing::{answer, block_roots_ring, field, json, posting, pubkey, ring_root, status_code},
    };

    const VALIDATORS: u64 = 64;
    const STATE_EPOCH: u64 = 300;
    const STATE_SLOT: u64 = STATE_EPOCH * SLOTS_PER_EPOCH + 5;
    const SPE: usize = SLOTS_PER_EPOCH as usize;

    /// Validator 7 sits twice in slot 3 and once in slot 5 of the state's
    /// epoch, 42 in slot 0 of the next, and 9 only in the previous epoch's
    /// window.
    fn ctx(gloas_fork_epoch: Epoch, head_is_gloas: bool) -> ApiCtx {
        let seeds: Vec<_> =
            (0..VALIDATORS).map(|i| ValSeed { pubkey: pubkey(i), ..ValSeed::default() }).collect();
        let fork_version = if head_is_gloas { GLOAS_FORK_VERSION } else { [0; 4] };
        let epoch_state = EpochState {
            fork: Fork { current_version: fork_version, ..Fork::default() },
            ..EpochState::default()
        };
        let mut state =
            BeaconState::for_test(EpochStateFinalized::from_state(epoch_state), &seeds, STATE_SLOT);
        state.slot_states = SlotStateGroup::new(SlotStateFinalized::new(SlotState {
            slot: STATE_SLOT,
            latest_block_header: BeaconBlockHeader { slot: STATE_SLOT - 2, ..Default::default() },
            ..Default::default()
        }));
        state.block_roots = block_roots_ring(STATE_SLOT);

        let mut window = zeroed_ptc_window();
        window[SPE + 3][10] = 7;
        window[SPE + 3][11] = 7;
        window[SPE + 5][20] = 7;
        window[2 * SPE][0] = 42;
        window[4][0] = 9;

        let mut owner = BeaconStateOwner::new(state);
        let anchor = owner.roll_fresh();
        let mut fork = owner.apply_block_view(anchor);
        let mut epoch = fork.epoch.roll_fresh();
        epoch.set_ptc_window(window);
        fork.epoch_idx = Some(epoch.commit());
        let head = fork.commit();
        owner.publish_state_id(head);

        let spec = SpecConfig { gloas_fork_epoch, ..SpecConfig::mainnet() };
        let mut ctx = test_ctx(&spec, owner.reader());
        ctx.node_status.target = Some(SyncUpdate::Following);
        ctx
    }

    fn post(ctx: &ApiCtx, epoch: u64, body: &str) -> Vec<u8> {
        answer(ctx, &posting(&format!("/eth/v1/validator/duties/ptc/{epoch}"), body))
    }

    fn duty_slots(response: &[u8]) -> Vec<(u64, u64)> {
        json(response)["data"]
            .as_array()
            .unwrap()
            .iter()
            .map(|duty| (field(duty, "validator_index"), field(duty, "slot")))
            .collect()
    }

    #[test]
    fn duties_name_every_ptc_slot_of_the_requested_epoch_once() {
        let ctx = ctx(0, true);
        let body = "[\"7\",\"9\",\"42\",\"9999\"]";

        let current = post(&ctx, STATE_EPOCH, body);
        let first_slot = STATE_EPOCH * SLOTS_PER_EPOCH;
        assert_eq!(duty_slots(&current), [(7, first_slot + 3), (7, first_slot + 5)]);
        let duty = &json(&current)["data"][0];
        assert_eq!(duty["pubkey"].as_str().unwrap(), format!("0x{}", hex::encode(pubkey(7))));

        let next = post(&ctx, STATE_EPOCH + 1, body);
        assert_eq!(duty_slots(&next), [(42, first_slot + SLOTS_PER_EPOCH)]);

        for (epoch, response) in [(STATE_EPOCH, current), (STATE_EPOCH + 1, next)] {
            let expected = ring_root((epoch - 1) * SLOTS_PER_EPOCH - 1);
            assert_eq!(json(&response)["dependent_root"], format!("0x{}", hex::encode(expected)));
            assert_eq!(json(&response)["execution_optimistic"], false);
        }
    }

    /// The VC polls from the epoch before the fork. That epoch has no PTC,
    /// and the fork epoch's waits for the Gloas head state.
    #[test]
    fn pre_fork_epochs_are_empty_and_the_fork_epoch_waits_for_a_gloas_head() {
        let ctx = ctx(STATE_EPOCH + 1, false);
        let before = post(&ctx, STATE_EPOCH, "[\"7\"]");
        assert_eq!(status_code(&before), "200");
        assert!(duty_slots(&before).is_empty());
        assert_eq!(status_code(&post(&ctx, STATE_EPOCH + 1, "[\"42\"]")), "503");
    }

    #[test]
    fn epochs_off_the_window_and_malformed_bodies_are_400() {
        let ctx = ctx(0, true);
        for epoch in [STATE_EPOCH - 1, STATE_EPOCH + 2] {
            assert_eq!(status_code(&post(&ctx, epoch, "[\"7\"]")), "400", "{epoch}");
        }
        for body in ["", "[]", "[7]"] {
            assert_eq!(status_code(&post(&ctx, STATE_EPOCH, body)), "400", "{body:?}");
        }
    }

    #[test]
    fn duties_are_503_until_the_node_follows_the_chain() {
        let mut ctx = ctx(0, true);
        ctx.node_status.target = None;
        assert_eq!(status_code(&post(&ctx, STATE_EPOCH, "[\"7\"]")), "503");
    }
}
