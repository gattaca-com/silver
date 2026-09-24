use silver_beacon_state_data::{
    B256, BLSPubkey, Epoch, MIN_SEED_LOOKAHEAD, SLOTS_PER_EPOCH, Slot, StateReadView,
};

use crate::{
    ctx::ApiCtx,
    http::{response::Response, router::Request},
    validator::duties::epoch_param,
};

pub(crate) fn proposer_duties(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    respond(req, ctx, resp, 0);
}

/// `proposer.v2.yaml` decides one epoch earlier than `proposer.yaml`: with the
/// proposer lookahead, an epoch's proposers are fixed before the epoch before
/// it begins.
pub(crate) fn proposer_duties_v2(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    respond(req, ctx, resp, 1);
}

fn respond(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>, epochs_back: u64) {
    if !ctx.follows_chain(resp) {
        return;
    }
    let Some(epoch) = epoch_param(req, resp) else {
        return;
    };

    let head_root = ctx.node_status.head_root;
    let duties = ctx.read_state(|view| {
        ProposerDuties::read(&view, epoch, epoch.saturating_sub(epochs_back), head_root)
    });
    let Some(duties) = duties else {
        resp.error(400, "epoch outside the proposer lookahead of the head state");
        return;
    };
    resp.json_body(|json| {
        json.proposer_duties(
            duties.dependent_root,
            ctx.node_status.execution_optimistic(),
            duties.duties.iter(),
        )
    });
}

pub(crate) struct ProposerDuties {
    pub(crate) dependent_root: B256,
    pub(crate) duties: [ProposerDuty; SLOTS_PER_EPOCH as usize],
}

pub(crate) struct ProposerDuty {
    pub(crate) pubkey: BLSPubkey,
    pub(crate) validator_index: u64,
    pub(crate) slot: Slot,
}

impl ProposerDuties {
    /// `None` for an epoch the head state cannot answer for: its lookahead
    /// holds the state's own epoch and the `MIN_SEED_LOOKAHEAD` after it.
    fn read(
        view: &StateReadView<'_>,
        epoch: Epoch,
        dependent_epoch: Epoch,
        head_root: B256,
    ) -> Option<Self> {
        let state_slot = view.slot.state().slot;
        let state_epoch = state_slot / SLOTS_PER_EPOCH;
        if epoch < state_epoch || epoch > state_epoch + MIN_SEED_LOOKAHEAD {
            return None;
        }

        let start_slot = epoch * SLOTS_PER_EPOCH;
        let lookahead_start = (start_slot - state_epoch * SLOTS_PER_EPOCH) as usize;
        let mut proposers = [0u64; SLOTS_PER_EPOCH as usize];
        for (offset, proposer) in proposers.iter_mut().enumerate() {
            let lookahead_idx = lookahead_start + offset;
            let Some(found) = view.epoch.proposer_at(lookahead_idx) else {
                tracing::error!(
                    epoch,
                    state_epoch,
                    lookahead_idx,
                    "proposer lookahead is shorter than the window it must cover"
                );
                return None;
            };
            *proposer = found;
        }

        let duties = std::array::from_fn(|offset| ProposerDuty {
            pubkey: *view.validators.pubkey(proposers[offset] as usize),
            validator_index: proposers[offset],
            slot: start_slot + offset as u64,
        });
        let dependent_root =
            view.block_roots.duty_dependent_root(dependent_epoch, head_root, state_slot)?;
        Some(Self { dependent_root, duties })
    }
}

#[cfg(test)]
mod tests {
    use silver_beacon_state_data::{
        BeaconBlockHeader, BeaconState, BeaconStateOwner, EpochState, EpochStateFinalized,
        PROPOSER_LOOKAHEAD_SIZE, SlotState, SlotStateFinalized, SlotStateGroup, SpecConfig,
        ValSeed,
    };
    use silver_common::SyncUpdate;

    use super::*;
    use crate::{
        ctx::test_ctx,
        testing::{self, answer, block_roots_ring, request, ring_root, status_code},
    };

    const STATE_EPOCH: u64 = 300;
    const STATE_SLOT: u64 = STATE_EPOCH * SLOTS_PER_EPOCH + 5;
    const HEAD_SLOT: u64 = STATE_SLOT - 2;
    const HEAD_ROOT: B256 = [0xdd; 32];

    fn ctx() -> ApiCtx {
        ctx_at(STATE_SLOT, HEAD_SLOT)
    }

    /// Three validators; the lookahead rotates through them so each slot's
    /// proposer is `slot % 3`.
    fn ctx_at(state_slot: Slot, head_slot: Slot) -> ApiCtx {
        let seeds: Vec<_> =
            (0..3u8).map(|i| ValSeed { pubkey: [0xa0 + i; 48], ..ValSeed::default() }).collect();
        let epoch = EpochState {
            proposer_lookahead: std::array::from_fn(|i| {
                (STATE_EPOCH * SLOTS_PER_EPOCH + i as u64) % 3
            }),
            ..Default::default()
        };
        let mut state =
            BeaconState::for_test(EpochStateFinalized::from_state(epoch), &seeds, state_slot);
        state.slot_states = SlotStateGroup::new(SlotStateFinalized::new(SlotState {
            slot: state_slot,
            latest_block_header: BeaconBlockHeader { slot: head_slot, ..Default::default() },
            ..Default::default()
        }));
        state.block_roots = block_roots_ring(state_slot);

        let mut owner = BeaconStateOwner::new(state);
        let anchor = owner.roll_fresh();
        owner.publish_state_id(anchor);
        let mut ctx = test_ctx(&SpecConfig::mainnet(), owner.reader());
        ctx.node_status.head_root = HEAD_ROOT;
        ctx.node_status.target = Some(SyncUpdate::Following);
        ctx
    }

    fn get(path: &str) -> Vec<u8> {
        get_from(&ctx(), path)
    }

    fn get_from(ctx: &ApiCtx, path: &str) -> Vec<u8> {
        answer(ctx, &request("GET", path))
    }

    fn body(response: &[u8]) -> String {
        assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"), "{:?}", status_code(response));
        String::from_utf8(testing::body(response).to_vec()).unwrap()
    }

    fn hex(bytes: &[u8]) -> String {
        format!("0x{}", hex::encode(bytes))
    }

    fn expected(dependent_root: B256, epoch: u64) -> String {
        let duties: Vec<_> = (epoch * SLOTS_PER_EPOCH..(epoch + 1) * SLOTS_PER_EPOCH)
            .map(|slot| {
                format!(
                    "{{\"pubkey\":\"{}\",\"validator_index\":\"{}\",\"slot\":\"{slot}\"}}",
                    hex(&[0xa0 + (slot % 3) as u8; 48]),
                    slot % 3
                )
            })
            .collect();
        format!(
            "{{\"dependent_root\":\"{}\",\"execution_optimistic\":false,\"data\":[{}]}}",
            hex(&dependent_root),
            duties.join(",")
        )
    }

    /// Body shape: `apis/validator/duties/proposer.yaml`. Both covered epochs
    /// come from the lookahead, and the v1 dependent root is the root before
    /// the epoch, or the head itself for the epoch still ahead of it.
    #[test]
    fn v1_serves_the_lookahead_epochs_with_the_root_before_each() {
        let current = format!("/eth/v1/validator/duties/proposer/{STATE_EPOCH}");
        let before_current = ring_root(STATE_EPOCH * SLOTS_PER_EPOCH - 1);
        assert_eq!(body(&get(&current)), expected(before_current, STATE_EPOCH));

        let next = format!("/eth/v1/validator/duties/proposer/{}", STATE_EPOCH + 1);
        assert_eq!(body(&get(&next)), expected(HEAD_ROOT, STATE_EPOCH + 1));
    }

    /// `proposer.v2.yaml`: the dependent root is one epoch earlier than v1's.
    #[test]
    fn v2_dependent_root_is_one_epoch_earlier() {
        let current = format!("/eth/v2/validator/duties/proposer/{STATE_EPOCH}");
        let before_previous = ring_root((STATE_EPOCH - 1) * SLOTS_PER_EPOCH - 1);
        assert_eq!(body(&get(&current)), expected(before_previous, STATE_EPOCH));

        let next = format!("/eth/v2/validator/duties/proposer/{}", STATE_EPOCH + 1);
        let before_current = ring_root(STATE_EPOCH * SLOTS_PER_EPOCH - 1);
        assert_eq!(body(&get(&next)), expected(before_current, STATE_EPOCH + 1));
    }

    #[test]
    fn epochs_outside_the_lookahead_and_malformed_epochs_are_400() {
        for epoch in [
            (STATE_EPOCH - 1).to_string(),
            (STATE_EPOCH + 2).to_string(),
            "0".to_string(),
            "-1".to_string(),
            "abc".to_string(),
        ] {
            for version in ["v1", "v2"] {
                let path = format!("/eth/{version}/validator/duties/proposer/{epoch}");
                assert_eq!(status_code(&get(&path)), "400", "{path}");
            }
        }
    }

    /// The decision slot of the epoch a state has just entered sits above its
    /// last block but below the state itself, so the ring holds the root and
    /// the head is not consulted.
    #[test]
    fn decision_slots_below_the_state_read_the_ring_not_the_head() {
        let state_slot = STATE_EPOCH * SLOTS_PER_EPOCH;
        let ctx = ctx_at(state_slot, state_slot - 6);
        let path = format!("/eth/v1/validator/duties/proposer/{STATE_EPOCH}");
        assert_eq!(body(&get_from(&ctx, &path)), expected(ring_root(state_slot - 1), STATE_EPOCH));
    }

    #[test]
    fn duties_are_503_until_the_node_follows_the_chain() {
        let mut ctx = ctx();
        ctx.node_status.target = None;
        for version in ["v1", "v2"] {
            let path = format!("/eth/{version}/validator/duties/proposer/{STATE_EPOCH}");
            assert_eq!(status_code(&get_from(&ctx, &path)), "503", "{path}");
        }
        assert_eq!(status_code(&get_from(&ctx, "/eth/v1/validator/duties/proposer/abc")), "503");
    }

    #[test]
    fn lookahead_size_covers_the_two_epochs_served() {
        assert_eq!(PROPOSER_LOOKAHEAD_SIZE as u64, (MIN_SEED_LOOKAHEAD + 1) * SLOTS_PER_EPOCH);
    }
}
