use silver_beacon_state_data::{
    BLSPubkey, Epoch, SLOTS_PER_EPOCH, Slot, StateReadView, committee_at_position,
    committees_per_slot,
};

use crate::{
    ctx::ApiCtx,
    http::{response::Response, router::Request},
    validator::duties::{epoch_param, requested_indices},
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
    let state_epoch = ctx.read_state(|view| view.slot.current_epoch());
    if epoch < state_epoch || epoch > state_epoch + 1 {
        resp.error(400, "attester duties cover the head state's epoch and the one after it");
        return;
    }
    let Some(shuffling) = ctx.shufflings.get(epoch) else {
        resp.error(503, "the head state's shuffling for this epoch has not been posted");
        return;
    };

    let head_root = ctx.node_status.head_root;
    let execution_optimistic = ctx.node_status.execution_optimistic();
    resp.json_body(|json| {
        ctx.read_state(|view| {
            json.restart();
            let state_slot = view.slot.state().slot;
            let dependent = view.block_roots.duty_dependent_root(
                epoch.saturating_sub(1),
                head_root,
                state_slot,
            );
            debug_assert!(dependent.is_some(), "a posted shuffling decides inside the ring");
            json.attester_duties(
                dependent.unwrap_or(head_root),
                execution_optimistic,
                indices.iter().filter_map(|&validator_index| {
                    AttesterDuty::read(&view, shuffling, epoch, validator_index)
                }),
            );
        });
    });
}

#[derive(Default)]
pub(crate) struct PostedShufflings {
    entries: [Shuffling; 3],
}

const NOT_ACTIVE: u32 = u32::MAX;

#[derive(Default)]
struct Shuffling {
    epoch: Option<Epoch>,
    shuffled_len: usize,
    /// Position in the shuffled active set per validator index; empty until
    /// posted.
    position_of: Vec<u32>,
}

impl PostedShufflings {
    pub(crate) fn record(&mut self, epoch: Epoch, bytes: &[u8]) {
        if bytes.len() < size_of::<u32>() {
            tracing::error!(epoch, "shuffling posted with no active validators");
            return;
        }
        self.entry_for(epoch).fill(epoch, bytes);
    }

    fn entry_for(&mut self, epoch: Epoch) -> &mut Shuffling {
        let held = self.entries.iter().position(|entry| entry.epoch == Some(epoch));
        let oldest = || {
            let (index, _) = self
                .entries
                .iter()
                .enumerate()
                .min_by_key(|(_, entry)| entry.epoch)
                .expect("three entries");
            index
        };
        &mut self.entries[held.unwrap_or_else(oldest)]
    }

    pub(crate) fn committees_per_slot(&self, epoch: Epoch) -> Option<u64> {
        self.get(epoch).map(|shuffling| committees_per_slot(shuffling.shuffled_len) as u64)
    }

    fn get(&self, epoch: Epoch) -> Option<&Shuffling> {
        self.entries
            .iter()
            .find(|entry| entry.epoch == Some(epoch) && !entry.position_of.is_empty())
    }
}

fn posted_indices(bytes: &[u8]) -> impl Iterator<Item = u32> {
    bytes
        .chunks_exact(size_of::<u32>())
        .map(|chunk| u32::from_le_bytes(chunk.try_into().expect("four bytes")))
}

impl Shuffling {
    /// Replaces whatever this entry held, reusing the table's allocation.
    fn fill(&mut self, epoch: Epoch, bytes: &[u8]) {
        self.epoch = Some(epoch);
        self.shuffled_len = bytes.len() / size_of::<u32>();
        self.fill_positions(bytes);
    }

    /// Inverts the posted order, so a request resolves its own validators
    /// without a walk over the whole set.
    fn fill_positions(&mut self, bytes: &[u8]) {
        self.position_of.clear();
        for (position, validator_index) in posted_indices(bytes).enumerate() {
            let ix = validator_index as usize;
            if ix >= self.position_of.len() {
                self.position_of.resize(ix + 1, NOT_ACTIVE);
            }
            self.position_of[ix] = position as u32;
        }
    }

    fn position(&self, validator_index: u64) -> Option<u32> {
        let position = *self.position_of.get(usize::try_from(validator_index).ok()?)?;
        (position != NOT_ACTIVE).then_some(position)
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
        let committees_at_slot = committees_per_slot(shuffling.shuffled_len);
        let position = shuffling.position(validator_index)? as usize;
        let index =
            usize::try_from(validator_index).ok().filter(|&ix| ix < view.validators.count())?;
        let committee = committee_at_position(shuffling.shuffled_len, committees_at_slot, position);
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
        SlotStateFinalized, SlotStateGroup, SpecConfig, ValSeed, committee_range,
    };
    use silver_common::SyncUpdate;

    use super::*;
    use crate::{
        ctx::test_ctx,
        testing::{
            answer, block_roots_ring, field, indices_body, json, posting, pubkey, ring_root,
            status_code,
        },
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
            ctx.shufflings.record(epoch, &posted_bytes(epoch));
        }
        ctx
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

    /// An empty shuffling has no committee to divide into; answering one
    /// would divide by zero.
    #[test]
    fn empty_shufflings_are_not_recorded() {
        let mut posted = PostedShufflings::default();
        posted.record(10, &[]);
        assert!(posted.get(10).is_none());
    }

    /// A repost for an epoch replaces it; a newer epoch evicts the oldest
    /// held.
    #[test]
    fn posted_shufflings_hold_the_three_newest_epochs() {
        let mut posted = PostedShufflings::default();
        posted.record(10, &posted_bytes(10));
        posted.record(11, &posted_bytes(11));
        posted.record(12, &posted_bytes(12));
        posted.record(10, &posted_bytes(13));
        for (position, &validator_index) in posted_order(13).iter().enumerate() {
            assert_eq!(
                posted.get(10).unwrap().position(validator_index as u64),
                Some(position as u32)
            );
        }

        posted.record(13, &posted_bytes(13));
        assert!(posted.get(10).is_none());
        assert!([11, 12, 13].iter().all(|&epoch| posted.get(epoch).is_some()));
    }

    /// Epoch zero is a real epoch, so recording it must not leave an unfilled
    /// slot looking like the oldest.
    #[test]
    fn epoch_zero_fills_one_slot_and_leaves_the_others_free() {
        let mut posted = PostedShufflings::default();
        posted.record(0, &posted_bytes(0));
        posted.record(1, &posted_bytes(1));
        posted.record(2, &posted_bytes(2));
        assert!([0, 1, 2].iter().all(|&epoch| posted.get(epoch).is_some()));
    }
}
