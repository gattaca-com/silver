use silver_beacon_state_data::{Epoch, SLOTS_PER_EPOCH, ShufflingId, Slot, StateReadView};
use silver_httpcore::Query;

use crate::{
    ctx::ApiCtx,
    http::{ids::parse_uint64, json::Json, response::Response, router::Request},
    validator::shufflings::PostedShufflings,
};

pub(crate) fn get_epoch_committees(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    let selection = match CommitteeSelection::from_query(req.query) {
        Ok(selection) => selection,
        Err(message) => return resp.error(400, message),
    };
    ctx.try_state_response(req, resp, |view, json| selection.render(&ctx.shufflings, view, json));
}

#[derive(Default)]
struct CommitteeSelection {
    epoch: Option<Epoch>,
    index: Option<u64>,
    slot: Option<Slot>,
}

impl CommitteeSelection {
    fn from_query(query: &str) -> Result<Self, &'static str> {
        let mut selection = Self::default();
        for (name, value) in Query::new(query) {
            let (field, invalid) = match &*name {
                "epoch" => (&mut selection.epoch, "invalid epoch"),
                "index" => (&mut selection.index, "invalid index"),
                "slot" => (&mut selection.slot, "invalid slot"),
                _ => continue,
            };
            *field = Some(parse_uint64(&value).ok_or(invalid)?);
        }
        Ok(selection)
    }

    /// The state fixes the shuffling up to the epoch after its own; only the
    /// shufflings Beacon State posted for its head can be answered.
    fn render(
        &self,
        shufflings: &PostedShufflings,
        view: &StateReadView<'_>,
        json: &mut Json<'_>,
    ) -> Result<(), (u16, &'static str)> {
        let state_epoch = view.slot.current_epoch();
        let epoch = self.epoch.unwrap_or(state_epoch);
        if epoch > state_epoch + 1 {
            return Err((400, "epoch is past the state's next epoch"));
        }
        if self.slot.is_some_and(|slot| slot / SLOTS_PER_EPOCH != epoch) {
            return Err((400, "slot is outside the epoch"));
        }
        let shuffling = ShufflingId::from_state(view, epoch)
            .and_then(|id| shufflings.get(id))
            .ok_or((500, "the epoch's committees are not available"))?;
        let per_slot = shuffling.committees_per_slot();
        if self.index.is_some_and(|index| index >= per_slot as u64) {
            return Err((400, "index is past the epoch's committee count"));
        }

        let first_slot = epoch * SLOTS_PER_EPOCH;
        let slots =
            self.slot.map_or(first_slot..first_slot + SLOTS_PER_EPOCH, |slot| slot..slot + 1);
        let indices = self.index.map_or(0..per_slot, |index| index as usize..index as usize + 1);
        json.begin_array();
        for slot in slots {
            for index in indices.clone() {
                json.committee(index as u64, slot, shuffling.committee(slot, index));
            }
        }
        json.end_array();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use silver_beacon_state_data::{
        BeaconBlockHeader, BeaconState, BeaconStateOwner, EpochStateFinalized, SlotState,
        SlotStateFinalized, SlotStateGroup, SpecConfig, ValSeed, committee_range,
        committees_per_slot,
    };
    use silver_httpcore::ParsedRequest;

    use super::*;
    use crate::{
        ctx::test_ctx,
        testing::{answer, block_roots_ring, json, request, status_code},
    };

    const ACTIVE: u32 = 8192;
    const STATE_EPOCH: u64 = 300;
    const STATE_SLOT: u64 = STATE_EPOCH * SLOTS_PER_EPOCH + 5;

    /// The active set reversed and rotated by `epoch`, so epochs differ.
    fn order(epoch: Epoch) -> Vec<u32> {
        (0..ACTIVE).rev().map(|i| (i + epoch as u32) % ACTIVE).collect()
    }

    /// Shufflings posted for the state's epoch and the next, not the previous.
    fn ctx() -> ApiCtx {
        let seeds: Vec<_> = (0..ACTIVE).map(|_| ValSeed::default()).collect();
        let mut state = BeaconState::for_test(EpochStateFinalized::default(), &seeds, STATE_SLOT);
        state.slot_states = SlotStateGroup::new(SlotStateFinalized::new(SlotState {
            slot: STATE_SLOT,
            latest_block_header: BeaconBlockHeader { slot: STATE_SLOT - 2, ..Default::default() },
            ..Default::default()
        }));
        state.block_roots = block_roots_ring(STATE_SLOT);
        let mut owner = BeaconStateOwner::new(state);
        let anchor = owner.roll_fresh();
        owner.publish_state_id(anchor);
        let mut ctx = test_ctx(&SpecConfig::mainnet(), owner.reader());
        for epoch in [STATE_EPOCH, STATE_EPOCH + 1] {
            let id = ctx.read_state(|view| ShufflingId::from_state(&view, epoch).unwrap());
            let bytes: Vec<u8> = order(epoch).iter().flat_map(|i| i.to_le_bytes()).collect();
            ctx.shufflings.record(id, &bytes);
        }
        ctx
    }

    fn get(ctx: &ApiCtx, state_id: &str, query: &str) -> Vec<u8> {
        let path = format!("/eth/v1/beacon/states/{state_id}/committees");
        answer(ctx, &ParsedRequest { query, ..request("GET", &path) })
    }

    fn uint(value: &serde_json::Value) -> u64 {
        value.as_str().unwrap().parse().unwrap()
    }

    /// Without filters, the state's epoch: every committee in slot and index
    /// order, together the whole posted order.
    #[test]
    fn the_state_epoch_partitions_into_ordered_committees() {
        let body = json(&get(&ctx(), "head", ""));
        let committees = body["data"].as_array().unwrap();
        let per_slot = committees_per_slot(ACTIVE as usize);
        assert_eq!(committees.len(), SLOTS_PER_EPOCH as usize * per_slot);
        let mut members = Vec::new();
        for (n, committee) in committees.iter().enumerate() {
            assert_eq!(
                uint(&committee["slot"]),
                STATE_EPOCH * SLOTS_PER_EPOCH + (n / per_slot) as u64
            );
            assert_eq!(uint(&committee["index"]), (n % per_slot) as u64);
            members
                .extend(committee["validators"].as_array().unwrap().iter().map(|v| uint(v) as u32));
        }
        assert_eq!(members, order(STATE_EPOCH));
        assert_eq!(body["finalized"], false);
    }

    #[test]
    fn epoch_slot_and_index_narrow_to_one_committee() {
        let epoch = STATE_EPOCH + 1;
        let slot = epoch * SLOTS_PER_EPOCH + 3;
        let query = format!("epoch={epoch}&slot={slot}&index=1");
        let body = json(&get(&ctx(), "head", &query));
        let [committee] = &body["data"].as_array().unwrap()[..] else { panic!("one committee") };
        let posted = order(epoch);
        let range = committee_range(posted.len(), committees_per_slot(posted.len()), slot, 1);
        let members: Vec<_> =
            committee["validators"].as_array().unwrap().iter().map(|v| uint(v) as u32).collect();
        assert_eq!(members, posted[range]);
    }

    #[test]
    fn requests_the_state_cannot_answer_are_400_and_unposted_epochs_500() {
        let ctx = ctx();
        let past = (STATE_EPOCH + 2).to_string();
        let outside = format!("epoch={STATE_EPOCH}&slot={}", (STATE_EPOCH + 1) * SLOTS_PER_EPOCH);
        let too_high = format!("index={}", committees_per_slot(ACTIVE as usize));
        for query in [format!("epoch={past}"), outside, too_high, "epoch=x".to_string()] {
            assert_eq!(status_code(&get(&ctx, "head", &query)), "400", "{query}");
        }
        let previous = format!("epoch={}", STATE_EPOCH - 1);
        assert_eq!(status_code(&get(&ctx, "head", &previous)), "500");
        assert_eq!(status_code(&get(&ctx, "finalized", "")), "404");
    }
}
