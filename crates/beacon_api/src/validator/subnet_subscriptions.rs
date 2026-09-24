use serde::Deserialize;
use silver_common::{
    BeaconApiRequest, SlotSubnets, SubnetsBySlot, compute_subnet_for_attestation,
    ssz_view::MAX_COMMITTEES_PER_SLOT,
};

use crate::{
    ctx::ApiCtx,
    http::{
        ids::{each_body_entry, uint64},
        response::Response,
        router::Request,
    },
};

pub(crate) fn post_beacon_committee_subscriptions(
    req: &Request<'_>,
    _ctx: &ApiCtx,
    resp: &mut Response<'_>,
) {
    let mut by_slot = SubnetsBySlot::default();
    let parsed = each_body_entry(req.body, |_, entry: CommitteeSubscription| {
        if let Some(subnet) = entry.subnet() {
            by_slot.insert(SlotSubnets { slot: entry.slot, subnets: 1 << subnet });
        }
    });
    if let Err(message) = parsed {
        return resp.error(400, message);
    }
    let held = by_slot.held().count();
    if held == 0 {
        return resp.ok();
    }

    resp.notify(
        held * SlotSubnets::SIZE,
        |out| {
            for (record, slot) in out.chunks_exact_mut(SlotSubnets::SIZE).zip(by_slot.held()) {
                slot.encode(record);
            }
        },
        |subscriptions| BeaconApiRequest::AttestationSubscriptions { subscriptions },
    );
}

#[derive(Deserialize)]
struct CommitteeSubscription {
    #[serde(deserialize_with = "uint64")]
    committee_index: u64,
    #[serde(deserialize_with = "uint64")]
    committees_at_slot: u64,
    #[serde(deserialize_with = "uint64")]
    slot: u64,
}

impl CommitteeSubscription {
    fn subnet(&self) -> Option<u64> {
        let committees = self.committees_at_slot;
        (self.committee_index < committees && committees <= MAX_COMMITTEES_PER_SLOT as u64)
            .then(|| compute_subnet_for_attestation(committees, self.slot, self.committee_index))
    }
}

#[cfg(test)]
mod tests {
    use silver_common::TCacheProducer;

    use super::*;
    use crate::{
        ctx::anchor_ctx,
        http::router::Outcome,
        testing::{dispatch, dispatch_into, posting, status_code, submissions},
    };

    const PATH: &str = "/eth/v1/validator/beacon_committee_subscriptions";

    fn entry(committee_index: u64, committees_at_slot: u64, slot: u64) -> String {
        format!(
            "{{\"validator_index\":\"1\",\"committee_index\":\"{committee_index}\",\
             \"committees_at_slot\":\"{committees_at_slot}\",\"slot\":\"{slot}\",\
             \"is_aggregator\":false}}"
        )
    }

    fn post(body: &str) -> (Outcome, Vec<u8>) {
        dispatch(&anchor_ctx(), &posting(PATH, body))
    }

    #[test]
    fn subscriptions_are_squashed_by_slot_into_the_cache() {
        let body = format!("[{},{},{}]", entry(0, 4, 32), entry(3, 4, 32), entry(1, 4, 33));
        let mut submissions = submissions();
        let (outcome, response) =
            dispatch_into(&anchor_ctx(), &posting(PATH, &body), &mut submissions);
        assert_eq!(status_code(&response), "200");
        let Outcome::Response(Some(BeaconApiRequest::AttestationSubscriptions { subscriptions })) =
            outcome
        else {
            panic!("{outcome:?}")
        };
        let written = submissions.read_buffer(subscriptions).unwrap();
        assert!(SlotSubnets::decode_all(written).eq([
            SlotSubnets { slot: 32, subnets: 1 << 0 | 1 << 3 },
            SlotSubnets { slot: 33, subnets: 1 << 5 },
        ]));
    }

    #[test]
    fn entries_naming_no_committee_of_their_slot_are_dropped() {
        for entry in [entry(4, 4, 32), entry(0, 65, 32), entry(0, 0, 32)] {
            let (outcome, response) = post(&format!("[{entry}]"));
            assert_eq!(outcome, Outcome::Response(None), "{entry}");
            assert_eq!(status_code(&response), "200", "{entry}");
        }
    }

    #[test]
    fn slot_evicts_the_one_a_ring_length_before_it() {
        let body = (0..=SubnetsBySlot::SLOTS as u64)
            .map(|slot| entry(0, 1, slot))
            .reduce(|body, entry| body + "," + &entry)
            .unwrap();
        let mut submissions = submissions();
        let (outcome, response) =
            dispatch_into(&anchor_ctx(), &posting(PATH, &format!("[{body}]")), &mut submissions);
        assert_eq!(status_code(&response), "200");
        let Outcome::Response(Some(BeaconApiRequest::AttestationSubscriptions { subscriptions })) =
            outcome
        else {
            panic!("{outcome:?}")
        };
        let written = submissions.read_buffer(subscriptions).unwrap();
        assert_eq!(SlotSubnets::decode_all(written).count(), SubnetsBySlot::SLOTS);
        assert!(SlotSubnets::decode_all(written).all(|held| held.slot != 0));
    }

    #[test]
    fn malformed_bodies_are_a_400() {
        let entry = entry(0, 4, 32);
        for body in [
            String::new(),
            "{}".to_owned(),
            "[1]".to_owned(),
            format!("[{}]", entry.replace("\"4\"", "4")),
        ] {
            let (outcome, response) = post(&body);
            assert_eq!(outcome, Outcome::Response(None));
            assert_eq!(status_code(&response), "400", "{body}");
        }
    }
}
