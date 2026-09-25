use std::fmt;

use serde::{
    Deserialize, Deserializer,
    de::{SeqAccess, Visitor},
};
use silver_beacon_state_data::{SYNC_COMMITTEE_SIZE, SYNC_SUBCOMMITTEE_SIZE};
use silver_common::{
    BeaconApiRequest, SYNC_COMMITTEE_SUBNETS, SlotSubnets, SubnetsBySlot,
    compute_subnet_for_attestation, ssz_view::MAX_COMMITTEES_PER_SLOT,
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
        if let Some(slot_subnets) = entry.slot_subnets() {
            by_slot.insert(slot_subnets);
        }
    });
    if let Err(message) = parsed {
        return resp.error(400, message);
    }
    let held = by_slot.held().count();
    if held == 0 {
        return resp.ok();
    }

    resp.submit(
        held * SlotSubnets::SIZE,
        |out| {
            for (record, slot) in out.chunks_exact_mut(SlotSubnets::SIZE).zip(by_slot.held()) {
                slot.encode(record);
            }
        },
        |subscriptions| BeaconApiRequest::BeaconCommitteeSubscriptions { subscriptions },
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
    is_aggregator: bool,
}

impl CommitteeSubscription {
    fn slot_subnets(&self) -> Option<SlotSubnets> {
        let committees = self.committees_at_slot;
        if self.committee_index >= committees || committees > MAX_COMMITTEES_PER_SLOT as u64 {
            return None;
        }
        let subnet =
            1 << compute_subnet_for_attestation(committees, self.slot, self.committee_index);
        Some(SlotSubnets {
            slot: self.slot,
            attesting: subnet,
            aggregating: if self.is_aggregator { subnet } else { 0 },
        })
    }
}

pub(crate) fn post_sync_committee_subscriptions(
    req: &Request<'_>,
    _ctx: &ApiCtx,
    resp: &mut Response<'_>,
) {
    let mut until_epochs = [0; SYNC_COMMITTEE_SUBNETS];
    let parsed = each_body_entry(req.body, |_, entry: SyncCommitteeSubscription| {
        for (subnet, until_epoch) in until_epochs.iter_mut().enumerate() {
            if entry.subnets >> subnet & 1 == 1 {
                *until_epoch = entry.until_epoch.max(*until_epoch);
            }
        }
    });
    if let Err(message) = parsed {
        return resp.error(400, message);
    }
    if until_epochs == [0; SYNC_COMMITTEE_SUBNETS] {
        return resp.ok();
    }
    resp.notify(BeaconApiRequest::SyncCommitteeSubscriptions { until_epochs });
}

#[derive(Deserialize)]
struct SyncCommitteeSubscription {
    #[serde(rename = "sync_committee_indices", deserialize_with = "sync_subnets")]
    subnets: u8,
    #[serde(deserialize_with = "uint64")]
    until_epoch: u64,
}

/// Indices past the committee name no subnet and are skipped.
fn sync_subnets<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u8, D::Error> {
    #[derive(Deserialize)]
    struct Index(#[serde(deserialize_with = "uint64")] u64);

    struct Subnets;

    impl<'de> Visitor<'de> for Subnets {
        type Value = u8;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("an array of Uint64")
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<u8, A::Error> {
            let mut subnets = 0;
            while let Some(Index(index)) = seq.next_element()? {
                if index < SYNC_COMMITTEE_SIZE as u64 {
                    subnets |= 1 << (index as usize / SYNC_SUBCOMMITTEE_SIZE);
                }
            }
            Ok(subnets)
        }
    }

    deserializer.deserialize_seq(Subnets)
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
    const SYNC_PATH: &str = "/eth/v1/validator/sync_committee_subscriptions";

    fn entry(
        committee_index: u64,
        committees_at_slot: u64,
        slot: u64,
        is_aggregator: bool,
    ) -> String {
        format!(
            "{{\"validator_index\":\"1\",\"committee_index\":\"{committee_index}\",\
             \"committees_at_slot\":\"{committees_at_slot}\",\"slot\":\"{slot}\",\
             \"is_aggregator\":{is_aggregator}}}"
        )
    }

    fn post(body: &str) -> (Outcome, Vec<u8>) {
        post_to(PATH, body)
    }

    fn post_to(path: &str, body: &str) -> (Outcome, Vec<u8>) {
        dispatch(&anchor_ctx(), &posting(path, body))
    }

    #[test]
    fn subscriptions_are_squashed_by_slot_into_the_cache() {
        let body = format!(
            "[{},{},{}]",
            entry(0, 4, 32, true),
            entry(3, 4, 32, false),
            entry(1, 4, 33, false)
        );
        let mut submissions = submissions();
        let (outcome, response) =
            dispatch_into(&anchor_ctx(), &posting(PATH, &body), &mut submissions);
        assert_eq!(status_code(&response), "200");
        let Outcome::Response(Some(BeaconApiRequest::BeaconCommitteeSubscriptions {
            subscriptions,
        })) = outcome
        else {
            panic!("{outcome:?}")
        };
        let written = submissions.read_buffer(subscriptions).unwrap();
        assert!(SlotSubnets::decode_all(written).eq([
            SlotSubnets { slot: 32, attesting: 1 << 0 | 1 << 3, aggregating: 1 << 0 },
            SlotSubnets { slot: 33, attesting: 1 << 5, aggregating: 0 },
        ]));
    }

    #[test]
    fn entries_naming_no_committee_of_their_slot_are_dropped() {
        for entry in [entry(4, 4, 32, true), entry(0, 65, 32, true), entry(0, 0, 32, true)] {
            let (outcome, response) = post(&format!("[{entry}]"));
            assert_eq!(outcome, Outcome::Response(None), "{entry}");
            assert_eq!(status_code(&response), "200", "{entry}");
        }
    }

    #[test]
    fn slot_evicts_the_one_a_ring_length_before_it() {
        let body = (0..=SubnetsBySlot::SLOTS as u64)
            .map(|slot| entry(0, 1, slot, false))
            .reduce(|body, entry| body + "," + &entry)
            .unwrap();
        let mut submissions = submissions();
        let (outcome, response) =
            dispatch_into(&anchor_ctx(), &posting(PATH, &format!("[{body}]")), &mut submissions);
        assert_eq!(status_code(&response), "200");
        let Outcome::Response(Some(BeaconApiRequest::BeaconCommitteeSubscriptions {
            subscriptions,
        })) = outcome
        else {
            panic!("{outcome:?}")
        };
        let written = submissions.read_buffer(subscriptions).unwrap();
        assert_eq!(SlotSubnets::decode_all(written).count(), SubnetsBySlot::SLOTS);
        assert!(SlotSubnets::decode_all(written).all(|held| held.slot != 0));
    }

    #[test]
    fn malformed_bodies_are_a_400() {
        let entry = entry(0, 4, 32, false);
        for body in [
            String::new(),
            "{}".to_owned(),
            "[1]".to_owned(),
            format!("[{}]", entry.replace("\"4\"", "4")),
            format!("[{}]", entry.replace("false", "\"false\"")),
        ] {
            let (outcome, response) = post(&body);
            assert_eq!(outcome, Outcome::Response(None));
            assert_eq!(status_code(&response), "400", "{body}");
        }
    }

    fn sync_entry(indices: &str, until_epoch: &str) -> String {
        format!(
            "{{\"validator_index\":\"1\",\"sync_committee_indices\":[{indices}],\
             \"until_epoch\":{until_epoch}}}"
        )
    }

    #[test]
    fn sync_subscriptions_keep_the_latest_epoch_per_subnet() {
        let body = format!(
            "[{},{},{}]",
            sync_entry("\"0\",\"300\"", "\"10\""),
            sync_entry("\"5\"", "\"12\""),
            sync_entry("\"512\"", "\"99\""),
        );
        let (outcome, response) = post_to(SYNC_PATH, &body);
        assert_eq!(status_code(&response), "200");
        assert_eq!(
            outcome,
            Outcome::Response(Some(BeaconApiRequest::SyncCommitteeSubscriptions {
                until_epochs: [12, 0, 10, 0]
            }))
        );
    }

    #[test]
    fn sync_subscriptions_naming_no_subnet_send_nothing() {
        for body in ["[]".to_owned(), format!("[{}]", sync_entry("", "\"10\""))] {
            let (outcome, response) = post_to(SYNC_PATH, &body);
            assert_eq!(outcome, Outcome::Response(None), "{body}");
            assert_eq!(status_code(&response), "200", "{body}");
        }
    }

    #[test]
    fn malformed_sync_subscriptions_are_a_400() {
        for body in [
            format!("[{}]", sync_entry("\"7.0\"", "\"10\"")),
            format!("[{}]", sync_entry("\"7\"", "10")),
            "{}".to_owned(),
        ] {
            let (outcome, response) = post_to(SYNC_PATH, &body);
            assert_eq!(outcome, Outcome::Response(None), "{body}");
            assert_eq!(status_code(&response), "400", "{body}");
        }
    }
}
