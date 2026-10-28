use std::collections::{BTreeMap, btree_map::Entry};

use silver_beacon_state_data::B256;
use silver_common::{
    json_fields::parse_uint64,
    ssz_view::{
        ProposerPreferencesView, SIGNED_PROPOSER_PREFERENCES_SIZE, SignedProposerPreferencesView,
    },
};
use silver_httpcore::Query;

use crate::{
    ctx::ApiCtx,
    http::{
        ids::parse_root,
        response::Response,
        router::{Request, SSZ_MEDIA_TYPE},
    },
};

#[derive(Default)]
pub(crate) struct ProposerPreferences {
    signed: BTreeMap<(u64, B256), [u8; SIGNED_PROPOSER_PREFERENCES_SIZE]>,
}

impl ProposerPreferences {
    pub(crate) fn record(
        &mut self,
        signed: &[u8; SIGNED_PROPOSER_PREFERENCES_SIZE],
        current_slot: u64,
    ) -> bool {
        let message = SignedProposerPreferencesView::message(signed);
        let slot = ProposerPreferencesView::proposal_slot(message);
        if slot < current_slot {
            return false;
        }
        let root = *ProposerPreferencesView::dependent_root(message);
        let Entry::Vacant(entry) = self.signed.entry((slot, root)) else { return false };
        entry.insert(*signed);
        true
    }

    pub(crate) fn on_slot(&mut self, slot: u64) {
        self.signed.retain(|&(proposal_slot, _), _| proposal_slot >= slot);
    }

    fn matching(
        &self,
        current_slot: u64,
        slot: Option<u64>,
        dependent_root: Option<B256>,
    ) -> impl Iterator<Item = &[u8; SIGNED_PROPOSER_PREFERENCES_SIZE]> {
        self.signed.range((current_slot, [0; 32])..).filter_map(move |(&(s, root), signed)| {
            (slot.is_none_or(|slot| slot == s) && dependent_root.is_none_or(|r| r == root))
                .then_some(signed)
        })
    }
}

pub(crate) fn get_proposer_preferences(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    if !ctx.follows_chain(resp) {
        return;
    }
    let mut slot = None;
    let mut dependent_root = None;
    for (name, value) in Query::new(req.query) {
        match name.as_ref() {
            "slot" => {
                let Some(value) = parse_uint64(&value) else {
                    resp.error(400, "invalid slot");
                    return;
                };
                slot = Some(value);
            }
            "dependent_root" => {
                let Some(value) = parse_root(&value) else {
                    resp.error(400, "invalid dependent_root");
                    return;
                };
                dependent_root = Some(value);
            }
            _ => {}
        }
    }
    let preferences =
        ctx.proposer_preferences.matching(ctx.node_status.wall_slot, slot, dependent_root);
    if req.accepts_ssz() {
        let parts: Vec<_> = preferences.map(|signed| signed.as_slice()).collect();
        resp.send(200, Some(SSZ_MEDIA_TYPE), &[("Eth-Consensus-Version", "gloas")], &parts);
    } else {
        resp.versioned_json("gloas", |json| {
            json.begin_array();
            for signed in preferences {
                json.signed_proposer_preferences(signed);
            }
            json.end_array();
        });
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use serde_json::{Value, json as value};
    use silver_httpcore::ParsedRequest;

    use super::*;
    use crate::{
        ctx::anchor_ctx,
        testing::{answer, json, request, status_code},
    };

    pub(crate) const PATH: &str = "/eth/v1/beacon/proposer_preferences";

    pub(crate) fn signed_preferences(
        slot: u64,
        root: u8,
    ) -> [u8; SIGNED_PROPOSER_PREFERENCES_SIZE] {
        let mut signed = [0x44; SIGNED_PROPOSER_PREFERENCES_SIZE];
        signed[..32].fill(root);
        signed[32..40].copy_from_slice(&slot.to_le_bytes());
        signed[40..48].copy_from_slice(&9u64.to_le_bytes());
        signed[48..68].fill(0x22);
        signed[68..76].copy_from_slice(&60_000_000u64.to_le_bytes());
        signed
    }

    pub(crate) fn preferences_json(slot: u64, root: u8) -> Value {
        value!({
            "message": {
                "dependent_root": format!("0x{}", hex::encode([root; 32])),
                "proposal_slot": slot.to_string(),
                "validator_index": "9",
                "fee_recipient": format!("0x{}", "22".repeat(20)),
                "target_gas_limit": "60000000",
            },
            "signature": format!("0x{}", "44".repeat(96)),
        })
    }

    #[test]
    fn get_filters_complete_signed_preferences_before_the_fork() {
        let mut ctx = anchor_ctx();
        ctx.spec.gloas_fork_epoch = 1;
        ctx.node_status.wall_slot = 31;
        for (slot, root) in [(33, 0x11), (32, 0x22), (32, 0x11)] {
            assert!(ctx.proposer_preferences.record(&signed_preferences(slot, root), 31));
        }
        let root = format!("dependent_root=0x{}", "11".repeat(32));
        for (query, expected) in [
            ("", vec![(32, 0x11), (32, 0x22), (33, 0x11)]),
            ("slot=32", vec![(32, 0x11), (32, 0x22)]),
            (root.as_str(), vec![(32, 0x11), (33, 0x11)]),
            (&format!("slot=32&{root}"), vec![(32, 0x11)]),
            (&format!("slot=34&{root}"), vec![]),
            ("slot=31", vec![]),
            ("slot=%33%32", vec![(32, 0x11), (32, 0x22)]),
        ] {
            let response = answer(&ctx, &ParsedRequest { query, ..request("GET", PATH) });
            assert!(
                std::str::from_utf8(&response)
                    .unwrap()
                    .contains("Eth-Consensus-Version: gloas\r\n")
            );
            let expected: Vec<_> =
                expected.into_iter().map(|(s, r)| preferences_json(s, r)).collect();
            assert_eq!(
                json(&response),
                value!({ "version": "gloas", "data": expected }),
                "{query}"
            );
        }
    }

    #[test]
    fn malformed_filters_are_bad_requests() {
        let ctx = anchor_ctx();
        for query in [
            "slot=",
            "slot=-1",
            "slot=+1",
            "slot=1.0",
            "slot=abc",
            "slot=18446744073709551616",
            "dependent_root=",
            "dependent_root=0x11",
            &format!("dependent_root={}", "11".repeat(32)),
            &format!("dependent_root=0x{}", "gg".repeat(32)),
        ] {
            let response = answer(&ctx, &ParsedRequest { query, ..request("GET", PATH) });
            assert_eq!(status_code(&response), "400", "{query}");
        }
    }

    #[test]
    fn ssz_is_a_list_of_fixed_signed_preferences() {
        let mut ctx = anchor_ctx();
        let first = signed_preferences(32, 0x11);
        let second = signed_preferences(33, 0x22);
        ctx.proposer_preferences.record(&second, 0);
        ctx.proposer_preferences.record(&first, 0);
        for (query, expected) in
            [("", [first, second].concat()), ("slot=33", second.to_vec()), ("slot=34", vec![])]
        {
            let response = answer(&ctx, &ParsedRequest {
                query,
                accept: Some(SSZ_MEDIA_TYPE),
                ..request("GET", PATH)
            });
            let split = response.windows(4).position(|bytes| bytes == b"\r\n\r\n").unwrap() + 4;
            let headers = std::str::from_utf8(&response[..split]).unwrap();
            assert!(headers.starts_with("HTTP/1.1 200 OK\r\n"));
            assert!(headers.contains("Content-Type: application/octet-stream\r\n"));
            assert!(headers.contains("Eth-Consensus-Version: gloas\r\n"));
            assert!(headers.contains(&format!("Content-Length: {}\r\n", expected.len())));
            assert_eq!(response[split..], expected, "{query}");
        }
    }

    #[test]
    fn first_preferences_survive_until_their_slot_has_passed() {
        let mut ctx = anchor_ctx();
        let first = signed_preferences(32, 0x11);
        assert!(ctx.proposer_preferences.record(&first, 31));
        assert!(!ctx.proposer_preferences.record(&first, 31));
        let mut conflicting = first;
        conflicting[48..68].fill(0x33);
        assert!(!ctx.proposer_preferences.record(&conflicting, 31));
        assert!(ctx.proposer_preferences.record(&signed_preferences(33, 0x11), 31));

        ctx.node_status.wall_slot = 32;
        ctx.proposer_preferences.on_slot(32);
        assert_eq!(ctx.proposer_preferences.signed.len(), 2);
        assert_eq!(
            json(&answer(&ctx, &request("GET", PATH)))["data"][0],
            preferences_json(32, 0x11)
        );

        ctx.node_status.wall_slot = 33;
        assert_eq!(
            json(&answer(&ctx, &request("GET", PATH)))["data"],
            value!([preferences_json(33, 0x11)])
        );
        ctx.proposer_preferences.on_slot(33);
        assert_eq!(ctx.proposer_preferences.signed.len(), 1);
        assert!(!ctx.proposer_preferences.record(&first, 33));

        ctx.node_status.wall_slot = 34;
        ctx.proposer_preferences.on_slot(34);
        assert!(ctx.proposer_preferences.signed.is_empty());
        assert_eq!(
            json(&answer(&ctx, &request("GET", PATH))),
            value!({ "version": "gloas", "data": [] })
        );
    }
}
