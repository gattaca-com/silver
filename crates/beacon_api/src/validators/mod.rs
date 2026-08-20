pub(crate) mod entry;
mod filter;
pub(crate) mod status;

use silver_beacon_state_data::StateReadView;

use crate::{
    response::Response,
    router::Request,
    routes::ApiCtx,
    validators::{
        entry::ValidatorEntry,
        filter::{Filter, ValidatorId},
    },
};

pub(crate) fn get_state_validators(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    match Filter::from_query(req.query) {
        Ok(filter) => respond_with_matches(req, ctx, resp, &filter),
        Err(error) => error.respond(resp),
    }
}

/// Same answer as the GET, from a body that carries lists too long for a
/// query string.
pub(crate) fn post_state_validators(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    match Filter::from_body(req.body) {
        Ok(filter) => respond_with_matches(req, ctx, resp, &filter),
        Err(error) => error.respond(resp),
    }
}

pub(crate) fn get_state_validator(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    let named = req.params.get("validator_id").expect("{validator_id} in the route pattern");
    let Some(validator_id) = ValidatorId::parse(named) else {
        resp.error(400, "invalid validator_id");
        return;
    };
    let read = |view: StateReadView<'_>| {
        let index = validator_id.resolve(&view.validators)?;
        Some(ValidatorEntry::read(&view, index, view.slot.current_epoch()))
    };
    let Some(state) = ctx.state_read(req, resp, read) else {
        return;
    };
    match &state.data {
        Some(entry) => resp.json_body(|json| {
            json.flagged_envelope(state.flags, |json| json.validator_entry(entry))
        }),
        None => resp.error(404, "validator not found"),
    }
}

fn respond_with_matches(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>, filter: &Filter) {
    let Some(state) = ctx.state_read(req, resp, |view| ValidatorEntry::matching(&view, filter))
    else {
        return;
    };
    resp.json_body(|json| json.flagged_envelope(state.flags, |json| json.validators(&state.data)));
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use silver_beacon_state_data::{
        BeaconState, BeaconStateOwner, Epoch, EpochStateFinalized, FAR_FUTURE_EPOCH,
        SLOTS_PER_EPOCH, SpecConfig, StateId, ValSeed, Withdrawals,
    };
    use silver_common::ELSyncStatus;
    use silver_httpcore::ParsedRequest;

    use super::*;
    use crate::{
        NodeStatus, PeerCounts, SlotStatus,
        json::Json,
        router::Router,
        routes::{ROUTES, preboot_ctx, test_ctx},
    };

    const HEAD_EPOCH: Epoch = 100;
    const HEAD_SLOT: u64 = HEAD_EPOCH * SLOTS_PER_EPOCH;
    const VALIDATORS_PATH: &str = "/eth/v1/beacon/states/head/validators";

    /// One validator per status at [`HEAD_EPOCH`], in status order, so an
    /// index in [`one_per_status`] doubles as the status it must carry.
    const STATUSES: [&str; 9] = [
        "pending_initialized",
        "pending_queued",
        "active_ongoing",
        "active_exiting",
        "active_slashed",
        "exited_unslashed",
        "exited_slashed",
        "withdrawal_possible",
        "withdrawal_done",
    ];

    /// The three fields `ValSeed` does not carry, applied through a writer.
    struct Extra {
        slashed: bool,
        activation_eligibility_epoch: Epoch,
        withdrawable_epoch: Epoch,
    }

    fn pubkey_of(index: usize) -> [u8; 48] {
        [0xa0 + index as u8; 48]
    }

    fn pubkey_text(index: usize) -> String {
        format!("0x{}", hex::encode(pubkey_of(index)))
    }

    fn credentials_of(index: usize) -> Withdrawals {
        Withdrawals::eth1(&[0xc0 + index as u8; 20])
    }

    /// Nine validators, one per status at [`HEAD_EPOCH`], with every field
    /// distinct enough that a golden catches a swapped one.
    fn one_per_status() -> (Vec<ValSeed>, Vec<Extra>) {
        let far = FAR_FUTURE_EPOCH;
        //     effective       balance     activation exit slashed elig withdrawable
        let rows: [(u64, u64, Epoch, Epoch, bool, Epoch, Epoch); 9] = [
            (1_000_000_000, 1_000_000_000, far, far, false, far, far),
            (32_000_000_000, 32_000_000_000, 105, far, false, 98, far),
            (32_000_000_000, 32_100_000_000, 10, far, false, 8, far),
            (32_000_000_000, 32_200_000_000, 10, 110, false, 8, 366),
            (32_000_000_000, 16_300_000_000, 10, 110, true, 8, 8_300),
            (32_000_000_000, 32_400_000_000, 10, 90, false, 8, 101),
            (16_000_000_000, 16_500_000_000, 10, 90, true, 8, 8_290),
            (32_000_000_000, 32_600_000_000, 10, 90, false, 8, 95),
            (0, 0, 10, 90, false, 8, 95),
        ];
        rows.iter()
            .enumerate()
            .map(|(index, &(effective, balance, activation, exit, slashed, elig, withdrawable))| {
                (
                    ValSeed {
                        pubkey: pubkey_of(index),
                        withdrawal_credentials: credentials_of(index),
                        effective_balance: effective,
                        balance,
                        activation_epoch: activation,
                        exit_epoch: exit,
                    },
                    Extra {
                        slashed,
                        activation_eligibility_epoch: elig,
                        withdrawable_epoch: withdrawable,
                    },
                )
            })
            .unzip()
    }

    fn published_state(
        seeds: &[ValSeed],
        extras: &[Extra],
        slot: u64,
    ) -> (BeaconStateOwner, StateId) {
        let mut owner = BeaconStateOwner::new(BeaconState::for_test(
            EpochStateFinalized::default(),
            seeds,
            slot,
        ));
        let anchor = owner.roll_fresh();
        let (mut writer, _, _) = owner.apply_block_view(anchor);
        for (index, extra) in extras.iter().enumerate() {
            let index = index as u32;
            writer.validators.set_slashed(index, extra.slashed);
            writer
                .validators
                .set_activation_eligibility_epoch(index, extra.activation_eligibility_epoch);
            writer.validators.set_withdrawable_epoch(index, extra.withdrawable_epoch);
        }
        let head = writer.commit(None, None);
        owner.publish_state_id(head);
        (owner, head)
    }

    fn published_ctx(seeds: &[ValSeed], extras: &[Extra], slot: u64) -> ApiCtx {
        let (owner, _) = published_state(seeds, extras, slot);
        let mut ctx = test_ctx(&SpecConfig::mainnet(), owner.reader());
        ctx.node_status = NodeStatus {
            slots: Some(SlotStatus { head_slot: slot, wall_slot: slot, head_optimistic: false }),
            syncing: false,
            el: ELSyncStatus::Synced,
            peers: PeerCounts::default(),
        };
        ctx
    }

    fn registry_ctx() -> ApiCtx {
        let (seeds, extras) = one_per_status();
        published_ctx(&seeds, &extras, HEAD_SLOT)
    }

    /// More validators than the widest query string could name, all but one
    /// of them active_ongoing.
    const BULK_REGISTRY: usize = 20_000;

    fn bulk_registry_ctx() -> ApiCtx {
        let seeds: Vec<_> = (0..BULK_REGISTRY)
            .map(|index| {
                let mut pubkey = [0u8; 48];
                pubkey[..8].copy_from_slice(&(index as u64).to_le_bytes());
                ValSeed {
                    pubkey,
                    withdrawal_credentials: Withdrawals::ZERO,
                    effective_balance: 32_000_000_000,
                    balance: 32_000_000_000,
                    activation_epoch: if index == 0 { FAR_FUTURE_EPOCH } else { 10 },
                    exit_epoch: FAR_FUTURE_EPOCH,
                }
            })
            .collect();
        // `ValSeed`'s registry defaults are already this test's `Extra`s:
        // unslashed, with no eligibility and no withdrawable epoch.
        published_ctx(&seeds, &[], HEAD_SLOT)
    }

    fn request<'a>(
        method: &'a str,
        path: &'a str,
        query: &'a str,
        body: &'a [u8],
    ) -> ParsedRequest<'a> {
        ParsedRequest {
            method,
            path,
            query,
            body,
            accept: None,
            content_type: None,
            eth_consensus_version: None,
            version: 1,
            keep_alive: true,
        }
    }

    fn dispatch(ctx: &ApiCtx, req: &ParsedRequest<'_>) -> Vec<u8> {
        let mut out = Vec::new();
        Router::new(ROUTES).dispatch(req, ctx, &mut out);
        out
    }

    fn get(ctx: &ApiCtx, path: &str, query: &str) -> Vec<u8> {
        dispatch(ctx, &request("GET", path, query, b""))
    }

    fn post(ctx: &ApiCtx, path: &str, body: &str) -> Vec<u8> {
        dispatch(ctx, &request("POST", path, "", body.as_bytes()))
    }

    fn body(response: &[u8]) -> &[u8] {
        let text = std::str::from_utf8(response).unwrap();
        &response[text.find("\r\n\r\n").unwrap() + 4..]
    }

    fn ok_body(response: &[u8]) -> String {
        assert!(
            response.starts_with(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"),
            "{}",
            String::from_utf8_lossy(response)
        );
        String::from_utf8(body(response).to_vec()).unwrap()
    }

    /// The `index`/`status` pairs a list body carries, in the order it lists
    /// them.
    fn listed(response: &[u8]) -> Vec<(u64, String)> {
        let parsed: serde_json::Value = serde_json::from_str(&ok_body(response)).unwrap();
        parsed["data"]
            .as_array()
            .expect("data is an array")
            .iter()
            .map(|entry| {
                (
                    entry["index"].as_str().unwrap().parse().unwrap(),
                    entry["status"].as_str().unwrap().to_owned(),
                )
            })
            .collect()
    }

    fn indices(response: &[u8]) -> Vec<u64> {
        listed(response).into_iter().map(|(index, _)| index).collect()
    }

    fn assert_error(response: &[u8], status: &str, code: u16, message: &str) {
        assert!(
            response.starts_with(format!("HTTP/1.1 {status}\r\n").as_bytes()),
            "{}",
            String::from_utf8_lossy(response)
        );
        assert_eq!(
            std::str::from_utf8(body(response)).unwrap(),
            format!("{{\"code\":{code},\"message\":\"{message}\"}}")
        );
    }

    /// Body shape: `GetStateValidatorsResponse` of
    /// `apis/beacon/states/validators.yaml` — both envelope flags, then a
    /// `data` array of `ValidatorResponse` with every integer a quoted decimal
    /// string and every byte string lowercase `0x`-hex.
    #[test]
    fn validators_body_is_the_envelope_around_a_validator_response_array() {
        let expected = format!(
            "{{\"execution_optimistic\":false,\"finalized\":false,\"data\":[\
             {{\"index\":\"0\",\"balance\":\"1000000000\",\"status\":\"pending_initialized\",\
             \"validator\":{{\"pubkey\":\"0x{a0}\",\"withdrawal_credentials\":\"0x{c0}\",\
             \"effective_balance\":\"1000000000\",\"slashed\":false,\
             \"activation_eligibility_epoch\":\"18446744073709551615\",\
             \"activation_epoch\":\"18446744073709551615\",\
             \"exit_epoch\":\"18446744073709551615\",\
             \"withdrawable_epoch\":\"18446744073709551615\"}}}},\
             {{\"index\":\"4\",\"balance\":\"16300000000\",\"status\":\"active_slashed\",\
             \"validator\":{{\"pubkey\":\"0x{a4}\",\"withdrawal_credentials\":\"0x{c4}\",\
             \"effective_balance\":\"32000000000\",\"slashed\":true,\
             \"activation_eligibility_epoch\":\"8\",\"activation_epoch\":\"10\",\
             \"exit_epoch\":\"110\",\"withdrawable_epoch\":\"8300\"}}}}]}}",
            a0 = hex::encode(pubkey_of(0)),
            c0 = hex::encode(credentials_of(0).0),
            a4 = hex::encode(pubkey_of(4)),
            c4 = hex::encode(credentials_of(4).0),
        );
        assert_eq!(ok_body(&get(&registry_ctx(), VALIDATORS_PATH, "id=0,4")), expected);
        serde_json::from_str::<serde_json::Value>(&expected).expect("valid JSON");
    }

    #[test]
    fn an_empty_result_set_keeps_the_envelope_and_an_empty_array() {
        assert_eq!(
            ok_body(&get(&registry_ctx(), VALIDATORS_PATH, "id=999")),
            "{\"execution_optimistic\":false,\"finalized\":false,\"data\":[]}"
        );
    }

    /// Every status the schema names, against a registry holding one of each.
    #[test]
    fn each_status_is_derived_from_the_validator_s_epochs_at_the_state_s_epoch() {
        let expected: Vec<_> =
            STATUSES.iter().enumerate().map(|(i, s)| (i as u64, s.to_string())).collect();
        assert_eq!(listed(&get(&registry_ctx(), VALIDATORS_PATH, "")), expected);
    }

    /// The boundaries the derivation keys on are the epoch of the state being
    /// read: the same registry one epoch on moves validators across them.
    #[test]
    fn a_later_state_epoch_moves_validators_across_the_status_boundaries() {
        let (seeds, extras) = one_per_status();
        let next = published_ctx(&seeds, &extras, (HEAD_EPOCH + 1) * SLOTS_PER_EPOCH);
        // Index 5 becomes withdrawable at epoch 101 and still holds a balance;
        // index 3's exit at epoch 110 has not arrived yet.
        assert_eq!(listed(&get(&next, VALIDATORS_PATH, "id=5"))[0].1, "withdrawal_possible");
        assert_eq!(listed(&get(&next, VALIDATORS_PATH, "id=3"))[0].1, "active_exiting");
    }

    #[test]
    fn ids_select_by_index_by_pubkey_and_by_both_at_once() {
        let ctx = registry_ctx();
        assert_eq!(indices(&get(&ctx, VALIDATORS_PATH, "id=3")), [3]);
        assert_eq!(indices(&get(&ctx, VALIDATORS_PATH, &format!("id={}", pubkey_text(6)))), [6]);
        assert_eq!(
            indices(&get(&ctx, VALIDATORS_PATH, &format!("id=3&id={}&id=1", pubkey_text(6)))),
            [1, 3, 6]
        );
    }

    /// `uniqueItems` in the schema: one validator named twice, by either
    /// spelling, is still one entry.
    #[test]
    fn a_validator_named_twice_is_listed_once() {
        let ctx = registry_ctx();
        let query = format!("id=2,2&id={}", pubkey_text(2));
        assert_eq!(indices(&get(&ctx, VALIDATORS_PATH, &query)), [2]);
    }

    /// "If an index or public key does not match any known validator, no
    /// information will be returned but this will not cause an error."
    #[test]
    fn an_id_matching_no_validator_is_left_out_rather_than_erroring() {
        let ctx = registry_ctx();
        let unknown_key = format!("0x{}", hex::encode([0xff; 48]));
        assert!(indices(&get(&ctx, VALIDATORS_PATH, "id=9")).is_empty());
        assert!(indices(&get(&ctx, VALIDATORS_PATH, &format!("id={unknown_key}"))).is_empty());
        assert_eq!(indices(&get(&ctx, VALIDATORS_PATH, &format!("id=2&id=9&id={unknown_key}"))), [
            2
        ]);
    }

    #[test]
    fn statuses_select_by_exact_name_and_by_stage() {
        let ctx = registry_ctx();
        assert_eq!(indices(&get(&ctx, VALIDATORS_PATH, "status=active_slashed")), [4]);
        assert_eq!(indices(&get(&ctx, VALIDATORS_PATH, "status=pending")), [0, 1]);
        assert_eq!(indices(&get(&ctx, VALIDATORS_PATH, "status=active")), [2, 3, 4]);
        assert_eq!(indices(&get(&ctx, VALIDATORS_PATH, "status=exited")), [5, 6]);
        assert_eq!(indices(&get(&ctx, VALIDATORS_PATH, "status=withdrawal")), [7, 8]);
        assert_eq!(indices(&get(&ctx, VALIDATORS_PATH, "status=pending,withdrawal")), [0, 1, 7, 8]);
    }

    #[test]
    fn the_two_filters_narrow_each_other() {
        let ctx = registry_ctx();
        assert_eq!(indices(&get(&ctx, VALIDATORS_PATH, "id=2,3,7&status=active")), [2, 3]);
        assert!(indices(&get(&ctx, VALIDATORS_PATH, "id=2&status=exited")).is_empty());
    }

    /// The POST body exists only to carry longer lists, so the same filter
    /// must produce the same bytes down either verb.
    #[test]
    fn post_and_get_answer_the_same_filter_with_the_same_bytes() {
        let ctx = registry_ctx();
        for (query, json_body) in [
            ("", "{}"),
            ("id=2,3", r#"{"ids":["2","3"]}"#),
            ("status=active", r#"{"statuses":["active"]}"#),
            ("id=2,3,7&status=active", r#"{"ids":["2","3","7"],"statuses":["active"]}"#),
        ] {
            assert_eq!(
                ok_body(&get(&ctx, VALIDATORS_PATH, query)),
                ok_body(&post(&ctx, VALIDATORS_PATH, json_body)),
                "{query}"
            );
        }
    }

    #[test]
    fn a_pubkey_id_reaches_the_registry_index_through_the_post_body_too() {
        let ctx = registry_ctx();
        let json_body = format!(r#"{{"ids":["{}"]}}"#, pubkey_text(6));
        assert_eq!(indices(&post(&ctx, VALIDATORS_PATH, &json_body)), [6]);
    }

    #[test]
    fn a_query_naming_no_validator_or_status_at_all_is_a_400() {
        let ctx = registry_ctx();
        assert_error(
            &get(&ctx, VALIDATORS_PATH, "id=banana"),
            "400 Bad Request",
            400,
            "invalid validator id",
        );
        assert_error(
            &get(&ctx, VALIDATORS_PATH, "status=banana"),
            "400 Bad Request",
            400,
            "invalid validator status",
        );
    }

    #[test]
    fn more_query_ids_than_the_schema_allows_is_a_414() {
        let ids = (0..65).map(|i| i.to_string()).collect::<Vec<_>>().join(",");
        assert_error(
            &get(&registry_ctx(), VALIDATORS_PATH, &format!("id={ids}")),
            "414 URI Too Long",
            414,
            "too many validator ids in request",
        );
    }

    #[test]
    fn a_post_body_that_is_not_the_schema_s_object_is_a_400() {
        let ctx = registry_ctx();
        for body in ["not json", "", "[]"] {
            assert_error(
                &post(&ctx, VALIDATORS_PATH, body),
                "400 Bad Request",
                400,
                "invalid request body",
            );
        }
    }

    /// Body shape: `GetStateValidatorResponse` of
    /// `apis/beacon/states/validator.yaml` — one `ValidatorResponse`, not an
    /// array holding one.
    #[test]
    fn the_single_validator_body_is_the_envelope_around_one_entry() {
        let ctx = registry_ctx();
        let by_index = ok_body(&get(&ctx, "/eth/v1/beacon/states/head/validators/2", ""));
        let path = format!("/eth/v1/beacon/states/head/validators/{}", pubkey_text(2));
        assert_eq!(by_index, ok_body(&get(&ctx, &path, "")));
        assert!(
            by_index.starts_with(
                "{\"execution_optimistic\":false,\"finalized\":false,\"data\":{\"index\":\"2\",\
                 \"balance\":\"32100000000\",\"status\":\"active_ongoing\",\"validator\":{"
            ),
            "{by_index}"
        );
        let parsed: serde_json::Value = serde_json::from_str(&by_index).unwrap();
        assert!(parsed["data"].is_object(), "one entry, not an array");
    }

    /// The list endpoint leaves out an id it cannot resolve; this one has
    /// nothing left to return, so its schema answers 404.
    #[test]
    fn a_single_validator_id_matching_no_validator_is_a_404() {
        let ctx = registry_ctx();
        for id in ["9", &format!("0x{}", hex::encode([0xff; 48]))] {
            assert_error(
                &get(&ctx, &format!("/eth/v1/beacon/states/head/validators/{id}"), ""),
                "404 Not Found",
                404,
                "validator not found",
            );
        }
    }

    /// A segment naming no validator at all is malformed whatever state it was
    /// asked against, so it is answered ahead of the state_id — including
    /// ahead of the 404 a state silver does not keep would get.
    #[test]
    fn a_validator_id_naming_no_validator_at_all_is_a_400() {
        let ctx = registry_ctx();
        for id in ["banana", "-1", "+1", "0x", "0xzz", "18446744073709551616", ""] {
            for state_id in ["head", "finalized", "banana"] {
                assert_error(
                    &get(&ctx, &format!("/eth/v1/beacon/states/{state_id}/validators/{id}"), ""),
                    "400 Bad Request",
                    400,
                    "invalid validator_id",
                );
            }
        }
    }

    fn all_three_routes(state_id: &str) -> [(String, &'static str); 3] {
        [
            (format!("/eth/v1/beacon/states/{state_id}/validators"), "GET"),
            (format!("/eth/v1/beacon/states/{state_id}/validators"), "POST"),
            (format!("/eth/v1/beacon/states/{state_id}/validators/0"), "GET"),
        ]
    }

    fn answer(ctx: &ApiCtx, path: &str, method: &str) -> Vec<u8> {
        match method {
            "POST" => post(ctx, path, "{}"),
            _ => get(ctx, path, ""),
        }
    }

    /// Silver publishes one state, the head. Every other identifier the
    /// schemas define names a state it does not keep; anything else names no
    /// state at all. All three routes answer by the same table.
    #[test]
    fn the_state_id_table_is_the_one_every_state_read_answers_by() {
        let ctx = registry_ctx();
        for (path, method) in all_three_routes("head") {
            assert!(answer(&ctx, &path, method).starts_with(b"HTTP/1.1 200 OK\r\n"), "{path}");
        }
        let root = format!("0x{}", "ab".repeat(32));
        for state_id in ["genesis", "justified", "finalized", "0", "3200", &root] {
            for (path, method) in all_three_routes(state_id) {
                assert_error(&answer(&ctx, &path, method), "404 Not Found", 404, "state not found");
            }
        }
        for state_id in ["current", "banana", "-1", "+5", "0x", "1.5", "HEAD"] {
            for (path, method) in all_three_routes(state_id) {
                assert_error(
                    &answer(&ctx, &path, method),
                    "400 Bad Request",
                    400,
                    "invalid state_id",
                );
            }
        }
    }

    /// The table carries both verbs on the list route and only GET on the
    /// single-validator one, so a POST there is a 405 rather than a 404.
    #[test]
    fn the_route_table_takes_the_two_verbs_the_schemas_declare() {
        let ctx = registry_ctx();
        assert!(
            post(&ctx, "/eth/v1/beacon/states/head/validators/0", "{}")
                .starts_with(b"HTTP/1.1 405 Method Not Allowed\r\n")
        );
        assert!(
            dispatch(&ctx, &request("PUT", VALIDATORS_PATH, "", b""))
                .starts_with(b"HTTP/1.1 405 Method Not Allowed\r\n")
        );
    }

    #[test]
    fn every_validator_route_is_404_before_the_first_state_is_published() {
        let ctx = preboot_ctx();
        for (path, method) in all_three_routes("head") {
            assert_error(&answer(&ctx, &path, method), "404 Not Found", 404, "state not found");
        }
    }

    /// [`BeaconStateReader::read`] re-runs its closure whole when a finalize
    /// lands mid-read, so the sweep must be a pure function of the view: two
    /// runs against one view produce the same entries, and rendering them
    /// twice produces two identical bodies rather than one doubled body.
    #[test]
    fn re_running_the_sweep_against_one_view_repeats_it_rather_than_extending_it() {
        let (seeds, extras) = one_per_status();
        let (owner, head) = published_state(&seeds, &extras, HEAD_SLOT);
        let view = owner.read_view(head);
        let filter = Filter::from_query("status=active").unwrap();

        let first = ValidatorEntry::matching(&view, &filter);
        let second = ValidatorEntry::matching(&view, &filter);
        assert_eq!(first, second);
        assert_eq!(first.len(), 3);

        let render = |entries: &[ValidatorEntry]| {
            let mut out = Vec::new();
            Json::new(&mut out).validators(entries);
            out
        };
        assert_eq!(render(&first), render(&second));
        assert_eq!(render(&second).len(), render(&first).len());
    }

    /// "If the supplied list is empty (i.e. the value is `[]`) or the property
    /// is omitted then all validators will be returned" — whatever the
    /// registry holds, down either verb, and with the status filter alone
    /// answerable the same way.
    #[test]
    fn an_empty_filter_returns_the_whole_registry_however_large_it_is() {
        let ctx = bulk_registry_ctx();
        let unfiltered = get(&ctx, VALIDATORS_PATH, "");
        assert_eq!(listed(&unfiltered).len(), BULK_REGISTRY);
        assert_eq!(post(&ctx, VALIDATORS_PATH, "{}"), unfiltered);
        assert_eq!(post(&ctx, VALIDATORS_PATH, r#"{"ids":[]}"#), unfiltered);
        assert_eq!(post(&ctx, VALIDATORS_PATH, r#"{"ids":null,"statuses":null}"#), unfiltered);

        let active = get(&ctx, VALIDATORS_PATH, "status=active");
        assert_eq!(listed(&active).len(), BULK_REGISTRY - 1, "index 0 is still pending");
        assert_eq!(post(&ctx, VALIDATORS_PATH, r#"{"statuses":["active"]}"#), active);
    }

    /// The schemas put no `maxItems` on `status`, and a request may repeat one
    /// value as many times as it has bytes for. A value no validator carries
    /// is the worst case — nothing short-circuits — so this is the sweep the
    /// registry-times-list cost would show up in: it must stay one sweep.
    #[test]
    fn a_status_repeated_across_a_whole_request_still_costs_one_sweep() {
        let ctx = bulk_registry_ctx();
        let flood = vec!["status=exited_slashed"; 100_000].join("&");

        let started = Instant::now();
        let flooded = get(&ctx, VALIDATORS_PATH, &flood);
        let elapsed = started.elapsed();

        assert_eq!(flooded, get(&ctx, VALIDATORS_PATH, "status=exited_slashed"));
        assert!(listed(&flooded).is_empty(), "no validator here is exited_slashed");
        // One sweep of this registry is well under a millisecond; the
        // registry-times-list product would be 2e9 status comparisons.
        assert!(elapsed < Duration::from_secs(5), "{elapsed:?} for one sweep");
    }
}
