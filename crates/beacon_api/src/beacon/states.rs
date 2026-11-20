use silver_beacon_state_data::{
    B256, EPOCHS_PER_HISTORICAL_VECTOR, Epoch, SYNC_COMMITTEE_SIZE, SYNC_SUBCOMMITTEE_SIZE,
};
use silver_common::json_fields::parse_uint64;
use silver_httpcore::Query;

use crate::{
    NodeStatus,
    ctx::ApiCtx,
    http::{
        json::{FinalityCheckpoints, GenesisData},
        response::Response,
        router::Request,
    },
    validator::sync_duties::CommitteePeriod,
};

pub(crate) fn genesis(_req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    let genesis = ctx.read_state(|view| GenesisData {
        genesis_time: view.imm.genesis_time,
        genesis_validators_root: view.imm.genesis_validators_root,
        genesis_fork_version: view.imm.genesis_fork_version,
    });
    resp.json_body(|json| json.data_envelope(|json| json.genesis(&genesis)));
}

pub(crate) fn state_fork(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    ctx.state_response(req, resp, |view, json| json.fork(view.epoch.fork()));
}

pub(crate) fn state_finality_checkpoints(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    ctx.state_response(req, resp, |view, json| {
        let epoch = view.epoch.state();
        json.finality_checkpoints(&FinalityCheckpoints {
            previous_justified: epoch.previous_justified_checkpoint,
            current_justified: epoch.current_justified_checkpoint,
            finalized: epoch.finalized_checkpoint,
        })
    });
}

/// The head block's post-state root, which is the published state's while
/// that state still sits at the block's slot. Slot processing advances the
/// published state past it, to a root nothing computes.
pub(crate) fn state_root(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    let NodeStatus { head_root, head_state_root, .. } = ctx.node_status;
    ctx.try_state_response(req, resp, |view, json| {
        let slot = view.slot.state();
        let known = head_state_root != B256::default() &&
            slot.latest_block_root == head_root &&
            slot.slot == slot.latest_block_header.slot;
        if !known {
            return Err((503, "head state root not yet known"));
        }
        json.root(&head_state_root);
        Ok(())
    });
}

pub(crate) fn state_randao(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    let Ok(epoch) = epoch_query(req.query) else {
        return resp.error(400, "invalid epoch");
    };
    ctx.try_state_response(req, resp, |view, json| {
        let state_epoch = view.slot.current_epoch();
        let epoch = epoch.unwrap_or(state_epoch);
        let held =
            epoch <= state_epoch && state_epoch - epoch < EPOCHS_PER_HISTORICAL_VECTOR as Epoch;
        if !held {
            return Err((400, "epoch is outside the state's randao mixes"));
        }
        json.randao(&view.randao_mixes.at_epoch(epoch));
        Ok(())
    });
}

pub(crate) fn state_sync_committees(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    let Ok(epoch) = epoch_query(req.query) else {
        return resp.error(400, "invalid epoch");
    };
    ctx.try_state_response(req, resp, |view, json| {
        let state_epoch = view.slot.current_epoch();
        let period = CommitteePeriod::serving(epoch.unwrap_or(state_epoch), state_epoch)
            .ok_or((400, "the state holds no sync committee for this epoch"))?;
        let mut validators = [0u32; SYNC_COMMITTEE_SIZE];
        for (position, index) in validators.iter_mut().enumerate() {
            *index = period
                .validator_index(view, position)
                .ok_or((500, "a sync committee member is not in the registry"))?;
        }
        json.sync_committee_indices(&validators, SYNC_SUBCOMMITTEE_SIZE);
        Ok(())
    });
}

fn epoch_query(query: &str) -> Result<Option<Epoch>, ()> {
    Query::new(query)
        .find(|(name, _)| name == "epoch")
        .map(|(_, value)| parse_uint64(&value).ok_or(()))
        .transpose()
}

#[cfg(test)]
mod tests {
    use silver_beacon_state_data::{
        BeaconBlockHeader, BeaconState, BeaconStateOwner, Checkpoint, EpochState,
        EpochStateFinalized, Fork, SLOTS_PER_EPOCH, SlotState, SlotStateFinalized, SlotStateGroup,
        SpecConfig,
    };
    use silver_common::ELSyncStatus;
    use silver_httpcore::ParsedRequest;

    use crate::{
        NodeStatus,
        ctx::{ApiCtx, anchor_ctx, test_ctx},
        node::status::tests::{ready, with_head_optimistic},
        testing::{answer, body, request},
    };

    fn get(ctx: &ApiCtx, path: &str) -> Vec<u8> {
        answer(ctx, &request("GET", path))
    }

    /// First slot of the epoch two past [`epoch_state`]'s finalized
    /// checkpoint — normal operation, where head is not the finalized state.
    const HEAD_SLOT: u64 = 12_345 * SLOTS_PER_EPOCH;

    fn epoch_state() -> EpochState {
        EpochState {
            fork: Fork {
                previous_version: [0x05, 0x00, 0x00, 0x00],
                current_version: [0x06, 0x00, 0x00, 0x00],
                epoch: 269_568,
            },
            previous_justified_checkpoint: Checkpoint { epoch: 12_344, root: [0x01; 32] },
            current_justified_checkpoint: Checkpoint { epoch: 12_345, root: [0x02; 32] },
            finalized_checkpoint: Checkpoint { epoch: 12_343, root: [0x03; 32] },
            ..Default::default()
        }
    }

    /// A synced node with its one state published — every distinct value these
    /// endpoints read is set, so a golden catches a swapped field.
    fn published_ctx(epoch: EpochState, slot: u64) -> ApiCtx {
        let mut state = BeaconState::for_test(EpochStateFinalized::from_state(epoch), &[], slot);
        state.slot_states = SlotStateGroup::new(SlotStateFinalized::new(SlotState {
            slot,
            latest_block_header: BeaconBlockHeader { slot, ..Default::default() },
            ..Default::default()
        }));
        state.immutable.genesis_time = 1_606_824_023;
        state.immutable.genesis_validators_root = [0x4b; 32];
        state.immutable.genesis_fork_version = [0x00, 0x00, 0x00, 0x01];

        let mut owner = BeaconStateOwner::new(state);
        let anchor = owner.roll_fresh();
        owner.publish_state_id(anchor);

        let mut ctx = test_ctx(&SpecConfig::mainnet(), owner.reader());
        ctx.node_status = ready();
        ctx
    }

    fn state_paths(state_id: &str) -> [String; 2] {
        [
            format!("/eth/v1/beacon/states/{state_id}/fork"),
            format!("/eth/v1/beacon/states/{state_id}/finality_checkpoints"),
        ]
    }

    fn state_body(ctx: &ApiCtx, path: &str) -> String {
        let resp = get(ctx, path);
        assert!(
            resp.starts_with(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"),
            "{path}: {}",
            String::from_utf8_lossy(&resp)
        );
        String::from_utf8(body(&resp).to_vec()).unwrap()
    }

    /// Body shape: `apis/beacon/genesis.yaml` — a bare `data` wrapper, the one
    /// state read that carries no envelope flags.
    #[test]
    fn genesis_body_is_a_bare_data_wrapper() {
        let ctx = published_ctx(epoch_state(), HEAD_SLOT);
        assert_eq!(
            state_body(&ctx, "/eth/v1/beacon/genesis"),
            "{\"data\":{\"genesis_time\":\"1606824023\",\
             \"genesis_validators_root\":\"0x4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b\",\
             \"genesis_fork_version\":\"0x00000001\"}}"
        );
    }

    /// Body shape: `apis/beacon/states/fork.yaml`.
    #[test]
    fn state_fork_body_is_the_envelope_around_the_fork() {
        let ctx = published_ctx(epoch_state(), HEAD_SLOT);
        assert_eq!(
            state_body(&ctx, "/eth/v1/beacon/states/head/fork"),
            "{\"execution_optimistic\":false,\"finalized\":false,\
             \"data\":{\"previous_version\":\"0x05000000\",\"current_version\":\"0x06000000\",\
             \"epoch\":\"269568\"}}"
        );
    }

    /// Body shape: `apis/beacon/states/finality_checkpoints.yaml`.
    #[test]
    fn finality_checkpoints_body_is_the_envelope_around_three_checkpoints() {
        let ctx = published_ctx(epoch_state(), HEAD_SLOT);
        assert_eq!(
            state_body(&ctx, "/eth/v1/beacon/states/head/finality_checkpoints"),
            "{\"execution_optimistic\":false,\"finalized\":false,\"data\":{\
             \"previous_justified\":{\"epoch\":\"12344\",\
             \"root\":\"0x0101010101010101010101010101010101010101010101010101010101010101\"},\
             \"current_justified\":{\"epoch\":\"12345\",\
             \"root\":\"0x0202020202020202020202020202020202020202020202020202020202020202\"},\
             \"finalized\":{\"epoch\":\"12343\",\
             \"root\":\"0x0303030303030303030303030303030303030303030303030303030303030303\"}}}"
        );
    }

    fn assert_state_not_found(ctx: &ApiCtx, state_id: &str) {
        for path in state_paths(state_id) {
            let resp = get(ctx, &path);
            assert!(resp.starts_with(b"HTTP/1.1 404 Not Found\r\n"), "{path}");
            assert_eq!(body(&resp), br#"{"code":404,"message":"state not found"}"#, "{path}");
        }
    }

    /// Silver publishes one state, the head. `justified` and `finalized` name
    /// states it does not keep, and their checkpoints differ from the head's,
    /// so answering them with head data would be a wrong answer rather than a
    /// missing one.
    #[test]
    fn only_head_reads_the_published_state() {
        let ctx = published_ctx(epoch_state(), HEAD_SLOT);
        for path in state_paths("head") {
            assert!(state_body(&ctx, &path).starts_with("{\"execution_optimistic\":false,"));
        }
        assert_state_not_found(&ctx, "justified");
        assert_state_not_found(&ctx, "finalized");
    }

    /// `Invalid state ID` in the schemas: a value that identifies no state at
    /// all is a 400, not the 404 an unavailable state gets.
    #[test]
    fn state_id_naming_no_state_at_all_is_400() {
        let ctx = published_ctx(epoch_state(), HEAD_SLOT);
        let short_root = format!("0x{}", "ab".repeat(31));
        let unhex_root = format!("0x{}", "zz".repeat(32));
        for state_id in
            ["current", "banana", "", "-1", "+5", "0x", "1.5", &short_root, &unhex_root, "HEAD"]
        {
            for path in state_paths(state_id) {
                let resp = get(&ctx, &path);
                assert!(resp.starts_with(b"HTTP/1.1 400 Bad Request\r\n"), "{path}");
                assert_eq!(body(&resp), br#"{"code":400,"message":"invalid state_id"}"#, "{path}");
            }
        }
    }

    /// The `state_id` verdict does not depend on there being a state to read.
    #[test]
    fn invalid_state_id_is_answered_before_the_state_is_read() {
        for path in state_paths("banana") {
            let resp = get(&anchor_ctx(), &path);
            assert!(resp.starts_with(b"HTTP/1.1 400 Bad Request\r\n"), "{path}");
        }
    }

    /// The envelope flag is the head's own execution status, not a reading of
    /// how far behind the node is: an unverified head is optimistic with both
    /// layers reporting themselves synced, and a verified one is not while they
    /// do not.
    #[test]
    fn execution_optimistic_is_the_head_s_own_status() {
        let mut ctx = published_ctx(epoch_state(), HEAD_SLOT);
        for (status, want) in [
            (with_head_optimistic(true), "true"),
            (with_head_optimistic(false), "false"),
            (NodeStatus { el: ELSyncStatus::Offline, ..with_head_optimistic(false) }, "false"),
        ] {
            ctx.node_status = status;
            for path in state_paths("head") {
                assert!(
                    state_body(&ctx, &path)
                        .starts_with(&format!("{{\"execution_optimistic\":{want},")),
                    "{status:?} {path}"
                );
            }
        }
    }

    #[test]
    fn finalized_is_whether_the_head_block_is_at_or_before_the_checkpoint() {
        let genesis_epoch = EpochState {
            previous_justified_checkpoint: Checkpoint::default(),
            current_justified_checkpoint: Checkpoint::default(),
            finalized_checkpoint: Checkpoint::default(),
            ..epoch_state()
        };
        let mut at_genesis = published_ctx(genesis_epoch, 0);
        at_genesis.node_status.finalized_epoch = 0;
        let mut at_anchor = published_ctx(epoch_state(), HEAD_SLOT);
        at_anchor.node_status.finalized_epoch = HEAD_SLOT / SLOTS_PER_EPOCH;
        let past_finality = published_ctx(epoch_state(), HEAD_SLOT);
        for path in state_paths("head") {
            let flags = "{\"execution_optimistic\":false,\"finalized\":";
            assert!(state_body(&at_genesis, &path).starts_with(&format!("{flags}true,")));
            assert!(state_body(&at_anchor, &path).starts_with(&format!("{flags}true,")));
            assert!(state_body(&past_finality, &path).starts_with(&format!("{flags}false,")));
        }
    }

    #[test]
    fn state_id_naming_a_state_silver_does_not_keep_is_404() {
        let ctx = published_ctx(epoch_state(), HEAD_SLOT);
        let head_slot = HEAD_SLOT.to_string();
        for state_id in ["genesis", "0", &head_slot, &format!("0x{}", "ab".repeat(32))] {
            assert_state_not_found(&ctx, state_id);
        }
    }

    #[test]
    fn state_root_answers_while_the_status_names_the_published_head() {
        let mut ctx = published_ctx(epoch_state(), HEAD_SLOT);
        let path = "/eth/v1/beacon/states/head/root";
        let resp = get(&ctx, path);
        assert!(resp.starts_with(b"HTTP/1.1 503 "), "{}", String::from_utf8_lossy(&resp));

        ctx.node_status.head_root = ctx.read_state(|view| view.slot.state().latest_block_root);
        let body = state_body(&ctx, path);
        let root = format!("0x{}", "12".repeat(32));
        assert_eq!(
            body,
            format!(
                r#"{{"execution_optimistic":false,"finalized":false,"data":{{"root":"{root}"}}}}"#
            )
        );
    }

    /// Past an empty slot the published state keeps the block's root but no
    /// longer its post-state root.
    #[test]
    fn state_root_is_unknown_once_the_state_advances_past_its_block() {
        let owner = BeaconStateOwner::published_empty_test(HEAD_SLOT);
        let mut ctx = test_ctx(&SpecConfig::mainnet(), owner.reader());
        ctx.node_status = ready();
        ctx.node_status.head_root = ctx.read_state(|view| view.slot.state().latest_block_root);
        let resp = get(&ctx, "/eth/v1/beacon/states/head/root");
        assert!(resp.starts_with(b"HTTP/1.1 503 "), "{}", String::from_utf8_lossy(&resp));
    }

    fn get_query(ctx: &ApiCtx, path: &str, query: &str) -> Vec<u8> {
        answer(ctx, &ParsedRequest { query, ..request("GET", path) })
    }

    fn query_body(ctx: &ApiCtx, path: &str, query: &str) -> serde_json::Value {
        let resp = get_query(ctx, path, query);
        assert!(resp.starts_with(b"HTTP/1.1 200 OK\r\n"), "{path}?{query}");
        serde_json::from_slice(body(&resp)).unwrap()
    }

    /// The fixture's epoch is below `EPOCHS_PER_HISTORICAL_VECTOR`, so every
    /// epoch up to it is held.
    #[test]
    fn randao_defaults_to_the_state_epoch_and_refuses_unheld_epochs() {
        let ctx = published_ctx(epoch_state(), HEAD_SLOT);
        let path = "/eth/v1/beacon/states/head/randao";
        let epoch = HEAD_SLOT / SLOTS_PER_EPOCH;
        let zero = format!("0x{}", "00".repeat(32));
        for query in [String::new(), format!("epoch={epoch}"), "epoch=0".to_string()] {
            assert_eq!(query_body(&ctx, path, &query)["data"]["randao"], zero, "{query}");
        }
        for query in ["epoch=x".to_string(), format!("epoch={}", epoch + 1)] {
            assert!(get_query(&ctx, path, &query).starts_with(b"HTTP/1.1 400 "), "{query}");
        }
    }

    #[test]
    fn sync_committees_list_the_period_members_and_their_subcommittees() {
        use crate::validator::sync_duties::tests::{ctx, next_period_epoch, seat_holders};

        let ctx = ctx();
        let indices = |body: &serde_json::Value| -> Vec<u32> {
            body["data"]["validators"]
                .as_array()
                .unwrap()
                .iter()
                .map(|index| index.as_str().unwrap().parse().unwrap())
                .collect()
        };
        let path = "/eth/v1/beacon/states/head/sync_committees";
        let current = query_body(&ctx, path, "");
        assert_eq!(indices(&current), seat_holders(0));
        let aggregates = current["data"]["validator_aggregates"].as_array().unwrap();
        assert_eq!(aggregates.len(), 4);
        assert!(
            aggregates.iter().all(|subcommittee| subcommittee.as_array().unwrap().len() == 128)
        );

        let next = query_body(&ctx, path, &format!("epoch={}", next_period_epoch()));
        assert_eq!(indices(&next), seat_holders(1));

        let past = get_query(&ctx, path, &format!("epoch={}", next_period_epoch() + 256));
        assert!(past.starts_with(b"HTTP/1.1 400 "));
    }
}
