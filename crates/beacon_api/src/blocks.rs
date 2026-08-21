use silver_beacon_state_data::{B256, BLSSignature, BeaconBlockHeader, Slot, StateReadView};

use crate::{
    ids::{parse_root, parse_uint64},
    json::ReadFlags,
    response::Response,
    router::Request,
    routes::ApiCtx,
};

/// `Block not found` in `apis/beacon/blocks/root.yaml` — the only answer
/// either schema offers for a block silver cannot name, whether the chain has
/// none there or this crate has no read path to it.
const NOT_FOUND: &str = "block not found";

const ZERO_ROOT: B256 = [0u8; 32];

/// The state carries `latest_block_header`, which the spec strips of the
/// signature the block arrived with, and the beacon-API tile has no channel to
/// the block store to read the original from. `SignedBeaconBlockHeader`
/// requires the field.
const UNAVAILABLE_SIGNATURE: BLSSignature = [0u8; 96];

/// Required beside `root` by the header schema. Asserted, not proved: these
/// endpoints read the last state applied, and fork choice — which re-heads on
/// attestations, between publishes — may have passed that branch over.
const CANONICAL: bool = true;

pub(crate) fn get_block_root(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    let Some(block) = read_block(req, ctx, resp) else {
        return;
    };
    let flags = block.flags(ctx.node_status.execution_optimistic());
    resp.json_body(|json| json.flagged_envelope(flags, |json| json.block_root(&block.root)));
}

pub(crate) fn get_block_header(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    let Some(block) = read_block(req, ctx, resp) else {
        return;
    };
    let Some(header) = block.header else {
        resp.error(404, NOT_FOUND);
        return;
    };
    let flags = block.flags(ctx.node_status.execution_optimistic());
    resp.json_body(|json| {
        json.flagged_envelope(flags, |json| {
            json.block_header_data(&block.root, CANONICAL, &header, &UNAVAILABLE_SIGNATURE)
        })
    });
}

fn read_block(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) -> Option<Block> {
    let named = req.params.get("block_id").expect("{block_id} in the route pattern");
    let Some(block_id) = BlockId::parse(named) else {
        resp.error(400, "invalid block_id");
        return None;
    };
    let block = ctx.read_state_or(resp, 404, NOT_FOUND, |view, head_root| {
        block_id.resolve(&view, head_root)
    })?;
    if block.is_none() {
        resp.error(404, NOT_FOUND);
    }
    block
}

struct Block {
    root: B256,
    /// The head block's header, and only while the state carries it whole —
    /// every other block this crate can name, it can name only by root.
    header: Option<BeaconBlockHeader>,
    finalized: bool,
}

impl Block {
    fn flags(&self, execution_optimistic: bool) -> ReadFlags {
        ReadFlags { execution_optimistic, finalized: self.finalized }
    }
}

/// `block_id` (`params/index.yaml#/BlockId`): a keyword, a slot, or a block
/// root. Not `state_id`'s vocabulary — `justified` names a state, never a
/// block. `genesis` is the first slot's block by another name.
#[derive(Clone, Copy)]
enum BlockId {
    Head,
    Finalized,
    Slot(Slot),
    Root(B256),
}

impl BlockId {
    fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "head" => Self::Head,
            "genesis" => Self::Slot(0),
            "finalized" => Self::Finalized,
            _ => match parse_uint64(text) {
                Some(slot) => Self::Slot(slot),
                None => Self::Root(parse_root(text)?),
            },
        })
    }

    /// `head_root` names the block the published state was applied from, which
    /// the state itself cannot: between that block's arrival and the next slot
    /// its header is the state's own with `state_root` still zero, and the
    /// `block_roots` entry naming it is written by the `process_slot` that
    /// fills it.
    fn resolve(self, view: &StateReadView<'_>, head_root: B256) -> Option<Block> {
        let head = view.slot.state().latest_block_header;
        let (root, finalized) = match self {
            Self::Head => (head_root, view.epoch.finalizes_slot(head.slot)),
            Self::Slot(slot) if slot == head.slot => (head_root, view.epoch.finalizes_slot(slot)),
            Self::Slot(slot) => (
                view.block_roots.proposed_at(slot, view.slot.slot_number())?,
                view.epoch.finalizes_slot(slot),
            ),
            Self::Finalized => (view.epoch.finalized_block_root()?, true),
            Self::Root(root) if root == head_root => (root, view.epoch.finalizes_slot(head.slot)),
            // Every other root is a block this crate has no read path to.
            Self::Root(_) => return None,
        };
        let header = (root == head_root && head.state_root != ZERO_ROOT).then_some(head);
        Some(Block { root, header, finalized })
    }
}

#[cfg(test)]
mod tests {
    use silver_beacon_state_data::{
        BeaconState, BeaconStateOwner, Checkpoint, EpochState, EpochStateFinalized,
        SLOTS_PER_EPOCH, SLOTS_PER_HISTORICAL_ROOT, SpecConfig, ValSeed,
    };
    use silver_common::ELSyncStatus;
    use silver_httpcore::ParsedRequest;

    use super::*;
    use crate::{
        NodeStatus, PeerCounts, SlotStatus,
        router::Router,
        routes::{ROUTES, preboot_ctx, test_ctx},
    };

    const FINALIZED_EPOCH: u64 = 280;
    const FINALIZED_SLOT: Slot = FINALIZED_EPOCH * SLOTS_PER_EPOCH;

    const HEAD_BLOCK_SLOT: Slot = 9_000;
    const STATE_SLOT: Slot = HEAD_BLOCK_SLOT + 1;
    const EMPTY_SLOT: Slot = HEAD_BLOCK_SLOT - 1;

    /// How far back the fixture chains are recorded: the ring holds an entry
    /// per slot from there up, and zeros below. A real ring holds all
    /// `SLOTS_PER_HISTORICAL_ROOT` slots below the state's own, whose wrap
    /// arithmetic belongs to — and is tested with — `RootsView::proposed_at`.
    const RECORDED_SLOTS: Slot = 64;

    /// A chain young enough that its first slot is still recorded, and too
    /// young to have finalized anything.
    const YOUNG_STATE_SLOT: Slot = 11;

    /// Roots keyed by the slot they belong to and by what they are, so a body
    /// that mixes two of them up says which.
    fn block_root_of(slot: Slot) -> B256 {
        tagged(0xb0, slot)
    }

    fn state_root_of(slot: Slot) -> B256 {
        tagged(0x57, slot)
    }

    fn body_root_of(slot: Slot) -> B256 {
        tagged(0xd0, slot)
    }

    fn tagged(kind: u8, slot: Slot) -> B256 {
        let mut root = [kind; 32];
        root[24..].copy_from_slice(&slot.to_be_bytes());
        root
    }

    /// Distinct from the slot it proposed at, so a body that reports one for
    /// the other says which.
    fn proposer_of(slot: Slot) -> u64 {
        slot + 11
    }

    fn root_text(root: B256) -> String {
        format!("0x{}", hex::encode(root))
    }

    fn epoch_base(finalized: Checkpoint) -> EpochStateFinalized {
        EpochStateFinalized::from_state(EpochState {
            finalized_checkpoint: finalized,
            ..Default::default()
        })
    }

    /// A published head state grown a slot at a time the way the tile grows
    /// one: every slot carries a block bar `empty_slots`, and the
    /// `process_slot` that leaves a slot fills the previous header's
    /// `state_root` and records the latest block's root. The walk stops with
    /// the state at `state_slot`, so a block there is one no slot has followed
    /// — and the newest block's root is published beside the state, as the
    /// tile publishes it.
    fn published_chain(finalized: Checkpoint, empty_slots: &[Slot], state_slot: Slot) -> ApiCtx {
        let base_slot = state_slot.saturating_sub(RECORDED_SLOTS);
        let mut owner = BeaconStateOwner::new(BeaconState::for_test(
            epoch_base(finalized),
            &[ValSeed::default()],
            base_slot,
        ));
        let anchor = owner.roll_fresh();
        let (mut writer, _, _) = owner.apply_block_view(anchor);
        let mut head_root = ZERO_ROOT;
        for slot in base_slot..=state_slot {
            if !empty_slots.contains(&slot) {
                writer.slot.state_mut().latest_block_header = BeaconBlockHeader {
                    slot,
                    proposer_index: proposer_of(slot),
                    parent_root: head_root,
                    state_root: ZERO_ROOT,
                    body_root: body_root_of(slot),
                };
                head_root = block_root_of(slot);
            }
            if slot == state_slot {
                break;
            }
            writer.slot.fill_latest_block_header_state_root(state_root_of(slot));
            let latest_block = writer.slot.state().latest_block_header.slot;
            let bucket = (slot % SLOTS_PER_HISTORICAL_ROOT as u64) as u32;
            writer.block_roots.set(bucket, block_root_of(latest_block));
            writer.slot.advance_slot();
        }
        let head = writer.commit(None, None);
        owner.set_head_block_root(head_root);
        owner.publish_state_id(head);

        let mut ctx = test_ctx(&SpecConfig::mainnet(), owner.reader());
        ctx.node_status = NodeStatus {
            slots: Some(SlotStatus {
                head_slot: state_slot,
                wall_slot: state_slot,
                head_optimistic: false,
            }),
            syncing: false,
            el: ELSyncStatus::Synced,
            peers: PeerCounts::default(),
        };
        ctx
    }

    fn finalized_checkpoint() -> Checkpoint {
        Checkpoint { epoch: FINALIZED_EPOCH, root: block_root_of(FINALIZED_SLOT) }
    }

    /// The ordinary state: the last block is a slot behind, so its own
    /// `state_root` is in and the state carries its whole header.
    fn head_ctx() -> ApiCtx {
        published_chain(finalized_checkpoint(), &[EMPTY_SLOT, STATE_SLOT], STATE_SLOT)
    }

    /// The state between a block's arrival and the next slot: the head block
    /// is the state's own, at [`STATE_SLOT`], with `state_root` still zero.
    fn just_applied_ctx() -> ApiCtx {
        published_chain(finalized_checkpoint(), &[EMPTY_SLOT], STATE_SLOT)
    }

    fn young_ctx() -> ApiCtx {
        published_chain(Checkpoint::default(), &[YOUNG_STATE_SLOT], YOUNG_STATE_SLOT)
    }

    fn root_path(block_id: &str) -> String {
        format!("/eth/v1/beacon/blocks/{block_id}/root")
    }

    fn header_path(block_id: &str) -> String {
        format!("/eth/v1/beacon/headers/{block_id}")
    }

    fn paths(block_id: &str) -> [String; 2] {
        [root_path(block_id), header_path(block_id)]
    }

    fn get(ctx: &ApiCtx, path: &str) -> Vec<u8> {
        let req = ParsedRequest {
            method: "GET",
            path,
            query: "",
            body: b"",
            accept: None,
            content_type: None,
            eth_consensus_version: None,
            version: 1,
            keep_alive: true,
        };
        let mut out = Vec::new();
        Router::new(ROUTES).dispatch(&req, ctx, &mut out);
        out
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

    fn parsed(ctx: &ApiCtx, path: &str) -> serde_json::Value {
        serde_json::from_str(&ok_body(&get(ctx, path))).expect("valid JSON")
    }

    fn served_root(ctx: &ApiCtx, block_id: &str) -> String {
        parsed(ctx, &root_path(block_id))["data"]["root"].as_str().unwrap().to_owned()
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

    fn assert_not_found(ctx: &ApiCtx, block_id: &str) {
        for path in paths(block_id) {
            assert_error(&get(ctx, &path), "404 Not Found", 404, NOT_FOUND);
        }
    }

    fn assert_no_header(ctx: &ApiCtx, block_id: &str) {
        assert_error(&get(ctx, &header_path(block_id)), "404 Not Found", 404, NOT_FOUND);
    }

    /// Body shape: `GetBlockRootResponse` of `apis/beacon/blocks/root.yaml` —
    /// both envelope flags, then a `data` object of the one root.
    #[test]
    fn block_root_body_is_the_envelope_around_one_root() {
        assert_eq!(
            ok_body(&get(&head_ctx(), &root_path("head"))),
            format!(
                "{{\"execution_optimistic\":false,\"finalized\":false,\
                 \"data\":{{\"root\":\"{root}\"}}}}",
                root = root_text(block_root_of(HEAD_BLOCK_SLOT)),
            )
        );
    }

    /// Body shape: `GetBlockHeaderResponse` of `apis/beacon/blocks/header.yaml`
    /// — root, canonical and a `Phase0.SignedBeaconBlockHeader`, whose five
    /// message fields are quoted decimals and lowercase `0x`-hex.
    #[test]
    fn block_header_body_is_the_envelope_around_the_signed_header() {
        let expected = format!(
            "{{\"execution_optimistic\":false,\"finalized\":false,\"data\":{{\
             \"root\":\"{root}\",\"canonical\":true,\"header\":{{\"message\":{{\
             \"slot\":\"{HEAD_BLOCK_SLOT}\",\"proposer_index\":\"{proposer}\",\
             \"parent_root\":\"{parent}\",\"state_root\":\"{state}\",\"body_root\":\"{body}\"}},\
             \"signature\":\"{signature}\"}}}}}}",
            root = root_text(block_root_of(HEAD_BLOCK_SLOT)),
            proposer = proposer_of(HEAD_BLOCK_SLOT),
            parent = root_text(block_root_of(EMPTY_SLOT - 1)),
            state = root_text(state_root_of(HEAD_BLOCK_SLOT)),
            body = root_text(body_root_of(HEAD_BLOCK_SLOT)),
            signature = format!("0x{}", hex::encode(UNAVAILABLE_SIGNATURE)),
        );
        assert_eq!(ok_body(&get(&head_ctx(), &header_path("head"))), expected);
        serde_json::from_str::<serde_json::Value>(&expected).expect("valid JSON");
    }

    /// The head block answers to all three of its names, and to the same root
    /// under each — the header endpoint serves whichever of them resolves to
    /// the block whose header the state carries.
    #[test]
    fn the_head_block_answers_to_head_to_its_slot_and_to_its_root() {
        let ctx = head_ctx();
        let root = root_text(block_root_of(HEAD_BLOCK_SLOT));
        for block_id in ["head", &HEAD_BLOCK_SLOT.to_string(), &root] {
            assert_eq!(served_root(&ctx, block_id), root, "{block_id}");
            assert_eq!(parsed(&ctx, &header_path(block_id))["data"]["root"], root, "{block_id}");
        }
    }

    /// A slot older than the head names its own block — the ring holds the
    /// roots, and only the roots: the header endpoint has no header for it.
    #[test]
    fn an_older_slot_names_its_block_by_root_alone() {
        let ctx = head_ctx();
        let older = EMPTY_SLOT - 1;
        assert_eq!(served_root(&ctx, &older.to_string()), root_text(block_root_of(older)));
        assert_no_header(&ctx, &older.to_string());
    }

    /// `process_slot` repeats the last block's root through a slot that
    /// carried none, so the ring holding a root for a slot is not the same as
    /// a block being there.
    #[test]
    fn a_slot_that_carried_no_block_is_not_found() {
        assert_not_found(&head_ctx(), &EMPTY_SLOT.to_string());
    }

    /// Past the head block there is nothing to name: the state's own slot is
    /// where the next block will go, and the ring stops below it.
    #[test]
    fn a_slot_past_the_head_block_is_not_found() {
        let ctx = head_ctx();
        for slot in [STATE_SLOT, STATE_SLOT + 1, u64::MAX] {
            assert_not_found(&ctx, &slot.to_string());
        }
    }

    /// `genesis` is the first slot's block under another name, so the two
    /// forms cannot drift: both answer while the chain's first slot is still
    /// recorded, and neither does once it has fallen out.
    #[test]
    fn genesis_answers_exactly_as_the_first_slot_does() {
        let young = young_ctx();
        assert_eq!(served_root(&young, "genesis"), root_text(block_root_of(0)));
        assert_eq!(served_root(&young, "0"), served_root(&young, "genesis"));
        assert_eq!(parsed(&young, &root_path("genesis"))["finalized"], true);
        assert_not_found(&head_ctx(), "genesis");
        assert_not_found(&head_ctx(), "0");
    }

    /// `finalized` is the checkpoint's own root, and the block it names
    /// answers to its slot as well.
    #[test]
    fn finalized_names_the_block_the_checkpoint_points_at() {
        let ctx = head_ctx();
        let root = root_text(block_root_of(FINALIZED_SLOT));
        assert_eq!(served_root(&ctx, "finalized"), root);
        assert_eq!(served_root(&ctx, &FINALIZED_SLOT.to_string()), root);
        assert_eq!(parsed(&ctx, &root_path("finalized"))["finalized"], true);
        assert_no_header(&ctx, "finalized");
    }

    /// The zero root a chain carries until its first finalization names no
    /// block, and answering with it would name the wrong one.
    #[test]
    fn finalized_before_the_first_finalization_is_not_found() {
        assert_not_found(&young_ctx(), "finalized");
    }

    /// The published head block root is the one root this crate can confirm;
    /// every other is a block it has no read path to.
    #[test]
    fn a_root_is_answered_only_for_the_head_block() {
        let ctx = head_ctx();
        assert_eq!(
            served_root(&ctx, &root_text(block_root_of(HEAD_BLOCK_SLOT))),
            root_text(block_root_of(HEAD_BLOCK_SLOT))
        );
        for block_id in [
            root_text(block_root_of(EMPTY_SLOT - 1)),
            root_text(block_root_of(FINALIZED_SLOT)),
            root_text([0xab; 32]),
        ] {
            assert_not_found(&ctx, &block_id);
        }
    }

    /// The window this pair of endpoints exists for: between a block's arrival
    /// and the next slot the state cannot name it — `latest_block_header`
    /// still carries the zero `state_root`, and no ring entry names the block
    /// — but the root published beside the state can, under all three of its
    /// names. The header is what waits: it is not the block's until the next
    /// `process_slot` fills it.
    #[test]
    fn the_head_is_named_before_its_own_state_can_name_it() {
        let ctx = just_applied_ctx();
        let root = root_text(block_root_of(STATE_SLOT));
        for block_id in ["head", &STATE_SLOT.to_string(), &root] {
            assert_eq!(served_root(&ctx, block_id), root, "{block_id}");
            assert_no_header(&ctx, block_id);
        }
        assert_eq!(
            served_root(&ctx, &HEAD_BLOCK_SLOT.to_string()),
            root_text(block_root_of(HEAD_BLOCK_SLOT)),
            "the block before it is still recorded"
        );
    }

    /// A served header is served with the root the state was published with,
    /// not with one derived from the header itself — the two agree only
    /// because the header is complete.
    #[test]
    fn a_served_header_carries_the_state_root_of_its_own_post_state() {
        let header = &parsed(&head_ctx(), &header_path("head"))["data"]["header"]["message"];
        assert_eq!(header["state_root"], root_text(state_root_of(HEAD_BLOCK_SLOT)));
        assert_ne!(header["state_root"], root_text(ZERO_ROOT));
    }

    /// `finalized` describes the block served, not the state read: the same
    /// state answers both ways either side of the finalized checkpoint's slot.
    #[test]
    fn the_finalized_flag_follows_the_block_not_the_state() {
        let ctx = head_ctx();
        for (slot, want) in
            [(FINALIZED_SLOT - 1, true), (FINALIZED_SLOT, true), (FINALIZED_SLOT + 1, false)]
        {
            assert_eq!(parsed(&ctx, &root_path(&slot.to_string()))["finalized"], want, "{slot}");
        }
        assert_eq!(parsed(&ctx, &root_path("head"))["finalized"], false);
        assert_eq!(parsed(&ctx, &header_path("head"))["finalized"], false);
    }

    /// The same flag the state reads carry: the head's own execution status.
    #[test]
    fn execution_optimistic_is_the_head_s_own_status() {
        let mut ctx = head_ctx();
        for optimistic in [true, false] {
            ctx.node_status.slots =
                Some(SlotStatus { head_optimistic: optimistic, ..ctx.node_status.slots.unwrap() });
            for path in paths("head") {
                assert_eq!(parsed(&ctx, &path)["execution_optimistic"], optimistic, "{path}");
            }
        }
    }

    /// `Invalid block ID` in both schemas: a value that identifies no block at
    /// all is a 400, where a block silver cannot name is a 404. `justified` is
    /// a `state_id` and no part of this vocabulary.
    #[test]
    fn a_block_id_naming_no_block_at_all_is_400() {
        let ctx = head_ctx();
        let short_root = format!("0x{}", "ab".repeat(31));
        let unhex_root = format!("0x{}", "zz".repeat(32));
        for block_id in [
            "justified",
            "current",
            "banana",
            "",
            "-1",
            "+5",
            "0x",
            "1.5",
            &short_root,
            &unhex_root,
            "HEAD",
        ] {
            for path in paths(block_id) {
                assert_error(&get(&ctx, &path), "400 Bad Request", 400, "invalid block_id");
            }
        }
    }

    /// Neither schema declares a 503, so a node with no state published
    /// answers the only way it can — and the `block_id` verdict does not wait
    /// on a state to read.
    #[test]
    fn reads_are_404_before_bootstrap_and_400_stays_400() {
        let ctx = preboot_ctx();
        for block_id in ["head", "genesis", "finalized", "9000", &root_text([0xab; 32])] {
            assert_not_found(&ctx, block_id);
        }
        for path in paths("banana") {
            assert_error(&get(&ctx, &path), "400 Bad Request", 400, "invalid block_id");
        }
    }
}
