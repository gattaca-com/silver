use silver_beacon_state_data::{
    B256, BLSPubkey, BeaconBlockHeader, BeaconState, BeaconStateOwner, EpochState,
    EpochStateFinalized, LongtailGroup, LongtailState, SLOTS_PER_HISTORICAL_ROOT,
    SYNC_COMMITTEE_SIZE, Slot, SpecConfig, SyncCommittee, ValSeed,
};
use silver_common::ELSyncStatus;
use silver_httpcore::ParsedRequest;

use super::*;
use crate::{
    NodeStatus, PeerCounts, SlotStatus,
    ids::MAX_BODY_IDS,
    router::Router,
    routes::{ROUTES, preboot_ctx, test_ctx},
};

/// Mid-epoch and mid-period: the head sits in epoch 300, which is in sync
/// committee period 1 (epochs 256..=511), so no window edge is the head's
/// own slot or epoch.
const HEAD_EPOCH: Epoch = 300;
const HEAD_SLOT: Slot = HEAD_EPOCH * SLOTS_PER_EPOCH + 5;
const NEXT_EPOCH: Epoch = HEAD_EPOCH + 1;

/// One validator per lookahead entry, so a proposer's index doubles as
/// the entry that named it: a body built from the wrong half of the
/// window says so.
const VALIDATOR_COUNT: usize = PROPOSER_LOOKAHEAD_SIZE;

/// How far back the fixture chain records block roots. The base ring
/// below it is zeroed, as `BeaconState::for_test` leaves it.
const RECORDED_SLOTS: Slot = 96;

/// The last slot of the epoch before the head's, whose entry is what v1 names
/// for the head epoch and v2 for the one after it.
const DEPENDENT_SLOT: Slot = HEAD_EPOCH * SLOTS_PER_EPOCH - 1;

/// The entry v2 names for the head epoch: one epoch further back than v1's.
const V2_DEPENDENT_SLOT: Slot = (HEAD_EPOCH - 1) * SLOTS_PER_EPOCH - 1;

/// Who sits where. Validator 7 sits at one position of each committee,
/// validator 11 at two of the current one, and validator 20 only in the
/// next; every other position is filler no test asks about.
const CURRENT_SEATS: &[(usize, u64)] = &[(3, 7), (0, 11), (SYNC_COMMITTEE_SIZE - 1, 11)];
const NEXT_SEATS: &[(usize, u64)] = &[(1, 7), (5, 20)];
const CURRENT_FILLER: u64 = 63;
const NEXT_FILLER: u64 = 62;
const SEATED_ONCE: u64 = CURRENT_SEATS[0].1;
const SEATED_TWICE: u64 = CURRENT_SEATS[1].1;
const SEATED_NEXT_PERIOD_ONLY: u64 = NEXT_SEATS[1].1;

const PROPOSER_OUT_OF_RANGE: &str = DutyWindow::ProposerLookahead.out_of_range();
const SYNC_OUT_OF_RANGE: &str = DutyWindow::SeatedSyncCommittees.out_of_range();

fn period_of(epoch: Epoch) -> u64 {
    DutyWindow::SeatedSyncCommittees.unit_of(epoch)
}

fn pubkey_of(index: usize) -> BLSPubkey {
    let mut pubkey = [0xd0u8; 48];
    pubkey[40..].copy_from_slice(&(index as u64).to_be_bytes());
    pubkey
}

fn pubkey_text(index: usize) -> String {
    format!("0x{}", hex::encode(pubkey_of(index)))
}

fn block_root_of(slot: Slot) -> B256 {
    let mut root = [0xb0u8; 32];
    root[24..].copy_from_slice(&slot.to_be_bytes());
    root
}

fn state_root_of(slot: Slot) -> B256 {
    let mut root = [0x57u8; 32];
    root[24..].copy_from_slice(&slot.to_be_bytes());
    root
}

/// A distinct index per list entry, so a capped request is not
/// deduplicated down to one lookup.
fn unquoted_index(position: usize) -> String {
    format!("\"{position}\"")
}

fn root_text(root: B256) -> String {
    format!("0x{}", hex::encode(root))
}

/// The lookahead entry for the slot `head_epoch * SLOTS_PER_EPOCH + i` is
/// `i`, so the entries of the head epoch name validators 0..32 and those
/// of the next name 32..64.
fn epoch_base() -> EpochStateFinalized {
    EpochStateFinalized::from_state(EpochState {
        proposer_lookahead: std::array::from_fn(|i| i as u64),
        ..Default::default()
    })
}

fn committee(seats: &[(usize, u64)], filler: u64) -> SyncCommittee {
    let mut committee = SyncCommittee {
        pubkeys: [pubkey_of(filler as usize); SYNC_COMMITTEE_SIZE],
        aggregate_pubkey: [0u8; 48],
    };
    for &(position, validator) in seats {
        committee.pubkeys[position] = pubkey_of(validator as usize);
    }
    committee
}

/// The current committee's pubkeys resolved to validator indices, the way the
/// rotation that installed the committee leaves them.
fn seated_indices() -> [u32; SYNC_COMMITTEE_SIZE] {
    let mut indices = [CURRENT_FILLER as u32; SYNC_COMMITTEE_SIZE];
    for &(position, validator) in CURRENT_SEATS {
        indices[position] = validator as u32;
    }
    indices
}

/// Both committees seated the way two period rotations seat them: the second
/// promotes the current committee out of `next`, carrying `indices` with it.
fn seated_longtail(indices: [u32; SYNC_COMMITTEE_SIZE]) -> LongtailGroup {
    let mut group = LongtailGroup::new(LongtailState::default());
    let seated = {
        let mut wv = group.roll_fresh();
        wv.rotate_sync_committees(&committee(CURRENT_SEATS, CURRENT_FILLER), indices);
        wv.rotate_sync_committees(&committee(NEXT_SEATS, NEXT_FILLER), indices);
        wv.commit()
    };
    group.finalize(seated, &[seated]);
    group
}

struct Fixture {
    state_slot: Slot,
    empty_slots: Vec<Slot>,
    validator_count: usize,
    sync_committee_indices: [u32; SYNC_COMMITTEE_SIZE],
    /// Silver holds Fulu states and later ones only — it has no Electra state
    /// transition and no upgrade into Fulu — so the default fixture is a chain
    /// that has been Fulu throughout.
    fulu_fork_epoch: Epoch,
}

impl Default for Fixture {
    fn default() -> Self {
        Self {
            state_slot: HEAD_SLOT,
            empty_slots: Vec::new(),
            validator_count: VALIDATOR_COUNT,
            sync_committee_indices: seated_indices(),
            fulu_fork_epoch: 0,
        }
    }
}

impl Fixture {
    /// A published head state grown a slot at a time the way the tile
    /// grows one: every slot carries a block bar `empty_slots`, and the
    /// `process_slot` that leaves a slot records the latest block's root
    /// — so an empty slot's entry repeats its predecessor's. The newest
    /// block's root is published beside the state, as the tile publishes
    /// it.
    fn published(self) -> ApiCtx {
        let seeds: Vec<ValSeed> = (0..self.validator_count)
            .map(|index| ValSeed { pubkey: pubkey_of(index), ..Default::default() })
            .collect();
        let base_slot = self.state_slot.saturating_sub(RECORDED_SLOTS);
        let mut state = BeaconState::for_test(epoch_base(), &seeds, base_slot);
        state.longtail = seated_longtail(self.sync_committee_indices);

        let mut owner = BeaconStateOwner::new(state);
        let anchor = owner.roll_fresh();
        let (mut writer, _, _) = owner.apply_block_view(anchor);
        let mut head_root = [0u8; 32];
        for slot in base_slot..=self.state_slot {
            if !self.empty_slots.contains(&slot) {
                writer.slot.state_mut().latest_block_header =
                    BeaconBlockHeader { slot, parent_root: head_root, ..Default::default() };
                head_root = block_root_of(slot);
            }
            if slot == self.state_slot {
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

        let spec = SpecConfig { fulu_fork_epoch: self.fulu_fork_epoch, ..SpecConfig::mainnet() };
        let mut ctx = test_ctx(&spec, owner.reader());
        ctx.node_status = synced_at(self.state_slot);
        ctx
    }
}

fn at_wall_slot(head_slot: Slot, wall_slot: Slot) -> NodeStatus {
    NodeStatus {
        slots: Some(SlotStatus { head_slot, wall_slot, head_optimistic: false }),
        syncing: false,
        el: ELSyncStatus::Synced,
        peers: PeerCounts::default(),
    }
}

fn synced_at(head_slot: Slot) -> NodeStatus {
    at_wall_slot(head_slot, head_slot)
}

fn head_ctx() -> ApiCtx {
    Fixture::default().published()
}

/// The same head state and chain, with the node reporting a wall clock that
/// has moved past it.
fn head_behind_wall(head_epoch: Epoch, wall_epoch: Epoch) -> ApiCtx {
    let state_slot = head_epoch * SLOTS_PER_EPOCH + 1;
    let mut ctx = Fixture { state_slot, ..Default::default() }.published();
    ctx.node_status = at_wall_slot(state_slot, wall_epoch * SLOTS_PER_EPOCH);
    ctx
}

fn proposer_path(version: u8, epoch: &str) -> String {
    format!("/eth/v{version}/validator/duties/proposer/{epoch}")
}

fn sync_path(epoch: &str) -> String {
    format!("/eth/v1/validator/duties/sync/{epoch}")
}

fn request<'a>(method: &'a str, path: &'a str, body: &'a [u8]) -> ParsedRequest<'a> {
    ParsedRequest {
        method,
        path,
        query: "",
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

fn get_proposers_v(ctx: &ApiCtx, version: u8, epoch: &str) -> Vec<u8> {
    dispatch(ctx, &request("GET", &proposer_path(version, epoch), b""))
}

fn get_proposers(ctx: &ApiCtx, epoch: &str) -> Vec<u8> {
    get_proposers_v(ctx, 1, epoch)
}

fn post_sync(ctx: &ApiCtx, epoch: &str, body: &str) -> Vec<u8> {
    dispatch(ctx, &request("POST", &sync_path(epoch), body.as_bytes()))
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

fn assert_syncing(response: &[u8]) {
    assert_error(response, "503 Service Unavailable", 503, CURRENTLY_SYNCING);
}

fn assert_bad_request(response: &[u8], message: &str) {
    assert_error(response, "400 Bad Request", 400, message);
}

/// The body the proposer schema declares for `epoch`, spelled out: the
/// dependent root and the optimistic flag beside one entry per slot, each
/// naming the validator the slot's lookahead entry does.
fn expected_proposers(epoch: Epoch, dependent_root: B256) -> String {
    let first_entry = (epoch - HEAD_EPOCH) * SLOTS_PER_EPOCH;
    let duties: Vec<String> = (0..SLOTS_PER_EPOCH)
        .map(|i| {
            format!(
                "{{\"pubkey\":\"{}\",\"validator_index\":\"{}\",\"slot\":\"{}\"}}",
                pubkey_text((first_entry + i) as usize),
                first_entry + i,
                epoch * SLOTS_PER_EPOCH + i
            )
        })
        .collect();
    format!(
        "{{\"dependent_root\":\"{}\",\"execution_optimistic\":false,\"data\":[{}]}}",
        root_text(dependent_root),
        duties.join(",")
    )
}

/// Body shape: `apis/validator/duties/proposer.yaml` — every slot of the
/// epoch, and the block root the epoch's duties depend on.
#[test]
fn proposer_duties_body_is_the_epoch_under_its_dependent_root() {
    let ctx = head_ctx();
    assert_eq!(
        ok_body(&get_proposers(&ctx, &HEAD_EPOCH.to_string())),
        expected_proposers(HEAD_EPOCH, block_root_of(DEPENDENT_SLOT))
    );
}

/// The lookahead is anchored to the head state's epoch, so the next
/// epoch's proposers are its second half — and the dependent slot has not
/// happened, which the endpoint's head-event rule answers with the head
/// block's root.
#[test]
fn the_next_epoch_reads_the_far_half_of_the_lookahead() {
    let ctx = head_ctx();
    assert_eq!(
        ok_body(&get_proposers(&ctx, &NEXT_EPOCH.to_string())),
        expected_proposers(NEXT_EPOCH, block_root_of(HEAD_SLOT))
    );
}

/// `proposer.v2.yaml` names `compute_start_slot_at_epoch(epoch - 1) - 1`, one
/// epoch further back than v1: the boundary the lookahead an epoch's
/// proposers came from was seeded at. Both epochs the window serves therefore
/// depend on a slot `block_roots` already records, so v2 never falls back to
/// the head block's root the way v1 does for the next epoch — and the duties
/// themselves are the same list.
#[test]
fn v2_depends_on_the_epoch_before_the_one_asked_for() {
    let ctx = head_ctx();
    for (epoch, dependent_slot) in [(HEAD_EPOCH, V2_DEPENDENT_SLOT), (NEXT_EPOCH, DEPENDENT_SLOT)] {
        let answered = ok_body(&get_proposers_v(&ctx, 2, &epoch.to_string()));
        assert_eq!(answered, expected_proposers(epoch, block_root_of(dependent_slot)));
        assert!(!answered.contains(&root_text(block_root_of(HEAD_SLOT))), "{answered}");
    }
}

/// v2's rule is the one EIP-7917 introduced, so it holds from Fulu on and no
/// earlier: the activation epoch's own lookahead is seeded by the fork
/// transition at its own boundary, and no epoch before it has a lookahead at
/// all. Both fall back to v1's dependent root — which is what a client
/// calling v2 on a chain that schedules Fulu ahead of it must be answered
/// with.
#[test]
fn v2_falls_back_to_v1s_dependent_root_up_to_the_fulu_activation_epoch() {
    let activating = Fixture { fulu_fork_epoch: HEAD_EPOCH, ..Default::default() }.published();
    for epoch in [HEAD_EPOCH, NEXT_EPOCH] {
        assert_eq!(
            ok_body(&get_proposers_v(&activating, 2, &epoch.to_string())),
            expected_proposers(epoch, block_root_of(DEPENDENT_SLOT)),
            "epoch {epoch}"
        );
    }

    let unreached = Fixture { fulu_fork_epoch: NEXT_EPOCH, ..Default::default() }.published();
    for epoch in [HEAD_EPOCH, NEXT_EPOCH] {
        assert_eq!(
            ok_body(&get_proposers_v(&unreached, 2, &epoch.to_string())),
            ok_body(&get_proposers(&unreached, &epoch.to_string())),
            "epoch {epoch}"
        );
    }
}

/// An empty slot records the last block's root, which is what the spec's
/// own accessor answers there — the dependent root of an epoch whose
/// predecessor's last slot carried no block.
#[test]
fn a_dependent_slot_that_carried_no_block_names_the_block_before_it() {
    let ctx =
        Fixture { empty_slots: vec![DEPENDENT_SLOT, V2_DEPENDENT_SLOT], ..Default::default() }
            .published();
    assert_eq!(
        ok_body(&get_proposers(&ctx, &HEAD_EPOCH.to_string())),
        expected_proposers(HEAD_EPOCH, block_root_of(DEPENDENT_SLOT - 1))
    );
    assert_eq!(
        ok_body(&get_proposers_v(&ctx, 2, &HEAD_EPOCH.to_string())),
        expected_proposers(HEAD_EPOCH, block_root_of(V2_DEPENDENT_SLOT - 1))
    );
}

/// The window is the head state's epoch and the next: an epoch below it is
/// nothing this node keeps, and one the wall clock has not scheduled is
/// nothing any state's lookahead covers.
#[test]
fn the_epochs_outside_the_lookahead_are_400() {
    let ctx = head_ctx();
    for epoch in [HEAD_EPOCH - 1, 0, HEAD_EPOCH + 2, u64::MAX] {
        for version in [1, 2] {
            assert_bad_request(
                &get_proposers_v(&ctx, version, &epoch.to_string()),
                PROPOSER_OUT_OF_RANGE,
            );
        }
    }
}

/// The epoch the wall clock is in, not the head state's, decides whether an
/// epoch above the window is early or wrong: for the slot between the clock
/// entering an epoch and the tile advancing the head into it the head state
/// is a whole epoch behind, and the epoch a validator client asks about
/// every slot is one this node answers as soon as it catches up.
#[test]
fn an_epoch_the_wall_clock_has_scheduled_is_503_while_the_head_is_behind() {
    let wall_epoch = HEAD_EPOCH;
    let ctx = head_behind_wall(wall_epoch - 1, wall_epoch);
    for version in [1, 2] {
        assert_syncing(&get_proposers_v(&ctx, version, &(wall_epoch + 1).to_string()));
        assert_bad_request(
            &get_proposers_v(&ctx, version, &(wall_epoch + 2).to_string()),
            PROPOSER_OUT_OF_RANGE,
        );
    }

    let last_of_period = EPOCHS_PER_SYNC_COMMITTEE_PERIOD - 1;
    let ctx = head_behind_wall(last_of_period, last_of_period + 1);
    let reachable = (period_of(last_of_period) + 2) * EPOCHS_PER_SYNC_COMMITTEE_PERIOD;
    assert_syncing(&post_sync(&ctx, &reachable.to_string(), "[\"7\"]"));
    assert_bad_request(
        &post_sync(&ctx, &(reachable + EPOCHS_PER_SYNC_COMMITTEE_PERIOD).to_string(), "[\"7\"]"),
        SYNC_OUT_OF_RANGE,
    );
}

/// The converse: an epoch no chain has scheduled duties for is the request's
/// own error however far behind the node reports itself, and an epoch below
/// the head's window is one no waiting brings back.
#[test]
fn an_unscheduled_epoch_is_400_even_while_syncing() {
    let mut ctx = head_ctx();
    ctx.node_status = NodeStatus { syncing: true, ..synced_at(HEAD_SLOT) };
    for version in [1, 2] {
        assert_bad_request(
            &get_proposers_v(&ctx, version, &(HEAD_EPOCH + 2).to_string()),
            PROPOSER_OUT_OF_RANGE,
        );
        assert_bad_request(
            &get_proposers_v(&ctx, version, &(HEAD_EPOCH - 1).to_string()),
            PROPOSER_OUT_OF_RANGE,
        );
    }
    assert_bad_request(
        &post_sync(&ctx, &(HEAD_EPOCH + 512).to_string(), "[\"7\"]"),
        SYNC_OUT_OF_RANGE,
    );

    let ctx = head_behind_wall(HEAD_EPOCH, HEAD_EPOCH + 1_000);
    for version in [1, 2] {
        assert_bad_request(
            &get_proposers_v(&ctx, version, &(HEAD_EPOCH - 1).to_string()),
            PROPOSER_OUT_OF_RANGE,
        );
    }
}

/// The same window, counted from the head state and from the wall clock: a
/// unit either holds is answered or waited for, and one neither holds is the
/// request's own error. Both endpoints, driven through the units they
/// schedule by.
#[test]
fn the_wall_clock_only_decides_the_epochs_the_head_cannot_answer() {
    let period = EPOCHS_PER_SYNC_COMMITTEE_PERIOD;
    for (window, unit) in
        [(DutyWindow::ProposerLookahead, 1), (DutyWindow::SeatedSyncCommittees, period)]
    {
        let head = 8 * unit;
        let ahead = |epoch, wall| {
            window.units_ahead(RequestedEpoch { epoch, wall_epoch: Some(wall) }, head)
        };
        assert!(matches!(ahead(head, head), Ok(0)));
        assert!(matches!(ahead(head + unit, head), Ok(1)));
        assert!(matches!(ahead(head - 1, head + 99 * unit), Err(OutOfWindow::Never)));
        assert!(matches!(ahead(head + 2 * unit, head), Err(OutOfWindow::Never)));
        assert!(matches!(ahead(head + 2 * unit, head + unit), Err(OutOfWindow::NotYet)));
        assert!(matches!(ahead(head + 99 * unit, head + 98 * unit), Err(OutOfWindow::NotYet)));
        assert!(matches!(ahead(head + 99 * unit, head + 97 * unit), Err(OutOfWindow::Never)));
        assert!(matches!(ahead(u64::MAX, head), Err(OutOfWindow::Never)));
        assert!(matches!(ahead(u64::MAX - 1, u64::MAX), Err(OutOfWindow::NotYet)));
        assert!(matches!(
            window.units_ahead(RequestedEpoch { epoch: head + 9 * unit, wall_epoch: None }, head),
            Err(OutOfWindow::NotYet)
        ));
    }
}

/// `Invalid epoch` in every duties schema: a path parameter that names no
/// epoch is answered before any state is read.
#[test]
fn an_epoch_that_is_no_number_is_400() {
    let ctx = head_ctx();
    for epoch in ["abc", "-1", "+1", "1.5", "", "0x12c", "300 ", "١٢"] {
        for version in [1, 2] {
            assert_bad_request(&get_proposers_v(&ctx, version, epoch), "invalid epoch");
            assert_bad_request(&get_proposers_v(&preboot_ctx(), version, epoch), "invalid epoch");
        }
        assert_bad_request(&post_sync(&ctx, epoch, "[\"7\"]"), "invalid epoch");
    }
}

/// No duties schema declares a 404, and a node with no state published is
/// the case their 503 describes.
#[test]
fn duties_are_503_before_bootstrap() {
    let ctx = preboot_ctx();
    for version in [1, 2] {
        assert_syncing(&get_proposers_v(&ctx, version, &HEAD_EPOCH.to_string()));
    }
    assert_syncing(&post_sync(&ctx, &HEAD_EPOCH.to_string(), "[\"7\"]"));
}

/// The one state whose own dependent root neither version can answer with:
/// at slot zero the genesis block's root is not in `block_roots` yet, and
/// both schemas require the field.
#[test]
fn an_epoch_whose_dependent_root_is_not_recorded_yet_is_503() {
    let ctx = Fixture { state_slot: 0, ..Default::default() }.published();
    for version in [1, 2] {
        assert_syncing(&get_proposers_v(&ctx, version, "0"));
    }
}

/// The epochs whose dependent slot underflows; the spec resolves them to the
/// genesis block root, which is the entry slot zero records once the chain
/// has left it. v1 underflows for epoch zero alone, v2 for the first two.
#[test]
fn an_underflowing_dependent_slot_reads_the_root_recorded_at_slot_zero() {
    let ctx = Fixture { state_slot: 20, ..Default::default() }.published();
    let genesis_root = format!("{{\"dependent_root\":\"{}\"", root_text(block_root_of(0)));
    for (version, epoch) in [(1, "0"), (2, "0"), (2, "1")] {
        let body = ok_body(&get_proposers_v(&ctx, version, epoch));
        assert!(body.starts_with(&genesis_root), "v{version} epoch {epoch}: {body}");
    }
}

/// A lookahead entry no validator answers to is the state contradicting
/// itself; leaving the slot out of the answer would hide a proposal duty.
#[test]
fn a_proposer_the_registry_does_not_hold_is_500() {
    let ctx = Fixture { validator_count: 8, ..Default::default() }.published();
    for version in [1, 2] {
        assert_error(
            &get_proposers_v(&ctx, version, &HEAD_EPOCH.to_string()),
            "500 Internal Server Error",
            500,
            "proposer lookahead names a validator this state does not hold",
        );
    }
}

/// The flag is the head's own execution status, the same source every
/// state read answers from.
#[test]
fn execution_optimistic_follows_the_head() {
    let mut ctx = head_ctx();
    ctx.node_status = NodeStatus {
        slots: Some(SlotStatus { head_optimistic: true, ..synced_at(HEAD_SLOT).slots.unwrap() }),
        ..synced_at(HEAD_SLOT)
    };
    for version in [1, 2] {
        assert!(
            ok_body(&get_proposers_v(&ctx, version, &HEAD_EPOCH.to_string()))
                .contains("\"execution_optimistic\":true,")
        );
    }
    assert!(
        ok_body(&post_sync(&ctx, &HEAD_EPOCH.to_string(), "[\"7\"]"))
            .starts_with("{\"execution_optimistic\":true,\"data\":[")
    );
}

/// Each response carries the flags its own schema declares beside `data`
/// and no others: `finalized` belongs to none of them, and `dependent_root`
/// to the proposer responses alone — the sync committee's dependent root is
/// defined against a period, which its schema does not carry.
#[test]
fn each_response_carries_only_the_wrapper_fields_its_schema_declares() {
    let ctx = head_ctx();
    for version in [1, 2] {
        let proposers: serde_json::Value = serde_json::from_str(&ok_body(&get_proposers_v(
            &ctx,
            version,
            &HEAD_EPOCH.to_string(),
        )))
        .unwrap();
        let proposer_fields = proposers.as_object().unwrap();
        assert!(proposer_fields.contains_key("dependent_root"));
        assert!(proposer_fields.contains_key("execution_optimistic"));
        assert!(proposer_fields.contains_key("data"));
        assert_eq!(proposer_fields.len(), 3, "{proposer_fields:?}");
    }

    let duties: serde_json::Value =
        serde_json::from_str(&ok_body(&post_sync(&ctx, &HEAD_EPOCH.to_string(), "[\"7\"]")))
            .unwrap();
    let duty_fields = duties.as_object().unwrap();
    assert!(duty_fields.contains_key("execution_optimistic"));
    assert!(duty_fields.contains_key("data"));
    assert_eq!(duty_fields.len(), 2, "{duty_fields:?}");
}

/// Body shape: `apis/validator/duties/sync.yaml` — one entry per
/// validator the committee holds, each carrying every position it sits
/// at, and nothing for one it does not.
#[test]
fn sync_duties_body_lists_a_seat_per_position_and_omits_non_members() {
    let ctx = head_ctx();
    let requested = format!("[\"{SEATED_ONCE}\",\"{SEATED_TWICE}\",\"{SEATED_NEXT_PERIOD_ONLY}\"]");
    assert_eq!(
        ok_body(&post_sync(&ctx, &HEAD_EPOCH.to_string(), &requested)),
        format!(
            "{{\"execution_optimistic\":false,\"data\":[\
             {{\"pubkey\":\"{}\",\"validator_index\":\"7\",\
             \"validator_sync_committee_indices\":[\"3\"]}},\
             {{\"pubkey\":\"{}\",\"validator_index\":\"11\",\
             \"validator_sync_committee_indices\":[\"0\",\"511\"]}}]}}",
            pubkey_text(SEATED_ONCE as usize),
            pubkey_text(SEATED_TWICE as usize),
        )
    );
}

/// `minItems: 1` on `validator_sync_committee_indices`: a validator the
/// committee does not hold is left out of the array, not carried in it
/// with an empty one. An index past the registry names no pubkey to match
/// against and is left out the same way.
#[test]
fn a_validator_in_no_seat_is_omitted_rather_than_carried_empty() {
    let ctx = head_ctx();
    for requested in [
        format!("[\"{SEATED_NEXT_PERIOD_ONLY}\"]"),
        format!("[\"{}\"]", VALIDATOR_COUNT + 1_000),
        format!("[\"{}\"]", u32::MAX),
        format!("[\"{}\"]", u64::MAX),
    ] {
        assert_eq!(
            ok_body(&post_sync(&ctx, &HEAD_EPOCH.to_string(), &requested)),
            "{\"execution_optimistic\":false,\"data\":[]}",
            "{requested}"
        );
    }
}

/// A validator seated in the next period's committee and in no current seat
/// has duties there and none now.
#[test]
fn the_next_period_reads_the_committee_seated_after_this_one() {
    let ctx = head_ctx();
    let next_period = (period_of(HEAD_EPOCH) + 1) * EPOCHS_PER_SYNC_COMMITTEE_PERIOD;
    let requested = format!("[\"{SEATED_ONCE}\",\"{SEATED_TWICE}\",\"{SEATED_NEXT_PERIOD_ONLY}\"]");
    assert_eq!(
        ok_body(&post_sync(&ctx, &next_period.to_string(), &requested)),
        format!(
            "{{\"execution_optimistic\":false,\"data\":[\
             {{\"pubkey\":\"{}\",\"validator_index\":\"7\",\
             \"validator_sync_committee_indices\":[\"1\"]}},\
             {{\"pubkey\":\"{}\",\"validator_index\":\"20\",\
             \"validator_sync_committee_indices\":[\"5\"]}}]}}",
            pubkey_text(SEATED_ONCE as usize),
            pubkey_text(SEATED_NEXT_PERIOD_ONLY as usize),
        )
    );
}

/// A committee serves its whole period, so every epoch of the head's own
/// answers from the current committee — including epochs the head has
/// passed and the period's last — and every epoch of the next from the
/// next committee.
#[test]
fn the_period_and_not_the_epoch_picks_the_committee() {
    let ctx = head_ctx();
    let period = period_of(HEAD_EPOCH);
    let first_of_period = period * EPOCHS_PER_SYNC_COMMITTEE_PERIOD;
    let last_of_period = first_of_period + EPOCHS_PER_SYNC_COMMITTEE_PERIOD - 1;
    let current_seat = format!(
        "{{\"execution_optimistic\":false,\"data\":[{{\"pubkey\":\"{}\",\
         \"validator_index\":\"7\",\"validator_sync_committee_indices\":[\"3\"]}}]}}",
        pubkey_text(SEATED_ONCE as usize)
    );
    let next_seat = format!(
        "{{\"execution_optimistic\":false,\"data\":[{{\"pubkey\":\"{}\",\
         \"validator_index\":\"7\",\"validator_sync_committee_indices\":[\"1\"]}}]}}",
        pubkey_text(SEATED_ONCE as usize)
    );
    for epoch in [first_of_period, HEAD_EPOCH, last_of_period] {
        assert_eq!(
            ok_body(&post_sync(&ctx, &epoch.to_string(), "[\"7\"]")),
            current_seat,
            "epoch {epoch}"
        );
    }
    for epoch in [last_of_period + 1, last_of_period + EPOCHS_PER_SYNC_COMMITTEE_PERIOD] {
        assert_eq!(
            ok_body(&post_sync(&ctx, &epoch.to_string(), "[\"7\"]")),
            next_seat,
            "epoch {epoch}"
        );
    }
    for epoch in
        [first_of_period - 1, 0, last_of_period + EPOCHS_PER_SYNC_COMMITTEE_PERIOD + 1, u64::MAX]
    {
        assert_bad_request(&post_sync(&ctx, &epoch.to_string(), "[\"7\"]"), SYNC_OUT_OF_RANGE);
    }
}

/// Duties are matched on the pubkey the registry holds for the index asked
/// about, so a seat the rotation could not resolve to a finalized index — it
/// leaves `u32::MAX` behind — is still served to the validator sitting in it.
#[test]
fn a_member_the_finalized_registry_did_not_hold_still_gets_its_duty() {
    let mut sync_committee_indices = seated_indices();
    sync_committee_indices[CURRENT_SEATS[0].0] = u32::MAX;
    let ctx = Fixture { sync_committee_indices, ..Default::default() }.published();
    assert_eq!(
        ok_body(&post_sync(&ctx, &HEAD_EPOCH.to_string(), &format!("[\"{SEATED_ONCE}\"]"))),
        format!(
            "{{\"execution_optimistic\":false,\"data\":[{{\"pubkey\":\"{}\",\
             \"validator_index\":\"7\",\"validator_sync_committee_indices\":[\"3\"]}}]}}",
            pubkey_text(SEATED_ONCE as usize)
        )
    );
}

/// A validator named twice is one validator, answered once.
#[test]
fn a_repeated_index_is_answered_once() {
    let ctx = head_ctx();
    assert_eq!(
        ok_body(&post_sync(&ctx, &HEAD_EPOCH.to_string(), "[\"7\",\"7\",\"7\"]")),
        ok_body(&post_sync(&ctx, &HEAD_EPOCH.to_string(), "[\"7\"]"))
    );
}

/// The body is an array of quoted integers with `minItems: 1`; anything
/// else is the 400 the schema declares for it, with no state read.
#[test]
fn a_body_that_is_no_index_array_is_400() {
    let ctx = head_ctx();
    let epoch = HEAD_EPOCH.to_string();
    for body in ["", "[]", "{}", "[1,2]", "\"7\"", "[\"7\"", "null", "[[\"7\"]]", "[null]"] {
        let expected = if body == "[]" {
            "no validator index in request body"
        } else {
            "invalid request body"
        };
        assert_bad_request(&post_sync(&ctx, &epoch, body), expected);
    }
    for body in ["[\"abc\"]", "[\"-1\"]", "[\"+1\"]", "[\"7\",\"1.5\"]", "[\"\"]"] {
        assert_bad_request(&post_sync(&ctx, &epoch, body), "invalid validator index");
    }
}

/// The schema caps the list at nothing, so this API does: a body naming
/// more validators than any client runs is refused rather than resolved
/// inside the seqlock read. A list at the cap is answered in full — the
/// seated validators it names come back whether it names two of them or a
/// quarter of a million.
#[test]
fn a_body_at_the_index_cap_is_answered_and_one_past_it_is_400() {
    let ctx = head_ctx();
    let epoch = HEAD_EPOCH.to_string();
    let at_cap =
        format!("[{}]", (0..MAX_BODY_IDS).map(unquoted_index).collect::<Vec<_>>().join(","));
    let past_cap =
        format!("[{}]", (0..=MAX_BODY_IDS).map(unquoted_index).collect::<Vec<_>>().join(","));

    assert_eq!(
        ok_body(&post_sync(&ctx, &epoch, &at_cap)),
        ok_body(&post_sync(
            &ctx,
            &epoch,
            &format!("[\"{SEATED_ONCE}\",\"{SEATED_TWICE}\",\"{CURRENT_FILLER}\"]"),
        ))
    );
    assert_bad_request(
        &post_sync(&ctx, &epoch, &past_cap),
        "too many validator indices in request body",
    );
}

/// Each route answers its own method and nothing else — the proposer
/// duties are a GET, the sync duties a POST.
#[test]
fn the_wrong_method_on_either_route_is_405() {
    let ctx = head_ctx();
    let epoch = HEAD_EPOCH.to_string();
    for req in [
        request("POST", &proposer_path(1, &epoch), b"[\"7\"]"),
        request("POST", &proposer_path(2, &epoch), b"[\"7\"]"),
        request("GET", &sync_path(&epoch), b""),
    ] {
        assert_error(&dispatch(&ctx, &req), "405 Method Not Allowed", 405, "method not allowed");
    }
}
