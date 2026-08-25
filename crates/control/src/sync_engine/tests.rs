use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use silver_chain_spec::SpecConfig;
use silver_common::{
    BlockSource, DataKind, Origin, RequestId, Scope, SyncNeed, SyncUpdate, SyncingStrategy,
};
use silver_peer::SyncingConfig;

use super::{
    BACKFILL_BATCH, BATCH, Phase, SETTLE_TIMEOUT, SLOTS_PER_EPOCH, SYNCING_STRATEGY_TIMEOUT_WINDOW,
    SyncAction, SyncEngine,
    sync_window::{BlockState, Coverage},
    syncing::{CHAIN_UNAVAILABLE_TIMEOUT, TAIL_UNAVAILABLE_TIMEOUT},
};

/// Read the same knobs the engine does, so a config change moves the tests
/// with it rather than silently invalidating them.
fn progress_timeout() -> Duration {
    Duration::from_millis(SyncingConfig::default().inflight_progress_timeout_ms)
}

fn awaiting_peer_backoff() -> Duration {
    super::ISSUE_RETRY_BACKOFF
}

const PEER: usize = 1;

fn tail(e: &SyncEngine) -> u64 {
    e.window.tail()
}
const HEAD_ROOT: [u8; 32] = [7; 32];

/// Any non-empty custody set: a node that custodies nothing is owed no
/// columns, which is a different régime (see `no_custody_owes_no_columns`).
const CUSTODY: u128 = 0b1;

fn engine() -> SyncEngine {
    SyncEngine::new(SyncingConfig::default(), false, CUSTODY, Arc::new(SpecConfig::mainnet()))
}

/// Booting with a fork tree on disk, so the replay gate starts closed.
fn engine_awaiting_replay() -> SyncEngine {
    SyncEngine::new(SyncingConfig::default(), true, CUSTODY, Arc::new(SpecConfig::mainnet()))
}

fn gloas_engine(custody: u128, gloas_fork_epoch: u64) -> SyncEngine {
    SyncEngine::new(
        SyncingConfig::default(),
        false,
        custody,
        Arc::new(SpecConfig { gloas_fork_epoch, ..SpecConfig::mainnet() }),
    )
}

/// Real `Status` bytes, so these go in through the same parse the wire
/// does. Finalized stays at epoch 0 unless a test says otherwise.
fn status_ssz(head_root: [u8; 32], head_slot: u64, finalized: (u64, [u8; 32])) -> [u8; 92] {
    let mut ssz = [0u8; 92];
    ssz[4..36].copy_from_slice(&finalized.1);
    ssz[36..44].copy_from_slice(&finalized.0.to_le_bytes());
    ssz[44..76].copy_from_slice(&head_root);
    ssz[76..84].copy_from_slice(&head_slot.to_le_bytes());
    ssz
}

fn peer_status(e: &mut SyncEngine, peer: usize, head_root: [u8; 32], head_slot: u64) {
    e.on_peer_status(peer, &status_ssz(head_root, head_slot, (0, [0; 32])));
}

fn peer_finalized(e: &mut SyncEngine, peer: usize, head: ([u8; 32], u64), epoch: u64) {
    e.on_peer_status(peer, &status_ssz(head.0, head.1, (epoch, [5; 32])));
}

fn local_status(e: &mut SyncEngine, head_slot: u64, wall_slot: u64) {
    e.on_local_status(head_slot, 0, [0; 32], wall_slot);
}

/// A block whose parent sits at `parent_slot`, which also proves every slot
/// between them empty.
fn block_at(e: &mut SyncEngine, slot: u64, parent_slot: Option<u64>) {
    e.on_block_received(slot, [slot as u8; 32], parent_slot, true);
}

/// A block in hand but not applied — beacon state parked it on a
/// dependency.
fn parked_at(e: &mut SyncEngine, slot: u64, parent_slot: Option<u64>) {
    e.on_block_received(slot, [slot as u8; 32], parent_slot, false);
}

/// A fully-satisfied slot: block present and its data covered. Says
/// nothing about *who* served it — use `served` for a range delivery.
fn covered(e: &mut SyncEngine, slot: u64, parent_slot: Option<u64>) {
    block_at(e, slot, parent_slot);
    e.on_columns_covered(slot, [slot as u8; 32]);
    e.on_envelope_covered(slot, [slot as u8; 32]);
}

/// A slot as request `rid` delivered it: the delivery that attributes it to
/// that peer, then the import report.
fn served(e: &mut SyncEngine, rid: u64, slot: u64, parent_slot: Option<u64>) {
    e.on_msg_served(rid);
    covered(e, slot, parent_slot);
}

/// Re-select, discarding the target. Tests that care about what was
/// published read `SyncEngine::advance`'s return directly.
fn advance(e: &mut SyncEngine) {
    let _ = e.advance();
}

fn actions(e: &mut SyncEngine, now: Instant, placed: bool) -> Vec<SyncAction> {
    let mut out = Vec::new();
    e.drive_requests(now, &mut |a| {
        out.push(a);
        placed
    });
    out
}

/// The range fetches of one kind that a drive emitted, as
/// `(request_id, start, count)`.
fn ranges(actions: &[SyncAction], kind: DataKind) -> Vec<(u64, u64, u64)> {
    actions
        .iter()
        .filter_map(|a| match a {
            SyncAction::Request { request_id, request }
                if request.kind == kind && matches!(request.scope, Scope::Range { .. }) =>
            {
                let Scope::Range { start, count } = request.scope else { unreachable!() };
                Some((*request_id, start, count))
            }
            _ => None,
        })
        .collect()
}

/// The roots chased for one kind.
fn roots(actions: &[SyncAction], kind: DataKind) -> Vec<[u8; 32]> {
    actions
        .iter()
        .filter_map(|a| match a {
            SyncAction::Request { request, .. } if request.kind == kind => match request.scope {
                Scope::Root(root) => Some(root),
                Scope::Range { .. } => None,
            },
            _ => None,
        })
        .collect()
}

fn block_range(actions: Vec<SyncAction>) -> Option<(u64, u64, u64)> {
    ranges(&actions, DataKind::Block).into_iter().next()
}

/// Drive one issuance: returns the emitted block `(request_id, start,
/// count)`, if any. The request is placed with a peer.
fn drive(e: &mut SyncEngine, now: Instant) -> Option<(u64, u64, u64)> {
    block_range(actions(e, now, true))
}

/// As `drive`, but no peer took the request.
fn drive_unplaced(e: &mut SyncEngine, now: Instant) -> Option<(u64, u64, u64)> {
    block_range(actions(e, now, false))
}

fn by_root_chases(e: &mut SyncEngine, now: Instant) -> Vec<[u8; 32]> {
    roots(&actions(e, now, true), DataKind::Block)
}

/// Bring the engine to `Syncing` against a single head peer and issue the
/// first range, routed to `PEER`. Returns `(request_id, start, count)`.
fn issue_one(e: &mut SyncEngine, peer_head: u64, local_head: u64, now: Instant) -> (u64, u64, u64) {
    peer_status(e, PEER, HEAD_ROOT, peer_head);
    local_status(e, local_head, peer_head);
    advance(e);
    assert!(matches!(e.current_target(), Some(SyncUpdate::SyncingHead { .. })), "entered Syncing");
    drive(e, now).expect("range issued")
}

#[test]
fn caught_up_enters_following_and_latches_just_synced() {
    let mut e = engine();
    peer_status(&mut e, PEER, HEAD_ROOT, 200);
    local_status(&mut e, 0, 200);
    advance(&mut e);
    assert!(matches!(e.current_target(), Some(SyncUpdate::SyncingHead { .. })));

    local_status(&mut e, 200, 200);
    advance(&mut e);
    assert_eq!(e.current_target(), Some(SyncUpdate::Following));
    assert!(e.take_just_synced());
    assert!(!e.take_just_synced(), "one-shot");
}

/// A node restarted at the tip concludes `Following` straight out of
/// `Idle`. Publishing nothing there leaves every tile that gates on the
/// target — gossip, backfill — waiting forever on a target that is already
/// correct.
#[test]
fn entering_following_from_idle_publishes_the_target() {
    let mut e = engine();
    peer_status(&mut e, PEER, HEAD_ROOT, 100);
    local_status(&mut e, 100, 100);
    assert_eq!(e.advance(), Some(SyncUpdate::Following), "the conclusion is published");

    local_status(&mut e, 100, 101);
    assert_eq!(e.advance(), None, "and not republished");
}

#[test]
fn cold_start_stays_idle_until_a_peer_has_spoken() {
    let mut e = engine();
    local_status(&mut e, 0, 1000);
    let emitted = e.advance();
    assert_eq!(emitted, None, "Following suppressed with nothing to compare against");
    assert!(matches!(e.phase, Phase::Idle), "no peer heard from: still Idle");
}

/// Slots go unproposed, so a wall-clock gap is not evidence of anything.
/// Gating cold start on one stranded us in `Idle` on a quiet chain.
#[test]
fn quiet_chain_is_caught_up_not_behind() {
    let mut e = engine();
    peer_status(&mut e, PEER, HEAD_ROOT, 100);
    local_status(&mut e, 100, 1000);
    advance(&mut e);
    assert_eq!(
        e.current_target(),
        Some(SyncUpdate::Following),
        "level with the only peer that told us anything"
    );
}

#[test]
fn tail_advances_only_on_coverage() {
    let now = Instant::now();
    let mut e = engine();
    let (_rid, start, _count) = issue_one(&mut e, 200, 0, now);
    assert_eq!(start, 1);
    assert_eq!(tail(&e), 0, "nothing covered yet");

    // Block alone is not enough — its data is still outstanding.
    block_at(&mut e, 1, Some(0));
    drive(&mut e, now);
    assert_eq!(tail(&e), 0, "block without its data does not retire the slot");

    e.on_columns_covered(1, [1; 32]);
    drive(&mut e, now);
    assert_eq!(tail(&e), 1, "covered slot retires");
}

/// Coverage is what this node is owed, not what the chain holds. A node
/// custodying nothing is never told a slot's columns are available, so
/// requiring them would stall the tail on the first block carrying blobs —
/// and nothing would ever be asked for, since issuance skips columns too.
#[test]
fn no_custody_owes_no_columns() {
    let now = Instant::now();
    let mut e = gloas_engine(0, SpecConfig::mainnet().gloas_fork_epoch);
    issue_one(&mut e, 200, 0, now);

    block_at(&mut e, 1, Some(0));
    let issued = drive_all(&mut e, now);
    assert_eq!(tail(&e), 1, "the block alone satisfies the slot");
    assert!(issued.columns.is_none(), "and nothing was asked for");
}

/// A fork sibling's parent link spans slots the other branch has a block
/// at. Reading it as emptiness retires a slot whose data is still owed, and
/// nothing repairs the entry — no reorg is reported for a mere sibling.
#[test]
fn fork_sibling_does_not_prove_a_slot_holding_a_block_empty() {
    let now = Instant::now();
    let mut e = engine();
    issue_one(&mut e, 200, 0, now);

    block_at(&mut e, 10, Some(0));
    block_at(&mut e, 12, Some(0));
    drive(&mut e, now);
    assert_eq!(tail(&e), 9, "the slot holding a block still owes its columns");

    e.on_columns_covered(10, [10; 32]);
    drive(&mut e, now);
    assert_eq!(tail(&e), 11, "released, and the empty run below the sibling with it");
}

#[test]
fn parent_link_proves_intervening_slots_empty() {
    let now = Instant::now();
    let mut e = engine();
    issue_one(&mut e, 200, 0, now);

    // One block at slot 5 whose parent is the anchor: 1..=4 held no blocks.
    covered(&mut e, 5, Some(0));
    drive(&mut e, now);
    assert_eq!(tail(&e), 5, "empty run walked without fetching it");
}

#[test]
fn terminator_marks_unfilled_slots_empty() {
    let now = Instant::now();
    let mut e = engine();
    let (rid, start, count) = issue_one(&mut e, 200, 0, now);
    // One batch size for both targets — no separate head-sync batch.
    assert_eq!((start, count), (1, BATCH));

    // Peer served nothing across the whole range and completed cleanly.
    e.on_terminator(rid, PEER, true, now);
    drive(&mut e, now);
    assert_eq!(tail(&e), BATCH, "a clean Complete is positive emptiness evidence");
}

/// Serving fewer slots than asked is legal, so a clean terminator says
/// nothing about the part the peer never reached.
#[test]
fn truncated_response_proves_nothing_past_its_last_block() {
    let now = Instant::now();
    let mut e = engine();
    let (rid, _, _) = issue_one(&mut e, 200, 0, now);

    // Peer served 1..=3 of the batch, then completed.
    for slot in 1..=3 {
        served(&mut e, rid, slot, Some(slot - 1));
    }
    e.on_terminator(rid, PEER, true, now);

    let (_, start, count) = drive(&mut e, now).expect("remainder re-requested");
    assert_eq!(tail(&e), 3, "the tail stops at the last block delivered");
    assert_eq!((start, count), (4, BATCH), "the unserved remainder is asked for again");
}

/// Gossip fills the top of the window while the middle is still being fetched,
/// so the reachable span has slots we hold at both ends. `start` already skips
/// the ones below; the range must stop below the ones above rather than pay a
/// peer to send them back.
#[test]
fn range_stops_at_the_top_of_what_is_owed() {
    let now = Instant::now();
    let mut e = engine();
    peer_status(&mut e, PEER, HEAD_ROOT, 200);
    local_status(&mut e, 0, 200);
    advance(&mut e);

    // Slots 60..=64 arrived on gossip, whole. Nothing below them has.
    for slot in 60..=64 {
        covered(&mut e, slot, None);
    }

    let (_, start, count) = drive(&mut e, now).expect("range issued");
    assert_eq!(start, 1, "from the lowest slot still owed");
    assert_eq!(count, 59, "and up to the last one, not a full batch through what we hold");
}

/// A response ending says the peer is done, not that the tiles are. Until they
/// have reported on every chunk that arrived, the rest of the span is in their
/// hands — asking again would download it twice.
#[test]
fn delivery_the_tiles_still_hold_is_not_asked_for_again() {
    let now = Instant::now();
    let mut e = engine();
    let (rid, ..) = issue_one(&mut e, 200, 0, now);

    // Ten blocks came off the wire; beacon state has reported on three.
    for _ in 0..10 {
        e.on_msg_served(rid);
    }
    for slot in 1..=3 {
        block_at(&mut e, slot, Some(slot - 1));
    }
    e.on_terminator(rid, PEER, true, now);

    assert!(
        drive(&mut e, now).is_none(),
        "seven chunks are still in beacon state's hands, and slot 4 may be one of them"
    );

    // It works through the rest. Nothing is outstanding now, so whatever is
    // still owed above was never served.
    for slot in 4..=10 {
        block_at(&mut e, slot, Some(slot - 1));
    }
    let (_, start, _) = drive(&mut e, now).expect("the span is accounted for, so it is asked past");
    assert_eq!(start, 11, "and only for what never arrived");
}

/// What a peer put on the wire is not evidence about the slots it covers:
/// beacon state may still be verifying those blocks, or have dropped
/// orphans it could not buffer, and either way has not reported them yet.
/// Reading the delivery as emptiness settles live slots — which then owe
/// nothing, so the tail walks over a chain that was never applied.
#[test]
fn served_slots_are_not_empty_before_beacon_state_reports_them() {
    let now = Instant::now();
    let mut e = engine();
    let (rid, ..) = issue_one(&mut e, 200, 0, now);

    // The batch arrives and the peer completes cleanly, but the only slot
    // beacon state has reported on is the bottom one, parked on its data.
    e.on_msg_served(rid);
    parked_at(&mut e, 1, Some(0));
    e.on_terminator(rid, PEER, true, now);

    assert_eq!(tail(&e), 0, "a slot holding an unapplied block never settles");
    let (_, start, _) = drive(&mut e, now).expect("the rest of the batch is still owed");
    assert_eq!(start, 2, "slots the peer served are still owed, not written off empty");
}

/// A block in hand disproves an emptiness assumed from a peer's silence.
/// Only an apply is a settled answer, so the assumption yields to the
/// block and the slot goes back to owed.
#[test]
fn block_in_hand_disproves_an_assumed_empty_slot() {
    let now = Instant::now();
    let mut e = engine();
    let (rid, ..) = issue_one(&mut e, 200, 0, now);

    // The peer holds the span and served nothing, so the batch reads as
    // empty — while beacon state is holding a block for slot 3.
    e.on_terminator(rid, PEER, true, now);
    parked_at(&mut e, 3, Some(2));

    drive(&mut e, now);
    assert_eq!(tail(&e), 2, "the tail stops at the slot found to hold a block");
}

/// A retarget invalidates the whole window above the imported head: coverage
/// is keyed by slot, and a slot says nothing about which branch filled it. That
/// is safe because the slot is asked for again, and a tile handed an object it
/// already holds announces it a second time.
#[test]
fn retarget_drops_the_window_and_re_asks_for_what_it_held() {
    let now = Instant::now();
    let mut e = engine();
    let (rid, ..) = issue_one(&mut e, 200, 0, now);

    // Slot 1: columns in hand, and the peer's silence read as empty.
    e.on_columns_covered(1, [1; 32]);
    e.on_terminator(rid, PEER, true, now);
    assert!(e.window.coverage(1).columns_covered);

    // Selection moves to another chain.
    peer_status(&mut e, PEER, [9; 32], 220);
    advance(&mut e);
    assert!(
        matches!(e.current_target(), Some(SyncUpdate::SyncingHead { head_root, .. }) if head_root == [9; 32]),
        "the test needs a real retarget: {:?}",
        e.current_target()
    );
    assert_eq!(
        e.window.coverage(1),
        Coverage::default(),
        "nothing above the imported head is carried over"
    );

    let issued = actions(&mut e, now, true);
    assert_eq!(
        ranges(&issued, DataKind::Columns).first().map(|&(_, start, _)| start),
        Some(1),
        "the slot is owed again"
    );
    e.on_columns_covered(1, [1; 32]);
    assert!(e.window.coverage(1).columns_covered, "and the re-delivery restores it");
}

/// Reaching a finalized checkpoint is not what usually ends a chase — being
/// abandoned is. Selection then picks the best head among peers, which is
/// backed by whoever is loudest and need not descend from the checkpoint we
/// gave up on, so its coverage cannot be carried into the new chase.
#[test]
fn chain_abandoned_for_a_head_target_does_not_carry_its_coverage() {
    let t0 = Instant::now();
    let mut e = engine();
    peer_finalized(&mut e, PEER, (HEAD_ROOT, 200), 3);
    local_status(&mut e, 0, 200);
    advance(&mut e);
    assert!(
        matches!(e.current_target(), Some(SyncUpdate::SyncingFinalized { .. })),
        "the chase being abandoned has to be a checkpoint one"
    );

    // Slot 1 goes unserved and holds the tail; slot 5's columns did arrive.
    drive(&mut e, t0).expect("range issued");
    e.on_columns_covered(5, [5; 32]);

    let mut now = t0;
    while now.saturating_duration_since(t0) < CHAIN_UNAVAILABLE_TIMEOUT {
        now += Duration::from_secs(1);
        actions(&mut e, now, true);
    }
    assert_eq!(tail(&e), 0, "the slot was never skipped");

    // A peer on some other chain is all that is left to chase.
    peer_status(&mut e, PEER + 1, [9; 32], 220);
    advance(&mut e);
    assert!(
        matches!(e.current_target(), Some(SyncUpdate::SyncingHead { head_root, .. }) if head_root == [9; 32]),
        "the test needs the abandoned checkpoint replaced by a head: {:?}",
        e.current_target()
    );
    assert_eq!(
        e.window.coverage(5),
        Coverage::default(),
        "the abandoned chain's coverage went with it"
    );
}

/// Delivering nothing is only evidence of emptiness from a peer that
/// claims to hold the range. From one that does not, its silence says
/// nothing about the chain — and reading it as proof skips live slots.
#[test]
fn peer_that_does_not_claim_the_range_proves_nothing_by_silence() {
    let now = Instant::now();
    const SHORT_PEER: usize = 2;
    let mut e = engine();
    let (rid, _, count) = issue_one(&mut e, 200, 0, now);

    // A peer whose head sits below the range completes with nothing.
    peer_status(&mut e, SHORT_PEER, [8; 32], count / 2);
    e.on_terminator(rid, SHORT_PEER, true, now);
    let (rid, ..) = drive(&mut e, now).expect("range re-asked, not written off");
    assert_eq!(tail(&e), 0, "silence from a peer without the range is not emptiness");

    // The peer that does claim it says the same thing, and is believed.
    e.on_terminator(rid, PEER, true, now);
    drive(&mut e, now);
    assert_eq!(tail(&e), count, "a peer holding the range proves it empty");
}

/// A peer whose history starts above the range answers a request for it
/// exactly as a peer holding an empty range does: cleanly, with nothing.
/// Its head says it is far ahead, so only the history claim tells them
/// apart.
#[test]
fn peer_that_pruned_the_range_proves_nothing_by_silence() {
    let now = Instant::now();
    const PRUNED_PEER: usize = 2;
    let mut e = engine();
    let (rid, _, count) = issue_one(&mut e, 200, 0, now);

    let mut ssz = status_ssz(HEAD_ROOT, 200, (0, [0; 32]));
    ssz[84..92].copy_from_slice(&(count / 2).to_le_bytes());
    e.on_peer_status(PRUNED_PEER, &ssz);

    e.on_terminator(rid, PRUNED_PEER, true, now);
    let (rid, ..) = drive(&mut e, now).expect("range re-asked, not written off");
    assert_eq!(tail(&e), 0, "silence from a peer without the history is not emptiness");

    e.on_terminator(rid, PEER, true, now);
    drive(&mut e, now);
    assert_eq!(tail(&e), count, "a peer holding the whole span proves it empty");
}

/// A block can land inside an in-flight range without that range's peer
/// having served it — a by-root chase answering, or a previous peer still
/// draining. Counting it as this peer's delivery would read its clean
/// terminator as proof about slots its response never contained.
#[test]
fn block_this_peer_did_not_serve_is_not_its_delivery() {
    let now = Instant::now();
    const SHORT_PEER: usize = 2;
    let mut e = engine();
    let (rid, _, count) = issue_one(&mut e, 200, 0, now);

    // The range lands on a peer whose head sits below it, so its silence
    // proves nothing. Meanwhile a by-root chase answers inside the span.
    peer_status(&mut e, SHORT_PEER, [8; 32], count / 2);
    covered(&mut e, 20, Some(19));
    e.on_terminator(rid, SHORT_PEER, true, now);

    drive(&mut e, now);
    assert_eq!(tail(&e), 0, "the chased block is not evidence about slots 1..20");
}

#[test]
fn error_terminator_leaves_slots_unknown() {
    let now = Instant::now();
    let mut e = engine();
    let (rid, _start, _count) = issue_one(&mut e, 200, 0, now);

    e.on_terminator(rid, PEER, false, now);
    let reissued = drive(&mut e, now).map(|(_, start, _)| start);
    assert_eq!(tail(&e), 0, "an error proves nothing");
    assert_eq!(reissued, Some(1), "range re-derived from the tail");
}

#[test]
fn scan_skips_slots_already_known() {
    let now = Instant::now();
    let mut e = engine();
    let (rid, _, _) = issue_one(&mut e, 200, 0, now);

    // Slots 1..=3 arrived; the rest of the range did not.
    for slot in 1..=3 {
        covered(&mut e, slot, Some(slot - 1));
    }
    e.on_terminator(rid, PEER, false, now);

    let (_, start, _) = drive(&mut e, now).expect("re-issued");
    assert_eq!(start, 4, "refetch starts past what is already in hand");
}

#[test]
fn unplaced_request_re_emits_after_backoff() {
    let t0 = Instant::now();
    let mut e = engine();
    peer_status(&mut e, PEER, HEAD_ROOT, 200);
    local_status(&mut e, 0, 200);
    advance(&mut e);
    let (rid, start, count) = drive_unplaced(&mut e, t0).expect("range issued");
    assert!(drive(&mut e, t0).is_none(), "awaits peer; no re-emit before backoff");

    // The re-emit lands with a peer, so it stops re-emitting on its own.
    let later = t0 + awaiting_peer_backoff();
    assert_eq!(drive(&mut e, later), Some((rid, start, count)), "re-emits same request");
    assert!(drive(&mut e, later).is_none(), "placed; stops re-emitting");
}

/// A placed range is PM's until PM says it ended. The engine holds it
/// however long that takes and keeps no deadline beside PM's — two timers
/// on one request race, and the loser reissues into a peer the winner
/// still counts as busy.
#[test]
fn placed_range_is_held_until_pm_reports_its_end() {
    let t0 = Instant::now();
    let mut e = engine();
    let (rid, start, count) = issue_one(&mut e, 200, 0, t0);

    let mut now = t0;
    for _ in 0..8 {
        now += progress_timeout();
        assert!(drive(&mut e, now).is_none(), "PM has it; the engine does not second-guess");
    }

    // PM's terminator — a stall it swept, so nothing was proven.
    e.on_terminator(rid, PEER, false, now);
    let (rid2, start2, count2) = drive(&mut e, now).expect("re-issued once released");
    assert_ne!(rid2, rid, "a new range, not the stalled one");
    assert_eq!((start2, count2), (start, count), "same span, nothing was proven");
}

#[test]
fn unplaceable_parent_is_chased_by_root() {
    let now = Instant::now();
    let mut e = engine();
    issue_one(&mut e, 200, 0, now);

    // Beacon state parked a block it could not place — no range scan finds
    // the parent, so it reports the root and the engine chases it.
    let orphan_parent = [9u8; 32];
    e.on_sync_need(
        SyncNeed::Missing {
            root: orphan_parent,
            slot: 201,
            kind: DataKind::Block,
            columns: 0,
            origin: Origin::Live,
        },
        now,
    );
    assert_eq!(by_root_chases(&mut e, now), vec![orphan_parent], "parent chased by root");

    // Arrival of that very block retires the chase.
    e.on_block_received(39, orphan_parent, Some(38), true);
    assert!(by_root_chases(&mut e, now).is_empty(), "arrival retires the chase");
}

/// The regression this whole redesign is about: a slot whose data never
/// arrives must stop the tail *there*, not reset progress and not skip it.
#[test]
fn an_unsatisfiable_slot_stalls_the_tail_without_conceding() {
    let t0 = Instant::now();
    let mut e = engine();
    issue_one(&mut e, 200, 0, t0);

    // Slots 1..=4 land fully; slot 5's block arrives but its columns never
    // do — a peer that has the block and not the data.
    for slot in 1..=4 {
        covered(&mut e, slot, Some(slot - 1));
    }
    block_at(&mut e, 5, Some(4));
    drive(&mut e, t0);
    assert_eq!(tail(&e), 4, "the tail stops below the unsatisfied slot");

    // Nothing arriving must not move it, in either direction — and the
    // stall escalates once for the slot rather than every loop.
    let mut now = t0;
    let mut discoveries = 0;
    while now.saturating_duration_since(t0) < TAIL_UNAVAILABLE_TIMEOUT * 2 {
        now += Duration::from_secs(1);
        discoveries += actions(&mut e, now, true)
            .iter()
            .filter(|a| matches!(a, SyncAction::DiscoverPeers))
            .count();
        assert_eq!(tail(&e), 4, "progress is neither reset nor advanced past it");
    }
    assert_eq!(discoveries, 1, "escalates once for the stalled slot");

    // Coverage finally arriving releases it — the slot was never skipped.
    e.on_columns_covered(5, [5; 32]);
    drive(&mut e, now);
    assert_eq!(tail(&e), 5, "the tail resumes from the slot it held at");
}

/// A slot can hold more than one block, so "we have it" and "it applied"
/// are different facts and the window keeps both. A parked block is held —
/// re-asking a peer for it would spin a range for as long as its dependency
/// is outstanding — but it settles nothing, so the tail waits for the
/// apply.
#[test]
fn parked_block_is_not_refetched_and_does_not_settle_its_slot() {
    let t0 = Instant::now();
    let mut e = engine();
    let (rid, ..) = issue_one(&mut e, 200, 0, t0);

    for slot in 1..=3 {
        served(&mut e, rid, slot, Some(slot - 1));
    }
    // Slot 4 arrives whole — data and all — but beacon state parks it, so
    // the tail stops there while the slots above stay genuinely owed.
    e.on_msg_served(rid);
    parked_at(&mut e, 4, Some(3));
    e.on_columns_covered(4, [4; 32]);
    e.on_envelope_covered(4, [4; 32]);

    e.on_terminator(rid, PEER, true, t0);
    let next = drive(&mut e, t0).expect("a further range is issued");
    assert_eq!(tail(&e), 3, "the tail stops below the block that has not applied");
    assert_eq!(next.1, 5, "and the parked block is not asked for a second time");

    // The apply is what releases it, and the tail then runs on through the
    // slots that were already settled behind it.
    block_at(&mut e, 4, Some(3));
    drive(&mut e, t0);
    assert_eq!(tail(&e), 4, "applying the parked block settles its slot");
}

/// Storage is owed exactly one answer, and the engine owes it promptly: the
/// on-disk tree is only worth replaying if no peer is finalized ahead of
/// it.
#[test]
fn peers_finalized_ahead_skip_the_disk_replay_without_waiting() {
    let t0 = Instant::now();
    let mut e = engine_awaiting_replay();
    peer_finalized(&mut e, PEER, (HEAD_ROOT, 400), 10);
    local_status(&mut e, 0, 400);

    assert_eq!(
        e.maybe_choose_syncing_strategy(t0),
        Some(SyncingStrategy::SyncFromPeers),
        "decided on the first status, with no window spent"
    );
    assert_eq!(e.maybe_choose_syncing_strategy(t0), None, "and storage is told once");
}

/// With nobody ahead, the disk is the best chain we have — but only after
/// giving peers the window to say otherwise.
#[test]
fn nobody_ahead_replays_the_disk_once_the_window_closes() {
    let t0 = Instant::now();
    let mut e = engine_awaiting_replay();
    peer_status(&mut e, PEER, HEAD_ROOT, 1);
    local_status(&mut e, 0, 1);

    assert_eq!(e.maybe_choose_syncing_strategy(t0), None, "the window is still open");
    let almost = t0 + SYNCING_STRATEGY_TIMEOUT_WINDOW - Duration::from_millis(1);
    assert_eq!(e.maybe_choose_syncing_strategy(almost), None, "and right up to its edge");
    assert_eq!(
        e.maybe_choose_syncing_strategy(t0 + SYNCING_STRATEGY_TIMEOUT_WINDOW),
        Some(SyncingStrategy::ReplayDisk)
    );
}

/// The window is timed from the first status, not from boot: a node that
/// takes a while to hear from anyone must still get its full window to
/// learn that peers are ahead, rather than having spent it while deaf.
#[test]
fn the_decision_window_starts_at_the_first_status_not_at_boot() {
    let t0 = Instant::now();
    let mut e = engine_awaiting_replay();
    let deaf_for = SYNCING_STRATEGY_TIMEOUT_WINDOW * 4;

    assert_eq!(e.maybe_choose_syncing_strategy(t0 + deaf_for), None, "no status, no clock");

    peer_status(&mut e, PEER, HEAD_ROOT, 1);
    local_status(&mut e, 0, 1);
    let first_status = t0 + deaf_for;
    assert_eq!(e.maybe_choose_syncing_strategy(first_status), None, "the clock starts here");
    assert_eq!(
        e.maybe_choose_syncing_strategy(first_status + SYNCING_STRATEGY_TIMEOUT_WINDOW),
        Some(SyncingStrategy::ReplayDisk),
        "a full window later, and not before"
    );
}

/// Nothing may be requested while beacon state is still replaying the disk:
/// a range issued now would race the replay for the same slots. Replay is
/// unbounded in duration — a large on-disk tree can take arbitrarily long —
/// so the only thing that opens the gate is `ReplayComplete`.
#[test]
fn the_replay_gate_holds_every_request_until_replay_reports_complete() {
    let t0 = Instant::now();
    let mut e = engine_awaiting_replay();
    peer_status(&mut e, PEER, HEAD_ROOT, 200);
    local_status(&mut e, 0, 200);
    advance(&mut e);

    let mut now = t0;
    for _ in 0..10 {
        now += Duration::from_secs(60);
        assert!(actions(&mut e, now, true).is_empty(), "gated, however long it takes");
    }

    e.on_replay_complete();
    assert!(drive(&mut e, now).is_some(), "and released by the report, not by a clock");
}

/// The columns tile refuses to acknowledge data availability at or below
/// what finalization already settles, so the engine must not ask for it
/// there: the columns would arrive, go unacknowledged, and hold the tail on
/// a slot nothing will ever complete. One method on `SyncUpdate` derives
/// the floor for both sides so they cannot drift apart across the
/// queue.
#[test]
fn columns_are_not_asked_for_below_what_finalization_settles() {
    let t0 = Instant::now();
    let mut e = engine();
    // A checkpoint ahead of us settles availability up to itself — trusted, so no
    // columns are owed below it — while the blocks are still owed from the tail.
    // Near enough that the settled floor falls inside the window's reach.
    let target_epoch = 2;
    let settled = target_epoch * SLOTS_PER_EPOCH;

    peer_finalized(&mut e, PEER, (HEAD_ROOT, 200), target_epoch);
    local_status(&mut e, 0, 200);
    advance(&mut e);
    assert!(
        matches!(e.current_target(), Some(SyncUpdate::SyncingFinalized { .. })),
        "the checkpoint is what raises the floor"
    );

    let issued = actions(&mut e, t0, true);
    assert_eq!(
        ranges(&issued, DataKind::Columns).first().map(|&(_, start, _)| start),
        Some(settled + 1),
        "columns start above the settled checkpoint, not at the window's tail"
    );
    // Blocks have no availability floor: history below the checkpoint is still
    // owed, which is what makes the columns floor a real difference.
    assert_eq!(
        ranges(&issued, DataKind::Block).first().map(|&(_, start, _)| start),
        Some(1),
        "blocks are still asked for from the tail up"
    );
}

/// What the stall report reads. Beacon state's logs are keyed by root, not
/// by slot, so a stalled slot is only traceable into them if the window
/// kept the root — and the root has to be the one whose state it reports,
/// or the report names a block that is not the one holding things up.
#[test]
fn the_window_names_the_block_whose_state_it_reports() {
    const A: [u8; 32] = [0xaa; 32];
    const B: [u8; 32] = [0xbb; 32];
    let mut e = engine();

    e.on_block_received(4, A, Some(3), false);
    assert_eq!(e.window.seen_blocks(4).root, A, "the parked block is named");
    assert_eq!(e.window.seen_blocks(4).count, 1);

    // A sibling parks at the same slot. It did not change what the slot is
    // waiting on, so it must not rename it — but it is worth knowing there
    // are two.
    e.on_block_received(4, B, Some(3), false);
    assert_eq!(e.window.seen_blocks(4).root, A, "a second parked block does not rename it");
    assert_eq!(e.window.seen_blocks(4).count, 2, "and both are counted");

    // The sibling applying does change it, and the name moves with it.
    e.on_block_received(4, B, Some(3), true);
    assert_eq!(e.window.seen_blocks(4).root, B, "the applied block renames the slot");
    assert_eq!(e.window.coverage(4).block, BlockState::Applied);
}

/// Step 3 of the starvation policy: one slot holding the tail long enough
/// is the chain's problem, not the round's, so selection is handed
/// something else to try. Nothing is conceded — the slot is still owed.
#[test]
fn chain_stalled_on_one_slot_is_abandoned_for_selection() {
    let t0 = Instant::now();
    let mut e = engine();
    issue_one(&mut e, 200, 0, t0);
    block_at(&mut e, 1, Some(0));

    let mut now = t0;
    while now.saturating_duration_since(t0) < CHAIN_UNAVAILABLE_TIMEOUT {
        now += Duration::from_secs(1);
        actions(&mut e, now, true);
    }
    assert_eq!(tail(&e), 0, "the slot was never skipped");

    // The only chain on offer is excluded, so there is nothing to sync to.
    advance(&mut e);
    assert!(!matches!(e.current_target(), Some(SyncUpdate::SyncingHead { .. })), "chain dropped");

    // The peer that already failed us re-sending its Status is not new
    // evidence — believing it would loop on the same unserved slot forever.
    peer_status(&mut e, PEER, HEAD_ROOT, 200);
    advance(&mut e);
    assert!(
        !matches!(e.current_target(), Some(SyncUpdate::SyncingHead { .. })),
        "a repeat Status from the same peer does not lift the exclusion"
    );

    // Nor does a new peer on some other chain: it knows nothing about the
    // slot that went unserved. Lifting every exclusion on any new connection
    // would mean nothing stays abandoned, since peer churn never stops. Its
    // head sits below the lag threshold so it is not a target in its own
    // right, which is what makes this an assertion about the exclusion.
    peer_status(&mut e, PEER + 2, [3; 32], 5);
    advance(&mut e);
    assert!(
        !matches!(e.current_target(), Some(SyncUpdate::SyncingHead { .. })),
        "a peer backing another chain does not lift this one's exclusion"
    );

    // A peer we have not asked, on the chain itself, does — the data may be
    // theirs.
    peer_status(&mut e, PEER + 1, HEAD_ROOT, 200);
    advance(&mut e);
    assert!(
        matches!(e.current_target(), Some(SyncUpdate::SyncingHead { .. })),
        "a new peer backing the chain earns it another go"
    );
}

/// Reach `Following` with the head at 100, then let the wall run to 120 so
/// there is a lag to diagnose.
fn following_at(head: u64, wall: u64) -> SyncEngine {
    let mut e = engine();
    // A peer level with us: nothing to sync to, but we have heard from
    // someone, which is what lets `Following` be a conclusion.
    peer_status(&mut e, PEER, HEAD_ROOT, head);
    local_status(&mut e, head, head);
    advance(&mut e);
    assert_eq!(e.current_target(), Some(SyncUpdate::Following), "entered Following");
    local_status(&mut e, head, wall);
    e
}

/// The four things a wall-clock lag used to conflate. Only one of them is
/// a reason to sync, and the window tells them apart by inspection.
#[test]
fn falling_behind_is_diagnosed_from_coverage_not_wall_lag() {
    // A slot holding a block but missing its columns is a data problem —
    // the by-root chasers' job, and syncing would be actively wrong.
    let mut e = following_at(100, 120);
    block_at(&mut e, 101, Some(100));
    assert!(!e.fell_behind(), "missing columns is not a block gap");

    // A quiet chain reads as empty, not unknown: the next block's parent
    // link proves the skipped slots.
    let mut e = following_at(100, 120);
    covered(&mut e, 120, Some(100));
    assert!(!e.fell_behind(), "a run of proven-empty slots is not a gap");

    // A run of slots we have neither seen nor proven empty is.
    let e = following_at(100, 120);
    assert!(e.fell_behind(), "nothing known above the head is a block gap");
}

/// Envelopes chase by root exactly like blocks, and retire the same way:
/// on the coverage that satisfies them, not on a clear message.
#[test]
fn an_unverified_payload_is_chased_by_root() {
    let now = Instant::now();
    let mut e = engine();
    issue_one(&mut e, 200, 0, now);

    let root = [9u8; 32];
    e.on_sync_need(
        SyncNeed::Missing {
            root,
            slot: 201,
            kind: DataKind::Envelope,
            columns: 0,
            origin: Origin::Live,
        },
        now,
    );
    let emitted = actions(&mut e, now, true);
    assert_eq!(roots(&emitted, DataKind::Envelope), vec![root], "chased by root, not by range");
    assert!(ranges(&emitted, DataKind::Envelope).is_empty(), "and not by range");

    e.on_sync_need(SyncNeed::Arrived { root, slot: 9, kind: DataKind::Envelope }, now);
    assert!(
        roots(&actions(&mut e, now, true), DataKind::Envelope).is_empty(),
        "coverage retires the need"
    );
}

/// Envelopes are one per block and dense along the chain, so backfill
/// sweeps storage's owed span by range — under the backfill origin,
/// since beacon state would only park a response for a block finality
/// dropped long ago.
#[test]
fn owed_envelopes_are_swept_by_range() {
    let now = Instant::now();
    let mut e = following_at(100, 120);

    e.on_sync_need(SyncNeed::BackfillGap { kind: DataKind::Envelope, floor: 0, next: 100 }, now);
    let issued = ranges(&actions(&mut e, now, true), DataKind::Envelope);

    assert_eq!(issued.len(), 1, "one range in flight at a time");
    let (request_id, start, count) = issued[0];
    assert_eq!(
        (start, count),
        (100 - BACKFILL_BATCH, BACKFILL_BATCH),
        "one batch below the top of the span"
    );
    assert_eq!(
        RequestId::from(request_id).origin,
        Origin::Backfill,
        "not the live envelope origin"
    );

    // A span narrower than a batch stops at the floor rather than below it.
    e.ctx.backfill.on_terminator(request_id, true, now);
    e.on_sync_need(SyncNeed::BackfillGap { kind: DataKind::Envelope, floor: 90, next: 100 }, now);
    let later = now + Duration::from_secs(30);
    let spans: Vec<(u64, u64)> = ranges(&actions(&mut e, later, true), DataKind::Envelope)
        .into_iter()
        .map(|(_, start, count)| (start, count))
        .collect();
    assert_eq!(spans, vec![(90, 10)], "clamped at the floor");

    // An empty span retires the sweep.
    e.on_sync_need(SyncNeed::BackfillGap { kind: DataKind::Envelope, floor: 0, next: 0 }, now);
    assert!(
        ranges(&actions(&mut e, later + Duration::from_secs(30), true), DataKind::Envelope)
            .is_empty(),
        "nothing owed, nothing asked"
    );
}

/// A backfill range only exists while `Following`, so its terminator has to
/// reach the backfill walk whether or not the peer delivered. Routing the
/// failure anywhere else leaves the walk holding a range that already
/// ended, and the sweep never resumes.
#[test]
fn failed_backfill_range_is_released_and_reasked() {
    let now = Instant::now();
    let mut e = following_at(100, 120);
    e.on_sync_need(SyncNeed::BackfillGap { kind: DataKind::Block, floor: 0, next: 100 }, now);

    let first = block_range(actions(&mut e, now, true)).expect("range issued");
    assert!(drive(&mut e, now).is_none(), "held while it is out there");

    e.on_terminator(first.0, PEER, false, now);
    let (rid, start, count) = drive(&mut e, now).expect("re-asked after the failure");
    assert_ne!(rid, first.0, "a fresh request");
    assert_eq!((start, count), (first.1, first.2), "covering the same gap");
}

#[test]
fn reorg_drops_coverage_above_the_ancestor() {
    let now = Instant::now();
    let mut e = engine();
    let (rid, _, _) = issue_one(&mut e, 200, 0, now);
    for slot in 1..=10 {
        covered(&mut e, slot, Some(slot - 1));
    }
    e.on_terminator(rid, PEER, false, now);
    drive(&mut e, now);
    assert_eq!(tail(&e), 10);

    // Everything above slot 4 belonged to the abandoned branch: the tail
    // comes back with the coverage, and the in-flight range goes with it.
    e.on_reorg(4);
    assert_eq!(tail(&e), 4, "tail follows the coverage back");
    let (_, start, _) = drive(&mut e, now).expect("refetch above the ancestor");
    assert_eq!(start, 5, "shared prefix kept, abandoned suffix refetched");
}

/// Fork choice can settle on a heavier but shorter branch, putting the
/// ancestor below what we had already imported. Having imported slot 10 is
/// no longer a statement about the canonical chain.
#[test]
fn reorg_below_the_applied_head_pulls_it_back() {
    let now = Instant::now();
    let mut e = engine();
    let (rid, _, _) = issue_one(&mut e, 200, 0, now);
    for slot in 1..=10 {
        covered(&mut e, slot, Some(slot - 1));
    }
    e.on_terminator(rid, PEER, false, now);
    local_status(&mut e, 10, 200);
    drive(&mut e, now);
    assert_eq!(tail(&e), 10);

    e.on_reorg(4);
    assert_eq!(tail(&e), 4, "import through 10 was on the abandoned branch");

    let (_, start, _) = drive(&mut e, now).expect("refetch above the ancestor");
    assert_eq!(start, 5, "the new chain's 5.. is fetched, not skipped");
}

/// An import landing above the tail is progress on one chain, not proof
/// about the slots it skipped: those may hold blocks of the chain being
/// fetched. So the tail follows coverage, and the gap stays owed.
#[test]
fn import_above_the_tail_does_not_settle_the_slots_below_it() {
    let now = Instant::now();
    let mut e = engine();
    let (rid, start, _) = issue_one(&mut e, 200, 0, now);
    assert_eq!(start, 1);

    // Beacon state applied a block well above the tail, with nothing
    // reported for the slots in between.
    local_status(&mut e, BATCH + 22, 200);
    drive(&mut e, now);
    assert_eq!(tail(&e), 0, "an apply above the tail settles nothing below it");

    // The range in flight still owns that gap, so a failed one is re-asked
    // from the same place rather than written off.
    e.on_terminator(rid, PEER, false, now);
    let (_, start, _) = drive(&mut e, now).expect("the gap is re-asked");
    assert_eq!(start, 1, "the slots the import skipped are still owed");
}

/// Replay applies a whole tree on disk without the window seeing a slot of
/// it, so its head is where this window starts — fetching back over it
/// would re-download the fork tree we just loaded.
#[test]
fn replay_head_becomes_the_window_floor() {
    let now = Instant::now();
    let mut e = engine_awaiting_replay();
    peer_status(&mut e, PEER, HEAD_ROOT, 200);
    local_status(&mut e, 0, 200);
    advance(&mut e);
    assert!(drive(&mut e, now).is_none(), "the replay gate holds requests");

    e.on_replay_complete();
    local_status(&mut e, 100, 200);

    let (_, start, _) = drive(&mut e, now).expect("requests open after replay");
    assert_eq!(tail(&e), 100, "the replayed head is the floor, not a gap to fetch");
    assert_eq!(start, 101, "so fetching resumes above it");
}

/// Coverage is keyed by slot with nothing recording which branch it came
/// from. A block beacon state merely parks moves the tail without moving
/// the head, so no reorg is reported — and reading that as progress on
/// a different chain writes those slots off for good.
#[test]
fn new_chain_does_not_inherit_the_old_chains_coverage() {
    let now = Instant::now();
    let mut e = engine();
    let (rid, _, _) = issue_one(&mut e, 200, 0, now);

    // Chain A's 1..=10 covered, nothing imported: the blocks are parked, so
    // fork choice never moves and nothing reports a reorg.
    for slot in 1..=10 {
        covered(&mut e, slot, Some(slot - 1));
    }
    e.on_terminator(rid, PEER, false, now);
    drive(&mut e, now);
    assert_eq!(tail(&e), 10, "the tail followed chain A's coverage");

    // Selection moves to an unrelated chain.
    e.on_peer_disconnected(PEER);
    peer_status(&mut e, 2, [9; 32], 300);
    local_status(&mut e, 0, 300);
    advance(&mut e);

    assert_eq!(tail(&e), 0, "chain A's coverage is not progress on chain B");
    let (_, start, _) = drive(&mut e, now).expect("re-issued for the new chain");
    assert_eq!(start, 1, "so chain B is fetched from the anchor, not from 11");
}

#[test]
fn rpc_block_reject_blacklists_finalized_target() {
    let mut e = engine();
    peer_finalized(&mut e, PEER, (HEAD_ROOT, 4000), 100);
    local_status(&mut e, 0, 4000);
    advance(&mut e);
    let target = e.current_target();
    assert!(
        matches!(target, Some(SyncUpdate::SyncingFinalized { target_root, .. }) if target_root == [5; 32])
    );

    e.on_block_rejected([1; 32], BlockSource::Rpc);
    advance(&mut e);
    assert!(
        !matches!(e.current_target(), Some(SyncUpdate::SyncingFinalized { target_root, .. }) if target_root == [5; 32]),
        "poisoned finalized target not re-pinned",
    );
}

/// Every range request one drive emits, by kind.
#[derive(Default)]
struct Issued {
    block: Option<(u64, u64, u64)>,
    columns: Option<(u64, u64, u64, u128)>,
    envelope: Option<(u64, u64, u64)>,
}

fn drive_all(e: &mut SyncEngine, now: Instant) -> Issued {
    let emitted = actions(e, now, true);
    let columns = emitted.iter().find_map(|a| match a {
        SyncAction::Request { request_id, request } if request.kind == DataKind::Columns => {
            let Scope::Range { start, count } = request.scope else { return None };
            Some((*request_id, start, count, request.columns))
        }
        _ => None,
    });
    Issued {
        block: ranges(&emitted, DataKind::Block).into_iter().next(),
        columns,
        envelope: ranges(&emitted, DataKind::Envelope).into_iter().next(),
    }
}

/// A column range becomes several wire requests across custody peers, but
/// that is PM's business: the engine is told the range ended once, and one
/// report is what frees it.
/// At the tip the owed span is a slot or two, so a response ending re-derives
/// the identical range at once — while the sidecars it delivered are still
/// being verified a tile away. A span that has not moved is one still in that
/// tile's hands, however many passes that takes.
#[test]
fn delivered_tip_span_is_not_re_asked_until_it_moves() {
    let now = Instant::now();
    let mut e = gloas_engine(0b11, u64::MAX);
    peer_status(&mut e, PEER, HEAD_ROOT, 200);
    local_status(&mut e, 0, 200);
    advance(&mut e);

    let mut issued = 0;
    let mut at = now;
    let mut delivered_for = None;
    for _ in 0..24 {
        if let Some((rid, start, ..)) = drive_all(&mut e, at).columns {
            issued += 1;
            e.on_msg_served(rid);
            e.on_terminator(rid, PEER, true, at);
            delivered_for = Some(start);
        }
        at += Duration::from_millis(1);
    }
    assert_eq!(issued, 1, "one request while its delivery goes uncovered");

    // The columns tile reports what it made of them: the span moves on, and
    // the next one is asked for without waiting out the backstop.
    let covered = delivered_for.expect("a range was issued");
    e.on_columns_covered(covered, [7; 32]);
    let (_, start, ..) = drive_all(&mut e, at).columns.expect("the span moved, so it is asked");
    assert!(start > covered, "and only for what is still owed");
}

#[test]
fn range_is_freed_by_its_one_terminator() {
    let now = Instant::now();
    let mut e = gloas_engine(0b11, u64::MAX);
    peer_status(&mut e, PEER, HEAD_ROOT, 200);
    local_status(&mut e, 0, 200);
    advance(&mut e);

    let (rid, ..) = drive_all(&mut e, now).columns.expect("column range issued");
    assert!(drive_all(&mut e, now).columns.is_none(), "held while it is out there");

    e.on_msg_served(rid);
    e.on_terminator(rid, PEER, true, now);
    assert!(
        drive_all(&mut e, now).columns.is_none(),
        "what it delivered is not covered yet, so the same span waits"
    );
    assert!(
        drive_all(&mut e, now + SETTLE_TIMEOUT).columns.is_some(),
        "and is asked again if coverage never comes"
    );
}

#[test]
fn columns_are_requested_alongside_blocks() {
    let now = Instant::now();
    let mut e = gloas_engine(0b1011, SpecConfig::mainnet().gloas_fork_epoch);
    peer_status(&mut e, PEER, HEAD_ROOT, 200);
    local_status(&mut e, 0, 200);
    advance(&mut e);

    // Both go out on the same drive: waiting for the blocks to land first
    // would split every batch into two serialised round trips.
    let issued = drive_all(&mut e, now);
    let (_, bstart, bcount) = issued.block.expect("block range issued");
    let (crid, cstart, ccount, ccols) = issued.columns.expect("column range issued");
    assert_eq!((cstart, ccount), (bstart, bcount), "same span as the blocks");
    assert_eq!(ccols, 0b1011, "requests the full custody mask");
    assert_eq!(
        (RequestId::from(crid).kind, RequestId::from(crid).origin),
        (DataKind::Columns, Origin::Live)
    );
}

#[test]
fn proven_empty_slots_are_not_asked_for() {
    let now = Instant::now();
    let mut e = gloas_engine(0b1011, SpecConfig::mainnet().gloas_fork_epoch);
    peer_status(&mut e, PEER, HEAD_ROOT, 200);
    local_status(&mut e, 0, 200);
    advance(&mut e);

    // A block at 5 whose parent is the anchor proves 1..=4 hold nothing, so
    // the scan starts past them — nothing can be owed on an empty slot.
    block_at(&mut e, 5, Some(0));
    let issued = drive_all(&mut e, now);
    let (_, cstart, _, _) = issued.columns.expect("column range issued");
    assert_eq!(cstart, 5, "empty slots are skipped, not asked about");
}

#[test]
fn envelopes_are_requested_alongside_blocks_in_gloas() {
    let now = Instant::now();
    let mut e = gloas_engine(0, 0);
    peer_status(&mut e, PEER, HEAD_ROOT, 200);
    local_status(&mut e, 0, 200);
    advance(&mut e);

    let issued = drive_all(&mut e, now);
    let (_, bstart, _) = issued.block.expect("block range issued");
    let (erid, estart, _) = issued.envelope.expect("envelope range issued");
    assert_eq!(estart, bstart, "same span as the blocks");
    assert_eq!(
        (RequestId::from(erid).kind, RequestId::from(erid).origin),
        (DataKind::Envelope, Origin::Live)
    );
}

#[test]
fn no_envelopes_below_gloas_fork() {
    let now = Instant::now();
    let mut e = gloas_engine(0, 32);
    peer_status(&mut e, PEER, HEAD_ROOT, 200);
    local_status(&mut e, 0, 200);
    advance(&mut e);

    let issued = drive_all(&mut e, now);
    assert!(issued.block.is_some(), "blocks are still fetched");
    assert!(issued.envelope.is_none(), "no envelope request below the gloas fork slot");
}
