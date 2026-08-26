//! What we tell peers about our own chain, what we make of theirs, and
//! which target the sync engine has us on. Turning a target into placed
//! requests is `rpc`'s job.

use std::collections::{HashSet, VecDeque};

use fxhash::FxHashSet;
use silver_common::{
    BlockSource, GossipTopic, PeerStatus, RpcSeverity, StreamProtocol, SyncUpdate,
    ssz_view::{METADATA_SIZE, STATUS_V2_SIZE, StatusView},
};

use super::PeerManager;
use crate::state::PeerState;

impl PeerManager {
    /// Set the current fork digest. Call at startup and on every hard-fork
    /// transition. Once set, discovery hits whose ENR doesn't carry the
    /// matching `eth2` field are dropped before dial.
    pub fn set_fork_digest(&mut self, digest: [u8; 4]) {
        self.adopt_fork_digest(digest);
    }

    fn adopt_fork_digest(&mut self, digest: [u8; 4]) -> bool {
        match self.our_fork_digest.replace(digest) {
            Some(held) if held == digest => false,
            Some(held) => {
                self.previous_fork_digest = Some(held);
                true
            }
            None => true,
        }
    }

    pub(super) fn is_our_fork_digest(&self, digest: &[u8]) -> bool {
        self.our_fork_digest.is_some_and(|ours| digest == ours) ||
            self.previous_fork_digest.is_some_and(|previous| digest == previous)
    }

    pub fn set_status(&mut self, mut ssz: [u8; STATUS_V2_SIZE]) -> bool {
        let digest_changed = self.adopt_fork_digest(*StatusView::fork_digest(&ssz));

        let head_slot = StatusView::head_slot(&ssz);
        let clamped_earliest = self.earliest_available_slot.min(head_slot);
        ssz[84..].copy_from_slice(&clamped_earliest.to_le_bytes());

        tracing::debug!("set status");
        self.status = Some(ssz);
        digest_changed
    }

    pub fn set_local_head_imported(&mut self, slot: u64) {
        self.local_head_imported_slot = slot;
    }

    /// Consume `BeaconStateEvent::BlockRejected`: blacklist `block_root` so a
    /// peer whose Status backs the rejected chain gets evicted. The sync-target
    /// + watermark invalidation is the `SyncEngine`'s.
    pub fn record_block_rejected(&mut self, block_root: [u8; 32], _source: BlockSource) {
        self.rejected.mark(block_root);
    }

    pub fn record_finalized_rejected(&mut self, root: [u8; 32]) {
        self.rejected.mark(root);
    }

    pub fn rejected(&self) -> &RejectedRoots {
        &self.rejected
    }

    pub fn current_sync_target(&self) -> SyncUpdate {
        self.current_target
    }

    pub fn drain_finished_requests(&mut self) -> std::vec::Drain<'_, (u64, usize, bool)> {
        self.finished_requests.drain(..)
    }

    pub fn our_fork_digest(&self) -> Option<[u8; 4]> {
        self.our_fork_digest
    }

    /// Track the engine-selected sync target (the engine is authoritative) so
    /// `pick_sync_peer` / `best_peer_for_data_columns` can match peers against
    /// it. Watermark + column resets are the engine's.
    pub fn set_sync_target(&mut self, new_target: SyncUpdate) {
        self.current_target = new_target;
    }

    pub fn status(&self) -> Option<&[u8; STATUS_V2_SIZE]> {
        self.status.as_ref()
    }

    pub fn metadata(&self) -> &[u8; METADATA_SIZE] {
        &self.metadata
    }

    pub fn set_metadata(&mut self, metadata: [u8; METADATA_SIZE]) {
        self.metadata = metadata;
    }

    /// Pick the connected, protocol-supporting peer with the highest cached
    /// score that also satisfies the caller-supplied `eligible` predicate
    /// (e.g., "not at outstanding-request cap"). Returns `None` when no peer
    /// matches.
    pub fn best_peer_for(
        &self,
        protocol: StreamProtocol,
        eligible: impl Fn(usize) -> bool,
    ) -> Option<usize> {
        self.database.live_peers_supporting(protocol).filter(|p| eligible(*p)).max_by(|a, b| {
            let sa = self.score(*a).unwrap_or(f64::NEG_INFINITY);
            let sb = self.score(*b).unwrap_or(f64::NEG_INFINITY);
            sa.partial_cmp(&sb).unwrap_or(std::cmp::Ordering::Equal)
        })
    }

    /// Validate an inbound Status RPC payload, then upsert the parsed
    /// fields into the DB.
    ///
    /// 1. `fork_digest` mismatch — peer is on a different chain/fork.
    /// 2. Same `finalized_epoch` as ours but different `finalized_root` — peer
    ///    has finalized a competing branch.
    /// 3. `finalized_root` is in our session blacklist — peer is backing a
    ///    chain we already rejected.
    pub(super) fn on_p2p_peer_status(&mut self, p2p_peer: usize, status_ssz: PeerStatus) {
        let buf: &[u8] = match &status_ssz {
            PeerStatus::V1(b) => b.as_slice(),
            PeerStatus::V2(b) => b.as_slice(),
        };
        if !StatusView::check_size(buf) {
            self.on_rpc_misbehaviour(
                p2p_peer,
                RpcSeverity::LowTolerance,
                "malformed status payload",
            );
            return;
        }
        let fork_digest = *StatusView::fork_digest(buf);
        let finalized_root = *StatusView::finalized_root(buf);
        let finalized_epoch = StatusView::finalized_epoch(buf);

        if let Some(our_fd) = self.our_fork_digest &&
            fork_digest != our_fd
        {
            self.on_rpc_misbehaviour(p2p_peer, RpcSeverity::Fatal, "status fork_digest mismatch");
            return;
        }

        // Only meaningful once something is actually finalized. At epoch 0 the
        // "finalized root" is a pre-finalization placeholder whose convention
        // differs across clients (zero vs genesis block root), so comparing it
        // would fatally evict every peer on a fresh chain.
        if let Some(local_ssz) = self.status.as_ref() &&
            finalized_epoch > 0 &&
            finalized_epoch == StatusView::finalized_epoch(local_ssz) &&
            finalized_root != *StatusView::finalized_root(local_ssz)
        {
            tracing::warn!("FATAL: finalized root and epoch mismatch");
            self.on_rpc_misbehaviour(
                p2p_peer,
                RpcSeverity::Fatal,
                "status finalized checkpoint mismatch",
            );
            return;
        }

        if self.rejected.contains(&finalized_root) {
            self.on_rpc_misbehaviour(p2p_peer, RpcSeverity::Fatal, "status backs rejected chain");
            return;
        }

        // Upsert the validated Status into the DB; the `SyncEngine` consumes
        // its own copy (`PeerStatus` event) for target selection + aggregates.
        let earliest_slot = StatusView::earliest_available_slot(buf);
        self.database.p2p_status(p2p_peer, status_ssz, earliest_slot);
    }

    /// (subscribed, advertised) overlap with our custody columns:
    /// `subscribed` counts our data-column topics in the peer's SUBSCRIBEs,
    /// `advertised` counts custody groups from its ENR/MetaData.
    pub(super) fn data_column_overlap(&self, conn: usize, state: &PeerState) -> (u32, u32) {
        let subscribed = subscribed_column_mask(&state.topics) & self.custody_columns;
        let advertised =
            self.database.data_column_custody_groups_intersection(conn, self.custody_columns);
        (subscribed.count_ones(), advertised.count_ones())
    }

    pub(super) fn data_column_peer_count(&self, exclude: usize) -> usize {
        self.peers
            .iter()
            .filter(|(conn, state)| {
                **conn != exclude && {
                    let (subscribed, advertised) = self.data_column_overlap(**conn, state);
                    subscribed > 0 || advertised > 0
                }
            })
            .count()
    }
}

pub struct RejectedRoots {
    cap: usize,
    order: VecDeque<[u8; 32]>,
    set: FxHashSet<[u8; 32]>,
}

impl RejectedRoots {
    pub fn new(cap: usize) -> Self {
        Self { cap, order: VecDeque::new(), set: FxHashSet::default() }
    }

    pub fn mark(&mut self, root: [u8; 32]) {
        if self.set.insert(root) {
            self.order.push_back(root);
            if self.order.len() > self.cap &&
                let Some(old) = self.order.pop_front()
            {
                self.set.remove(&old);
            }
        }
    }

    pub fn contains(&self, root: &[u8; 32]) -> bool {
        self.set.contains(root)
    }

    pub fn count(&self) -> usize {
        self.set.len()
    }

    pub fn unmark(&mut self, root: &[u8; 32]) {
        if self.set.remove(root) {
            self.order.retain(|held| held != root);
        }
    }
}

fn subscribed_column_mask(topics: &HashSet<GossipTopic>) -> u128 {
    topics.iter().fold(0u128, |mask, t| match t {
        GossipTopic::DataColumnSidecar(id) if *id < 128 => mask | (1u128 << id),
        _ => mask,
    })
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use silver_common::PeerControl;
    use silver_config::ScoreParams;

    use super::*;
    use crate::manager::fixture::*;

    fn fork_a() -> [u8; 4] {
        [0x01, 0x02, 0x03, 0x04]
    }

    fn fork_b() -> [u8; 4] {
        [0x05, 0x06, 0x07, 0x08]
    }

    #[test]
    fn p2p_status_fork_digest_mismatch_evicts() {
        let now = Instant::now();
        let (mut mgr, mut cap) = fixture(vec![], ScoreParams::default());
        connect(&mut mgr, &mut cap, 1, 1, now);
        mgr.set_fork_digest(fork_a());
        cap.0.clear();

        send_status(&mut mgr, &mut cap, 1, make_status_v2(fork_b(), [0u8; 32], 0, [0u8; 32], 0));
        mgr.tick(now + Duration::from_millis(100), &mut |c| cap.0.push(c));

        assert!(
            cap.0.iter().any(|e| matches!(e, PeerControl::Ban { .. })),
            "fork_digest mismatch must trigger Fatal eviction, got {:?}",
            cap.0
        );
        assert!(mgr.score(1).is_none());
    }

    #[test]
    fn p2p_status_matching_fork_digest_keeps_peer_and_parses_db() {
        let now = Instant::now();
        let (mut mgr, mut cap) = fixture(vec![], ScoreParams::default());
        connect(&mut mgr, &mut cap, 1, 1, now);
        mgr.set_fork_digest(fork_a());

        send_status(&mut mgr, &mut cap, 1, make_status_v2(fork_a(), [0u8; 32], 10, [0u8; 32], 320));
        mgr.tick(now + Duration::from_millis(100), &mut |c| cap.0.push(c));

        assert!(mgr.score(1).is_some(), "valid Status must not evict");
        let ssz = mgr.database.peer_status_bytes(1).expect("status present");
        assert_eq!(StatusView::fork_digest(ssz), &fork_a());
        assert_eq!(StatusView::finalized_epoch(ssz), 10);
        assert_eq!(StatusView::head_slot(ssz), 320);
    }

    #[test]
    fn p2p_status_divergent_finalized_root_evicts() {
        let now = Instant::now();
        let (mut mgr, mut cap) = fixture(vec![], ScoreParams::default());
        connect(&mut mgr, &mut cap, 1, 1, now);
        set_local(&mut mgr, status_v2_ssz(fork_a(), [0xAA; 32], 42, [0xCC; 32], 42 * 32 + 5));
        cap.0.clear();

        // Same epoch, DIFFERENT finalized root → permanent fork divergence.
        send_status(
            &mut mgr,
            &mut cap,
            1,
            make_status_v2(fork_a(), [0xBB; 32], 42, [0xDD; 32], 42 * 32 + 5),
        );
        mgr.tick(now + Duration::from_millis(100), &mut |c| cap.0.push(c));

        assert!(
            cap.0.iter().any(|e| matches!(e, PeerControl::Ban { .. })),
            "divergent finalized root must trigger Fatal eviction, got {:?}",
            cap.0
        );
        assert!(mgr.score(1).is_none());
    }

    #[test]
    fn p2p_status_same_finalized_root_accepted() {
        let now = Instant::now();
        let (mut mgr, mut cap) = fixture(vec![], ScoreParams::default());
        connect(&mut mgr, &mut cap, 1, 1, now);
        set_local(&mut mgr, status_v2_ssz(fork_a(), [0xAA; 32], 42, [0xCC; 32], 42 * 32 + 5));

        send_status(
            &mut mgr,
            &mut cap,
            1,
            make_status_v2(fork_a(), [0xAA; 32], 42, [0xEE; 32], 42 * 32 + 9),
        );
        mgr.tick(now + Duration::from_millis(100), &mut |c| cap.0.push(c));
        assert!(mgr.score(1).is_some());
    }

    #[test]
    fn p2p_status_rejected_finalized_root_evicts() {
        let now = Instant::now();
        let (mut mgr, mut cap) = fixture(vec![], ScoreParams::default());
        connect(&mut mgr, &mut cap, 1, 1, now);
        set_local(&mut mgr, status_v2_ssz(fork_a(), [0xAA; 32], 42, [0xCC; 32], 42 * 32 + 5));
        // Mark a competing finalized root as rejected. Any peer reporting
        // it must be evicted on next inbound Status.
        mgr.record_finalized_rejected([0xBB; 32]);
        cap.0.clear();

        // Peer is ahead in finality (so divergence rule doesn't fire), but
        // their finalized_root is the blacklisted one.
        send_status(
            &mut mgr,
            &mut cap,
            1,
            make_status_v2(fork_a(), [0xBB; 32], 50, [0xDD; 32], 50 * 32 + 1),
        );
        mgr.tick(now + Duration::from_millis(100), &mut |c| cap.0.push(c));

        assert!(
            cap.0.iter().any(|e| matches!(e, PeerControl::Ban { .. })),
            "blacklisted finalized_root must trigger Fatal eviction, got {:?}",
            cap.0
        );
        assert!(mgr.score(1).is_none());
    }

    #[test]
    fn set_status_syncs_fork_digest() {
        // When BS publishes LocalStateUpdate, our_fork_digest moves in
        // lockstep so ENR-discovery filter and inbound Status check never
        // diverge.
        let now = Instant::now();
        let (mut mgr, mut cap) = fixture(vec![], ScoreParams::default());
        connect(&mut mgr, &mut cap, 1, 1, now);

        set_local(&mut mgr, status_v2_ssz(fork_b(), [0; 32], 0, [0; 32], 0));
        send_status(&mut mgr, &mut cap, 1, make_status_v2(fork_b(), [0u8; 32], 0, [0u8; 32], 0));
        mgr.tick(now + Duration::from_millis(100), &mut |c| cap.0.push(c));
        assert!(mgr.score(1).is_some());
    }

    #[test]
    fn set_status_reports_fork_digest_change() {
        let (mut mgr, _cap) = fixture(vec![], ScoreParams::default());
        // First set (None -> Some) is a change.
        assert!(mgr.set_status(status_v2_ssz(fork_a(), [0; 32], 0, [0; 32], 0)));
        // Same digest, other fields differ -> not a change (only the digest matters).
        assert!(!mgr.set_status(status_v2_ssz(fork_a(), [0; 32], 0, [1; 32], 5)));
        // Fork flip -> change (triggers subscription re-announce).
        assert!(mgr.set_status(status_v2_ssz(fork_b(), [0; 32], 0, [0; 32], 0)));
    }
}
