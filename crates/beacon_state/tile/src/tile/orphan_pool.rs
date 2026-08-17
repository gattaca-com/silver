use flux::spine::SpineProducers;
use rustc_hash::FxHashMap;
use silver_beacon_state_data::{B256, SLOTS_PER_EPOCH, Slot};
use silver_common::{
    BeaconStateEvent, BlockSource, NewGossipMsg, P2pStreamId, PeerEvent, RpcSeverity, TCacheRead,
    TRandomAccess, hex32, metrics::timed, ssz_view::SignedBeaconBlockView,
};

use super::{BY_ROOT_REQUEST_ID, BeaconStateTile, Feedback, Producers};

impl BeaconStateTile {
    #[timed]
    pub(super) fn clear_pending_blocks(&mut self, finalized_slot: u64) {
        tracing::debug!(
            pending_blocks = self.pending_blocks.len(),
            finalized_slot,
            "clear pending blocks at finalization"
        );
        let (gossip_consumer, rpc_consumer) = (&mut self.gossip_consumer, &mut self.rpc_consumer);
        let mut outlives = |msg: &PendingBlock| {
            pending_block_outlives(gossip_consumer, rpc_consumer, msg, finalized_slot)
        };
        self.pending_blocks.retain(|_, msgs| msgs.iter().all(|(_, msg)| outlives(msg)));
        self.dc_pending_blocks.retain(|_, msg| outlives(msg));
        self.payload_pending_blocks.retain(|_, msgs| msgs.iter().all(&mut outlives));
        self.dc_available.retain(|_, slot| *slot > finalized_slot);
        self.pending_envelopes.retain(|_, handle| handle.buffer().is_ok());

        let fc = &self.fork_choice;
        self.envelope_requested.retain(|root, _| fc.find_node_idx(root).is_some());
    }

    pub(super) fn apply_pending_blocks(&mut self, parent_root: B256, producers: &mut Producers) {
        if let Some(pending) = self.pending_blocks.remove(&parent_root) {
            for (_, child) in pending {
                // First successful validation of an orphan held on a missing
                // parent: relay it now. Recursively applies chained orphans.
                // Not pre-verified — precheck bailed at parent-missing before
                // the BLS check, so the signature is still unverified.
                self.replay_pending_block(child, true, false, producers);
            }
        }
    }

    pub(super) fn buffer_orphan(
        &mut self,
        parent_root: B256,
        block_root: B256,
        pending: PendingBlock,
        block_slot: Slot,
        peer: usize,
        producers: &mut Producers,
    ) {
        if !self.within_pending_window(block_slot) {
            return;
        }

        let head_slot = self.head_state_slot();
        if self.mode.is_following() &&
            block_slot.saturating_sub(head_slot) > self.pending_bounds.max_chain_len as u64
        {
            tracing::warn!(
                block_slot,
                head_slot,
                limit = self.pending_bounds.max_chain_len,
                "orphan too far ahead; falling back to range sync"
            );
            producers.produce(BeaconStateEvent::BacktrackStall);
            return;
        }

        let existing = self.pending_blocks.get(&parent_root);
        if existing.is_some_and(|v| v.iter().any(|(r, _)| *r == block_root)) {
            return;
        }

        let at_parent_cap = existing.is_some_and(|v| v.len() >= self.max_pending_per_parent);
        let new_parent = existing.is_none();
        if at_parent_cap ||
            (new_parent && self.pending_blocks.len() >= self.pending_bounds.max_parents)
        {
            tracing::warn!(
                parent = hex32(&parent_root),
                at_parent_cap,
                pending_parents = self.pending_blocks.len(),
                "pending-orphan buffer full; dropping orphan"
            );
            return;
        }

        let request =
            self.mode.is_following() && !self.dc_pending_blocks.contains_key(&parent_root);
        self.pending_blocks.entry(parent_root).or_default().push((block_root, pending));
        if request {
            producers.produce(PeerEvent::SendBlocksByRootRequest {
                request_id: BY_ROOT_REQUEST_ID,
                p2p_peer: Some(peer),
                block_root: parent_root,
            });
        }
    }

    /// True iff `block_slot` is inside the pending admission window:
    /// above the finalized boundary and at most `future_tolerance` slots ahead
    /// of the wall clock.
    pub(super) fn within_pending_window(&self, block_slot: Slot) -> bool {
        let finalized_slot = self.head_finalized_checkpoint().epoch * SLOTS_PER_EPOCH;
        block_slot > finalized_slot &&
            block_slot <= self.ticker.current_slot() + self.pending_bounds.future_tolerance
    }

    pub(super) fn buffer_awaiting_columns(&mut self, block_root: B256, pending: PendingBlock) {
        if !has_room(&self.dc_pending_blocks, self.pending_bounds.max_dc, &block_root) {
            return;
        }
        self.dc_pending_blocks.entry(block_root).or_insert(pending);
    }

    pub(super) fn buffer_awaiting_payload(
        &mut self,
        parent_root: B256,
        pending: PendingBlock,
        peer: usize,
        producers: &mut Producers,
    ) {
        let known = self.payload_pending_blocks.contains_key(&parent_root);
        if !known && self.payload_pending_blocks.len() >= self.pending_bounds.max_dc {
            return;
        }
        self.payload_pending_blocks.entry(parent_root).or_default().push(pending);
        if !known {
            producers.produce(PeerEvent::SendEnvelopesByRootRequest {
                request_id: BY_ROOT_REQUEST_ID,
                p2p_peer: Some(peer),
                block_root: parent_root,
            });
        }
    }

    pub(super) fn drain_awaiting_payload(
        &mut self,
        verified_root: B256,
        producers: &mut Producers,
    ) {
        if let Some(pending) = self.payload_pending_blocks.remove(&verified_root) {
            for child in pending {
                self.replay_pending_block(child, false, false, producers);
            }
        }
    }

    fn replay_pending_block(
        &mut self,
        pending: PendingBlock,
        do_relay: bool,
        pre_verified: bool,
        producers: &mut Producers,
    ) {
        match pending {
            PendingBlock::Gossip(g) => {
                self.handle_gossip(g.ssz, g, do_relay, pre_verified, producers);
            }
            PendingBlock::Rpc(stream_id, ssz) => {
                self.handle_rpc_block(stream_id, ssz, pre_verified, producers);
            }
        }
    }

    pub(super) fn handle_data_columns_available(
        &mut self,
        block_root: B256,
        slot: u64,
        producers: &mut Producers,
    ) {
        if slot > self.da_boundary() {
            self.dc_available.insert(block_root, slot);
        }
        tracing::debug!(
            block = hex32(&block_root),
            slot = slot,
            is_buffered = self.dc_pending_blocks.contains_key(&block_root),
            dc_pending = self.dc_pending_blocks.len(),
            "DataColumnsAvailable received"
        );
        if let Some(pending) = self.dc_pending_blocks.remove(&block_root) {
            // Already relayed and BLS-verified when first seen (it reached the
            // DA gate, which is past the signature check).
            self.replay_pending_block(pending, false, true, producers);
        }
    }

    pub(super) fn on_accept(&mut self, block_root: Option<B256>, producers: &mut Producers) {
        if let Some(root) = block_root {
            self.apply_pending_blocks(root, producers);
            self.drain_pending_envelope(root, producers);
        }
        producers.produce(self.status_event());
    }

    pub(super) fn park_block(
        &mut self,
        feedback: Feedback,
        source: PendingBlock,
        data: &[u8],
        producers: &mut Producers,
    ) {
        match feedback {
            Feedback::RequestParent { parent_root, block_root } => {
                let peer = source.peer();
                let block_slot = SignedBeaconBlockView::slot(data);
                self.buffer_orphan(parent_root, block_root, source, block_slot, peer, producers);
            }
            Feedback::AwaitData(block_root) => self.buffer_awaiting_columns(block_root, source),
            Feedback::AwaitParentPayload { parent_root, .. } => {
                let peer = source.peer();
                self.buffer_awaiting_payload(parent_root, source, peer, producers);
            }
            _ => debug_assert!(false, "park_block: unexpected feedback {feedback:?}"),
        }
    }

    pub(super) fn handle_rpc_block(
        &mut self,
        sender: P2pStreamId,
        read: TCacheRead,
        pre_verified: bool,
        producers: &mut Producers,
    ) {
        let acquired = self.rpc_consumer.acquire(read);
        let Some((data, _)) = acquired.buffer().ok() else {
            return;
        };

        if !SignedBeaconBlockView::check_size(data) {
            producers.produce(PeerEvent::RpcMisbehaviour {
                p2p_peer: sender.peer(),
                severity: RpcSeverity::LowTolerance,
            });
            return;
        }

        let feedback =
            self.apply_block(data, read, BlockSource::Rpc, pre_verified, producers, |_| {});
        match feedback {
            Feedback::Accept(block_root) => self.on_accept(block_root, producers),
            Feedback::Reject(_) => producers.produce(PeerEvent::RpcMisbehaviour {
                p2p_peer: sender.peer(),
                severity: RpcSeverity::Fatal,
            }),
            Feedback::Ignore => {}
            _ => self.park_block(feedback, PendingBlock::Rpc(sender, read), data, producers),
        }
    }

    /// Below this slot data availability is not required (already finalized,
    /// or PM is range-syncing past it).
    pub(super) fn da_boundary(&self) -> Slot {
        self.sync_finalized_slot.max(self.fork_choice.finalized_checkpoint.epoch * SLOTS_PER_EPOCH)
    }
}

pub(super) enum PendingBlock {
    Gossip(NewGossipMsg),
    Rpc(P2pStreamId, TCacheRead),
}

impl PendingBlock {
    fn peer(&self) -> usize {
        match self {
            Self::Gossip(m) => m.stream_id.peer(),
            Self::Rpc(sender, _) => sender.peer(),
        }
    }
}

/// Resolve a pending block's slot via its source consumer. `None` if the
/// buffer was recycled (the block's data is gone).
fn pending_block_slot(
    gossip_consumer: &mut TRandomAccess,
    rpc_consumer: &mut TRandomAccess,
    msg: &PendingBlock,
) -> Option<Slot> {
    let acquired = match msg {
        PendingBlock::Gossip(g) => gossip_consumer.acquire(g.ssz),
        PendingBlock::Rpc(_, ssz) => rpc_consumer.acquire(*ssz),
    };
    acquired.buffer().ok().map(|(buffer, _)| SignedBeaconBlockView::slot(buffer))
}

pub(super) fn has_room<V>(map: &FxHashMap<B256, V>, cap: usize, key: &B256) -> bool {
    map.len() < cap || map.contains_key(key)
}

/// Keep a pending block iff its slot is above the finalized boundary.
fn pending_block_outlives(
    gossip_consumer: &mut TRandomAccess,
    rpc_consumer: &mut TRandomAccess,
    msg: &PendingBlock,
    finalized_slot: u64,
) -> bool {
    pending_block_slot(gossip_consumer, rpc_consumer, msg).is_some_and(|s| s > finalized_slot)
}
