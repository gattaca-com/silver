use flux::spine::SpineProducers;
use silver_beacon_state_data::{B256, SLOTS_PER_EPOCH, Slot};
use silver_common::{
    BeaconStateEvent, BlockSource, DataColumnsAvailable, NewGossipMsg, P2pStreamId, PeerEvent,
    RpcSeverity, TCacheRead, TRandomAccess, TRead, hex32, ssz_view::SignedBeaconBlockView,
};

use super::{BeaconStateTile, Feedback, Producers};

impl BeaconStateTile {
    pub(super) fn clear_pending_blocks(&mut self, finalized_slot: u64) {
        tracing::debug!(
            pending_blocks = self.pending_blocks.len(),
            finalized_slot,
            "clear pending blocks at finalization"
        );
        let (gossip_consumer, rpc_consumer) = (&mut self.gossip_consumer, &mut self.rpc_consumer);
        self.pending_blocks.retain(|_, msgs| {
            msgs.iter().all(|(_, msg)| {
                pending_block_outlives(gossip_consumer, rpc_consumer, msg, finalized_slot)
            })
        });

        self.dc_pending_blocks.retain(|_, msg| {
            pending_block_outlives(gossip_consumer, rpc_consumer, msg, finalized_slot)
        });
        self.dc_available.retain(|_, slot| *slot > finalized_slot);
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
                request_id: 0,
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
        if self.dc_pending_blocks.len() >= self.pending_bounds.max_dc &&
            !self.dc_pending_blocks.contains_key(&block_root)
        {
            return;
        }
        self.dc_pending_blocks.entry(block_root).or_insert(pending);
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
                let acquired = self.gossip_consumer.acquire(g.ssz);
                if let Some(p) = acquired.buffer().ok().map(|(d, _)| d as *const [u8]) {
                    self.handle_gossip(g, unsafe { &*p }, do_relay, pre_verified, producers);
                }
            }
            PendingBlock::Rpc(stream_id, ssz) => {
                let acquired = self.rpc_consumer.acquire(ssz);
                if let Some(p) = acquired.buffer().ok().map(|(d, _)| d as *const [u8]) {
                    self.handle_rpc_block(
                        stream_id,
                        unsafe { &*p },
                        acquired,
                        pre_verified,
                        producers,
                    );
                } else {
                    tracing::error!("failed to acquire buffer for pending replay");
                }
            }
        }
    }

    pub(super) fn handle_data_columns_available(
        &mut self,
        m: DataColumnsAvailable,
        producers: &mut Producers,
    ) {
        if m.slot > self.da_boundary() {
            self.dc_available.insert(m.block_root, m.slot);
        }
        tracing::debug!(
            block = hex32(&m.block_root),
            slot = m.slot,
            is_buffered = self.dc_pending_blocks.contains_key(&m.block_root),
            dc_pending = self.dc_pending_blocks.len(),
            "DataColumnsAvailable received"
        );
        if let Some(pending) = self.dc_pending_blocks.remove(&m.block_root) {
            // Already relayed and BLS-verified when first seen (it reached the
            // DA gate, which is past the signature check).
            self.replay_pending_block(pending, false, true, producers);
        }
    }

    pub(super) fn handle_rpc_block(
        &mut self,
        sender: P2pStreamId,
        data: &[u8],
        data_tcache: TRead,
        pre_verified: bool,
        producers: &mut Producers,
    ) {
        {
            if !SignedBeaconBlockView::check_size(data) {
                producers.produce(PeerEvent::RpcMisbehaviour {
                    p2p_peer: sender.peer(),
                    severity: RpcSeverity::LowTolerance,
                });
                return;
            }
            let tcache = data_tcache.read;
            let f = self.apply_block(data, data_tcache, BlockSource::Rpc, pre_verified, producers);
            match f {
                Feedback::Accept(block_root) => {
                    // Try to apply any pending blocks for which this one was the parent.
                    if let Some(root) = block_root {
                        self.apply_pending_blocks(root, producers);
                    }
                    producers.produce(self.status_event());
                }
                Feedback::RequestParent { parent_root, block_root } => {
                    let peer = sender.peer();
                    let block_slot = SignedBeaconBlockView::slot(data);
                    self.buffer_orphan(
                        parent_root,
                        block_root,
                        PendingBlock::Rpc(sender, tcache),
                        block_slot,
                        peer,
                        producers,
                    );
                }
                Feedback::AwaitData(block_root) => {
                    self.buffer_awaiting_columns(block_root, PendingBlock::Rpc(sender, tcache));
                }
                Feedback::Ignore => {}
                Feedback::Reject(_) => producers.produce(PeerEvent::RpcMisbehaviour {
                    p2p_peer: sender.peer(),
                    severity: RpcSeverity::Fatal,
                }),
            }
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

/// Keep a pending block iff its slot is above the finalized boundary
/// (unreadable buffers are dropped).
fn pending_block_outlives(
    gossip_consumer: &mut TRandomAccess,
    rpc_consumer: &mut TRandomAccess,
    msg: &PendingBlock,
    finalized_slot: u64,
) -> bool {
    pending_block_slot(gossip_consumer, rpc_consumer, msg).is_some_and(|s| s > finalized_slot)
}
