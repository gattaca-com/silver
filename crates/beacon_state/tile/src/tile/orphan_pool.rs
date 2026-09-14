use flux::spine::SpineProducers;
use silver_beacon_state_data::{B256, SLOTS_PER_EPOCH, Slot};
use silver_common::{
    BeaconStateEvent, BlockSource, BlockStage, P2pStreamId, PeerEvent, RpcSeverity, SyncNeed,
    TCacheRead, hex32, metrics::timed, ssz_view::SignedBeaconBlockView,
};

use super::{
    BeaconStateTile, Feedback, Producers,
    held_blocks::{BlockSourceMsg, Orphan},
};

impl BeaconStateTile {
    #[timed]
    pub(super) fn clear_finalized_held(&mut self, finalized_slot: u64) {
        tracing::debug!(
            orphan_parents = self.held.orphans.parents(),
            finalized_slot,
            "clear held blocks at finalization"
        );
        self.held.clear_outdated(finalized_slot);

        self.pending_envelopes.retain(|root, handle| {
            let held = handle.buffer().is_ok();
            if !held {
                tracing::error!(
                    block = hex32(root),
                    "parked envelope lapped in the tcache before its block arrived"
                );
            }
            held
        });
    }

    pub(super) fn replay_orphans(&mut self, parent_root: B256, producers: &mut Producers) {
        for child in self.held.orphans.take(&parent_root) {
            // First successful validation of an orphan held on a missing
            // parent: relay it now. Recursively applies chained orphans.
            // Not pre-verified — precheck bailed at parent-missing before
            // the BLS check, so the signature is still unverified.
            self.replay_pending_block(child, true, false, producers);
        }
    }

    pub(super) fn buffer_orphan(
        &mut self,
        parent_root: B256,
        block_root: B256,
        msg: BlockSourceMsg,
        block_slot: Slot,
        producers: &mut Producers,
    ) -> bool {
        if !self.within_pending_window(block_slot) {
            tracing::debug!(
                block_slot,
                wall_slot = self.ticker.current_slot(),
                "orphan outside the pending window; dropped"
            );
            return false;
        }

        let head_slot = self.head_state_slot();
        if block_slot.saturating_sub(head_slot) > self.pending_bounds.max_chain_len as u64 {
            tracing::warn!(
                block_slot,
                head_slot,
                limit = self.pending_bounds.max_chain_len,
                "orphan too far ahead"
            );
            return false;
        }

        let orphan = Orphan { block_root, slot: block_slot, msg };
        if !self.held.orphans.park(parent_root, orphan) {
            return false;
        }
        // A staged parent is already held; its import drains this child.
        if !self.held.is_staged(&parent_root) {
            producers.produce(SyncNeed::missing_block(parent_root, block_slot));
        }
        true
    }

    /// True iff `block_slot` is inside the pending admission window:
    /// above the finalized boundary and at most `future_tolerance` slots ahead
    /// of the wall clock.
    pub(super) fn within_pending_window(&self, block_slot: Slot) -> bool {
        let finalized_slot = self.head_finalized_checkpoint().epoch * SLOTS_PER_EPOCH;
        block_slot > finalized_slot &&
            block_slot <= self.ticker.current_slot() + self.pending_bounds.future_tolerance
    }

    pub(super) fn buffer_awaiting_payload(
        &mut self,
        parent_root: B256,
        block_root: B256,
        block_slot: Slot,
        msg: BlockSourceMsg,
        producers: &mut Producers,
    ) -> bool {
        let orphan = Orphan { block_root, slot: block_slot, msg };
        if !self.held.payload_orphans.park(parent_root, orphan) {
            return false;
        }
        producers.produce(SyncNeed::missing_envelope(parent_root, block_slot));
        true
    }

    pub(super) fn drain_awaiting_payload(
        &mut self,
        verified_root: B256,
        producers: &mut Producers,
    ) {
        for child in self.held.payload_orphans.take(&verified_root) {
            self.replay_pending_block(child, false, false, producers);
        }
    }

    fn replay_pending_block(
        &mut self,
        orphan: Orphan,
        do_relay: bool,
        pre_verified: bool,
        producers: &mut Producers,
    ) {
        let Orphan { block_root, slot, msg } = orphan;
        let replayed = match msg {
            BlockSourceMsg::Gossip(g) => {
                self.handle_gossip(g.ssz, g, do_relay, pre_verified, producers)
            }
            BlockSourceMsg::Rpc(stream_id, ssz) => {
                self.handle_rpc_block(stream_id, ssz, pre_verified, producers)
            }
        };
        if !replayed {
            tracing::warn!(
                block = hex32(&block_root),
                slot,
                "parked block lapped in the tcache before its dependency arrived; re-requesting"
            );
            producers.produce(SyncNeed::missing_block(block_root, slot));
        }
    }

    pub(super) fn on_accept(&mut self, block_root: Option<B256>, producers: &mut Producers) {
        if let Some(root) = block_root {
            self.replay_orphans(root, producers);
            self.drain_pending_envelope(root, producers);
        }
        producers.produce(self.status_event());
    }

    pub(super) fn park_block(
        &mut self,
        feedback: Feedback,
        msg: BlockSourceMsg,
        data: &[u8],
        producers: &mut Producers,
    ) {
        let block_source = msg.source();
        let admitted = match feedback {
            Feedback::RequestParent { parent_root, block_root } => {
                let block_slot = SignedBeaconBlockView::slot(data);
                self.buffer_orphan(parent_root, block_root, msg, block_slot, producers)
                    .then_some(block_root)
            }
            Feedback::AwaitParentPayload { parent_root, block_root } => self
                .buffer_awaiting_payload(
                    parent_root,
                    block_root,
                    SignedBeaconBlockView::slot(data),
                    msg,
                    producers,
                )
                .then_some(block_root),
            _ => {
                debug_assert!(false, "park_block: unexpected feedback {feedback:?}");
                None
            }
        };

        if let Some(block_root) = admitted {
            self.emit_block_received(
                data,
                block_root,
                BlockStage::AwaitParent,
                block_source,
                producers,
            );
        }
    }

    pub(super) fn emit_block_received(
        &self,
        data: &[u8],
        block_root: B256,
        stage: BlockStage,
        source: BlockSource,
        producers: &mut Producers,
    ) {
        let parent_root = *SignedBeaconBlockView::parent_root(data);
        producers.produce(BeaconStateEvent::BlockReceived {
            slot: SignedBeaconBlockView::slot(data),
            block_root,
            stage,
            source,
            parent_slot: self
                .fork_choice
                .find_node_idx(&parent_root)
                .map(|idx| self.fork_choice.node(idx).slot),
        });
    }

    /// False when the ring lapped `read` before it could be handled.
    pub(super) fn handle_rpc_block(
        &mut self,
        sender: P2pStreamId,
        read: TCacheRead,
        pre_verified: bool,
        producers: &mut Producers,
    ) -> bool {
        let acquired = self.rpc_consumer.acquire(read);
        let Some((data, _)) = acquired.buffer().ok() else {
            return false;
        };

        if !SignedBeaconBlockView::check_size(data) {
            producers.produce(PeerEvent::RpcMisbehaviour {
                p2p_peer: sender.peer(),
                severity: RpcSeverity::LowTolerance,
            });
            return true;
        }

        let feedback =
            self.apply_block(data, read, BlockSource::Rpc, pre_verified, producers, |_, _| {});
        match feedback {
            Feedback::Accept(block_root) => self.on_accept(block_root, producers),
            Feedback::Reject(_) => producers.produce(PeerEvent::RpcMisbehaviour {
                p2p_peer: sender.peer(),
                severity: RpcSeverity::Fatal,
            }),
            Feedback::AwaitData(_) | Feedback::AlreadyKnown(_) | Feedback::Ignore => {}
            _ => self.park_block(feedback, BlockSourceMsg::Rpc(sender, read), data, producers),
        }
        true
    }
}
