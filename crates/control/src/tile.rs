use std::time::{Duration, Instant};

use flux::{spine::SpineAdapter, tile::Tile};
use silver_common::{
    BeaconStateEvent, GossipTopic, Nanos, P2pSend, PeerControl, PeerEvent, PeerStats, RpcInbound,
    RpcOutbound, RpcRequest, RpcRequestOutbound, RpcResponse, RpcResponseInbound, SilverSpine,
    SilverSpineProducers, SyncNeed, SyncUpdate, TMultiProducer, TRandomAccess,
    ssz_view::{METADATA_SIZE, STATUS_V2_SIZE, StatusView},
};
use silver_gossip::{GossipHandler, GossipHandlerEvent};
use silver_peer::PeerManager;

use crate::sync_engine::{SyncAction, SyncEngine};

const PEER_PERSIST_INTERVAL: Duration = Duration::from_secs(300);

pub struct Controller {
    peer_manager: PeerManager,
    gossip_handler: GossipHandler,
    /// Authoritative sync driver: owns target selection (produces the
    /// `sync_target`) and forward block issuance. PM serves its requests
    /// (peer-pick, caps, send) and owns column sync.
    sync_engine: SyncEngine,
    rpc_producer: TMultiProducer,
    /// Reads `incoming_rpc` sidecar payloads referenced by
    /// `PeerEvent::PublishDataColumn`.
    rpc_ssz_consumer: TRandomAccess,
    last_tick: Instant,
    last_ping: Instant,
    last_status: Instant,
    last_peer_persist: Instant,

    /// When false, the 17000ms heartbeat skips the per-peer Ping fan-out.
    /// Tests use this to keep the peer-state machine ticking without
    /// generating background Ping traffic that would interfere with
    /// targeted RPC assertions.
    auto_ping: bool,

    /// Long-lived subnet topics advertised (ENR/MetaData) from boot but
    /// subscribed only once the node is Following — grafted-while-syncing
    /// meshes would earn P3 deficit at peers since nothing validates or
    /// forwards until then. Drained into the PM on the first transition.
    pending_subnet_topics: Vec<GossipTopic>,
}

impl Controller {
    /// Build a Controller. `status` and `metadata` start empty — callers
    /// update them via `set_status` / `set_metadata` once chain state is
    /// available.
    pub fn new(
        peer_manager: PeerManager,
        gossip_handler: GossipHandler,
        rpc_producer: TMultiProducer,
        rpc_ssz_consumer: TRandomAccess,
        sync_engine: SyncEngine,
    ) -> Self {
        Self {
            peer_manager,
            gossip_handler,
            sync_engine,
            rpc_producer,
            rpc_ssz_consumer,
            last_tick: Instant::now(),
            last_ping: Instant::now(),
            last_status: Instant::now(),
            last_peer_persist: Instant::now(),
            auto_ping: true,
            pending_subnet_topics: Vec::new(),
        }
    }

    pub fn set_pending_subnet_topics(&mut self, topics: Vec<GossipTopic>) {
        self.pending_subnet_topics = topics;
    }

    pub fn set_status(&mut self, status: [u8; STATUS_V2_SIZE]) {
        self.peer_manager.set_status(status);
    }

    pub fn set_metadata(&mut self, metadata: [u8; METADATA_SIZE]) {
        self.peer_manager.set_metadata(metadata);
    }

    /// Toggle the heartbeat-driven outbound Ping fan-out. Default is on.
    pub fn set_auto_ping(&mut self, enabled: bool) {
        self.auto_ping = enabled;
    }

    pub fn peer_manager(&self) -> &PeerManager {
        &self.peer_manager
    }

    fn handle_latest_status(&mut self, latest_status_event: Option<([u8; 92], u64, u64)>) -> bool {
        if let Some((ssz, latest_block_slot, wall_slot)) = latest_status_event {
            tracing::debug!(wall_slot, latest_block_slot, "new status set");
            // PM still tracks our Status (peer-Status validation) + applied head
            // (custody-peer eligibility); the wall slot is the engine's only.
            let fork_digest_changed = self.peer_manager.set_status(ssz);
            self.gossip_handler.set_fork_digest(&ssz);
            self.peer_manager.set_local_head_imported(latest_block_slot);
            self.sync_engine.on_local_status(
                latest_block_slot,
                StatusView::finalized_epoch(&ssz),
                *StatusView::finalized_root(&ssz),
                wall_slot,
            );

            return fork_digest_changed;
        }

        false
    }

    fn msg_served_for(rpc: &RpcInbound) -> Option<u64> {
        let RpcInbound::Response(RpcResponseInbound { application_id, response, .. }) = rpc else {
            return None;
        };
        match response {
            RpcResponse::StatusV1(_) |
            RpcResponse::StatusV2(_) |
            RpcResponse::Ping(_) |
            RpcResponse::MetaData(_) |
            RpcResponse::Error { .. } |
            RpcResponse::Complete => None,
            RpcResponse::BeaconBlock { .. } |
            RpcResponse::DataColumnSidecar { .. } |
            RpcResponse::ExecutionPayloadEnvelope { .. } => Some(*application_id),
        }
    }
}

impl Tile<SilverSpine> for Controller {
    fn loop_body(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        let now = Instant::now();
        self.rpc_ssz_consumer.free();

        // Local status must land before the sync drive below: issuance is
        // capped against the imported head, and a one-loop-stale watermark
        // stalls lock-step tests (and costs a loop of latency live).
        let mut latest_status_event = None;
        adapter.consume(|beacon_event: BeaconStateEvent, _producers| {
            self.sync_engine.on_beacon_state_event(&beacon_event);

            match beacon_event {
                BeaconStateEvent::Status { ssz, latest_block_slot, wall_slot, .. } => {
                    latest_status_event = Some((ssz, latest_block_slot, wall_slot));
                }
                // PM keeps the reject for peer eviction (Status backing a
                // rejected chain); the engine owns target invalidation.
                BeaconStateEvent::BlockRejected { block_root, source } => {
                    self.peer_manager.record_block_rejected(block_root, source)
                }
                _ => {}
            }
        });

        adapter.consume(|need: SyncNeed, _producers| self.sync_engine.on_sync_need(need, now));

        let fork_digest_changed = self.handle_latest_status(latest_status_event);
        if fork_digest_changed {
            tracing::info!("fork digest changed; re-announcing gossip subscriptions");
            self.peer_manager.fan_out_subscriptions(&mut |evt| {
                handle_peer_control(
                    &mut self.gossip_handler,
                    &mut self.rpc_producer,
                    evt,
                    &mut adapter.producers,
                )
            });
        }

        adapter.consume(|event: PeerEvent, producers| {
            if let PeerEvent::PublishDataColumn { originator, topic, ssz } = event {
                let read = self.rpc_ssz_consumer.acquire(ssz);
                match read.buffer() {
                    Ok((bytes, _)) => {
                        if let Some((msg_hash, protobuf)) =
                            self.gossip_handler.publish(topic, bytes)
                        {
                            self.peer_manager.handle_event(
                                PeerEvent::SendGossip {
                                    originator_stream_id: originator,
                                    topic,
                                    msg_hash,
                                    recv_ts: Nanos::now(),
                                    protobuf,
                                },
                                now,
                                &mut |evt| {
                                    handle_peer_control(
                                        &mut self.gossip_handler,
                                        &mut self.rpc_producer,
                                        evt,
                                        producers,
                                    )
                                },
                            );
                        }
                    }
                    Err(e) => tracing::warn!(?e, ?topic, "publish column ssz read failed"),
                }
                return;
            }

            self.sync_engine.on_peer_event(event, self.peer_manager.our_fork_digest());

            if let PeerEvent::SendGossip {
                originator_stream_id: _,
                topic,
                msg_hash,
                recv_ts: _,
                protobuf,
            } = &event
            {
                self.gossip_handler.mcache_insert(*msg_hash, *topic, *protobuf);
            }

            self.peer_manager.handle_event(event, now, &mut |evt| {
                handle_peer_control(
                    &mut self.gossip_handler,
                    &mut self.rpc_producer,
                    evt,
                    producers,
                )
            });
        });

        adapter.consume(|rpc: RpcInbound, producers| {
            self.sync_engine.rpc_event(&rpc, self.peer_manager.our_fork_digest());
            if let Some(request_id) = Self::msg_served_for(&rpc) {
                self.sync_engine.on_msg_served(request_id);
            }
            self.peer_manager.on_rpc_inbound(rpc, now, &mut |evt| {
                handle_peer_control(
                    &mut self.gossip_handler,
                    &mut self.rpc_producer,
                    evt,
                    producers,
                )
            });
        });

        // Target selection: the engine is authoritative. Produce its target
        // onto the `sync_target` queue, and feed it to PM for peer-pick + column
        // gating (PM keeps `current_target` in step; runs its column reset).
        if let Some(target) = self.sync_engine.advance() {
            adapter.produce(target);
        }
        if let Some(target) = self.sync_engine.current_target() {
            self.peer_manager.set_sync_target(target);
        }
        if let Some(strategy) = self.sync_engine.maybe_choose_syncing_strategy(now) {
            adapter.produce(strategy);
        }

        if !self.pending_subnet_topics.is_empty() &&
            matches!(self.sync_engine.current_target(), Some(SyncUpdate::Following))
        {
            let topics = std::mem::take(&mut self.pending_subnet_topics);
            tracing::info!(?topics, "activating long-lived subnet subscriptions");
            self.peer_manager.activate_topics(&topics, &mut |evt| {
                handle_peer_control(
                    &mut self.gossip_handler,
                    &mut self.rpc_producer,
                    evt,
                    &mut adapter.producers,
                )
            });
        }

        // Syncing → Following edge: fan out Status to every peer
        // so they reciprocate with their fresh head — primes the head-sync
        // set — and announce our topic subscriptions so peers connected
        // while syncing start gossiping to us. Subsequent Status fan-outs
        // run on the periodic 300s heartbeat.
        if self.sync_engine.take_just_synced() {
            self.last_status = now;
            self.peer_manager.fan_out_status(now, &mut |evt| {
                handle_peer_control(
                    &mut self.gossip_handler,
                    &mut self.rpc_producer,
                    evt,
                    &mut adapter.producers,
                )
            });
            self.peer_manager.fan_out_subscriptions(&mut |evt| {
                handle_peer_control(
                    &mut self.gossip_handler,
                    &mut self.rpc_producer,
                    evt,
                    &mut adapter.producers,
                )
            });
        }

        let sync_engine = &mut self.sync_engine;
        for (request_id, peer, delivered) in self.peer_manager.drain_finished_requests() {
            sync_engine.on_terminator(request_id, peer, delivered, now);
        }

        // Sync issuance: the engine (Syncing or Following) decides the ranges +
        // owns completion. Forward requests are PM-picked (peer matched to the
        // target); backfill requests (BACKFILL/COLUMN_BACKFILL prefix) route via
        // PM's history-/custody-aware path, peer-agnostic.
        let peer_manager = &mut self.peer_manager;
        let gossip_handler = &mut self.gossip_handler;
        let rpc_producer = &mut self.rpc_producer;
        self.sync_engine.drive_requests(now, &mut |action| {
            handle_sync_action(peer_manager, action, now, &mut |pc| {
                handle_peer_control(gossip_handler, rpc_producer, pc, &mut adapter.producers)
            })
        });

        if self.last_tick.elapsed() > Duration::from_millis(700) {
            self.last_tick = now;
            // Before tick: redials shrink the peer deficit so tick's
            // discovery request only backfills what the database can't.
            self.peer_manager.redial_known_peers(now, &mut |evt| {
                handle_peer_control(
                    &mut self.gossip_handler,
                    &mut self.rpc_producer,
                    evt,
                    &mut adapter.producers,
                )
            });
            self.peer_manager.tick(now, &mut |evt| {
                handle_peer_control(
                    &mut self.gossip_handler,
                    &mut self.rpc_producer,
                    evt,
                    &mut adapter.producers,
                )
            });

            self.peer_manager.peer_scores(&mut |scores| {
                adapter.produce(PeerStats::Scores(scores));
            });
            self.peer_manager.peer_topic_scores(now, &mut |topic_scores| {
                adapter.produce(PeerStats::Topic(topic_scores));
            });

            if self.auto_ping && self.last_ping.elapsed() > Duration::from_secs(17) {
                self.last_ping = now;
                self.peer_manager.fan_out_ping(now, &mut |evt| {
                    handle_peer_control(
                        &mut self.gossip_handler,
                        &mut self.rpc_producer,
                        evt,
                        &mut adapter.producers,
                    )
                });
            }
        }

        if self.last_peer_persist.elapsed() > PEER_PERSIST_INTERVAL {
            self.last_peer_persist = now;
            for peer in self.peer_manager.live_peers_with_status() {
                if let Some(enr) = peer.enr.as_ref() {
                    handle_peer_control(
                        &mut self.gossip_handler,
                        &mut self.rpc_producer,
                        PeerControl::PersistPeer { enr: *enr },
                        &mut adapter.producers,
                    );
                }
            }
        }

        // Off-schedule Status fan-out on a silent fall-behind. Tight 1 s
        // backoff: if we suddenly look behind wall_slot, peers either know
        // a newer head or we need to learn we're stranded — either way,
        // refresh sooner rather than waiting on the 5 min keepalive.
        let fell_behind =
            self.sync_engine.fell_behind() && self.last_status.elapsed() > Duration::from_secs(1);
        if fell_behind || self.last_status.elapsed() > Duration::from_secs(30) {
            self.last_status = now;
            self.peer_manager.fan_out_status(now, &mut |evt| {
                handle_peer_control(
                    &mut self.gossip_handler,
                    &mut self.rpc_producer,
                    evt,
                    &mut adapter.producers,
                )
            });
        }

        if self.gossip_handler.spin(adapter) {
            adapter.mark_work();
        }
        while let Some(event) = self.gossip_handler.pop_event() {
            match event {
                GossipHandlerEvent::PeerEvent(peer_event) => {
                    self.sync_engine.on_peer_event(peer_event, self.peer_manager.our_fork_digest());
                    self.peer_manager.handle_event(peer_event, now, &mut |evt| {
                        handle_peer_control(
                            &mut self.gossip_handler,
                            &mut self.rpc_producer,
                            evt,
                            &mut adapter.producers,
                        )
                    });
                }
                GossipHandlerEvent::NewGossip(new_gossip_msg) => adapter.produce(new_gossip_msg),
                GossipHandlerEvent::SendGossip(gossip_msg_out) => {
                    adapter.produce(P2pSend::Gossip(gossip_msg_out))
                }
            }
        }
    }
}

fn handle_peer_control(
    gossip_handler: &mut GossipHandler,
    rpc_producer: &mut TMultiProducer,
    pc: PeerControl,
    producers: &mut SilverSpineProducers,
) {
    gossip_handler.handle_peer_control(pc);

    match pc {
        PeerControl::P2pSend(send) => {
            producers.p2p_send.produce(&send.into());
        }
        PeerControl::P2pBlockByRootRequest { app_id, peer, block_root } => {
            match RpcRequest::by_root(rpc_producer, &block_root) {
                Ok(read) => {
                    producers.p2p_send.produce(
                        &P2pSend::Rpc(RpcOutbound::Request(RpcRequestOutbound {
                            application_id: app_id,
                            peer,
                            request: RpcRequest::BlockByRoot(read),
                        }))
                        .into(),
                    );
                }
                Err(e) => {
                    tracing::error!(?e, "failed to allocate blocks by root request");
                }
            }
        }
        PeerControl::P2pDataColumnsRequest { app_id, peer, block_root, columns } => {
            tracing::debug!(peer, columns, "emit data columns P2pSend");
            match RpcRequest::data_columns_by_root(rpc_producer, &block_root, columns) {
                Ok(tcache) => {
                    producers.p2p_send.produce(
                        &P2pSend::Rpc(RpcOutbound::Request(RpcRequestOutbound {
                            application_id: app_id,
                            peer,
                            request: RpcRequest::DataColumnsByRoot(tcache),
                        }))
                        .into(),
                    );
                }
                Err(e) => {
                    tracing::error!(?e, "failed to allocate data columns request");
                }
            };
        }
        PeerControl::P2pEnvelopeByRootRequest { app_id, peer, block_root } => {
            match RpcRequest::by_root(rpc_producer, &block_root) {
                Ok(read) => {
                    producers.p2p_send.produce(
                        &P2pSend::Rpc(RpcOutbound::Request(RpcRequestOutbound {
                            application_id: app_id,
                            peer,
                            request: RpcRequest::ExecutionPayloadEnvelopesByRoot(read),
                        }))
                        .into(),
                    );
                }
                Err(e) => {
                    tracing::error!(?e, "failed to allocate envelopes by root request");
                }
            }
        }
        other => {
            producers.peer_control.produce(&other.into());
        }
    }
}

fn handle_sync_action(
    peer_manager: &mut PeerManager,
    action: SyncAction,
    now: Instant,
    emit: &mut impl FnMut(PeerControl),
) -> bool {
    match action {
        SyncAction::Request { request_id, request } => {
            peer_manager.place(request, request_id, now, emit)
        }
        SyncAction::DiscoverPeers => {
            emit(PeerControl::DiscoverNodes);
            true
        }
    }
}
