use std::{
    io::{self, ErrorKind, Write},
    sync::Arc,
    time::{Duration, Instant},
};

use flux::{spine::SpineAdapter, tile::Tile};
use silver_chain_spec::SpecConfig;
use silver_common::{
    BeaconStateEvent, Nanos, P2pSend, PeerControl, PeerEvent, RpcInbound, RpcOutbound,
    RpcRequestOutbound, SilverSpine, SilverSpineProducers, TCacheProducer, TCacheRead,
    TMultiProducer, TRandomAccess, msg_is_backfill,
    ssz_view::{BLOCKS_BY_RANGE_REQ_SIZE, METADATA_SIZE, STATUS_V2_SIZE, StatusView},
};
use silver_gossip::{GossipHandler, GossipHandlerEvent};
use silver_peer::PeerManager;

use crate::sync_engine::{SyncAction, SyncEngine, SyncEvent};

const OUTBOUND_DRAIN_INTERVAL: Duration = Duration::from_secs(5);
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
    last_drain: Instant,
    last_peer_persist: Instant,

    /// When false, the 17000ms heartbeat skips the per-peer Ping fan-out.
    /// Tests use this to keep the peer-state machine ticking without
    /// generating background Ping traffic that would interfere with
    /// targeted RPC assertions.
    auto_ping: bool,
}

impl Controller {
    /// Build a Controller. `status` and `metadata` start empty — callers
    /// update them via `set_status` / `set_metadata` once chain state is
    /// available.
    pub fn new(
        peer_manager: PeerManager,
        gossip_handler: GossipHandler,
        rpc_producer: TMultiProducer,
        spec: Arc<SpecConfig>,
        rpc_ssz_consumer: TRandomAccess,
    ) -> Self {
        let sync_engine = SyncEngine::new(
            peer_manager.syncing_config(),
            peer_manager.awaiting_local_replay(),
            peer_manager.custody_columns(),
            spec,
        );
        Self {
            peer_manager,
            gossip_handler,
            sync_engine,
            rpc_producer,
            rpc_ssz_consumer,
            last_tick: Instant::now(),
            last_ping: Instant::now(),
            last_status: Instant::now(),
            last_drain: Instant::now(),
            last_peer_persist: Instant::now(),
            auto_ping: true,
        }
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

    fn handle_latest_status(
        &mut self,
        now: Instant,
        latest_status_event: Option<([u8; 92], u64, u64)>,
    ) -> bool {
        if let Some((ssz, latest_block_slot, wall_slot)) = latest_status_event {
            tracing::debug!(wall_slot, latest_block_slot, "new status set");
            // PM still tracks our Status (peer-Status validation) + applied head
            // (custody-peer eligibility); the wall slot is the engine's only.
            let fork_digest_changed = self.peer_manager.set_status(ssz);
            self.peer_manager.set_local_head_imported(latest_block_slot);
            self.sync_engine.on_event(
                SyncEvent::LocalStatus {
                    head_slot: latest_block_slot,
                    finalized_epoch: StatusView::finalized_epoch(&ssz),
                    finalized_root: *StatusView::finalized_root(&ssz),
                    wall_slot,
                },
                now,
            );

            return fork_digest_changed;
        }

        false
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
        adapter.consume(|beacon_event: BeaconStateEvent, _producers| match beacon_event {
            BeaconStateEvent::Status { ssz, latest_block_slot, wall_slot, .. } => {
                latest_status_event = Some((ssz, latest_block_slot, wall_slot));
                self.gossip_handler.set_fork_digest(&ssz);
            }
            BeaconStateEvent::BlockRejected { block_root, source } => {
                // PM keeps the reject for peer eviction (Status backing a
                // rejected chain); the engine owns target invalidation.
                self.peer_manager.record_block_rejected(block_root, source);
                self.sync_engine.on_event(SyncEvent::BlockRejected { block_root, source }, now);
            }
            BeaconStateEvent::ReplayComplete => {
                self.peer_manager.on_local_replay_complete();
                self.sync_engine.on_event(SyncEvent::ReplayComplete, now);
            }
            BeaconStateEvent::BacktrackStall => {
                // Relax the engine's (authoritative) target selection for one
                // pass so a slightly-ahead peer qualifies for range sync.
                self.sync_engine.request_resync();
            }
            _ => {}
        });

        let fork_digest_changed = self.handle_latest_status(now, latest_status_event);
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

            self.sync_engine.peer_event(event, now, self.peer_manager.our_fork_digest());

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
            self.sync_engine.rpc_event(now, &rpc, self.peer_manager.our_fork_digest());
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
        self.sync_engine.advance(now, &mut |action| {
            if let SyncAction::SetSyncTarget(target) = action {
                adapter.produce(target);
            }
        });
        self.peer_manager.set_sync_target(self.sync_engine.current_target());
        if let Some(strategy) = self.sync_engine.maybe_choose_syncing_strategy(now) {
            adapter.produce(strategy);
        }

        // Catchup → Following edge: fan out Status to every peer
        // so they reciprocate with their fresh head — primes the head-sync
        // set — and announce our topic subscriptions so peers connected
        // during catch-up start gossiping to us. Subsequent Status fan-outs
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

        // Sync issuance: the engine (Syncing or Following) decides the ranges +
        // owns completion. Forward requests are PM-picked (peer matched to the
        // target); backfill requests (BACKFILL/COLUMN_BACKFILL prefix) route via
        // PM's history-/custody-aware path, peer-agnostic.
        sync(now, &mut self.sync_engine, &mut self.peer_manager, adapter);

        if self.last_drain.elapsed() > OUTBOUND_DRAIN_INTERVAL {
            self.last_drain = now;
            self.peer_manager.drain_pending_outbound(now, &mut |evt| {
                handle_peer_control(
                    &mut self.gossip_handler,
                    &mut self.rpc_producer,
                    evt,
                    &mut adapter.producers,
                )
            });
        }

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

        if self.gossip_handler.spin() {
            adapter.mark_work();
        }
        while let Some(event) = self.gossip_handler.pop_event() {
            match event {
                GossipHandlerEvent::PeerEvent(peer_event) => {
                    self.sync_engine.peer_event(
                        peer_event,
                        now,
                        self.peer_manager.our_fork_digest(),
                    );
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
            match allocate_blocks_by_root(rpc_producer, &block_root) {
                Ok(read) => {
                    producers.p2p_send.produce(
                        &P2pSend::Rpc(RpcOutbound::Request(RpcRequestOutbound {
                            application_id: app_id,
                            peer,
                            request: silver_common::RpcRequest::BlockByRoot(read),
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
            match allocate_data_columns_by_root(rpc_producer, &block_root, columns) {
                Ok(tcache) => {
                    producers.p2p_send.produce(
                        &P2pSend::Rpc(RpcOutbound::Request(RpcRequestOutbound {
                            application_id: app_id,
                            peer,
                            request: silver_common::RpcRequest::DataColumnsByRoot(tcache),
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
            match allocate_blocks_by_root(rpc_producer, &block_root) {
                Ok(read) => {
                    producers.p2p_send.produce(
                        &P2pSend::Rpc(RpcOutbound::Request(RpcRequestOutbound {
                            application_id: app_id,
                            peer,
                            request: silver_common::RpcRequest::ExecutionPayloadEnvelopesByRoot(
                                read,
                            ),
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

fn produce_sync_control(adapter: &mut SpineAdapter<SilverSpine>, pc: PeerControl) {
    match pc {
        PeerControl::P2pSend(send) => {
            adapter.produce(send);
        }
        other => {
            adapter.produce(other);
        }
    }
}

fn sync(
    now: Instant,
    sync_engine: &mut SyncEngine,
    peer_manager: &mut PeerManager,
    adapter: &mut SpineAdapter<SilverSpine>,
) {
    let mut request_issued = None;
    let mut column_request_issued = None;
    let mut envelope_request_issued = None;
    sync_engine.drive_forward_sync(now, &mut |action| match action {
        SyncAction::RequestBlocksByRange { request_id, start, count, .. } => {
            if msg_is_backfill(request_id) {
                let mut ssz = [0u8; BLOCKS_BY_RANGE_REQ_SIZE];
                ssz[..8].copy_from_slice(&start.to_le_bytes());
                ssz[8..16].copy_from_slice(&count.to_le_bytes());
                ssz[16..].copy_from_slice(&1u64.to_le_bytes());
                peer_manager.on_rpc_request(
                    request_id,
                    silver_common::RpcRequest::BlocksByRange(ssz),
                    now,
                    &mut |pc| produce_sync_control(adapter, pc),
                );
            } else {
                let peer = peer_manager.issue_sync_blocks_by_range(
                    request_id,
                    start,
                    count,
                    now,
                    &mut |pc| produce_sync_control(adapter, pc),
                );
                request_issued = Some(move |sync_engine: &mut SyncEngine| {
                    sync_engine.on_request_issued(request_id, start, count, peer, now)
                });
            }
        }
        SyncAction::RequestEnvelopesByRange { request_id, start, count, .. } => {
            let peer = peer_manager.issue_sync_envelopes_by_range(
                request_id,
                start,
                count,
                now,
                &mut |pc| produce_sync_control(adapter, pc),
            );
            envelope_request_issued = Some(move |sync_engine: &mut SyncEngine| {
                sync_engine.on_range_request_issued(request_id, peer.map(|p| (p, 0)), now)
            });
        }
        SyncAction::RequestColumnsByRange {
            request_id,
            start,
            count,
            columns,
            tried_peers,
            ..
        } => {
            let peer = peer_manager.issue_sync_columns_by_range(
                request_id,
                start,
                count,
                columns,
                &tried_peers,
                now,
                &mut |pc| produce_sync_control(adapter, pc),
            );
            column_request_issued = Some(move |sync_engine: &mut SyncEngine| {
                sync_engine.on_range_request_issued(request_id, peer, now)
            });
        }
        SyncAction::RequestColumnsByRoot { request_id, block_root, columns, .. } => {
            peer_manager.on_request_data_columns_by_root(
                request_id,
                columns,
                block_root,
                now,
                &mut |pc| produce_sync_control(adapter, pc),
            );
        }
        SyncAction::ScorePeer { peer, severity } => {
            peer_manager.score_sync_peer(peer, severity);
        }
        _ => {}
    });

    if let Some(req_issued) = request_issued {
        req_issued(sync_engine);
    }
    if let Some(column_req_issued) = column_request_issued {
        column_req_issued(sync_engine);
    }
    if let Some(envelope_req_issued) = envelope_request_issued {
        envelope_req_issued(sync_engine);
    }
}

fn allocate_data_columns_by_root(
    producer: &mut TMultiProducer,
    root: &[u8; 32],
    columns: u128,
) -> Result<TCacheRead, io::Error> {
    // the data columns by root request is a list of `DataColumnsByRootIdentifier`.
    // Each of those is the block root followed by the list of column
    // indices. So the layout is: N x 4 byte offsets of list entries (little
    // endian) (so first offset / 4 is list length) Then N times:
    //   32 bytes block root
    //   4  bytes columns data offset (always = 36, little endian)
    //   8 bytes column index for each column, little endian
    let number_of_columns = columns.count_ones() as usize;
    let length = 4 + 32 + 4 + (8 * number_of_columns);
    let Some(mut reservation) = producer.reserve(length, true) else {
        tracing::warn!("Failed to allocate TCache buffer for data columns request");
        return Err(ErrorKind::StorageFull.into());
    };
    reservation.write_all(&4u32.to_le_bytes())?;
    reservation.write_all(root)?;
    reservation.write_all(&36u32.to_le_bytes())?;
    for i in 0..128 {
        if columns & (1 << i) != 0 {
            reservation.write_all(&(i as u64).to_le_bytes())?;
        }
    }
    reservation.flush()?;
    Ok(reservation.read())
}

fn allocate_blocks_by_root(
    producer: &mut TMultiProducer,
    root: &[u8; 32],
) -> Result<TCacheRead, io::Error> {
    let Some(mut reservation) = producer.reserve(32, true) else {
        tracing::warn!("Failed to allocate TCache buffer for blocks request");
        return Err(ErrorKind::StorageFull.into());
    };
    reservation.write_all(root)?;
    reservation.flush()?;
    Ok(reservation.read())
}
