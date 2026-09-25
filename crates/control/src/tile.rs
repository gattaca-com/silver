use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use flux::{
    spine::{SpineAdapter, SpineProducers},
    tile::Tile,
};
use silver_chain_spec::SpecConfig;
use silver_common::{
    BeaconApiRequest, BeaconStateEvent, DataColumnsEvent, GossipDomain, GossipTopic,
    LocalGossipFailure, P2pSend, PeerControl, PeerEvent, PeerStats, RpcInbound, RpcOutbound,
    RpcRequest, RpcRequestOutbound, RpcResponse, RpcResponseInbound, SLOTS_PER_EPOCH, SilverSpine,
    SilverSpineProducers, SlotSubnets, SyncNeed, SyncUpdate, TCacheError, TCacheId, TCacheProducer,
    TCacheRead, TCacheReader, TCacheTable, TProducer, TReadMode, TileId,
    cell_store::{CellStoreConfig, CellStoreEvent, PartialColumnsMode, StoreError},
    ssz_view::{
        METADATA_SIZE, STATUS_V2_SIZE, SignedAggregateAndProofView, SignedSyncCommitteeProofView,
        StatusView, SyncCommitteeView,
    },
    ticker::SlotTicker,
};
use silver_gossip::{GossipHandler, GossipHandlerEvent};
use silver_peer::PeerManager;

use self::{
    attestation_cluster::{AttestationClusterHandler, PendingAttestation},
    attnet_duties::AttnetDuties,
    gossip_schedule::GossipSchedule,
    local_validation::{LocalMessage, LocalValidation, produce_response},
};
use crate::{
    cell_ingress::{CellIngress, handle_data_column_event},
    cluster::{AttestationClusterConfig, ClusterError},
    partial_exchange::PartialExchange,
    sync_engine::{SyncAction, SyncEngine},
};

mod attestation_cluster;
mod attnet_duties;
mod gossip_schedule;
mod local_validation;

const PEER_PERSIST_INTERVAL: Duration = Duration::from_secs(300);

#[cfg(test)]
mod tests;

pub struct Controller {
    peer_manager: PeerManager,
    gossip_handler: GossipHandler,
    /// Authoritative sync driver: owns target selection (produces the
    /// `sync_target`) and forward block issuance. PM serves its requests
    /// (peer-pick, caps, send) and owns column sync.
    sync_engine: SyncEngine,
    rpc_producer: TProducer,
    attestation_cluster: AttestationClusterHandler,
    local_validation: LocalValidation,
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
    attnet_duties: AttnetDuties,
    cell_ingress: Option<CellIngress>,
    partial_exchange: Option<PartialExchange>,
    /// Chain schedule, used to resolve the active gossip fork domain from
    /// the wall slot.
    spec: Arc<SpecConfig>,
    gossip_schedule: Option<GossipSchedule>,

    // Last: acquired reads above point into it.
    reader: TCacheReader,
}

impl Controller {
    /// Build a Controller. `status` and `metadata` start empty — callers
    /// update them via `set_status` / `set_metadata` once chain state is
    /// available.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        peer_manager: PeerManager,
        gossip_handler: GossipHandler,
        rpc_producer: TProducer,
        tcaches: TCacheTable,
        cluster_outbound_producer: TProducer,
        cluster_config: Option<AttestationClusterConfig>,
        sync_engine: SyncEngine,
        spec: Arc<SpecConfig>,
    ) -> Result<Self, ClusterError> {
        let now = Instant::now();
        let attestation_cluster =
            AttestationClusterHandler::new(cluster_outbound_producer, cluster_config, now)?;

        Ok(Self {
            peer_manager,
            gossip_handler,
            sync_engine,
            rpc_producer,
            attestation_cluster,
            local_validation: LocalValidation::default(),
            last_tick: now,
            last_ping: now,
            last_status: now,
            last_peer_persist: now,
            auto_ping: true,
            pending_subnet_topics: Vec::new(),
            attnet_duties: AttnetDuties::default(),
            cell_ingress: None,
            partial_exchange: None,
            spec,
            gossip_schedule: None,
            reader: TCacheReader::new(tcaches),
        })
    }

    fn on_local_gossip(
        &mut self,
        request_id: u64,
        topic: GossipTopic,
        ssz_read: TCacheRead,
        now: Instant,
        producers: &mut SilverSpineProducers,
    ) {
        let acquired = self.reader.acquire(ssz_read);
        let Ok((ssz, _)) = acquired.buffer() else {
            tracing::error!(request_id, ?topic, "submitted message overwritten before it was read");
            return produce_response(producers, request_id, Err(LocalGossipFailure::Internal));
        };
        match topic {
            GossipTopic::BeaconAttestation(subnet) => {
                let Ok(ssz) = ssz.try_into() else {
                    tracing::error!(
                        request_id,
                        len = ssz.len(),
                        "submitted attestation is misframed"
                    );
                    return produce_response(
                        producers,
                        request_id,
                        Err(LocalGossipFailure::Internal),
                    );
                };
                self.attestation_cluster.on_local_attestation(
                    PendingAttestation::new(request_id, subnet, ssz),
                    now,
                    &mut self.local_validation,
                    &mut self.gossip_handler,
                    producers,
                )
            }
            GossipTopic::SyncCommittee(_) => {
                let Ok(message) = ssz.try_into() else {
                    tracing::error!(
                        request_id,
                        len = ssz.len(),
                        "submitted sync committee message is misframed"
                    );
                    return produce_response(
                        producers,
                        request_id,
                        Err(LocalGossipFailure::Internal),
                    );
                };
                let slot = SyncCommitteeView::slot(message);
                self.local_validation.submit(
                    LocalMessage { request_id, topic, ssz, ssz_read: Some(ssz_read), slot },
                    now,
                    &mut self.gossip_handler,
                    producers,
                )
            }
            GossipTopic::BeaconAggregateAndProof => {
                let slot = SignedAggregateAndProofView::agg_slot(ssz);
                self.local_validation.submit(
                    LocalMessage { request_id, topic, ssz, ssz_read: Some(ssz_read), slot },
                    now,
                    &mut self.gossip_handler,
                    producers,
                )
            }
            GossipTopic::SyncCommitteeContributionAndProof => {
                let Ok(proof) = ssz.try_into() else {
                    tracing::error!(
                        request_id,
                        len = ssz.len(),
                        "submitted contribution is misframed"
                    );
                    return produce_response(
                        producers,
                        request_id,
                        Err(LocalGossipFailure::Internal),
                    );
                };
                let slot = SignedSyncCommitteeProofView::slot(proof);
                self.local_validation.submit(
                    LocalMessage { request_id, topic, ssz, ssz_read: Some(ssz_read), slot },
                    now,
                    &mut self.gossip_handler,
                    producers,
                )
            }
            topic => {
                tracing::error!(request_id, ?topic, "no local submission path for the topic");
                produce_response(producers, request_id, Err(LocalGossipFailure::Internal))
            }
        }
    }

    fn on_attestation_subscriptions(&mut self, subscriptions: TCacheRead, wall_slot: u64) {
        let acquired = self.reader.acquire(subscriptions);
        let Ok((bytes, _)) = acquired.buffer() else {
            tracing::error!("submitted subscriptions overwritten before they were read");
            return;
        };
        for slot_subnets in SlotSubnets::decode_all(bytes) {
            self.attnet_duties.add(slot_subnets, wall_slot);
        }
    }

    pub fn open_tcaches(&mut self) -> Result<(), TCacheError> {
        self.reader.open(
            TCacheId::NetworkProcessing,
            "ctl_network_processing",
            TReadMode::Sliding,
        )?;
        self.reader.open(TCacheId::ClusterInbound, "control_cluster_inbound", TReadMode::Strict)?;
        self.reader.open(
            TCacheId::BoundaryProcessing,
            "ctl_boundary_processing",
            TReadMode::Sliding,
        )?;
        self.reader.declare(TCacheId::NetworkProcessing, &[TileId::BeaconState, TileId::Columns]);
        self.gossip_handler.open_tcaches()
    }

    pub fn with_data_columns_cache(
        mut self,
        config: CellStoreConfig,
        producer: TProducer,
        slot: u64,
        slot_start: Instant,
        mode: PartialColumnsMode,
    ) -> Result<Self, StoreError> {
        self.partial_exchange =
            mode.supports_sending().then(|| PartialExchange::new(&config, slot, slot_start, mode));
        self.gossip_handler.set_partial_columns_mode(mode);
        self.cell_ingress = Some(CellIngress::new(config, producer, slot, slot_start)?);
        Ok(self)
    }

    pub fn set_pending_subnet_topics(&mut self, topics: Vec<GossipTopic>) {
        self.attnet_duties.set_long_lived(&topics);
        self.pending_subnet_topics = topics;
    }

    pub fn set_gossip_clock(&mut self, ticker: SlotTicker, genesis_validators_root: &[u8; 32]) {
        self.attnet_duties
            .set_rejoin_wait(self.peer_manager.topic_rejoin_wait(), ticker.slot_duration());
        self.gossip_schedule =
            Some(GossipSchedule::new(&self.spec, genesis_validators_root, ticker));
    }

    fn advance_gossip_domains(&mut self, producers: &mut SilverSpineProducers) {
        let Some(update) = self.gossip_schedule.as_mut().and_then(GossipSchedule::advance) else {
            return;
        };
        if self.gossip_handler.current_domain() != Some(update.current) {
            tracing::info!(domain = ?update.current, "fork digest changed; gossip subscriptions updated");
        }
        self.gossip_handler.set_domains(update.current, update.other);
        self.peer_manager.set_active_domains(
            update.current.digest(),
            update.other.map(|domain| domain.digest()),
            &mut |event| {
                handle_peer_control(
                    &mut self.gossip_handler,
                    &mut self.rpc_producer,
                    event,
                    producers,
                )
            },
        );
        producers.peer_control.produce(
            &PeerControl::UpdateEnrForkId { epoch: update.epoch, enr_fork_id: update.enr_fork_id }
                .into(),
        );
    }

    pub fn set_status(&mut self, mut status: [u8; STATUS_V2_SIZE]) {
        if let Some(schedule) = &self.gossip_schedule {
            status[..4].copy_from_slice(&schedule.current().digest());
        }
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
        latest_status_event: Option<([u8; 92], u64, u64)>,
        producers: &mut SilverSpineProducers,
    ) {
        if let Some((mut ssz, latest_block_slot, wall_slot)) = latest_status_event {
            if let Some(ingress) = &mut self.cell_ingress {
                ingress.set_min_slot(StatusView::finalized_epoch(&ssz) * SLOTS_PER_EPOCH);
            }
            tracing::debug!(wall_slot, latest_block_slot, "new status set");
            // PM still tracks our Status (peer-Status validation) + applied head
            // (custody-peer eligibility); the wall slot is the engine's only.
            if let Some(schedule) = &self.gossip_schedule {
                // Delayed status cannot roll back a wall-clock transition.
                ssz[..4].copy_from_slice(&schedule.current().digest());
            } else {
                // Clockless test harnesses drive the domain through status.
                let domain = GossipDomain::new(
                    *StatusView::fork_digest(&ssz),
                    self.spec.fork_at_slot(wall_slot),
                );
                if self.gossip_handler.current_domain() != Some(domain) {
                    tracing::info!(?domain, "fork digest changed; gossip subscriptions updated");
                }
                self.gossip_handler.set_domains(domain, None);
                self.peer_manager.set_active_domains(domain.digest(), None, &mut |event| {
                    handle_peer_control(
                        &mut self.gossip_handler,
                        &mut self.rpc_producer,
                        event,
                        producers,
                    );
                });
            }
            self.peer_manager.set_status(ssz);
            self.peer_manager.set_local_head_imported(latest_block_slot);
            self.sync_engine.on_local_status(
                latest_block_slot,
                StatusView::finalized_epoch(&ssz),
                *StatusView::finalized_root(&ssz),
                wall_slot,
            );
        }
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
        self.gossip_handler.loop_start();
        self.rpc_producer.loop_start();
        self.attestation_cluster.loop_start();
        if let Some(ingress) = &mut self.cell_ingress {
            ingress.loop_start();
        }
        let now = Instant::now();
        self.advance_gossip_domains(&mut adapter.producers);
        self.reader.free();
        if let Some(ingress) = &mut self.cell_ingress {
            ingress.spin(now, &adapter.producers);
            if let Some(exchange) = &mut self.partial_exchange {
                exchange.advance(
                    ingress,
                    &self.peer_manager,
                    &mut self.gossip_handler.mcache_publish,
                    now,
                    &mut |send| adapter.producers.produce(send),
                    &mut |need| adapter.producers.produce(need),
                );
            }
            adapter.consume(|event: CellStoreEvent, producers| {
                ingress.handle(event, now, producers);
                if let Some(exchange) = &mut self.partial_exchange {
                    match event {
                        CellStoreEvent::Allocate(request)
                            if request.context.slot == ingress.slot_window().0 =>
                        {
                            exchange.context(request, ingress.slot_window().1, now);
                        }
                        CellStoreEvent::Available(column) => {
                            if let Some(column) =
                                ingress.availability(&column.block_root, column.column, now)
                            {
                                exchange.available(column, &self.peer_manager, now, false);
                            }
                        }
                        CellStoreEvent::RejectedContext { block_root } => {
                            exchange.reject(&block_root)
                        }
                        _ => {}
                    }
                }
            });
        }

        // Local status must land before the sync drive below: issuance is
        // capped against the imported head, and a one-loop-stale watermark
        // stalls lock-step tests (and costs a loop of latency live).
        let mut latest_status_event = None;
        adapter.consume(|beacon_event: BeaconStateEvent, producers| {
            self.sync_engine.on_beacon_state_event(&beacon_event);

            match beacon_event {
                BeaconStateEvent::Status { ssz, latest_block_slot, wall_slot, .. } => {
                    self.attestation_cluster.on_status(StatusView::head_slot(&ssz), wall_slot);
                    latest_status_event = Some((ssz, latest_block_slot, wall_slot));
                }
                BeaconStateEvent::LocalGossipVerdict { hash, result } => {
                    self.local_validation.complete(hash, result, producers)
                }
                // PM keeps the reject for peer eviction (Status backing a
                // rejected chain); the engine owns target invalidation.
                BeaconStateEvent::BlockRejected { block_root, source } => {
                    self.peer_manager.record_block_rejected(block_root, source)
                }
                _ => {}
            }
        });

        let wall_slot =
            self.gossip_schedule.as_ref().map(|schedule| schedule.ticker.current_slot());
        adapter.consume(|request: BeaconApiRequest, producers| match request {
            BeaconApiRequest::LocalGossip { request_id, topic, ssz } => {
                self.on_local_gossip(request_id, topic, ssz, now, producers)
            }
            BeaconApiRequest::AttestationSubscriptions { subscriptions } => {
                if let Some(wall_slot) = wall_slot {
                    self.on_attestation_subscriptions(subscriptions, wall_slot);
                }
            }
            BeaconApiRequest::AggregateAttestation { .. } |
            BeaconApiRequest::SyncCommitteeContribution { .. } |
            BeaconApiRequest::Block { .. } => {}
        });

        self.attestation_cluster.spin(
            now,
            adapter,
            &mut self.local_validation,
            &mut self.gossip_handler,
            &mut self.reader,
        );

        adapter.consume(|need: SyncNeed, _producers| self.sync_engine.on_sync_need(need, now));

        self.handle_latest_status(latest_status_event, &mut adapter.producers);

        adapter.consume(|event: DataColumnsEvent, producers| {
            if let Some(exchange) = &mut self.partial_exchange {
                exchange.validated(event, now);
            }
            handle_data_column_event(
                event,
                &mut self.reader,
                self.cell_ingress.as_mut(),
                &mut self.gossip_handler,
                &mut self.peer_manager,
                &mut |evt, gossip_handler| {
                    handle_peer_control(gossip_handler, &mut self.rpc_producer, evt, producers)
                },
            );
        });

        adapter.consume(|event: PeerEvent, producers| {
            self.sync_engine.on_peer_event(event, self.peer_manager.our_fork_digest());

            if let PeerEvent::SendGossip { topic, domain, msg_hash, protobuf, .. } = &event {
                self.gossip_handler.mcache_insert(*msg_hash, *topic, *domain, *protobuf);
            }

            if let Some(exchange) = &mut self.partial_exchange {
                exchange.peer_event(&event, now);
            }
            let serving_column =
                self.cell_ingress.as_ref().and_then(|ingress| ingress.serving_column(&event, now));
            if let (
                Some(exchange),
                Some(column),
                PeerEvent::SendGossip { originator_stream_id, .. },
            ) = (&mut self.partial_exchange, serving_column, event)
            {
                exchange.validated_sender(originator_stream_id.peer(), column);
            }
            let partial_serving = serving_column.is_some();
            self.peer_manager.handle_event_with_partial(event, now, partial_serving, &mut |evt| {
                handle_peer_control(
                    &mut self.gossip_handler,
                    &mut self.rpc_producer,
                    evt,
                    producers,
                )
            });
        });

        // Consume every validation outcome already queued before expiring
        // requests, so an event arriving at the deadline wins the race.
        self.local_validation.expire(now, &mut adapter.producers);

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

        let following = matches!(self.sync_engine.current_target(), Some(SyncUpdate::Following));
        if !self.pending_subnet_topics.is_empty() && following {
            let topics = std::mem::take(&mut self.pending_subnet_topics);
            tracing::info!(?topics, "activating long-lived subnet subscriptions");
            self.peer_manager.activate_topics(topics.iter().copied(), &mut |evt| {
                handle_peer_control(
                    &mut self.gossip_handler,
                    &mut self.rpc_producer,
                    evt,
                    &mut adapter.producers,
                )
            });
        }
        if following &&
            let Some(wall_slot) = wall_slot &&
            let Some(changes) = self.attnet_duties.advance(wall_slot)
        {
            tracing::debug!(wall_slot, ?changes, "attestation duty subnets changed");
            self.peer_manager.set_duty_attnets(changes.attesting);
            let emit = &mut |evt| {
                handle_peer_control(
                    &mut self.gossip_handler,
                    &mut self.rpc_producer,
                    evt,
                    &mut adapter.producers,
                )
            };
            self.peer_manager.activate_topics(changes.joined(), emit);
            self.peer_manager.deactivate_topics(changes.left(), now, emit);
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

        if self.gossip_handler.spin_columns(adapter, self.cell_ingress.as_mut()) {
            adapter.mark_work();
        }
        while let Some(event) = self.gossip_handler.pop_event() {
            match event {
                GossipHandlerEvent::PartialMetadata(metadata) => {
                    if let (Some(exchange), Some(ingress)) =
                        (&mut self.partial_exchange, &self.cell_ingress)
                    {
                        exchange.metadata(metadata, ingress, &self.peer_manager, now);
                    }
                }
                GossipHandlerEvent::PeerEvent(peer_event) => {
                    self.sync_engine.on_peer_event(peer_event, self.peer_manager.our_fork_digest());
                    if let Some(exchange) = &mut self.partial_exchange {
                        exchange.peer_event(&peer_event, now);
                    }
                    let partial_serving = self
                        .cell_ingress
                        .as_ref()
                        .and_then(|ingress| ingress.serving_column(&peer_event, now))
                        .is_some();
                    self.peer_manager.handle_event_with_partial(
                        peer_event,
                        now,
                        partial_serving,
                        &mut |evt| {
                            handle_peer_control(
                                &mut self.gossip_handler,
                                &mut self.rpc_producer,
                                evt,
                                &mut adapter.producers,
                            )
                        },
                    );
                }
                GossipHandlerEvent::NewGossip(new_gossip_msg) => adapter.produce(new_gossip_msg),
                GossipHandlerEvent::SendGossip(gossip_msg_out) => {
                    adapter.produce(P2pSend::Gossip(gossip_msg_out))
                }
            }
        }
        if let (Some(exchange), Some(ingress)) = (&mut self.partial_exchange, &self.cell_ingress) {
            if exchange.spin(
                ingress,
                &self.peer_manager,
                &mut self.gossip_handler.mcache_publish,
                now,
                &mut |send| adapter.producers.produce(send),
                &mut |need| adapter.producers.produce(need),
            ) {
                adapter.mark_work();
            }
        }
    }

    fn try_init(&mut self, _adapter: &mut SpineAdapter<SilverSpine>) -> bool {
        self.open_tcaches().expect("tcache wiring");
        self.last_tick = Instant::now() + Duration::from_millis(700);
        true
    }
}

fn handle_peer_control(
    gossip_handler: &mut GossipHandler,
    rpc_producer: &mut TProducer,
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
