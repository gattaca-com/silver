use std::time::Duration;

use flux::{spine::SpineAdapter, tile::Tile};
use silver_beacon_api::{BeaconApi, SlotStatus};
use silver_beacon_state_data::{BeaconStateReader, SpecConfig};
use silver_common::{
    BeaconStateEvent, BlockStage, Enr, GossipTopic, Identify, Keypair, PeerEvent, SilverSpine,
    SyncUpdate, TProducer, TRandomAccess, TRead,
    column_util::{SidecarIdentity, block_root},
    ssz_view::{SignedBeaconBlockView, StatusView},
};
use silver_config::EngineConfig;
use silver_engine_api::EngineApi;
use silver_httpcore::{Bind, Readiness, TokenRange};

use crate::observed_head::{HeadChange, ObservedHead};

mod observed_head;

/// A tenant added here takes the next share of a raised `TENANTS`, which keeps
/// every share disjoint without a base to compute.
const TENANTS: usize = 2;
const BEACON_TOKENS: TokenRange = TokenRange::share(0, TENANTS);
const ENGINE_TOKENS: TokenRange = TokenRange::share(1, TENANTS);

pub struct ApplicationBoundaryTile {
    readiness: Readiness,
    pub beacon: BeaconApi,
    engine: EngineApi,
    head: ObservedHead,
    spec: SpecConfig,
    relayed_gossip: TRandomAccess,
    relayed_rpc: TRandomAccess,
}

impl Tile<SilverSpine> for ApplicationBoundaryTile {
    fn loop_body(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        self.engine.intake(adapter);
        self.readiness.wait(Duration::ZERO);
        self.engine.spin(adapter, self.readiness.events());
        self.consume_spine_events(adapter);
        if self.beacon.pump(self.readiness.events()) {
            adapter.mark_work();
        }
    }
}

impl ApplicationBoundaryTile {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        binds: &[Bind],
        max_connections: usize,
        idle_timeout: Duration,
        keypair: &Keypair,
        local_enr: Enr,
        identify: &Identify,
        spec: &SpecConfig,
        state: BeaconStateReader,
        engine_config: EngineConfig,
        gossip_consumer: TRandomAccess,
        rpc_consumer: TRandomAccess,
        resp_producer: TProducer,
        relayed_gossip: TRandomAccess,
        relayed_rpc: TRandomAccess,
    ) -> Self {
        // A batch too small for every socket the tile can register leaves the
        // rest of a busy iteration's readiness for the next one.
        let sockets =
            binds.len() + max_connections + EngineApi::max_sockets(engine_config.max_connections);

        let readiness = Readiness::new(sockets);
        let beacon = BeaconApi::new(
            readiness.registry(),
            BEACON_TOKENS,
            binds,
            max_connections,
            idle_timeout,
            keypair,
            local_enr,
            identify,
            spec,
            state,
        );
        let engine = EngineApi::new(
            readiness.registry(),
            ENGINE_TOKENS,
            engine_config,
            gossip_consumer,
            rpc_consumer,
            resp_producer,
        );
        Self {
            readiness,
            beacon,
            engine,
            head: ObservedHead::default(),
            spec: spec.clone(),
            relayed_gossip,
            relayed_rpc,
        }
    }

    fn consume_spine_events(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        let Self { beacon, head, spec, relayed_gossip, relayed_rpc, .. } = self;
        // Publish tails even without reads so idle consumers can release cache space.
        relayed_gossip.free();
        relayed_rpc.free();

        // A consumer's first consume starts at the producer's write head.
        // Keep both event queues active during engine saturation; delaying
        // their first consume would discard notifications already queued.
        adapter.consume(|event: BeaconStateEvent, _| match event {
            BeaconStateEvent::Status {
                ssz,
                latest_block_slot,
                wall_slot,
                head_optimistic,
                head_roots,
                head_payload,
                ..
            } => {
                beacon.node_status_mut().slots =
                    Some(SlotStatus { head_slot: latest_block_slot, wall_slot, head_optimistic });
                if let Some(HeadChange { event, legacy }) = head.observe(
                    StatusView::head_slot(&ssz),
                    *StatusView::head_root(&ssz),
                    head_optimistic,
                    head_payload,
                    head_roots,
                ) {
                    if legacy {
                        beacon.publish_head(&event);
                    }
                    beacon.publish_head_v2(&event);
                }
            }
            BeaconStateEvent::BlockReceived {
                slot,
                block_root,
                stage: BlockStage::Applied,
                ..
            } => beacon.publish_block(slot, &block_root),
            _ => {}
        });
        adapter.consume(|event: PeerEvent, _| match event {
            PeerEvent::SendGossip { topic: GossipTopic::BeaconBlock, ssz, .. } => {
                match relayed_gossip.acquire(ssz).buffer() {
                    Ok((block, _)) => {
                        let slot = SignedBeaconBlockView::slot(block);
                        let block_root = block_root(block, spec.is_gloas_at_slot(slot));
                        beacon.publish_block_gossip(slot, &block_root);
                    }
                    Err(e) => tracing::warn!(?e, "relayed block unavailable to block_gossip"),
                }
            }
            PeerEvent::SendGossip { topic: GossipTopic::DataColumnSidecar(_), ssz, .. } => {
                publish_data_column_sidecar(beacon, relayed_gossip.acquire(ssz))
            }
            PeerEvent::PublishDataColumn { ssz, .. } => {
                publish_data_column_sidecar(beacon, relayed_rpc.acquire(ssz))
            }
            _ => {}
        });
        let status = beacon.node_status_mut();
        adapter.consume(|update: SyncUpdate, _| {
            status.syncing = !matches!(update, SyncUpdate::Following);
        });

        status.el = self.engine.sync_status();
    }
}

fn publish_data_column_sidecar(beacon: &mut BeaconApi, sidecar: TRead) {
    match sidecar.buffer().map(|(bytes, _)| SidecarIdentity::of(bytes)) {
        Ok(Some(column)) => {
            beacon.publish_data_column_sidecar(&column.block_root, column.column_index, column.slot)
        }
        Ok(None) => tracing::warn!("published sidecar fits no layout data_column_sidecar reads"),
        Err(e) => tracing::warn!(?e, "published sidecar unavailable to data_column_sidecar"),
    }
}
