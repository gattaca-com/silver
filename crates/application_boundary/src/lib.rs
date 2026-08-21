use std::time::Duration;

use flux::{spine::SpineAdapter, tile::Tile};
use silver_beacon_api::{BeaconApi, PeerCounts, SlotStatus};
use silver_beacon_state_data::{BeaconStateReader, SpecConfig};
use silver_common::{
    BeaconStateEvent, Enr, Identify, Keypair, SilverSpine, SyncUpdate, TProducer, TRandomAccess,
};
use silver_config::EngineConfig;
use silver_engine_api::EngineApi;
use silver_httpcore::{Bind, Readiness, TokenRange};
use silver_peer::PeerCounters;

/// A tenant added here takes the next share of a raised `TENANTS`, which keeps
/// every share disjoint without a base to compute.
const TENANTS: usize = 2;
const BEACON_TOKENS: TokenRange = TokenRange::share(0, TENANTS);
const ENGINE_TOKENS: TokenRange = TokenRange::share(1, TENANTS);

pub struct ApplicationBoundaryTile {
    readiness: Readiness,
    pub beacon: BeaconApi,
    engine: EngineApi,
}

impl Tile<SilverSpine> for ApplicationBoundaryTile {
    fn loop_body(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        self.engine.intake(adapter);
        self.readiness.wait(Duration::ZERO);
        self.engine.spin(adapter, self.readiness.events());
        self.refresh_node_status(adapter);
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
        Self { readiness, beacon, engine }
    }

    fn refresh_node_status(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        let status = self.beacon.node_status_mut();

        // Consumed every iteration, and never behind the engine's capacity
        // gate: a consumer's first `consume` jumps its cursor to the
        // producer's write head, so a queue left unread while the pool is
        // saturated loses everything published in the meantime.
        adapter.consume(|event: BeaconStateEvent, _| {
            if let BeaconStateEvent::Status {
                latest_block_slot, wall_slot, head_optimistic, ..
            } = event
            {
                status.slots =
                    Some(SlotStatus { head_slot: latest_block_slot, wall_slot, head_optimistic });
            }
        });
        adapter.consume(|update: SyncUpdate, _| {
            status.syncing = !matches!(update, SyncUpdate::Following);
        });

        status.el = self.engine.sync_status();
        status.peers = PeerCounts {
            connected: PeerCounters::PeersConnected.get(),
            connecting: PeerCounters::PeersConnecting.get(),
        };
    }
}
