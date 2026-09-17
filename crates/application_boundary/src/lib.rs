use std::time::Duration;

use flux::{spine::SpineAdapter, tile::Tile};
use silver_beacon_api::BeaconApi;
use silver_beacon_state_data::{B256, BeaconStateReader, SpecConfig};
use silver_common::{
    BeaconApiResponse, BeaconStateEvent, DataColumnsEvent, EngineResp, Enr, Identify, Keypair,
    PeerEvent, SilverSpine, SyncUpdate, TProducer, TRandomAccess,
};
use silver_config::EngineConfig;
use silver_engine_api::EngineApi;
use silver_httpcore::{Bind, Readiness, TokenRange};

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
        self.consume_spine_events(adapter);
        let events = self.readiness.events();
        if self.beacon.pump(events, &mut |request| adapter.produce(request)) {
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
        anchor_root: B256,
        engine_config: EngineConfig,
        gossip_consumer: TRandomAccess,
        rpc_consumer: TRandomAccess,
        resp_producer: TProducer,
        relayed_gossip: TRandomAccess,
        outgoing_rpc: TRandomAccess,
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
            anchor_root,
            relayed_gossip,
            outgoing_rpc,
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

    fn consume_spine_events(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        let Self { beacon, engine, .. } = self;

        adapter.consume(|event: BeaconStateEvent, _| beacon.handle_beacon_state_event(event));
        adapter.consume(|response: EngineResp, _| beacon.handle_engine_resp(response));
        adapter.consume(|event: PeerEvent, _| beacon.handle_peer_event(event));
        adapter.consume(|event: DataColumnsEvent, _| beacon.handle_data_columns_event(event));
        adapter.consume(|update: SyncUpdate, _| beacon.handle_sync_update(update));
        adapter.consume(|response: BeaconApiResponse, _| beacon.handle_response(response));

        beacon.set_el_sync_status(engine.sync_status());
    }
}
