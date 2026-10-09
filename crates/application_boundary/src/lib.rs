use std::time::Duration;

use flux::{
    spine::{SpineAdapter, SpineProducers},
    tile::Tile,
};
use silver_beacon_api::BeaconApi;
use silver_beacon_state_data::{BeaconStateReader, SpecConfig};
use silver_common::{
    BeaconApiResponse, BeaconStateEvent, DataColumnsEvent, EngineResp, Enr, Identify, Keypair,
    PeerEvent, SidecarBidRequest, SidecarBidResponse, SilverSpine, SyncUpdate, TCacheError,
    TCacheProducer, TCacheTable, TProducer,
};
use silver_config::{EngineConfig, PbsConfig};
use silver_engine_api::EngineApi;
use silver_httpcore::{Bind, Readiness, TokenRange};
use silver_pbs::{PbsClient, SidecarEvent};

/// A tenant added here takes the next share of a raised `TENANTS`, which keeps
/// every share disjoint without a base to compute.
const TENANTS: usize = 5;
const BEACON_TOKENS: TokenRange = TokenRange::share(0, TENANTS);
const ENGINE_TOKENS: TokenRange = TokenRange::share(1, TENANTS);
const PBS_TOKENS: TokenRange = TokenRange::share(2, TENANTS);
const PBS_HEADER_TOKENS: TokenRange = TokenRange::share(3, TENANTS);
const PBS_SUBMISSION_TOKENS: TokenRange = TokenRange::share(4, TENANTS);

pub struct ApplicationBoundaryTile {
    readiness: Readiness,
    pub beacon: BeaconApi,
    engine: EngineApi,
    pbs: Option<PbsClient>,
    /// The tile's one producer, shared by engine responses and the messages
    /// the beacon api publishes.
    processing: TProducer,
}

impl Tile<SilverSpine> for ApplicationBoundaryTile {
    fn on_attach(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        adapter.subscribe_broadcast::<PeerEvent>();
        adapter.subscribe_broadcast::<BeaconStateEvent>();
        adapter.subscribe_broadcast::<SyncUpdate>();
    }

    fn try_init(&mut self, _adapter: &mut SpineAdapter<SilverSpine>) -> bool {
        self.open_tcaches().expect("tcache wiring");
        true
    }

    fn loop_body(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        self.processing.loop_start();
        self.engine.intake(adapter, &mut self.processing);
        self.readiness.wait(Duration::ZERO);

        self.engine.spin(adapter, self.readiness.events(), &mut self.processing);

        if let Some(pbs) = &mut self.pbs {
            let Self { readiness, beacon, processing, .. } = self;
            pbs.spin(readiness.events(), &mut |event| match event {
                SidecarEvent::Response { request_id, response: answer } => {
                    beacon.handle_sidecar_response(request_id, answer, processing)
                }
                SidecarEvent::Bid { slot, parent_hash, signed_bid } => {
                    let signed_bid = signed_bid.and_then(|signed_bid| {
                        let ssz = processing
                            .write_with(signed_bid.len(), |out| out.copy_from_slice(signed_bid));
                        if ssz.is_none() {
                            silver_log::error!(slot, "boundary tcache full; sidecar bid dropped");
                        }
                        ssz
                    });
                    adapter.produce(SidecarBidResponse { slot, parent_hash, signed_bid });
                }
            });
        }

        self.consume_spine_events(adapter);

        let Self { readiness, beacon, pbs, processing, .. } = self;
        let did_work = beacon.pump(
            readiness.events(),
            processing,
            &mut |request| adapter.produce(request),
            &mut |request_id, path, body| {
                pbs.as_mut()
                    .expect("a sidecar request needs a pbs.endpoint")
                    .send(request_id, path, body)
            },
        );
        if did_work {
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
        pbs: Option<&PbsConfig>,
        tcaches: TCacheTable,
        processing: TProducer,
    ) -> Self {
        // A batch too small for every socket the tile can register leaves the
        // rest of a busy iteration's readiness for the next one.
        let sockets = binds.len() +
            max_connections +
            EngineApi::max_sockets(engine_config.max_connections) +
            PbsClient::MAX_SOCKETS;

        let readiness = Readiness::new(sockets);
        let has_sidecar = pbs.is_some();
        let pbs = pbs.map(|pbs| {
            PbsClient::new(
                readiness.registry(),
                PBS_TOKENS,
                PBS_HEADER_TOKENS,
                PBS_SUBMISSION_TOKENS,
                pbs,
                spec,
                state.read(|view| view.imm.genesis_time).expect("the anchor state is published"),
            )
        });
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
            has_sidecar,
            tcaches,
        );
        let engine = EngineApi::new(readiness.registry(), ENGINE_TOKENS, engine_config, tcaches);
        Self { readiness, beacon, engine, pbs, processing }
    }

    pub fn open_tcaches(&mut self) -> Result<(), TCacheError> {
        self.beacon.open_tcaches()?;
        self.engine.open_tcaches()
    }

    fn consume_spine_events(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        let Self { beacon, engine, pbs, processing, .. } = self;

        adapter.consume(|event: BeaconStateEvent, _| beacon.handle_beacon_state_event(event));
        adapter.consume(|request: SidecarBidRequest, producers| {
            if !pbs.as_mut().is_some_and(|pbs| pbs.request_bid(&request)) {
                let SidecarBidRequest { slot, parent_hash, .. } = request;
                producers.produce(SidecarBidResponse { slot, parent_hash, signed_bid: None });
            }
        });
        adapter.consume(|response: EngineResp, _| beacon.handle_engine_resp(response));
        adapter.consume(|event: PeerEvent, _| beacon.handle_peer_event(event));
        adapter.consume(|event: DataColumnsEvent, _| beacon.handle_data_columns_event(event));
        adapter.consume(|update: SyncUpdate, _| beacon.handle_sync_update(update));
        adapter
            .consume(|response: BeaconApiResponse, _| beacon.handle_response(response, processing));

        beacon.set_el_sync_status(engine.sync_status());
    }
}
