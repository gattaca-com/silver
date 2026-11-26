#[cfg(feature = "metrics")]
mod metrics;

use std::time::Duration;
#[cfg(feature = "metrics")]
use std::{io, net::SocketAddr, path::PathBuf};

use flux::{
    spine::{SpineAdapter, SpineProducers},
    tile::Tile,
};
use silver_beacon_api::BeaconApi;
use silver_beacon_state_data::{BeaconStateReader, SpecConfig};
use silver_common::{
    BeaconApiResponse, BeaconStateEvent, BuilderBidsRequest, BuilderBidsResponse, ClientVersion,
    DataColumnsEvent, EngineResp, Enr, Identify, Keypair, PeerEvent, SidecarBidRequest,
    SidecarBidResponse, SilverSpine, SyncUpdate, TCacheError, TCacheProducer, TCacheTable,
    TProducer,
};
use silver_config::{EngineConfig, PbsConfig};
use silver_engine_api::EngineApi;
use silver_httpcore::{Bind, Readiness, TokenRange};
use silver_pbs::{BuilderBids, BuilderEvent, PbsClient, SidecarEvent};

/// A tenant added here takes the next share of a raised `TENANTS`, which keeps
/// every share disjoint without a base to compute.
const TENANTS: usize = 6 + cfg!(feature = "metrics") as usize;
const BEACON_TOKENS: TokenRange = TokenRange::share(0, TENANTS);
const ENGINE_TOKENS: TokenRange = TokenRange::share(1, TENANTS);
const PBS_TOKENS: TokenRange = TokenRange::share(2, TENANTS);
const PBS_HEADER_TOKENS: TokenRange = TokenRange::share(3, TENANTS);
const PBS_SUBMISSION_TOKENS: TokenRange = TokenRange::share(4, TENANTS);
const BUILDER_TOKENS: TokenRange = TokenRange::share(5, TENANTS);
/// Above every share, so no tenant dispatches it.
#[cfg(feature = "thread_park")]
const WAKER_TOKEN: mio::Token = mio::Token(usize::MAX);

/// Bounds the sleep of an idle loop, so request and connection deadlines
/// still fire with no socket or spine activity.
#[cfg(feature = "thread_park")]
const IDLE_WAIT: Duration = Duration::from_millis(10);
#[cfg(not(feature = "thread_park"))]
const IDLE_WAIT: Duration = Duration::ZERO;

pub struct ApplicationBoundaryTile {
    readiness: Readiness,
    #[cfg(feature = "metrics")]
    metrics: Option<metrics::MetricsEndpoint>,
    pub beacon: BeaconApi,
    engine: EngineApi,
    pbs: Option<PbsClient>,
    builder_bids: BuilderBids,
    /// The tile's one producer, shared by engine responses and the messages
    /// the beacon api publishes.
    processing: TProducer,
    worked: bool,
}

impl Tile<SilverSpine> for ApplicationBoundaryTile {
    fn on_attach(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        adapter.subscribe_broadcast::<PeerEvent>();
        adapter.subscribe_broadcast::<BeaconStateEvent>();
        adapter.subscribe_broadcast::<SyncUpdate>();
    }

    fn try_init(&mut self, adapter: &mut SpineAdapter<SilverSpine>) -> bool {
        self.open_tcaches().expect("tcache wiring");
        // Without a waker the tile parks on the spine signal alone, and its
        // sockets cannot end the park.
        #[cfg(feature = "thread_park")]
        {
            let waker =
                mio::Waker::new(self.readiness.registry(), WAKER_TOKEN).expect("boundary waker");
            adapter.register_waker(waker);
        }
        #[cfg(not(feature = "thread_park"))]
        let _ = adapter;
        true
    }

    fn loop_body(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        self.processing.loop_start();
        self.engine.intake(adapter, &mut self.processing);
        self.readiness.wait(if self.worked { Duration::ZERO } else { IDLE_WAIT });

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

        let Self { readiness, beacon, builder_bids, processing, .. } = self;
        builder_bids.spin(readiness.events(), &mut |event| match event {
            BuilderEvent::Bids { request_id, bids } => {
                let bids = (!bids.is_empty())
                    .then(|| processing.write_with(bids.len(), |out| out.copy_from_slice(bids)))
                    .flatten();
                adapter.produce(BuilderBidsResponse { request_id, bids });
            }
            BuilderEvent::Preferences { request_id, failures } => {
                beacon.handle_builder_preferences_response(request_id, failures, processing)
            }
        });

        self.consume_spine_events(adapter);

        let Self { readiness, beacon, pbs, builder_bids, processing, .. } = self;
        let did_work = beacon.pump(
            readiness.events(),
            processing,
            &mut |request| adapter.produce(request),
            &mut |request_id, call_path, body| {
                pbs.as_mut()
                    .expect("a sidecar request needs a pbs.endpoint")
                    .send(request_id, call_path, body)
            },
            &mut |request_id, body| builder_bids.submit_preferences(request_id, body),
        );
        #[cfg(feature = "metrics")]
        let did_work = self.metrics.as_mut().is_some_and(|m| m.pump(readiness)) || did_work;
        if did_work {
            adapter.mark_work();
        }
        self.worked = adapter.did_work();
    }
}

impl ApplicationBoundaryTile {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        binds: &[Bind],
        allowed_hosts: &[String],
        max_connections: usize,
        idle_timeout: Duration,
        keypair: &Keypair,
        local_enr: Enr,
        identify: &Identify,
        spec: &SpecConfig,
        state: BeaconStateReader,
        engine_config: EngineConfig,
        pbs: Option<&PbsConfig>,
        builder_bid_timeout: Duration,
        tcaches: TCacheTable,
        processing: TProducer,
        version: ClientVersion,
    ) -> Self {
        // A batch too small for every socket the tile can register leaves the
        // rest of a busy iteration's readiness for the next one.
        let sockets = binds.len() +
            max_connections +
            EngineApi::max_sockets(engine_config.max_connections) +
            PbsClient::MAX_SOCKETS +
            BuilderBids::MAX_SOCKETS;
        #[cfg(feature = "metrics")]
        let sockets = sockets + metrics::SOCKETS;

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
        let custody_columns =
            local_enr.cgc().map(|count| local_enr.node_id().custody_groups(count as u8));
        let beacon = BeaconApi::new(
            readiness.registry(),
            BEACON_TOKENS,
            binds,
            allowed_hosts,
            max_connections,
            idle_timeout,
            keypair,
            local_enr,
            identify,
            spec,
            state,
            has_sidecar,
            tcaches,
            version,
        );
        let engine = EngineApi::new(
            readiness.registry(),
            ENGINE_TOKENS,
            engine_config,
            tcaches,
            custody_columns,
            version,
        );
        let builder_bids =
            BuilderBids::new(readiness.registry(), BUILDER_TOKENS, builder_bid_timeout);
        Self {
            #[cfg(feature = "metrics")]
            metrics: None,
            readiness,
            beacon,
            engine,
            pbs,
            builder_bids,
            processing,
            worked: false,
        }
    }

    #[cfg(feature = "metrics")]
    pub fn listen_metrics(&mut self, bind: SocketAddr, sources: PathBuf) -> io::Result<SocketAddr> {
        let endpoint = metrics::MetricsEndpoint::bind(bind, sources, self.readiness.registry())
            .map_err(|e| io::Error::new(e.kind(), format!("metrics listener {bind}: {e}")))?;
        let addr = endpoint.local_addr()?;
        self.metrics = Some(endpoint);
        Ok(addr)
    }

    pub fn open_tcaches(&mut self) -> Result<(), TCacheError> {
        self.beacon.open_tcaches()?;
        self.engine.open_tcaches()
    }

    fn consume_spine_events(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        let Self {
            beacon,
            engine,
            pbs,
            builder_bids,
            processing,
            #[cfg(feature = "metrics")]
            metrics,
            ..
        } = self;

        adapter.consume(|event: BeaconStateEvent, _| {
            #[cfg(feature = "metrics")]
            if let (BeaconStateEvent::Status { ssz, wall_slot, .. }, Some(metrics)) =
                (&event, metrics.as_mut())
            {
                metrics.on_status(ssz, *wall_slot);
            }
            if let BeaconStateEvent::CustodyChange { columns, .. } = event {
                engine.grow_custody(columns);
            }
            beacon.handle_beacon_state_event(event)
        });
        adapter.consume(|request: SidecarBidRequest, producers| {
            if !pbs.as_mut().is_some_and(|pbs| pbs.request_bid(&request)) {
                let SidecarBidRequest { slot, parent_hash, .. } = request;
                producers.produce(SidecarBidResponse { slot, parent_hash, signed_bid: None });
            }
        });
        adapter.consume(|request: BuilderBidsRequest, producers| {
            match beacon.builder_config(request.request_id) {
                Some(config) => builder_bids.request(&request, config),
                None => {
                    let request_id = request.request_id;
                    producers.produce(BuilderBidsResponse { request_id, bids: None });
                }
            }
        });
        adapter.consume(|response: EngineResp, _| beacon.handle_engine_resp(response));
        adapter.consume(|event: PeerEvent, _| beacon.handle_peer_event(event));
        adapter.consume(|event: DataColumnsEvent, _| beacon.handle_data_columns_event(event));
        adapter.consume(|update: SyncUpdate, _| beacon.handle_sync_update(update));
        adapter.consume(|response: BeaconApiResponse, _| {
            beacon.handle_response(
                response,
                processing,
                &mut |request_id, call_path, body| {
                    pbs.as_mut()
                        .expect("a sidecar request needs a pbs.endpoint")
                        .send(request_id, call_path, body)
                },
                &mut |url, signed_block| builder_bids.submit_block(url, signed_block),
            )
        });

        beacon.set_el_sync_status(engine.sync_status());
        beacon.set_el_version(engine.el_version());
    }
}
