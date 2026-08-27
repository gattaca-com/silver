use std::time::{Duration, Instant};

use flux::{spine::SpineAdapter, tile::Tile};
use silver_common::{
    ELSyncStatus, EngineHealthEvent, EngineReq, SilverSpine, TProducer, TRandomAccess,
};
use silver_config::EngineConfig;

use crate::{
    EngineClient,
    client::{ReqKind, exchange_capabilities, get_client_version, get_sync_status, poll},
    req_handlers::{handle_request, handle_request_no_el},
    resp_handlers::*,
};

const HEALTHCHECK_INTERVAL: Duration = Duration::from_secs(10);

pub struct EngineTile {
    /// `None` in unsafe no-EL testing mode — see
    /// [`EngineConfig::unsafe_no_el`].
    pub client: Option<EngineClient>,
    pub gossip_consumer: TRandomAccess,
    pub rpc_consumer: TRandomAccess,
    resp_producer: TProducer,
    // Reusable scratch buffer for the JSON→SSZ response conversions: cleared on
    // each use, capacity retained across calls.
    scratch: Vec<u8>,

    first_run: bool,
    healthcheck_pending: bool,
    healthcheck_deadline: Instant,
    sync_status: ELSyncStatus,
}

impl Tile<SilverSpine> for EngineTile {
    fn loop_body(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        self.rpc_consumer.free();
        self.gossip_consumer.free();

        if self.client.is_none() {
            // Unsafe no-EL testing mode: report healthy once so peers don't
            // gate on EL liveness, then answer every request with VALID.
            if self.first_run {
                adapter.produce(EngineHealthEvent { sync_status: ELSyncStatus::Synced });
                self.first_run = false;
            }
            let resp_producer = &mut self.resp_producer;
            adapter.consume(|req: EngineReq, producers| {
                handle_request_no_el(resp_producer, &req, producers)
            });
            return;
        }
        adapter.consume(|req: EngineReq, producers| {
            handle_request(
                self.client.as_mut().unwrap(),
                &mut self.gossip_consumer,
                &mut self.rpc_consumer,
                &req,
                producers,
            );
        });
        self.spin(adapter);
    }
}

impl EngineTile {
    pub fn new(
        config: EngineConfig,
        gossip_consumer: TRandomAccess,
        rpc_consumer: TRandomAccess,
        resp_producer: TProducer,
    ) -> Self {
        let client = if config.unsafe_no_el {
            tracing::warn!(
                "engine tile in UNSAFE no-EL testing mode: answering all requests VALID"
            );
            None
        } else {
            Some(EngineClient::new(&config.execution_endpoint, &config.jwt_secret))
        };
        Self {
            client,
            gossip_consumer,
            rpc_consumer,
            resp_producer,

            first_run: true,
            healthcheck_pending: false,
            healthcheck_deadline: Instant::now(),
            sync_status: ELSyncStatus::Unknown,
            scratch: Vec::new(),
        }
    }

    fn spin(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        let mut negotiated_get_payload_method: Option<&'static str> = None;

        {
            let Self {
                client,
                resp_producer,
                scratch,
                first_run,
                healthcheck_pending,
                healthcheck_deadline,
                sync_status,
                ..
            } = self;
            // Only reached in EL mode; loop_body returns early otherwise.
            let client = client.as_mut().expect("spin without EL client");

            if !*healthcheck_pending && Instant::now() >= *healthcheck_deadline {
                run_healthcheck(client, first_run, healthcheck_pending, healthcheck_deadline);
            }

            let mut out = Responses::new(adapter, resp_producer, scratch);
            poll(client, |req_kind, response| match req_kind {
                ReqKind::Capabilities => {
                    negotiated_get_payload_method = Some(handle_capabilities_response(response));
                }
                ReqKind::ClientVersion => handle_client_version_response(response),
                ReqKind::Syncing => out.syncing(response, sync_status, healthcheck_pending),
                ReqKind::Fcu(block_root) => out.fcu(block_root, response),
                ReqKind::NewPayload(block_root) => out.new_payload(block_root, response),
                ReqKind::GetPayloadFetch(spine_id) => out.get_payload(spine_id, response),
                ReqKind::GetBlobs { block_root, slot } => out.get_blobs(block_root, slot, response),
                ReqKind::GetPayloadBodiesByHash(spine_id) |
                ReqKind::GetPayloadBodiesByRange(spine_id) => {
                    out.payload_bodies(spine_id, response)
                }
            });
        }

        if let Some(method) = negotiated_get_payload_method {
            if let Some(client) = self.client.as_mut() {
                client.get_payload_method = method;
            }
        }
    }
}

fn run_healthcheck(
    client: &mut EngineClient,
    first_run: &mut bool,
    healthcheck_pending: &mut bool,
    healthcheck_deadline: &mut Instant,
) {
    if *first_run {
        exchange_capabilities(client);
        get_client_version(client);
        *first_run = false;
    }

    get_sync_status(client);
    *healthcheck_deadline = Instant::now() + HEALTHCHECK_INTERVAL;
    *healthcheck_pending = true;
}
