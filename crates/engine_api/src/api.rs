use std::time::{Duration, Instant};

use flux::spine::SpineAdapter;
use mio::{Events, Registry};
use silver_common::{
    ELSyncStatus, EngineHealthEvent, EngineReq, SilverSpine, TProducer, TRandomAccess,
};
use silver_config::EngineConfig;
use silver_httpcore::TokenRange;

use crate::{
    EngineClient,
    client::{ReqKind, exchange_capabilities, get_client_version, get_sync_status},
    pool::HEALTHCHECK_OVERSHOOT,
    req_handlers::{handle_request, handle_request_no_el},
    resp_handlers::*,
};

const HEALTHCHECK_INTERVAL: Duration = Duration::from_secs(10);

pub struct EngineApi {
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

impl EngineApi {
    /// Sockets the pool can hold registered at once: one per pooled
    /// connection, plus the healthcheck's overshoot of the cap.
    pub const fn max_sockets(max_connections: usize) -> usize {
        max_connections + HEALTHCHECK_OVERSHOOT
    }

    pub fn new(
        registry: &Registry,
        tokens: TokenRange,
        config: EngineConfig,
        gossip_consumer: TRandomAccess,
        rpc_consumer: TRandomAccess,
        resp_producer: TProducer,
    ) -> Self {
        let client = if config.unsafe_no_el {
            tracing::warn!("engine api in UNSAFE no-EL testing mode: answering all requests VALID");
            None
        } else {
            Some(EngineClient::new(
                registry,
                tokens,
                &config.execution_endpoint,
                &config.jwt_secret,
                config.max_connections,
                Duration::from_secs(config.request_timeout_secs),
            ))
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

    /// Last status the EL reported to `eth_syncing`; `Unknown` until the
    /// first healthcheck completes.
    pub fn sync_status(&self) -> ELSyncStatus {
        self.sync_status
    }

    pub fn intake(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        self.rpc_consumer.free();
        self.gossip_consumer.free();

        if self.client.is_none() {
            // Unsafe no-EL testing mode: report healthy once so peers don't
            // gate on EL liveness, then answer every request with VALID.
            if self.first_run {
                adapter.produce(EngineHealthEvent { sync_status: ELSyncStatus::Synced });
                self.sync_status = ELSyncStatus::Synced;
                self.first_run = false;
            }
            let resp_producer = &mut self.resp_producer;
            adapter.consume(|req: EngineReq, producers| {
                handle_request_no_el(resp_producer, &req, producers)
            });
            return;
        }
        // Requests stay queued on the spine while every connection is busy and
        // the pool is at max_connections; intake resumes as completions free
        // connections.
        while self.client.as_ref().unwrap().has_capacity() {
            let consumed = adapter.consume_one(|req: EngineReq, producers| {
                handle_request(
                    self.client.as_mut().unwrap(),
                    &mut self.gossip_consumer,
                    &mut self.rpc_consumer,
                    &req,
                    producers,
                );
            });
            if !consumed {
                break;
            }
        }
    }

    pub fn spin(&mut self, adapter: &mut SpineAdapter<SilverSpine>, events: &Events) {
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
            let Some(client) = client.as_mut() else { return };

            if !*healthcheck_pending &&
                Instant::now() >= *healthcheck_deadline &&
                client.has_capacity()
            {
                run_healthcheck(client, first_run, healthcheck_pending, healthcheck_deadline);
            }

            let mut out = Responses::new(adapter, resp_producer, scratch);
            client.dispatch(events, |req_kind, response| match req_kind {
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
