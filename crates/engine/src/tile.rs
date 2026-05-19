use std::time::{Duration, Instant};

use flux::{spine::SpineAdapter, tile::Tile};
use silver_common::{ELSyncStatus, EngineReq, SilverSpine, TProducer, TRandomAccess};

use crate::{
    EngineClient,
    client::{
        ReqKind, exchange_capabilities, get_client_version, get_payload, get_sync_status, poll,
    },
    req_handlers::handle_request,
    resp_handlers::*,
};

const HEALTHCHECK_INTERVAL: Duration = Duration::from_secs(10);

pub struct EngineTile {
    pub client: EngineClient,
    pub req_consumer: TRandomAccess,
    pub resp_producer: TProducer,

    first_run: bool,
    healthcheck_pending: bool,
    healthcheck_deadline: Instant,
    sync_status: ELSyncStatus,
}

impl Tile<SilverSpine> for EngineTile {
    fn loop_body(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        adapter.consume(|req: EngineReq, producers| {
            handle_request(&mut self.client, &mut self.req_consumer, &req, producers);
        });
        self.spin(adapter);
    }
}

impl EngineTile {
    pub fn new(
        client: EngineClient,
        req_consumer: TRandomAccess,
        resp_producer: TProducer,
    ) -> Self {
        Self {
            client,
            req_consumer,
            resp_producer,

            first_run: true,
            healthcheck_pending: false,
            healthcheck_deadline: Instant::now(),
            sync_status: ELSyncStatus::Unknown,
        }
    }

    fn spin(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        let mut pending_get_payload: Option<([u8; 8], u64)> = None;

        {
            let Self {
                client,
                resp_producer,
                first_run,
                healthcheck_pending,
                healthcheck_deadline,
                sync_status,
                ..
            } = self;

            if !*healthcheck_pending && Instant::now() >= *healthcheck_deadline {
                run_healthcheck(client, first_run, healthcheck_pending, healthcheck_deadline);
            }

            poll(client, |req_kind, response| match req_kind {
                ReqKind::Capabilities => handle_capabilities_response(response),
                ReqKind::ClientVersion => handle_client_version_response(response),
                ReqKind::Syncing => {
                    handle_sync_response(response, adapter, sync_status, healthcheck_pending)
                }
                ReqKind::Fcu(spine_id) => handle_fcu_response(spine_id, response, adapter),
                ReqKind::NewPayload(spine_id) => {
                    handle_new_payload_response(spine_id, response, adapter)
                }
                ReqKind::GetPayloadFcu(spine_id) => {
                    handle_get_payload_fcu(spine_id, response, adapter, &mut pending_get_payload)
                }
                ReqKind::GetPayloadFetch(spine_id) => {
                    handle_get_payload_fetch(spine_id, response, adapter, resp_producer)
                }
                ReqKind::GetBlobs(spine_id) => {
                    handle_get_blobs_response(spine_id, response, adapter, resp_producer)
                }
                ReqKind::GetPayloadBodiesByHash(spine_id) |
                ReqKind::GetPayloadBodiesByRange(spine_id) => {
                    handle_get_payload_bodies_response(spine_id, response, adapter, resp_producer);
                }
            });
        }

        // GetPayloadFcu enqueues a follow-up RPC; done here so the closure
        // above doesn't need to borrow client while poll holds it.
        if let Some((payload_id, spine_id)) = pending_get_payload {
            get_payload(&mut self.client, payload_id, spine_id);
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
