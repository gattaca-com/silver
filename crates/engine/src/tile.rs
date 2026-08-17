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
    pub resp_producer: TProducer,

    first_run: bool,
    healthcheck_pending: bool,
    healthcheck_deadline: Instant,
    sync_status: ELSyncStatus,
    // Reusable scratch buffer for the JSON→SSZ getPayload conversion.
    // Cleared on each use; capacity is retained across calls.
    scratch: Vec<u8>,
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
            Some(EngineClient::new(
                &config.execution_endpoint,
                &config.jwt_secret,
                config.max_connections,
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

            if !*healthcheck_pending &&
                Instant::now() >= *healthcheck_deadline &&
                client.has_capacity()
            {
                run_healthcheck(client, first_run, healthcheck_pending, healthcheck_deadline);
            }

            poll(client, |req_kind, response| match req_kind {
                ReqKind::Capabilities => {
                    negotiated_get_payload_method = Some(handle_capabilities_response(response));
                }
                ReqKind::ClientVersion => handle_client_version_response(response),
                ReqKind::Syncing => {
                    handle_sync_response(response, adapter, sync_status, healthcheck_pending)
                }
                ReqKind::Fcu(block_root) => handle_fcu_response(block_root, response, adapter),
                ReqKind::NewPayload(block_root) => {
                    handle_new_payload_response(block_root, response, adapter)
                }
                ReqKind::GetPayloadFetch(spine_id) => {
                    handle_get_payload_fetch(spine_id, response, adapter, resp_producer, scratch)
                }
                ReqKind::GetBlobs(spine_id) => {
                    handle_get_blobs_response(spine_id, response, adapter, resp_producer, scratch)
                }
                ReqKind::GetPayloadBodiesByHash(spine_id) |
                ReqKind::GetPayloadBodiesByRange(spine_id) => {
                    handle_get_payload_bodies_response(
                        spine_id,
                        response,
                        adapter,
                        resp_producer,
                        scratch,
                    );
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

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use flux::{spine::SpineAdapter, tile::Tile};
    use silver_common::{EngineFcuReq, EngineReq, EngineResp, SilverSpine, TCache, TCacheProducer};
    use silver_config::EngineConfig;
    use tempfile::TempDir;

    use super::EngineTile;
    use crate::test_el::{FCU_VALID_RESULT, FakeEl, write_jwt};

    struct Injector;
    impl Tile<SilverSpine> for Injector {
        fn loop_body(&mut self, _: &mut SpineAdapter<SilverSpine>) {}
    }

    fn fcu_req(byte: u8) -> EngineReq {
        EngineReq::Fcu(EngineFcuReq {
            block_root: [byte; 32],
            head_block_hash: [byte; 32],
            safe_block_hash: [0u8; 32],
            finalized_block_hash: [0u8; 32],
        })
    }

    fn head_block_hash_json(byte: u8) -> String {
        format!("\"headBlockHash\":\"0x{}\"", hex::encode([byte; 32]))
    }

    /// (cap+1) concurrent spine requests with `max_connections = cap`: the
    /// last one must stay queued on the spine until a completion frees a
    /// connection, and completions must correlate out of order.
    #[test]
    fn pool_cap_gates_spine_intake() {
        let base = TempDir::new().unwrap();
        let mut spine = Box::new(SilverSpine::new_with_base_dir(base.path(), None));
        let (mut el, endpoint) = FakeEl::tcp();
        let jwt_path = write_jwt(base.path());

        let gossip_p = TCache::producer("engine_cap_test_gossip", 1 << 12);
        let rpc_p = TCache::producer("engine_cap_test_rpc", 1 << 12);
        let resp_p = TCache::producer("engine_cap_test_resp", 1 << 12);
        let config = EngineConfig {
            execution_endpoint: endpoint,
            jwt_secret: jwt_path.to_str().unwrap().to_string(),
            max_connections: 3,
            ..EngineConfig::default()
        };
        let mut tile = EngineTile::new(
            config,
            gossip_p.cache_ref().random_access("t", true).unwrap(),
            rpc_p.cache_ref().random_access("t", true).unwrap(),
            resp_p,
        );
        let mut adapter = SpineAdapter::connect_tile(&tile, &mut *spine);
        let mut inj = SpineAdapter::connect_tile(&Injector, &mut *spine);
        inj.consume(|_: EngineResp, _| {});

        let deadline = Instant::now() + Duration::from_secs(10);
        let mut crank = |tile: &mut EngineTile, el: &mut FakeEl, msg: &str| {
            assert!(Instant::now() < deadline, "timeout: {msg}");
            tile.loop_body(&mut adapter);
            el.pump();
            std::thread::sleep(Duration::from_millis(1));
        };

        // First loop_body fires the startup healthcheck trio; answer it so all
        // three pooled connections are free before the capped scenario.
        while el.requests.len() < 3 {
            crank(&mut tile, &mut el, "startup healthcheck trio");
        }
        for i in 0..3 {
            el.respond(i, "false");
        }

        for byte in [11u8, 12, 13, 14] {
            inj.produce(fcu_req(byte));
        }

        let fcu_count = |el: &FakeEl| {
            el.requests.iter().filter(|r| r.method == "engine_forkchoiceUpdatedV3").count()
        };
        while fcu_count(&el) < 3 {
            crank(&mut tile, &mut el, "first three FCUs sent");
        }
        for _ in 0..50 {
            crank(&mut tile, &mut el, "cap holds");
            assert_eq!(fcu_count(&el), 3, "4th request must wait while pool is at cap");
        }

        // Free one connection by answering the SECOND fcu; the gated request
        // must then be sent, and the completion must carry the responded
        // request's block root.
        let second = el
            .requests
            .iter()
            .position(|r| r.body.contains(&head_block_hash_json(12)))
            .expect("fcu for root 12 on the wire");
        el.respond(second, FCU_VALID_RESULT);

        while fcu_count(&el) < 4 {
            crank(&mut tile, &mut el, "gated FCU sent after a connection freed");
        }

        let mut completed = Vec::new();
        inj.consume(|resp: EngineResp, _| {
            if let EngineResp::Fcu(r) = resp {
                completed.push(r.block_root);
            }
        });
        assert_eq!(completed, vec![[12u8; 32]], "out-of-order completion correlated");
    }
}
