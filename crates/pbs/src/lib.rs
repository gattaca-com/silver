use std::{collections::VecDeque, ops::Range, time::Duration};

use mio::{Events, Registry};
use silver_httpcore::{
    BufferCapacity, ClientRequest, ClientResponse, Endpoint, HttpPool, Method, TokenRange,
};

/// The sidecar tries each relay up to three times, 3 s apiece.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(3 * 3 + 3);

/// Buffers grow past this for a large registration set.
const CONNECTION_CAPACITY: BufferCapacity = BufferCapacity { read: 64 << 10, write: 64 << 10 };

pub struct PbsClient {
    pool: HttpPool,
    registry: Registry,
    in_flight: &'static str,
    /// Requests waiting on the connection, their bodies in `queued_bodies`.
    queued: VecDeque<(u64, &'static str, Range<usize>)>,
    queued_bodies: Vec<u8>,
}

impl PbsClient {
    pub const MAX_SOCKETS: usize = 1;

    pub fn new(registry: &Registry, tokens: TokenRange, endpoint: &str) -> Self {
        assert!(
            endpoint.starts_with("http://"),
            "unsupported pbs_endpoint scheme (only http:// is served): {endpoint}"
        );
        Self {
            pool: HttpPool::new(
                Endpoint::Http(endpoint.to_owned()),
                tokens,
                CONNECTION_CAPACITY,
                1,
                REQUEST_TIMEOUT,
            ),
            registry: registry.try_clone().expect("mio Registry::try_clone failed"),
            in_flight: "",
            queued: VecDeque::new(),
            queued_bodies: Vec::new(),
        }
    }

    /// POSTs the JSON `body` to `path` at once when the connection is free,
    /// else after the requests ahead of it. `spin` reports the answer under
    /// `id`.
    pub fn send(&mut self, id: u64, path: &'static str, body: &[u8]) {
        if self.queued.is_empty() && self.pool.has_capacity() {
            self.post(id, path, body);
            return;
        }
        let start = self.queued_bodies.len();
        self.queued_bodies.extend_from_slice(body);
        self.queued.push_back((id, path, start..self.queued_bodies.len()));
    }

    pub fn spin(
        &mut self,
        events: &Events,
        answered: &mut impl FnMut(u64, Result<ClientResponse<'_>, &str>),
    ) {
        let Self { pool, registry, in_flight, .. } = self;
        pool.dispatch_events(events, registry, &mut |id, response| {
            match &response {
                Ok(response) if response.status != 200 => silver_log::warn!(
                    path = *in_flight,
                    status = response.status,
                    "sidecar refused request"
                ),
                Ok(_) => {}
                Err(error) => {
                    silver_log::warn!(path = *in_flight, error, "request did not reach sidecar")
                }
            }
            answered(id, response);
        });

        while self.pool.has_capacity() {
            let Some((id, path, body)) = self.queued.pop_front() else { break };
            let Self { pool, registry, queued_bodies, in_flight, .. } = self;
            *in_flight = path;
            pool.enqueue(id, &post(path, &queued_bodies[body]), registry);
        }
        if self.queued.is_empty() {
            self.queued_bodies.clear();
        }
    }

    fn post(&mut self, id: u64, path: &'static str, body: &[u8]) {
        self.in_flight = path;
        self.pool.enqueue(id, &post(path, body), &self.registry);
    }
}

fn post<'a>(path: &'a str, body: &'a [u8]) -> ClientRequest<'a> {
    ClientRequest { method: Method::Post, path, body, authorization: None }
}
