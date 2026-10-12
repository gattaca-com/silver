use mio::{Events, Registry};
use silver_config::PbsConfig;
use silver_httpcore::{
    BufferCapacity, ClientRequest, ClientResponse, Endpoint, HttpPool, Method, TokenRange,
};

use crate::{CONSENSUS_VERSION, FULU, SUBMIT_BLINDED_BLOCK};

/// A blinded block on a connection of its own, so it never waits behind a
/// registration batch the sidecar is still forwarding.
pub(crate) struct BlockSubmission {
    pool: HttpPool,
    /// Submissions that arrived while one was in flight, answered on the next
    /// spin.
    refused: Vec<u64>,
}

impl BlockSubmission {
    pub(crate) fn new(tokens: TokenRange, config: &PbsConfig) -> Self {
        Self {
            pool: HttpPool::new(
                Endpoint::Http(config.endpoint.clone()),
                tokens,
                BufferCapacity { read: 4 << 10, write: 64 << 10 },
                1,
                config.submit_blinded_block_timeout(),
            ),
            refused: Vec::new(),
        }
    }

    pub(crate) fn send(&mut self, id: u64, signed_blinded_block: &[u8], registry: &Registry) {
        if !self.pool.has_capacity() {
            self.refused.push(id);
            return;
        }
        let post = ClientRequest {
            method: Method::Post,
            path: SUBMIT_BLINDED_BLOCK,
            body: signed_blinded_block,
            authorization: None,
            accept: None,
            content_type: Some("application/octet-stream"),
            headers: &[(CONSENSUS_VERSION, FULU)],
        };
        self.pool.enqueue(id, &post, registry);
    }

    pub(crate) fn spin(
        &mut self,
        events: &Events,
        registry: &Registry,
        answered: &mut impl FnMut(u64, Result<ClientResponse<'_>, &str>),
    ) {
        for id in self.refused.drain(..) {
            answered(id, Err("a blinded block is already being submitted"));
        }
        self.pool.dispatch_events(events, registry, answered);
    }
}
