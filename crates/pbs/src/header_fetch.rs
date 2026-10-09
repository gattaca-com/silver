use std::fmt::Write;

use mio::{Events, Registry};
use silver_beacon_state_data::{B256, SpecConfig};
use silver_common::{SidecarBidRequest, wei_saturating};
use silver_config::PbsConfig;
use silver_httpcore::{BufferCapacity, ClientRequest, Endpoint, HttpPool, Method, TokenRange};
use silver_ssz::ssz_view::{
    BuilderBidFuluView, ExecutionPayloadHeaderFuluView, SignedBuilderBidFuluView,
};

use crate::{
    CONSENSUS_VERSION,
    bid::{BidRefusal, BidRequest, builder_domain},
    registrations::Registration,
};

pub(crate) struct HeaderFetch {
    pool: HttpPool,
    genesis_time: u64,
    spec: SpecConfig,
    builder_domain: B256,
    path: String,
    pending: Option<BidRequest>,
}

impl HeaderFetch {
    pub(crate) fn new(
        tokens: TokenRange,
        config: &PbsConfig,
        spec: &SpecConfig,
        genesis_time: u64,
    ) -> Self {
        Self {
            pool: HttpPool::new(
                Endpoint::Http(config.endpoint.clone()),
                tokens,
                BufferCapacity { read: 16 << 10, write: 1 << 10 },
                1,
                config.get_header_timeout(),
            ),
            genesis_time,
            spec: spec.clone(),
            builder_domain: builder_domain(spec.genesis_fork_version),
            path: String::new(),
            pending: None,
        }
    }

    pub(crate) fn fetch(
        &mut self,
        request: &SidecarBidRequest,
        registration: Registration,
        registry: &Registry,
    ) -> bool {
        if !self.pool.has_capacity() {
            silver_log::warn!(slot = request.slot, "header request still in flight; no bid asked");
            return false;
        }
        let SidecarBidRequest { slot, parent_hash, proposer_pubkey, .. } = *request;
        self.path.clear();
        write!(self.path, "/eth/v1/builder/header/{slot}/").unwrap();
        write_hex(&mut self.path, &parent_hash);
        self.path.push('/');
        write_hex(&mut self.path, &proposer_pubkey);
        let get = ClientRequest {
            method: Method::Get,
            path: &self.path,
            body: &[],
            authorization: None,
            accept: Some("application/octet-stream"),
            content_type: None,
            headers: &[],
        };
        self.pool.enqueue(slot, &get, registry);
        self.pending = Some(BidRequest::new(request, registration, &self.spec, self.genesis_time));
        true
    }

    pub(crate) fn spin(
        &mut self,
        events: &Events,
        registry: &Registry,
        on_response: &mut impl FnMut(&BidRequest, Option<&[u8]>),
    ) {
        let Self { pool, pending, builder_domain, .. } = self;
        pool.dispatch_events(events, registry, &mut |slot, response| {
            let request = pending.take().expect("a response answers the pending request");
            let signed_bid = match response {
                Ok(response) if response.status == 200 => {
                    let checked = request.check(
                        response.body,
                        response.header(CONSENSUS_VERSION),
                        builder_domain,
                    );
                    bid_passes(&request, checked, response.body).then_some(&*response.body)
                }
                Ok(response) if response.status == 204 => {
                    silver_log::debug!(slot, "sidecar has no bid");
                    None
                }
                Ok(response) => {
                    silver_log::warn!(
                        slot,
                        status = response.status,
                        "sidecar refused header request"
                    );
                    None
                }
                Err(error) => {
                    silver_log::warn!(slot, error, "header request did not reach sidecar");
                    None
                }
            };
            on_response(&request, signed_bid);
        });
    }
}

fn bid_passes(request: &BidRequest, checked: Result<(), BidRefusal>, signed_bid: &[u8]) -> bool {
    let slot = request.slot;
    if let Err(refusal) = checked {
        silver_log::warn!(slot, ?refusal, "sidecar bid refused");
        return false;
    }
    let bid = SignedBuilderBidFuluView::message(signed_bid);
    if !request.pays_fee_recipient(signed_bid) {
        silver_log::warn!(slot, "sidecar bid pays a fee recipient other than the registration's");
    }
    silver_log::info!(
        slot,
        value_wei = wei_saturating(BuilderBidFuluView::value(bid)),
        block_hash = %hex::encode(ExecutionPayloadHeaderFuluView::block_hash(BuilderBidFuluView::header(bid))),
        relay = %hex::encode(BuilderBidFuluView::pubkey(bid)),
        "sidecar bid verified"
    );
    true
}

fn write_hex(out: &mut String, bytes: &[u8]) {
    out.push_str("0x");
    for byte in bytes {
        write!(out, "{byte:02x}").unwrap();
    }
}
