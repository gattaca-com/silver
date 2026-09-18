use silver_common::{Nanos, P2pStreamId, SilverSpineProducers, TProducer};

use super::metadata::PartialGroup;
use crate::{ColumnGroupKey, generated::PartialMessagesExtensionView, handler::ActiveDomains};

#[derive(Clone, Copy)]
pub struct PartialInbound<'a> {
    pub stream_id: P2pStreamId,
    pub group: ColumnGroupKey,
    pub slot: Option<u64>,
    pub received: Nanos,
    pub payload: &'a [u8],
}

impl<'a> PartialInbound<'a> {
    pub(crate) fn decode(
        partial: &PartialMessagesExtensionView<'a>,
        stream_id: P2pStreamId,
        received: Nanos,
        domains: &ActiveDomains,
    ) -> Option<Self> {
        let PartialGroup { group, slot } = PartialGroup::decode(partial, domains)?;
        Some(Self { stream_id, group, slot, received, payload: partial.partial_message? })
    }
}

pub trait ColumnIngress {
    fn producer_mut(&mut self) -> &mut TProducer;
    fn receive_partial(&mut self, message: PartialInbound<'_>, producers: &SilverSpineProducers);
}

impl ColumnIngress for TProducer {
    fn producer_mut(&mut self) -> &mut TProducer {
        self
    }
    fn receive_partial(&mut self, _: PartialInbound<'_>, _: &SilverSpineProducers) {}
}
