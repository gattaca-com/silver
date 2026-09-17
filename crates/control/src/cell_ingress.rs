use std::time::Instant;

use flux::spine::SpineProducers;
use fxhash::FxHashMap;
use silver_common::{
    ColumnOrigin, DataColumnsEvent, GossipTopic, PeerControl, SilverSpineProducers, SszCache,
    TProducer, TRandomAccess,
    cell_store::{
        CellKey, CellStoreConfig, CellStoreEvent, ColumnAvailability, PendingCell, StoreError,
    },
    ssz_view::{BYTES_PER_CELL, BYTES_PER_KZG_PROOF},
};
use silver_gossip::GossipHandler;
use silver_peer::PeerManager;

use crate::cell_allocator::CellAllocator;

pub(super) fn handle_data_column_event<F>(
    event: DataColumnsEvent,
    rpc_ssz_consumer: &mut TRandomAccess,
    el_ssz_consumer: &mut TRandomAccess,
    cell_ingress: Option<&mut CellIngress>,
    gossip_handler: &mut GossipHandler,
    peer_manager: &mut PeerManager,
    handle_peer_control: &mut F,
) where
    F: FnMut(PeerControl, &mut GossipHandler),
{
    let DataColumnsEvent::Persist { ssz, origin, ssz_cache, domain, column_index, .. } = event
    else {
        return;
    };
    if origin == ColumnOrigin::Gossip {
        return;
    }
    let read = match ssz_cache {
        SszCache::Rpc => Some(rpc_ssz_consumer.acquire(ssz)),
        SszCache::El => Some(el_ssz_consumer.acquire(ssz)),
        SszCache::DataColumns => None,
        SszCache::Gossip => return,
    };
    let bytes = match read.as_ref() {
        Some(read) => read.buffer().map(|(bytes, _)| bytes),
        None => {
            let Some(ingress) = cell_ingress else { return };
            ingress.producer_mut().read_buffer(ssz)
        }
    };
    let topic = GossipTopic::DataColumnSidecar(column_index);
    match bytes {
        Ok(bytes) => {
            let published = match domain {
                Some(domain) => gossip_handler.publish_in_domain(topic, domain, bytes),
                None => gossip_handler.publish(topic, bytes),
            };
            if let Some(published) = published {
                peer_manager.publish_local(topic, published, &mut |evt| {
                    handle_peer_control(evt, gossip_handler)
                });
            }
        }
        Err(e) => tracing::warn!(?e, ?topic, "publish column ssz read failed"),
    }
}

pub struct CellIngress {
    allocator: CellAllocator,
    available: FxHashMap<([u8; 32], usize), ColumnAvailability>,
    capacity: usize,
    min_slot: u64,
}

impl CellIngress {
    pub fn new(
        config: CellStoreConfig,
        producer: TProducer,
        slot: u64,
        slot_start: Instant,
    ) -> Result<Self, StoreError> {
        let capacity = config.column_capacity();
        Ok(Self {
            allocator: CellAllocator::new(config, producer, slot, slot_start)?,
            available: FxHashMap::with_capacity_and_hasher(capacity, Default::default()),
            capacity,
            min_slot: 0,
        })
    }

    pub fn set_min_slot(&mut self, min_slot: u64) {
        self.min_slot = self.min_slot.max(min_slot);
    }

    pub fn spin(&mut self, now: Instant, producers: &SilverSpineProducers) {
        if let Some(event) = self.allocator.advance(now, self.min_slot) {
            self.available.clear();
            producers.produce(event);
        }
    }

    pub fn handle(
        &mut self,
        event: CellStoreEvent,
        now: Instant,
        producers: &SilverSpineProducers,
    ) {
        self.spin(now, producers);
        match event {
            CellStoreEvent::RejectedContext { block_root } => {
                self.allocator.reject(&block_root);
                self.available.retain(|(root, _), _| *root != block_root);
            }
            CellStoreEvent::Allocate(request) => {
                let set = match self.allocator.allocate(request) {
                    Ok(set) => Some(set),
                    Err(e) => {
                        tracing::debug!(?e, slot = request.context.slot, "cell allocation failed");
                        None
                    }
                };
                producers.produce(CellStoreEvent::Allocated { request, set });
            }
            CellStoreEvent::Available(update)
                if now < update.expires && update.slot >= self.min_slot =>
            {
                let key = (update.block_root, update.column);
                if self.available.contains_key(&key) || self.available.len() < self.capacity {
                    self.available.insert(key, update);
                }
            }
            _ => {}
        }
    }

    pub fn availability(
        &self,
        root: &[u8; 32],
        column: usize,
        now: Instant,
    ) -> Option<ColumnAvailability> {
        self.available
            .get(&(*root, column))
            .copied()
            .filter(|update| now < update.expires && update.slot >= self.min_slot)
    }

    pub fn stage_cell(
        &self,
        key: CellKey,
        cell: &[u8; BYTES_PER_CELL],
        proof: &[u8; BYTES_PER_KZG_PROOF],
        now: Instant,
    ) -> Result<Option<PendingCell>, StoreError> {
        if self
            .availability(&key.block_root, key.column, now)
            .is_some_and(|column| column.cell(key.row).is_some())
        {
            return Ok(None);
        }
        let reference = self.allocator.column(key).ok_or(StoreError::UnknownCell)?;
        if now >= reference.expires {
            return Err(StoreError::ContextExpired);
        }
        self.allocator.stage(key, cell, proof)
    }

    pub fn cancel(&mut self, pending: PendingCell, now: Instant) -> bool {
        if self.allocator.column(pending.key).is_none_or(|column| now >= column.expires) {
            return false;
        }
        self.allocator.cancel(pending).unwrap_or(false)
    }

    pub fn allocator_mut(&mut self) -> &mut CellAllocator {
        &mut self.allocator
    }
    pub fn producer_mut(&mut self) -> &mut TProducer {
        self.allocator.producer_mut()
    }
}
