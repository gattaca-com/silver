use std::time::Instant;

use flux::spine::SpineProducers;
use silver_columns::cell_store::{
    CellStore, CellStoreConfig, CommitmentContext, ContextData, StoreError,
};
use silver_common::{
    SilverSpineProducers, TProducer,
    cells::{CellKey, CellStoreEvent, CellValidationOutcome, PendingCell},
};

pub struct CellIngress {
    store: CellStore,
    min_slot: u64,
}

impl CellIngress {
    pub fn new(
        config: CellStoreConfig,
        producer: TProducer,
        slot: u64,
        slot_start: Instant,
    ) -> Result<Self, StoreError> {
        Ok(Self { store: CellStore::new(config, producer, slot, slot_start)?, min_slot: 0 })
    }

    pub fn set_min_slot(&mut self, min_slot: u64) {
        self.min_slot = self.min_slot.max(min_slot);
    }

    pub fn spin(&mut self, now: Instant, producers: &SilverSpineProducers) {
        self.store.advance(now, self.min_slot, |_| {});
        if let Some(event) = self.store.take_retention_event() {
            producers.produce(event);
        }
    }

    pub fn admit_context(
        &mut self,
        context: CommitmentContext,
        data: ContextData<'_>,
        now: Instant,
        producers: &SilverSpineProducers,
    ) -> Result<bool, StoreError> {
        self.spin(now, producers);
        if !self.store.admit_context(context, data)? {
            return Ok(false);
        }
        let expires = self.store.slot_end();
        let (_, ssz) = self.store.context(&context.block_root).unwrap();
        producers.produce(CellStoreEvent::Context {
            block_root: context.block_root,
            slot: context.slot,
            format: context.format,
            blob_count: context.blob_count,
            ssz,
            expires,
        });
        for column in self.store.reservations(&context.block_root) {
            producers.produce(CellStoreEvent::Reservation(column));
        }
        Ok(true)
    }

    pub fn handle(
        &mut self,
        event: CellStoreEvent,
        now: Instant,
        producers: &SilverSpineProducers,
    ) {
        match event {
            CellStoreEvent::Cancel(pending) => {
                self.cancel(pending, now);
            }
            CellStoreEvent::Validation { request, outcome: CellValidationOutcome::Accepted } => {
                self.spin(now, producers);
                let key = request.pending.key;
                let Ok(update) = self.store.refresh_column(&key.block_root, key.column) else {
                    return;
                };
                let mut rows = update.new_cells.bits();
                while rows != 0 {
                    let row = rows.trailing_zeros() as usize;
                    rows &= rows - 1;
                    let key = CellKey { row, ..key };
                    if let Some(cell) = self.store.cell(key) {
                        producers.produce(CellStoreEvent::Available { key, cell });
                    }
                }
            }
            _ => {}
        }
    }

    pub fn cancel(&mut self, pending: PendingCell, now: Instant) -> bool {
        self.store.advance(now, self.min_slot, |_| {});
        self.store.cancel_pending(pending).unwrap_or(false)
    }

    pub fn store_mut(&mut self) -> &mut CellStore {
        &mut self.store
    }
}
