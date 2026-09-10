use std::{
    ptr,
    time::{Duration, Instant},
};

use silver_beacon_state_data::ForkName;

use crate::{
    AcquiredRange, GossipTopic, MessageId, Nanos, P2pStreamId, PendingSubReservation,
    SubReservationError, SubReservationRef, TCacheRead, TRandomAccess,
    ssz_view::{BYTES_PER_CELL, BYTES_PER_KZG_PROOF},
};

pub const GOSSIP_DELIVERY_RETENTION: Duration = Duration::from_secs(11);

#[derive(Clone, Copy, Debug)]
pub struct RetentionEvent {
    pub expired_slot: u64,
    // Captured before the sole producer allocates any next-slot data.
    pub retain_from: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CellKey {
    pub block_root: [u8; 32],
    pub column: usize,
    pub row: usize,
}

#[derive(Clone, Copy, Debug)]
pub enum CellSource {
    Full { read: TCacheRead, cell: usize, proof: usize },
    Assembly { reservation: SubReservationRef, row: usize },
}

#[derive(Clone, Copy, Debug)]
pub struct CellRef {
    pub source: CellSource,
    pub slot: u64,
    pub expires: Instant,
}

impl CellRef {
    pub fn read(self) -> TCacheRead {
        match self.source {
            CellSource::Full { read, .. } => read,
            CellSource::Assembly { reservation, .. } => reservation.read(),
        }
    }

    pub fn acquire(self, consumer: &mut TRandomAccess) -> Option<AcquiredCell> {
        let [cell, proof] = match self.source {
            CellSource::Assembly { reservation, row } => {
                reservation.acquire(consumer).ok()?.ranges(row)?
            }
            CellSource::Full { read, cell, proof } => {
                if !consumer.is_strict() || !ptr::eq(&*consumer.cache_ref(), &*read.cache_ref()) {
                    return None;
                }
                let pin = consumer.acquire_strict(read)?;
                [pin.with_range(cell, BYTES_PER_CELL)?, pin.with_range(proof, BYTES_PER_KZG_PROOF)?]
            }
        };
        Some(AcquiredCell { cell, proof })
    }
}

pub struct AcquiredCell {
    pub cell: AcquiredRange,
    pub proof: AcquiredRange,
}

#[derive(Clone, Copy, Debug)]
pub struct ColumnRef {
    pub block_root: [u8; 32],
    pub column: usize,
    pub reservation: SubReservationRef,
    pub slot: u64,
    pub expires: Instant,
}

impl ColumnRef {
    pub fn stage(
        self,
        consumer: &mut TRandomAccess,
        row: usize,
        cell: &[u8; BYTES_PER_CELL],
        proof: &[u8; BYTES_PER_KZG_PROOF],
    ) -> Result<Option<PendingCell>, SubReservationError> {
        let acquired = self.reservation.acquire(consumer)?;
        let claim = match acquired.claim(row) {
            Ok(claim) => claim,
            Err(SubReservationError::Claimed | SubReservationError::Published) => return Ok(None),
            Err(error) => return Err(error),
        };
        Ok(Some(PendingCell {
            key: CellKey { block_root: self.block_root, column: self.column, row },
            data: claim.write(cell, proof)?,
        }))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct PendingCell {
    pub key: CellKey,
    pub data: PendingSubReservation,
}

#[derive(Clone, Copy, Debug)]
pub enum CellOrigin {
    Gossip { stream_id: P2pStreamId, topic: GossipTopic, message_id: MessageId, received: Nanos },
    El { request_id: u64 },
}

#[derive(Clone, Copy, Debug)]
pub struct CellValidationRequest {
    pub pending: PendingCell,
    pub origin: CellOrigin,
    pub deadline: Instant,
}

#[derive(Clone, Copy, Debug)]
pub enum CellValidationOutcome {
    Accepted,
    Rejected,
    Ignored,
}

#[derive(Clone, Copy, Debug)]
pub enum CellStoreEvent {
    Context {
        block_root: [u8; 32],
        slot: u64,
        format: ForkName,
        blob_count: usize,
        ssz: TCacheRead,
        expires: Instant,
    },
    Reservation(ColumnRef),
    Available {
        key: CellKey,
        cell: CellRef,
    },
    Validate(CellValidationRequest),
    Cancel(PendingCell),
    Validation {
        request: CellValidationRequest,
        outcome: CellValidationOutcome,
    },
}
