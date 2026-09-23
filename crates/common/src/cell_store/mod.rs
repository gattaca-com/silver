use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use silver_beacon_state_data::ForkName;

use crate::{
    AcquiredRange, GossipDomain, GossipTopic, Nanos, P2pStreamId, PendingSubReservation,
    SubReservationError, SubReservationList, SubReservationRef, TCacheRead, TCacheReader,
    ssz_view::{
        BYTES_PER_CELL, BYTES_PER_KZG_COMMITMENT, BYTES_PER_KZG_PROOF,
        partial_column::PARTIAL_HEADER_FIXED,
    },
};

mod config;
mod context;
mod counters;

pub use config::CellStoreConfig;
pub use context::ContextData;
pub use counters::DataColumnCounters;

pub const CELL_RECORD_BYTES: usize = BYTES_PER_CELL + BYTES_PER_KZG_PROOF;
pub const MAX_CONTEXT_BYTES: usize = PARTIAL_HEADER_FIXED + 128 * BYTES_PER_KZG_COMMITMENT;

/// `SendOnly` serves partials while requesting full sidecars; `Enabled` also
/// requests partials.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PartialColumnsMode {
    #[default]
    Off,
    SendOnly,
    Enabled,
}

impl PartialColumnsMode {
    #[inline]
    pub const fn supports_sending(self) -> bool {
        !matches!(self, Self::Off)
    }

    #[inline]
    pub const fn requests(self) -> bool {
        matches!(self, Self::Enabled)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreError {
    InvalidConfig,
    UnsupportedBlobCount(u64),
    CapacityOverflow,
    CacheTooSmall,
    WrongCache,
    InvalidContext,
    ConflictingContext,
    ContextExpired,
    OutsideServingSlot,
    BelowSlotFloor,
    UnknownCell,
    Full,
    CacheFull,
}

impl From<SubReservationError> for StoreError {
    fn from(error: SubReservationError) -> Self {
        match error {
            SubReservationError::CacheFull => {
                DataColumnCounters::CellStoreCacheFull.inc();
                Self::CacheFull
            }
            SubReservationError::Closed | SubReservationError::Stale => Self::ContextExpired,
            SubReservationError::WrongConsumer | SubReservationError::WrongProducer => {
                Self::WrongCache
            }
            _ => Self::InvalidContext,
        }
    }
}

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

    pub fn acquire(self, reader: &mut TCacheReader) -> Option<AcquiredCell> {
        let [cell, proof] = match self.source {
            CellSource::Assembly { reservation, row } => {
                reservation.acquire(reader).ok()?.ranges(row)?
            }
            CellSource::Full { read, cell, proof } => {
                if !reader.is_strict(read.id()) {
                    return None;
                }
                let pin = reader.acquire_strict(read)?;
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
        reader: &mut TCacheReader,
        row: usize,
        cell: &[u8; BYTES_PER_CELL],
        proof: &[u8; BYTES_PER_KZG_PROOF],
    ) -> Result<Option<PendingCell>, SubReservationError> {
        let acquired = self.reservation.acquire(reader)?;
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
    Gossip { stream_id: P2pStreamId, topic: GossipTopic, received: Nanos },
    El { request_id: u64 },
}

#[derive(Clone, Copy, Debug)]
pub struct CellValidationRequest {
    pub pending: PendingCell,
    pub slot: u64,
    pub origin: CellOrigin,
    pub deadline: Instant,
    pub domain: GossipDomain,
}

#[derive(Clone, Copy, Debug)]
pub struct HeaderValidationRequest {
    pub block_root: [u8; 32],
    pub ssz: TCacheRead,
    pub domain: GossipDomain,
    pub origin: CellOrigin,
    pub deadline: Instant,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ColumnGroupKey {
    pub domain: GossipDomain,
    pub block_root: [u8; 32],
    pub column: u64,
}

impl From<ColumnAvailability> for ColumnGroupKey {
    fn from(column: ColumnAvailability) -> Self {
        Self { domain: column.domain, block_root: column.block_root, column: column.column as u64 }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommitmentContext {
    pub block_root: [u8; 32],
    pub slot: u64,
    pub format: ForkName,
    pub blob_count: usize,
}

#[derive(Clone, Copy, Debug)]
pub struct AssemblyRequest {
    pub id: u64,
    pub context: CommitmentContext,
    pub domain: GossipDomain,
    pub columns: u128,
}

#[derive(Clone, Copy, Debug)]
pub struct AssemblySet {
    pub request: AssemblyRequest,
    pub reservations: SubReservationList,
    /// Space for the Fulu header, filled by Columns from its validated context.
    pub header: Option<SubReservationRef>,
    pub expires: Instant,
}

#[derive(Clone, Copy, Debug)]
pub struct ColumnAvailability {
    pub block_root: [u8; 32],
    pub column: usize,
    pub slot: u64,
    pub blob_count: usize,
    pub domain: GossipDomain,
    pub available: u128,
    pub full: Option<(TCacheRead, usize, usize)>,
    pub assembly: Option<SubReservationRef>,
    pub header: Option<TCacheRead>,
    pub expires: Instant,
}

impl ColumnAvailability {
    pub fn cell(self, row: usize) -> Option<CellRef> {
        if row >= 128 || self.available & (1u128 << row) == 0 {
            return None;
        }
        let source = match self.full {
            Some((read, cell, proof)) => CellSource::Full {
                read,
                cell: cell + row * BYTES_PER_CELL,
                proof: proof + row * BYTES_PER_KZG_PROOF,
            },
            None => CellSource::Assembly { reservation: self.assembly?, row },
        };
        Some(CellRef { source, slot: self.slot, expires: self.expires })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CellValidationOutcome {
    Accepted,
    Rejected,
    Ignored,
}

#[derive(Clone, Copy, Debug)]
pub enum CellStoreEvent {
    RejectedContext { block_root: [u8; 32] },
    Allocate(AssemblyRequest),
    Allocated { request: AssemblyRequest, set: Option<AssemblySet> },
    Available(ColumnAvailability),
    Validate(CellValidationRequest),
    Header(HeaderValidationRequest),
    Cancel(PendingCell),
    Validation { request: CellValidationRequest, outcome: CellValidationOutcome },
}
