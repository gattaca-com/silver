use std::{sync::Arc, time::Duration};

use silver_beacon_state_data::{FAR_FUTURE_EPOCH, SLOTS_PER_EPOCH, SpecConfig};

use super::StoreError;
use crate::{
    SubLayout,
    ssz_view::{
        BYTES_PER_CELL, BYTES_PER_KZG_COMMITMENT, BYTES_PER_KZG_PROOF, DATA_COLUMN_SIDECAR_MIN,
    },
};

#[derive(Clone)]
pub struct CellStoreConfig {
    spec: Arc<SpecConfig>,
    columns: u128,
    column_indices: Box<[usize]>,
    max_blobs: usize,
    slot_duration: Duration,
    block_capacity: usize,
    live_blocks: usize,
    cell_capacity: usize,
    cache_bytes: usize,
}

impl CellStoreConfig {
    pub fn new(
        spec: Arc<SpecConfig>,
        columns: u128,
        delivery_retention: Duration,
    ) -> Result<Self, StoreError> {
        let max_blobs = spec
            .blob_schedule
            .iter()
            .filter(|entry| entry.epoch != FAR_FUTURE_EPOCH)
            .map(|entry| entry.max_blobs_per_block)
            .fold(spec.max_blobs_per_block_electra, u64::max);
        if max_blobs > u128::BITS as u64 {
            return Err(StoreError::UnsupportedBlobCount(max_blobs));
        }
        if columns == 0 || spec.slot_duration_ms() == 0 {
            return Err(StoreError::InvalidConfig);
        }

        let slot_duration = Duration::from_millis(spec.slot_duration_ms());
        let retention =
            slot_duration.checked_add(delivery_retention).ok_or(StoreError::CapacityOverflow)?;
        // One additional block covers a burst at the ends of the retention window.
        let live_blocks = usize::try_from(retention.as_nanos().div_ceil(slot_duration.as_nanos()))
            .ok()
            .and_then(|blocks| blocks.checked_add(1))
            .ok_or(StoreError::CapacityOverflow)?;
        // Keep duplicate/completion metadata across two epochs, allowing fork siblings.
        let block_capacity = live_blocks
            .max(2 * SLOTS_PER_EPOCH as usize)
            .checked_mul(2)
            .ok_or(StoreError::CapacityOverflow)?;
        let max_blobs = max_blobs as usize;
        let column_count = columns.count_ones() as usize;
        let cell_capacity = live_blocks
            .checked_mul(column_count)
            .and_then(|n| n.checked_mul(max_blobs))
            .ok_or(StoreError::CapacityOverflow)?;
        let context_bytes =
            DATA_COLUMN_SIDECAR_MIN + max_blobs * BYTES_PER_KZG_COMMITMENT + column_count * 16;
        let column_bytes = SubLayout {
            parts: max_blobs,
            first_len: BYTES_PER_CELL,
            second_len: BYTES_PER_KZG_PROOF,
        }
        .reservation_bytes(DATA_COLUMN_SIDECAR_MIN, max_blobs * BYTES_PER_KZG_COMMITMENT)
        .ok_or(StoreError::CapacityOverflow)?;
        let payload_bytes = live_blocks
            .checked_mul(column_count)
            .and_then(|n| n.checked_mul(column_bytes))
            .and_then(|n| n.checked_add(live_blocks.checked_mul(context_bytes)?))
            .ok_or(StoreError::CapacityOverflow)?;
        let full_column_bytes = DATA_COLUMN_SIDECAR_MIN +
            max_blobs * (BYTES_PER_CELL + BYTES_PER_KZG_COMMITMENT + BYTES_PER_KZG_PROOF);
        let full_payload_bytes = live_blocks
            .checked_mul(column_count)
            .and_then(|n| n.checked_mul(full_column_bytes))
            .ok_or(StoreError::CapacityOverflow)?;
        // Speculative sets cannot spend the space needed for trusted replacements.
        // Extra headroom covers ingress duplicates, wrap padding, and bucket rounding.
        let payload_bytes = payload_bytes
            .checked_mul(2)
            .and_then(|n| n.checked_add(full_payload_bytes))
            .ok_or(StoreError::CapacityOverflow)?;
        let cache_bytes = payload_bytes
            .checked_add(payload_bytes / 2)
            .and_then(|n| n.checked_add(64 * 1024))
            .and_then(usize::checked_next_power_of_two)
            .filter(|n| u32::try_from(*n).is_ok())
            .ok_or(StoreError::CapacityOverflow)?;
        Ok(Self {
            spec,
            columns,
            column_indices: (0..u128::BITS as usize)
                .filter(|column| columns & (1u128 << column) != 0)
                .collect(),
            max_blobs,
            slot_duration,
            block_capacity,
            live_blocks,
            cell_capacity,
            cache_bytes,
        })
    }

    #[inline]
    pub fn spec(&self) -> &SpecConfig {
        &self.spec
    }

    #[inline]
    pub fn columns(&self) -> u128 {
        self.columns
    }

    #[inline]
    pub fn column_indices(&self) -> &[usize] {
        &self.column_indices
    }

    #[inline]
    pub fn slot_duration(&self) -> Duration {
        self.slot_duration
    }

    #[inline]
    pub fn block_capacity(&self) -> usize {
        self.block_capacity
    }

    #[inline]
    pub fn live_blocks(&self) -> usize {
        self.live_blocks
    }

    #[inline]
    pub fn cache_capacity(&self) -> usize {
        self.cache_bytes
    }

    #[inline]
    pub fn cell_capacity(&self) -> usize {
        self.cell_capacity
    }

    #[inline]
    pub fn column_capacity(&self) -> usize {
        self.live_blocks * self.column_indices.len()
    }

    #[inline]
    pub fn max_blobs(&self) -> usize {
        self.max_blobs
    }

    #[inline]
    pub fn column_position(&self, column: usize) -> Option<usize> {
        let bit = 1u128.checked_shl(u32::try_from(column).ok()?)?;
        (self.columns & bit != 0).then(|| (self.columns & (bit - 1)).count_ones() as usize)
    }
}
