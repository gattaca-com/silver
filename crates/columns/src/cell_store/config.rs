use std::{sync::Arc, time::Duration};

use silver_beacon_state_data::{SLOTS_PER_EPOCH, SpecConfig};
use silver_common::{
    SubLayout,
    ssz_view::{
        BYTES_PER_CELL, BYTES_PER_KZG_COMMITMENT, BYTES_PER_KZG_PROOF, DATA_COLUMN_SIDECAR_MIN,
    },
};

use super::StoreError;

pub struct CellStoreConfig {
    pub(super) spec: Arc<SpecConfig>,
    pub(super) columns: u128,
    pub(super) column_indices: Box<[usize]>,
    pub(super) max_blobs: usize,
    pub(super) slot_duration: Duration,
    pub(super) block_capacity: usize,
    pub(super) live_blocks: usize,
    pub(super) cell_capacity: usize,
    cache_bytes: usize,
    full_cache_bytes: usize,
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
            .filter(|entry| entry.epoch != u64::MAX)
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
        let context_bytes = DATA_COLUMN_SIDECAR_MIN + max_blobs * BYTES_PER_KZG_COMMITMENT;
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
        // Headroom covers reservation headers, wrap padding, and the consumer's
        // lookback guard.
        let [Some(cache_bytes), Some(full_cache_bytes)] =
            [payload_bytes, full_payload_bytes].map(|bytes| {
                bytes
                    .checked_add(bytes / 2)
                    .and_then(|n| n.checked_add(64 * 1024))
                    .and_then(usize::checked_next_power_of_two)
                    .filter(|n| u32::try_from(*n).is_ok())
            })
        else {
            return Err(StoreError::CapacityOverflow);
        };
        block_capacity
            .checked_mul(column_count)
            .and_then(|n| n.checked_mul(max_blobs))
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
            full_cache_bytes,
        })
    }

    pub fn cache_capacity(&self) -> usize {
        self.cache_bytes
    }

    pub fn full_cache_capacity(&self) -> usize {
        self.full_cache_bytes
    }

    pub fn cell_capacity(&self) -> usize {
        self.cell_capacity
    }

    pub fn max_blobs(&self) -> usize {
        self.max_blobs
    }

    #[inline]
    pub(super) fn column_position(&self, column: usize) -> Option<usize> {
        let bit = 1u128.checked_shl(u32::try_from(column).ok()?)?;
        (self.columns & bit != 0).then(|| (self.columns & (bit - 1)).count_ones() as usize)
    }
}
