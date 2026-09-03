//! Per-block stage events, decoded from the node's spine queues. Joining,
//! display and storage stay with the consumer.
//!
//! Timestamps come off the `InternalMessage` envelope: arrivals (`Received`,
//! `ColumnRecv`) use the ingestion clock, everything else the publish clock.

pub use clock::SlotClock;
pub use event::{Stage, StageEvent};
pub use reader::StageReader;

mod clock;
mod event;
mod reader;

#[cfg(test)]
mod test_clock {
    use flux::timing::Nanos;

    pub const GENESIS_SECS: u64 = 1_000;
    pub const SLOT_MS: u64 = 12_000;

    pub fn at(slot: u64, ms_into_slot: u64) -> Nanos {
        Nanos::from_secs(GENESIS_SECS) + Nanos::from_millis(slot * SLOT_MS + ms_into_slot)
    }
}
