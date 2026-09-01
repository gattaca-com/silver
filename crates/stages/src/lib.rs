//! Per-block stage events, decoded from the node's spine queues. A broadcast
//! consumer drains four queues through one [`StageReader`] and gets a flat
//! stream of stage timings; joining, display and storage stay with the
//! consumer.
//!
//! Timestamps come off the `InternalMessage` envelope: arrivals (`Received`,
//! `ColumnRecv`) use the ingestion clock, everything else the publish clock.

pub use clock::SlotClock;
pub use event::{Stage, StageEvent};
pub use reader::StageReader;

mod clock;
mod event;
mod reader;
