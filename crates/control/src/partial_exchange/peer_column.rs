use std::time::Instant;

use silver_gossip::{ColumnGroupKey, PartsMetadata};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) struct ExchangeKey {
    pub peer: usize,
    pub group: ColumnGroupKey,
}

pub(super) struct PeerColumnExchange {
    pub remote: Option<PartsMetadata>,
    pub remote_slot: Option<u64>,
    pub advertised: Option<u128>,
    pub sent: u128,
    pub pending: bool,
    pub scheduled: bool,
    pub retry_at: Instant,
    pub expires: Instant,
    pub slot: u64,
    pub n_rows: usize,
    pub frames_sent: u8,
}

impl PeerColumnExchange {
    pub fn new(slot: u64, n_rows: usize, expires: Instant, now: Instant) -> Self {
        Self {
            remote: None,
            remote_slot: None,
            advertised: None,
            sent: 0,
            pending: false,
            scheduled: false,
            retry_at: now,
            expires,
            slot,
            n_rows,
            frames_sent: 0,
        }
    }

    pub fn replace(&mut self, metadata: PartsMetadata, slot: Option<u64>) {
        // Repeated snapshots do not bypass the retransmission budget.
        self.sent &= metadata.requests & !metadata.available;
        self.remote = Some(metadata);
        self.remote_slot = slot;
    }

    pub fn requested(&self, available: u128) -> u128 {
        self.remote.map_or(0, |remote| available & remote.requests & !remote.available & !self.sent)
    }
}
