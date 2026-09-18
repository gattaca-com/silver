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
            scheduled: false,
            retry_at: now,
            expires,
            slot,
            n_rows,
            frames_sent: 0,
        }
    }

    /// Returns newly requested cells, excluding cells the peer already has.
    pub fn replace(&mut self, metadata: PartsMetadata, slot: Option<u64>) -> u32 {
        let requested = metadata.requests & !metadata.available;
        let previous = self.remote.map_or(0, |remote| remote.requests & !remote.available);
        // Repeated snapshots do not bypass the retransmission budget.
        self.sent &= requested;
        self.remote = Some(metadata);
        self.remote_slot = slot;
        (requested & !previous).count_ones()
    }

    pub fn requested(&self, available: u128) -> u128 {
        self.remote.map_or(0, |remote| available & remote.requests & !remote.available & !self.sent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exchange() -> PeerColumnExchange {
        let now = Instant::now();
        PeerColumnExchange::new(0, 128, now, now)
    }

    fn metadata(available: u128, requests: u128) -> PartsMetadata {
        PartsMetadata { available, requests, n_rows: 128 }
    }

    #[test]
    fn counts_new_requests_not_repeated_snapshots_or_available_cells() {
        let mut exchange = exchange();
        assert_eq!(exchange.replace(metadata(0b0101, 0b1111), None), 2);
        assert_eq!(exchange.replace(metadata(0b0101, 0b1111), None), 0);
        exchange.sent = 0b1010;
        assert_eq!(exchange.replace(metadata(0b0101, 0b1111), None), 0);
        assert_eq!(exchange.sent, 0b1010);
        assert_eq!(exchange.replace(metadata(0b0101, 0b1_1111), None), 1);
        assert_eq!(exchange.requested(u128::MAX), 0b1_0000);
    }

    #[test]
    fn cancellation_then_rerequest_counts_new_demand() {
        let mut exchange = exchange();
        assert_eq!(exchange.replace(metadata(0, 1), None), 1);
        exchange.sent = 1;
        assert_eq!(exchange.replace(metadata(0, 0), None), 0);
        assert_eq!(exchange.sent, 0);
        assert_eq!(exchange.replace(metadata(0, 1), None), 1);
        assert_eq!(exchange.requested(1), 1);
        assert_eq!(exchange.replace(metadata(1, 1), None), 0);
        assert_eq!(exchange.replace(metadata(0, 1), None), 1);
    }

    #[test]
    fn counts_requests_before_local_availability_and_in_the_highest_row() {
        let mut exchange = exchange();
        assert_eq!(exchange.replace(metadata(0, u128::MAX), Some(0)), 128);
        assert_eq!(exchange.requested(0), 0);
        assert_eq!(exchange.replace(metadata(u128::MAX, u128::MAX), Some(0)), 0);
        assert_eq!(exchange.replace(metadata(0, 1 << 127), Some(0)), 1);
        assert_eq!(exchange.requested(1 << 127), 1 << 127);
    }
}
