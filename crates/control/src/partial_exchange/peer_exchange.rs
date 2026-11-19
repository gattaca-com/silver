const MAX_FRAMES: usize = 16;
const MAX_BYTES: usize = 4 * 1024 * 1024;

pub(super) struct PeerExchange {
    pub columns: usize,
    /// Exchanges per column index, so removing a column the peer holds no
    /// exchange for costs no scan.
    pub per_column: [u16; 128],
    frames: usize,
    bytes: usize,
    sent: Option<(u64, u64)>,
}

impl Default for PeerExchange {
    fn default() -> Self {
        Self { columns: 0, per_column: [0; 128], frames: 0, bytes: 0, sent: None }
    }
}

impl PeerExchange {
    pub fn add(&mut self, column: u64) {
        self.columns += 1;
        self.per_column[column as usize] += 1;
    }

    pub fn remove(&mut self, column: u64) {
        self.columns = self.columns.saturating_sub(1);
        let count = &mut self.per_column[column as usize];
        *count = count.saturating_sub(1);
    }

    pub fn clear_columns(&mut self) {
        self.columns = 0;
        self.per_column = [0; 128];
    }

    pub fn remaining_bytes(&self) -> usize {
        if self.frames == MAX_FRAMES { 0 } else { MAX_BYTES - self.bytes }
    }

    pub fn record(&mut self, seq: u64, bytes: usize) {
        assert!(self.frames < MAX_FRAMES && bytes <= MAX_BYTES - self.bytes);
        self.frames += 1;
        self.bytes += bytes;
        let range = self.sent.get_or_insert((seq, seq));
        range.1 = seq;
    }

    pub fn dropped(&mut self, seq: u64) -> bool {
        if !self.sent.is_some_and(|(first, last)| (first..=last).contains(&seq)) {
            return false;
        }
        // One peer-wide reset covers every frame submitted before this failure.
        // Later failures from that batch must not invalidate its replacements.
        self.sent = None;
        true
    }

    pub fn reset_sends(&mut self) {
        self.sent = None;
    }

    pub fn heartbeat(&mut self) {
        self.frames = 0;
        self.bytes = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_count_all_sends_without_refunding_drops() {
        let mut peer = PeerExchange::default();
        for seq in 0..MAX_FRAMES {
            assert!(peer.remaining_bytes() > 0);
            peer.record(seq as u64, 1);
            assert!(peer.dropped(seq as u64));
        }
        assert_eq!(peer.remaining_bytes(), 0);
        peer.heartbeat();
        assert_eq!(peer.remaining_bytes(), MAX_BYTES);
        peer.record(100, MAX_BYTES);
        assert_eq!(peer.remaining_bytes(), 0);
        peer.heartbeat();
        assert_eq!(peer.remaining_bytes(), MAX_BYTES);
    }

    #[test]
    fn failure_batches_and_stale_drops_do_not_reset_new_sends() {
        let mut peer = PeerExchange::default();
        peer.record(10, 1);
        peer.record(20, 1);
        assert!(peer.dropped(10));
        assert!(!peer.dropped(20));
        peer.record(30, 1);
        assert!(!peer.dropped(20));
        assert!(!peer.dropped(40));
        assert!(peer.dropped(30));
        peer.record(40, 1);
        peer.reset_sends();
        assert!(!peer.dropped(40));
    }
}
