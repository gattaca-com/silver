use std::collections::VecDeque;

/// Byte-budgeted FIFO of whole datagrams, addressed by absolute index so
/// readers hold a plain `u64` cursor. An index below `first()` was evicted.
pub struct DatagramRing {
    entries: VecDeque<Vec<u8>>,
    first: u64,
    bytes: usize,
    budget: usize,
}

impl DatagramRing {
    pub fn new(budget: usize) -> Self {
        Self { entries: VecDeque::new(), first: 0, bytes: 0, budget }
    }

    /// Evicted buffers are reused, so a full ring allocates nothing.
    pub fn push(&mut self, dgram: &[u8]) {
        let mut buf = Vec::new();
        while self.bytes + dgram.len() > self.budget {
            let Some(old) = self.entries.pop_front() else { break };
            self.bytes -= old.len();
            self.first += 1;
            buf = old;
        }
        buf.clear();
        buf.extend_from_slice(dgram);
        self.bytes += buf.len();
        self.entries.push_back(buf);
    }

    pub fn first(&self) -> u64 {
        self.first
    }

    pub fn get(&self, idx: u64) -> Option<&[u8]> {
        let off = idx.checked_sub(self.first)?;
        self.entries.get(off as usize).map(Vec::as_slice)
    }

    pub fn oldest(&self) -> Option<&[u8]> {
        self.entries.front().map(Vec::as_slice)
    }

    pub fn newest(&self) -> Option<&[u8]> {
        self.entries.back().map(Vec::as_slice)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn bytes(&self) -> usize {
        self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evicts_oldest_to_budget_and_keeps_absolute_indices() {
        let mut ring = DatagramRing::new(10);
        for i in 0..5u8 {
            ring.push(&[i; 4]);
        }
        assert_eq!((ring.first(), ring.len()), (3, 2), "two 4 B entries fit in 10 B");
        assert_eq!(ring.bytes(), 8);
        assert_eq!(ring.get(2), None, "evicted");
        assert_eq!(ring.get(3), Some(&[3u8; 4][..]));
        assert_eq!(ring.get(4), Some(&[4u8; 4][..]));
        assert_eq!(ring.get(5), None, "not yet written");
    }

    #[test]
    fn oversized_datagram_still_lands() {
        let mut ring = DatagramRing::new(4);
        ring.push(&[1; 2]);
        ring.push(&[2; 8]);
        assert_eq!((ring.first(), ring.len()), (1, 1));
        assert_eq!(ring.newest(), Some(&[2u8; 8][..]));
    }
}
