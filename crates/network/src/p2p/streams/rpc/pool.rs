use super::RpcCodec;

/// Keep the idle pool bounded: a codec retains roughly 184 KiB after its raw
/// Snappy encoder has allocated the large-input hash table.
const MAX_IDLE_RPC_CODECS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RpcCodecDirection {
    Incoming,
    Outgoing,
}

/// Network-tile-wide free list of RPC codecs.
///
/// The tile is single-threaded, so checkout and return are explicit and need
/// no shared ownership or synchronization. Keeping the codec boxed makes a
/// pool operation move only a pointer, while retaining both staging buffers
/// and `snap::raw::Encoder`'s lazily allocated hash table.
#[derive(Debug)]
// The Box is the ownership unit handed to a Stream. Storing codecs by value
// would either make every Stream large or allocate a new Box on each checkout.
#[allow(clippy::vec_box)]
pub(crate) struct RpcCodecPool {
    idle: Vec<Box<RpcCodec>>,
    max_idle: usize,
}

impl Default for RpcCodecPool {
    fn default() -> Self {
        crate::NetworkCounters::RpcCodecPoolIdle.set(0);
        Self { idle: Vec::new(), max_idle: MAX_IDLE_RPC_CODECS }
    }
}

impl RpcCodecPool {
    pub(crate) fn acquire(&mut self, direction: RpcCodecDirection) -> Box<RpcCodec> {
        let mut codec = self.idle.pop().unwrap_or_else(RpcCodec::allocate);
        crate::NetworkCounters::RpcCodecPoolIdle.set(self.idle.len() as u64);
        codec.enc.reset();
        codec.dec.reset_for_direct(matches!(direction, RpcCodecDirection::Outgoing));
        codec
    }

    pub(crate) fn release(&mut self, codec: Box<RpcCodec>) {
        if self.idle.len() < self.max_idle {
            self.idle.push(codec);
            crate::NetworkCounters::RpcCodecPoolIdle.set(self.idle.len() as u64);
        }
    }

    #[cfg(test)]
    fn with_max_idle(max_idle: usize) -> Self {
        Self { idle: Vec::new(), max_idle }
    }

    #[cfg(test)]
    pub(crate) fn idle_len(&self) -> usize {
        self.idle.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reuses_codec_and_reconfigures_decoder_direction() {
        let mut pool = RpcCodecPool::with_max_idle(1);
        let codec = pool.acquire(RpcCodecDirection::Incoming);
        let address = std::ptr::from_ref(codec.as_ref());
        assert!(!codec.dec.is_direct());
        pool.release(codec);

        let codec = pool.acquire(RpcCodecDirection::Outgoing);
        assert_eq!(std::ptr::from_ref(codec.as_ref()), address);
        assert!(codec.dec.is_direct());
        pool.release(codec);

        let codec = pool.acquire(RpcCodecDirection::Incoming);
        assert_eq!(std::ptr::from_ref(codec.as_ref()), address);
        assert!(!codec.dec.is_direct());
    }

    #[test]
    fn bounds_idle_codecs() {
        let mut pool = RpcCodecPool::with_max_idle(1);
        let first = pool.acquire(RpcCodecDirection::Incoming);
        let second = pool.acquire(RpcCodecDirection::Outgoing);

        pool.release(first);
        pool.release(second);

        assert_eq!(pool.idle_len(), 1);
    }
}
