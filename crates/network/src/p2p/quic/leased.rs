use std::{
    cell::Cell,
    ops::Deref,
    ptr::NonNull,
    time::{Duration, Instant},
};

/// End-to-end age after which outbound gossip delivery is stale, measured from
/// enqueue until Quinn releases every owner after ACK or teardown. Expiry is
/// rounded up to the next wheel tick, so detection occurs within one
/// additional second.
pub(crate) const GOSSIP_DELIVERY_TIMEOUT: Duration = Duration::from_secs(10);
pub(crate) const OUTBOUND_LEASE_TICK: Duration = Duration::from_secs(1);
const OUTBOUND_LEASE_BUCKETS: usize = 32;

/// Per-peer timer wheel for outbound delivery leases. The allocation keeps
/// every counter at a stable address while `Peer` moves in its hash map.
/// Access is confined to NetworkTile, so the counters are `Cell`s rather than
/// atomics.
pub(crate) struct OutboundLeaseWheel {
    counts: [Cell<u32>; OUTBOUND_LEASE_BUCKETS],
    /// Bucket inspected at `next_tick`.
    head: Cell<usize>,
    next_tick: Cell<Instant>,
    /// Set once the connection starts teardown. Buckets are never reused after
    /// this point, but late Quinn drops still decrement their original count.
    terminal: Cell<bool>,
}

impl OutboundLeaseWheel {
    pub(crate) fn new(now: Instant) -> Self {
        Self {
            counts: std::array::from_fn(|_| Cell::new(0)),
            head: Cell::new(0),
            next_tick: Cell::new(now + OUTBOUND_LEASE_TICK),
            terminal: Cell::new(false),
        }
    }

    pub(crate) fn leased<T>(&self, value: T, now: Instant) -> Leased<T> {
        Leased { value, lease: self.lease(now) }
    }

    pub(crate) fn lease(&self, now: Instant) -> OutboundLease {
        assert!(!self.terminal.get(), "cannot acquire a terminal outbound lease wheel");
        assert!(
            now < self.next_tick.get(),
            "outbound lease wheel must be advanced before acquiring"
        );

        // Round up to a bucket boundary so a lease never expires early.
        let until = (now + GOSSIP_DELIVERY_TIMEOUT).saturating_duration_since(self.next_tick.get());
        let tick_nanos = OUTBOUND_LEASE_TICK.as_nanos();
        let ticks = until.as_nanos().div_ceil(tick_nanos) as usize;
        assert!(ticks < OUTBOUND_LEASE_BUCKETS, "delivery timeout exceeds wheel horizon");

        let bucket = (self.head.get() + ticks) % OUTBOUND_LEASE_BUCKETS;
        self.increment(bucket);
        OutboundLease { wheel: NonNull::from(self), bucket }
    }

    fn increment(&self, bucket: usize) {
        let count = &self.counts[bucket];
        count.set(count.get().checked_add(1).expect("outbound lease count overflow"));
    }

    /// Process every elapsed bucket. A non-zero expired bucket is terminal:
    /// callers close the peer, so it is neither cleared nor reused while late
    /// `Bytes` drops may still refer to it.
    pub(crate) fn expire(&self, now: Instant) -> Option<u32> {
        if self.terminal.get() {
            return None;
        }
        if now < self.next_tick.get() {
            return None;
        }

        // With no leases there is no phase to preserve. Rebase directly after
        // a long idle period instead of rotating once per elapsed second.
        if self.counts.iter().all(|count| count.get() == 0) {
            if now >= self.next_tick.get() {
                self.head.set(0);
                self.next_tick.set(now + OUTBOUND_LEASE_TICK);
            }
            return None;
        }

        while now >= self.next_tick.get() {
            let head = self.head.get();
            let retained = self.counts[head].get();
            if retained != 0 {
                self.terminal.set(true);
                return Some(retained);
            }
            self.head.set((head + 1) % OUTBOUND_LEASE_BUCKETS);
            self.next_tick.set(self.next_tick.get() + OUTBOUND_LEASE_TICK);
        }
        None
    }

    pub(crate) fn deadline(&self) -> Option<Instant> {
        if self.terminal.get() {
            return None;
        }
        self.counts.iter().enumerate().find_map(|(offset, _)| {
            let bucket = (self.head.get() + offset) % OUTBOUND_LEASE_BUCKETS;
            (self.counts[bucket].get() != 0)
                .then_some(self.next_tick.get() + OUTBOUND_LEASE_TICK * offset as u32)
        })
    }

    pub(crate) fn terminate(&self) {
        self.terminal.set(true);
    }

    #[cfg(test)]
    pub(crate) fn is_terminal(&self) -> bool {
        self.terminal.get()
    }

    pub(crate) fn active_count(&self) -> u64 {
        self.counts.iter().map(|count| u64::from(count.get())).sum()
    }
}

impl Drop for OutboundLeaseWheel {
    fn drop(&mut self) {
        debug_assert_eq!(self.active_count(), 0, "outbound lease wheel dropped with active leases");
    }
}

#[derive(Debug)]
pub(crate) struct OutboundLease {
    wheel: NonNull<OutboundLeaseWheel>,
    bucket: usize,
}

// SAFETY: `Bytes::from_owner` requires its owner to be `Send`, but all
// creation and destruction remains confined to NetworkTile. The wheel
// outlives every lease by `Peer` field drop order, documented on its field.
unsafe impl Send for OutboundLease {}

impl Clone for OutboundLease {
    fn clone(&self) -> Self {
        // SAFETY: the boxed wheel has a stable address and outlives every
        // root and child lease.
        unsafe { self.wheel.as_ref() }.increment(self.bucket);
        Self { wheel: self.wheel, bucket: self.bucket }
    }
}

impl Drop for OutboundLease {
    fn drop(&mut self) {
        // SAFETY: the boxed wheel has a stable address and is declared after
        // every Peer field that can contain a Quinn-owned `Bytes` clone.
        let wheel = unsafe { self.wheel.as_ref() };
        let count = &wheel.counts[self.bucket];
        count.set(count.get().checked_sub(1).expect("outbound lease count underflow"));
    }
}

/// Value carrying one reference to its original enqueue-time delivery lease.
/// Moving the wrapper preserves the lease; `child` deliberately forks another
/// reference in the same timeout bucket for a Quinn-owned body segment.
#[derive(Debug)]
pub(crate) struct Leased<T> {
    value: T,
    lease: OutboundLease,
}

impl<T> Leased<T> {
    pub(crate) fn child<U>(&self, value: U) -> Leased<U> {
        Leased { value, lease: self.lease.clone() }
    }
}

impl<T> Deref for Leased<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for Leased<T> {
    fn as_ref(&self) -> &[u8] {
        self.value.as_ref()
    }
}
