use std::mem;

use super::SocketId;
use crate::NetworkCounters;

pub(super) struct RxPoolMetrics {
    socket: SocketId,
    capacity: u64,
    high_water: u64,
    consumed: u64,
    recycled: u64,
    no_buffers: u64,
    dirty: bool,
}

impl RxPoolMetrics {
    pub(super) fn new(socket: SocketId, capacity: u16) -> Self {
        Self {
            socket,
            capacity: u64::from(capacity),
            high_water: 0,
            consumed: 0,
            recycled: 0,
            no_buffers: 0,
            dirty: true,
        }
    }

    pub(super) fn publish(&mut self, in_use: usize) {
        if !self.dirty {
            return;
        }
        let [capacity, provided, used, high_water, consumed, recycled, no_buffers] =
            match self.socket {
                SocketId::Quic => [
                    NetworkCounters::UringQuicRxBuffersCapacity,
                    NetworkCounters::UringQuicRxBuffersProvided,
                    NetworkCounters::UringQuicRxBuffersInUse,
                    NetworkCounters::UringQuicRxBuffersHighWater,
                    NetworkCounters::UringQuicRxBuffersConsumed,
                    NetworkCounters::UringQuicRxBuffersRecycled,
                    NetworkCounters::UringQuicRxNoBuffers,
                ],
                SocketId::Discovery => [
                    NetworkCounters::UringDiscoveryRxBuffersCapacity,
                    NetworkCounters::UringDiscoveryRxBuffersProvided,
                    NetworkCounters::UringDiscoveryRxBuffersInUse,
                    NetworkCounters::UringDiscoveryRxBuffersHighWater,
                    NetworkCounters::UringDiscoveryRxBuffersConsumed,
                    NetworkCounters::UringDiscoveryRxBuffersRecycled,
                    NetworkCounters::UringDiscoveryRxNoBuffers,
                ],
            };
        capacity.set(self.capacity);
        provided.set(self.capacity - in_use as u64);
        used.set(in_use as u64);
        high_water.set(self.high_water);
        for (counter, delta) in [
            (consumed, mem::take(&mut self.consumed)),
            (recycled, mem::take(&mut self.recycled)),
            (no_buffers, mem::take(&mut self.no_buffers)),
        ] {
            if delta != 0 {
                counter.add(delta);
            }
        }
        self.dirty = false;
    }
}

#[cfg(all(target_os = "linux", feature = "io-uring"))]
impl RxPoolMetrics {
    pub(super) fn consumed(&mut self, in_use: usize) {
        self.consumed += 1;
        self.high_water = self.high_water.max(in_use as u64);
        self.dirty = true;
    }

    pub(super) fn recycled(&mut self, count: usize) {
        self.recycled += count as u64;
        self.dirty |= count != 0;
    }

    pub(super) fn no_buffers(&mut self) {
        self.no_buffers += 1;
        self.dirty = true;
    }

    pub(super) fn close(&mut self) {
        self.capacity = 0;
        self.high_water = 0;
        self.dirty = true;
        self.publish(0);
    }
}
