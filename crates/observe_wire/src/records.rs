#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceClass {
    Counters = 0,
    TCache = 1,
    Timing = 2,
    Tile = 3,
}

/// `id` is assigned by the exporter and stable for one `boot_id`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Source<'a> {
    pub id: u16,
    pub class: SourceClass,
    pub name: &'a str,
}

/// One bucket of one tile's loop: busy/total ticks summed, plus
/// work-iteration count and the longest iteration.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TileUtil {
    pub source_id: u16,
    pub busy: u64,
    pub total: u64,
    pub busy_count: u64,
    pub busy_max: u64,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimingChannel {
    Latency = 0,
    Processing = 1,
}

/// One bucket of one timing channel's distribution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimingStats {
    pub source_id: u16,
    pub channel: TimingChannel,
    pub count: u64,
    pub p50_ns: u64,
    pub p99_ns: u64,
    pub max_ns: u64,
}
