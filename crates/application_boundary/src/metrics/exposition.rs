use std::fmt::{self, Write};

pub(super) struct Family {
    part: usize,
    name: &'static str,
    kind: &'static str,
    help: &'static str,
}

const fn family(part: usize, name: &'static str, kind: &'static str, help: &'static str) -> Family {
    Family { part, name, kind, help }
}

const FAMILIES: usize = 13;

pub(super) const EVENTS: Family =
    family(0, "silver_events_total", "counter", "Cumulative value of a Silver counter.");
pub(super) const CURRENT_VALUE: Family =
    family(1, "silver_current_value", "gauge", "Current value of a Silver gauge.");
pub(super) const RAW_SLOT: Family =
    family(2, "silver_slot", "untyped", "Raw value from an unregistered counter slot.");
const TIMER_DURATION: Family = family(
    3,
    "silver_timer_duration_seconds",
    "histogram",
    "Observed durations from Flux timer queues.",
);
pub(super) const TILE_BUSY: Family = family(
    4,
    "silver_tile_busy_seconds_total",
    "counter",
    "Observed time spent performing tile work.",
);
pub(super) const TILE_OBSERVED: Family = family(
    5,
    "silver_tile_observed_seconds_total",
    "counter",
    "Total duration of observed tile samples.",
);
pub(super) const TILE_ITERATIONS: Family = family(
    6,
    "silver_tile_busy_iterations_total",
    "counter",
    "Tile iterations that performed work.",
);
pub(super) const TILE_UTILISATION: Family = family(
    7,
    "silver_tile_utilisation_ratio",
    "gauge",
    "Fraction of observed time busy in the last collection window.",
);
pub(super) const TILE_BUSY_MAX: Family = family(
    8,
    "silver_tile_busy_max_seconds",
    "gauge",
    "Longest busy iteration in the last collection window.",
);
pub(super) const BUILD_INFO: Family =
    family(9, "silver_build_info", "gauge", "Silver node build information.");
pub(super) const TCACHE_CAPACITY: Family =
    family(10, "silver_tcache_capacity_bytes", "gauge", "TCache capacity in bytes.");
pub(super) const TCACHE_HEAD: Family =
    family(11, "silver_tcache_head_sequence", "gauge", "Current TCache producer sequence.");
pub(super) const TCACHE_TAIL: Family =
    family(12, "silver_tcache_tail_sequence", "gauge", "Current TCache consumer sequence.");

/// One part per family keeps each family contiguous. Cleared parts keep
/// their capacity, so a reused snapshot renders without allocating.
#[derive(Default)]
pub(super) struct Snapshot {
    pub parts: [String; FAMILIES],
    pub len: usize,
}

impl Snapshot {
    pub fn clear(&mut self) {
        self.parts.iter_mut().for_each(String::clear);
        self.len = 0;
    }

    fn family(&mut self, family: &Family) -> &mut String {
        let Family { part, name, kind, help } = family;
        let part = &mut self.parts[*part];
        if part.is_empty() {
            write!(part, "# HELP {name} {help}\n# TYPE {name} {kind}\n").unwrap();
        }
        part
    }

    pub fn sample(&mut self, family: &Family, labels: &str, value: impl fmt::Display) {
        let name = family.name;
        writeln!(self.family(family), "{name}{{{labels}}} {value}").unwrap();
    }

    pub fn finish(&mut self) {
        self.len = self.parts.iter().map(String::len).sum();
    }
}

pub(super) fn escape(label: &str) -> String {
    label.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n")
}

const BOUNDS_NS: [u64; 9] = [
    1_000,
    10_000,
    100_000,
    1_000_000,
    10_000_000,
    100_000_000,
    1_000_000_000,
    10_000_000_000,
    60_000_000_000,
];

#[derive(Default)]
pub(super) struct Histogram {
    bins: [u64; 10],
    sum_ns: u128,
}

impl Histogram {
    pub fn record(&mut self, ns: u64) {
        self.bins[BOUNDS_NS.partition_point(|&limit| limit < ns)] += 1;
        self.sum_ns += u128::from(ns);
    }

    pub fn encode(&self, text: &mut Snapshot, labels: &str) {
        let name = TIMER_DURATION.name;
        let out = text.family(&TIMER_DURATION);
        let mut count = 0;
        for (ns, hits) in BOUNDS_NS.iter().zip(self.bins) {
            count += hits;
            writeln!(out, "{name}_bucket{{{labels},le=\"{}\"}} {count}", *ns as f64 / 1e9).unwrap();
        }
        count += self.bins[BOUNDS_NS.len()];
        writeln!(out, "{name}_bucket{{{labels},le=\"+Inf\"}} {count}").unwrap();
        writeln!(out, "{name}_sum{{{labels}}} {}", self.sum_ns as f64 / 1e9).unwrap();
        writeln!(out, "{name}_count{{{labels}}} {count}").unwrap();
    }
}
