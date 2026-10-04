use std::{fs::OpenOptions, io::Write};

use hdrhistogram::Histogram;
use serde::Serialize;
use serde_json::json;

use crate::args::Args;

/// Nanosecond histogram bounded at 10 s, 3 significant figures.
pub struct Latency(Histogram<u64>);

impl Latency {
    pub fn new() -> Self {
        Self(Histogram::new_with_bounds(1, 10_000_000_000, 3).expect("histogram bounds"))
    }

    pub fn record(&mut self, ns: u64) {
        self.0.saturating_record(ns.max(1));
    }

    pub fn summary(&self) -> LatencySummary {
        let us = |ns: u64| ns as f64 / 1e3;
        let at = |quantile| us(self.0.value_at_quantile(quantile));
        LatencySummary {
            count: self.0.len(),
            min_us: us(self.0.min()),
            mean_us: self.0.mean() / 1e3,
            p50_us: at(0.50),
            p90_us: at(0.90),
            p99_us: at(0.99),
            p999_us: at(0.999),
            max_us: us(self.0.max()),
        }
    }
}

#[derive(Serialize)]
pub struct LatencySummary {
    count: u64,
    min_us: f64,
    mean_us: f64,
    p50_us: f64,
    p90_us: f64,
    p99_us: f64,
    p999_us: f64,
    max_us: f64,
}

/// Prints the run as pretty JSON and appends one line to `--json`, if set.
pub fn emit(args: &Args, results: &impl Serialize) {
    let record = json!({ "config": args, "results": results });
    println!("{}", serde_json::to_string_pretty(&record).expect("serialize report"));
    let Some(path) = &args.json else { return };
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .unwrap_or_else(|error| panic!("open {}: {error}", path.display()));
    writeln!(file, "{record}").expect("append report");
}
