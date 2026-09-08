//! `thresholds.json`: one ceiling per `#[timed]` frame statistic.

use std::fmt;

use silver_common::Nanos;
use silver_metrics::TimingStats;

#[derive(Clone, Copy, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Stat {
    Total,
    Avg,
    P50,
    Max,
}

impl Stat {
    pub fn measure(self, stats: &TimingStats, frame: &str) -> Option<Nanos> {
        match self {
            Stat::Total => {
                let (sum, count) = stats.aggregate_leaf(frame);
                (count > 0).then_some(sum)
            }
            Stat::Avg => {
                let (sum, count) = stats.aggregate_leaf(frame);
                (count > 0).then(|| sum / count)
            }
            Stat::P50 => stats.aggregate_leaf_p50(frame),
            Stat::Max => stats.aggregate_leaf_max(frame),
        }
    }
}

impl fmt::Display for Stat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Stat::Total => "total",
            Stat::Avg => "avg",
            Stat::P50 => "p50",
            Stat::Max => "max",
        })
    }
}

/// `frame` is the full `#[timed]` label, generics included; a `null` `max`
/// lists the row without gating on it.
#[derive(Clone, serde::Deserialize)]
pub struct Threshold {
    pub frame: String,
    pub stat: Stat,
    #[serde(default, deserialize_with = "de_duration")]
    pub max: Option<Nanos>,
}

impl Threshold {
    /// `stage_and_import<BeaconStateTile>` at p50 → `stage_and_import (p50)`.
    pub fn label(&self) -> String {
        let name = self.frame.split('<').next().unwrap_or(&self.frame);
        format!("{name} ({})", self.stat)
    }
}

/// Accepts `"2.5s" | "500ms" | "100us" | "100µs" | "100ns"` (or `null`).
/// Rejects bare numbers — the unit is mandatory so the file stays
/// self-documenting (`Nanos`' own deserializer would silently read a bare
/// number as nanoseconds, so we keep this stricter parser).
fn de_duration<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Nanos>, D::Error> {
    use serde::Deserialize;
    let s: Option<String> = Option::deserialize(d)?;
    s.map(|s| parse_duration_ns(s.as_str()).map(Nanos).map_err(serde::de::Error::custom))
        .transpose()
}

fn parse_duration_ns(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let split = s
        .find(|c: char| c.is_alphabetic() || c == 'µ')
        .filter(|&i| i > 0)
        .ok_or_else(|| format!("missing unit in {s:?} (expected e.g. \"2.5s\")"))?;
    let n: f64 = s[..split].trim().parse().map_err(|e| format!("number in {s:?}: {e}"))?;
    let mult: f64 = match s[split..].trim() {
        "ns" => 1.0,
        "us" | "µs" => 1_000.0,
        "ms" => 1_000_000.0,
        "s" => 1_000_000_000.0,
        u => return Err(format!("unknown unit {u:?} in {s:?} (expected ns|us|ms|s)")),
    };
    Ok((n * mult).round() as u64)
}
