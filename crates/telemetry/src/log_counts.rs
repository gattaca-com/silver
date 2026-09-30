//! One row per WARN/ERROR callsite per slot it logged in, labelled with its
//! format string. The messages themselves stay in the node's log file.

use std::path::Path;

use serde::Serialize;
use silver_common::APP_NAME;
use silver_log::counts::{LogName, counters_path, names_path};

use crate::{counter_deltas::CounterDeltas, node_meta::NodeMeta};

pub const TABLE: &str = "log_counts";

pub const DDL: &str = "CREATE TABLE IF NOT EXISTS log_counts (
    slot                 UInt64                 COMMENT 'Slot the count covers',
    slot_start_date_time DateTime               COMMENT 'Wall clock the slot started at',
    level                LowCardinality(String),
    file                 LowCardinality(String),
    line                 UInt32,
    template             LowCardinality(String) COMMENT 'Format string of the logging call',
    count                UInt64                 COMMENT 'Events logged in the slot',
    version              LowCardinality(String) COMMENT 'Commit the node was built from',
    meta_client_name     LowCardinality(String) COMMENT 'Hostname of the node that produced the row',
    meta_network_name    LowCardinality(String) COMMENT 'Ethereum network the node is running'
) ENGINE = MergeTree
ORDER BY (meta_client_name, level, file, line, slot)";

#[derive(Serialize)]
pub struct LogCountRow<'a> {
    slot: u64,
    slot_start_date_time: u32,
    level: &'a str,
    file: &'a str,
    line: u32,
    template: &'a str,
    count: u64,
    version: &'a str,
    meta_client_name: &'a str,
    meta_network_name: &'a str,
}

/// One node run's counters with the names they were created under.
struct Run {
    deltas: CounterDeltas,
    names: Vec<LogName>,
}

impl Run {
    fn open(counters: &Path, names: &Path, from_zero: bool) -> Option<Self> {
        let deltas = CounterDeltas::open(counters, from_zero)?;
        Some(Self { deltas, names: LogName::read(names).ok()? })
    }

    fn rows<'a>(&'a mut self, slot: u64, meta: &'a NodeMeta) -> Vec<LogCountRow<'a>> {
        let Self { deltas, names } = self;
        let mut rows = Vec::new();
        for changed in deltas.changed() {
            let Some(name) = names.get(changed.index) else { continue };
            rows.push(LogCountRow {
                slot,
                slot_start_date_time: meta.clock.slot_start(slot).as_secs_u64() as u32,
                level: &name.level,
                file: &name.file,
                line: name.line,
                template: &name.template,
                count: changed.value - changed.previous,
                version: &meta.version,
                meta_client_name: &meta.node,
                meta_network_name: &meta.network,
            });
        }
        rows
    }
}

#[derive(Default)]
pub struct LogCounts {
    run: Option<Run>,
    restarted: bool,
}

impl LogCounts {
    /// A starting node recreates its counters, so the next run is read from
    /// zero. A run already underway when the daemon attaches starts from its
    /// current counts, so its history is not reported as one slot's worth.
    pub fn node_restarted(&mut self) {
        self.run = None;
        self.restarted = true;
    }

    pub fn rows<'a>(&'a mut self, slot: u64, meta: &'a NodeMeta) -> Vec<LogCountRow<'a>> {
        if self.run.is_none() {
            let (counters, names) = (counters_path(APP_NAME), names_path(APP_NAME));
            self.run = Run::open(&counters, &names, self.restarted);
        }
        self.run.as_mut().map(|run| run.rows(slot, meta)).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use silver_stages::SlotClock;
    use tempfile::TempDir;

    use super::*;

    fn meta() -> NodeMeta {
        NodeMeta {
            node: "n".into(),
            network: "net".into(),
            clock: SlotClock::new(0, 12_000),
            version: String::new(),
        }
    }

    /// Stands in for the node: counters as the raw file, names one per line.
    fn write(dir: &Path, counts: &[u64]) {
        let bytes: Vec<_> = counts.iter().flat_map(|c| c.to_le_bytes()).collect();
        fs::write(dir.join("counters"), bytes).unwrap();
        let names: String =
            (0..counts.len()).map(|i| format!("ERROR\tf.rs\t{i}\tt{i}\n")).collect();
        fs::write(dir.join("names"), names).unwrap();
    }

    fn open(dir: &Path, from_zero: bool) -> Run {
        Run::open(&dir.join("counters"), &dir.join("names"), from_zero).unwrap()
    }

    fn templates(rows: Vec<LogCountRow<'_>>) -> Vec<(String, u64)> {
        rows.into_iter().map(|r| (r.template.to_owned(), r.count)).collect()
    }

    #[test]
    fn attach_skips_history() {
        let dir = TempDir::new().unwrap();
        write(dir.path(), &[5, 0]);
        let meta = meta();
        let mut run = open(dir.path(), false);
        assert!(run.rows(1, &meta).is_empty());

        write(dir.path(), &[5, 2]);
        assert_eq!(templates(run.rows(2, &meta)), [("t1".to_owned(), 2)]);
    }

    #[test]
    fn restart_counts_from_zero() {
        let dir = TempDir::new().unwrap();
        write(dir.path(), &[3, 0]);
        let meta = meta();
        let mut run = open(dir.path(), true);
        assert_eq!(templates(run.rows(1, &meta)), [("t0".to_owned(), 3)]);
    }
}
