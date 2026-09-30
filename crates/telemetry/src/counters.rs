//! One row per exported `declare_counters!` counter per slot its value moved
//! in. Values persist across node restarts, so no run tracking is needed.

use std::sync::atomic::Ordering;

use flux::utils::directories::shmem_dir_queues;
use serde::Serialize;
use silver_common::APP_NAME;
use silver_stages::{CounterValues, counter_names};

use crate::node_meta::NodeMeta;

pub const TABLE: &str = "counters";

pub const DDL: &str = "CREATE TABLE IF NOT EXISTS counters (
    slot                 UInt64                 COMMENT 'Slot the row covers',
    slot_start_date_time DateTime               COMMENT 'Wall clock the slot started at',
    component            LowCardinality(String) COMMENT 'The counters-{component} file',
    name                 LowCardinality(String) COMMENT 'Counter variant',
    value                UInt64                 COMMENT 'Value at the end of the slot',
    delta                Int64                  COMMENT 'Change during the slot; negative for a falling gauge',
    version              LowCardinality(String) COMMENT 'Commit the node was built from',
    meta_client_name     LowCardinality(String) COMMENT 'Hostname of the node that produced the row',
    meta_network_name    LowCardinality(String) COMMENT 'Ethereum network the node is running'
) ENGINE = MergeTree
ORDER BY (meta_client_name, component, name, slot)";

const EXPORTED: [&str; 7] =
    ["beacon_state", "columns", "control", "network", "peer", "storage", "tcache"];

#[derive(Serialize)]
pub struct CounterRow<'a> {
    slot: u64,
    slot_start_date_time: u32,
    component: &'static str,
    name: &'static str,
    value: u64,
    delta: i64,
    version: &'a str,
    meta_client_name: &'a str,
    meta_network_name: &'a str,
}

/// Opened once the node has created its file; the first read only sets the
/// baseline.
struct Component {
    name: &'static str,
    counter_names: &'static [&'static str],
    values: Option<CounterValues>,
    previous: Vec<u64>,
}

impl Component {
    fn new(name: &'static str) -> Self {
        let counter_names = counter_names(name).expect("exported component has names");
        Self { name, counter_names, values: None, previous: Vec::new() }
    }

    fn rows<'a>(&mut self, slot: u64, meta: &'a NodeMeta, rows: &mut Vec<CounterRow<'a>>) {
        if self.values.is_none() {
            let path = shmem_dir_queues(APP_NAME).join(format!("counters-{}", self.name));
            self.values = CounterValues::open(&path).ok();
            self.previous = self.snapshot();
            return;
        }
        for (index, value) in self.snapshot().into_iter().enumerate() {
            let previous = self.previous[index];
            if value == previous {
                continue;
            }
            self.previous[index] = value;
            let Some(&name) = self.counter_names.get(index) else { continue };
            rows.push(CounterRow {
                slot,
                slot_start_date_time: meta.clock.slot_start(slot).as_secs_u64() as u32,
                component: self.name,
                name,
                value,
                delta: value.wrapping_sub(previous) as i64,
                version: &meta.version,
                meta_client_name: &meta.node,
                meta_network_name: &meta.network,
            });
        }
    }

    fn snapshot(&self) -> Vec<u64> {
        self.values.iter().flat_map(|v| v.values()).map(|v| v.load(Ordering::Relaxed)).collect()
    }
}

pub struct Counters {
    components: Vec<Component>,
}

impl Default for Counters {
    fn default() -> Self {
        Self { components: EXPORTED.into_iter().map(Component::new).collect() }
    }
}

impl Counters {
    pub fn rows<'a>(&mut self, slot: u64, meta: &'a NodeMeta) -> Vec<CounterRow<'a>> {
        let mut rows = Vec::new();
        for component in &mut self.components {
            component.rows(slot, meta, &mut rows);
        }
        rows
    }
}
