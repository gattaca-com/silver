//! The DA capture's on-disk layout and schedule format, in one place: the
//! collector (`just da-fixtures`) writes it, the replay (`just da-local`) reads
//! it. Splitting that knowledge is how the schedule and the files drift apart.
//!
//! ```text
//! crates/e2e/data/da/
//!   finalized_state.ssz          anchor checkpoint, within the proposer
//!                                lookahead of the window
//!   columns/<slot>_<index>.ssz   sidecars, named by the schedule
//!   schedule.tsv                 `slot \t column_index \t unix_us`
//! ```

use std::{collections::BTreeMap, fs, path::PathBuf};

use silver_beacon_state_data::SpecConfig;

use crate::fixtures::FixtureRoot;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Arrival {
    pub at_us: u64,
    pub index: u64,
}

#[derive(Default)]
pub struct SlotCapture {
    pub arrivals: Vec<Arrival>,
    pub sidecars: BTreeMap<u64, Vec<u8>>,
}

/// The index `fraction` of the way through `len` ascending samples — an order
/// statistic, so `0.5` of a custody set is the column a gate reconstructing
/// from half would wait for.
pub fn order_index(len: usize, fraction: f64) -> Option<usize> {
    Some((fraction * len.checked_sub(1)? as f64).round() as usize)
}

impl SlotCapture {
    /// Microseconds into the slot by which `fraction` of the custody set had
    /// arrived.
    pub fn arrival_percentile(&self, fraction: f64) -> Option<u64> {
        let index = order_index(self.arrivals.len(), fraction)?;
        self.arrivals.get(index).map(|a| a.at_us)
    }

    /// Emulating a node that custodies less than everything: only its own
    /// subnets reach it, so both the arrivals and the completion target shrink.
    pub fn retain_custody(&mut self, custody: u128) {
        self.arrivals.retain(|a| custody & (1 << a.index) != 0);
        self.sidecars.retain(|index, _| custody & (1 << index) != 0);
    }

    /// A slot whose columns turned up after it ended was served over RPC while
    /// the node caught up; its curve is not a gossip arrival curve.
    pub fn is_backfill(&self) -> bool {
        let slot_us = SpecConfig::mainnet().seconds_per_slot() * 1_000_000;
        self.arrivals.first().is_some_and(|a| a.at_us > slot_us)
    }
}

pub struct Capture {
    pub state: Vec<u8>,
    pub slots: BTreeMap<u64, SlotCapture>,
}

impl Capture {
    /// A slot outside the custody set entirely has nothing left to replay.
    pub fn retain_custody(&mut self, custody: u128) {
        self.slots.values_mut().for_each(|slot| slot.retain_custody(custody));
        self.slots.retain(|_, slot| !slot.sidecars.is_empty());
    }
}

pub struct ColumnFixtures(FixtureRoot);

impl ColumnFixtures {
    pub fn da() -> Self {
        Self(FixtureRoot::new("DA_FIXTURES", "data/da"))
    }

    pub fn root(&self) -> &FixtureRoot {
        &self.0
    }

    pub fn columns(&self) -> PathBuf {
        self.0.join("columns")
    }

    pub fn schedule(&self) -> PathBuf {
        self.0.join("schedule.tsv")
    }

    pub fn sidecar(&self, slot: u64, index: u64) -> PathBuf {
        self.columns().join(format!("{slot}_{index}.ssz"))
    }

    /// Every slot the schedule names, with its sidecars read off disk and its
    /// timestamps rebased onto the slot's own start, so an arrival reads as the
    /// `ms into slot` prod telemetry reports.
    pub fn load(&self) -> Capture {
        let (state, _) = self.0.read_finalized_state().unwrap_or_else(|e| panic!("{e}"));

        // `genesis_time` is the state's first field, and the only thing needed to
        // turn an absolute arrival into an offset into its slot.
        let genesis = u64::from_le_bytes(state[..8].try_into().expect("state holds genesis_time"));
        let spec = SpecConfig::mainnet();

        let mut slots = BTreeMap::new();
        let tsv = fs::read_to_string(self.schedule()).expect("schedule.tsv");
        for line in tsv.lines() {
            let fields: Vec<&str> = line.split('\t').collect();
            let [slot, index, at] = fields[..] else { panic!("malformed schedule row: {line}") };
            let entry = slots
                .entry(slot.parse().expect("schedule slot"))
                .or_insert_with(SlotCapture::default);
            entry.arrivals.push(Arrival {
                at_us: at.parse().expect("schedule timestamp"),
                index: index.parse().expect("column index"),
            });
        }

        for (slot, cap) in &mut slots {
            cap.arrivals.sort_unstable();
            // `column_recv` records every copy a peer sent, and a supernode sees
            // each column ~3 times. Availability turns on the first of each, and
            // replaying the rest would only measure the duplicate path.
            let mut seen = 0u128;
            cap.arrivals.retain(|a| {
                let first = seen & (1 << a.index) == 0;
                seen |= 1 << a.index;
                first
            });
            let slot_start_us = (genesis + slot * spec.seconds_per_slot()) * 1_000_000;
            for arrival in &mut cap.arrivals {
                let at = arrival.at_us;
                assert!(
                    at >= slot_start_us,
                    "slot {slot} arrival {at} precedes the slot — the schedule holds relative \
                     timestamps, so recollect it with `just da-fixtures`"
                );
                arrival.at_us -= slot_start_us;
            }

            for arrival in &cap.arrivals {
                let path = self.sidecar(*slot, arrival.index);
                let ssz = fs::read(&path)
                    .unwrap_or_else(|e| panic!("{}: {e} — recollect the capture", path.display()));
                cap.sidecars.insert(arrival.index, ssz);
            }
        }
        Capture { state, slots }
    }
}

/// One `COL` row per sidecar at its arrival. Absolute microseconds: at
/// millisecond resolution a burst of sidecars collapses into one arrival and
/// the tile flushes them as one batch, which is the cost the replay exists to
/// measure. Only gossip-delivered sidecars are recorded, so a slot that
/// completed over RPC or from EL blobs comes out short of its custody set.
pub fn schedule_query(node: &str, first: u64, last: u64) -> String {
    format!(
        "SELECT slot, column_index, toUnixTimestamp64Micro(event_date_time) AS us
         FROM block_events
         WHERE stage = 'column_recv' AND meta_client_name = '{node}'
           AND slot BETWEEN {first} AND {last}
         ORDER BY slot, us FORMAT TSV"
    )
}
