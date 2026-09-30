use std::{path::Path, sync::atomic::Ordering};

use silver_stages::CounterValues;

pub struct Changed {
    pub index: usize,
    pub value: u64,
    pub previous: u64,
}

pub struct CounterDeltas {
    values: CounterValues,
    previous: Vec<u64>,
}

impl CounterDeltas {
    /// Without `from_zero` the first read is only the baseline, so what the
    /// file held before it was opened is never reported.
    pub fn open(path: &Path, from_zero: bool) -> Option<Self> {
        let values = CounterValues::open(path).ok()?;
        let previous = match from_zero {
            true => vec![0; values.values().len()],
            false => values.values().iter().map(|v| v.load(Ordering::Relaxed)).collect(),
        };
        Some(Self { values, previous })
    }

    /// The counters that changed since the previous call.
    pub fn changed(&mut self) -> impl Iterator<Item = Changed> {
        let counters = self.values.values().iter().zip(&mut self.previous).enumerate();
        counters.filter_map(|(index, (value, previous))| {
            let value = value.load(Ordering::Relaxed);
            if value == *previous {
                return None;
            }
            let changed = Changed { index, value, previous: *previous };
            *previous = value;
            Some(changed)
        })
    }
}
