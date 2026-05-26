//! Consumer for a flux `tilemetrics-{name}` SPMC queue. Each
//! `TileSample` represents a 1024-iteration window of one tile's loop:
//! total ticks, busy ticks, busy/avg/min/max per work-iter, loop_count.
//! Surfer keeps the latest sample for the live table plus a ring of
//! the last N utilisation values for a sparkline.

use std::collections::VecDeque;

use flux::{
    communication::queue::{ConsumerBare, Queue},
    tile::metrics::TileSample,
};

use crate::{discovery::TileMetricsFile, sources::counters::BUCKET_HISTORY_LEN};

pub struct TileMetricsSet {
    pub name: String,
    consumer: ConsumerBare<TileSample>,
    pub latest: TileSample,
    /// Utilisation ratio (0.0-1.0) per sample observed. Same depth as
    /// counter/timing rings for visual consistency.
    pub utilisation_hist: VecDeque<f64>,
    pub samples_seen: u64,
}

impl TileMetricsSet {
    pub fn open(file: &TileMetricsFile) -> Result<Self, String> {
        let queue: Queue<TileSample> = Queue::try_open_shared(&file.path)
            .map_err(|e| format!("open_shared({:?}): {e:?}", file.path))?;
        let label: &'static str = Box::leak(format!("surfer-{}", file.name).into_boxed_str());
        let consumer = ConsumerBare::<TileSample>::new(queue, label);
        Ok(Self {
            name: file.name.clone(),
            consumer,
            latest: TileSample::default(),
            utilisation_hist: VecDeque::with_capacity(BUCKET_HISTORY_LEN),
            samples_seen: 0,
        })
    }

    /// Drain everything currently available.
    pub fn drain(&mut self) {
        let mut sample = TileSample::default();
        while self.consumer.try_consume(&mut sample).is_ok() {
            self.latest = sample;
            self.samples_seen += 1;
            if self.utilisation_hist.len() == BUCKET_HISTORY_LEN {
                self.utilisation_hist.pop_front();
            }
            self.utilisation_hist.push_back(sample.utilisation());
        }
    }
}
