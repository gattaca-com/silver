use std::time::{Duration, Instant};

use silver_metrics::{
    TimingStats, fold_stats,
    profiler::{CrossProcessReader, published_pid},
};

const DRAIN_BUDGET: Duration = Duration::from_millis(20);

pub struct Flamegraph {
    reader: Option<CrossProcessReader>,
    stats: Option<TimingStats>,
    tree: String,
    scroll: u16,
    /// When set, stop polling/folding so the tree holds still for reading — a
    /// live producer otherwise keeps growing the cumulative tree every tick.
    paused: bool,
}

impl Flamegraph {
    pub fn attach(app_name: &str) -> Self {
        Self {
            reader: CrossProcessReader::attach(app_name),
            stats: None,
            tree: String::new(),
            scroll: 0,
            paused: false,
        }
    }

    pub fn sample(&mut self) {
        if self.paused {
            return;
        }
        let Some(reader) = &mut self.reader else { return };
        let deadline = Instant::now() + DRAIN_BUDGET;
        while reader.poll() && Instant::now() < deadline {}
    }

    pub fn roll_bucket(&mut self) {
        if self.paused {
            return;
        }
        let Some(reader) = &mut self.reader else { return };
        let drained = fold_stats(reader.events());
        reader.release();

        let stats = match &mut self.stats {
            Some(held) => {
                held.merge(drained);
                held
            }
            empty => empty.insert(drained),
        };
        self.tree = stats.call_tree();
    }

    pub fn scroll_by(&mut self, dir: i32) {
        self.scroll = self.scroll.saturating_add_signed(dir as i16);
    }

    pub fn toggle_pause(&mut self) {
        self.paused = !self.paused;
    }

    /// Drop the accumulator and start a fresh cumulative window from now —
    /// sheds one-time boot frames so steady-state stands out.
    pub fn clear(&mut self, app_name: &str) {
        self.reattach(app_name);
        self.paused = false;
    }

    /// Reattach when a fresh pid is published — surfer started before the
    /// producer, or the producer restarted with a new pid and new rings.
    pub fn reattach_if_restarted(&mut self, app_name: &str) {
        if let Some(pid) = published_pid(app_name) {
            if self.reader.as_ref().map(CrossProcessReader::pid) != Some(pid) {
                self.reattach(app_name);
            }
        }
    }

    fn reattach(&mut self, app_name: &str) {
        self.reader = CrossProcessReader::attach(app_name);
        self.stats = None;
        self.tree.clear();
        self.scroll = 0;
    }

    pub fn is_attached(&self) -> bool {
        self.reader.is_some()
    }

    pub fn tree(&self) -> &str {
        &self.tree
    }

    pub fn paused(&self) -> bool {
        self.paused
    }

    pub fn scroll(&self) -> u16 {
        self.scroll
    }
}
