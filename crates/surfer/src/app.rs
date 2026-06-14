use std::collections::HashSet;

use ratatui::widgets::TableState;

use crate::{
    discovery::DiscoveredSources,
    sources::{
        counters::CounterSet, perf::PerfSet, tilemetrics::TileMetricsSet, timings::TimingSet,
    },
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Pane {
    Counters,
    TCaches,
    Timings,
    Tiles,
    Perf,
}

impl Pane {
    pub fn label(self) -> &'static str {
        match self {
            Pane::Counters => "Counters",
            Pane::TCaches => "TCaches",
            Pane::Timings => "Timings",
            Pane::Tiles => "Tiles",
            Pane::Perf => "Perf",
        }
    }

    pub fn next(self) -> Self {
        match self {
            Pane::Counters => Pane::TCaches,
            Pane::TCaches => Pane::Timings,
            Pane::Timings => Pane::Tiles,
            Pane::Tiles => Pane::Perf,
            Pane::Perf => Pane::Counters,
        }
    }
}

pub struct App {
    pub pane: Pane,
    pub counters: Vec<CounterSet>,
    /// Currently selected (counter_set_idx, slot_idx) inside the counters pane.
    pub counters_selection: (usize, usize),
    pub tcaches: Vec<CounterSet>,
    pub tcaches_selection: usize,
    pub timings: Vec<TimingSet>,
    /// Selected timing-set index inside the timings pane.
    pub timings_selection: usize,
    pub tilemetrics: Vec<TileMetricsSet>,
    pub tiles_selection: usize,
    pub perf: Vec<PerfSet>,
    pub perf_selection: usize,
    /// When true, the active pane renders only the plot for the
    /// selected row, full-area. Toggled by Enter; Esc exits.
    pub drilled_in: bool,
    /// Percent of the active pane's height allocated to the table
    /// (top). Plot takes the remainder. Adjustable via `[` / `]`.
    /// Clamped to `[SPLIT_MIN, SPLIT_MAX]`.
    pub split_pct: u16,
    /// Persistent scroll/offset state for each pane's table. ratatui
    /// uses `TableState::selected` for scroll positioning when
    /// `render_stateful_widget` is called; we re-set it from the
    /// pane's selection each frame and ratatui keeps the offset in
    /// view.
    pub counters_table_state: TableState,
    pub tcaches_table_state: TableState,
    pub timings_table_state: TableState,
    pub tiles_table_state: TableState,
    pub perf_table_state: TableState,
    pub quit: bool,
}

const SPLIT_DEFAULT: u16 = 60;
const SPLIT_MIN: u16 = 20;
const SPLIT_MAX: u16 = 80;
const SPLIT_STEP: i32 = 5;

impl App {
    pub fn new(
        counters: Vec<CounterSet>,
        tcaches: Vec<CounterSet>,
        timings: Vec<TimingSet>,
        tilemetrics: Vec<TileMetricsSet>,
        perf: Vec<PerfSet>,
    ) -> Self {
        Self {
            pane: Pane::Counters,
            counters,
            counters_selection: (0, 0),
            tcaches,
            tcaches_selection: 0,
            timings,
            timings_selection: 0,
            tilemetrics,
            tiles_selection: 0,
            perf,
            perf_selection: 0,
            drilled_in: false,
            split_pct: SPLIT_DEFAULT,
            counters_table_state: TableState::default(),
            tcaches_table_state: TableState::default(),
            timings_table_state: TableState::default(),
            tiles_table_state: TableState::default(),
            perf_table_state: TableState::default(),
            quit: false,
        }
    }

    /// Flat body-row index of the currently-selected counter slot
    /// (counts source-header rows as body rows; matches ratatui's
    /// `TableState::selected` indexing).
    pub fn counters_flat_idx(&self) -> usize {
        let (sel_set, sel_slot) = self.counters_selection;
        let mut idx = 0;
        for (i, set) in self.counters.iter().enumerate() {
            if i == sel_set {
                return idx + 1 + sel_slot;
            }
            idx += 1 + set.slot_count();
        }
        idx
    }

    /// Move the table/plot split by `dir * SPLIT_STEP` percent points,
    /// clamped to `[SPLIT_MIN, SPLIT_MAX]`.
    pub fn adjust_split(&mut self, dir: i32) {
        let new =
            (self.split_pct as i32 + dir * SPLIT_STEP).clamp(SPLIT_MIN as i32, SPLIT_MAX as i32);
        self.split_pct = new as u16;
    }

    /// Absorb any sources that appeared since the last discovery.
    /// Insertion-only — existing handles keep their mmaps and history
    /// rings. Selections are restored by name across the sort so a
    /// newly-inserted source doesn't shift the user's highlight.
    pub fn merge_new_sources(&mut self, sources: DiscoveredSources) {
        // Counters.
        let sel_name = self.counters.get(self.counters_selection.0).map(|c| c.name.clone());
        let existing: HashSet<String> = self.counters.iter().map(|c| c.name.clone()).collect();
        for f in &sources.counters {
            if !existing.contains(&f.name) {
                if let Ok(c) = CounterSet::open(f) {
                    self.counters.push(c);
                }
            }
        }
        self.counters.sort_by(|a, b| a.name.cmp(&b.name));
        if let Some(n) = sel_name {
            if let Some(idx) = self.counters.iter().position(|c| c.name == n) {
                self.counters_selection.0 = idx;
            }
        }

        // TCaches.
        let sel_name = self.tcaches.get(self.tcaches_selection).map(|c| c.name.clone());
        let existing: HashSet<String> = self.tcaches.iter().map(|c| c.name.clone()).collect();
        for f in &sources.tcaches {
            if !existing.contains(&f.name) {
                if let Ok(c) = CounterSet::open(f) {
                    self.tcaches.push(c);
                }
            }
        }
        self.tcaches.sort_by(|a, b| a.name.cmp(&b.name));
        if let Some(n) = sel_name {
            if let Some(idx) = self.tcaches.iter().position(|c| c.name == n) {
                self.tcaches_selection = idx;
            }
        }

        // Timings.
        let sel_name = self.timings.get(self.timings_selection).map(|t| t.name.clone());
        let existing: HashSet<String> = self.timings.iter().map(|t| t.name.clone()).collect();
        for f in &sources.timings {
            if !existing.contains(&f.name) {
                if let Ok(t) = TimingSet::open(f) {
                    self.timings.push(t);
                }
            }
        }
        self.timings.sort_by(|a, b| a.name.cmp(&b.name));
        if let Some(n) = sel_name {
            if let Some(idx) = self.timings.iter().position(|t| t.name == n) {
                self.timings_selection = idx;
            }
        }

        // Tile metrics.
        let sel_name = self.tilemetrics.get(self.tiles_selection).map(|t| t.name.clone());
        let existing: HashSet<String> = self.tilemetrics.iter().map(|t| t.name.clone()).collect();
        for f in &sources.tilemetrics {
            if !existing.contains(&f.name) {
                if let Ok(t) = TileMetricsSet::open(f) {
                    self.tilemetrics.push(t);
                }
            }
        }
        self.tilemetrics.sort_by(|a, b| a.name.cmp(&b.name));
        if let Some(n) = sel_name {
            if let Some(idx) = self.tilemetrics.iter().position(|t| t.name == n) {
                self.tiles_selection = idx;
            }
        }

        // Perf.
        let sel_name = self.perf.get(self.perf_selection).map(|p| p.name.clone());
        let existing: HashSet<String> = self.perf.iter().map(|p| p.name.clone()).collect();
        for f in &sources.perf {
            if !existing.contains(&f.name) {
                if let Ok(p) = PerfSet::open(f) {
                    self.perf.push(p);
                }
            }
        }
        self.perf.sort_by(|a, b| a.name.cmp(&b.name));
        if let Some(n) = sel_name {
            if let Some(idx) = self.perf.iter().position(|p| p.name == n) {
                self.perf_selection = idx;
            }
        }
    }

    pub fn sample(&mut self) {
        for c in &mut self.counters {
            c.sample();
        }
        for c in &mut self.tcaches {
            c.sample();
        }
        for t in &mut self.timings {
            t.drain();
        }
        for t in &mut self.tilemetrics {
            t.drain();
        }
        for p in &mut self.perf {
            p.drain();
        }
    }

    pub fn roll_bucket(&mut self) {
        for c in &mut self.counters {
            c.roll_bucket();
        }
        for c in &mut self.tcaches {
            // For tcaches the per-slot delta IS the metric — head/tail
            // values are monotonically-increasing seq cursors so a 1 s
            // delta gives bytes/sec produced or consumed.
            c.roll_bucket();
        }
        for t in &mut self.timings {
            t.roll_bucket();
        }
        for t in &mut self.tilemetrics {
            t.roll_bucket();
        }
        for p in &mut self.perf {
            p.roll_bucket();
        }
    }

    /// Scroll the selection within the active pane. `dir = +1`
    /// (down) or `-1` (up). For the counters pane, wraps across
    /// counter-sets at start/end of a set.
    pub fn move_selection(&mut self, dir: i32) {
        match self.pane {
            Pane::Counters => self.move_counter_selection(dir),
            Pane::TCaches => self.move_tcache_selection(dir),
            Pane::Timings => self.move_timing_selection(dir),
            Pane::Tiles => self.move_tile_selection(dir),
            Pane::Perf => self.move_perf_selection(dir),
        }
    }

    fn move_perf_selection(&mut self, dir: i32) {
        if self.perf.is_empty() {
            return;
        }
        let n = self.perf.len() as i32;
        let new = (self.perf_selection as i32 + dir).rem_euclid(n);
        self.perf_selection = new as usize;
    }

    fn move_tcache_selection(&mut self, dir: i32) {
        if self.tcaches.is_empty() {
            return;
        }
        let n = self.tcaches.len() as i32;
        let new = (self.tcaches_selection as i32 + dir).rem_euclid(n);
        self.tcaches_selection = new as usize;
    }

    fn move_tile_selection(&mut self, dir: i32) {
        if self.tilemetrics.is_empty() {
            return;
        }
        let n = self.tilemetrics.len() as i32;
        let new = (self.tiles_selection as i32 + dir).rem_euclid(n);
        self.tiles_selection = new as usize;
    }

    fn move_counter_selection(&mut self, dir: i32) {
        if self.counters.is_empty() {
            return;
        }
        let (mut set, mut slot) = self.counters_selection;
        let n_sets = self.counters.len();
        let cur_len = self.counters[set].slot_count() as i32;
        let new_slot = slot as i32 + dir;
        if new_slot < 0 {
            set = (set + n_sets - 1) % n_sets;
            slot = self.counters[set].slot_count().saturating_sub(1);
        } else if new_slot >= cur_len {
            set = (set + 1) % n_sets;
            slot = 0;
        } else {
            slot = new_slot as usize;
        }
        self.counters_selection = (set, slot);
    }

    fn move_timing_selection(&mut self, dir: i32) {
        if self.timings.is_empty() {
            return;
        }
        let n = self.timings.len() as i32;
        let new = (self.timings_selection as i32 + dir).rem_euclid(n);
        self.timings_selection = new as usize;
    }
}
