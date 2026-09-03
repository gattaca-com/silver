use std::collections::HashSet;

use ratatui::widgets::TableState;
use silver_common::{GossipTopic, PeerId};

use crate::{
    discovery::DiscoveredSources,
    flamegraph::Flamegraph,
    render::events::EventsPane,
    sources::{
        counters::CounterSet, peers::Peers, tilemetrics::TileMetricsSet, timings::TimingSet,
    },
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Pane {
    Counters,
    TCaches,
    Timings,
    Tiles,
    Peers,
    Gossip,
    Events,
    Flamegraph,
}

pub const PANES: [Pane; 8] = [
    Pane::Counters,
    Pane::TCaches,
    Pane::Timings,
    Pane::Tiles,
    Pane::Peers,
    Pane::Gossip,
    Pane::Events,
    Pane::Flamegraph,
];

impl Pane {
    pub fn label(self) -> &'static str {
        match self {
            Pane::Counters => "Counters",
            Pane::TCaches => "TCaches",
            Pane::Timings => "Timings",
            Pane::Tiles => "Tiles",
            Pane::Peers => "Peers",
            Pane::Gossip => "Gossip",
            Pane::Events => "Events",
            Pane::Flamegraph => "Flamegraph",
        }
    }

    pub fn next(self) -> Self {
        match self {
            Pane::Counters => Pane::TCaches,
            Pane::TCaches => Pane::Timings,
            Pane::Timings => Pane::Tiles,
            Pane::Tiles => Pane::Peers,
            Pane::Peers => Pane::Gossip,
            Pane::Gossip => Pane::Events,
            Pane::Events => Pane::Flamegraph,
            Pane::Flamegraph => Pane::Counters,
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
    pub peers: Peers,
    /// Selection is by identity: the highlight and gossip expansion follow
    /// this peer as live re-sorting moves its row.
    pub peers_selected: Option<PeerId>,
    /// Row order as last drawn; navigation moves relative to it.
    pub peers_display_order: Vec<PeerId>,
    pub peers_sort_col: usize,
    pub peers_sort_desc: bool,
    /// Topic selection by identity, mirroring the peers pane.
    pub gossip_selected: Option<GossipTopic>,
    pub gossip_display_order: Vec<GossipTopic>,
    pub events: EventsPane,
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
    pub peers_table_state: TableState,
    pub gossip_table_state: TableState,
    pub flamegraph: Flamegraph,
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
        peers: Peers,
        events: EventsPane,
        flamegraph: Flamegraph,
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
            peers,
            peers_selected: None,
            peers_display_order: Vec::new(),
            peers_sort_col: 11,
            peers_sort_desc: true,
            gossip_selected: None,
            gossip_display_order: Vec::new(),
            events,
            drilled_in: false,
            split_pct: SPLIT_DEFAULT,
            counters_table_state: TableState::default(),
            tcaches_table_state: TableState::default(),
            timings_table_state: TableState::default(),
            tiles_table_state: TableState::default(),
            peers_table_state: TableState::default(),
            gossip_table_state: TableState::default(),
            flamegraph,
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
                let visible_before = (0..sel_slot).filter(|&s| set.slot_visible(s)).count();
                return idx + 1 + visible_before;
            }
            idx += 1 + set.visible_slots();
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
        self.counters.sort_by(|a, b| {
            crate::schema::sort_key(&a.name).cmp(&crate::schema::sort_key(&b.name))
        });
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
    }

    pub fn sample(&mut self) {
        // First: the mark rings lap if they wait on the other sources' latency.
        self.flamegraph.sample();
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
        self.peers.sample();
        self.events.sample();
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
        self.flamegraph.roll_bucket();
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
            Pane::Peers => self.move_peer_selection(dir),
            Pane::Gossip => self.move_gossip_selection(dir),
            Pane::Events => self.events.move_selection(dir),
            Pane::Flamegraph => self.flamegraph.scroll_by(dir),
        }
    }

    fn move_peer_selection(&mut self, dir: i32) {
        if self.peers_display_order.is_empty() {
            return;
        }
        let pos = self
            .peers_selected
            .and_then(|id| self.peers_display_order.iter().position(|p| *p == id))
            .unwrap_or(0);
        let new = pos.saturating_add_signed(dir as isize).min(self.peers_display_order.len() - 1);
        self.peers_selected = Some(self.peers_display_order[new]);
    }

    fn move_gossip_selection(&mut self, dir: i32) {
        if self.gossip_display_order.is_empty() {
            return;
        }
        let pos = self
            .gossip_selected
            .and_then(|t| self.gossip_display_order.iter().position(|x| *x == t))
            .unwrap_or(0);
        let new = pos.saturating_add_signed(dir as isize).min(self.gossip_display_order.len() - 1);
        self.gossip_selected = Some(self.gossip_display_order[new]);
    }

    /// Peers pane: jump selection to the first row of the current sort.
    pub fn select_top_peer(&mut self) {
        self.peers_selected = self.peers_display_order.first().copied();
    }

    /// Peers pane: move the sort column left/right, wrapping.
    pub fn adjust_peers_sort(&mut self, dir: i32) {
        let n = crate::render::peers_pane::COLUMNS.len() as i32;
        self.peers_sort_col = (self.peers_sort_col as i32 + dir).rem_euclid(n) as usize;
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
        let total: usize = self.counters.iter().map(|s| s.slot_count()).sum();
        // Step one slot at a time (wrapping across sets), skipping hidden
        // zero-valued slots; bounded by the total slot count.
        for _ in 0..total {
            if dir > 0 {
                slot += 1;
                if slot >= self.counters[set].slot_count() {
                    set = (set + 1) % n_sets;
                    slot = 0;
                }
            } else if slot == 0 {
                set = (set + n_sets - 1) % n_sets;
                slot = self.counters[set].slot_count().saturating_sub(1);
            } else {
                slot -= 1;
            }
            if self.counters[set].slot_visible(slot) {
                self.counters_selection = (set, slot);
                return;
            }
        }
    }

    /// Indices of timing sets that have recorded at least one value.
    pub fn visible_timings(&self) -> Vec<usize> {
        self.timings.iter().enumerate().filter(|(_, t)| t.has_values()).map(|(i, _)| i).collect()
    }

    fn move_timing_selection(&mut self, dir: i32) {
        let visible = self.visible_timings();
        if visible.is_empty() {
            return;
        }
        let n = visible.len() as i32;
        let pos = visible.iter().position(|&i| i == self.timings_selection).unwrap_or(0) as i32;
        self.timings_selection = visible[(pos + dir).rem_euclid(n) as usize];
    }
}
