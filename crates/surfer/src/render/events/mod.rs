//! The Events tab: per-block waterfalls on a shared ms-into-slot axis.
//!
//! One line per (slot, root); its bar spans arrival → attestable. Expanding a
//! line unfolds the three components that join at attestable (`data available
//! → cols`, `stf → validate/apply`, `el`), every level drawn with the same
//! grammar. Bars that overlap vertically ran in parallel; a gap in a span is
//! waiting.

use std::path::Path;

use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::Style,
    widgets::{Block, BorderType, Borders, List, ListItem, ListState, Paragraph},
};

use self::{
    axis::Axis,
    line::{axis_width, header, row_line},
    tree::{DisplayRow, Expanded, Node, display_rows},
};
use crate::sources::events::{BlockTrace, Events, Interval};

mod axis;
mod line;
mod palette;
mod tree;

const HINT: &str = "waterfall, ms into slot — Enter expands, bars overlapping ran in parallel";

pub struct EventsPane {
    data: Events,
    list: ListState,
    expanded: Expanded,
}

impl EventsPane {
    pub fn open(base_dir: &Path, genesis_unix_secs: u64, slot_ms: u64) -> Self {
        Self {
            data: Events::open(base_dir, genesis_unix_secs, slot_ms),
            list: ListState::default(),
            expanded: Expanded::default(),
        }
    }

    pub fn sample(&mut self) {
        self.data.sample();
    }

    fn display(&self) -> Vec<DisplayRow> {
        display_rows(self.data.traces(), &self.expanded)
    }

    fn trace(&self, root: [u8; 32]) -> Option<&BlockTrace> {
        self.data.traces().iter().find(|r| r.block_root == root)
    }

    fn selected(&self, display: &[DisplayRow]) -> Option<DisplayRow> {
        self.list.selected().and_then(|i| display.get(i)).copied()
    }

    pub fn move_selection(&mut self, dir: i32) {
        let n = self.display().len() as i32;
        if n == 0 {
            return;
        }
        let cur = self.list.selected().unwrap_or(0) as i32;
        self.list.select(Some((cur + dir).rem_euclid(n) as usize));
    }

    /// A group toggles itself; a child folds the group it is in, so a long
    /// column list closes without scrolling back to its header.
    pub fn toggle_expand(&mut self) {
        let Some(DisplayRow { root, node, .. }) = self.selected(&self.display()) else {
            return;
        };
        let Some(group) = node.opens().or_else(|| node.parent(self.trace(root)?)) else {
            return;
        };
        self.expanded.toggle(root, group);
        // The toggle rewrites the display list; keep the highlight on the
        // toggled group rather than whatever lands at the old index.
        let opener = Node::Span(group.opener());
        self.list.select(self.display().iter().position(|d| d.root == root && d.node == opener));
    }

    pub fn draw(&mut self, f: &mut Frame, area: Rect) {
        let display = self.display();
        let title = match self.selected_wall_range(&display) {
            Some(iv) => format!(
                " events — {} → {} — {HINT} ",
                iv.start.with_fmt_utc("%H:%M:%S%.3f"),
                iv.end.with_fmt_utc("%H:%M:%S%.3f"),
            ),
            None => format!(" events — {HINT} "),
        };
        let block =
            Block::default().borders(Borders::ALL).border_type(BorderType::Rounded).title(title);
        let inner = block.inner(area);
        f.render_widget(block, area);

        if display.is_empty() {
            f.render_widget(
                Paragraph::new("no blocks observed yet").style(Style::default().fg(palette::EMPTY)),
                inner,
            );
            return;
        }

        let clock = self.data.clock();
        let deadline = self.data.attestation_deadline();
        let axis = Axis::fit(
            axis_width(inner.width as usize),
            deadline,
            self.data.traces().max_strip_offset(clock),
        );

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(1), Constraint::Min(1)])
            .split(inner);
        f.render_widget(Paragraph::new(header(&axis)), chunks[0]);

        let items: Vec<ListItem> = display
            .iter()
            .map(|d| {
                let trace = self.trace(d.root).expect("display rows come from the ring");
                ListItem::new(row_line(trace, d, &axis, clock, deadline))
            })
            .collect();
        let list = List::new(items).highlight_style(Style::default().bg(palette::SELECTION_BG));
        f.render_stateful_widget(list, chunks[1], &mut self.list);
    }

    /// Absolute wall clock of the selected node's span, for log correlation.
    fn selected_wall_range(&self, display: &[DisplayRow]) -> Option<Interval> {
        let DisplayRow { root, node, .. } = self.selected(display)?;
        node.interval(self.trace(root)?)
    }
}
