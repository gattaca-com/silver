//! The Events tab: each block's pipeline on a shared ms-into-slot axis.
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
    widgets::{Block, BorderType, Borders, List, ListState, Paragraph},
};
use silver_stages::SlotClock;

use self::{
    axis::Axis,
    line::{Grid, RowCells},
    tree::{DisplayRow, Expanded, Node, display_rows},
};
use crate::{
    render::fmt::wall_time,
    sources::events::{BlockTrace, Events, Interval},
};

mod axis;
mod line;
mod palette;
mod tree;

const TITLE: &str = "block pipeline: arrival → attestable, ms into slot";

pub struct EventsPane {
    data: Events,
    list: ListState,
    expanded: Expanded,
}

impl EventsPane {
    pub fn open(base_dir: &Path, clock: SlotClock) -> Self {
        Self {
            data: Events::open(base_dir, clock),
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
        self.data.traces().by_root(root)
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
        // toggled row, or on the group's last opener when a child folded it.
        let keep = match node.opens() {
            Some(_) => node,
            None => Node::Span(*group.openers().last().expect("every group has an opener")),
        };
        self.list.select(self.display().iter().position(|d| d.root == root && d.node == keep));
    }

    pub fn draw(&mut self, f: &mut Frame, area: Rect) {
        let display = self.display();
        let title = match self.selected_wall_range(&display) {
            Some(iv) => {
                format!(" {TITLE} — selected {} → {} ", wall_time(iv.start), wall_time(iv.end))
            }
            None => format!(" {TITLE} "),
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
        let rows: Vec<_> = display
            .iter()
            .map(|d| {
                let trace = self.trace(d.root).expect("display rows come from the ring");
                RowCells::new(trace, d, clock, deadline)
            })
            .collect();
        let grid = Grid::fit(rows.iter(), inner.width as usize);
        let axis = Axis::fit(grid.axis, deadline, self.data.traces().max_strip_offset(clock));

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(1), Constraint::Min(1)])
            .split(inner);
        f.render_widget(Paragraph::new(grid.header(&axis)), chunks[0]);

        let list = List::new(rows.into_iter().map(|cells| cells.into_line(&grid, &axis)))
            .highlight_style(Style::default().bg(palette::SELECTION_BG));
        f.render_stateful_widget(list, chunks[1], &mut self.list);
    }

    /// Absolute wall clock of the selected node's span, for log correlation.
    fn selected_wall_range(&self, display: &[DisplayRow]) -> Option<Interval> {
        let DisplayRow { root, node, .. } = self.selected(display)?;
        node.interval(self.trace(root)?)
    }
}
