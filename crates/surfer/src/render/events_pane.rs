//! The Events tab: per-block waterfalls on a shared ms-into-slot axis.
//!
//! One line per (slot, root); its bar spans arrival → attestable. Expanding a
//! line unfolds the block's dependency tree (`data → cols/kzg/da`,
//! `block → validate/stf/el`), every level drawn with the same grammar:
//! `label │ start │ bar on the axis │ duration`. Bars that overlap vertically
//! ran in parallel; a gap in a lane is waiting.

use std::{collections::HashSet, path::Path};

use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, List, ListItem, ListState, Paragraph},
};
use silver_beacon_state_data::SLOTS_PER_EPOCH;
use silver_common::{ColumnSource, Nanos, PayloadValidationStatus};

use crate::sources::events::{BlockRow, Events, Lane};

const HINT: &str = "waterfall, ms into slot — Enter expands, bars overlapping ran in parallel";

/// Fixed-width left columns; the axis takes the rest.
const LABEL_W: usize = 22;
/// Wall clock of the row's start, for log correlation.
const TIME_W: usize = 13;
const START_W: usize = 9;
/// Duration plus a short suffix (column counts, the EL verdict), in a fixed
/// column so the numbers align instead of floating at each bar's end.
const DURATION_W: usize = 16;
/// Deadline margin, on block strips only.
const MARGIN_W: usize = 9;

/// Which subtree of a block a display row belongs to; `Enter` on the group
/// toggles it, `Enter` on a child collapses the group it is in.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Expand {
    Strip,
    Data,
    GossipCols,
    RpcCols,
    ElCols,
    Exec,
}

impl Expand {
    fn cols(source: ColumnSource) -> Self {
        match source {
            ColumnSource::Gossip => Self::GossipCols,
            ColumnSource::Rpc => Self::RpcCols,
            ColumnSource::El => Self::ElCols,
        }
    }
}

/// One display row: a lane of the block's graph, or one column sidecar.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Node {
    Lane(Lane),
    Col(usize),
}

pub struct EventsPane {
    data: Events,
    list: ListState,
    expanded: HashSet<([u8; 32], Expand)>,
}

impl EventsPane {
    pub fn open(base_dir: &Path, genesis_unix_secs: u64, slot_ms: u64) -> Self {
        Self {
            data: Events::open(base_dir, genesis_unix_secs, slot_ms),
            list: ListState::default(),
            expanded: HashSet::new(),
        }
    }

    pub fn sample(&mut self) {
        self.data.sample();
    }

    /// The visible tree, newest block first, in display order.
    fn display(&self) -> Vec<([u8; 32], Node)> {
        let mut out = Vec::new();
        for r in self.data.rows().iter().rev() {
            let root = r.block_root;
            let open = |e| self.expanded.contains(&(root, e));
            out.push((root, Node::Lane(Lane::Strip)));
            if !open(Expand::Strip) {
                continue;
            }
            out.push((root, Node::Lane(Lane::Data)));
            if open(Expand::Data) {
                out.push((root, Node::Lane(Lane::Da)));
                for source in [ColumnSource::Gossip, ColumnSource::El, ColumnSource::Rpc] {
                    if r.columns.iter().all(|c| c.source != source) {
                        continue;
                    }
                    out.push((root, Node::Lane(Lane::Cols(source))));
                    if open(Expand::cols(source)) {
                        let mut order: Vec<_> = (0..r.columns.len())
                            .filter(|&i| r.columns[i].source == source)
                            .collect();
                        order.sort_unstable_by_key(|&i| r.columns[i].recv);
                        out.extend(order.into_iter().map(|i| (root, Node::Col(i))));
                    }
                }
            }
            out.push((root, Node::Lane(Lane::Exec)));
            if open(Expand::Exec) {
                out.push((root, Node::Lane(Lane::Validate)));
                out.push((root, Node::Lane(Lane::Stf)));
                out.push((root, Node::Lane(Lane::El)));
            }
        }
        out
    }

    pub fn move_selection(&mut self, dir: i32) {
        let n = self.display().len() as i32;
        if n == 0 {
            return;
        }
        let cur = self.list.selected().unwrap_or(0) as i32;
        self.list.select(Some((cur + dir).rem_euclid(n) as usize));
    }

    pub fn toggle_expand(&mut self) {
        let display = self.display();
        let Some(&(root, node)) = self.list.selected().and_then(|i| display.get(i)) else {
            return;
        };
        // A group toggles itself; a child collapses the group it is in, so a
        // long column list folds without scrolling back to its header.
        let (expand, follow) = match node {
            Node::Lane(Lane::Strip) => (Expand::Strip, node),
            Node::Lane(Lane::Data) => (Expand::Data, node),
            Node::Lane(Lane::Cols(source)) => (Expand::cols(source), node),
            Node::Lane(Lane::Exec) => (Expand::Exec, node),
            Node::Lane(Lane::Da) => (Expand::Data, Node::Lane(Lane::Data)),
            Node::Lane(Lane::Validate | Lane::Stf | Lane::El) => {
                (Expand::Exec, Node::Lane(Lane::Exec))
            }
            Node::Col(i) => {
                let source = self.row(root).map(|r| r.columns[i].source);
                let Some(source) = source else {
                    return;
                };
                (Expand::cols(source), Node::Lane(Lane::Cols(source)))
            }
        };
        if !self.expanded.remove(&(root, expand)) {
            self.expanded.insert((root, expand));
        }
        // The toggle rewrites the display list; keep the highlight on the
        // toggled group rather than whatever lands at the old index.
        self.list.select(self.display().iter().position(|&e| e == (root, follow)));
    }

    pub fn draw(&mut self, f: &mut Frame, area: Rect) {
        let display = self.display();
        let title = match self.selected_wall_range(&display) {
            Some((start, end)) => format!(
                " events — {} → {} — {HINT} ",
                start.with_fmt_utc("%H:%M:%S%.3f"),
                end.with_fmt_utc("%H:%M:%S%.3f"),
            ),
            None => format!(" events — {HINT} "),
        };
        let block =
            Block::default().borders(Borders::ALL).border_type(BorderType::Rounded).title(title);
        let inner = block.inner(area);
        f.render_widget(block, area);

        if display.is_empty() {
            f.render_widget(
                Paragraph::new("no blocks observed yet")
                    .style(Style::default().fg(Color::DarkGray)),
                inner,
            );
            return;
        }

        let axis_w = (inner.width as usize)
            .saturating_sub(LABEL_W + TIME_W + START_W + DURATION_W + MARGIN_W + 5);
        let axis = Axis::fit(axis_w, self.data.attestation_deadline(), self.max_offset());

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(1), Constraint::Min(1)])
            .split(inner);
        f.render_widget(Paragraph::new(self.header_line(&axis)), chunks[0]);

        let items: Vec<ListItem> = display
            .iter()
            .map(|&(root, node)| {
                let row = self.row(root).expect("display rows come from the ring");
                ListItem::new(self.node_line(row, node, &axis))
            })
            .collect();
        let list = List::new(items).highlight_style(Style::default().bg(Color::Indexed(236)));
        f.render_stateful_widget(list, chunks[1], &mut self.list);
    }

    fn row(&self, root: [u8; 32]) -> Option<&BlockRow> {
        self.data.rows().iter().find(|r| r.block_root == root)
    }

    /// Absolute wall clock of the selected node's span, for log correlation.
    fn selected_wall_range(&self, display: &[([u8; 32], Node)]) -> Option<(Nanos, Nanos)> {
        let &(root, node) = self.list.selected().and_then(|i| display.get(i))?;
        let row = self.row(root)?;
        match node {
            Node::Lane(lane) => row.span(lane),
            Node::Col(i) => {
                let c = row.columns.get(i)?;
                Some((c.recv, c.validated.unwrap_or(c.recv)))
            }
        }
    }

    /// Largest strip end offset, so the axis covers every visible bar.
    fn max_offset(&self) -> Nanos {
        self.data
            .rows()
            .iter()
            .filter_map(|r| {
                let (_, end) = r.span(Lane::Strip)?;
                self.offset(r, end)
            })
            .max()
            .unwrap_or(Nanos(0))
    }

    /// Into-slot offset of a wall timestamp, `None` outside the live window.
    fn offset(&self, r: &BlockRow, ts: Nanos) -> Option<Nanos> {
        self.data.clock().offset_in_slot(ts, r.slot)
    }

    fn header_line(&self, axis: &Axis) -> Line<'static> {
        let mut labels = String::new();
        for sec in 0.. {
            let Some(cell) = axis.cell(Nanos::from_secs(sec)) else {
                break;
            };
            while labels.chars().count() < cell {
                labels.push('\u{254c}'); // ╌
            }
            labels.push_str(&format!("{sec}s"));
        }
        while labels.chars().count() < axis.width {
            labels.push('\u{254c}');
        }
        let head = format!(
            "{:<LABEL_W$} {:<TIME_W$} {:<START_W$} {} {:<DURATION_W$} deadline",
            "slot/component", "time", "start", labels, "duration"
        );
        Line::styled(head, Style::default().fg(Color::Cyan))
    }

    /// `label │ start │ bar │ duration [suffix]`, one line per node.
    fn node_line(&self, r: &BlockRow, node: Node, axis: &Axis) -> Line<'static> {
        let (label, span, style) = match node {
            Node::Lane(lane) => (self.lane_label(r, lane), r.span(lane), lane_style(r, lane)),
            Node::Col(i) => {
                let c = &r.columns[i];
                // The gate's own color on the column that opened it; custody
                // traffic past the gate dimmed.
                let color = if r.da_trigger() == Some(i) {
                    Color::Magenta
                } else if r.da_available().is_some_and(|gate| c.recv > gate) {
                    Color::DarkGray
                } else {
                    Color::White
                };
                let span = Some((c.recv, c.validated.unwrap_or(c.recv)));
                (format!("        col {}", c.index), span, Style::default().fg(color))
            }
        };

        let (time_text, start_text, bar) = match span {
            Some((start, end)) => {
                let offset = self.offset(r, start);
                let start_text = offset.map_or_else(|| "-".to_string(), dur);
                (
                    start.with_fmt_utc("%H:%M:%S%.3f"),
                    start_text,
                    axis.bar(offset, end.saturating_sub(start)),
                )
            }
            None => ("-".to_string(), "-".to_string(), String::new()),
        };

        let duration = span.map_or_else(String::new, |(start, end)| match node {
            Node::Lane(Lane::Da) => String::new(),
            _ => dur(end.saturating_sub(start)),
        });
        let suffix = self.suffix(r, node);

        // The first slot of an epoch is highlighted so boundaries stand out.
        let label_color = match node {
            Node::Lane(Lane::Strip) if r.slot.is_multiple_of(SLOTS_PER_EPOCH) => Color::Cyan,
            _ => Color::Gray,
        };
        let mut spans = vec![Span::styled(
            format!("{label:<LABEL_W$} {time_text:<TIME_W$} {start_text:<START_W$} "),
            Style::default().fg(label_color),
        )];
        // The axis area holds bars only, padded to its exact width, so the
        // duration and deadline columns align on every row.
        let bar_pad = axis.width.saturating_sub(bar.chars().count());
        spans.push(Span::styled(format!("{bar}{}", " ".repeat(bar_pad)), style));
        spans.push(Span::styled(format!(" {:<DURATION_W$}", format!("{duration}{suffix}")), style));
        if let Node::Lane(Lane::Strip) = node {
            spans.push(margin_span(self.margin(r)));
        }
        Line::from(spans)
    }

    fn lane_label(&self, r: &BlockRow, lane: Lane) -> String {
        let open = |e| self.expanded.contains(&(r.block_root, e));
        let arrow = |e| if open(e) { '\u{25be}' } else { '\u{25b8}' }; // ▾ ▸
        match lane {
            Lane::Strip => {
                format!("{} {} {}", arrow(Expand::Strip), r.slot, root_prefix(&r.block_root))
            }
            Lane::Data => format!("  {} data", arrow(Expand::Data)),
            Lane::Cols(source) => {
                format!("    {} {} cols", arrow(Expand::cols(source)), source_label(source))
            }
            Lane::Da => "    da".to_string(),
            Lane::Exec => format!("  {} block", arrow(Expand::Exec)),
            Lane::Validate => "      validate".to_string(),
            Lane::Stf => "      stf".to_string(),
            Lane::El => "      el".to_string(),
        }
    }

    fn suffix(&self, r: &BlockRow, node: Node) -> String {
        match node {
            // The gate open with no sidecars ever seen: a block without
            // blobs, whose DA is trivially satisfied — not a display hole.
            Node::Lane(Lane::Data) if r.columns.is_empty() && r.da_available().is_some() => {
                " 0 blobs".to_string()
            }
            Node::Lane(Lane::Cols(source)) => {
                let of_source = || r.columns.iter().filter(|c| c.source == source);
                match r.da_available() {
                    Some(gate) => format!(
                        " {}/{}",
                        of_source().filter(|c| c.recv <= gate).count(),
                        of_source().count()
                    ),
                    None => format!(" {}", of_source().count()),
                }
            }
            Node::Lane(Lane::El) => {
                r.verdict().map_or_else(String::new, |v| format!(" {}", status_label(v)))
            }
            _ => String::new(),
        }
    }

    /// Attestation-deadline margin at attestable; `None` before applied.
    fn margin(&self, r: &BlockRow) -> Option<(Nanos, bool)> {
        let applied_into_slot = self.offset(r, r.applied_at()?)?;
        let deadline = self.data.attestation_deadline();
        Some(if applied_into_slot <= deadline {
            (deadline.saturating_sub(applied_into_slot), true)
        } else {
            (applied_into_slot.saturating_sub(deadline), false)
        })
    }
}

/// The shared time scale: into-slot nanoseconds → axis cells.
struct Axis {
    width: usize,
    range: Nanos,
}

impl Axis {
    /// Covers the deadline and every visible bar, with 5% headroom.
    fn fit(width: usize, deadline: Nanos, max_offset: Nanos) -> Self {
        let range = Nanos(deadline.0.max(max_offset.0).max(1) * 21 / 20);
        Self { width, range }
    }

    fn cell(&self, offset: Nanos) -> Option<usize> {
        (offset <= self.range)
            .then(|| {
                ((offset.0 as u128 * self.width as u128) / self.range.0.max(1) as u128) as usize
            })
            .filter(|&c| c < self.width)
    }

    /// Spaces up to the bar, then at least one bar cell. Empty when the start
    /// offset is unknown (replay clock).
    fn bar(&self, start: Option<Nanos>, len: Nanos) -> String {
        let Some(start_cell) = start.and_then(|s| self.cell(s)) else {
            return String::new();
        };
        let end_cell = start
            .map(|s| s + len)
            .and_then(|e| self.cell(e))
            .unwrap_or(self.width.saturating_sub(1));
        let bar_len = (end_cell.saturating_sub(start_cell)).max(1);
        format!("{}{}", " ".repeat(start_cell), "\u{2588}".repeat(bar_len))
    }
}

fn lane_style(r: &BlockRow, lane: Lane) -> Style {
    let color = match lane {
        Lane::Da => Color::Magenta,
        Lane::El => el_color(r.verdict()),
        Lane::Cols(_) => Color::White,
        Lane::Stf | Lane::Validate => Color::LightBlue,
        _ => Color::White,
    };
    Style::default().fg(color)
}

/// Auto-unit duration via flux's `Nanos` Display ("2.345s", "12.5ms", "910μs"),
/// with a plain "0" for the zero it would otherwise render blank.
fn dur(d: Nanos) -> String {
    if d.0 == 0 { "0".to_string() } else { d.to_string() }
}

/// Green with time to spare, red past the deadline.
fn margin_span(margin: Option<(Nanos, bool)>) -> Span<'static> {
    let Some((delta, made_it)) = margin else {
        return Span::raw("");
    };
    let (sign, color) = if made_it { ('+', Color::Green) } else { ('-', Color::Red) };
    Span::styled(format!("{sign}{}", dur(delta)), Style::default().fg(color))
}

/// Spelled out next to the `el` duration: a syncing or accepted EL answers in a
/// few ms without executing the payload, so the round-trip alone reads as a
/// fast success.
fn status_label(status: PayloadValidationStatus) -> &'static str {
    match status {
        PayloadValidationStatus::Valid => "valid",
        PayloadValidationStatus::Invalid => "invalid",
        PayloadValidationStatus::Syncing => "syncing",
        PayloadValidationStatus::Accepted => "accepted",
    }
}

fn source_label(source: ColumnSource) -> &'static str {
    match source {
        ColumnSource::Gossip => "gossip",
        ColumnSource::Rpc => "rpc",
        ColumnSource::El => "el",
    }
}

/// Colour for the `el` lane, carrying the EL verdict: green valid, red invalid,
/// yellow syncing/accepted, grey while the EL has not responded.
fn el_color(status: Option<PayloadValidationStatus>) -> Color {
    match status {
        Some(PayloadValidationStatus::Valid) => Color::Green,
        Some(PayloadValidationStatus::Invalid) => Color::Red,
        Some(PayloadValidationStatus::Syncing | PayloadValidationStatus::Accepted) => Color::Yellow,
        None => Color::Gray,
    }
}

/// First 4 bytes of the block root as 8 hex chars.
fn root_prefix(root: &[u8; 32]) -> String {
    format!("{:02x}{:02x}{:02x}{:02x}", root[0], root[1], root[2], root[3])
}
