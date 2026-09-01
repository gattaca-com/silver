use std::{iter::repeat_n, path::Path};

use ratatui::{
    Frame,
    layout::{Constraint, Rect},
    style::{Color, Style},
    text::{Line, Text},
    widgets::{Block, BorderType, Borders, Cell, Paragraph, Row, Table, TableState},
};
use silver_beacon_state_data::SLOTS_PER_EPOCH;
use silver_common::{BlockSource, Nanos, PayloadValidationStatus};

use crate::sources::events::{BlockRow, Events};

/// Descriptive title suffix. `stf` and `el` share one cell (stacked) because
/// they run concurrently — both start at EL-sent, so `total` is not their sum.
const HINT: &str = "recv into slot, per-step Δ (stf ‖ el), Enter expands columns";

const COLS: [&str; 10] = [
    "slot",
    "block root",
    "src",
    "received time",
    "into slot",
    "validate",
    "stf ‖ el",
    "da",
    "total",
    "attestation deadline",
];

/// The Events tab: a spine data source plus its own scroll/selection state.
pub struct EventsPane {
    data: Events,
    table: TableState,
    /// Block whose per-column rows are unfolded beneath it.
    expanded: Option<[u8; 32]>,
}

impl EventsPane {
    pub fn open(base_dir: &Path, genesis_unix_secs: u64, slot_ms: u64) -> Self {
        Self {
            data: Events::open(base_dir, genesis_unix_secs, slot_ms),
            table: TableState::default(),
            expanded: None,
        }
    }

    pub fn sample(&mut self) {
        self.data.sample();
    }

    /// The block each display row belongs to, newest block first: one row per
    /// block, plus one per column of the expanded one.
    fn display_roots(&self) -> Vec<[u8; 32]> {
        let mut roots = Vec::new();
        for r in self.data.rows().iter().rev() {
            roots.push(r.block_root);
            if self.expanded == Some(r.block_root) {
                roots.extend(repeat_n(r.block_root, r.columns.len()));
            }
        }
        roots
    }

    pub fn move_selection(&mut self, dir: i32) {
        let n = self.display_roots().len() as i32;
        if n == 0 {
            return;
        }
        let cur = self.table.selected().unwrap_or(0) as i32;
        self.table.select(Some((cur + dir).rem_euclid(n) as usize));
    }

    pub fn toggle_expand(&mut self) {
        let roots = self.display_roots();
        let Some(&root) = self.table.selected().and_then(|i| roots.get(i)) else {
            return;
        };
        self.expanded = (self.expanded != Some(root)).then_some(root);
        // The toggle rewrites the display list; keep the highlight on the
        // toggled block rather than whatever lands at the old index.
        self.table.select(self.display_roots().iter().position(|&r| r == root));
    }

    pub fn draw(&mut self, f: &mut Frame, area: Rect) {
        let rows = self.data.rows();
        let display_rows = self.display_roots().len();
        let title = match self.table.selected() {
            Some(i) if !rows.is_empty() => {
                format!(" events {}/{} — {HINT} ", i + 1, display_rows)
            }
            _ => format!(" events — {HINT} "),
        };
        let block =
            Block::default().borders(Borders::ALL).border_type(BorderType::Rounded).title(title);

        if rows.is_empty() {
            let inner = block.inner(area);
            f.render_widget(block, area);
            f.render_widget(
                Paragraph::new("no blocks observed yet")
                    .style(Style::default().fg(Color::DarkGray)),
                inner,
            );
            return;
        }

        // Build the styled cell content first so column widths can be sized to
        // the widest cell (like the builder's DataTable), newest row first.
        // Block rows are two lines tall; expanded column subrows one.
        let deadline = self.data.attestation_deadline();
        let mut grid: Vec<(Vec<Text>, u16)> = Vec::new();
        for r in rows.iter().rev() {
            grid.push((self.block_cells(r, deadline), 2));
            if self.expanded == Some(r.block_root) {
                let mut columns: Vec<_> = r.columns.iter().collect();
                columns.sort_unstable_by_key(|c| c.recv);
                for c in columns {
                    let recv_offset = self.data.clock().offset_in_slot(c.recv, r.slot);
                    let cells = vec![
                        Text::raw(""),
                        Text::styled(
                            format!("└ col {}", c.index),
                            Style::default().fg(Color::Magenta),
                        ),
                        Text::raw(""),
                        Text::raw(c.recv.with_fmt_utc("%H:%M:%S%.3f")),
                        Text::raw(recv_offset.map_or_else(|| "-".to_string(), dur)),
                        Text::raw(
                            c.validated
                                .map_or_else(|| "-".to_string(), |v| dur(v.saturating_sub(c.recv))),
                        ),
                        Text::raw(""),
                        Text::raw(""),
                        Text::raw(""),
                        Text::raw(""),
                    ];
                    grid.push((cells, 1));
                }
            }
        }

        let col_widths: Vec<u16> = (0..COLS.len())
            .map(|c| {
                let widest = grid.iter().map(|(row, _)| row[c].width()).max().unwrap_or(0);
                Text::raw(COLS[c]).width().max(widest) as u16
            })
            .collect();

        let header = Row::new(with_separators(COLS.iter().map(|s| Cell::from(*s)).collect(), 1))
            .style(Style::default().fg(Color::Cyan));
        let body = grid.into_iter().map(|(row, height)| {
            let cells = with_separators(row.into_iter().map(Cell::from).collect(), height as usize);
            Row::new(cells).height(height)
        });

        let table = Table::new(body, interleave_widths(&col_widths))
            .header(header)
            .block(block)
            .column_spacing(1)
            .row_highlight_style(Style::default().bg(Color::Indexed(236)))
            .highlight_symbol("▶ ");
        f.render_stateful_widget(table, area, &mut self.table);
    }

    fn block_cells(&self, r: &BlockRow, deadline: Nanos) -> Vec<Text<'static>> {
        let t = r.timeline();
        vec![
            slot_text(r.slot),
            Text::raw(root_prefix(&r.block_root)),
            Text::raw(match r.source {
                Some(BlockSource::Gossip) => "gossip",
                Some(BlockSource::Rpc) => "rpc",
                None => "-",
            }),
            Text::raw(
                t.received_at.map_or_else(|| "-".to_string(), |at| at.with_fmt_utc("%H:%M:%S%.3f")),
            ),
            Text::raw(t.received.map_or_else(|| "-".to_string(), dur)),
            Text::raw(t.validate.map_or_else(|| "-".to_string(), dur)),
            // stf and el stacked, coloured differently, so it reads as
            // "these two run in parallel".
            Text::from(vec![
                stage_line("stf", t.stf, None, Color::LightBlue),
                stage_line("el", t.el, t.verdict.map(status_label), el_color(t.verdict)),
            ]),
            // The DA gate: arrival → data available, with the column count.
            Text::from(vec![
                Line::styled(
                    t.da.map_or_else(|| "-".to_string(), dur),
                    Style::default().fg(if t.da.is_some() { Color::Magenta } else { Color::Gray }),
                ),
                Line::styled(
                    format!("{} cols", r.columns.len()),
                    Style::default().fg(Color::DarkGray),
                ),
            ]),
            Text::raw(t.total.map_or_else(|| "-".to_string(), dur)),
            // Applied into-slot = arrival + validate + stf; that's when
            // the head is importable, i.e. when we could attest.
            margin_text(
                t.received
                    .zip(t.validate)
                    .zip(t.stf)
                    .map(|((recv, validate), stf)| recv + validate + stf),
                deadline,
            ),
        ]
    }
}

/// Interleave a dim, `lines`-tall `│` divider between adjacent cells so the
/// rules span the full height of multi-line rows.
fn with_separators(cells: Vec<Cell<'static>>, lines: usize) -> Vec<Cell<'static>> {
    let mut out = Vec::with_capacity(cells.len() * 2 - 1);
    for (i, cell) in cells.into_iter().enumerate() {
        if i > 0 {
            let bar = Text::from(vec![Line::from("│"); lines]);
            out.push(Cell::from(bar).style(Style::default().fg(Color::DarkGray)));
        }
        out.push(cell);
    }
    out
}

/// Column widths with a 1-wide divider column interleaved to match
/// [`with_separators`].
fn interleave_widths(widths: &[u16]) -> Vec<Constraint> {
    let mut out = Vec::with_capacity(widths.len() * 2 - 1);
    for (i, &w) in widths.iter().enumerate() {
        if i > 0 {
            out.push(Constraint::Length(1));
        }
        out.push(Constraint::Length(w));
    }
    out
}

/// Auto-unit duration via flux's `Nanos` Display ("2.345s", "12.5ms", "910μs"),
/// with a plain "0" for the zero it would otherwise render blank.
fn dur(d: Nanos) -> String {
    if d.0 == 0 { "0".to_string() } else { d.to_string() }
}

/// Margin against the attestation deadline at the point the block became
/// importable (applied): green when we beat it (time to spare), red (`-…`) when
/// we missed it. `-` when there is no applied-into-slot to compare.
fn margin_text(applied_into_slot: Option<Nanos>, deadline: Nanos) -> Text<'static> {
    let Some(applied) = applied_into_slot else {
        return Text::raw("-");
    };
    let (text, color) = if applied <= deadline {
        (format!("+{}", dur(deadline.saturating_sub(applied))), Color::Green)
    } else {
        (format!("-{}", dur(applied.saturating_sub(deadline))), Color::Red)
    };
    Text::styled(text, Style::default().fg(color))
}

/// One line of the stacked `stf ‖ el` cell: `"<label> <dur> [note]"`, coloured;
/// `-` while the stage hasn't happened.
fn stage_line(label: &str, d: Option<Nanos>, note: Option<&str>, color: Color) -> Line<'static> {
    let mut text = match d {
        Some(d) => format!("{label:<3} {}", dur(d)),
        None => format!("{label:<3} -"),
    };
    if let Some(note) = note {
        text.push(' ');
        text.push_str(note);
    }
    Line::styled(text, Style::default().fg(color))
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

/// First 4 bytes of the block root as 8 hex chars.
fn root_prefix(root: &[u8; 32]) -> String {
    format!("{:02x}{:02x}{:02x}{:02x}", root[0], root[1], root[2], root[3])
}

/// The first slot of an epoch is highlighted (cyan) so epoch boundaries stand
/// out. Cosmetic only — assumes the mainnet epoch length.
fn slot_text(slot: u64) -> Text<'static> {
    let text = slot.to_string();
    if slot.is_multiple_of(SLOTS_PER_EPOCH) {
        Text::styled(text, Style::default().fg(Color::Cyan))
    } else {
        Text::raw(text)
    }
}

/// Colour for the `el` line, carrying the EL verdict: green valid, red invalid,
/// yellow syncing/accepted, grey while the EL has not responded.
fn el_color(status: Option<PayloadValidationStatus>) -> Color {
    match status {
        Some(PayloadValidationStatus::Valid) => Color::Green,
        Some(PayloadValidationStatus::Invalid) => Color::Red,
        Some(PayloadValidationStatus::Syncing | PayloadValidationStatus::Accepted) => Color::Yellow,
        None => Color::Gray,
    }
}
