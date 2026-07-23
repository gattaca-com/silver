use std::path::Path;

use ratatui::{
    Frame,
    layout::{Constraint, Rect},
    style::{Color, Style},
    text::{Line, Text},
    widgets::{Block, BorderType, Borders, Cell, Paragraph, Row, Table, TableState},
};
use silver_beacon_state_data::SLOTS_PER_EPOCH;
use silver_common::{BlockSource, Nanos, PayloadValidationStatus};

use crate::sources::events::Events;

/// Descriptive title suffix. `stf` and `el` share one cell (stacked) because
/// they run concurrently — both start at EL-sent, so `total` is not their sum.
const HINT: &str = "recv into slot, per-step Δ (stf ‖ el)";

const COLS: [&str; 8] =
    ["slot", "block root", "src", "time (utc)", "into slot", "validate", "stf ‖ el", "total"];

/// The Events tab: a spine data source plus its own scroll/selection state.
/// `App` holds one of these and only calls `sample`/`move_selection`/`draw`.
pub struct EventsPane {
    data: Events,
    table: TableState,
}

impl EventsPane {
    pub fn open(base_dir: &Path, genesis_unix_secs: u64, slot_ms: u64) -> Self {
        Self {
            data: Events::open(base_dir, genesis_unix_secs, slot_ms),
            table: TableState::default(),
        }
    }

    pub fn sample(&mut self) {
        self.data.sample();
    }

    pub fn move_selection(&mut self, dir: i32) {
        let n = self.data.rows().len() as i32;
        if n == 0 {
            return;
        }
        let cur = self.table.selected().unwrap_or(0) as i32;
        self.table.select(Some((cur + dir).rem_euclid(n) as usize));
    }

    pub fn draw(&mut self, f: &mut Frame, area: Rect) {
        let rows = self.data.rows();
        let title = match self.table.selected() {
            Some(i) if !rows.is_empty() => format!(" events {}/{} — {HINT} ", i + 1, rows.len()),
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
        let grid: Vec<[Text; 8]> = rows
            .iter()
            .rev()
            .map(|r| {
                let t = r.timeline();
                [
                    slot_text(r.slot),
                    Text::raw(root_prefix(&r.block_root)),
                    Text::raw(match r.source {
                        BlockSource::Gossip => "gossip",
                        BlockSource::Rpc => "rpc",
                    }),
                    Text::raw(t.received_at.with_fmt_utc("%H:%M:%S%.3f")),
                    Text::raw(dur(t.received)),
                    Text::raw(dur(t.validate)),
                    // stf and el stacked, coloured differently, so it reads as
                    // "these two run in parallel".
                    Text::from(vec![
                        stage_line("stf", t.stf, Color::Blue),
                        stage_line("el", t.el, el_color(t.verdict)),
                    ]),
                    Text::raw(dur(t.total)),
                ]
            })
            .collect();

        let col_widths: [u16; 8] = std::array::from_fn(|c| {
            let widest = grid.iter().map(|row| row[c].width()).max().unwrap_or(0);
            Text::raw(COLS[c]).width().max(widest) as u16
        });

        let header = Row::new(with_separators(COLS.map(Cell::from), 1))
            .style(Style::default().fg(Color::Cyan));
        let body =
            grid.into_iter().map(|row| Row::new(with_separators(row.map(Cell::from), 2)).height(2));

        let table = Table::new(body, interleave_widths(&col_widths))
            .header(header)
            .block(block)
            .column_spacing(1)
            .row_highlight_style(Style::default().bg(Color::DarkGray))
            .highlight_symbol("▶ ");
        f.render_stateful_widget(table, area, &mut self.table);
    }
}

/// Interleave a dim, `lines`-tall `│` divider between adjacent cells so the
/// rules span the full height of two-line rows.
fn with_separators(cells: [Cell<'static>; 8], lines: usize) -> Vec<Cell<'static>> {
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
fn interleave_widths(widths: &[u16; 8]) -> Vec<Constraint> {
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

/// One line of the stacked `stf ‖ el` cell: `"<label> <dur>"`, coloured; `-`
/// while the stage hasn't happened.
fn stage_line(label: &str, d: Option<Nanos>, color: Color) -> Line<'static> {
    let text = match d {
        Some(d) => format!("{label:<3} {}", dur(d)),
        None => format!("{label:<3} -"),
    };
    Line::styled(text, Style::default().fg(color))
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
        None => Color::DarkGray,
    }
}
