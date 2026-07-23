use std::path::Path;

use ratatui::{
    Frame,
    layout::{Constraint, Rect},
    style::{Color, Modifier, Style},
    widgets::{Block, BorderType, Borders, Cell, Paragraph, Row, Table, TableState},
};
use silver_beacon_state_data::SLOTS_PER_EPOCH;
use silver_common::{BlockSource, Nanos, PayloadValidationStatus};

use crate::sources::events::Events;

/// Descriptive title suffix. `stf` and `el` run concurrently (both start at
/// EL-sent), so `total` is not their sum.
const HINT: &str = "recv into slot, per-step Δ (stf ‖ el)";

const COLS: [&str; 9] =
    ["slot", "block root", "src", "time (utc)", "into slot", "validate", "stf", "el", "total"];
const COL_WIDTHS: [u16; 9] = [8, 9, 6, 12, 8, 10, 10, 10, 9];

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

        let header =
            Row::new(with_separators(COLS.map(Cell::from))).style(Style::default().fg(Color::Cyan));

        let body: Vec<Row> = rows
            .iter()
            .rev()
            .map(|r| {
                let t = r.timeline();
                Row::new(with_separators([
                    slot_cell(r.slot),
                    Cell::from(root_prefix(&r.block_root)),
                    Cell::from(match r.source {
                        BlockSource::Gossip => "gossip",
                        BlockSource::Rpc => "rpc",
                    }),
                    Cell::from(t.received_at.with_fmt_utc("%H:%M:%S%.3f")),
                    Cell::from(dur(t.received)),
                    dur_cell(Some(t.validate), None),
                    dur_cell(t.stf, None),
                    dur_cell(t.el, Some(el_color(t.verdict))),
                    Cell::from(dur(t.total)),
                ]))
            })
            .collect();

        let table = Table::new(body, column_widths())
            .header(header)
            .block(block)
            .column_spacing(1)
            .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED))
            .highlight_symbol("▶ ");
        f.render_stateful_widget(table, area, &mut self.table);
    }
}

/// Interleave a dim `│` divider between adjacent cells for a ruled table.
fn with_separators(cells: [Cell<'static>; 9]) -> Vec<Cell<'static>> {
    let mut out = Vec::with_capacity(cells.len() * 2 - 1);
    for (i, cell) in cells.into_iter().enumerate() {
        if i > 0 {
            out.push(Cell::from("│").style(Style::default().fg(Color::DarkGray)));
        }
        out.push(cell);
    }
    out
}

/// `COL_WIDTHS` with a 1-wide divider column interleaved to match
/// [`with_separators`].
fn column_widths() -> Vec<Constraint> {
    let mut out = Vec::with_capacity(COL_WIDTHS.len() * 2 - 1);
    for (i, &w) in COL_WIDTHS.iter().enumerate() {
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

/// First 4 bytes of the block root as 8 hex chars.
fn root_prefix(root: &[u8; 32]) -> String {
    format!("{:02x}{:02x}{:02x}{:02x}", root[0], root[1], root[2], root[3])
}

/// The first slot of an epoch is highlighted (cyan) so epoch boundaries stand
/// out. Cosmetic only — assumes the mainnet epoch length.
fn slot_cell(slot: u64) -> Cell<'static> {
    let cell = Cell::from(slot.to_string());
    if slot.is_multiple_of(SLOTS_PER_EPOCH) {
        cell.style(Style::default().fg(Color::Cyan))
    } else {
        cell
    }
}

fn dur_cell(d: Option<Nanos>, color: Option<Color>) -> Cell<'static> {
    let Some(d) = d else {
        return Cell::from("-");
    };
    match color {
        Some(c) => Cell::from(dur(d)).style(Style::default().fg(c)),
        None => Cell::from(dur(d)),
    }
}

/// Colour for the `el` cell, carrying the EL verdict: green valid, red invalid,
/// yellow syncing/accepted, grey while the EL has not responded.
fn el_color(status: Option<PayloadValidationStatus>) -> Color {
    match status {
        Some(PayloadValidationStatus::Valid) => Color::Green,
        Some(PayloadValidationStatus::Invalid) => Color::Red,
        Some(PayloadValidationStatus::Syncing | PayloadValidationStatus::Accepted) => Color::Yellow,
        None => Color::DarkGray,
    }
}
