use std::path::Path;

use ratatui::{
    Frame,
    layout::{Constraint, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Text},
    widgets::{Block, BorderType, Borders, Cell, Paragraph, Row, Table, TableState},
};
use silver_beacon_state_data::SLOTS_PER_EPOCH;
use silver_common::{BlockSource, Nanos, PayloadValidationStatus};

use crate::sources::events::Events;

/// Descriptive title suffix. `stf ‖ el` are stacked in one column to show they
/// run concurrently.
const HINT: &str = "recv into slot, per-step Δ";

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

        let header = Row::new([
            "slot",
            "time (utc)",
            "block root",
            "src",
            "into slot",
            "validate",
            "stf ‖ el",
            "total",
        ])
        .style(Style::default().add_modifier(Modifier::BOLD).fg(Color::Cyan))
        .bottom_margin(1);

        let body: Vec<Row> = rows
            .iter()
            .rev()
            .map(|r| {
                let t = r.timeline();
                // Slowest step is the bottleneck — bold it (concurrent el and
                // stf compete on the same clock, so comparing them is fair).
                let peak = t.validate.max(t.stf.unwrap_or_default()).max(t.el.unwrap_or_default());
                let bottleneck = |d: Nanos| d == peak && peak.0 > 0;

                // stf and el stacked in one cell, coloured differently, to show
                // they run in parallel (both start at EL-sent).
                let parallel = Cell::from(Text::from(vec![
                    stage_line("stf", t.stf, Color::Blue, t.stf.is_some_and(bottleneck)),
                    stage_line("el", t.el, el_color(t.verdict), t.el.is_some_and(bottleneck)),
                ]));

                Row::new(vec![
                    slot_cell(r.slot),
                    Cell::from(t.received_at.with_fmt_utc("%H:%M:%S%.3f")),
                    Cell::from(root_prefix(&r.block_root)),
                    Cell::from(match r.source {
                        BlockSource::Gossip => "gossip",
                        BlockSource::Rpc => "rpc",
                    }),
                    Cell::from(dur(t.received)),
                    dur_cell(t.validate, bottleneck(t.validate)),
                    parallel,
                    Cell::from(dur(t.total)),
                ])
                .height(2)
            })
            .collect();

        let widths = [
            Constraint::Length(9),
            Constraint::Length(12),
            Constraint::Length(11),
            Constraint::Length(7),
            Constraint::Length(9),
            Constraint::Length(9),
            Constraint::Length(12),
            Constraint::Length(9),
        ];
        let table = Table::new(body, widths)
            .header(header)
            .block(block)
            .column_spacing(1)
            .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED))
            .highlight_symbol("▶ ");
        f.render_stateful_widget(table, area, &mut self.table);
    }
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

/// The first slot of an epoch is highlighted so epoch boundaries stand out.
/// Cosmetic only — assumes the mainnet epoch length.
fn slot_cell(slot: u64) -> Cell<'static> {
    let cell = Cell::from(slot.to_string());
    if slot.is_multiple_of(SLOTS_PER_EPOCH) {
        cell.style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
    } else {
        cell
    }
}

fn dur_cell(d: Nanos, bottleneck: bool) -> Cell<'static> {
    let style = if bottleneck {
        Style::default().add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
    } else {
        Style::default()
    };
    Cell::from(dur(d)).style(style)
}

/// One line of the stacked `stf ‖ el` cell: `"<label> <dur>"`, coloured, bold
/// when it is the block's bottleneck. `-` while the stage hasn't happened.
fn stage_line(label: &str, d: Option<Nanos>, color: Color, bottleneck: bool) -> Line<'static> {
    let text = match d {
        Some(d) => format!("{label:<3} {}", dur(d)),
        None => format!("{label:<3} -"),
    };
    let mut style = Style::default().fg(color);
    if bottleneck {
        style = style.add_modifier(Modifier::BOLD | Modifier::UNDERLINED);
    }
    Line::styled(text, style)
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
