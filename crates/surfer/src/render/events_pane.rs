use std::path::Path;

use ratatui::{
    Frame,
    layout::{Constraint, Rect},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState},
};
use silver_common::{BlockSource, Nanos, PayloadValidationStatus};

use crate::sources::events::Events;

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
        let title = format!(
            " block events — recv into slot ({}ms), Δ per step; el ‖ stf ",
            self.data.slot_ms()
        );
        let block = Block::default().borders(Borders::ALL).title(title);
        if self.data.rows().is_empty() {
            let inner = block.inner(area);
            f.render_widget(block, area);
            f.render_widget(
                Paragraph::new("no blocks observed yet")
                    .style(Style::default().fg(Color::DarkGray)),
                inner,
            );
            return;
        }

        let header = Row::new(vec![
            Cell::from("slot"),
            Cell::from("root"),
            Cell::from("src"),
            Cell::from("recv"),
            Cell::from("validate"),
            Cell::from("stf"),
            Cell::from("el ‖"),
            Cell::from("total"),
        ])
        .style(Style::default().add_modifier(Modifier::BOLD).fg(Color::White))
        .height(1);

        let selected = self.table.selected().unwrap_or(0);
        let rows: Vec<Row> = self
            .data
            .rows()
            .iter()
            .rev()
            .enumerate()
            .map(|(i, r)| {
                let t = r.timeline();
                // Slowest step is the bottleneck — bold it (concurrent el and
                // stf compete on the same clock, so comparing them is fair).
                let peak = t.validate.max(t.stf.unwrap_or_default()).max(t.el.unwrap_or_default());
                let bottleneck = |d: Nanos| d == peak && peak.0 > 0;

                let row_style = if i == selected {
                    Style::default()
                        .bg(Color::DarkGray)
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                };
                Row::new(vec![
                    Cell::from(r.slot.to_string()),
                    Cell::from(root_prefix(&r.block_root)),
                    Cell::from(match r.source {
                        BlockSource::Gossip => "gossip",
                        BlockSource::Rpc => "rpc",
                    }),
                    Cell::from(format!("+{}", ms(t.received))),
                    dur_cell(Some(t.validate), bottleneck(t.validate), None),
                    dur_cell(t.stf, t.stf.is_some_and(bottleneck), None),
                    dur_cell(t.el, t.el.is_some_and(bottleneck), verdict_color(t.verdict)),
                    Cell::from(ms(t.total)),
                ])
                .height(1)
                .style(row_style)
            })
            .collect();

        let widths = [
            Constraint::Length(9),
            Constraint::Length(10),
            Constraint::Length(7),
            Constraint::Length(11),
            Constraint::Length(9),
            Constraint::Length(9),
            Constraint::Length(9),
            Constraint::Length(9),
        ];
        let table = Table::new(rows, widths).header(header).block(block);
        f.render_stateful_widget(table, area, &mut self.table);
    }
}

fn ms(d: Nanos) -> String {
    format!("{:.2}ms", d.as_millis())
}

/// First 4 bytes of the block root as 8 hex chars.
fn root_prefix(root: &[u8; 32]) -> String {
    format!("{:02x}{:02x}{:02x}{:02x}", root[0], root[1], root[2], root[3])
}

fn dur_cell(d: Option<Nanos>, bottleneck: bool, color: Option<Color>) -> Cell<'static> {
    let Some(d) = d else {
        return Cell::from("-");
    };
    let mut style = Style::default();
    if let Some(c) = color {
        style = style.fg(c);
    }
    if bottleneck {
        style = style.add_modifier(Modifier::BOLD | Modifier::UNDERLINED);
    }
    Cell::from(ms(d)).style(style)
}

/// EL verdict as a colour on the `el` duration: green valid, red invalid,
/// yellow syncing/accepted. `None` while the EL has not responded.
fn verdict_color(status: Option<PayloadValidationStatus>) -> Option<Color> {
    status.map(|s| match s {
        PayloadValidationStatus::Valid => Color::Green,
        PayloadValidationStatus::Invalid => Color::Red,
        PayloadValidationStatus::Syncing | PayloadValidationStatus::Accepted => Color::Yellow,
    })
}
