use std::path::Path;

use ratatui::{
    Frame,
    layout::{Constraint, Rect},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState},
};
use silver_common::{BlockSource, PayloadValidationStatus, hex32};

use crate::sources::events::{BlockRow, Events};

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
        let title = format!(" block events — ms into slot ({}ms) ", self.data.slot_ms());
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
            Cell::from("el sent"),
            Cell::from("applied"),
            Cell::from("el verdict"),
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
                let style = if i == selected {
                    Style::default()
                        .bg(Color::DarkGray)
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                };
                Row::new(vec![
                    Cell::from(r.slot.to_string()),
                    Cell::from(hex32(&r.block_root)[..8].to_string()),
                    Cell::from(match r.source {
                        BlockSource::Gossip => "gossip",
                        BlockSource::Rpc => "rpc",
                    }),
                    Cell::from(format!("+{}ms", r.received_ms)),
                    Cell::from(format!("+{}ms", r.el_sent_ms)),
                    Cell::from(opt_ms(r.applied_ms)),
                    verdict_cell(r),
                ])
                .height(1)
                .style(style)
            })
            .collect();

        let widths = [
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Length(6),
            Constraint::Length(9),
            Constraint::Length(9),
            Constraint::Length(9),
            Constraint::Min(16),
        ];
        let table = Table::new(rows, widths).header(header).block(block);
        f.render_stateful_widget(table, area, &mut self.table);
    }
}

fn opt_ms(ms: Option<u32>) -> String {
    match ms {
        Some(ms) => format!("+{ms}ms"),
        None => "-".to_string(),
    }
}

fn verdict_cell(r: &BlockRow) -> Cell<'static> {
    let Some((status, ms)) = r.verdict else {
        return Cell::from("-");
    };
    let (label, color) = match status {
        PayloadValidationStatus::Valid => ("valid", Color::Green),
        PayloadValidationStatus::Invalid => ("INVALID", Color::Red),
        PayloadValidationStatus::Syncing => ("syncing", Color::Yellow),
        PayloadValidationStatus::Accepted => ("accepted", Color::Yellow),
    };
    Cell::from(format!("{label} +{ms}ms")).style(Style::default().fg(color))
}
