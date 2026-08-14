use std::net::IpAddr;

use ratatui::{
    Frame,
    layout::{Constraint, Rect},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
};

use crate::{app::App, sources::peers::PeerRow};

pub const COLUMNS: [&str; 9] =
    ["conn", "addr", "age", "rtt", "lost", "rx blk", "tx blk", "rx dgrams", "tx dgrams"];

/// Comparable key for the sort column. Addresses order by (ip, port).
fn sort_key(row: &PeerRow, col: usize) -> u128 {
    let s = &row.stats;
    match col {
        0 => s.connection as u128,
        1 => {
            let ip = match s.addr.ip() {
                IpAddr::V4(v4) => u128::from(u32::from(v4)),
                IpAddr::V6(v6) => u128::from(v6),
            };
            (ip << 16) | s.addr.port() as u128
        }
        2 => s.connected.as_millis(),
        3 => s.rtt.as_micros(),
        4 => s.lost_packets as u128,
        5 => s.rx_blocking as u128,
        6 => s.tx_blocking as u128,
        7 => s.rx_datagrams as u128,
        8 => s.tx_datagrams as u128,
        _ => 0,
    }
}

pub fn draw(f: &mut Frame, area: Rect, app: &mut App) {
    let title = " peers — ←/→ sort column · r reverse ";
    let block = Block::default().borders(Borders::ALL).title(title);
    if app.peers.is_empty() {
        let inner = block.inner(area);
        f.render_widget(block, area);
        f.render_widget(
            Paragraph::new("no peer stats yet (peers report after 30s connected)")
                .style(Style::default().fg(Color::DarkGray)),
            inner,
        );
        return;
    }

    let header = Row::new(COLUMNS.iter().enumerate().map(|(i, name)| {
        if i == app.peers_sort_col {
            let arrow = if app.peers_sort_desc { "▼" } else { "▲" };
            Cell::from(format!("{name} {arrow}"))
                .style(Style::default().add_modifier(Modifier::BOLD).fg(Color::Cyan))
        } else {
            Cell::from(*name).style(Style::default().add_modifier(Modifier::BOLD))
        }
    }))
    .height(1);

    let mut rows: Vec<&PeerRow> = app.peers.rows().collect();
    rows.sort_by_key(|r| sort_key(r, app.peers_sort_col));
    if app.peers_sort_desc {
        rows.reverse();
    }

    app.peers_selection = app.peers_selection.min(rows.len().saturating_sub(1));
    let table_rows: Vec<Row> = rows
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let s = &r.stats;
            let style = if i == app.peers_selection {
                Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            Row::new(vec![
                Cell::from(format!("{}", s.connection)),
                Cell::from(format!("{}", s.addr)),
                Cell::from(format_secs(s.connected.as_secs())),
                Cell::from(format!("{:.1}ms", s.rtt.as_secs_f64() * 1_000.0)),
                Cell::from(format!("{}", s.lost_packets)),
                Cell::from(format!("{}", s.rx_blocking)),
                Cell::from(format!("{}", s.tx_blocking)),
                Cell::from(format!("{}", s.rx_datagrams)),
                Cell::from(format!("{}", s.tx_datagrams)),
            ])
            .height(1)
            .style(style)
        })
        .collect();

    let widths = [
        Constraint::Length(6),
        Constraint::Min(24),
        Constraint::Length(8),
        Constraint::Length(9),
        Constraint::Length(8),
        Constraint::Length(8),
        Constraint::Length(8),
        Constraint::Length(11),
        Constraint::Length(11),
    ];
    let table = Table::new(table_rows, widths).header(header).block(block);
    app.peers_table_state.select(Some(app.peers_selection));
    f.render_stateful_widget(table, area, &mut app.peers_table_state);
}

fn format_secs(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m{}s", secs / 60, secs % 60)
    } else {
        format!("{}h{}m", secs / 3600, (secs % 3600) / 60)
    }
}
