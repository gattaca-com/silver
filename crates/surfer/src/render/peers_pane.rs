use std::{cmp::Ordering, net::IpAddr};

use ratatui::{
    Frame,
    layout::{Constraint, Rect},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
};

use crate::{app::App, sources::peers::PeerRow};

const NET_COLS: usize = 10;
pub const COLUMNS: [&str; 20] = [
    "conn", "peer", "addr", "age", "rtt", "lost", "rxb", "txb", "rxdg", "txdg", "mesh", "p1", "p2",
    "p3", "p3b", "p4", "p5", "p6", "p7", "total",
];

const SCORE_COLOR: Color = Color::Magenta;

enum Key {
    Int(u128),
    Float(f64),
}

/// Comparable key for the sort column. Addresses order by (ip, port); rows
/// missing the column's side sort as zero.
fn sort_key(row: &PeerRow, col: usize) -> Key {
    if col < NET_COLS {
        let Some(s) = &row.p2p else { return Key::Int(0) };
        Key::Int(match col {
            0 => s.connection as u128,
            2 => {
                let ip = match s.addr.ip() {
                    IpAddr::V4(v4) => u128::from(u32::from(v4)),
                    IpAddr::V6(v6) => u128::from(v6),
                };
                (ip << 16) | s.addr.port() as u128
            }
            3 => s.connected.as_millis(),
            4 => s.rtt.as_micros(),
            5 => s.lost_packets as u128,
            6 => s.rx_blocking as u128,
            7 => s.tx_blocking as u128,
            8 => s.rx_datagrams as u128,
            9 => s.tx_datagrams as u128,
            _ => 0,
        })
    } else {
        let Some(s) = &row.scores else {
            return if col == NET_COLS { Key::Int(0) } else { Key::Float(0.0) };
        };
        match col {
            10 => Key::Int(s.mesh_count as u128),
            11 => Key::Float(s.p1_time_in_mesh),
            12 => Key::Float(s.p2_first_deliveries),
            13 => Key::Float(s.p3_mesh_deficit),
            14 => Key::Float(s.p3b_mesh_failure),
            15 => Key::Float(s.p4_invalid),
            16 => Key::Float(s.p5_application),
            17 => Key::Float(s.p6_ip_colocation),
            18 => Key::Float(s.p7_behaviour),
            _ => Key::Float(s.total),
        }
    }
}

// The mixed arms are unreachable while `sort_key` returns one variant per
// column, but they must still order deterministically: `Equal` here breaks
// transitivity and panics the stdlib sort's total-order check.
fn compare(a: &Key, b: &Key) -> Ordering {
    match (a, b) {
        (Key::Int(a), Key::Int(b)) => a.cmp(b),
        (Key::Float(a), Key::Float(b)) => a.total_cmp(b),
        (Key::Int(_), Key::Float(_)) => Ordering::Less,
        (Key::Float(_), Key::Int(_)) => Ordering::Greater,
    }
}

pub fn draw(f: &mut Frame, area: Rect, app: &mut App) {
    if app.peers.is_empty() {
        let block =
            Block::default().borders(Borders::ALL).title(" peers — ←/→ sort column · r reverse ");
        let inner = block.inner(area);
        f.render_widget(block, area);
        f.render_widget(
            Paragraph::new("no peer stats yet (connections report after 30s)")
                .style(Style::default().fg(Color::DarkGray)),
            inner,
        );
        return;
    }

    let header = Row::new(COLUMNS.iter().enumerate().map(|(i, name)| {
        let mut style = Style::default().add_modifier(Modifier::BOLD);
        if i >= NET_COLS {
            style = style.fg(SCORE_COLOR);
        }
        if i == app.peers_sort_col {
            let arrow = if app.peers_sort_desc { "▼" } else { "▲" };
            Cell::from(format!("{name}{arrow}")).style(style.fg(Color::Cyan))
        } else {
            Cell::from(*name).style(style)
        }
    }))
    .height(1);

    let mut rows: Vec<_> = app.peers.rows().collect();
    rows.sort_by(|(_, a), (_, b)| {
        compare(&sort_key(a, app.peers_sort_col), &sort_key(b, app.peers_sort_col))
    });
    if app.peers_sort_desc {
        rows.reverse();
    }

    app.peers_display_order = rows.iter().map(|(id, _)| **id).collect();
    let sel_pos =
        app.peers_selected.and_then(|sel| rows.iter().position(|(id, _)| **id == sel)).unwrap_or(0);
    app.peers_selected = rows.get(sel_pos).map(|(id, _)| **id);

    let sel_agent = rows
        .get(sel_pos)
        .and_then(|(_, r)| r.scores.as_ref())
        .map(|s| s.user_agent.as_str())
        .filter(|a| !a.is_empty());
    let title = match sel_agent {
        Some(agent) => format!(" peers — ←/→ sort column · r reverse · {agent} "),
        None => " peers — ←/→ sort column · r reverse ".to_string(),
    };
    let block = Block::default().borders(Borders::ALL).title(title);

    let mut table_rows: Vec<Row> = Vec::with_capacity(rows.len());
    for (i, (id, r)) in rows.iter().enumerate() {
        let row = {
            let style = if i == sel_pos {
                Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };

            let conn = match &r.p2p {
                Some(s) => format!("{}", s.connection),
                None => "·".to_string(),
            };
            let mut cells = vec![Cell::from(conn), Cell::from(short_id(id.as_bytes()))];
            match &r.p2p {
                Some(s) => cells.extend([
                    Cell::from(format!("{}", s.addr)),
                    Cell::from(format_secs(s.connected.as_secs())),
                    Cell::from(format!("{:.1}ms", s.rtt.as_secs_f64() * 1_000.0)),
                    Cell::from(format!("{}", s.lost_packets)),
                    Cell::from(format!("{}", s.rx_blocking)),
                    Cell::from(format!("{}", s.tx_blocking)),
                    Cell::from(format!("{}", s.rx_datagrams)),
                    Cell::from(format!("{}", s.tx_datagrams)),
                ]),
                None => cells.extend((2..NET_COLS).map(|_| Cell::from("·"))),
            }
            let score_cell =
                |v: f64| Cell::from(format!("{v:.1}")).style(Style::default().fg(SCORE_COLOR));
            match &r.scores {
                Some(s) => cells.extend([
                    Cell::from(format!("{}", s.mesh_count)).style(Style::default().fg(SCORE_COLOR)),
                    score_cell(s.p1_time_in_mesh),
                    score_cell(s.p2_first_deliveries),
                    score_cell(s.p3_mesh_deficit),
                    score_cell(s.p3b_mesh_failure),
                    score_cell(s.p4_invalid),
                    score_cell(s.p5_application),
                    score_cell(s.p6_ip_colocation),
                    score_cell(s.p7_behaviour),
                    score_cell(s.total),
                ]),
                None => cells.extend(
                    (NET_COLS..COLUMNS.len())
                        .map(|_| Cell::from("·").style(Style::default().fg(SCORE_COLOR))),
                ),
            }
            Row::new(cells).height(1).style(style)
        };
        table_rows.push(row);

        if i == sel_pos {
            table_rows.extend(r.sorted_topics().into_iter().map(topic_row));
        }
    }

    let mut widths = vec![
        Constraint::Length(6),
        Constraint::Length(9),
        Constraint::Min(21),
        Constraint::Length(7),
        Constraint::Length(8),
        Constraint::Length(6),
        Constraint::Length(5),
        Constraint::Length(5),
        Constraint::Length(8),
        Constraint::Length(8),
        Constraint::Length(5),
    ];
    widths.extend(std::iter::repeat_n(Constraint::Length(7), COLUMNS.len() - widths.len()));
    let table = Table::new(table_rows, widths).header(header).block(block);
    app.peers_table_state.select(Some(sel_pos));
    f.render_stateful_widget(table, area, &mut app.peers_table_state);
}

/// Expansion sub-row for one meshed topic of the selected peer. The raw
/// counters sit under the score columns they feed: first deliveries → p2,
/// mesh deliveries → p3, failure penalty → p3b, invalid → p4; the fan-out
/// forward ratio (sent/total — the shortfall is the peer's own first
/// deliveries, IDONTWANT, or score gate) sits under p5.
fn topic_row(t: &silver_common::PeerTopicScores) -> Row<'static> {
    let val = |v: f64| Cell::from(format!("{v:.1}"));
    let mut cells = vec![
        Cell::from(""),
        Cell::from(""),
        Cell::from(format!("└ {}", t.topic)),
        Cell::from(format_secs(t.meshed_secs)),
        Cell::from(""),
        Cell::from(""),
        Cell::from(""),
        Cell::from(""),
        Cell::from(""),
        Cell::from(""),
        Cell::from(if !t.p3_scored {
            "—"
        } else if t.mesh_active {
            "act"
        } else {
            "grace"
        }),
        Cell::from(""),
    ];
    cells.extend([
        val(t.first_deliveries),
        val(t.mesh_deliveries),
        val(t.mesh_failure_penalty),
        val(t.invalid_deliveries),
    ]);
    cells.push(Cell::from(if t.fanout_total == 0 {
        "·".to_string()
    } else {
        format!("{:.0}%", t.fanout_sent as f64 * 100.0 / t.fanout_total as f64)
    }));
    Row::new(cells).height(1).style(Style::default().fg(Color::Green))
}

pub(crate) fn short_id(bytes: &[u8]) -> String {
    let tail = &bytes[bytes.len().saturating_sub(4)..];
    tail.iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn format_secs(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m{}s", secs / 60, secs % 60)
    } else {
        format!("{}h{}m", secs / 3600, (secs % 3600) / 60)
    }
}
