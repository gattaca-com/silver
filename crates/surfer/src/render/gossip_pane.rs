use std::collections::HashMap;

use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
};
use silver_common::{
    GOSSIP_TOPIC_COUNTER_SLOTS, GossipTopic, PeerTopicScores, gossip_topic_for_counter_slot,
};

use crate::{
    app::App,
    render::peers_pane::{format_secs, short_id},
    sources::counters::{BUCKET_SECS, CounterSet},
};

pub const COLUMNS: [&str; 12] =
    ["topic", "mesh", "subs", "rx/s", "tx/s", "act", "age", "fd", "md", "p3b", "p4", "fwd"];

/// Slots per topic in the `gossip_topics` counter file; layout shared with
/// `GossipTopicCounters` (sent, recv, mesh, subs) and `schema::names_for`.
const PER_TOPIC: usize = 4;

struct Member<'a> {
    conn: Option<usize>,
    short_id: String,
    agent: &'a str,
    scores: &'a PeerTopicScores,
}

fn median(values: &mut [f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.sort_by(f64::total_cmp);
    let mid = values.len() / 2;
    if values.len().is_multiple_of(2) { (values[mid - 1] + values[mid]) * 0.5 } else { values[mid] }
}

fn fwd_pct(total: u64, sent: u64) -> String {
    if total == 0 {
        "·".to_string()
    } else {
        format!("{:.0}%", sent as f64 * 100.0 / total as f64)
    }
}

fn gauge(set: &CounterSet, slot: usize) -> u64 {
    set.current.get(slot).copied().unwrap_or(0)
}

/// Last completed bucket's delta as a per-second rate.
fn rate(set: &CounterSet, slot: usize) -> String {
    match set.history.get(slot).and_then(|h| h.back()) {
        Some(delta) => format!("{:.1}", *delta as f64 / BUCKET_SECS as f64),
        None => "·".to_string(),
    }
}

pub fn draw(f: &mut Frame, area: Rect, app: &mut App) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Min(40), Constraint::Length(AGENTS_PANEL_WIDTH)])
        .split(area);
    draw_agent_counts(f, cols[1], app);
    let area = cols[0];

    let mut meshed: HashMap<GossipTopic, Vec<Member>> = HashMap::new();
    for (id, row) in app.peers.rows() {
        let conn = row.p2p.as_ref().map(|s| s.connection);
        let agent = row.scores.as_ref().map(|s| s.user_agent.as_str()).unwrap_or("");
        for (t, _) in row.topics.values() {
            meshed.entry(t.topic).or_default().push(Member {
                conn,
                short_id: short_id(id.as_bytes()),
                agent,
                scores: t,
            });
        }
    }

    // Topics with any signal: meshed peers reported on the spine, or a live
    // mesh/subs gauge in the counter file (catches subscribed-but-unmeshed
    // topics the peer stats can't see).
    let counters = app.counters.iter().find(|c| c.name == "gossip_topics");
    let mut order: Vec<GossipTopic> = match counters {
        Some(set) => (0..GOSSIP_TOPIC_COUNTER_SLOTS)
            .filter_map(gossip_topic_for_counter_slot)
            .filter(|t| {
                let base = t.counter_slot() * PER_TOPIC;
                meshed.contains_key(t) || gauge(set, base + 2) > 0 || gauge(set, base + 3) > 0
            })
            .collect(),
        None => meshed.keys().copied().collect(),
    };
    order.sort_by_key(|t| t.counter_slot());

    let title = " gossip meshes — ↑/↓ select topic ";
    if order.is_empty() {
        let block = Block::default().borders(Borders::ALL).title(title);
        let inner = block.inner(area);
        f.render_widget(block, area);
        f.render_widget(
            Paragraph::new("no gossip topics yet").style(Style::default().fg(Color::DarkGray)),
            inner,
        );
        return;
    }

    app.gossip_display_order = order.clone();
    let sel_pos =
        app.gossip_selected.and_then(|sel| order.iter().position(|t| *t == sel)).unwrap_or(0);
    app.gossip_selected = order.get(sel_pos).copied();

    let header = Row::new(
        COLUMNS
            .iter()
            .map(|name| Cell::from(*name).style(Style::default().add_modifier(Modifier::BOLD))),
    )
    .height(1);

    let mut table_rows: Vec<Row> = Vec::with_capacity(order.len());
    for (i, topic) in order.iter().enumerate() {
        let style = if i == sel_pos {
            Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        let mut cells = vec![Cell::from(topic.to_string())];
        match counters {
            Some(set) => {
                let base = topic.counter_slot() * PER_TOPIC;
                cells.extend([
                    Cell::from(format!("{}", gauge(set, base + 2))),
                    Cell::from(format!("{}", gauge(set, base + 3))),
                    Cell::from(rate(set, base + 1)),
                    Cell::from(rate(set, base)),
                ]);
            }
            None => cells.extend((1..5).map(|_| Cell::from("·"))),
        }
        match meshed.get(topic) {
            Some(members) => {
                let act = members.iter().filter(|m| m.scores.mesh_active).count();
                let p3_scored = members.first().is_some_and(|m| m.scores.p3_scored);
                let mut ages: Vec<f64> =
                    members.iter().map(|m| m.scores.meshed_secs as f64).collect();
                let mut fds: Vec<f64> = members.iter().map(|m| m.scores.first_deliveries).collect();
                let mut mds: Vec<f64> = members.iter().map(|m| m.scores.mesh_deliveries).collect();
                let p3b: f64 = members.iter().map(|m| m.scores.mesh_failure_penalty).sum();
                let p4: f64 = members.iter().map(|m| m.scores.invalid_deliveries).sum();
                let fanout_total: u64 = members.iter().map(|m| m.scores.fanout_total).sum();
                let fanout_sent: u64 = members.iter().map(|m| m.scores.fanout_sent).sum();
                cells.extend([
                    Cell::from(if p3_scored { format!("{act}") } else { "—".to_string() }),
                    Cell::from(format_secs(median(&mut ages) as u64)),
                    Cell::from(format!("{:.1}", median(&mut fds))),
                    Cell::from(format!("{:.1}", median(&mut mds))),
                    Cell::from(format!("{p3b:.1}")),
                    Cell::from(format!("{p4:.1}")),
                    Cell::from(fwd_pct(fanout_total, fanout_sent)),
                ]);
            }
            None => cells.extend((5..COLUMNS.len()).map(|_| Cell::from("·"))),
        }
        table_rows.push(Row::new(cells).height(1).style(style));

        if i == sel_pos {
            if let Some(members) = meshed.get(topic) {
                let mut sorted: Vec<&Member> = members.iter().collect();
                sorted.sort_by(|a, b| {
                    b.scores.first_deliveries.total_cmp(&a.scores.first_deliveries)
                });
                table_rows.extend(sorted.into_iter().map(member_row));
            }
        }
    }

    let block = Block::default().borders(Borders::ALL).title(title);
    let mut widths = vec![
        Constraint::Min(30),
        Constraint::Length(5),
        Constraint::Length(5),
        Constraint::Length(7),
        Constraint::Length(7),
        Constraint::Length(5),
    ];
    widths.extend(std::iter::repeat_n(Constraint::Length(7), COLUMNS.len() - widths.len()));
    let table = Table::new(table_rows, widths).header(header).block(block);
    app.gossip_table_state.select(Some(sel_pos));
    f.render_stateful_widget(table, area, &mut app.gossip_table_state);
}

/// type (10 chars) + dir + two count columns + borders.
const AGENTS_PANEL_WIDTH: u16 = 29;

const COMBINED_COLOR: Color = Color::Cyan;

#[derive(Default)]
struct AgentCounts {
    conns_in: usize,
    conns_out: usize,
    meshes_in: usize,
    meshes_out: usize,
}

impl AgentCounts {
    fn add(&mut self, other: &AgentCounts) {
        self.conns_in += other.conns_in;
        self.conns_out += other.conns_out;
        self.meshes_in += other.meshes_in;
        self.meshes_out += other.meshes_out;
    }
}

/// Per-client-type counts (the user-agent segment before the first '/',
/// truncated to 10 chars), split by connection direction into in/out pairs:
/// connections and mesh memberships — a peer in 10 meshes contributes 10 to
/// its direction's mesh count.
fn draw_agent_counts(f: &mut Frame, area: Rect, app: &App) {
    let mut counts: HashMap<String, AgentCounts> = HashMap::new();
    for (_, row) in app.peers.rows() {
        let Some(p2p) = &row.p2p else { continue };
        let agent = row.scores.as_ref().map(|s| s.user_agent.as_str()).unwrap_or("");
        let kind = agent.split('/').next().unwrap_or("");
        let kind = if kind.is_empty() { "unknown" } else { kind };
        let entry = counts.entry(kind.chars().take(10).collect()).or_default();
        if p2p.inbound {
            entry.conns_in += 1;
            entry.meshes_in += row.topics.len();
        } else {
            entry.conns_out += 1;
            entry.meshes_out += row.topics.len();
        }
    }
    let mut ranked: Vec<(String, AgentCounts)> = counts.into_iter().collect();
    ranked.sort_by(|a, b| {
        (b.1.conns_in + b.1.conns_out)
            .cmp(&(a.1.conns_in + a.1.conns_out))
            .then_with(|| a.0.cmp(&b.0))
    });
    let mut total = AgentCounts::default();
    for (_, c) in &ranked {
        total.add(c);
    }

    let header = Row::new(["agent", "dir", "conn", "mesh"].map(Cell::from))
        .style(Style::default().add_modifier(Modifier::BOLD));
    let mut rows = Vec::with_capacity((ranked.len() + 1) * 3);
    let push_triple = |rows: &mut Vec<Row>, kind: &str, c: &AgentCounts| {
        let dir_row = |name, dir, conn: usize, mesh: usize| {
            Row::new([
                Cell::from(String::from(name)),
                Cell::from(dir),
                Cell::from(format!("{conn}")),
                Cell::from(format!("{mesh}")),
            ])
        };
        rows.push(dir_row(kind, "in", c.conns_in, c.meshes_in));
        rows.push(dir_row("", "out", c.conns_out, c.meshes_out));
        rows.push(
            dir_row("", "all", c.conns_in + c.conns_out, c.meshes_in + c.meshes_out)
                .style(Style::default().fg(COMBINED_COLOR)),
        );
    };
    for (kind, c) in &ranked {
        push_triple(&mut rows, kind, c);
    }
    push_triple(&mut rows, "total", &total);
    let table = Table::new(rows, [
        Constraint::Length(10),
        Constraint::Length(3),
        Constraint::Length(5),
        Constraint::Length(5),
    ])
    .header(header)
    .block(Block::default().borders(Borders::ALL).title(" peers "));
    f.render_widget(table, area);
}

/// One meshed peer of the selected topic: the peers-tab expansion fields
/// plus identity (conn + short id + agent) for log correlation.
fn member_row(m: &Member) -> Row<'static> {
    let t = m.scores;
    let conn = m.conn.map(|c| c.to_string()).unwrap_or_else(|| "·".to_string());
    let val = |v: f64| Cell::from(format!("{v:.1}"));
    Row::new(vec![
        Cell::from(format!("└ {conn} {} {}", m.short_id, m.agent)),
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
        Cell::from(format_secs(t.meshed_secs)),
        val(t.first_deliveries),
        val(t.mesh_deliveries),
        val(t.mesh_failure_penalty),
        val(t.invalid_deliveries),
        Cell::from(fwd_pct(t.fanout_total, t.fanout_sent)),
    ])
    .height(1)
    .style(Style::default().fg(Color::Green))
}
