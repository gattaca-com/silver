use std::time::Duration;

use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
};
use silver_common::{ClusterProgress, Nanos};

use crate::{
    app::App,
    render::fmt::fmt_nanos,
    sources::{cluster::ClusterPeerRow, counters::CounterSet, timings::TimingSet},
};

/// One mainnet slot of 1 s buckets.
const WINDOW_BUCKETS: usize = 12;
const LABEL_WIDTH: usize = 18;

const PEER_COLUMNS: [(&str, &str); 9] = [
    ("peer", "the voter this row describes; ★ marks the leader"),
    ("link", "QUIC connection to the peer, and its round trip"),
    ("raft rtt", "heartbeat → response round trip, leader only; includes the peer's loop stalls"),
    ("last heard", "time since this node last received any Raft message from the peer"),
    ("replication", "leader only: the peer's state and how many log entries it lags"),
    ("in flight", "leader only: appends sent and not yet acknowledged"),
    ("msgs out · in", "Raft messages to and from the peer since start"),
    ("queue", "messages waiting in the cluster stream to the peer, out of 128"),
    (
        "evicted",
        "messages the full cluster stream dropped since start; any growth means lost Raft messages",
    ),
];

struct ClusterCounterValues<'a> {
    set: &'a CounterSet,
}

impl<'a> ClusterCounterValues<'a> {
    fn find(app: &'a App) -> Option<Self> {
        app.counters.iter().find(|set| set.name == "cluster").map(|set| Self { set })
    }

    fn index(&self, name: &str) -> Option<usize> {
        self.set.slot_names.iter().position(|slot| slot == name)
    }

    fn value(&self, name: &str) -> u64 {
        self.index(name).map_or(0, |i| self.set.current[i])
    }

    fn window(&self, name: &str) -> u64 {
        self.index(name).map_or(0, |i| self.set.history[i].iter().rev().take(WINDOW_BUCKETS).sum())
    }
}

pub fn draw(f: &mut Frame, area: Rect, app: &mut App) {
    let key_height = PEER_COLUMNS.len() as u16 - 1;
    let [summary, table, key] = Layout::vertical([
        Constraint::Length(7),
        Constraint::Min(3),
        Constraint::Length(key_height),
    ])
    .areas(area);
    let counters = ClusterCounterValues::find(app);
    draw_summary(f, summary, app, counters.as_ref());
    draw_peers(f, table, app, counters.as_ref());
    draw_key(f, key);
}

fn draw_summary(f: &mut Frame, area: Rect, app: &App, counters: Option<&ClusterCounterValues>) {
    let block = Block::default().borders(Borders::ALL).title(" cluster ");
    let inner = block.inner(area);
    f.render_widget(block, area);

    let Some(counters) = counters else {
        f.render_widget(
            Paragraph::new("no counters-cluster file discovered")
                .style(Style::default().fg(Color::DarkGray)),
            inner,
        );
        return;
    };

    let columns = [
        node_column(counters),
        locks_column(counters),
        refused_column(counters),
        commit_column(counters, app),
    ];
    let areas = Layout::horizontal([Constraint::Ratio(1, 4); 4]).spacing(2).split(inner);
    for (lines, area) in columns.into_iter().zip(areas.iter()) {
        f.render_widget(Paragraph::new(lines), *area);
    }
}

fn heading(text: &str) -> Line<'static> {
    Line::from(Span::styled(
        text.to_string(),
        Style::default().add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
    ))
}

fn entry(label: &str, value: Span<'static>) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{label:<LABEL_WIDTH$}"), Style::default().fg(Color::DarkGray)),
        value,
    ])
}

/// Red when nonzero: these stay at 0 on a healthy cluster with one signer.
fn alarm(counters: &ClusterCounterValues, names: &[&str]) -> Span<'static> {
    let n: u64 = names.iter().map(|name| counters.window(name)).sum();
    let style = if n > 0 { Style::default().fg(Color::Red) } else { Style::default() };
    Span::styled(n.to_string(), style)
}

fn node_column(counters: &ClusterCounterValues) -> Vec<Line<'static>> {
    let (role, role_color) = match counters.value("Role") {
        0 => ("▲ follower", Color::Cyan),
        1 => ("candidate", Color::Yellow),
        _ => ("★ leader", Color::Green),
    };
    let duties = if counters.value("FloorLatched") == 1 {
        Span::styled(
            format!("from slot {}", counters.value("StartupFloorSlot")),
            Style::default().fg(Color::Green),
        )
    } else {
        Span::styled("refused until synced", Style::default().fg(Color::Yellow))
    };
    let raft = if counters.value("Failed") == 1 {
        Span::styled("FAILED", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))
    } else {
        Span::raw("running")
    };
    vec![
        heading("node"),
        entry(
            "role",
            Span::styled(role, Style::default().fg(role_color).add_modifier(Modifier::BOLD)),
        ),
        entry(
            "leader · term",
            Span::raw(format!("{} · {}", counters.value("LeaderId"), counters.value("Term"))),
        ),
        entry("duties", duties),
        entry("raft", raft),
    ]
}

fn locks_column(counters: &ClusterCounterValues) -> Vec<Line<'static>> {
    let count = |names: &[&str]| {
        Span::raw(names.iter().map(|name| counters.window(name)).sum::<u64>().to_string())
    };
    vec![
        heading(&format!("locks, last {WINDOW_BUCKETS}s")),
        entry("proposals", count(&["ProposalsSubmitted"])),
        entry("locks taken", count(&["AttestationLockAccepted", "BlockLockAccepted"])),
        entry("identical repeats", count(&["AttestationLockSame", "BlockLockSame"])),
    ]
}

fn refused_column(counters: &ClusterCounterValues) -> Vec<Line<'static>> {
    vec![
        heading(&format!("refused, last {WINDOW_BUCKETS}s")),
        entry("conflicting", alarm(counters, &["AttestationLockConflicting"])),
        entry("surrounding", alarm(counters, &["AttestationLockSurrounding"])),
        entry("block conflicting", alarm(counters, &["BlockLockConflicting"])),
        entry("too old", alarm(counters, &["AttestationLockTooOld", "BlockLockTooOld"])),
    ]
}

/// Clustering latency is signed duty received → lock released. Attestations
/// and blocks take the same Raft path, so each figure is the slower of the two.
fn commit_column(counters: &ClusterCounterValues, app: &App) -> Vec<Line<'static>> {
    let sets: Vec<&TimingSet> = ["cluster_duty_attestation", "cluster_duty_block"]
        .iter()
        .filter_map(|name| app.timings.iter().find(|set| set.name == *name))
        .collect();
    let buckets: Vec<_> = sets.iter().filter_map(|set| set.latency.last_bucket()).collect();
    let fmt = |ns: Option<u64>| ns.map_or_else(|| "-".to_string(), |ns| fmt_nanos(Nanos(ns)));
    vec![
        heading(&format!("commits, last {WINDOW_BUCKETS}s")),
        entry("timed out", alarm(counters, &["ProposalsTimedOut"])),
        entry("dropped batches", alarm(counters, &["ProposalBatchesDropped"])),
        entry(
            "latency p50 · p99",
            Span::raw(format!(
                "{} · {}",
                fmt(buckets.iter().map(|b| b.p50_ns).max()),
                fmt(buckets.iter().map(|b| b.p99_ns).max()),
            )),
        ),
        entry("latency max", Span::raw(fmt(sets.iter().map(|set| set.latency.max_ns).max()))),
    ]
}

fn draw_peers(f: &mut Frame, area: Rect, app: &App, counters: Option<&ClusterCounterValues>) {
    let block = Block::default().borders(Borders::ALL).title(" raft peers ");
    let header = Row::new(PEER_COLUMNS.map(|(name, _)| Cell::from(name)))
        .style(Style::default().add_modifier(Modifier::BOLD).fg(Color::White));
    let last_index = counters.map(|counters| counters.value("LastIndex"));
    let rows: Vec<Row> = app
        .peers
        .cluster()
        .iter()
        .map(|(node_id, row)| peer_row(*node_id, row, last_index))
        .collect();
    let widths = [
        Constraint::Length(6),
        Constraint::Length(11),
        Constraint::Length(9),
        Constraint::Length(11),
        Constraint::Length(18),
        Constraint::Length(10),
        Constraint::Length(16),
        Constraint::Length(6),
        Constraint::Length(8),
    ];
    f.render_widget(Table::new(rows, widths).header(header).block(block), area);
}

fn draw_key(f: &mut Frame, area: Rect) {
    let lines: Vec<Line> = PEER_COLUMNS[1..]
        .iter()
        .map(|(name, meaning)| {
            Line::from(vec![
                Span::styled(format!("{name}: "), Style::default().add_modifier(Modifier::BOLD)),
                Span::styled(*meaning, Style::default().fg(Color::DarkGray)),
            ])
        })
        .collect();
    f.render_widget(Paragraph::new(lines), area);
}

fn peer_row(node_id: u64, row: &ClusterPeerRow, last_index: Option<u64>) -> Row<'static> {
    let dash = || Cell::from("-");
    let raft = row.raft.as_ref();
    let link = row.link.as_ref();
    let is_leader = raft.is_some_and(|raft| raft.is_leader);
    let fmt_duration = |d: Duration| fmt_nanos(Nanos(d.as_nanos() as u64));

    let peer = Cell::from(if is_leader { format!("{node_id} ★") } else { node_id.to_string() });
    let link_cell = link.map_or_else(dash, |link| {
        if link.connected {
            Cell::from(format!("✓ {}", fmt_duration(link.rtt)))
                .style(Style::default().fg(Color::Green))
        } else {
            Cell::from("✗").style(Style::default().fg(Color::Red))
        }
    });
    let raft_rtt =
        raft.and_then(|raft| raft.raft_rtt).map_or_else(dash, |rtt| Cell::from(fmt_duration(rtt)));
    let last_heard = raft
        .and_then(|raft| raft.last_contact)
        .map_or_else(dash, |age| Cell::from(fmt_duration(age)));
    let replicating = raft.filter(|raft| raft.progress != ClusterProgress::Follower);
    let replication = replicating.map_or_else(dash, |raft| {
        let (label, color) = match raft.progress {
            ClusterProgress::Replicate => ("replicate", Color::Green),
            ClusterProgress::Probe => ("probe", Color::Yellow),
            ClusterProgress::Snapshot => ("snapshot", Color::Red),
            ClusterProgress::Follower => unreachable!("filtered above"),
        };
        let lag = last_index.map_or(String::new(), |last| {
            format!(" · lag {}", last.saturating_sub(raft.match_index))
        });
        Cell::from(format!("{label}{lag}")).style(Style::default().fg(color))
    });
    let number =
        |value: Option<u64>| value.map_or_else(dash, |value| Cell::from(value.to_string()));
    let messages = raft.map_or_else(dash, |raft| {
        Cell::from(format!("{} · {}", raft.messages_out, raft.messages_in))
    });
    let evicted = link.map_or_else(dash, |link| {
        let style =
            if link.overwrites > 0 { Style::default().fg(Color::Red) } else { Style::default() };
        Cell::from(link.overwrites.to_string()).style(style)
    });

    Row::new(vec![
        peer,
        link_cell,
        raft_rtt,
        last_heard,
        replication,
        number(replicating.map(|raft| raft.inflight)),
        messages,
        number(link.map(|link| link.out_queue_len)),
        evicted,
    ])
}
