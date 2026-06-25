use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    symbols,
    text::Line,
    widgets::{Axis, Block, Borders, Cell, Chart, Dataset, GraphType, Paragraph, Row, Table},
};

use crate::{app::App, sources::timings::TimingChannel};

pub fn draw(f: &mut Frame, area: Rect, app: &mut App) {
    if app.timings.is_empty() {
        let block = Block::default().borders(Borders::ALL).title(" timings ");
        let inner = block.inner(area);
        f.render_widget(block, area);
        f.render_widget(
            Paragraph::new("no timing queues discovered")
                .style(Style::default().fg(Color::DarkGray)),
            inner,
        );
        return;
    }

    if app.drilled_in {
        draw_charts(f, area, app);
        return;
    }
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(app.split_pct),
            Constraint::Percentage(100 - app.split_pct),
        ])
        .split(area);

    draw_table(f, rows[0], app);
    draw_charts(f, rows[1], app);
}

fn draw_table(f: &mut Frame, area: Rect, app: &mut App) {
    let block = Block::default().borders(Borders::ALL).title(" timings ");
    let header = Row::new(vec![
        Cell::from("timer"),
        Cell::from("last"),
        Cell::from("p50 (last bucket)"),
        Cell::from("p99 (last bucket)"),
        Cell::from("count (last bucket)"),
    ])
    .style(Style::default().add_modifier(Modifier::BOLD).fg(Color::White))
    .height(1);

    let rows: Vec<Row> = app
        .timings
        .iter()
        .enumerate()
        .map(|(i, t)| {
            let last_bucket = t.latency.last_bucket().unwrap_or_default();
            let style = if i == app.timings_selection {
                Style::default().bg(Color::DarkGray).fg(Color::White).add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            Row::new(vec![
                Cell::from(t.name.clone()),
                Cell::from(format_ns(t.latency.last_ns)),
                Cell::from(format_ns(last_bucket.p50_ns)),
                Cell::from(format_ns(last_bucket.p99_ns)),
                Cell::from(format!("{:>10}", last_bucket.count)),
            ])
            .height(1)
            .style(style)
        })
        .collect();

    let widths = [
        Constraint::Percentage(35),
        Constraint::Length(12),
        Constraint::Length(18),
        Constraint::Length(18),
        Constraint::Length(20),
    ];
    let table = Table::new(rows, widths).header(header).block(block);
    app.timings_table_state.select(Some(app.timings_selection));
    f.render_stateful_widget(table, area, &mut app.timings_table_state);
}

fn draw_charts(f: &mut Frame, area: Rect, app: &App) {
    let Some(timer) = app.timings.get(app.timings_selection) else {
        f.render_widget(Block::default().borders(Borders::ALL).title(" history "), area);
        return;
    };
    draw_channel_chart(f, area, &timer.name, &timer.latency);
}

fn draw_channel_chart(f: &mut Frame, area: Rect, name: &str, ch: &TimingChannel) {
    let title = format!(
        " {name} — latency p50 / p99 over {}s buckets ",
        crate::sources::counters::BUCKET_SECS
    );
    let block = Block::default().borders(Borders::ALL).title(title);

    let buckets = &ch.history;
    let live = ch.current_bucket();
    if buckets.is_empty() && live.is_none() {
        f.render_widget(block, area);
        return;
    }

    let mut p50: Vec<(f64, f64)> =
        buckets.iter().enumerate().map(|(i, b)| (i as f64, b.p50_ns as f64 / 1_000.0)).collect();
    let mut p99: Vec<(f64, f64)> =
        buckets.iter().enumerate().map(|(i, b)| (i as f64, b.p99_ns as f64 / 1_000.0)).collect();
    if let Some(live) = live {
        let x = buckets.len() as f64;
        p50.push((x, live.p50_ns as f64 / 1_000.0));
        p99.push((x, live.p99_ns as f64 / 1_000.0));
    }

    let y_max = p99.iter().map(|(_, y)| *y).fold(0.0f64, f64::max).max(1.0);
    let n = p99.len();
    let x_max = n.saturating_sub(1).max(1) as f64;

    let datasets = vec![
        Dataset::default()
            .name("p50 µs")
            .marker(symbols::Marker::Braille)
            .style(Style::default().fg(Color::Magenta))
            .graph_type(GraphType::Line)
            .data(&p50),
        Dataset::default()
            .name("p99 µs")
            .marker(symbols::Marker::Braille)
            .style(Style::default().fg(Color::Yellow))
            .graph_type(GraphType::Line)
            .data(&p99),
    ];

    let span_fmt = crate::render::fmt::fmt_span_ago;
    let x_labels = vec![
        Line::from(format!("-{}", span_fmt(n))),
        Line::from(format!("-{}", span_fmt(n / 2))),
        Line::from("now"),
    ];
    let chart = Chart::new(datasets)
        .block(block)
        .x_axis(
            Axis::default()
                .bounds([0.0, x_max])
                .labels(x_labels)
                .style(Style::default().fg(Color::DarkGray)),
        )
        .y_axis(
            Axis::default()
                .bounds([0.0, y_max * 1.1])
                .labels(vec![Line::from("0"), Line::from(format!("{y_max:.0}µs"))])
                .style(Style::default().fg(Color::DarkGray)),
        );
    f.render_widget(chart, area);
}

fn format_ns(ns: u64) -> String {
    if ns == 0 {
        "·".to_string()
    } else if ns < 1_000 {
        format!("{ns}ns")
    } else if ns < 1_000_000 {
        format!("{:.2}µs", ns as f64 / 1_000.0)
    } else if ns < 1_000_000_000 {
        format!("{:.2}ms", ns as f64 / 1_000_000.0)
    } else {
        format!("{:.2}s", ns as f64 / 1_000_000_000.0)
    }
}
