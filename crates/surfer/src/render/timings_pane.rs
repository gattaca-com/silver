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

const LAT_COLOR: Color = Color::Cyan;
const PROC_COLOR: Color = Color::Yellow;

fn draw_table(f: &mut Frame, area: Rect, app: &mut App) {
    let block =
        Block::default().borders(Borders::ALL).title(" timings — latency | processing (bucket) ");
    let lat_hdr = Style::default().add_modifier(Modifier::BOLD).fg(LAT_COLOR);
    let proc_hdr = Style::default().add_modifier(Modifier::BOLD).fg(PROC_COLOR);
    let header = Row::new(vec![
        Cell::from("timer").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("last").style(lat_hdr),
        Cell::from("p50").style(lat_hdr),
        Cell::from("p99").style(lat_hdr),
        Cell::from("max").style(lat_hdr),
        Cell::from("last").style(proc_hdr),
        Cell::from("p50").style(proc_hdr),
        Cell::from("p99").style(proc_hdr),
        Cell::from("max").style(proc_hdr),
        Cell::from("count").style(Style::default().add_modifier(Modifier::BOLD)),
    ])
    .height(1);

    let rows: Vec<Row> = app
        .timings
        .iter()
        .enumerate()
        .map(|(i, t)| {
            let lat = t.latency.last_bucket().unwrap_or_default();
            let (proc_last, proc_max, proc_bucket) = match &t.processing {
                Some(p) => (p.last_ns, p.max_ns, p.last_bucket().unwrap_or_default()),
                None => (0, 0, Default::default()),
            };
            let style = if i == app.timings_selection {
                Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            let lat_cell = |ns| Cell::from(format_ns(ns)).style(Style::default().fg(LAT_COLOR));
            let proc_cell = |ns| Cell::from(format_ns(ns)).style(Style::default().fg(PROC_COLOR));
            Row::new(vec![
                Cell::from(t.name.clone()),
                lat_cell(t.latency.last_ns),
                lat_cell(lat.p50_ns),
                lat_cell(lat.p99_ns),
                lat_cell(t.latency.max_ns),
                proc_cell(proc_last),
                proc_cell(proc_bucket.p50_ns),
                proc_cell(proc_bucket.p99_ns),
                proc_cell(proc_max),
                Cell::from(format!("{:>8}", lat.count)),
            ])
            .height(1)
            .style(style)
        })
        .collect();

    let widths = [
        Constraint::Percentage(26),
        Constraint::Length(10),
        Constraint::Length(10),
        Constraint::Length(10),
        Constraint::Length(10),
        Constraint::Length(10),
        Constraint::Length(10),
        Constraint::Length(10),
        Constraint::Length(10),
        Constraint::Length(10),
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
    draw_channel_chart(f, area, timer);
}

type Series = Vec<(f64, f64)>;

/// (p50, p99) series in µs from a channel's rolled buckets plus the live one.
fn percentile_series(ch: &TimingChannel) -> (Series, Series) {
    let buckets = &ch.history;
    let mut p50: Vec<(f64, f64)> =
        buckets.iter().enumerate().map(|(i, b)| (i as f64, b.p50_ns as f64 / 1_000.0)).collect();
    let mut p99: Vec<(f64, f64)> =
        buckets.iter().enumerate().map(|(i, b)| (i as f64, b.p99_ns as f64 / 1_000.0)).collect();
    if let Some(live) = ch.current_bucket() {
        let x = buckets.len() as f64;
        p50.push((x, live.p50_ns as f64 / 1_000.0));
        p99.push((x, live.p99_ns as f64 / 1_000.0));
    }
    (p50, p99)
}

fn draw_channel_chart(f: &mut Frame, area: Rect, timer: &crate::sources::timings::TimingSet) {
    let title = format!(
        " {} — latency / processing p50 p99 over {}s buckets ",
        timer.name,
        crate::sources::counters::BUCKET_SECS
    );
    let block = Block::default().borders(Borders::ALL).title(title);

    let (lat_p50, lat_p99) = percentile_series(&timer.latency);
    let (proc_p50, proc_p99) = timer.processing.as_ref().map(percentile_series).unwrap_or_default();
    if lat_p99.is_empty() && proc_p99.is_empty() {
        f.render_widget(block, area);
        return;
    }

    let y_max = lat_p99.iter().chain(&proc_p99).map(|(_, y)| *y).fold(0.0f64, f64::max).max(1.0);
    let n = lat_p99.len().max(proc_p99.len());
    let x_max = n.saturating_sub(1).max(1) as f64;

    let mut datasets = vec![
        Dataset::default()
            .name("lat p50 µs")
            .marker(symbols::Marker::Braille)
            .style(Style::default().fg(LAT_COLOR))
            .graph_type(GraphType::Line)
            .data(&lat_p50),
        Dataset::default()
            .name("lat p99 µs")
            .marker(symbols::Marker::Braille)
            .style(Style::default().fg(Color::LightCyan))
            .graph_type(GraphType::Line)
            .data(&lat_p99),
    ];
    if !proc_p99.is_empty() {
        datasets.push(
            Dataset::default()
                .name("proc p50 µs")
                .marker(symbols::Marker::Braille)
                .style(Style::default().fg(PROC_COLOR))
                .graph_type(GraphType::Line)
                .data(&proc_p50),
        );
        datasets.push(
            Dataset::default()
                .name("proc p99 µs")
                .marker(symbols::Marker::Braille)
                .style(Style::default().fg(Color::LightYellow))
                .graph_type(GraphType::Line)
                .data(&proc_p99),
        );
    }

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
