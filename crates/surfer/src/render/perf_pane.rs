use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    symbols,
    text::{Line, Span},
    widgets::{Axis, Block, Borders, Cell, Chart, Dataset, GraphType, Paragraph, Row, Table},
};

use crate::{app::App, render::fmt::fmt_span_ago};

pub fn draw(f: &mut Frame, area: Rect, app: &mut App) {
    if app.perf.is_empty() {
        let block = Block::default().borders(Borders::ALL).title(" perf ");
        let inner = block.inner(area);
        f.render_widget(block, area);
        f.render_widget(
            Paragraph::new("no perf queues discovered (build with --features perf)")
                .style(Style::default().fg(Color::DarkGray)),
            inner,
        );
        return;
    }

    if app.drilled_in {
        draw_chart(f, area, app);
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
    draw_chart(f, rows[1], app);
}

fn draw_table(f: &mut Frame, area: Rect, app: &mut App) {
    let block = Block::default().borders(Borders::ALL).title(" perf — 30 s avg per call ");
    let header = Row::new(vec![
        Cell::from("function"),
        Cell::from("calls/s"),
        Cell::from("instr"),
        Cell::from("cycles"),
        Cell::from("ipc"),
        Cell::from("br/1k"),
        Cell::from("llc/call"),
    ])
    .style(Style::default().add_modifier(Modifier::BOLD).fg(Color::White))
    .height(1);

    let rows: Vec<Row> = app
        .perf
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let row_style = if i == app.perf_selection {
                Style::default().bg(Color::DarkGray).fg(Color::White).add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            Row::new(vec![
                Cell::from(Span::styled(p.name.clone(), row_style)),
                Cell::from(format!("{:>9}", p.call_rate())),
                Cell::from(format!("{:>12}", p.instr_avg())),
                Cell::from(format!("{:>12}", p.cycles_avg())),
                Cell::from(format!("{:>6.2}", p.ipc())),
                Cell::from(format!("{:>7.2}", p.branch_per_kinstr())),
                Cell::from(format!("{:>9}", p.cache_miss_avg())),
            ])
            .height(1)
        })
        .collect();

    let widths = [
        Constraint::Percentage(42),
        Constraint::Length(10),
        Constraint::Length(14),
        Constraint::Length(14),
        Constraint::Length(8),
        Constraint::Length(9),
        Constraint::Length(10),
    ];
    let table = Table::new(rows, widths).header(header).block(block);
    app.perf_table_state.select(Some(app.perf_selection));
    f.render_stateful_widget(table, area, &mut app.perf_table_state);
}

/// IPC over the retained bucket ring for the selected function.
fn draw_chart(f: &mut Frame, area: Rect, app: &mut App) {
    let Some(p) = app.perf.get(app.perf_selection) else {
        f.render_widget(Block::default().borders(Borders::ALL).title(" ipc "), area);
        return;
    };
    let n = p.history.len();
    let title = format!(" {} — ipc ", p.name);
    let block = Block::default().borders(Borders::ALL).title(title);
    if n == 0 || !p.has_data() {
        let inner = block.inner(area);
        f.render_widget(block, area);
        f.render_widget(
            Paragraph::new("no samples yet").style(Style::default().fg(Color::DarkGray)),
            inner,
        );
        return;
    }

    // One bucket per second, oldest at x=0, newest at right.
    let data: Vec<(f64, f64)> =
        p.history.iter().enumerate().map(|(i, b)| (i as f64, b.ipc())).collect();
    let y_max = data.iter().map(|(_, y)| *y).fold(0.0_f64, f64::max).max(1.0);
    let x_max = n.saturating_sub(1).max(1) as f64;

    let dataset = Dataset::default()
        .marker(symbols::Marker::Braille)
        .style(Style::default().fg(Color::Cyan))
        .graph_type(GraphType::Line)
        .data(&data);

    let x_labels = vec![
        Line::from(format!("-{}", fmt_span_ago(n))),
        Line::from(format!("-{}", fmt_span_ago(n / 2))),
        Line::from("now"),
    ];
    let chart = Chart::new(vec![dataset])
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
                .labels(vec![Line::from("0"), Line::from(format!("{y_max:.1}"))])
                .style(Style::default().fg(Color::DarkGray)),
        );
    f.render_widget(chart, area);
}
