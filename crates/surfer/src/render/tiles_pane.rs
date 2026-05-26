use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    symbols,
    text::Span,
    widgets::{Block, Borders, Cell, Paragraph, Row, Sparkline, Table},
};

use crate::app::App;

pub fn draw(f: &mut Frame, area: Rect, app: &mut App) {
    if app.tilemetrics.is_empty() {
        let block = Block::default().borders(Borders::ALL).title(" tiles ");
        let inner = block.inner(area);
        f.render_widget(block, area);
        f.render_widget(
            Paragraph::new("no tilemetrics queues discovered")
                .style(Style::default().fg(Color::DarkGray)),
            inner,
        );
        return;
    }

    if app.drilled_in {
        draw_spark(f, area, app);
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
    draw_spark(f, rows[1], app);
}

fn draw_table(f: &mut Frame, area: Rect, app: &mut App) {
    let block = Block::default().borders(Borders::ALL).title(" tiles ");
    let header = Row::new(vec![
        Cell::from("tile"),
        Cell::from("util %"),
        Cell::from("busy avg (ns)"),
        Cell::from("busy max (ns)"),
        Cell::from("loop_cnt"),
        Cell::from("samples"),
    ])
    .style(Style::default().add_modifier(Modifier::BOLD).fg(Color::White))
    .height(1);

    let rows: Vec<Row> = app
        .tilemetrics
        .iter()
        .enumerate()
        .map(|(i, t)| {
            let s = t.latest;
            let util = s.utilisation();
            let row_style = if i == app.tiles_selection {
                Style::default().bg(Color::DarkGray).fg(Color::White).add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            let util_style = if util > 0.9 {
                Style::default().fg(Color::Red)
            } else if util > 0.75 {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default().fg(Color::Green)
            };
            Row::new(vec![
                Cell::from(Span::styled(t.name.clone(), row_style)),
                Cell::from(Span::styled(format!("{:>6.1}%", util * 100.0), util_style)),
                Cell::from(format!("{:>12}", s.busy_avg())),
                Cell::from(format!("{:>12}", s.busy_max)),
                Cell::from(format!("{:>10}", s.loop_count)),
                Cell::from(format!("{:>10}", t.samples_seen)),
            ])
            .height(1)
        })
        .collect();

    let widths = [
        Constraint::Percentage(20),
        Constraint::Length(10),
        Constraint::Length(15),
        Constraint::Length(15),
        Constraint::Length(12),
        Constraint::Length(12),
    ];
    let table = Table::new(rows, widths).header(header).block(block);
    app.tiles_table_state.select(Some(app.tiles_selection));
    f.render_stateful_widget(table, area, &mut app.tiles_table_state);
}

fn draw_spark(f: &mut Frame, area: Rect, app: &mut App) {
    let Some(t) = app.tilemetrics.get(app.tiles_selection) else {
        f.render_widget(Block::default().borders(Borders::ALL).title(" util "), area);
        return;
    };
    let n = t.utilisation_hist.len();
    let span_label = if n == 0 {
        "no samples yet".to_string()
    } else {
        // Tile samples are emitted per 1024-iter window, not on the
        // 12s bucket clock — so the time span is approximate. We
        // show the sample count instead of a wall-clock duration.
        format!("{n} samples — newest at right")
    };
    let title = format!(" {} — utilisation — {span_label} ", t.name);
    let block = Block::default().borders(Borders::ALL).title(title);
    // Sparkline takes u64s; scale 0..1 → 0..1000 for resolution.
    let data: Vec<u64> = t.utilisation_hist.iter().map(|&u| (u * 1000.0) as u64).collect();
    let spark = Sparkline::default()
        .block(block)
        .data(&data)
        .max(1000)
        .style(Style::default().fg(Color::Cyan))
        .bar_set(symbols::bar::NINE_LEVELS);
    f.render_widget(spark, area);
}
