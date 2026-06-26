use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    symbols,
    text::{Line, Span},
    widgets::{Axis, Block, Borders, Cell, Chart, Dataset, GraphType, Paragraph, Row, Table},
};

use crate::{
    app::App,
    render::fmt::{delta_span, fmt_signed, fmt_span_ago, fmt_u64},
};

pub fn draw(f: &mut Frame, area: Rect, app: &mut App) {
    if app.counters.is_empty() {
        let block = Block::default().borders(Borders::ALL).title(" counters ");
        let inner = block.inner(area);
        f.render_widget(block, area);
        let p =
            Paragraph::new("no counters discovered").style(Style::default().fg(Color::DarkGray));
        f.render_widget(p, inner);
        return;
    }

    if app.drilled_in {
        draw_chart(f, area, app);
        return;
    }
    // Vertical split: counter list on top, plot below. Split ratio
    // configurable via [/] keys.
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
    let block = Block::default().borders(Borders::ALL).title(" counters ");

    let header = Row::new(vec![
        Cell::from("source / counter"),
        Cell::from("value"),
        Cell::from("Δ 100ms"),
        Cell::from("Δ 1s"),
    ])
    .style(Style::default().add_modifier(Modifier::BOLD).fg(Color::White))
    .height(1);

    let (sel_set, sel_slot) = app.counters_selection;
    let mut rows: Vec<Row> = Vec::new();
    let mut prev_group: Option<&str> = None;

    for (set_idx, set) in app.counters.iter().enumerate() {
        let (group, thread) = crate::schema::group_of(&set.name);
        // One section header per group: thread counters of the same group share it.
        if prev_group != Some(group) {
            let mut header_spans = vec![Span::styled(
                format!("[{group}]"),
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
            )];
            if !set.schema_registered {
                header_spans.push(Span::raw("  "));
                header_spans
                    .push(Span::styled("(no schema registered)", Style::default().fg(Color::Red)));
            }
            rows.push(
                Row::new(vec![
                    Cell::from(Line::from(header_spans)),
                    Cell::from(""),
                    Cell::from(""),
                    Cell::from(""),
                ])
                .height(1),
            );
            prev_group = Some(group);
        }

        for (slot_idx, slot_name) in set.slot_names.iter().enumerate() {
            let cur = *set.current.get(slot_idx).unwrap_or(&0);
            let prev = *set.previous.get(slot_idx).unwrap_or(&0);
            let tick_delta = cur as i64 - prev as i64;
            let bucket_delta = set.last_bucket_delta(slot_idx) as i64;

            let selected = set_idx == sel_set && slot_idx == sel_slot;
            // Row-wide highlight: delta cells keep their own red/green fg and
            // just inherit the selected background.
            let row_style = if selected {
                Style::default().bg(Color::DarkGray).fg(Color::White).add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            let label = if thread.is_empty() {
                format!("  {slot_name}")
            } else {
                format!("  {thread} / {slot_name}")
            };
            let value_str = if set.signed { fmt_signed(cur as i64) } else { fmt_u64(cur) };
            rows.push(
                Row::new(vec![
                    Cell::from(label),
                    Cell::from(Span::raw(format!("{value_str:>10}"))),
                    Cell::from(Line::from(vec![delta_span(tick_delta, 10)])),
                    Cell::from(Line::from(vec![delta_span(bucket_delta, 10)])),
                ])
                .height(1)
                .style(row_style),
            );
        }
    }

    let widths = [
        Constraint::Percentage(40),
        Constraint::Length(12),
        Constraint::Length(12),
        Constraint::Length(12),
    ];
    let table = Table::new(rows, widths).header(header).block(block);
    let flat_idx = app.counters_flat_idx();
    app.counters_table_state.select(Some(flat_idx));
    f.render_stateful_widget(table, area, &mut app.counters_table_state);
}

fn draw_chart(f: &mut Frame, area: Rect, app: &mut App) {
    let (set_idx, slot_idx) = app.counters_selection;
    let Some(set) = app.counters.get(set_idx) else {
        f.render_widget(Block::default().borders(Borders::ALL).title(" history "), area);
        return;
    };
    let label = set.slot_names.get(slot_idx).map(String::as_str).unwrap_or("?");
    let Some(hist) = set.value_history.get(slot_idx) else {
        f.render_widget(Block::default().borders(Borders::ALL).title(" history "), area);
        return;
    };
    let n = hist.len();
    let secs = crate::sources::counters::BUCKET_SECS;
    let span_label = if n == 0 {
        "no buckets yet".to_string()
    } else {
        format!("{secs}s × {n} buckets — {} → now", fmt_span_ago(n))
    };
    let title = format!(" {} / {label} — {span_label} ", set.name);
    let block = Block::default().borders(Borders::ALL).title(title);
    if n == 0 {
        f.render_widget(block, area);
        return;
    }

    let signed = set.signed;
    let data: Vec<(f64, f64)> = hist
        .iter()
        .enumerate()
        .map(|(i, &v)| (i as f64, if signed { v as i64 as f64 } else { v as f64 }))
        .collect();
    // Value plot: auto-range to the data's span (padded) rather than anchoring
    // at 0, so the trajectory is visible regardless of magnitude.
    let data_lo = data.iter().map(|(_, y)| *y).fold(f64::INFINITY, f64::min);
    let data_hi = data.iter().map(|(_, y)| *y).fold(f64::NEG_INFINITY, f64::max);
    let pad = ((data_hi - data_lo) * 0.05).max(1.0);
    let y_min = data_lo - pad;
    let y_max = data_hi + pad;
    let x_max = n.saturating_sub(1).max(1) as f64;

    let datasets = vec![
        Dataset::default()
            .name("value")
            .marker(symbols::Marker::Braille)
            .style(Style::default().fg(Color::Cyan))
            .graph_type(GraphType::Line)
            .data(&data),
    ];

    let x_labels = vec![
        Line::from(format!("-{}", fmt_span_ago(n))),
        Line::from(format!("-{}", fmt_span_ago(n / 2))),
        Line::from("now"),
    ];
    let fmt_y = |v: f64| {
        if signed { fmt_signed(v.round() as i64) } else { fmt_u64(v.round() as u64) }
    };
    let y_labels = vec![
        Line::from(fmt_y(y_min)),
        Line::from(fmt_y((y_min + y_max) / 2.0)),
        Line::from(fmt_y(y_max)),
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
                .bounds([y_min, y_max])
                .labels(y_labels)
                .style(Style::default().fg(Color::DarkGray)),
        );
    f.render_widget(chart, area);
}
