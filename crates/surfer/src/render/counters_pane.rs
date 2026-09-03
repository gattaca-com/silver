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
    render::fmt::{delta_span, fmt_secs_ago, fmt_signed, fmt_span_ago, fmt_u64},
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
        draw_delta_chart(f, area, app);
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

    for (set_idx, set) in app.counters.iter().enumerate() {
        let mut header_spans = vec![Span::styled(
            format!("[{}]", set.name),
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

        for (slot_idx, slot_name) in set.slot_names.iter().enumerate() {
            let selected = set_idx == sel_set && slot_idx == sel_slot;
            if !set.slot_visible(slot_idx) && !selected {
                continue;
            }
            let cur = *set.current.get(slot_idx).unwrap_or(&0);
            let prev = *set.previous.get(slot_idx).unwrap_or(&0);
            let tick_delta = cur as i64 - prev as i64;
            let bucket_delta = set.last_bucket_delta(slot_idx) as i64;
            // Row-wide highlight: delta cells keep their own red/green fg and
            // just inherit the selected background.
            let row_style = if selected {
                Style::default().bg(Color::DarkGray).fg(Color::White).add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            rows.push(
                Row::new(vec![
                    Cell::from(format!("  {slot_name}")),
                    Cell::from(Span::raw(format!("{:>10}", fmt_u64(cur)))),
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
    // Group-header rows aren't selectable, so scrolling up stops one short
    // of them: when the selection is its group's first row, pull the offset
    // back to keep the `[source]` header in view.
    let first_of_group =
        app.counters.get(sel_set).is_some_and(|set| (0..sel_slot).all(|s| !set.slot_visible(s)));
    if first_of_group && flat_idx > 0 && app.counters_table_state.offset() >= flat_idx {
        *app.counters_table_state.offset_mut() = flat_idx - 1;
    }
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

    let data: Vec<(f64, f64)> =
        hist.iter().enumerate().map(|(i, &v)| (i as f64, v as f64)).collect();
    // Value plot: auto-range to the data's span (padded) rather than
    // anchoring at 0, so the trajectory is visible at any magnitude.
    let data_lo = data.iter().map(|(_, y)| *y).fold(f64::INFINITY, f64::min);
    let data_hi = data.iter().map(|(_, y)| *y).fold(f64::NEG_INFINITY, f64::max);
    let pad = ((data_hi - data_lo) * 0.05).max(1.0);
    let y_min = (data_lo - pad).max(0.0);
    let y_max = data_hi + pad;
    let x_max = n.saturating_sub(1).max(1) as f64;

    let datasets = vec![
        Dataset::default()
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
    let y_labels = vec![
        Line::from(fmt_u64(y_min.round() as u64)),
        Line::from(fmt_u64(((y_min + y_max) / 2.0).round() as u64)),
        Line::from(fmt_u64(y_max.round() as u64)),
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

fn draw_delta_chart(f: &mut Frame, area: Rect, app: &mut App) {
    const TICK_SECS: f64 = 0.1;

    let (set_idx, slot_idx) = app.counters_selection;
    let Some(set) = app.counters.get(set_idx) else {
        f.render_widget(Block::default().borders(Borders::ALL).title(" deltas "), area);
        return;
    };
    let label = set.slot_names.get(slot_idx).map(String::as_str).unwrap_or("?");
    let (Some(ticks), Some(buckets)) = (set.tick_history.get(slot_idx), set.history.get(slot_idx))
    else {
        f.render_widget(Block::default().borders(Borders::ALL).title(" deltas "), area);
        return;
    };
    let m = ticks.len();
    let n = buckets.len();
    let bucket_secs = crate::sources::counters::BUCKET_SECS as f64;

    // Rings store signed deltas wrapped through the u64 (gauge
    // decrements); cast back via i64 so they plot below zero instead
    // of as 1.8e19 spikes.
    let tick_data: Vec<(f64, f64)> = ticks
        .iter()
        .enumerate()
        .map(|(j, &v)| (((j + 1) as f64 - m as f64) * TICK_SECS, v as i64 as f64))
        .collect();
    let bucket_data: Vec<(f64, f64)> = buckets
        .iter()
        .enumerate()
        .map(|(i, &v)| (((i + 1) as f64 - n as f64) * bucket_secs, v as i64 as f64))
        .collect();

    let span_secs = (m as f64 * TICK_SECS).max(n as f64 * bucket_secs);
    let span_label = if m == 0 && n == 0 {
        "no samples yet".to_string()
    } else {
        format!("{} → now", fmt_secs_ago(span_secs.round() as u64))
    };
    let title = format!(" {} / {label} — deltas — {span_label} ", set.name);
    let block = Block::default().borders(Borders::ALL).title(title);
    if m == 0 && n == 0 {
        f.render_widget(block, area);
        return;
    }

    let ys = tick_data.iter().chain(&bucket_data).map(|&(_, y)| y);
    let data_lo = ys.clone().fold(0.0f64, f64::min);
    let data_hi = ys.fold(0.0f64, f64::max);
    let pad = ((data_hi - data_lo) * 0.05).max(1.0);
    let y_min = if data_lo < 0.0 { data_lo - pad } else { 0.0 };
    let y_max = data_hi + pad;
    let x_min = -span_secs.max(bucket_secs);

    let datasets = vec![
        Dataset::default()
            .name("Δ 100ms")
            .marker(symbols::Marker::Braille)
            .style(Style::default().fg(Color::Yellow))
            .graph_type(GraphType::Line)
            .data(&tick_data),
        Dataset::default()
            .name("Δ 1s")
            .marker(symbols::Marker::Braille)
            .style(Style::default().fg(Color::Cyan))
            .graph_type(GraphType::Line)
            .data(&bucket_data),
    ];

    let x_labels = vec![
        Line::from(format!("-{}", fmt_secs_ago(-x_min as u64))),
        Line::from(format!("-{}", fmt_secs_ago((-x_min / 2.0) as u64))),
        Line::from("now"),
    ];
    let y_labels = vec![
        Line::from(fmt_signed(y_min.round() as i64)),
        Line::from(fmt_signed(((y_min + y_max) / 2.0).round() as i64)),
        Line::from(fmt_signed(y_max.round() as i64)),
    ];

    let chart = Chart::new(datasets)
        .block(block)
        .x_axis(
            Axis::default()
                .bounds([x_min, 0.0])
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
