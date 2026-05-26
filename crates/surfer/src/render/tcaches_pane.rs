//! TCaches pane — one row per TCache instance. Visual is a horizontal
//! ring-buffer bar showing the head/min-tail occupancy, followed by
//! human-readable capacity + current length columns.
//!
//! Slot layout per CounterSet (synthesised by `schema::names_for`):
//!   0: capacity
//!   1: head_seq
//!   2..: tail_seq[i] — tails never updated by their consumer remain
//!       at the `u64::MAX` sentinel and are ignored.

use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    symbols,
    text::{Line, Span},
    widgets::{Axis, Block, Borders, Cell, Chart, Dataset, GraphType, Paragraph, Row, Table},
};

use crate::{app::App, render::fmt::fmt_span_ago, sources::counters::CounterSet};

pub fn draw(f: &mut Frame, area: Rect, app: &mut App) {
    if app.tcaches.is_empty() {
        let block = Block::default().borders(Borders::ALL).title(" tcaches ");
        let inner = block.inner(area);
        f.render_widget(block, area);
        f.render_widget(
            Paragraph::new("no tcache counters discovered")
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
    let block = Block::default().borders(Borders::ALL).title(" tcaches ");

    let header = Row::new(vec![
        Cell::from("name"),
        Cell::from("occupancy"),
        Cell::from("head"),
        Cell::from("min_tail"),
        Cell::from("capacity"),
        Cell::from("length"),
    ])
    .style(Style::default().add_modifier(Modifier::BOLD).fg(Color::White))
    .height(1);

    // Bar is column 1; width is what's left after the other columns.
    // ratatui doesn't expose computed column widths from the Table API,
    // so we hard-derive: area.width − name_pct(20%) − caps + spacing.
    let inner_w = area.width.saturating_sub(2) as usize; // borders
    let name_w = (inner_w * 20).div_ceil(100);
    let head_w = 12usize;
    let tail_w = 12usize;
    let cap_w = 12usize;
    let len_w = 12usize;
    let bar_w = inner_w.saturating_sub(name_w + head_w + tail_w + cap_w + len_w + 5); // 5 cell gaps

    let rows: Vec<Row> = app
        .tcaches
        .iter()
        .map(|set| {
            let view = TCacheView::from(set);
            let display_name = view.display_name();

            let bar_line = bar_line(view.capacity, view.head_seq, view.min_tail_seq, bar_w);

            Row::new(vec![
                Cell::from(display_name),
                Cell::from(bar_line),
                Cell::from(Span::raw(format!("{:>10}", fmt_bytes(view.head_seq)))),
                Cell::from(Span::raw(format!("{:>10}", fmt_bytes(view.min_tail_seq)))),
                Cell::from(Span::raw(format!("{:>10}", fmt_bytes(view.capacity)))),
                Cell::from(Span::raw(format!("{:>10}", fmt_bytes(view.length())))),
            ])
            .height(1)
        })
        .collect();

    let widths = [
        Constraint::Percentage(20),
        Constraint::Min(10),
        Constraint::Length(head_w as u16),
        Constraint::Length(tail_w as u16),
        Constraint::Length(cap_w as u16),
        Constraint::Length(len_w as u16),
    ];
    let table = Table::new(rows, widths).header(header).block(block);
    app.tcaches_table_state.select(Some(app.tcaches_selection));
    f.render_stateful_widget(table, area, &mut app.tcaches_table_state);
}

/// Per-line palette for tail consumers; head is always Cyan.
const TAIL_COLORS: &[Color] = &[
    Color::Magenta,
    Color::Yellow,
    Color::Green,
    Color::Red,
    Color::LightBlue,
    Color::LightMagenta,
    Color::LightYellow,
    Color::LightGreen,
];

struct ChartSeries {
    name: String,
    color: Color,
    data: Vec<(f64, f64)>,
}

fn draw_chart(f: &mut Frame, area: Rect, app: &App) {
    let Some(set) = app.tcaches.get(app.tcaches_selection) else {
        f.render_widget(Block::default().borders(Borders::ALL).title(" history "), area);
        return;
    };
    let view = TCacheView::from(set);

    // Collect head + every active tail. Slot 1 = head_seq,
    // slot 2..N = tail_seq[i]. Slot 0 (capacity) is constant so its
    // delta is always zero — skip.
    let mut series: Vec<ChartSeries> = Vec::new();
    if let Some(hist) = set.history.get(1) {
        let data: Vec<(f64, f64)> =
            hist.iter().enumerate().map(|(i, &v)| (i as f64, v as f64)).collect();
        series.push(ChartSeries { name: "head".to_string(), color: Color::Cyan, data });
    }
    for slot_idx in 2..set.current.len() {
        // u64::MAX = unused slot (no consumer registered). Real
        // consumers write their tail value, which can be 0 if
        // registered before any production.
        let current = set.current.get(slot_idx).copied().unwrap_or(u64::MAX);
        if current == u64::MAX {
            continue;
        }
        let Some(hist) = set.history.get(slot_idx) else { continue };
        if hist.is_empty() {
            continue;
        }
        let consumer_idx = slot_idx - 2;
        let color = TAIL_COLORS[consumer_idx % TAIL_COLORS.len()];
        let data: Vec<(f64, f64)> =
            hist.iter().enumerate().map(|(i, &v)| (i as f64, v as f64)).collect();
        series.push(ChartSeries { name: format!("tail_{consumer_idx}"), color, data });
    }

    let title = format!(" {} — 1s deltas (bytes/s) ", view.display_name());
    let block = Block::default().borders(Borders::ALL).title(title);

    let any_data = series.iter().any(|s| !s.data.is_empty());
    if !any_data {
        f.render_widget(block, area);
        return;
    }

    let y_max =
        series.iter().flat_map(|s| s.data.iter().map(|(_, y)| *y)).fold(0.0f64, f64::max).max(1.0);
    let n = series.iter().map(|s| s.data.len()).max().unwrap_or(0);
    let x_max = n.saturating_sub(1).max(1) as f64;

    let datasets: Vec<Dataset> = series
        .iter()
        .map(|s| {
            Dataset::default()
                .name(s.name.clone())
                .marker(symbols::Marker::Braille)
                .style(Style::default().fg(s.color))
                .graph_type(GraphType::Line)
                .data(&s.data)
        })
        .collect();

    let x_labels = vec![
        Line::from(format!("-{}", fmt_span_ago(n))),
        Line::from(format!("-{}", fmt_span_ago(n / 2))),
        Line::from("now"),
    ];
    let y_labels = vec![
        Line::from("0"),
        Line::from(format!("{}/s", fmt_bytes((y_max / 2.0).round() as u64))),
        Line::from(format!("{}/s", fmt_bytes(y_max.round() as u64))),
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
                .labels(y_labels)
                .style(Style::default().fg(Color::DarkGray)),
        );
    f.render_widget(chart, area);
}

/// Decoded view of a tcache counter file.
struct TCacheView<'a> {
    name: &'a str,
    capacity: u64,
    head_seq: u64,
    /// Minimum of every non-sentinel tail. If all tails are still at
    /// the `u64::MAX` sentinel (no consumer ever called free yet),
    /// falls back to `head_seq` so length renders as 0.
    min_tail_seq: u64,
}

impl<'a> TCacheView<'a> {
    fn from(set: &'a CounterSet) -> Self {
        let capacity = set.current.first().copied().unwrap_or(0);
        let head_seq = set.current.get(1).copied().unwrap_or(0);
        // Distinguish "no real consumer" from "consumer caught up":
        // - At least one real (non-sentinel) tail → use the minimum. Sentinel slots are
        //   unused; treat them as `head_seq` so they don't drag the minimum.
        // - All tails are sentinel → no consumer has ever published progress on this
        //   TCache. Show the ring contents as the producer sees them: from `head -
        //   capacity` up to `head` (clamped at 0 for pre-wrap producers).
        let any_real = set.current.iter().skip(2).any(|&t| t != u64::MAX);
        let min_tail_seq = if any_real {
            set.current
                .iter()
                .skip(2)
                .copied()
                .map(|t| if t == u64::MAX { head_seq } else { t })
                .min()
                .unwrap_or(head_seq)
        } else {
            head_seq.saturating_sub(capacity)
        };
        Self { name: &set.name, capacity, head_seq, min_tail_seq }
    }

    fn display_name(&self) -> String {
        self.name.strip_prefix("tcache-").unwrap_or(self.name).to_string()
    }

    fn length(&self) -> u64 {
        self.head_seq.saturating_sub(self.min_tail_seq)
    }
}

/// Build a horizontal bar showing the ring occupancy as a styled
/// `Line`. Filled section is `[min_tail_pos, head_pos)` wrapping when
/// `head < tail`. Width is `width` chars; `[`/`]` brackets sit outside
/// the count.
fn bar_line(capacity: u64, head_seq: u64, min_tail_seq: u64, width: usize) -> Line<'static> {
    if width < 3 || capacity == 0 {
        return Line::from("");
    }
    let inner = width.saturating_sub(2);
    // Modular positions inside the ring.
    let mask = capacity - 1;
    let head_pos = head_seq & mask;
    let tail_pos = min_tail_seq & mask;

    // Map a byte offset → bar character index.
    // tail_c uses floor (the byte sits inside char `tail_c`), head_c
    // uses ceil so any non-zero backlog always spans at least one
    // visible char even when head_pos and tail_pos round to the same
    // floor.
    let to_char_floor =
        |bytes: u64| -> usize { ((bytes as u128 * inner as u128) / capacity as u128) as usize };
    let to_char_ceil = |bytes: u64| -> usize {
        ((bytes as u128 * inner as u128).div_ceil(capacity as u128)) as usize
    };
    let head_c = to_char_ceil(head_pos);
    let tail_c = to_char_floor(tail_pos);
    let length = head_seq.saturating_sub(min_tail_seq);
    let full = length >= capacity;

    let bar: String = (0..inner)
        .map(|i| {
            if full {
                '█'
            } else if length == 0 {
                // Empty queue (head == min_tail) — render a vertical
                // marker at the head/tail position so the user can
                // still see where the cursor sits.
                if i == head_c { '│' } else { '░' }
            } else if head_c >= tail_c {
                if i >= tail_c && i < head_c { '█' } else { '░' }
            } else {
                // Wrapped.
                if i >= tail_c || i < head_c { '█' } else { '░' }
            }
        })
        .collect();

    Line::from(vec![
        Span::raw("["),
        Span::styled(bar, Style::default().fg(Color::Cyan)),
        Span::raw("]"),
    ])
}

fn fmt_bytes(bytes: u64) -> String {
    const KB: u64 = 1 << 10;
    const MB: u64 = 1 << 20;
    const GB: u64 = 1 << 30;
    if bytes == 0 {
        "0B".to_string()
    } else if bytes >= GB {
        format!("{:.2}GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2}MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2}KB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes}B")
    }
}
