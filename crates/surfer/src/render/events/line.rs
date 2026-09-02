//! One text line per display row, on a grid fitted to the rows being shown:
//! `label │ time │ start │ bar on the axis │ duration [attributes] │ margin`.

use ratatui::{
    style::{Color, Style},
    text::{Line, Span as TextSpan},
};
use silver_common::{Nanos, PayloadValidationStatus};
use silver_stages::SlotClock;

use super::{
    axis::Axis,
    palette,
    tree::{DisplayRow, Fold, Node},
};
use crate::{
    render::fmt::{fmt_nanos, root_prefix, wall_time},
    sources::events::{BlockTrace, DaSpan, Interval, Margin, Span},
};

const HEADINGS: [&str; 5] = ["slot/component", "time", "start", "duration", "deadline"];

/// Column widths for one draw: each text column is as wide as its widest
/// cell or heading, and the axis takes what is left.
pub struct Grid {
    label: usize,
    time: usize,
    start: usize,
    pub axis: usize,
    duration: usize,
    margin: usize,
}

impl Grid {
    /// Single spaces between the six columns.
    const GAPS: usize = 5;

    pub fn fit<'a>(cells: impl Iterator<Item = &'a RowCells> + Clone, inner_width: usize) -> Self {
        let widest = |min: &str, text: fn(&RowCells) -> usize| {
            cells.clone().map(text).max().unwrap_or(0).max(min.chars().count())
        };
        let [label, time, start, duration, margin] = HEADINGS;
        let label = widest(label, |c| c.label.chars().count());
        let time = widest(time, |c| c.time.chars().count());
        let start = widest(start, |c| c.start.chars().count());
        let duration = widest(duration, |c| c.duration.chars().count());
        let margin = widest(margin, |c| c.margin_text().chars().count());
        let axis =
            inner_width.saturating_sub(label + time + start + duration + margin + Self::GAPS);
        Self { label, time, start, axis, duration, margin }
    }

    #[cfg(test)]
    fn width(&self) -> usize {
        self.label + self.time + self.start + self.axis + self.duration + self.margin + Self::GAPS
    }

    pub fn header(&self, axis: &Axis) -> Line<'static> {
        let [label, time, start, duration, margin] = HEADINGS;
        let head = format!(
            "{label:<lw$} {time:<tw$} {start:<sw$} {} {duration:<dw$} {margin:<mw$}",
            axis.ticks(),
            lw = self.label,
            tw = self.time,
            sw = self.start,
            dw = self.duration,
            mw = self.margin,
        );
        Line::styled(head, Style::default().fg(palette::HEADER))
    }
}

/// The row's text per column plus its bar geometry, ahead of layout.
pub struct RowCells {
    pub label: String,
    pub time: String,
    pub start: String,
    pub offset: Option<Nanos>,
    pub len: Nanos,
    pub duration: String,
    pub margin: Option<Margin>,
    bar_color: Color,
    label_color: Color,
}

impl RowCells {
    pub fn new(
        trace: &BlockTrace,
        display: &DisplayRow,
        clock: &SlotClock,
        deadline: Nanos,
    ) -> Self {
        let node = display.node;
        let interval = node.interval(trace);
        let offset = interval.and_then(|iv| trace.offset_in_slot(clock, iv.start));
        let time = interval.map_or_else(|| "-".to_string(), |iv| wall_time(iv.start));
        let start = offset.map_or_else(|| "-".to_string(), fmt_nanos);
        let len = interval.map_or(Nanos(0), Interval::duration);
        let duration = match interval {
            Some(iv) if !node.is_instant(trace) => fmt_nanos(iv.duration()),
            _ => String::new(),
        };
        let margin = match node {
            Node::Span(Span::Strip) => trace.deadline_margin(clock, deadline),
            _ => None,
        };
        Self {
            label: label(trace, display),
            time,
            start,
            offset,
            len,
            duration: [duration, attributes(trace, node)]
                .into_iter()
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join(" "),
            margin,
            bar_color: palette::node_color(trace, node),
            label_color: palette::label_color(trace, node),
        }
    }

    fn margin_text(&self) -> String {
        self.margin.map_or_else(String::new, |m| {
            let sign = if m.made_it { '+' } else { '-' };
            format!("{sign}{}", fmt_nanos(m.delta))
        })
    }

    pub fn into_line(self, grid: &Grid, axis: &Axis) -> Line<'static> {
        let bar_style = Style::default().fg(self.bar_color);
        let margin_style = self
            .margin
            .map_or_else(Style::default, |m| Style::default().fg(palette::margin_color(m)));
        Line::from(vec![
            TextSpan::styled(
                format!(
                    "{:<lw$} {:<tw$} {:<sw$} ",
                    self.label,
                    self.time,
                    self.start,
                    lw = grid.label,
                    tw = grid.time,
                    sw = grid.start,
                ),
                Style::default().fg(self.label_color),
            ),
            TextSpan::styled(axis.bar(self.offset, self.len), bar_style),
            TextSpan::styled(format!(" {:<dw$} ", self.duration, dw = grid.duration), bar_style),
            TextSpan::styled(
                format!("{:<mw$}", self.margin_text(), mw = grid.margin),
                margin_style,
            ),
        ])
    }
}

/// Indented by depth; openers carry a fold glyph, leaves a blank of the same
/// width so sibling text aligns.
fn label(trace: &BlockTrace, display: &DisplayRow) -> String {
    let indent = "  ".repeat(display.depth as usize);
    let marker = match display.fold {
        Fold::Open => "▾ ",
        Fold::Closed => "▸ ",
        Fold::Leaf => "  ",
    };
    let text = match display.node {
        Node::Span(Span::Strip) => format!("{} {}", trace.slot, root_prefix(&trace.block_root)),
        Node::Span(span) => span.spec().label.to_string(),
        Node::Col(i) => format!("col {}", trace.da.columns[i].index),
    };
    format!("{indent}{marker}{text}")
}

fn attributes(trace: &BlockTrace, node: Node) -> String {
    match node {
        // The gate open with no sidecars ever seen: a block without
        // blobs, whose DA is trivially satisfied — not a display hole.
        Node::Span(Span::Da(DaSpan::Root))
            if !trace.da.has_columns() && trace.da.available().is_some() =>
        {
            "no blobs".to_string()
        }
        Node::Span(Span::Da(DaSpan::Custody)) => format!("{} held", trace.da.columns.len()),
        Node::Span(Span::Da(DaSpan::Cols(source))) => {
            let of_source = || trace.da.of_source(source).map(|(_, c)| c);
            match trace.da.available() {
                Some(gate) => format!(
                    "{}/{}",
                    of_source().filter(|c| c.received_at <= gate).count(),
                    of_source().count()
                ),
                None => of_source().count().to_string(),
            }
        }
        Node::Span(Span::El) => {
            trace.el.status().map_or_else(String::new, |v| status_label(v).to_string())
        }
        _ => String::new(),
    }
}

/// Spelled out next to the `el` duration: a syncing or accepted EL answers in a
/// few ms without executing the payload, so the round-trip alone reads as a
/// fast success.
fn status_label(status: PayloadValidationStatus) -> &'static str {
    match status {
        PayloadValidationStatus::Valid => "valid",
        PayloadValidationStatus::Invalid => "invalid",
        PayloadValidationStatus::Syncing => "syncing",
        PayloadValidationStatus::Accepted => "accepted",
    }
}

#[cfg(test)]
mod tests {
    use silver_stages::Stage;

    use super::*;
    use crate::{
        render::events::tree::{Expanded, Group, display_rows},
        sources::events::{
            BlockTraces,
            trace_tests::{APPLY, DA, GENESIS_SECS, SLOT_MS, el_sent, received, trace, valid},
        },
    };

    const DEADLINE: Nanos = Nanos::from_millis(4_000);
    const INNER_WIDTH: usize = 120;

    fn clock() -> SlotClock {
        SlotClock::new(GENESIS_SECS, SLOT_MS)
    }

    fn block() -> BlockTrace {
        trace(&[
            (received(), 300),
            (el_sent(), 320),
            (Stage::DaAvailable, 350),
            (Stage::StfImported, 460),
            (valid(), 520),
        ])
    }

    /// Every row of a fully unfolded block, paired with its cells.
    fn all_rows(block: BlockTrace) -> Vec<(DisplayRow, RowCells)> {
        let mut expanded = Expanded::default();
        for group in [Group::Block, Group::Da, Group::Stf] {
            expanded.toggle(block.block_root, group);
        }
        let traces = BlockTraces::from_iter([block]);
        display_rows(&traces, &expanded)
            .into_iter()
            .map(|d| {
                let cells = RowCells::new(&traces[0], &d, &clock(), DEADLINE);
                (d, cells)
            })
            .collect()
    }

    fn cells_of(cells: &[(DisplayRow, RowCells)], node: Node) -> &RowCells {
        &cells.iter().find(|(d, _)| d.node == node).expect("node displayed").1
    }

    #[test]
    fn cells_carry_start_duration_and_annotations() {
        let cells = all_rows(block());

        let strip = cells_of(&cells, Node::Span(Span::Strip));
        assert_eq!(strip.label, "▾ 2 01010101");
        assert_eq!(strip.start, "300ms");
        assert_eq!(strip.duration, "220ms", "arrival → attestable");
        assert_eq!(strip.margin, Some(Margin { delta: Nanos::from_millis(3_480), made_it: true }));
        assert_eq!(strip.margin_text(), "+3.48s");

        let el = cells_of(&cells, Node::Span(Span::El));
        assert_eq!(el.label, "    el", "a component of its own, not under stf");
        assert_eq!(el.duration, "200ms valid");
        assert_eq!(el.margin, None, "only strips carry a margin");

        let da = cells_of(&cells, Node::Span(DA));
        assert_eq!(da.label, "  ▾ data available");
        assert_eq!(
            da.duration, "no blobs",
            "gate open with no sidecars: a point, not a 0 duration"
        );
    }

    /// The grid takes its widths from the rows, so a long margin or label
    /// widens its column instead of being clipped at the border.
    #[test]
    fn grid_fits_the_widest_cell_and_fills_the_inner_width() {
        let cells = all_rows(block());
        let grid = Grid::fit(cells.iter().map(|(_, c)| c), INNER_WIDTH);
        assert_eq!(grid.label, "  ▾ data available".chars().count(), "widest label");
        assert_eq!(grid.duration, "200ms valid".len(), "widest duration + attributes");
        assert_eq!(grid.margin, "deadline".len(), "+3.48s is narrower than the heading");
        assert_eq!(grid.width(), INNER_WIDTH);

        let axis = Axis::fit(grid.axis, DEADLINE, Nanos(0));
        assert_eq!(grid.header(&axis).width(), INNER_WIDTH);
        for (display, cells) in cells {
            let line = cells.into_line(&grid, &axis);
            assert_eq!(line.width(), INNER_WIDTH, "{:?}", display.node);
        }
    }

    #[test]
    fn bars_take_the_component_colour() {
        let cells =
            all_rows(trace(&[(received(), 300), (el_sent(), 320), (Stage::StfImported, 460)]));
        let grid = Grid::fit(cells.iter().map(|(_, c)| c), INNER_WIDTH);
        let axis = Axis::fit(grid.axis, DEADLINE, Nanos(0));
        let (_, apply) = cells.into_iter().find(|(d, _)| d.node == Node::Span(APPLY)).unwrap();
        let line = apply.into_line(&grid, &axis);
        assert_eq!(line.spans[1].style.fg, Some(palette::APPLY));
        assert_eq!(line.spans[2].style.fg, Some(palette::APPLY), "duration matches its bar");
    }

    #[test]
    fn replay_rows_draw_no_bar() {
        let mut replayed = BlockTrace::new(7, [1u8; 32]);
        let far_later = Nanos::from_secs(GENESIS_SECS) + Nanos::from_secs(900 * 12);
        replayed.apply(silver_stages::StageEvent {
            stage: received(),
            ts: far_later,
            block_root: [1u8; 32],
            slot: Some(7),
        });
        let display = DisplayRow {
            root: [1u8; 32],
            node: Node::Span(Span::Strip),
            depth: 0,
            fold: Fold::Closed,
        };
        let cells = RowCells::new(&replayed, &display, &clock(), DEADLINE);
        assert_eq!(cells.start, "-");
        assert_eq!(cells.offset, None);
        assert_ne!(cells.time, "-", "the wall clock still reads");
    }
}
