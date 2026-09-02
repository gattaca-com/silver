//! One text line per display row, on a fixed grid so every column aligns:
//! `label │ time │ start │ bar on the axis │ duration [suffix] │ margin`.

use ratatui::{
    style::Style,
    text::{Line, Span as TextSpan},
};
use silver_common::{Nanos, PayloadValidationStatus};
use silver_stages::SlotClock;

use super::{
    axis::Axis,
    palette,
    tree::{DisplayRow, Node},
};
use crate::{
    render::fmt::{fmt_nanos, root_prefix},
    sources::events::{BlockTrace, DaSpan, Margin, Span},
};

const LABEL_W: usize = 22;
/// Wall clock of the trace's start, for log correlation.
const TIME_W: usize = 13;
const START_W: usize = 9;
/// Duration plus a short suffix (column counts, the EL verdict), in a fixed
/// column so the numbers align instead of floating at each bar's end.
const DURATION_W: usize = 16;
/// Deadline margin, on block strips only.
const MARGIN_W: usize = 9;
/// Single spaces between the six columns.
const GAPS: usize = 5;

/// What is left for the axis once the fixed columns have their share.
pub fn axis_width(inner_width: usize) -> usize {
    inner_width.saturating_sub(LABEL_W + TIME_W + START_W + DURATION_W + MARGIN_W + GAPS)
}

#[cfg(test)]
fn row_width(axis: &Axis) -> usize {
    LABEL_W + TIME_W + START_W + axis.width + DURATION_W + MARGIN_W + GAPS
}

pub fn header(axis: &Axis) -> Line<'static> {
    let head = format!(
        "{:<LABEL_W$} {:<TIME_W$} {:<START_W$} {} {:<DURATION_W$} {:<MARGIN_W$}",
        "slot/component",
        "time",
        "start",
        axis.ticks(),
        "duration",
        "deadline"
    );
    Line::styled(head, Style::default().fg(palette::HEADER))
}

/// The trace's text per column, ahead of styling.
pub struct RowCells {
    pub label: String,
    pub time: String,
    pub start: String,
    pub bar: String,
    pub duration: String,
    pub margin: Option<Margin>,
}

impl RowCells {
    pub fn new(
        trace: &BlockTrace,
        display: &DisplayRow,
        axis: &Axis,
        clock: &SlotClock,
        deadline: Nanos,
    ) -> Self {
        let node = display.node;
        let interval = node.interval(trace);
        let (time, start, bar) = match interval {
            Some(iv) => {
                let offset = trace.offset_in_slot(clock, iv.start);
                (
                    iv.start.with_fmt_utc("%H:%M:%S%.3f"),
                    offset.map_or_else(|| "-".to_string(), fmt_nanos),
                    axis.bar(offset, iv.duration()),
                )
            }
            None => ("-".to_string(), "-".to_string(), axis.bar(None, Nanos(0))),
        };
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
            bar,
            duration: format!("{duration}{}", attributes(trace, node)).trim_start().to_string(),
            margin,
        }
    }

    pub fn into_line(self, trace: &BlockTrace, node: Node) -> Line<'static> {
        let bar_style = Style::default().fg(palette::node_color(trace, node));
        let margin = match self.margin {
            Some(m) => TextSpan::styled(
                format!("{:<MARGIN_W$}", margin_text(m)),
                Style::default().fg(palette::margin_color(m)),
            ),
            None => TextSpan::raw(" ".repeat(MARGIN_W)),
        };
        Line::from(vec![
            TextSpan::styled(
                format!(
                    "{:<LABEL_W$} {:<TIME_W$} {:<START_W$} ",
                    self.label, self.time, self.start
                ),
                Style::default().fg(palette::label_color(trace, node)),
            ),
            TextSpan::styled(self.bar, bar_style),
            TextSpan::styled(format!(" {:<DURATION_W$} ", self.duration), bar_style),
            margin,
        ])
    }
}

pub fn row_line(
    trace: &BlockTrace,
    display: &DisplayRow,
    axis: &Axis,
    clock: &SlotClock,
    deadline: Nanos,
) -> Line<'static> {
    RowCells::new(trace, display, axis, clock, deadline).into_line(trace, display.node)
}

/// Indented by depth; openers carry a fold glyph, leaves a blank of the same
/// width so sibling text aligns.
fn label(trace: &BlockTrace, display: &DisplayRow) -> String {
    let indent = "  ".repeat(display.depth as usize);
    let marker = match display.open {
        Some(true) => "\u{25be} ",  // ▾
        Some(false) => "\u{25b8} ", // ▸
        None => "  ",
    };
    let text = match display.node {
        Node::Span(Span::Strip) => format!("{} {}", trace.slot, root_prefix(&trace.block_root)),
        Node::Span(span) => span.spec().label.to_string(),
        Node::Col(i) => format!("col {}", trace.da.columns[i].index),
    };
    format!("{indent}{marker}{text}")
}

/// Per-node annotation after the duration.
fn attributes(trace: &BlockTrace, node: Node) -> String {
    match node {
        // The gate open with no sidecars ever seen: a block without
        // blobs, whose DA is trivially satisfied — not a display hole.
        Node::Span(Span::Da(DaSpan::Root))
            if !trace.da.has_columns() && trace.da.available().is_some() =>
        {
            " no blobs".to_string()
        }
        Node::Span(Span::Da(DaSpan::Cols(source))) => {
            let of_source = || trace.da.columns.iter().filter(|c| c.source == source);
            match trace.da.available() {
                Some(gate) => format!(
                    " {}/{}",
                    of_source().filter(|c| c.recv <= gate).count(),
                    of_source().count()
                ),
                None => format!(" {}", of_source().count()),
            }
        }
        Node::Span(Span::El) => {
            trace.el.status().map_or_else(String::new, |v| format!(" {}", status_label(v)))
        }
        _ => String::new(),
    }
}

fn margin_text(margin: Margin) -> String {
    let sign = if margin.made_it { '+' } else { '-' };
    format!("{sign}{}", fmt_nanos(margin.delta))
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

    fn clock() -> SlotClock {
        SlotClock::new(GENESIS_SECS, SLOT_MS)
    }

    fn axis() -> Axis {
        Axis::fit(20, DEADLINE, Nanos(0))
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

    /// Every trace of a fully unfolded block, paired with its cells.
    fn all_rows(block: BlockTrace) -> Vec<(DisplayRow, RowCells)> {
        let mut expanded = Expanded::default();
        for group in [Group::Block, Group::Da, Group::Stf] {
            expanded.toggle(block.block_root, group);
        }
        let traces = BlockTraces::from_iter([block]);
        display_rows(&traces, &expanded)
            .into_iter()
            .map(|d| {
                let cells = RowCells::new(&traces[0], &d, &axis(), &clock(), DEADLINE);
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
        assert_eq!(strip.label, "\u{25be} 2 01010101");
        assert_eq!(strip.start, "300ms");
        assert_eq!(strip.duration, "220ms", "arrival → attestable");
        assert_eq!(strip.margin, Some(Margin { delta: Nanos::from_millis(3_480), made_it: true }));

        let el = cells_of(&cells, Node::Span(Span::El));
        assert_eq!(el.label, "    el", "a component of its own, not under stf");
        assert_eq!(el.duration, "200ms valid");
        assert_eq!(el.margin, None, "only strips carry a margin");

        let da = cells_of(&cells, Node::Span(DA));
        assert_eq!(da.label, "  \u{25be} data available");
        assert_eq!(
            da.duration, "no blobs",
            "gate open with no sidecars: a point, not a 0 duration"
        );
    }

    #[test]
    fn every_line_has_the_same_width() {
        let cells = all_rows(block());
        let block = block();
        let width = row_width(&axis());
        for (display, _) in &cells {
            let line = row_line(&block, display, &axis(), &clock(), DEADLINE);
            assert_eq!(line.width(), width, "{:?}", display.node);
        }
        assert_eq!(header(&axis()).width(), width);
    }

    #[test]
    fn bars_take_the_lane_colour() {
        let block = block();
        let cells =
            all_rows(trace(&[(received(), 300), (el_sent(), 320), (Stage::StfImported, 460)]));
        let stf = cells.iter().find(|(d, _)| d.node == Node::Span(APPLY)).unwrap();
        let line = row_line(&block, &stf.0, &axis(), &clock(), DEADLINE);
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
            open: Some(false),
        };
        let cells = RowCells::new(&replayed, &display, &axis(), &clock(), DEADLINE);
        assert_eq!(cells.start, "-");
        assert_eq!(cells.bar, " ".repeat(20));
        assert_ne!(cells.time, "-", "the wall clock still reads");
    }
}
