//! One text line per display row, on a grid fitted to the rows being shown:
//! `label │ root │ time │ start │ end │ bar on the axis │ duration [attributes]
//! │ margin`.

use ratatui::{
    style::Style,
    text::{Line, Span as TextSpan},
};
use silver_common::{Nanos, PayloadValidationStatus, ssz_view::NUMBER_OF_COLUMNS};
use silver_stages::SlotClock;

use super::{
    axis::Axis,
    theme::Theme,
    tree::{DisplayRow, Node},
};
use crate::{
    render::fmt::{fmt_nanos, root_prefix, wall_time},
    sources::events::{BlockTrace, DaSpan, Interval, Margin, Span},
};

const HEADINGS: [&str; 7] =
    ["slot/component", "root", "time", "start", "end", "duration", "deadline"];

/// Column widths for one draw: each text column is as wide as its widest
/// cell or heading, and the axis takes what is left.
pub struct Grid {
    label: usize,
    root: usize,
    time: usize,
    start: usize,
    end: usize,
    pub axis: usize,
    duration: usize,
    margin: usize,
    separator: &'static str,
}

impl Grid {
    pub fn fit<'a>(
        cells: impl Iterator<Item = &'a RowCells> + Clone,
        inner_width: usize,
        theme: &Theme,
    ) -> Self {
        let widest = |min: &str, text: fn(&RowCells) -> usize| {
            cells.clone().map(text).max().unwrap_or(0).max(min.chars().count())
        };
        let [label, root, time, start, end, duration, margin] = HEADINGS;
        let label = widest(label, |c| c.label.chars().count());
        let root = widest(root, |c| c.root.chars().count());
        let time = widest(time, |c| c.time.chars().count());
        let start = widest(start, |c| c.start.chars().count());
        let end = widest(end, |c| c.end.chars().count());
        let duration = widest(duration, |c| c.duration.chars().count());
        let margin = widest(margin, |c| c.margin_text().chars().count());
        let separator = theme.symbols.separator;
        let gaps = (HEADINGS.len()) * separator.chars().count();
        let axis = inner_width
            .saturating_sub(label + root + time + start + end + duration + margin + gaps);
        Self { label, root, time, start, end, axis, duration, margin, separator }
    }

    #[cfg(test)]
    fn width(&self) -> usize {
        self.label +
            self.root +
            self.time +
            self.start +
            self.end +
            self.axis +
            self.duration +
            self.margin +
            HEADINGS.len() * self.separator.chars().count()
    }

    pub fn header(&self, axis: &Axis, theme: &Theme) -> Line<'static> {
        let style = theme.header();
        let [label, root, time, start, end, duration, margin] = HEADINGS.map(str::to_string);
        self.line(
            [label, root, time, start, end, axis.ticks(), duration, margin]
                .map(|t| vec![TextSpan::styled(t, style)]),
            theme,
        )
    }

    /// One cell per column, padded to the column and separated by the
    /// theme's separator symbol. A cell may hold several styled pieces.
    fn line(&self, cells: [Vec<TextSpan<'static>>; 8], theme: &Theme) -> Line<'static> {
        let widths = [
            self.label,
            self.root,
            self.time,
            self.start,
            self.end,
            self.axis,
            self.duration,
            self.margin,
        ];
        let mut spans = Vec::with_capacity(3 * cells.len());
        for (i, (pieces, width)) in cells.into_iter().zip(widths).enumerate() {
            if i > 0 {
                spans.push(TextSpan::styled(self.separator, theme.separator()));
            }
            let filled: usize = pieces.iter().map(|p| p.width()).sum();
            spans.extend(pieces);
            spans.push(TextSpan::raw(" ".repeat(width.saturating_sub(filled))));
        }
        Line::from(spans)
    }
}

/// The row's text per column plus its bar geometry, ahead of layout.
pub struct RowCells {
    pub label: String,
    pub root: String,
    pub time: String,
    pub start: String,
    pub end: String,
    pub offset: Option<Nanos>,
    pub len: Nanos,
    pub duration: String,
    pub margin: Option<Margin>,
    /// Into-slot offset of the gate, where a data row's bar changes colour.
    split: Option<Nanos>,
    bar: (Style, Style),
    label_style: Style,
}

impl RowCells {
    pub fn new(
        trace: &BlockTrace,
        display: &DisplayRow,
        clock: &SlotClock,
        deadline: Nanos,
        theme: &Theme,
    ) -> Self {
        let node = display.node;
        let interval = node.interval(trace);
        let offset = interval.and_then(|iv| trace.offset_in_slot(clock, iv.start));
        let time = interval.map_or_else(|| "-".to_string(), |iv| wall_time(iv.start));
        let start = offset.map_or_else(|| "-".to_string(), fmt_nanos);
        let len = interval.map_or(Nanos(0), Interval::duration);
        let end = offset.map_or_else(|| "-".to_string(), |offset| fmt_nanos(offset + len));
        let duration = match interval {
            Some(iv) if !node.is_instant(trace) => fmt_nanos(iv.duration()),
            _ => String::new(),
        };
        let margin = match node {
            Node::Span(Span::Strip) => trace.deadline_margin(clock, deadline),
            _ => None,
        };
        let split = match node.splits_at_the_gate() {
            true => trace.da.available().and_then(|gate| trace.offset_in_slot(clock, gate)),
            false => None,
        };
        Self {
            label: label(trace, display, theme),
            root: match node {
                Node::Span(Span::Strip) => root_prefix(&trace.block_root),
                _ => String::new(),
            },
            time,
            start,
            end,
            offset,
            len,
            duration: [duration, attributes(trace, node)]
                .into_iter()
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join(" "),
            margin,
            split,
            bar: theme.bar(trace, node),
            label_style: theme.label(trace, node),
        }
    }

    /// The duration takes the colour of the bar's end.
    fn duration_style(&self) -> Style {
        let (before, after) = self.bar;
        match (self.split, self.offset) {
            (Some(split), Some(offset)) if offset + self.len > split => after,
            _ => before,
        }
    }

    fn margin_text(&self) -> String {
        self.margin.map_or_else(String::new, |m| {
            let sign = if m.made_it { '+' } else { '-' };
            format!("{sign}{}", fmt_nanos(m.delta))
        })
    }

    pub fn into_line(self, grid: &Grid, axis: &Axis, theme: &Theme) -> Line<'static> {
        let margin_text = self.margin_text();
        let duration_style = self.duration_style();
        let (before, after) = axis.split_bar(self.offset, self.len, self.split);
        let one = |text, style| vec![TextSpan::styled(text, style)];
        grid.line(
            [
                one(self.label, self.label_style),
                one(self.root, theme.text()),
                one(self.time, theme.text()),
                one(self.start, theme.text()),
                one(self.end, theme.text()),
                vec![TextSpan::styled(before, self.bar.0), TextSpan::styled(after, self.bar.1)],
                one(self.duration, duration_style),
                one(margin_text, theme.margin(self.margin)),
            ],
            theme,
        )
    }
}

/// Indented by depth; openers carry a fold symbol, leaves a blank of the same
/// width so sibling text aligns.
fn label(trace: &BlockTrace, display: &DisplayRow, theme: &Theme) -> String {
    let indent = "  ".repeat(display.depth as usize);
    let marker = theme.fold(display.fold);
    let text = match display.node {
        Node::Span(Span::Strip) => trace.slot.to_string(),
        Node::Span(span) => span.spec().label.to_string(),
        Node::Batch { .. } => {
            let batch = display.node.batch(trace).expect("displayed batch");
            let (first, last) = batch.ranks();
            format!("#{first}..#{last}")
        }
        Node::Col { index, rank } => format!("#{rank} col {}", trace.da.columns[index].index),
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
        // The custody size is not on the wire; a supernode's is every column.
        Node::Span(Span::Da(DaSpan::Custody)) => {
            format!("{}/{NUMBER_OF_COLUMNS} cols", trace.da.columns.len())
        }
        Node::Span(Span::Da(DaSpan::Cols(source))) => {
            format!("{} cols", trace.da.of_source(source).count())
        }
        Node::Batch { .. } => {
            let batch = node.batch(trace).expect("displayed batch");
            let gate = if trace.da.opened_gate(&batch) { " DA" } else { "" };
            format!("{} cols{gate}", batch.columns.len())
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
    use silver_common::ColumnSource;
    use silver_stages::Stage;

    use super::*;
    use crate::{
        render::events::tree::{Expanded, Fold, Group, display_rows},
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
    fn all_rows(block: BlockTrace, theme: &Theme) -> Vec<(DisplayRow, RowCells)> {
        let mut expanded = Expanded::default();
        for group in [Group::Block, Group::Da, Group::Stf, Group::Cols(ColumnSource::Gossip)] {
            expanded.toggle(block.block_root, group);
        }
        let traces = BlockTraces::from_iter([block]);
        display_rows(&traces, &expanded)
            .into_iter()
            .map(|d| {
                let cells = RowCells::new(&traces[0], &d, &clock(), DEADLINE, theme);
                (d, cells)
            })
            .collect()
    }

    fn cells_of(cells: &[(DisplayRow, RowCells)], node: Node) -> &RowCells {
        &cells.iter().find(|(d, _)| d.node == node).expect("node displayed").1
    }

    #[test]
    fn cells_carry_start_duration_and_annotations() {
        let cells = all_rows(block(), &Theme::default());

        let strip = cells_of(&cells, Node::Span(Span::Strip));
        assert_eq!(strip.label, "▾ 2");
        assert_eq!(strip.root, "01010101");
        assert_eq!(strip.start, "300ms");
        assert_eq!(strip.end, "520ms");
        assert_eq!(strip.duration, "220ms", "rank → attestable");
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
        let theme = Theme::default();
        let cells = all_rows(block(), &theme);
        let grid = Grid::fit(cells.iter().map(|(_, c)| c), INNER_WIDTH, &theme);
        assert_eq!(grid.label, "  ▾ data available".chars().count(), "widest label");
        assert_eq!(grid.duration, "200ms valid".len(), "widest duration + attributes");
        assert_eq!(grid.margin, "deadline".len(), "+3.48s is narrower than the heading");
        assert_eq!(grid.width(), INNER_WIDTH);

        let axis = Axis::fit(grid.axis, DEADLINE, Nanos(0), theme.symbols);
        assert_eq!(grid.header(&axis, &theme).width(), INNER_WIDTH);
        for (display, cells) in cells {
            let line = cells.into_line(&grid, &axis, &theme);
            assert_eq!(line.width(), INNER_WIDTH, "{:?}", display.node);
        }
    }

    #[test]
    fn bars_take_the_component_colour() {
        let theme = Theme::default();
        let cells = all_rows(
            trace(&[(received(), 300), (el_sent(), 320), (Stage::StfImported, 460)]),
            &theme,
        );
        let grid = Grid::fit(cells.iter().map(|(_, c)| c), INNER_WIDTH, &theme);
        let axis = Axis::fit(grid.axis, DEADLINE, Nanos(0), theme.symbols);
        let (_, apply) = cells.into_iter().find(|(d, _)| d.node == Node::Span(APPLY)).unwrap();
        let line = apply.into_line(&grid, &axis, &theme);
        let bar = line.spans.iter().find(|s| s.content.contains(theme.symbols.bar)).unwrap();
        assert_eq!(bar.style.fg, Some(theme.components.apply));
        let duration = line.spans.iter().find(|s| s.content == "140ms").unwrap();
        assert_eq!(duration.style.fg, Some(theme.components.apply), "duration matches its bar");
        assert!(line.spans.iter().any(|s| s.content == theme.symbols.separator));
    }

    /// A custody row's bar changes colour at the gate; rows ending after it
    /// take the custody colour for their duration.
    #[test]
    fn data_bars_split_at_the_gate() {
        let theme = Theme::default();
        let recv = |i| Stage::ColumnRecv { index: i, source: ColumnSource::Gossip };
        let validated = |i| Stage::ColumnValidated { index: i, source: ColumnSource::Gossip };
        let cells = all_rows(
            trace(&[
                (received(), 300),
                (recv(1), 200),
                (validated(1), 400),
                (Stage::DaAvailable, 1_000),
                (recv(2), 2_000),
                (validated(2), 3_000),
                (Stage::CustodyDone, 3_001),
            ]),
            &theme,
        );
        let grid = Grid::fit(cells.iter().map(|(_, c)| c), INNER_WIDTH, &theme);
        let axis = Axis::fit(grid.axis, DEADLINE, Nanos(0), theme.symbols);

        let colour_of = |node: Node| {
            let (_, cells) = cells.iter().find(|(d, _)| d.node == node).unwrap();
            cells.duration_style().fg
        };
        let custody = Node::Span(Span::Da(DaSpan::Custody));
        assert_eq!(colour_of(Node::Span(DA)), Some(theme.components.da));
        assert_eq!(colour_of(custody), Some(theme.components.custody));
        assert_eq!(colour_of(Node::Col { index: 0, rank: 1 }), Some(theme.components.da));
        assert_eq!(colour_of(Node::Col { index: 1, rank: 2 }), Some(theme.components.custody));

        let lines: Vec<_> =
            cells.into_iter().map(|(d, c)| (d.node, c.into_line(&grid, &axis, &theme))).collect();
        let bars_of = |node: Node| {
            let (_, line) = lines.iter().find(|(n, _)| *n == node).unwrap();
            line.spans
                .iter()
                .filter(|s| s.content.contains(theme.symbols.bar))
                .map(|s| s.style.fg)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            bars_of(custody),
            [Some(theme.components.da), Some(theme.components.custody)],
            "one piece each side of the gate"
        );
        assert_eq!(
            bars_of(Node::Col { index: 1, rank: 2 }),
            [Some(theme.components.custody)],
            "a column crossing the gate is one colour"
        );
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
        let cells = RowCells::new(&replayed, &display, &clock(), DEADLINE, &Theme::default());
        assert_eq!(cells.start, "-");
        assert_eq!(cells.end, "-");
        assert_eq!(cells.offset, None);
        assert_ne!(cells.time, "-", "the wall clock still reads");
    }
}
