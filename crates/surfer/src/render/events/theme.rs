//! Every colour and symbol the pane draws with, as one value handed down from
//! `main`. Rows ask for the style of a situation, never for a colour.

use ratatui::style::{Color, Style};
use silver_beacon_state_data::SLOTS_PER_EPOCH;
use silver_common::PayloadValidationStatus;

use super::tree::{Fold, Node};
use crate::sources::events::{BlockTrace, DaSpan, Margin, Span, StfSpan};

#[derive(Clone, Copy)]
pub struct Symbols {
    pub bar: char,
    pub tick: char,
    pub separator: &'static str,
    pub fold_open: &'static str,
    pub fold_closed: &'static str,
    pub fold_leaf: &'static str,
}

impl Default for Symbols {
    fn default() -> Self {
        Self {
            bar: '█',
            tick: '╌',
            separator: " │ ",
            fold_open: "▾ ",
            fold_closed: "▸ ",
            fold_leaf: "  ",
        }
    }
}

/// One colour per span of the block's pipeline.
pub struct Components {
    pub strip: Color,
    pub da: Color,
    pub cols: Color,
    pub custody: Color,
    pub stf: Color,
    pub validate: Color,
    pub apply: Color,
}

impl Default for Components {
    fn default() -> Self {
        Self {
            strip: Color::White,
            da: Color::Cyan,
            cols: Color::LightCyan,
            custody: Color::LightMagenta,
            stf: Color::Yellow,
            validate: Color::LightBlue,
            apply: Color::Blue,
        }
    }
}

impl Components {
    /// `El` has no colour of its own; it wears the verdict.
    fn of(&self, span: Span) -> Option<Color> {
        match span {
            Span::Strip => Some(self.strip),
            Span::Da(DaSpan::Root) => Some(self.da),
            Span::Da(DaSpan::Custody) => Some(self.custody),
            Span::Da(DaSpan::Cols(_)) => Some(self.cols),
            Span::Stf(StfSpan::Root) => Some(self.stf),
            Span::Stf(StfSpan::Validate) => Some(self.validate),
            Span::Stf(StfSpan::Apply) => Some(self.apply),
            Span::El => None,
        }
    }
}

pub struct Verdicts {
    pub valid: Color,
    pub invalid: Color,
    pub optimistic: Color,
    pub pending: Color,
}

impl Default for Verdicts {
    fn default() -> Self {
        Self {
            valid: Color::Green,
            invalid: Color::Red,
            optimistic: Color::Yellow,
            pending: Color::Gray,
        }
    }
}

impl Verdicts {
    fn of(&self, status: Option<PayloadValidationStatus>) -> Color {
        match status {
            Some(PayloadValidationStatus::Valid) => self.valid,
            Some(PayloadValidationStatus::Invalid) => self.invalid,
            Some(PayloadValidationStatus::Syncing | PayloadValidationStatus::Accepted) => {
                self.optimistic
            }
            None => self.pending,
        }
    }
}

pub struct Margins {
    pub made_it: Color,
    pub missed: Color,
}

impl Default for Margins {
    fn default() -> Self {
        Self { made_it: Color::Green, missed: Color::Red }
    }
}

impl Margins {
    fn of(&self, margin: Margin) -> Color {
        if margin.made_it { self.made_it } else { self.missed }
    }
}

/// Everything around the bars: labels, text cells, header and frame.
pub struct Chrome {
    pub label: Color,
    pub epoch_label: Color,
    pub text: Color,
    pub header: Color,
    pub separator: Color,
    pub selection_bg: Color,
    pub empty: Color,
}

impl Default for Chrome {
    fn default() -> Self {
        Self {
            label: Color::Gray,
            epoch_label: Color::Cyan,
            text: Color::White,
            header: Color::Cyan,
            separator: Color::DarkGray,
            selection_bg: Color::Indexed(236),
            empty: Color::DarkGray,
        }
    }
}

#[derive(Default)]
pub struct Theme {
    pub components: Components,
    pub verdicts: Verdicts,
    pub margins: Margins,
    pub chrome: Chrome,
    pub symbols: Symbols,
}

impl Theme {
    /// The bar and duration of a row: `el` carries the verdict, a column the
    /// colour of the row it served, neutral until the gate has opened.
    pub fn bar(&self, trace: &BlockTrace, node: Node) -> Style {
        let color = match node {
            Node::Span(span) => {
                self.components.of(span).unwrap_or_else(|| self.verdicts.of(trace.el.status()))
            }
            Node::Col { index, .. } => match trace.da.available() {
                None => self.components.cols,
                Some(_) if trace.da.counted_for_gate(&trace.da.columns[index]) => {
                    self.components.da
                }
                Some(_) => self.components.custody,
            },
        };
        Style::default().fg(color)
    }

    /// The first slot of an epoch is highlighted so boundaries stand out.
    pub fn label(&self, trace: &BlockTrace, node: Node) -> Style {
        let color = match node {
            Node::Span(Span::Strip) if trace.slot.is_multiple_of(SLOTS_PER_EPOCH) => {
                self.chrome.epoch_label
            }
            _ => self.chrome.label,
        };
        Style::default().fg(color)
    }

    pub fn text(&self) -> Style {
        Style::default().fg(self.chrome.text)
    }

    pub fn header(&self) -> Style {
        Style::default().fg(self.chrome.header)
    }

    pub fn separator(&self) -> Style {
        Style::default().fg(self.chrome.separator)
    }

    pub fn margin(&self, margin: Option<Margin>) -> Style {
        margin.map_or_else(Style::default, |m| Style::default().fg(self.margins.of(m)))
    }

    pub fn selection(&self) -> Style {
        Style::default().bg(self.chrome.selection_bg)
    }

    pub fn empty(&self) -> Style {
        Style::default().fg(self.chrome.empty)
    }

    pub fn fold(&self, fold: Fold) -> &'static str {
        match fold {
            Fold::Open => self.symbols.fold_open,
            Fold::Closed => self.symbols.fold_closed,
            Fold::Leaf => self.symbols.fold_leaf,
        }
    }
}
