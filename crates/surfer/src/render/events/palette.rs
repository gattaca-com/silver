use ratatui::style::Color;
use silver_beacon_state_data::SLOTS_PER_EPOCH;
use silver_common::PayloadValidationStatus;

use super::tree::Node;
use crate::sources::events::{BlockTrace, Margin, Span};

pub const STRIP: Color = Color::White;
pub const DA: Color = Color::Cyan;
pub const COLS: Color = Color::LightCyan;
pub const CUSTODY: Color = Color::LightMagenta;
/// The column whose validation opened the gate.
pub const TRIGGER: Color = Color::Magenta;
pub const STF: Color = Color::Yellow;
pub const VALIDATE: Color = Color::LightBlue;
pub const APPLY: Color = Color::Blue;
/// Columns arriving after the gate: custody duty, not what the block waited
/// for.
pub const CUSTODY_TAIL: Color = Color::DarkGray;
pub const LABEL: Color = Color::Gray;
/// The first slot of an epoch, so boundaries stand out.
pub const EPOCH_LABEL: Color = Color::Cyan;
pub const HEADER: Color = Color::Cyan;
pub const SELECTION_BG: Color = Color::Indexed(236);
pub const EMPTY: Color = Color::DarkGray;
pub const MARGIN_OK: Color = Color::Green;
pub const MARGIN_MISSED: Color = Color::Red;

pub fn verdict_color(status: Option<PayloadValidationStatus>) -> Color {
    match status {
        Some(PayloadValidationStatus::Valid) => Color::Green,
        Some(PayloadValidationStatus::Invalid) => Color::Red,
        Some(PayloadValidationStatus::Syncing | PayloadValidationStatus::Accepted) => Color::Yellow,
        None => Color::Gray,
    }
}

pub fn node_color(trace: &BlockTrace, node: Node) -> Color {
    match node {
        Node::Span(Span::El) => verdict_color(trace.el.status()),
        Node::Span(span) => span.spec().color,
        Node::Col(i) => {
            if trace.da.trigger() == Some(i) {
                TRIGGER
            } else if trace
                .da
                .available()
                .is_some_and(|gate| trace.da.columns[i].received_at > gate)
            {
                CUSTODY_TAIL
            } else {
                COLS
            }
        }
    }
}

pub fn label_color(trace: &BlockTrace, node: Node) -> Color {
    match node {
        Node::Span(Span::Strip) if trace.slot.is_multiple_of(SLOTS_PER_EPOCH) => EPOCH_LABEL,
        _ => LABEL,
    }
}

pub fn margin_color(margin: Margin) -> Color {
    if margin.made_it { MARGIN_OK } else { MARGIN_MISSED }
}
