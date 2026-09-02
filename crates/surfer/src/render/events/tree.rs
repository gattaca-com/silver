//! Which rows the pane shows for a block and in what order. The shape is two
//! static tables, `Group::children` and `Span::spec`, each written per
//! component; the only data-driven rows are the column sidecars under an open
//! `Cols` group.

use std::collections::HashSet;

use ratatui::style::Color;
use silver_common::ColumnSource;

use super::palette;
use crate::sources::events::{BlockTrace, BlockTraces, DaSpan, Interval, Span, StfSpan};

/// A toggleable subtree; `Enter` on its opener flips it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Group {
    Block,
    Da,
    Cols(ColumnSource),
    Stf,
}

impl Group {
    /// Groups whose children are spans; `Cols` holds sidecar rows instead.
    const WITH_SPANS: [Self; 3] = [Self::Block, Self::Da, Self::Stf];

    pub fn children(self) -> &'static [Span] {
        match self {
            Self::Block => &[Span::Da(DaSpan::Root), Span::Stf(StfSpan::Root), Span::El],
            Self::Da => &[
                Span::Da(DaSpan::Cols(ColumnSource::Gossip)),
                Span::Da(DaSpan::Cols(ColumnSource::El)),
                Span::Da(DaSpan::Cols(ColumnSource::Rpc)),
            ],
            Self::Cols(_) => &[],
            Self::Stf => &[Span::Stf(StfSpan::Validate), Span::Stf(StfSpan::Apply)],
        }
    }

    pub fn opener(self) -> Span {
        match self {
            Self::Block => Span::Strip,
            Self::Da => Span::Da(DaSpan::Root),
            Self::Cols(source) => Span::Da(DaSpan::Cols(source)),
            Self::Stf => Span::Stf(StfSpan::Root),
        }
    }
}

pub struct SpanSpec {
    pub label: &'static str,
    /// The bar colour before trace-dependent overrides.
    pub color: Color,
    pub opens: Option<Group>,
}

impl SpanSpec {
    const fn new(label: &'static str, color: Color, opens: Option<Group>) -> Self {
        Self { label, color, opens }
    }
}

impl Span {
    pub fn spec(self) -> SpanSpec {
        match self {
            Self::Strip => SpanSpec::new("", palette::STRIP, Some(Group::Block)),
            Self::Da(span) => span.spec(),
            Self::Stf(span) => span.spec(),
            Self::El => SpanSpec::new("el", palette::verdict_color(None), None),
        }
    }

    /// The group listing this span; `Strip` has none.
    fn parent(self) -> Option<Group> {
        Group::WITH_SPANS.into_iter().find(|g| g.children().contains(&self))
    }

    /// `Cols(source)` hides while no sidecar of that source has arrived.
    fn hidden(self, trace: &BlockTrace) -> bool {
        matches!(self, Self::Da(DaSpan::Cols(source)) if !trace.da.has_source(source))
    }
}

impl DaSpan {
    fn spec(self) -> SpanSpec {
        match self {
            Self::Root => SpanSpec::new("data available", palette::DA, Some(Group::Da)),
            Self::Cols(source) => {
                SpanSpec::new(cols_label(source), palette::COLS, Some(Group::Cols(source)))
            }
        }
    }
}

impl StfSpan {
    fn spec(self) -> SpanSpec {
        match self {
            Self::Root => SpanSpec::new("stf", palette::STF, Some(Group::Stf)),
            Self::Validate => SpanSpec::new("validate", palette::VALIDATE, None),
            Self::Apply => SpanSpec::new("apply", palette::APPLY, None),
        }
    }
}

fn cols_label(source: ColumnSource) -> &'static str {
    match source {
        ColumnSource::Gossip => "gossip cols",
        ColumnSource::Rpc => "rpc cols",
        ColumnSource::El => "el cols",
    }
}

/// One display row: a span of the block's graph, or one column sidecar.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Node {
    Span(Span),
    Col(usize),
}

impl Node {
    pub fn opens(self) -> Option<Group> {
        match self {
            Self::Span(span) => span.spec().opens,
            Self::Col(_) => None,
        }
    }

    /// The group this row is listed under, so `Enter` on a child folds it.
    pub fn parent(self, trace: &BlockTrace) -> Option<Group> {
        match self {
            Self::Span(span) => span.parent(),
            Self::Col(i) => Some(Group::Cols(trace.da.columns[i].source)),
        }
    }

    pub fn interval(self, trace: &BlockTrace) -> Option<Interval> {
        match self {
            Self::Span(span) => trace.interval(span),
            Self::Col(i) => Some(trace.da.columns[i].interval()),
        }
    }

    /// A blobless block's data component is nothing but the gate opening.
    pub fn is_instant(self, trace: &BlockTrace) -> bool {
        matches!(self, Self::Span(Span::Da(DaSpan::Root)) if !trace.da.has_columns())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DisplayRow {
    pub root: [u8; 32],
    pub node: Node,
    pub depth: u8,
    /// `Some` on a group opener: whether its subtree is unfolded.
    pub open: Option<bool>,
}

#[derive(Hash, PartialEq, Eq)]
struct OpenGroup {
    root: [u8; 32],
    group: Group,
}

/// Which subtrees are unfolded, per block.
#[derive(Default)]
pub struct Expanded(HashSet<OpenGroup>);

impl Expanded {
    pub fn is_open(&self, root: [u8; 32], group: Group) -> bool {
        self.0.contains(&OpenGroup { root, group })
    }

    pub fn toggle(&mut self, root: [u8; 32], group: Group) {
        let key = OpenGroup { root, group };
        if !self.0.remove(&key) {
            self.0.insert(key);
        }
    }
}

/// The visible tree, newest block first; each block is a preorder walk of
/// `Group::children` through the open groups.
pub fn display_rows(traces: &BlockTraces, expanded: &Expanded) -> Vec<DisplayRow> {
    let mut out = Vec::new();
    for trace in traces.iter().rev() {
        Walk { trace, expanded, out: &mut out }.push_span(Span::Strip, 0);
    }
    out
}

struct Walk<'a> {
    trace: &'a BlockTrace,
    expanded: &'a Expanded,
    out: &'a mut Vec<DisplayRow>,
}

impl Walk<'_> {
    fn push_span(&mut self, span: Span, depth: u8) {
        let root = self.trace.block_root;
        let opens = span.spec().opens;
        let open = opens.map(|group| self.expanded.is_open(root, group));
        self.out.push(DisplayRow { root, node: Node::Span(span), depth, open });

        let Some(group) = opens.filter(|_| open == Some(true)) else {
            return;
        };
        for &child in group.children() {
            if !child.hidden(self.trace) {
                self.push_span(child, depth + 1);
            }
        }
        if let Group::Cols(source) = group {
            self.push_columns(source, depth + 1);
        }
    }

    /// Sidecar rows in arrival order.
    fn push_columns(&mut self, source: ColumnSource, depth: u8) {
        let columns = &self.trace.da.columns;
        let mut order: Vec<_> =
            (0..columns.len()).filter(|&i| columns[i].source == source).collect();
        order.sort_unstable_by_key(|&i| columns[i].recv);
        self.out.extend(order.into_iter().map(|i| DisplayRow {
            root: self.trace.block_root,
            node: Node::Col(i),
            depth,
            open: None,
        }));
    }
}

#[cfg(test)]
mod tests {
    use silver_stages::Stage;

    use super::*;
    use crate::sources::events::trace_tests::{APPLY, DA, STF, VALIDATE, cols, received, trace};

    fn rows_of(trace: BlockTrace) -> BlockTraces {
        BlockTraces::from_iter([trace])
    }

    fn nodes(display: &[DisplayRow]) -> Vec<Node> {
        display.iter().map(|d| d.node).collect()
    }

    fn with_columns() -> BlockTrace {
        let recv = |i| Stage::ColumnRecv { index: i, source: ColumnSource::Gossip };
        trace(&[(received(), 300), (recv(7), 260), (recv(3), 250)])
    }

    #[test]
    fn a_closed_block_is_one_row() {
        let display = display_rows(&rows_of(with_columns()), &Expanded::default());
        assert_eq!(display.len(), 1);
        assert_eq!(display[0], DisplayRow {
            root: [1u8; 32],
            node: Node::Span(Span::Strip),
            depth: 0,
            open: Some(false),
        });
    }

    #[test]
    fn open_groups_unfold_their_children_in_order() {
        let block = with_columns();
        let mut expanded = Expanded::default();
        expanded.toggle(block.block_root, Group::Block);
        expanded.toggle(block.block_root, Group::Da);
        expanded.toggle(block.block_root, Group::Stf);

        let display = display_rows(&rows_of(block), &expanded);
        assert_eq!(nodes(&display), [
            Node::Span(Span::Strip),
            Node::Span(DA),
            Node::Span(cols(ColumnSource::Gossip)),
            Node::Span(STF),
            Node::Span(VALIDATE),
            Node::Span(APPLY),
            Node::Span(Span::El),
        ]);
        assert_eq!(display[1].depth, 1);
        assert_eq!(display[2].depth, 2);
        assert_eq!(display[2].open, Some(false), "an unopened group");
        assert_eq!(display[4].open, None, "validate is a leaf");
        assert_eq!(display[6].depth, 1, "el is a component of its own");
        assert_eq!(display[6].open, None);
    }

    #[test]
    fn column_rows_follow_their_group_in_arrival_order() {
        let block = with_columns();
        let mut expanded = Expanded::default();
        for group in [Group::Block, Group::Da, Group::Cols(ColumnSource::Gossip)] {
            expanded.toggle(block.block_root, group);
        }

        let display = display_rows(&rows_of(block), &expanded);
        let cols: Vec<_> = display.iter().filter(|d| matches!(d.node, Node::Col(_))).collect();
        assert_eq!(cols.iter().map(|d| d.node).collect::<Vec<_>>(), [Node::Col(1), Node::Col(0)]);
        assert!(cols.iter().all(|d| d.depth == 3 && d.open.is_none()));
    }

    #[test]
    fn a_child_folds_into_its_group() {
        let block = with_columns();
        assert_eq!(Node::Span(Span::Strip).opens(), Some(Group::Block));
        assert_eq!(Node::Span(Span::Strip).parent(&block), None);
        assert_eq!(Node::Span(APPLY).parent(&block), Some(Group::Stf));
        assert_eq!(Node::Span(Span::El).parent(&block), Some(Group::Block));
        assert_eq!(Node::Col(0).parent(&block), Some(Group::Cols(ColumnSource::Gossip)));
        assert_eq!(Group::Cols(ColumnSource::Gossip).opener(), cols(ColumnSource::Gossip));
    }

    #[test]
    fn toggling_twice_closes() {
        let mut expanded = Expanded::default();
        expanded.toggle([1u8; 32], Group::Block);
        assert!(expanded.is_open([1u8; 32], Group::Block));
        assert!(!expanded.is_open([2u8; 32], Group::Block), "per block");
        expanded.toggle([1u8; 32], Group::Block);
        assert!(!expanded.is_open([1u8; 32], Group::Block));
    }
}
