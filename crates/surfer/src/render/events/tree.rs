//! Which rows the pane shows for a block and in what order: static
//! per-component tables, plus the column batches and sidecars under an open
//! `Cols` group as the only data-driven rows.

use std::collections::HashSet;

use silver_common::ColumnSource;

use crate::sources::events::{Batch, BlockTrace, BlockTraces, DaSpan, Interval, Span, StfSpan};

/// A toggleable subtree; `Enter` on its opener flips it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Group {
    Block,
    Da,
    Cols(ColumnSource),
    /// Position in the source's `DataAvailability::batches`.
    Batch {
        source: ColumnSource,
        batch: usize,
    },
    Stf,
}

impl Group {
    /// Groups whose children are spans; `Cols` holds sidecar rows instead.
    const WITH_SPANS: [Self; 3] = [Self::Block, Self::Da, Self::Stf];

    pub fn children(self) -> &'static [Span] {
        match self {
            Self::Block => &[
                Span::Da(DaSpan::Root),
                Span::Da(DaSpan::Custody),
                Span::Stf(StfSpan::Root),
                Span::El,
            ],
            Self::Da => &[
                Span::Da(DaSpan::Cols(ColumnSource::Gossip)),
                Span::Da(DaSpan::Cols(ColumnSource::El)),
                Span::Da(DaSpan::Cols(ColumnSource::Rpc)),
            ],
            Self::Cols(_) | Self::Batch { .. } => &[],
            Self::Stf => &[Span::Stf(StfSpan::Validate), Span::Stf(StfSpan::Apply)],
        }
    }

    /// The row that toggles this group.
    pub fn opener(self) -> Node {
        match self {
            Self::Block => Node::Span(Span::Strip),
            Self::Da => Node::Span(Span::Da(DaSpan::Root)),
            Self::Cols(source) => Node::Span(Span::Da(DaSpan::Cols(source))),
            Self::Batch { source, batch } => Node::Batch { source, batch },
            Self::Stf => Node::Span(Span::Stf(StfSpan::Root)),
        }
    }

    /// The group whose children unfold under this row. The column list sits
    /// below both data rows, being the arrivals the gate and custody are two
    /// ends of.
    fn unfolding_after(span: Span) -> Option<Self> {
        match span {
            Span::Da(DaSpan::Root) => None,
            Span::Da(DaSpan::Custody) => Some(Self::Da),
            _ => span.spec().opens,
        }
    }
}

pub struct SpanSpec {
    pub label: &'static str,
    pub opens: Option<Group>,
}

impl SpanSpec {
    const fn new(label: &'static str, opens: Option<Group>) -> Self {
        Self { label, opens }
    }
}

impl Span {
    pub fn spec(self) -> SpanSpec {
        match self {
            Self::Strip => SpanSpec::new("", Some(Group::Block)),
            Self::Da(span) => span.spec(),
            Self::Stf(span) => span.spec(),
            Self::El => SpanSpec::new("el", None),
        }
    }

    /// Custody folds the column list it heads, not the block.
    fn parent(self) -> Option<Group> {
        match self {
            Self::Da(DaSpan::Custody) => Some(Group::Da),
            _ => Group::WITH_SPANS.into_iter().find(|g| g.children().contains(&self)),
        }
    }

    fn hidden(self, trace: &BlockTrace) -> bool {
        match self {
            Self::Da(DaSpan::Cols(source)) => !trace.da.has_source(source),
            Self::Da(DaSpan::Custody) => !trace.da.has_columns(),
            _ => false,
        }
    }
}

impl DaSpan {
    fn spec(self) -> SpanSpec {
        match self {
            Self::Root => SpanSpec::new("data available", Some(Group::Da)),
            Self::Custody => SpanSpec::new("custody", None),
            Self::Cols(source) => SpanSpec::new(cols_label(source), Some(Group::Cols(source))),
        }
    }
}

impl StfSpan {
    fn spec(self) -> SpanSpec {
        match self {
            Self::Root => SpanSpec::new("stf", Some(Group::Stf)),
            Self::Validate => SpanSpec::new("validate", None),
            Self::Apply => SpanSpec::new("apply", None),
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Node {
    Span(Span),
    /// Columns validated together; a batch of one is shown as its column.
    Batch {
        source: ColumnSource,
        batch: usize,
    },
    Col {
        /// Position in the trace's `da.columns`.
        index: usize,
        /// 1-based rank by arrival within its source.
        arrival: usize,
    },
}

impl Node {
    pub fn opens(self) -> Option<Group> {
        match self {
            Self::Span(span) => span.spec().opens,
            Self::Batch { source, batch } => Some(Group::Batch { source, batch }),
            Self::Col { .. } => None,
        }
    }

    /// The group this row is listed under, so `Enter` on a child folds it.
    pub fn parent(self, trace: &BlockTrace) -> Option<Group> {
        match self {
            Self::Span(span) => span.parent(),
            Self::Batch { source, .. } => Some(Group::Cols(source)),
            Self::Col { index, .. } => {
                let source = trace.da.columns[index].source;
                let batches = trace.da.batches(source);
                let batch = batches.iter().position(|b| b.contains(index));
                Some(match batch {
                    Some(batch) if !batches[batch].is_single() => Group::Batch { source, batch },
                    _ => Group::Cols(source),
                })
            }
        }
    }

    pub fn batch(self, trace: &BlockTrace) -> Option<Batch> {
        let Self::Batch { source, batch } = self else {
            return None;
        };
        trace.da.batches(source).into_iter().nth(batch)
    }

    pub fn interval(self, trace: &BlockTrace) -> Option<Interval> {
        match self {
            Self::Span(span) => trace.interval(span),
            Self::Batch { .. } => Some(self.batch(trace)?.interval(&trace.da.columns)),
            Self::Col { index, .. } => Some(trace.da.columns[index].interval()),
        }
    }

    /// A column or batch the gate waited on: validated by the time it opened.
    pub fn counted_for_gate(self, trace: &BlockTrace) -> bool {
        match trace.da.available() {
            None => true,
            Some(gate) => self.interval(trace).is_none_or(|iv| iv.end <= gate),
        }
    }

    /// Rows spanning many columns, whose bars split at the gate.
    pub fn splits_at_the_gate(self) -> bool {
        matches!(self, Self::Span(Span::Da(_)))
    }

    /// A blobless block's data component is nothing but the gate opening.
    pub fn is_instant(self, trace: &BlockTrace) -> bool {
        matches!(self, Self::Span(Span::Da(DaSpan::Root)) if !trace.da.has_columns())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fold {
    Leaf,
    Closed,
    Open,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DisplayRow {
    pub root: [u8; 32],
    pub node: Node,
    pub depth: u8,
    pub fold: Fold,
}

#[derive(Hash, PartialEq, Eq)]
struct OpenGroup {
    root: [u8; 32],
    group: Group,
}

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
        let fold = match opens {
            None => Fold::Leaf,
            Some(group) if self.expanded.is_open(root, group) => Fold::Open,
            Some(_) => Fold::Closed,
        };
        self.out.push(DisplayRow { root, node: Node::Span(span), depth, fold });

        let Some(group) = Group::unfolding_after(span).filter(|g| self.expanded.is_open(root, *g))
        else {
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

    /// One row per batch in validation order; a batch of one is its column,
    /// a larger one folds its columns in arrival order.
    fn push_columns(&mut self, source: ColumnSource, depth: u8) {
        let root = self.trace.block_root;
        for (batch, columns) in self.trace.da.batches(source).iter().enumerate() {
            let mut col_depth = depth;
            if !columns.is_single() {
                let open = self.expanded.is_open(root, Group::Batch { source, batch });
                let fold = if open { Fold::Open } else { Fold::Closed };
                self.out.push(DisplayRow {
                    root,
                    node: Node::Batch { source, batch },
                    depth,
                    fold,
                });
                if !open {
                    continue;
                }
                col_depth = depth + 1;
            }
            self.out.extend(columns.columns.iter().map(|c| DisplayRow {
                root,
                node: Node::Col { index: c.index, arrival: c.arrival },
                depth: col_depth,
                fold: Fold::Leaf,
            }));
        }
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
            fold: Fold::Closed,
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
            Node::Span(Span::Da(DaSpan::Custody)),
            Node::Span(cols(ColumnSource::Gossip)),
            Node::Span(STF),
            Node::Span(VALIDATE),
            Node::Span(APPLY),
            Node::Span(Span::El),
        ]);
        assert_eq!(display[1].depth, 1);
        assert_eq!(display[2].depth, 1, "custody sits beside data available");
        assert_eq!(display[2].fold, Fold::Leaf, "custody carries no fold marker");
        assert_eq!(display[3].depth, 2, "the column list unfolds under custody");
        assert_eq!(display[3].fold, Fold::Closed, "an unopened group");
        assert_eq!(display[5].fold, Fold::Leaf, "validate is a leaf");
        assert_eq!(display[7].depth, 1, "el is a component of its own");
        assert_eq!(display[7].fold, Fold::Leaf);
    }

    #[test]
    fn column_rows_follow_their_group_in_arrival_order() {
        let block = with_columns();
        let mut expanded = Expanded::default();
        for group in [Group::Block, Group::Da, Group::Cols(ColumnSource::Gossip)] {
            expanded.toggle(block.block_root, group);
        }

        let display = display_rows(&rows_of(block), &expanded);
        let cols: Vec<_> = display.iter().filter(|d| matches!(d.node, Node::Col { .. })).collect();
        assert_eq!(cols.iter().map(|d| d.node).collect::<Vec<_>>(), [
            Node::Col { index: 1, arrival: 1 },
            Node::Col { index: 0, arrival: 2 },
        ]);
        assert!(cols.iter().all(|d| d.depth == 3 && d.fold == Fold::Leaf));
    }

    #[test]
    fn a_child_folds_into_its_group() {
        let block = with_columns();
        assert_eq!(Node::Span(Span::Strip).opens(), Some(Group::Block));
        assert_eq!(Node::Span(Span::Strip).parent(&block), None);
        assert_eq!(Node::Span(APPLY).parent(&block), Some(Group::Stf));
        assert_eq!(Node::Span(Span::El).parent(&block), Some(Group::Block));
        let col = Node::Col { index: 0, arrival: 2 };
        assert_eq!(col.parent(&block), Some(Group::Cols(ColumnSource::Gossip)));
        assert_eq!(
            Group::Cols(ColumnSource::Gossip).opener(),
            Node::Span(cols(ColumnSource::Gossip))
        );
        let custody = Node::Span(Span::Da(DaSpan::Custody));
        assert_eq!(custody.opens(), None, "custody is a leaf");
        assert_eq!(custody.parent(&block), Some(Group::Da), "but folds the column list it heads");
    }

    /// Columns validated together fold into one batch row; a lone column
    /// stays a column row, and a column folds back into its batch.
    #[test]
    fn batches_fold_their_columns() {
        let recv = |i| Stage::ColumnRecv { index: i, source: ColumnSource::Gossip };
        let validated = |i| Stage::ColumnValidated { index: i, source: ColumnSource::Gossip };
        let batched = || {
            trace(&[
                (received(), 300),
                (recv(7), 200),
                (recv(3), 210),
                (validated(7), 230),
                (validated(3), 230),
                (recv(1), 240),
                (validated(1), 260),
            ])
        };
        let source = ColumnSource::Gossip;
        let mut expanded = Expanded::default();
        for group in [Group::Block, Group::Da, Group::Cols(source)] {
            expanded.toggle([1u8; 32], group);
        }
        let batch = Node::Batch { source, batch: 0 };
        let lone = Node::Col { index: 2, arrival: 3 };
        let under_cols = |display: &[DisplayRow]| {
            display
                .iter()
                .filter(|d| d.depth >= 3)
                .map(|d| (d.node, d.depth, d.fold))
                .collect::<Vec<_>>()
        };

        let display = display_rows(&rows_of(batched()), &expanded);
        assert_eq!(under_cols(&display), [(batch, 3, Fold::Closed), (lone, 3, Fold::Leaf)]);

        expanded.toggle([1u8; 32], Group::Batch { source, batch: 0 });
        let display = display_rows(&rows_of(batched()), &expanded);
        assert_eq!(under_cols(&display), [
            (batch, 3, Fold::Open),
            (Node::Col { index: 0, arrival: 1 }, 4, Fold::Leaf),
            (Node::Col { index: 1, arrival: 2 }, 4, Fold::Leaf),
            (lone, 3, Fold::Leaf),
        ]);

        let block = batched();
        assert_eq!(
            Node::Col { index: 0, arrival: 1 }.parent(&block),
            Some(Group::Batch { source, batch: 0 })
        );
        assert_eq!(
            lone.parent(&block),
            Some(Group::Cols(source)),
            "a lone column folds the source"
        );
        assert_eq!(batch.parent(&block), Some(Group::Cols(source)));
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
