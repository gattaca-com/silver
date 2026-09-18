//! Which rows the pane shows for a block and in what order: static
//! per-component tables, plus the column batches and sidecars under an open
//! `Cols` group as the only data-driven rows.

use std::collections::HashSet;

use silver_common::ColumnOrigin;

use crate::sources::events::{Batch, BlockTrace, BlockTraces, DaSpan, Interval, Span, StfSpan};

/// A toggleable subtree; `Enter` on its opener flips it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Group {
    Block,
    Da,
    Cols(ColumnOrigin),
    /// Position in the origin's `DataAvailability::batches`.
    Batch {
        origin: ColumnOrigin,
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
                Span::Da(DaSpan::Cols(ColumnOrigin::Gossip)),
                Span::Da(DaSpan::Cols(ColumnOrigin::El)),
                Span::Da(DaSpan::Cols(ColumnOrigin::Rpc)),
            ],
            Self::Cols(_) | Self::Batch { .. } => &[],
            Self::Stf => &[
                Span::Stf(StfSpan::Validate),
                Span::Stf(StfSpan::Apply),
                Span::Stf(StfSpan::DaWait),
            ],
        }
    }

    /// The row that toggles this group.
    pub fn opener(self) -> Node {
        match self {
            Self::Block => Node::Span(Span::Strip),
            Self::Da => Node::Span(Span::Da(DaSpan::Root)),
            Self::Cols(origin) => Node::Span(Span::Da(DaSpan::Cols(origin))),
            Self::Batch { origin, batch } => Node::Batch { origin, batch },
            Self::Stf => Node::Span(Span::Stf(StfSpan::Root)),
        }
    }

    /// The group whose children unfold under this row. Both data rows open
    /// the column list, being the arrivals the gate and custody are two ends
    /// of; it unfolds under the lower one.
    fn unfolding_after(span: Span) -> Option<Self> {
        match span {
            Span::Da(DaSpan::Root) => None,
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

    fn parent(self) -> Option<Group> {
        Group::WITH_SPANS.into_iter().find(|g| g.children().contains(&self))
    }

    fn hidden(self, trace: &BlockTrace) -> bool {
        match self {
            Self::Da(DaSpan::Cols(origin)) => !trace.da.has_origin(origin),
            Self::Da(DaSpan::Custody) => !trace.da.has_columns(),
            Self::Stf(StfSpan::DaWait) => !trace.stf.parked(),
            _ => false,
        }
    }
}

impl DaSpan {
    fn spec(self) -> SpanSpec {
        match self {
            Self::Root => SpanSpec::new("data available", Some(Group::Da)),
            Self::Custody => SpanSpec::new("custody", Some(Group::Da)),
            Self::Cols(origin) => SpanSpec::new(cols_label(origin), Some(Group::Cols(origin))),
        }
    }
}

impl StfSpan {
    fn spec(self) -> SpanSpec {
        match self {
            Self::Root => SpanSpec::new("stf", Some(Group::Stf)),
            Self::Validate => SpanSpec::new("validate", None),
            Self::Apply => SpanSpec::new("apply", None),
            Self::DaWait => SpanSpec::new("da wait", None),
        }
    }
}

fn cols_label(origin: ColumnOrigin) -> &'static str {
    match origin {
        ColumnOrigin::Gossip => "gossip cols",
        ColumnOrigin::Rpc => "rpc cols",
        ColumnOrigin::El => "el cols",
        ColumnOrigin::Assembly => "assembled cols",
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Node {
    Span(Span),
    /// Columns validated together; a batch of one is shown as its column.
    Batch {
        origin: ColumnOrigin,
        batch: usize,
    },
    Col {
        /// Position in the trace's `da.columns`.
        index: usize,
        /// 1-based position in the origin's persist order.
        rank: usize,
    },
}

impl Node {
    pub fn opens(self) -> Option<Group> {
        match self {
            Self::Span(span) => span.spec().opens,
            Self::Batch { origin, batch } => Some(Group::Batch { origin, batch }),
            Self::Col { .. } => None,
        }
    }

    /// The group this row is listed under, so `Enter` on a child folds it.
    pub fn parent(self, trace: &BlockTrace) -> Option<Group> {
        match self {
            Self::Span(span) => span.parent(),
            Self::Batch { origin, .. } => Some(Group::Cols(origin)),
            Self::Col { index, .. } => {
                let origin = trace.da.columns[index].origin;
                let batches = trace.da.batches(origin);
                let batch = batches.iter().position(|b| b.contains(index));
                Some(match batch {
                    Some(batch) if !batches[batch].is_single() => Group::Batch { origin, batch },
                    _ => Group::Cols(origin),
                })
            }
        }
    }

    pub fn batch(self, trace: &BlockTrace) -> Option<Batch> {
        let Self::Batch { origin, batch } = self else {
            return None;
        };
        trace.da.batches(origin).into_iter().nth(batch)
    }

    pub fn interval(self, trace: &BlockTrace) -> Option<Interval> {
        match self {
            Self::Span(span) => trace.interval(span),
            Self::Batch { .. } => Some(self.batch(trace)?.interval(&trace.da.columns)),
            Self::Col { index, .. } => Some(trace.da.columns[index].interval()),
        }
    }

    /// A batch the gate waited on, or a column of one.
    pub fn counted_for_gate(self, trace: &BlockTrace) -> bool {
        let batch = match self {
            Self::Span(_) => return true,
            Self::Batch { .. } => self.batch(trace),
            Self::Col { index, .. } => trace.da.batch_of(index),
        };
        batch.is_none_or(|b| b.counted_for_gate(&trace.da.columns, trace.da.available()))
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
        if let Group::Cols(origin) = group {
            self.push_columns(origin, depth + 1);
        }
    }

    /// One row per batch in validation order; a batch of one is its column,
    /// a larger one folds its columns in rank order.
    fn push_columns(&mut self, origin: ColumnOrigin, depth: u8) {
        let root = self.trace.block_root;
        for (batch, columns) in self.trace.da.batches(origin).iter().enumerate() {
            let mut col_depth = depth;
            if !columns.is_single() {
                let open = self.expanded.is_open(root, Group::Batch { origin, batch });
                let fold = if open { Fold::Open } else { Fold::Closed };
                self.out.push(DisplayRow {
                    root,
                    node: Node::Batch { origin, batch },
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
                node: Node::Col { index: c.index, rank: c.rank },
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
    use crate::sources::events::trace_tests::{
        APPLY, DA, DA_WAIT, STF, VALIDATE, cols, el_sent, received, trace,
    };

    fn rows_of(trace: BlockTrace) -> BlockTraces {
        BlockTraces::from_iter([trace])
    }

    fn nodes(display: &[DisplayRow]) -> Vec<Node> {
        display.iter().map(|d| d.node).collect()
    }

    /// Two columns validated a round apart, so each is a batch of one.
    fn with_columns() -> BlockTrace {
        let recv = |i| Stage::ColumnRecv { index: i, origin: ColumnOrigin::Gossip };
        let validated = |i| Stage::ColumnValidated { index: i, origin: ColumnOrigin::Gossip };
        trace(&[
            (received(), 300),
            (recv(7), 250),
            (validated(7), 255),
            (recv(3), 262),
            (validated(3), 270),
        ])
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
            Node::Span(cols(ColumnOrigin::Gossip)),
            Node::Span(STF),
            Node::Span(VALIDATE),
            Node::Span(APPLY),
            Node::Span(Span::El),
        ]);
        assert_eq!(display[1].depth, 1);
        assert_eq!(display[2].depth, 1, "custody sits beside data available");
        assert_eq!(display[2].fold, Fold::Open, "custody carries the same fold marker");
        assert_eq!(display[3].depth, 2, "the column list unfolds under custody");
        assert_eq!(display[3].fold, Fold::Closed, "an unopened group");
        assert_eq!(display[5].fold, Fold::Leaf, "validate is a leaf");
        assert_eq!(display[7].depth, 1, "el is a component of its own");
        assert_eq!(display[7].fold, Fold::Leaf);
    }

    /// The wait row exists only for a block that parked on its columns.
    #[test]
    fn da_wait_unfolds_only_for_a_parked_block() {
        let stf_rows = |block: BlockTrace| {
            let mut expanded = Expanded::default();
            expanded.toggle(block.block_root, Group::Block);
            expanded.toggle(block.block_root, Group::Stf);
            let display = display_rows(&rows_of(block), &expanded);
            nodes(&display)
                .into_iter()
                .filter(|n| matches!(n, Node::Span(Span::Stf(_))))
                .collect::<Vec<_>>()
        };

        let parked = trace(&[
            (received(), 300),
            (el_sent(), 301),
            (Stage::StfDone, 308),
            (Stage::Attestable, 337),
        ]);
        assert_eq!(stf_rows(parked), [STF, VALIDATE, APPLY, DA_WAIT].map(Node::Span));

        let unparked = trace(&[
            (received(), 300),
            (el_sent(), 301),
            (Stage::StfDone, 308),
            (Stage::Attestable, 308),
        ]);
        assert_eq!(stf_rows(unparked), [STF, VALIDATE, APPLY].map(Node::Span));
    }

    #[test]
    fn column_rows_follow_their_group_in_persist_order() {
        let block = with_columns();
        let mut expanded = Expanded::default();
        for group in [Group::Block, Group::Da, Group::Cols(ColumnOrigin::Gossip)] {
            expanded.toggle(block.block_root, group);
        }

        let display = display_rows(&rows_of(block), &expanded);
        let cols: Vec<_> = display.iter().filter(|d| matches!(d.node, Node::Col { .. })).collect();
        assert_eq!(cols.iter().map(|d| d.node).collect::<Vec<_>>(), [
            Node::Col { index: 0, rank: 1 },
            Node::Col { index: 1, rank: 2 },
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
        let col = Node::Col { index: 0, rank: 1 };
        assert_eq!(col.parent(&block), Some(Group::Cols(ColumnOrigin::Gossip)));
        assert_eq!(
            Group::Cols(ColumnOrigin::Gossip).opener(),
            Node::Span(cols(ColumnOrigin::Gossip))
        );
        let custody = Node::Span(Span::Da(DaSpan::Custody));
        assert_eq!(custody.opens(), Some(Group::Da), "custody opens the column list it heads");
    }

    /// Columns validated together fold into one batch row; a lone column
    /// stays a column row, and a column folds back into its batch.
    #[test]
    fn batches_fold_their_columns() {
        let recv = |i| Stage::ColumnRecv { index: i, origin: ColumnOrigin::Gossip };
        let validated = |i| Stage::ColumnValidated { index: i, origin: ColumnOrigin::Gossip };
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
        let origin = ColumnOrigin::Gossip;
        let mut expanded = Expanded::default();
        for group in [Group::Block, Group::Da, Group::Cols(origin)] {
            expanded.toggle([1u8; 32], group);
        }
        let batch = Node::Batch { origin, batch: 0 };
        let lone = Node::Col { index: 2, rank: 3 };
        let under_cols = |display: &[DisplayRow]| {
            display
                .iter()
                .filter(|d| d.depth >= 3)
                .map(|d| (d.node, d.depth, d.fold))
                .collect::<Vec<_>>()
        };

        let display = display_rows(&rows_of(batched()), &expanded);
        assert_eq!(under_cols(&display), [(batch, 3, Fold::Closed), (lone, 3, Fold::Leaf)]);

        expanded.toggle([1u8; 32], Group::Batch { origin, batch: 0 });
        let display = display_rows(&rows_of(batched()), &expanded);
        assert_eq!(under_cols(&display), [
            (batch, 3, Fold::Open),
            (Node::Col { index: 0, rank: 1 }, 4, Fold::Leaf),
            (Node::Col { index: 1, rank: 2 }, 4, Fold::Leaf),
            (lone, 3, Fold::Leaf),
        ]);

        let block = batched();
        assert_eq!(
            Node::Col { index: 0, rank: 1 }.parent(&block),
            Some(Group::Batch { origin, batch: 0 })
        );
        assert_eq!(
            lone.parent(&block),
            Some(Group::Cols(origin)),
            "a lone column folds the origin"
        );
        assert_eq!(batch.parent(&block), Some(Group::Cols(origin)));
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
