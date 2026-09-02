use silver_common::{ColumnSource, Nanos};

use super::trace::Interval;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DaSpan {
    /// First sidecar arrival → the gate opening.
    Root,
    /// First sidecar arrival → the node's custody set complete.
    Custody,
    /// One source's columns: first arrival → last validation.
    Cols(ColumnSource),
}

pub struct Column {
    pub index: u64,
    pub source: ColumnSource,
    pub received_at: Nanos,
    pub validated_at: Option<Nanos>,
}

impl Column {
    pub fn interval(&self) -> Interval {
        Interval { start: self.received_at, end: self.validated_at.unwrap_or(self.received_at) }
    }
}

#[derive(Default)]
pub struct DataAvailability {
    /// One entry per data-column sidecar, in arrival order.
    pub columns: Vec<Column>,
    available: Option<Nanos>,
    custody_done: Option<Nanos>,
}

impl DataAvailability {
    pub(super) fn column_received(&mut self, index: u64, source: ColumnSource, ts: Nanos) {
        if self.columns.iter().all(|c| c.index != index) {
            self.columns.push(Column { index, source, received_at: ts, validated_at: None });
        }
    }

    pub(super) fn column_validated(&mut self, index: u64, ts: Nanos) {
        if let Some(col) = self.columns.iter_mut().find(|c| c.index == index) {
            col.validated_at.get_or_insert(ts);
        }
    }

    pub(super) fn gate_opened(&mut self, ts: Nanos) {
        self.available = Some(ts);
    }

    pub(super) fn custody_completed(&mut self, ts: Nanos) {
        self.custody_done = Some(ts);
    }

    pub fn available(&self) -> Option<Nanos> {
        self.available
    }

    pub fn has_columns(&self) -> bool {
        !self.columns.is_empty()
    }

    pub fn of_source(&self, source: ColumnSource) -> impl Iterator<Item = (usize, &Column)> {
        self.columns.iter().enumerate().filter(move |(_, c)| c.source == source)
    }

    pub fn has_source(&self, source: ColumnSource) -> bool {
        self.of_source(source).next().is_some()
    }

    pub fn first_column_at(&self) -> Option<Nanos> {
        self.columns.iter().map(|c| c.received_at).min()
    }

    pub fn interval(&self, span: DaSpan) -> Option<Interval> {
        let interval = match span {
            DaSpan::Root => {
                let start = self.first_column_at().or(self.available)?;
                let end = self
                    .available
                    .or_else(|| self.columns.iter().map(|c| c.interval().end).max())
                    .unwrap_or(start);
                Interval { start, end }
            }
            DaSpan::Custody => Interval { start: self.first_column_at()?, end: self.custody_done? },
            DaSpan::Cols(source) => {
                let start = self.of_source(source).map(|(_, c)| c.received_at).min()?;
                let end = self.of_source(source).map(|(_, c)| c.interval().end).max()?;
                Interval { start, end }
            }
        };
        Some(interval)
    }
}
