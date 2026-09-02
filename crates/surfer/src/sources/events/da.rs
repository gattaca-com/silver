use silver_common::{ColumnSource, Nanos};

use super::trace::Interval;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DaSpan {
    /// First sidecar arrival → the gate opening.
    Root,
    /// One source's columns: first arrival → last validation.
    Cols(ColumnSource),
}

pub struct ColumnRow {
    pub index: u64,
    pub source: ColumnSource,
    pub recv: Nanos,
    pub validated: Option<Nanos>,
}

impl ColumnRow {
    pub fn interval(&self) -> Interval {
        Interval { start: self.recv, end: self.validated.unwrap_or(self.recv) }
    }
}

/// The data-availability component: sidecars feeding the DA gate.
#[derive(Default)]
pub struct DataAvailability {
    /// One entry per data-column sidecar, in arrival order.
    pub columns: Vec<ColumnRow>,
    available: Option<Nanos>,
}

impl DataAvailability {
    /// A duplicate arrival of a held column re-emits `Persist`; the first
    /// arrival and validation stand.
    pub(super) fn column_received(&mut self, index: u64, source: ColumnSource, ts: Nanos) {
        if self.columns.iter().all(|c| c.index != index) {
            self.columns.push(ColumnRow { index, source, recv: ts, validated: None });
        }
    }

    pub(super) fn column_validated(&mut self, index: u64, ts: Nanos) {
        if let Some(col) = self.columns.iter_mut().find(|c| c.index == index) {
            col.validated.get_or_insert(ts);
        }
    }

    pub(super) fn gate_opened(&mut self, ts: Nanos) {
        self.available = Some(ts);
    }

    /// When the DA gate opened; columns arriving after it are custody duty,
    /// not what this block waited for.
    pub fn available(&self) -> Option<Nanos> {
        self.available
    }

    pub fn has_columns(&self) -> bool {
        !self.columns.is_empty()
    }

    pub fn has_source(&self, source: ColumnSource) -> bool {
        self.columns.iter().any(|c| c.source == source)
    }

    pub fn first_column_at(&self) -> Option<Nanos> {
        self.columns.iter().map(|c| c.recv).min()
    }

    /// `None` while the span has no events.
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
            DaSpan::Cols(source) => {
                let of_source = || self.columns.iter().filter(|c| c.source == source);
                let start = of_source().map(|c| c.recv).min()?;
                let end = of_source().map(|c| c.interval().end).max()?;
                Interval { start, end }
            }
        };
        Some(interval)
    }

    /// The column whose validation crossed the DA threshold — the event that
    /// opened the gate, when gossip columns opened it.
    pub fn trigger(&self) -> Option<usize> {
        let gate = self.available?;
        self.columns
            .iter()
            .enumerate()
            .filter(|(_, c)| c.validated.is_some_and(|v| v <= gate))
            .max_by_key(|(_, c)| c.validated)
            .map(|(i, _)| i)
    }
}
