use silver_common::{ColumnSource, Nanos};

use super::{
    da::{Column, DataAvailability},
    trace::Interval,
};

/// Columns of one KZG verification land microseconds apart; separate
/// verifications are at least a round apart.
const BATCH_GAP: Nanos = Nanos::from_millis(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BatchColumn {
    /// Position in `DataAvailability::columns`.
    pub index: usize,
    /// 1-based position in the source's persist order.
    pub rank: usize,
}

/// Columns of one source validated together, in persist order.
#[derive(Debug, PartialEq, Eq)]
pub struct Batch {
    pub columns: Vec<BatchColumn>,
}

impl Batch {
    pub fn contains(&self, index: usize) -> bool {
        self.columns.iter().any(|c| c.index == index)
    }

    pub fn is_single(&self) -> bool {
        self.columns.len() == 1
    }

    pub fn ranks(&self) -> (usize, usize) {
        debug_assert!(!self.columns.is_empty());
        (self.columns[0].rank, self.columns[self.columns.len() - 1].rank)
    }

    /// First rank → last validation.
    pub fn interval(&self, columns: &[Column]) -> Interval {
        debug_assert!(!self.columns.is_empty());
        let start = self.columns.iter().map(|c| columns[c.index].received_at).min();
        let end = self.columns.iter().map(|c| columns[c.index].interval().end).max();
        Interval { start: start.expect("non-empty"), end: end.expect("non-empty") }
    }

    fn first_validation(&self, columns: &[Column]) -> Nanos {
        debug_assert!(!self.columns.is_empty());
        self.columns.iter().map(|c| columns[c.index].interval().end).min().expect("non-empty")
    }

    /// The gate waited on this batch: its validation began before the gate
    /// opened. The gate message precedes the threshold column's own, so the
    /// batch that opened it straddles the gate timestamp and counts whole.
    pub fn counted_for_gate(&self, columns: &[Column], gate: Option<Nanos>) -> bool {
        gate.is_none_or(|gate| self.first_validation(columns) <= gate)
    }
}

impl DataAvailability {
    /// One source's columns in persist order, which is validation order, cut
    /// where consecutive validations are more than `BATCH_GAP` apart. Each
    /// batch is a contiguous run of ranks.
    pub fn batches(&self, source: ColumnSource) -> Vec<Batch> {
        let mut batches: Vec<Batch> = Vec::new();
        let mut previous_end = None;
        for ((index, column), rank) in self.of_source(source).zip(1..) {
            let end = column.interval().end;
            let same_batch =
                previous_end.is_some_and(|prev: Nanos| end.saturating_sub(prev) <= BATCH_GAP);
            let column = BatchColumn { index, rank };
            match batches.last_mut() {
                Some(batch) if same_batch => batch.columns.push(column),
                _ => batches.push(Batch { columns: vec![column] }),
            }
            previous_end = Some(end);
        }
        batches
    }

    pub fn batch_of(&self, index: usize) -> Option<Batch> {
        let source = self.columns.get(index)?.source;
        self.batches(source).into_iter().find(|b| b.contains(index))
    }

    /// Whether this is the batch that opened the gate: the last one, across
    /// sources, whose validation began before the gate did.
    pub fn opened_gate(&self, batch: &Batch) -> bool {
        let Some(gate) = self.available() else {
            return false;
        };
        let first_validation = |b: &Batch| b.first_validation(&self.columns);
        let opener = SOURCES
            .into_iter()
            .flat_map(|source| self.batches(source))
            .filter(|b| first_validation(b) <= gate)
            .max_by_key(first_validation);
        opener.as_ref() == Some(batch)
    }
}

const SOURCES: [ColumnSource; 3] = [ColumnSource::Gossip, ColumnSource::El, ColumnSource::Rpc];

#[cfg(test)]
mod tests {
    use silver_stages::Stage;

    use super::*;
    use crate::sources::events::trace_tests::{at, received, trace};

    fn recv(i: u64) -> Stage {
        Stage::ColumnRecv { index: i, source: ColumnSource::Gossip }
    }

    fn validated(i: u64) -> Stage {
        Stage::ColumnValidated { index: i, source: ColumnSource::Gossip }
    }

    fn indices(batch: &Batch, da: &DataAvailability) -> Vec<u64> {
        batch.columns.iter().map(|c| da.columns[c.index].index).collect()
    }

    /// Three columns validated within a millisecond form one batch, ordered
    /// by rank inside it; the fourth, validated a round later, is alone.
    #[test]
    fn batches_cut_at_the_gap() {
        let t = trace(&[
            (received(), 300),
            (recv(7), 200),
            (recv(3), 210),
            (recv(9), 220),
            (validated(9), 230),
            (validated(7), 230),
            (validated(3), 231),
            (recv(1), 240),
            (validated(1), 260),
        ]);
        let batches = t.da.batches(ColumnSource::Gossip);
        assert_eq!(batches.len(), 2);
        assert_eq!(indices(&batches[0], &t.da), [7, 3, 9]);
        assert_eq!(batches[0].ranks(), (1, 3));
        assert_eq!(batches[0].interval(&t.da.columns), Interval {
            start: at(2, 200),
            end: at(2, 231)
        });
        assert_eq!(indices(&batches[1], &t.da), [1]);
        assert!(batches[1].is_single());
    }

    /// The gate message lands between the columns of the flush that opened
    /// it; that flush stays one batch, counted whole, and is the opener. A
    /// later batch is not counted.
    #[test]
    fn the_batch_straddling_the_gate_opened_it() {
        let mut t = trace(&[(received(), 300), (recv(1), 200), (recv(2), 201), (recv(3), 202)]);
        let us = |ms: u64, micros: u64| at(2, ms) + Nanos(micros * 1_000);
        for (stage, ts) in [
            (validated(1), us(230, 0)),
            (Stage::DaAvailable, us(230, 5)),
            (validated(2), us(230, 10)),
            (validated(3), us(240, 0)),
        ] {
            t.apply(silver_stages::StageEvent {
                stage,
                ts,
                block_root: t.block_root,
                slot: Some(t.slot),
            });
        }
        let batches = t.da.batches(ColumnSource::Gossip);
        assert_eq!(batches.len(), 2);
        let gate = t.da.available();
        assert!(batches[0].counted_for_gate(&t.da.columns, gate));
        assert!(t.da.opened_gate(&batches[0]));
        assert!(!batches[1].counted_for_gate(&t.da.columns, gate));
        assert!(!t.da.opened_gate(&batches[1]));
        assert_eq!(t.da.batch_of(1), Some(Batch { columns: batches[0].columns.clone() }));
    }

    #[test]
    fn unvalidated_columns_batch_by_arrival() {
        let t = trace(&[(received(), 300), (recv(1), 200), (recv(2), 200)]);
        let batches = t.da.batches(ColumnSource::Gossip);
        assert_eq!(batches.len(), 1, "same instant, no validation yet");
        assert_eq!(batches[0].ranks(), (1, 2));
    }
}
