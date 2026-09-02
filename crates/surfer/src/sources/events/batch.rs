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
    /// 1-based rank by arrival within the source.
    pub arrival: usize,
}

/// Columns of one source validated together, by arrival.
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

    pub fn arrivals(&self) -> (usize, usize) {
        debug_assert!(!self.columns.is_empty());
        (self.columns[0].arrival, self.columns[self.columns.len() - 1].arrival)
    }

    /// First arrival → last validation.
    pub fn interval(&self, columns: &[Column]) -> Interval {
        debug_assert!(!self.columns.is_empty());
        let start = self.columns.iter().map(|c| columns[c.index].received_at).min();
        let end = self.columns.iter().map(|c| columns[c.index].interval().end).max();
        Interval { start: start.expect("non-empty"), end: end.expect("non-empty") }
    }
}

impl DataAvailability {
    /// One source's columns in validation order, cut where consecutive
    /// validations are more than `BATCH_GAP` apart or the gate opened between
    /// them, so a batch is one colour.
    pub fn batches(&self, source: ColumnSource) -> Vec<Batch> {
        let mut by_arrival: Vec<_> = self.of_source(source).map(|(i, _)| i).collect();
        by_arrival.sort_by_key(|&i| self.columns[i].received_at);
        let mut ranked: Vec<_> = by_arrival
            .into_iter()
            .zip(1..)
            .map(|(index, arrival)| BatchColumn { index, arrival })
            .collect();
        ranked.sort_by_key(|c| (self.columns[c.index].interval().end, c.arrival));

        let mut batches: Vec<Batch> = Vec::new();
        let mut previous_end = None;
        for column in ranked {
            let end = self.columns[column.index].interval().end;
            let same_batch = previous_end.is_some_and(|prev: Nanos| {
                end - prev <= BATCH_GAP && !self.gate_between(prev, end)
            });
            match batches.last_mut() {
                Some(batch) if same_batch => batch.columns.push(column),
                _ => batches.push(Batch { columns: vec![column] }),
            }
            previous_end = Some(end);
        }
        for batch in &mut batches {
            batch.columns.sort_by_key(|c| c.arrival);
        }
        batches
    }

    fn gate_between(&self, before: Nanos, after: Nanos) -> bool {
        self.available().is_some_and(|gate| before <= gate && gate < after)
    }

    /// Whether a row ending at `end` is the last validation the gate waited on.
    pub fn opened_gate(&self, end: Nanos) -> bool {
        let Some(gate) = self.available() else {
            return false;
        };
        let last_before_gate =
            self.columns.iter().map(|c| c.interval().end).filter(|&e| e <= gate).max();
        last_before_gate == Some(end)
    }
}

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
    /// by arrival inside it; the fourth, validated a round later, is alone.
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
        assert_eq!(batches[0].arrivals(), (1, 3));
        assert_eq!(batches[0].interval(&t.da.columns), Interval {
            start: at(2, 200),
            end: at(2, 231)
        });
        assert_eq!(indices(&batches[1], &t.da), [1]);
        assert!(batches[1].is_single());
    }

    /// Two validations a microsecond apart still split when the gate opened
    /// between them, so no batch straddles the colour change.
    #[test]
    fn batches_cut_at_the_gate() {
        let mut t = trace(&[(received(), 300), (recv(1), 200), (recv(2), 201)]);
        let us = |ms: u64, micros: u64| at(2, ms) + Nanos(micros * 1_000);
        for (stage, ts) in [
            (validated(1), us(230, 0)),
            (Stage::DaAvailable, us(230, 5)),
            (validated(2), us(230, 10)),
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
        assert!(t.da.opened_gate(us(230, 0)));
        assert!(!t.da.opened_gate(us(230, 10)));
    }

    #[test]
    fn unvalidated_columns_batch_by_arrival() {
        let t = trace(&[(received(), 300), (recv(1), 200), (recv(2), 200)]);
        let batches = t.da.batches(ColumnSource::Gossip);
        assert_eq!(batches.len(), 1, "same instant, no validation yet");
        assert_eq!(batches[0].arrivals(), (1, 2));
    }
}
