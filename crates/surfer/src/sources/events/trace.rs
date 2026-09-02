use silver_common::Nanos;
use silver_stages::{SlotClock, Stage, StageEvent};

use super::{
    da::{DaSpan, DataAvailability},
    el::Execution,
    stf::{StateTransition, StfSpan},
};

/// Wall-clock extent of one span; an instant span is a zero-length interval.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Interval {
    pub start: Nanos,
    pub end: Nanos,
}

impl Interval {
    pub fn duration(self) -> Nanos {
        self.end.saturating_sub(self.start)
    }
}

/// Distance from the attestation deadline at attestable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Margin {
    pub delta: Nanos,
    pub made_it: bool,
}

/// One span of the block's dependency graph: the whole strip, then the three
/// components that join at attestable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Span {
    Strip,
    Da(DaSpan),
    Stf(StfSpan),
    El,
}

/// The block's common points — arrival and `newPayload` dispatch, which both
/// `stf` and `el` start from — plus the three components, joined at attestable.
pub struct BlockTrace {
    pub slot: u64,
    pub block_root: [u8; 32],
    received_at: Option<Nanos>,
    el_sent_at: Option<Nanos>,
    pub da: DataAvailability,
    pub stf: StateTransition,
    pub el: Execution,
}

impl BlockTrace {
    pub fn new(slot: u64, block_root: [u8; 32]) -> Self {
        Self {
            slot,
            block_root,
            received_at: None,
            el_sent_at: None,
            da: DataAvailability::default(),
            stf: StateTransition::default(),
            el: Execution::default(),
        }
    }

    /// First-wins: the reader dedups per root only within a finite window,
    /// and duplicate sidecars re-emit their stage.
    pub fn apply(&mut self, event: StageEvent) {
        let ts = event.ts;
        match event.stage {
            Stage::Received { .. } => {
                if self.received_at.is_none() {
                    self.received_at = Some(ts);
                }
            }
            Stage::ElSent { .. } => self.el_sent_at = Some(ts),
            Stage::StfImported => self.stf.imported(ts),
            // The FCU times dispatch, not import; telemetry keeps it.
            Stage::Applied => {}
            Stage::ElVerdict { verdict } => self.el.verdict_received(verdict, ts),
            Stage::ColumnRecv { index, source } => self.da.column_received(index, source, ts),
            Stage::ColumnValidated { index, .. } => self.da.column_validated(index, ts),
            Stage::DaAvailable => self.da.gate_opened(ts),
            Stage::CustodyDone => self.da.custody_completed(ts),
        }
    }

    /// When the head became attestable: every component done — imported into
    /// fork choice, the EL verdict `Valid`, and the gate open where it was
    /// seen. `None` while the verdict is pending or not `Valid`.
    pub fn attestable_at(&self) -> Option<Nanos> {
        let imported = self.stf.imported_at()?;
        let valid = self.el.valid_at()?;
        Some(imported.max(valid).max(self.da.available().unwrap_or(imported)))
    }

    /// The last event on the block's own path — column custody traffic
    /// excluded, so a strip without a verdict ends at import, not at the
    /// custody tail.
    fn last_event(&self) -> Option<Nanos> {
        [self.stf.imported_at(), self.el.verdict_at(), self.el_sent_at, self.da.available()]
            .into_iter()
            .flatten()
            .max()
    }

    /// Where CL validation starts: the DA gate when it held the block (the
    /// gate precedes dispatch), else arrival.
    fn validate_from(&self) -> Option<Nanos> {
        self.received_at.map(|at| match self.da.available() {
            Some(gate) if self.el_sent_at.is_some_and(|sent| gate < sent) => at.max(gate),
            _ => at,
        })
    }

    /// `None` while the span has no events.
    pub fn interval(&self, span: Span) -> Option<Interval> {
        match span {
            Span::Strip => {
                let start = self.received_at.or_else(|| self.da.first_column_at())?;
                let end = self.attestable_at().or_else(|| self.last_event()).unwrap_or(start);
                Some(Interval { start, end: end.max(start) })
            }
            Span::Da(span) => self.da.interval(span),
            Span::Stf(span) => self.stf.interval(span, self.validate_from(), self.el_sent_at),
            Span::El => self.el.interval(self.el_sent_at),
        }
    }

    pub fn offset_in_slot(&self, clock: &SlotClock, ts: Nanos) -> Option<Nanos> {
        clock.offset_in_slot(ts, self.slot)
    }

    /// `None` before attestable.
    pub fn deadline_margin(&self, clock: &SlotClock, deadline: Nanos) -> Option<Margin> {
        let at = self.offset_in_slot(clock, self.attestable_at()?)?;
        Some(if at <= deadline {
            Margin { delta: deadline - at, made_it: true }
        } else {
            Margin { delta: at - deadline, made_it: false }
        })
    }
}

#[cfg(test)]
pub mod tests {
    use silver_common::{BlockSource, ColumnSource, PayloadValidationStatus};

    use super::*;

    pub const GENESIS_SECS: u64 = 1_000;
    pub const SLOT_MS: u64 = 12_000;

    pub const DA: Span = Span::Da(DaSpan::Root);
    pub const STF: Span = Span::Stf(StfSpan::Root);
    pub const VALIDATE: Span = Span::Stf(StfSpan::Validate);
    pub const APPLY: Span = Span::Stf(StfSpan::Apply);

    pub fn cols(source: ColumnSource) -> Span {
        Span::Da(DaSpan::Cols(source))
    }

    pub fn at(slot: u64, ms_into_slot: u64) -> Nanos {
        Nanos::from_secs(GENESIS_SECS) + Nanos::from_millis(slot * SLOT_MS + ms_into_slot)
    }

    pub fn event(stage: Stage, ts: Nanos, slot: Option<u64>) -> StageEvent {
        StageEvent { stage, ts, block_root: [1u8; 32], slot }
    }

    pub fn received() -> Stage {
        Stage::Received { source: BlockSource::Gossip }
    }

    pub fn el_sent() -> Stage {
        Stage::ElSent { source: BlockSource::Gossip }
    }

    pub fn valid() -> Stage {
        Stage::ElVerdict { verdict: PayloadValidationStatus::Valid }
    }

    pub fn iv(start: Nanos, end: Nanos) -> Option<Interval> {
        Some(Interval { start, end })
    }

    /// A slot-2 trace with every stage applied at the given ms offsets.
    pub fn trace(stages: &[(Stage, u64)]) -> BlockTrace {
        let mut trace = BlockTrace::new(2, [1u8; 32]);
        for &(stage, ms) in stages {
            trace.apply(event(stage, at(2, ms), Some(2)));
        }
        trace
    }

    #[test]
    fn block_spans() {
        let t = trace(&[
            (received(), 300),
            (el_sent(), 300),
            (Stage::StfImported, 460),
            (valid(), 520),
            (Stage::DaAvailable, 350),
        ]);

        assert_eq!(t.interval(Span::Strip), iv(at(2, 300), at(2, 520)), "arrival → attestable");
        // The gate fired after dispatch, so it never held the block.
        assert_eq!(t.interval(VALIDATE), iv(at(2, 300), at(2, 300)));
        assert_eq!(t.interval(APPLY), iv(at(2, 300), at(2, 460)));
        assert_eq!(t.interval(STF), iv(at(2, 300), at(2, 460)), "validate → import");
        assert_eq!(t.interval(Span::El), iv(at(2, 300), at(2, 520)));
        assert_eq!(
            t.interval(DA),
            iv(at(2, 350), at(2, 350)),
            "no sidecars: the component is the gate"
        );
        assert_eq!(t.interval(cols(ColumnSource::Gossip)), None, "no sidecars observed");
        assert_eq!(t.attestable_at(), Some(at(2, 520)));
        assert_eq!(t.el.status(), Some(PayloadValidationStatus::Valid));
    }

    /// The DA gate precedes `newPayload` dispatch, so a gated block's
    /// `validate` starts at the gate — the data wait must not be counted as
    /// validation.
    #[test]
    fn gated_block_measures_validate_from_the_gate() {
        let t = trace(&[
            (received(), 300),
            (Stage::DaAvailable, 410),
            (el_sent(), 413),
            (Stage::StfImported, 422),
        ]);

        assert_eq!(t.interval(VALIDATE), iv(at(2, 410), at(2, 413)), "gate → dispatch");
        assert_eq!(t.interval(APPLY), iv(at(2, 413), at(2, 422)));
        assert_eq!(t.interval(STF), iv(at(2, 410), at(2, 422)));
    }

    /// Attestable needs every component: import (STF behind the gate) and a
    /// `Valid` verdict. Until then the strip ends at the last event on the
    /// path.
    #[test]
    fn attestable_needs_import_and_a_valid_verdict() {
        let imported_only =
            trace(&[(received(), 300), (el_sent(), 310), (Stage::StfImported, 460)]);
        assert_eq!(imported_only.attestable_at(), None);
        assert_eq!(imported_only.interval(Span::Strip), iv(at(2, 300), at(2, 460)));

        let syncing = Stage::ElVerdict { verdict: PayloadValidationStatus::Syncing };
        let optimistic = trace(&[(received(), 300), (Stage::StfImported, 460), (syncing, 330)]);
        assert_eq!(optimistic.attestable_at(), None, "an optimistic head is not attestable");

        let verdict_first = trace(&[(received(), 300), (valid(), 330), (Stage::StfImported, 460)]);
        assert_eq!(verdict_first.attestable_at(), Some(at(2, 460)), "the later component decides");

        let late_gate = trace(&[
            (received(), 300),
            (valid(), 330),
            (Stage::StfImported, 460),
            (Stage::DaAvailable, 470),
        ]);
        assert_eq!(late_gate.attestable_at(), Some(at(2, 470)), "DA joins the max when known");
    }

    /// Duplicates re-announce an imported block; the first import is the apply.
    #[test]
    fn repeat_imports_keep_the_first() {
        let t = trace(&[
            (received(), 300),
            (el_sent(), 320),
            (Stage::StfImported, 460),
            (Stage::StfImported, 900),
        ]);
        assert_eq!(t.interval(APPLY), iv(at(2, 320), at(2, 460)));
    }

    /// The FCU no longer times anything here; it stays a stage for telemetry.
    #[test]
    fn fcu_moves_no_span() {
        let t = trace(&[(received(), 300), (el_sent(), 320), (Stage::Applied, 900)]);
        assert_eq!(t.interval(APPLY), None);
        assert_eq!(t.interval(Span::Strip), iv(at(2, 300), at(2, 320)));
    }

    /// Duplicate `Persist` events (an already-held column re-arriving) fold
    /// into one column with the first timestamps.
    #[test]
    fn duplicate_column_events_fold_into_one_column() {
        let recv = Stage::ColumnRecv { index: 48, source: ColumnSource::Gossip };
        let validated = Stage::ColumnValidated { index: 48, source: ColumnSource::Gossip };
        let t = trace(&[(recv, 200), (validated, 210), (recv, 500), (validated, 510)]);

        assert_eq!(t.da.columns.len(), 1);
        assert_eq!(t.da.columns[0].interval(), Interval { start: at(2, 200), end: at(2, 210) });
        assert_eq!(t.interval(cols(ColumnSource::Gossip)), iv(at(2, 200), at(2, 210)));
        assert_eq!(t.interval(cols(ColumnSource::El)), None, "no EL-built sidecars");
        assert_eq!(t.interval(DA), iv(at(2, 200), at(2, 210)), "no gate yet: arrival → validation");
        assert!(t.da.has_source(ColumnSource::Gossip));
        assert!(!t.da.has_source(ColumnSource::Rpc));
    }

    /// The gate opens on the column whose validation crossed the threshold;
    /// later columns are custody traffic.
    #[test]
    fn the_data_component_ends_at_the_gate() {
        let recv = |i| Stage::ColumnRecv { index: i, source: ColumnSource::Gossip };
        let validated = |i| Stage::ColumnValidated { index: i, source: ColumnSource::Gossip };
        let t = trace(&[
            (recv(1), 200),
            (validated(1), 210),
            (recv(2), 220),
            (validated(2), 240),
            (Stage::DaAvailable, 241),
            (recv(3), 300),
            (validated(3), 310),
        ]);
        assert_eq!(t.interval(DA), iv(at(2, 200), at(2, 241)));
        assert_eq!(
            t.interval(cols(ColumnSource::Gossip)),
            iv(at(2, 200), at(2, 310)),
            "the source's columns run past the gate"
        );
    }

    /// Custody completion is the node's duty, not the block's wait: it gets
    /// its own span and never stretches the strip.
    #[test]
    fn custody_span_outlives_the_strip() {
        let recv = |i| Stage::ColumnRecv { index: i, source: ColumnSource::Gossip };
        let t = trace(&[
            (recv(1), 200),
            (received(), 240),
            (Stage::DaAvailable, 300),
            (Stage::StfImported, 320),
            (valid(), 330),
            (recv(2), 900),
            (Stage::CustodyDone, 905),
        ]);
        assert_eq!(t.interval(Span::Da(DaSpan::Custody)), iv(at(2, 200), at(2, 905)));
        assert_eq!(t.interval(DA), iv(at(2, 200), at(2, 300)));
        assert_eq!(t.interval(Span::Strip), iv(at(2, 240), at(2, 330)));

        let pending = trace(&[(recv(1), 200), (Stage::DaAvailable, 300)]);
        assert_eq!(pending.interval(Span::Da(DaSpan::Custody)), None);
    }

    #[test]
    fn deadline_margin_signs() {
        let clock = SlotClock::new(GENESIS_SECS, SLOT_MS);
        let deadline = Nanos::from_millis(4_000);

        let early = trace(&[(received(), 300), (Stage::StfImported, 460), (valid(), 520)]);
        assert_eq!(
            early.deadline_margin(&clock, deadline),
            Some(Margin { delta: Nanos::from_millis(3_480), made_it: true })
        );

        let late = trace(&[(received(), 300), (Stage::StfImported, 4_500), (valid(), 520)]);
        assert_eq!(
            late.deadline_margin(&clock, deadline),
            Some(Margin { delta: Nanos::from_millis(500), made_it: false })
        );

        let pending = trace(&[(received(), 300), (Stage::StfImported, 460)]);
        assert_eq!(pending.deadline_margin(&clock, deadline), None);
    }
}
