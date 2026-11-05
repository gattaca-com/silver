use silver_common::{
    BlockSource, Nanos,
    ticker::{BASIS_POINTS, PAYLOAD_ATTESTATION_DUE_BPS, attestation_due_bps},
};
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

/// Distance from a deadline: the attestation deadline at attestable, or the
/// payload attestation deadline at a Gloas payload's readiness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Margin {
    pub delta: Nanos,
    pub made_it: bool,
}

/// One span of the block's dependency graph: the whole strip, then the three
/// components that join at attestable. From Gloas the payload travels in its
/// own envelope, so its data and `el` are no longer on the block's path: they
/// join under `Payload`, judged against the payload attestation deadline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Span {
    Strip,
    Da(DaSpan),
    Stf(StfSpan),
    El,
    Payload,
}

/// The block's common points — arrival and `newPayload` dispatch, which both
/// `stf` and `el` start from — plus the three components, joined at attestable.
pub struct BlockTrace {
    pub slot: u64,
    pub block_root: [u8; 32],
    pub gloas: bool,
    /// Where the block itself arrived from; `None` until its first
    /// `Received`, which a reader attaching mid-slot can miss.
    pub source: Option<BlockSource>,
    received_at: Option<Nanos>,
    el_sent_at: Option<Nanos>,
    pub da: DataAvailability,
    pub stf: StateTransition,
    pub el: Execution,
}

impl BlockTrace {
    pub fn new(slot: u64, block_root: [u8; 32], gloas: bool) -> Self {
        Self {
            slot,
            block_root,
            gloas,
            source: None,
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
            Stage::Received { source } => {
                if self.received_at.is_none() {
                    self.received_at = Some(ts);
                    self.source = Some(source);
                }
            }
            Stage::ElSent { .. } => self.el_sent_at = Some(ts),
            Stage::StfDone => self.stf.done(ts),
            Stage::Attestable => self.stf.attestable(ts),
            Stage::ElVerdict { verdict } => self.el.verdict_received(verdict, ts),
            Stage::ColumnRecv { index, origin } => self.da.column_received(index, origin, ts),
            Stage::ColumnValidated { index, .. } => self.da.column_validated(index, ts),
            Stage::DaAvailable => self.da.gate_opened(ts),
            Stage::CustodyDone => self.da.custody_completed(ts),
        }
    }

    /// Before Gloas the pane's attestable is stricter than the node's stage:
    /// the node's `attestable`, the EL verdict `Valid`, and the gate open
    /// where it was seen; `None` while the verdict is pending or not `Valid`.
    /// A Gloas block is attestable at import: its payload is judged apart.
    pub fn attestable_at(&self) -> Option<Nanos> {
        let attestable = self.stf.attestable_at()?;
        if self.gloas {
            return Some(attestable);
        }
        let valid = self.el.valid_at()?;
        Some(attestable.max(valid).max(self.da.available().unwrap_or(attestable)))
    }

    /// What a PTC member attests to: the payload `Valid` and its data
    /// available.
    pub fn payload_ready_at(&self) -> Option<Nanos> {
        debug_assert!(self.gloas);
        let valid = self.el.valid_at()?;
        Some(valid.max(self.da.available()?))
    }

    fn payload_events(&self) -> [Option<Nanos>; 3] {
        [self.el.verdict_at(), self.el_sent_at, self.da.available()]
    }

    /// The last event on the block's own path — column custody traffic
    /// excluded, so a strip without a verdict ends at attestable, not at the
    /// custody tail.
    fn last_event(&self) -> Option<Nanos> {
        let payload = if self.gloas { [None; 3] } else { self.payload_events() };
        payload.into_iter().chain([self.stf.attestable_at()]).flatten().max()
    }

    /// Where CL validation starts: the DA gate when it held the block (the
    /// gate precedes dispatch), else arrival. No gate holds a Gloas block.
    fn validate_from(&self) -> Option<Nanos> {
        self.received_at.map(|at| match self.da.available() {
            Some(gate) if !self.gloas && self.el_sent_at.is_some_and(|sent| gate < sent) => {
                at.max(gate)
            }
            _ => at,
        })
    }

    /// `newPayload` dispatch as the block's own stage; a Gloas dispatch is
    /// its envelope's.
    fn block_el_sent_at(&self) -> Option<Nanos> {
        self.el_sent_at.filter(|_| !self.gloas)
    }

    /// `None` while the span has no events.
    pub fn interval(&self, span: Span) -> Option<Interval> {
        match span {
            Span::Strip => {
                let early_columns = self.da.first_column_at().filter(|_| !self.gloas);
                let start = self.received_at.or(early_columns)?;
                let end = self.attestable_at().or_else(|| self.last_event()).unwrap_or(start);
                Some(Interval { start, end: end.max(start) })
            }
            Span::Da(span) => self.da.interval(span),
            Span::Stf(span) => {
                self.stf.interval(span, self.validate_from(), self.block_el_sent_at())
            }
            Span::El => self.el.interval(self.el_sent_at),
            Span::Payload => {
                let start = [self.el_sent_at, self.da.first_column_at(), self.da.available()]
                    .into_iter()
                    .flatten()
                    .min()?;
                let end = self
                    .payload_ready_at()
                    .or_else(|| self.payload_events().into_iter().flatten().max())
                    .unwrap_or(start);
                Some(Interval { start, end: end.max(start) })
            }
        }
    }

    pub fn attestation_deadline(&self, clock: &SlotClock) -> Nanos {
        clock.slot_duration() * attestation_due_bps(self.gloas) / BASIS_POINTS
    }

    pub fn offset_in_slot(&self, clock: &SlotClock, ts: Nanos) -> Option<Nanos> {
        clock.offset_in_slot(ts, self.slot)
    }

    /// The strip against the attestation deadline, a Gloas payload against
    /// the payload attestation deadline; `None` for other spans and before
    /// the span's readiness.
    pub fn deadline_margin(&self, clock: &SlotClock, span: Span) -> Option<Margin> {
        let (ready, deadline) = match span {
            Span::Strip => (self.attestable_at()?, self.attestation_deadline(clock)),
            Span::Payload => (
                self.payload_ready_at()?,
                clock.slot_duration() * PAYLOAD_ATTESTATION_DUE_BPS / BASIS_POINTS,
            ),
            _ => return None,
        };
        let at = self.offset_in_slot(clock, ready)?;
        Some(if at <= deadline {
            Margin { delta: deadline - at, made_it: true }
        } else {
            Margin { delta: at - deadline, made_it: false }
        })
    }
}

#[cfg(test)]
pub mod tests {
    use silver_common::{ColumnOrigin, PayloadValidationStatus};

    use super::*;

    pub const GENESIS_SECS: u64 = 1_000;
    pub const SLOT_MS: u64 = 12_000;

    pub const DA: Span = Span::Da(DaSpan::Root);
    pub const STF: Span = Span::Stf(StfSpan::Root);
    pub const VALIDATE: Span = Span::Stf(StfSpan::Validate);
    pub const APPLY: Span = Span::Stf(StfSpan::Apply);
    pub const DA_WAIT: Span = Span::Stf(StfSpan::DaWait);

    pub fn cols(origin: ColumnOrigin) -> Span {
        Span::Da(DaSpan::Cols(origin))
    }

    pub fn at(slot: u64, ms_into_slot: u64) -> Nanos {
        Nanos::from_secs(GENESIS_SECS) + Nanos::from_millis(slot * SLOT_MS + ms_into_slot)
    }

    pub fn event(stage: Stage, ts: Nanos, slot: Option<u64>) -> StageEvent {
        StageEvent { stage, ts, block_root: [1u8; 32], slot }
    }

    pub fn received() -> Stage {
        received_from(BlockSource::Gossip)
    }

    pub fn received_from(source: BlockSource) -> Stage {
        Stage::Received { source }
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
        fork_trace(stages, false)
    }

    pub fn gloas_trace(stages: &[(Stage, u64)]) -> BlockTrace {
        fork_trace(stages, true)
    }

    fn fork_trace(stages: &[(Stage, u64)], gloas: bool) -> BlockTrace {
        let mut trace = BlockTrace::new(2, [1u8; 32], gloas);
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
            (Stage::Attestable, 460),
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
        assert_eq!(t.interval(cols(ColumnOrigin::Gossip)), None, "no sidecars observed");
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
            (Stage::Attestable, 422),
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
        let imported_only = trace(&[(received(), 300), (el_sent(), 310), (Stage::Attestable, 460)]);
        assert_eq!(imported_only.attestable_at(), None);
        assert_eq!(imported_only.interval(Span::Strip), iv(at(2, 300), at(2, 460)));

        let syncing = Stage::ElVerdict { verdict: PayloadValidationStatus::Syncing };
        let optimistic = trace(&[(received(), 300), (Stage::Attestable, 460), (syncing, 330)]);
        assert_eq!(optimistic.attestable_at(), None, "an optimistic head is not attestable");

        let verdict_first = trace(&[(received(), 300), (valid(), 330), (Stage::Attestable, 460)]);
        assert_eq!(verdict_first.attestable_at(), Some(at(2, 460)), "the later component decides");

        let late_gate = trace(&[
            (received(), 300),
            (valid(), 330),
            (Stage::Attestable, 460),
            (Stage::DaAvailable, 470),
        ]);
        assert_eq!(late_gate.attestable_at(), Some(at(2, 470)), "DA joins the max when known");
    }

    /// A block parked on its columns commits its post-state, then waits; the
    /// wait is its own span, and an unparked import has none.
    #[test]
    fn parked_block_waits_between_apply_and_import() {
        let parked = trace(&[
            (received(), 300),
            (el_sent(), 301),
            (Stage::StfDone, 308),
            (Stage::DaAvailable, 336),
            (Stage::Attestable, 337),
        ]);
        assert_eq!(parked.interval(APPLY), iv(at(2, 301), at(2, 308)), "dispatch → staged");
        assert_eq!(parked.interval(DA_WAIT), iv(at(2, 308), at(2, 337)), "staged → import");
        assert_eq!(parked.interval(STF), iv(at(2, 300), at(2, 337)));
        assert!(parked.stf.parked());

        let waiting = trace(&[(received(), 300), (el_sent(), 301), (Stage::StfDone, 308)]);
        assert!(waiting.stf.parked(), "still parked");
        assert_eq!(waiting.interval(DA_WAIT), None, "no import yet");

        let unparked = trace(&[
            (received(), 300),
            (el_sent(), 301),
            (Stage::StfDone, 308),
            (Stage::Attestable, 308),
        ]);
        assert!(!unparked.stf.parked());
        assert_eq!(unparked.interval(DA_WAIT), iv(at(2, 308), at(2, 308)));
    }

    /// Duplicates re-announce an imported block; the first import is the apply.
    #[test]
    fn repeat_imports_keep_the_first() {
        let t = trace(&[
            (received(), 300),
            (el_sent(), 320),
            (Stage::Attestable, 460),
            (Stage::Attestable, 900),
        ]);
        assert_eq!(t.interval(APPLY), iv(at(2, 320), at(2, 460)));
    }

    /// Duplicate `Persist` events (an already-held column re-arriving) fold
    /// into one column with the first timestamps.
    #[test]
    fn duplicate_column_events_fold_into_one_column() {
        let recv = Stage::ColumnRecv { index: 48, origin: ColumnOrigin::Gossip };
        let validated = Stage::ColumnValidated { index: 48, origin: ColumnOrigin::Gossip };
        let t = trace(&[(recv, 200), (validated, 210), (recv, 500), (validated, 510)]);

        assert_eq!(t.da.columns.len(), 1);
        assert_eq!(t.da.columns[0].interval(), Interval { start: at(2, 200), end: at(2, 210) });
        assert_eq!(t.interval(cols(ColumnOrigin::Gossip)), iv(at(2, 200), at(2, 210)));
        assert_eq!(t.interval(cols(ColumnOrigin::El)), None, "no EL-built sidecars");
        assert_eq!(t.interval(DA), iv(at(2, 200), at(2, 210)), "no gate yet: arrival → validation");
        assert!(t.da.has_origin(ColumnOrigin::Gossip));
        assert!(!t.da.has_origin(ColumnOrigin::Rpc));
    }

    /// The gate opens on the column whose validation crossed the threshold;
    /// later columns are custody traffic.
    #[test]
    fn the_data_component_ends_at_the_gate() {
        let recv = |i| Stage::ColumnRecv { index: i, origin: ColumnOrigin::Gossip };
        let validated = |i| Stage::ColumnValidated { index: i, origin: ColumnOrigin::Gossip };
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
            t.interval(cols(ColumnOrigin::Gossip)),
            iv(at(2, 200), at(2, 310)),
            "the source's columns run past the gate"
        );
    }

    /// Custody completion is the node's duty, not the block's wait: it gets
    /// its own span and never stretches the strip.
    #[test]
    fn custody_span_outlives_the_strip() {
        let recv = |i| Stage::ColumnRecv { index: i, origin: ColumnOrigin::Gossip };
        let t = trace(&[
            (recv(1), 200),
            (received(), 240),
            (Stage::DaAvailable, 300),
            (Stage::Attestable, 320),
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

        let early = trace(&[(received(), 300), (Stage::Attestable, 460), (valid(), 520)]);
        assert_eq!(
            early.deadline_margin(&clock, Span::Strip),
            Some(Margin { delta: Nanos(3_479_600_000), made_it: true }),
            "3333 bps of 12 s"
        );

        let late = trace(&[(received(), 300), (Stage::Attestable, 4_500), (valid(), 520)]);
        assert_eq!(
            late.deadline_margin(&clock, Span::Strip),
            Some(Margin { delta: Nanos(500_400_000), made_it: false })
        );

        let pending = trace(&[(received(), 300), (Stage::Attestable, 460)]);
        assert_eq!(pending.deadline_margin(&clock, Span::Strip), None);
        assert_eq!(early.deadline_margin(&clock, STF), None, "only the strip has a deadline");
    }

    /// Slot 605404 on devnet-8: imported 4 ms after arrival, while its
    /// envelope's columns and `newPayload` ran on for hundreds of ms.
    fn gloas_block() -> BlockTrace {
        let recv = Stage::ColumnRecv { index: 5, origin: ColumnOrigin::Gossip };
        let validated = Stage::ColumnValidated { index: 5, origin: ColumnOrigin::Gossip };
        gloas_trace(&[
            (received(), 306),
            (Stage::StfDone, 310),
            (Stage::Attestable, 310),
            (recv, 420),
            (validated, 470),
            (Stage::DaAvailable, 472),
            (el_sent(), 636),
            (valid(), 730),
        ])
    }

    #[test]
    fn gloas_block_is_attestable_at_import() {
        let t = gloas_block();
        assert_eq!(t.attestable_at(), Some(at(2, 310)));
        assert_eq!(t.interval(Span::Strip), iv(at(2, 306), at(2, 310)));
        assert_eq!(t.interval(STF), iv(at(2, 306), at(2, 310)), "no gate holds the block");
        assert_eq!(t.interval(VALIDATE), None, "the dispatch is the envelope's");
        assert_eq!(t.interval(APPLY), None);

        let recv = Stage::ColumnRecv { index: 5, origin: ColumnOrigin::Gossip };
        let missed_arrival = gloas_trace(&[(recv, 420), (Stage::Attestable, 430)]);
        assert_eq!(missed_arrival.interval(Span::Strip), None, "the columns are the payload's");

        let unrevealed = gloas_trace(&[(received(), 306), (Stage::Attestable, 310)]);
        assert_eq!(unrevealed.attestable_at(), Some(at(2, 310)), "no payload needed");
        assert_eq!(unrevealed.interval(Span::Payload), None);
    }

    #[test]
    fn gloas_payload_is_ready_once_valid_and_available() {
        let t = gloas_block();
        assert_eq!(t.payload_ready_at(), Some(at(2, 730)));
        assert_eq!(t.interval(Span::Payload), iv(at(2, 420), at(2, 730)), "first column → valid");
        assert_eq!(t.interval(Span::El), iv(at(2, 636), at(2, 730)));

        let blobless = gloas_trace(&[
            (received(), 322),
            (Stage::Attestable, 326),
            (Stage::DaAvailable, 326),
            (el_sent(), 521),
            (valid(), 617),
        ]);
        assert_eq!(blobless.interval(Span::Payload), iv(at(2, 326), at(2, 617)));

        let syncing = Stage::ElVerdict { verdict: PayloadValidationStatus::Syncing };
        let optimistic = gloas_trace(&[
            (received(), 300),
            (Stage::DaAvailable, 300),
            (el_sent(), 400),
            (syncing, 420),
        ]);
        assert_eq!(optimistic.payload_ready_at(), None);
        assert_eq!(optimistic.interval(Span::Payload), iv(at(2, 300), at(2, 420)));
    }

    #[test]
    fn gloas_deadlines() {
        let clock = SlotClock::new(GENESIS_SECS, SLOT_MS);
        let t = gloas_block();
        assert_eq!(t.attestation_deadline(&clock), Nanos::from_millis(3_000));
        assert_eq!(
            t.deadline_margin(&clock, Span::Strip),
            Some(Margin { delta: Nanos::from_millis(2_690), made_it: true })
        );
        assert_eq!(
            t.deadline_margin(&clock, Span::Payload),
            Some(Margin { delta: Nanos::from_millis(8_270), made_it: true })
        );
        assert_eq!(gloas_block().deadline_margin(&clock, Span::El), None);
        assert_eq!(trace(&[]).attestation_deadline(&clock), Nanos(3_999_600_000), "pre-Gloas");
    }
}
