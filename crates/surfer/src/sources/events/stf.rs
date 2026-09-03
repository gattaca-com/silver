use silver_common::Nanos;

use super::trace::Interval;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StfSpan {
    /// Start of CL validation → fork-choice import.
    Root,
    /// CL validation → `newPayload` dispatch.
    Validate,
    /// `newPayload` dispatch → post-state committed.
    Apply,
}

#[derive(Default)]
pub struct StateTransition {
    done: Option<Nanos>,
    attestable: Option<Nanos>,
}

impl StateTransition {
    pub(super) fn done(&mut self, ts: Nanos) {
        self.done.get_or_insert(ts);
    }

    pub(super) fn attestable(&mut self, ts: Nanos) {
        self.attestable.get_or_insert(ts);
    }

    pub fn attestable_at(&self) -> Option<Nanos> {
        self.attestable
    }

    pub fn interval(
        &self,
        span: StfSpan,
        validate_from: Option<Nanos>,
        el_sent_at: Option<Nanos>,
    ) -> Option<Interval> {
        let interval = match span {
            StfSpan::Root => {
                let start = validate_from.or(el_sent_at)?;
                let end = self.attestable.or(el_sent_at)?;
                Interval { start, end: end.max(start) }
            }
            StfSpan::Validate => Interval { start: validate_from?, end: el_sent_at? },
            StfSpan::Apply => Interval { start: el_sent_at?, end: self.done.or(self.attestable)? },
        };
        Some(interval)
    }
}
