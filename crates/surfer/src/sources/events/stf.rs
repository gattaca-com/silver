use silver_common::Nanos;

use super::trace::Interval;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StfSpan {
    /// Start of CL validation → fork-choice import.
    Root,
    /// CL validation → `newPayload` dispatch.
    Validate,
    /// `newPayload` dispatch → fork-choice import.
    Apply,
}

#[derive(Default)]
pub struct StateTransition {
    imported: Option<Nanos>,
}

impl StateTransition {
    pub(super) fn imported(&mut self, ts: Nanos) {
        self.imported.get_or_insert(ts);
    }

    pub fn imported_at(&self) -> Option<Nanos> {
        self.imported
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
                let end = self.imported.or(el_sent_at)?;
                Interval { start, end: end.max(start) }
            }
            StfSpan::Validate => Interval { start: validate_from?, end: el_sent_at? },
            StfSpan::Apply => Interval { start: el_sent_at?, end: self.imported? },
        };
        Some(interval)
    }
}
