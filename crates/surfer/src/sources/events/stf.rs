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

/// The consensus component: CL validation, then STF and fork-choice import.
#[derive(Default)]
pub struct StateTransition {
    imported: Option<Nanos>,
}

impl StateTransition {
    /// Duplicates re-announce an imported block; the first import stands.
    pub(super) fn imported(&mut self, ts: Nanos) {
        self.imported.get_or_insert(ts);
    }

    pub fn imported_at(&self) -> Option<Nanos> {
        self.imported
    }

    /// The component starts from the block's common points, which the trace
    /// owns: where validation started and when `newPayload` was dispatched.
    pub fn interval(
        &self,
        span: StfSpan,
        validate_from: Option<Nanos>,
        el_sent: Option<Nanos>,
    ) -> Option<Interval> {
        let interval = match span {
            StfSpan::Root => {
                let start = validate_from.or(el_sent)?;
                let end = self.imported.or(el_sent)?;
                Interval { start, end: end.max(start) }
            }
            StfSpan::Validate => Interval { start: validate_from?, end: el_sent? },
            StfSpan::Apply => Interval { start: el_sent?, end: self.imported? },
        };
        Some(interval)
    }
}
