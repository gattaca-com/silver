use silver_common::{Nanos, PayloadValidationStatus};

use super::trace::Interval;

#[derive(Clone, Copy)]
struct Verdict {
    status: PayloadValidationStatus,
    at: Nanos,
}

#[derive(Default)]
pub struct Execution {
    verdict: Option<Verdict>,
}

impl Execution {
    pub(super) fn verdict_received(&mut self, status: PayloadValidationStatus, ts: Nanos) {
        self.verdict = Some(Verdict { status, at: ts });
    }

    pub fn status(&self) -> Option<PayloadValidationStatus> {
        self.verdict.map(|v| v.status)
    }

    pub fn verdict_at(&self) -> Option<Nanos> {
        self.verdict.map(|v| v.at)
    }

    /// When the EL said `Valid`; `None` while pending or not `Valid`, since an
    /// optimistic head must not be attested to.
    pub fn valid_at(&self) -> Option<Nanos> {
        let verdict = self.verdict?;
        (verdict.status == PayloadValidationStatus::Valid).then_some(verdict.at)
    }

    pub fn interval(&self, el_sent_at: Option<Nanos>) -> Option<Interval> {
        let verdict = self.verdict?;
        Some(Interval { start: el_sent_at.unwrap_or(verdict.at), end: verdict.at })
    }
}
