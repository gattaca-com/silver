use silver_common::{Nanos, PayloadValidationStatus};

use super::trace::Interval;

/// The execution component: `newPayload` dispatch → the EL's verdict.
#[derive(Default)]
pub struct Execution {
    verdict: Option<(PayloadValidationStatus, Nanos)>,
}

impl Execution {
    pub(super) fn verdict_received(&mut self, status: PayloadValidationStatus, ts: Nanos) {
        self.verdict = Some((status, ts));
    }

    pub fn status(&self) -> Option<PayloadValidationStatus> {
        self.verdict.map(|(status, _)| status)
    }

    pub fn verdict_at(&self) -> Option<Nanos> {
        self.verdict.map(|(_, ts)| ts)
    }

    /// When the EL said `Valid`; `None` while pending or not `Valid`, since an
    /// optimistic head must not be attested to.
    pub fn valid_at(&self) -> Option<Nanos> {
        let (status, ts) = self.verdict?;
        (status == PayloadValidationStatus::Valid).then_some(ts)
    }

    pub fn interval(&self, el_sent: Option<Nanos>) -> Option<Interval> {
        let (_, verdict_ts) = self.verdict?;
        Some(Interval { start: el_sent.unwrap_or(verdict_ts), end: verdict_ts })
    }
}
