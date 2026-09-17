use silver_beacon_state_data::B256;
use silver_common::PayloadValidationStatus;

use crate::events::HeadEvent;

/// The EL's last final verdict, applied to the head the tile announces. The
/// verdict may arrive on either side of the tile's Status, so both are kept.
#[derive(Default)]
pub(crate) struct HeadVerdict {
    announced: Option<HeadEvent>,
    verdict: Option<(B256, PayloadValidationStatus)>,
}

impl HeadVerdict {
    pub(crate) fn verdict(&self, block_root: &B256) -> Option<PayloadValidationStatus> {
        self.verdict.filter(|(root, _)| root == block_root).map(|(_, status)| status)
    }

    /// The legacy `head` to publish: once per root, and only EL-valid.
    pub(crate) fn on_head(&mut self, head: HeadEvent) -> Option<HeadEvent> {
        let already = self
            .announced
            .is_some_and(|h| h.block_root == head.block_root && !h.execution_optimistic);
        // TODO(xatu): remove optimistic flag check when Xatu will add filtering by
        // optimistic flag + allow publish 2 time for optimistic and not
        self.announced = Some(head);
        (!head.execution_optimistic && !already).then_some(head)
    }

    /// The legacy `head` to publish, when a Valid clears the announced
    /// optimistic head. Syncing and Accepted decide nothing and are not kept.
    pub(crate) fn on_verdict(
        &mut self,
        block_root: B256,
        status: PayloadValidationStatus,
    ) -> Option<HeadEvent> {
        if !matches!(status, PayloadValidationStatus::Valid | PayloadValidationStatus::Invalid) {
            return None;
        }
        self.verdict = Some((block_root, status));
        let head = self.announced.filter(|h| {
            status == PayloadValidationStatus::Valid &&
                h.block_root == block_root &&
                h.execution_optimistic
        })?;
        self.on_head(HeadEvent { execution_optimistic: false, ..head })
    }
}
