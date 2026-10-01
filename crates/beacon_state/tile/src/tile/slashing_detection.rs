use silver_common::BlockSource;

use super::{BeaconStateTile, Feedback, block::ParsedBlock};
use crate::error::PrecheckError;

impl BeaconStateTile {
    pub(super) fn admit_block(
        &mut self,
        data: &[u8],
        source: BlockSource,
    ) -> Result<ParsedBlock, Feedback> {
        self.parse_and_verify_block(data).map_err(|error| match error {
            PrecheckError::BlockKnown { .. } | PrecheckError::AwaitingData { .. }
                if source == BlockSource::LocalGossip =>
            {
                Feedback::AlreadySeen
            }
            error => error.feedback(),
        })
    }
}
