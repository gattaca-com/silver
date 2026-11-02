use silver_beacon_state_data::Slot;
use silver_common::{
    TRead, block_contents::SignedBlockContents, ssz_hash::HashedBody,
    ssz_view::SignedBeaconBlockView,
};

/// Bodies the API hashed for blocks it publishes, held until the block comes
/// back through gossip. Comparing a body costs a memcmp; hashing it costs
/// about a millisecond.
#[derive(Default)]
pub(super) struct SubmittedBodies(Vec<SubmittedBody>);

struct SubmittedBody {
    slot: Slot,
    submission: TRead,
    hashed: HashedBody,
}

impl SubmittedBodies {
    pub(super) fn insert(&mut self, submission: TRead, hashed: HashedBody) {
        let Some(slot) = signed_block(&submission).map(SignedBeaconBlockView::slot) else {
            return;
        };
        self.0.push(SubmittedBody { slot, submission, hashed });
    }

    /// A match is removed, as a block is imported once.
    pub(super) fn take(&mut self, slot: Slot, body: &[u8]) -> Option<HashedBody> {
        let at = self.0.iter().position(|submitted| {
            submitted.slot == slot &&
                signed_block(&submitted.submission)
                    .is_some_and(|block| SignedBeaconBlockView::body(block) == body)
        })?;
        Some(self.0.swap_remove(at).hashed)
    }

    pub(super) fn prune_before(&mut self, slot: Slot) {
        self.0.retain(|submitted| submitted.slot >= slot);
    }
}

/// A Gloas block is submitted bare, a Fulu block as `SignedBlockContents`.
fn signed_block(submission: &TRead) -> Option<&[u8]> {
    let (bytes, _) = submission.buffer().ok()?;
    if SignedBeaconBlockView::check_size(bytes) {
        Some(bytes)
    } else {
        SignedBlockContents::signed_block(bytes)
    }
}

#[cfg(test)]
mod tests {
    use silver_common::{
        TCache, TCacheId, TCacheProducer, TCacheReader, TCacheTable, TReadMode,
        ssz_hash::BlockFork,
        test_util::{SynthBid, SynthBlock},
    };

    use super::*;

    fn hashed(tag: u8) -> HashedBody {
        HashedBody { root: [tag; 32], fork: BlockFork::Gloas }
    }

    #[test]
    fn submitted_body_is_named_once_for_its_slot_and_bytes() {
        let block = SynthBlock::gloas(7, SynthBid::new(&[])).into_bytes();
        let mut cache = TCache::producer(TCacheId::BoundaryProcessing, 1 << 20);
        let mut reader = TCacheReader::new(TCacheTable::from_iter([cache.cache_ref()]));
        reader.open(TCacheId::BoundaryProcessing, "test", TReadMode::Sliding).unwrap();
        let submission = cache.write_with(block.len(), |out| out.copy_from_slice(&block)).unwrap();
        cache.loop_start();

        let mut bodies = SubmittedBodies::default();
        bodies.insert(reader.acquire(submission), hashed(1));
        let body = SignedBeaconBlockView::body(&block);
        assert_eq!(bodies.take(8, body), None, "another slot is hashed");
        assert_eq!(bodies.take(7, &body[1..]), None, "another body is hashed");
        assert_eq!(bodies.take(7, body), Some(hashed(1)));
        assert_eq!(bodies.take(7, body), None, "a block imports once");

        bodies.insert(reader.acquire(submission), hashed(2));
        bodies.prune_before(8);
        assert_eq!(bodies.take(7, body), None, "a past slot's body is dropped");
    }
}
