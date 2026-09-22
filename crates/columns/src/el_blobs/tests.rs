use flux::{spine::SpineAdapter, tile::Tile};
use silver_common::{
    SilverSpine, TCache, TCacheId, TCacheReader, TCacheTable, TReadMode,
    test_util::{ShmemDir, SynthBlock},
};

use super::*;

struct Endpoint;

impl Tile<SilverSpine> for Endpoint {
    fn loop_body(&mut self, _: &mut SpineAdapter<SilverSpine>) {}
}

struct Rig {
    fetcher: ElBlobFetcher,
    reader: TCacheReader,
    response: TProducer,
    output: TProducer,
    adapter: SpineAdapter<SilverSpine>,
    _spine: Box<SilverSpine>,
    _dir: ShmemDir,
}

impl Rig {
    fn new() -> Self {
        let response = TCache::producer(TCacheId::IncomingEngineResp, 1 << 18);
        let mut reader = TCacheReader::new(TCacheTable::from_iter([response.cache_ref()]));
        reader.open(TCacheId::IncomingEngineResp, "", TReadMode::Sliding).unwrap();
        let dir = ShmemDir::new().unwrap();
        let mut spine = Box::new(SilverSpine::new_with_base_dir(dir.path(), None));
        let mut adapter = SpineAdapter::connect_tile(&Endpoint, &mut spine);
        adapter.consume(|_: EngineReq, _| {});
        Self {
            fetcher: ElBlobFetcher::new(Duration::from_secs(60)),
            reader,
            response,
            output: TCache::producer(TCacheId::IncomingGossip, 1 << 16),
            adapter,
            _spine: spine,
            _dir: dir,
        }
    }

    fn request(&mut self, root: BlockRoot) {
        self.fetcher.try_fetch(
            CommitmentContext { block_root: root, slot: 7, format: ForkName::Gloas, blob_count: 1 },
            GossipDomain::new([0; 4], ForkName::Gloas),
            ContextData::Gloas { commitments: &[0; 48] },
            1,
            &self.adapter.producers,
        );
    }

    fn response(&mut self, root: BlockRoot, slot: u64) {
        let mut write = self.response.reserve(4, true).unwrap();
        write.write_all(&0u32.to_le_bytes()).unwrap();
        self.fetcher.handle_response(
            EngineGetBlobsResp {
                block_root: root,
                slot,
                ok: true,
                blobs_present: 0,
                data: write.read(),
            },
            &mut self.reader,
        );
    }

    fn requests(&mut self) -> usize {
        let mut count = 0;
        self.adapter.consume(|_: EngineReq, _| count += 1);
        count
    }
}

#[test]
fn wrong_slot_cannot_consume_the_request_and_completion_remains_deduplicated() {
    let mut rig = Rig::new();
    rig.request([1; 32]);
    assert_eq!(rig.requests(), 1);
    rig.response([1; 32], 6);
    assert!(rig.fetcher.responses.is_empty());
    assert!(rig.fetcher.pending.contains(&[1; 32]));
    rig.response([1; 32], 7);
    assert_eq!(rig.fetcher.responses.len(), 1);
    assert!(!rig.fetcher.pending.contains(&[1; 32]));
    rig.response([1; 32], 7);
    rig.request([1; 32]);
    assert_eq!(rig.requests(), 0);
    assert_eq!(rig.fetcher.responses.len(), 1);
    rig.fetcher.reject(&[1; 32]);
    assert!(rig.fetcher.responses.is_empty());
}

#[test]
fn response_pins_are_bounded_and_expired_responses_are_released() {
    let mut rig = Rig::new();
    for index in 0..=MAX_RESPONSES {
        let root = [index as u8; 32];
        rig.request(root);
        rig.response(root, 7);
    }
    assert_eq!(rig.fetcher.responses.len(), MAX_RESPONSES);
    assert!(rig.fetcher.pending.is_empty());
    for pending in &mut rig.fetcher.responses {
        pending.fetch.deadline = Instant::now();
    }
    rig.fetcher.process_responses(
        None,
        &mut ColumnTracker::new(1, Duration::from_secs(60)),
        &SyncStatus::default(),
        &mut rig.output,
        &mut rig.adapter.producers,
    );
    rig.reader.free();
    assert!(rig.fetcher.responses.is_empty());
    rig.request([99; 32]);
    let Entry::Occupied(mut entry) = rig.fetcher.pending.entry([99; 32]) else { unreachable!() };
    entry.get_mut().deadline = Instant::now();
    rig.response([99; 32], 7);
    assert!(rig.fetcher.responses.is_empty());
    rig.requests();
    rig.request([99; 32]);
    assert_eq!(rig.requests(), 0, "a timeout must not restart the lookup");
}

#[test]
fn unvalidated_candidates_expire_before_request_deduplication() {
    let mut rig = Rig::new();
    rig.request([1; 32]);
    let block = SynthBlock::fulu(7, &[0; 48]);
    rig.fetcher.cache_fulu_block(block.bytes(), [2; 32], GossipDomain::new([0; 4], ForkName::Fulu));
    assert_eq!(rig.fetcher.pending.len(), 2);
    let now = Instant::now();
    for rotation in 1..=4 {
        rig.fetcher.rotate(now + Duration::from_millis(501 * rotation));
    }
    assert!(rig.fetcher.pending.is_empty());
    assert!(rig.fetcher.attempted.contains(&[1; 32]));
    assert!(!rig.fetcher.attempted.contains(&[2; 32]));
}

#[test]
fn forced_tail_advance_invalidates_a_queued_response_before_its_bytes_are_reused() {
    let mut rig = Rig::new();
    rig.request([1; 32]);
    rig.response([1; 32], 7);
    let mut padding = rig.response.reserve(240 * 1024, false).unwrap();
    padding.buffer().unwrap().fill(0);
    padding.flush().unwrap();
    rig.request([2; 32]);
    rig.response([2; 32], 7);
    let old = &rig.fetcher.responses[0].read;
    assert!(old.buffer().is_ok(), "the sequence alone cannot detect a released pin");
    assert!(old.with_offset(0).is_none(), "re-acquisition also checks the consumer tail");
    rig.fetcher.process_responses(
        None,
        &mut ColumnTracker::new(1, Duration::from_secs(60)),
        &SyncStatus::default(),
        &mut rig.output,
        &mut rig.adapter.producers,
    );
    assert!(rig.fetcher.responses.is_empty());
}
