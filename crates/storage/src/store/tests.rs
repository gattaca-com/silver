// NOTE: tests that stage reads via `add_block`/`add_data_column` must drain
// the write queue with `file_io` before scope exit. `AcquiredRead`s parked
// in `write_queue` hold raw `*const` pointers into their consumer; if the
// consumer drops first, releasing them on drop is use-after-free.
use std::{
    io::{ErrorKind, Read, Write},
    thread,
    time::{Duration, Instant},
};

use silver_common::{Prefill, SyncNeed, SyncUpdate};

use super::{column_path, envelope_path, slot_dir};

fn index_records(dir: &std::path::Path) -> Vec<super::block_index::Record> {
    let mut records = Vec::new();
    super::block_index::load_dir(dir, &mut |r| records.push(r)).unwrap();
    records
}

fn load_fulu(store_dir: String) -> super::Store {
    load_fulu_custodying(store_dir, 0)
}

fn load_fulu_custodying(store_dir: String, custody: u128) -> super::Store {
    super::Store::load(store_dir, super::test_spec(u64::MAX), custody).unwrap()
}

fn load_gloas(store_dir: String) -> super::Store {
    super::Store::load(store_dir, super::test_spec(0), 0).unwrap()
}

use silver_common::column_util;

use crate::tile::IoEvent;

#[test]
fn concurrent_read_write() {
    let path = format!("/tmp/silver_storage_rw_{}.txt", rand::random::<u32>());
    let _ = std::fs::remove_file(&path);
    let mut file = super::io::open_file_write(&path, false).unwrap();

    let mut handles = vec![];
    for i in 0..10 {
        let path = path.clone();
        let h = thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(1));
            let start = Instant::now();
            let mut file = super::io::open_file_read(&path).unwrap();
            let mut data = vec![0u8; 128 * 1024];
            let mut read = 0;
            for _ in 0..400 {
                match file.read(&mut data) {
                    Ok(wrote) if wrote == data.len() => {
                        read += wrote;
                    }
                    Ok(n) => {
                        read += n;
                        //println!("read {n }/{}", data.len());
                    }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {
                        println!("would block!");
                    }
                    Err(e) => panic!("{e:?}"),
                }
            }
            println!("{i} read {read} in {:?}", start.elapsed());
        });
        handles.push(h);
    }
    let data = vec![0u8; 128 * 1024];
    for _ in 0..400 {
        match file.write(&data) {
            Ok(wrote) if wrote == data.len() => {}
            Ok(n) => {
                println!("wrote {n }/{}", data.len());
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                println!("would block!");
            }
            Err(e) => panic!("{e:?}"),
        }
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn fork_tree_persist_serve_promote() {
    use silver_common::{
        P2pSend, P2pStreamId, RpcOutbound, RpcRequest, RpcRequestInbound, RpcResponse,
        RpcResponseOutbound, StreamProtocol, TCache, TCacheProducer,
    };

    let store_path = format!("/tmp/test_store_fork_{}", rand::random::<u32>());
    let _ = std::fs::remove_dir_all(&store_path);
    let mut store = load_fulu(store_path.clone());

    // Two competing blocks at slot 42 sharing parent CC: A canonical, B fork.
    let parent_root = [0xCC; 32];
    let root_a = [0xAA; 32];
    let root_b = [0xBB; 32];
    let slot = 42u64;
    let bytes_a = [0xA7u8; 100];
    let bytes_b = [0xB7u8; 80];

    // Stage both payloads in a tcache and acquire reads to hand to the store.
    let mut blocks = TCache::producer("fork_blocks", 1024 * 1024);
    let mut res_a = blocks.reserve(bytes_a.len(), true).unwrap();
    res_a.write_all(&bytes_a).unwrap();
    res_a.flush().unwrap();
    let ssz_a = res_a.read();
    let mut res_b = blocks.reserve(bytes_b.len(), true).unwrap();
    res_b.write_all(&bytes_b).unwrap();
    res_b.flush().unwrap();
    let ssz_b = res_b.read();
    let mut blocks_consumer = blocks.cache_ref().random_access("fork_blocks_cons", true).unwrap();
    let read_a = blocks_consumer.acquire(ssz_a);
    let read_b = blocks_consumer.acquire(ssz_b);

    store.add_block(root_a, read_a, slot, parent_root);
    store.add_block(root_b, read_b, slot, parent_root);
    assert!(store.unfinalized.contains(&root_a));
    assert!(store.unfinalized.contains(&root_b));

    // Head selects A; not yet finalized.
    store.update_head(slot, root_a, 0, [0u8; 32]);

    let fork_digest = [1, 2, 3, 4];
    let producer_cache = TCache::multi_producer("fork_rpc_in", 1024 * 1024);
    let mut producer = producer_cache.clone();
    store.file_io(|_| fork_digest, &mut producer, &mut |_| {}).unwrap();

    let path_a = store.unfinalized_dir(super::Payload::Block).join(super::io::unfinalized_name(
        slot,
        &parent_root,
        &root_a,
    ));
    let path_b = store.unfinalized_dir(super::Payload::Block).join(super::io::unfinalized_name(
        slot,
        &parent_root,
        &root_b,
    ));
    assert!(path_a.exists());
    assert!(path_b.exists());

    // Asserts a response is a BeaconBlock carrying `expected` bytes.
    let mut read_consumer = producer_cache.cache_ref().random_access("fork_read", true).unwrap();
    let mut assert_block = |resp: &P2pSend, expected: &[u8]| {
        let P2pSend::Rpc(RpcOutbound::Response(RpcResponseOutbound {
            response: RpcResponse::BeaconBlock { ssz, .. },
            ..
        })) = resp
        else {
            panic!("expected BeaconBlock response, got {resp:?}");
        };
        let acquired = read_consumer.acquire(*ssz);
        let (buf, _) = acquired.buffer().unwrap();
        assert_eq!(buf, expected);
    };

    // BeaconBlocksByRange [42,43) serves the canonical block A only.
    let mut range = [0u8; 24];
    range[0..8].copy_from_slice(&slot.to_le_bytes()); // start_slot
    range[8..16].copy_from_slice(&1u64.to_le_bytes()); // count
    range[16..24].copy_from_slice(&1u64.to_le_bytes()); // step
    let sid = P2pStreamId::new(1234, 1, StreamProtocol::BeaconBlocksByRange, false);

    // BlockByRoot request buffer (one root) staged in a tcache.
    let mut req_producer = TCache::producer("fork_req", 1024 * 1024);
    let mut byroot_res = req_producer.reserve(32, true).unwrap();
    byroot_res.write_all(&root_b).unwrap();
    byroot_res.flush().unwrap();
    let byroot_ssz = byroot_res.read();
    let mut req_consumer = req_producer.cache_ref().random_access("fork_req_cons", true).unwrap();

    store.rpc_request(&mut req_consumer, RpcRequestInbound {
        stream_id: sid,
        request: RpcRequest::BlocksByRange(range),
    });
    let mut responses = vec![];
    store
        .file_io(|_| fork_digest, &mut producer, &mut |s| match s {
            IoEvent::P2pSend(s) => responses.push(s),
            _ => {}
        })
        .unwrap();
    assert_eq!(responses.len(), 2); // canonical block A + Complete
    assert_block(&responses[0], &bytes_a);
    assert!(matches!(
        &responses[1],
        P2pSend::Rpc(RpcOutbound::Response(RpcResponseOutbound {
            response: RpcResponse::Complete,
            ..
        }))
    ));

    // BlockByRoot serves the non-canonical fork B regardless of canonicity.
    store.rpc_request(&mut req_consumer, RpcRequestInbound {
        stream_id: sid,
        request: RpcRequest::BlockByRoot(byroot_ssz),
    });
    let mut byroot = vec![];
    store
        .file_io(|_| fork_digest, &mut producer, &mut |s| match s {
            IoEvent::P2pSend(s) => byroot.push(s),
            _ => {}
        })
        .unwrap();
    assert_eq!(byroot.len(), 2);
    assert_block(&byroot[0], &bytes_b);

    // Finalize at slot 42 on A: promote A, prune the orphan B.
    store.update_head(slot, root_a, slot, root_a);
    assert_eq!(store.finalized.slot_of(&root_a), Some(slot));
    assert!(!store.unfinalized.contains(&root_a));
    assert!(!store.unfinalized.contains(&root_b));

    store.file_io(|_| fork_digest, &mut producer, &mut |_| {}).unwrap();
    assert_eq!(
        index_records(&store.finalized_slot_dir(super::Payload::Block, slot)),
        vec![super::block_index::Record { block_root: root_a, slot }],
        "only the promoted block is indexed"
    );
    let flat_a =
        store.finalized_slot_dir(super::Payload::Block, slot).join(format!("{slot}_block.ssz"));
    assert!(flat_a.exists());
    assert!(!path_a.exists()); // moved to flat store
    assert!(!path_b.exists()); // orphan pruned

    // Range still serves A, now from the flat finalized store.
    store.rpc_request(&mut req_consumer, RpcRequestInbound {
        stream_id: sid,
        request: RpcRequest::BlocksByRange(range),
    });
    let mut after = vec![];
    store
        .file_io(|_| fork_digest, &mut producer, &mut |s| match s {
            IoEvent::P2pSend(s) => after.push(s),
            _ => {}
        })
        .unwrap();
    assert_eq!(after.len(), 2);
    assert_block(&after[0], &bytes_a);

    // Reload: finalized index persisted, unfinalized tree empty.
    let reloaded = load_fulu(store_path.clone());
    assert_eq!(reloaded.finalized.slot_of(&root_a), Some(slot));
    assert!(reloaded.unfinalized.is_empty());

    let _ = std::fs::remove_dir_all(&store_path);
}

// Envelopes: persist unfinalized, promote the canonical one to the flat
// store on finalization, prune the orphan, and rebuild the index on reload.
#[test]
fn envelope_persist_promote_prune() {
    use silver_common::{TCache, TCacheProducer};

    let store_path = format!("/tmp/test_store_env_{}", rand::random::<u32>());
    let _ = std::fs::remove_dir_all(&store_path);
    let mut store = load_gloas(store_path.clone());

    // Canonical block A + fork block B at slot 42, shared parent CC; each
    // gets an envelope.
    let parent_root = [0xCC; 32];
    let root_a = [0xAA; 32];
    let root_b = [0xBB; 32];
    let slot = 42u64;
    let block_a = [0xA7u8; 100];
    let block_b = [0xB7u8; 80];
    let env_a = [0x1Au8; 120];
    let env_b = [0x1Bu8; 60];

    let mut cache = TCache::producer("env_blocks", 1024 * 1024);
    let stage = |cache: &mut _, bytes: &[u8]| {
        let mut res = TCacheProducer::reserve(cache, bytes.len(), true).unwrap();
        res.write_all(bytes).unwrap();
        res.flush().unwrap();
        res.read()
    };
    let ssz_ba = stage(&mut cache, &block_a);
    let ssz_bb = stage(&mut cache, &block_b);
    let ssz_ea = stage(&mut cache, &env_a);
    let ssz_eb = stage(&mut cache, &env_b);
    let mut cons = cache.cache_ref().random_access("env_cons", true).unwrap();

    // Block before envelope: `add_envelope` derives the slot from the block.
    store.add_block(root_a, cons.acquire(ssz_ba), slot, parent_root);
    store.add_block(root_b, cons.acquire(ssz_bb), slot, parent_root);
    store.add_envelope(root_a, cons.acquire(ssz_ea));
    store.add_envelope(root_b, cons.acquire(ssz_eb));
    assert_eq!(store.unfinalized_envelopes.slot_of(&root_a), Some(slot));
    assert_eq!(store.unfinalized_envelopes.slot_of(&root_b), Some(slot));

    // Head selects A; nothing finalized yet.
    store.update_head(slot, root_a, 0, [0u8; 32]);

    let fork_digest = [1, 2, 3, 4];
    let producer_cache = TCache::multi_producer("env_rpc_in", 1024 * 1024);
    let mut producer = producer_cache.clone();
    store.file_io(|_| fork_digest, &mut producer, &mut |_| {}).unwrap();

    let unf_a = store
        .unfinalized_dir(super::Payload::Envelope)
        .join(super::io::unfinalized_envelope_name(slot, &root_a));
    let unf_b = store
        .unfinalized_dir(super::Payload::Envelope)
        .join(super::io::unfinalized_envelope_name(slot, &root_b));
    assert!(unf_a.exists());
    assert!(unf_b.exists());

    // Replay pairs each block with its envelope: a gloas child's precheck
    // only passes once the parent's payload is verified.
    let entries = store.replay_entries();
    assert_eq!(entries.len(), 2, "both forks replayable");
    assert_eq!(
        entries.iter().filter(|e| e.envelope.as_ref() == Some(&unf_a)).count(),
        1,
        "A paired with its unfinalized envelope"
    );
    assert_eq!(
        entries.iter().filter(|e| e.envelope.as_ref() == Some(&unf_b)).count(),
        1,
        "B paired with its own, not A's"
    );

    // Finalize at slot 42 on A: promote A's envelope, prune orphan B's.
    store.update_head(slot, root_a, slot, root_a);
    assert!(store.unfinalized_envelopes.is_empty());
    store.file_io(|_| fork_digest, &mut producer, &mut |_| {}).unwrap();

    let flat_a = store
        .finalized_slot_dir(super::Payload::Envelope, slot)
        .join(format!("{slot}_envelope.ssz"));
    assert!(flat_a.exists(), "canonical envelope promoted to flat store");
    assert_eq!(std::fs::read(&flat_a).unwrap(), env_a);
    assert!(!unf_a.exists(), "promoted out of unfinalized");
    assert!(!unf_b.exists(), "orphan envelope pruned");

    let entries = store.replay_entries();
    assert_eq!(entries.len(), 1, "only the promoted block replays");
    assert_eq!(
        entries[0].envelope.as_ref(),
        Some(&flat_a),
        "paired with the promoted envelope, found by slot"
    );

    // Reload rebuilds the (now empty) unfinalized envelope index.
    let reloaded = load_gloas(store_path.clone());
    assert!(reloaded.unfinalized_envelopes.is_empty());

    let _ = std::fs::remove_dir_all(&store_path);
}

// A self-parenting block (cycle) must not hang the canonical walk.
#[test]
fn range_query_terminates_on_cycle() {
    use silver_common::{
        P2pStreamId, RpcRequest, RpcRequestInbound, StreamProtocol, TCache, TCacheProducer,
    };

    let store_path = format!("/tmp/test_store_cycle_{}", rand::random::<u32>());
    let _ = std::fs::remove_dir_all(&store_path);
    let mut store = load_fulu(store_path.clone());

    // parent_root == block_root: a self-loop in the fork tree.
    let root_x = [0xEE; 32];
    let slot = 10u64;
    let mut blocks = TCache::producer("cycle_blocks", 1024 * 1024);
    let mut res = blocks.reserve(8, true).unwrap();
    res.write_all(&[0u8; 8]).unwrap();
    res.flush().unwrap();
    let ssz = res.read();
    let mut consumer = blocks.cache_ref().random_access("cycle_cons", true).unwrap();
    let read = consumer.acquire(ssz);
    store.add_block(root_x, read, slot, root_x);
    store.update_head(slot, root_x, 0, [0u8; 32]);

    // Drain the staged write so the acquired read is released while its
    // consumer is still alive (`read` is parked in the write queue).
    let mut producer = TCache::multi_producer("cycle_rpc_in", 1024 * 1024).clone();
    store.file_io(|_| [0u8; 4], &mut producer, &mut |_| {}).unwrap();

    // A range spanning the self-loop slot must return rather than spin.
    let mut range = [0u8; 24];
    range[0..8].copy_from_slice(&5u64.to_le_bytes()); // start_slot
    range[8..16].copy_from_slice(&10u64.to_le_bytes()); // count
    range[16..24].copy_from_slice(&1u64.to_le_bytes()); // step
    let sid = P2pStreamId::new(1, 1, StreamProtocol::BeaconBlocksByRange, false);
    let req_producer = TCache::producer("cycle_req", 1024 * 1024);
    let mut req_consumer = req_producer.cache_ref().random_access("cycle_req_cons", true).unwrap();
    store.rpc_request(&mut req_consumer, RpcRequestInbound {
        stream_id: sid,
        request: RpcRequest::BlocksByRange(range),
    });
    // Reaching here proves the walk terminated.
    assert!(!store.query_queue.is_empty());

    let _ = std::fs::remove_dir_all(&store_path);
}

#[test]
fn envelope_range_request_served_empty() {
    use silver_common::{
        P2pSend, P2pStreamId, RpcOutbound, RpcRequest, RpcRequestInbound, RpcResponse,
        RpcResponseOutbound, StreamProtocol, TCache, TCacheProducer,
        ssz_view::EXECUTION_PAYLOAD_ENVELOPES_BY_RANGE_REQ_SIZE,
    };

    let store_path = format!("/tmp/test_store_env_{}", rand::random::<u32>());
    let _ = std::fs::remove_dir_all(&store_path);
    let mut store = load_fulu(store_path.clone());

    // We don't persist envelopes, but an inbound range request must still get
    // a clean empty response (`Complete` only), never a hung stream.
    let req_producer = TCache::producer("env_req", 1024 * 1024);
    let mut req_consumer = req_producer.cache_ref().random_access("env_req_cons", true).unwrap();
    let sid = P2pStreamId::new(9, 1, StreamProtocol::ExecutionPayloadEnvelopesByRange, false);
    let mut req = [0u8; EXECUTION_PAYLOAD_ENVELOPES_BY_RANGE_REQ_SIZE];
    req[0..8].copy_from_slice(&10u64.to_le_bytes());
    req[8..16].copy_from_slice(&5u64.to_le_bytes());
    store.rpc_request(&mut req_consumer, RpcRequestInbound {
        stream_id: sid,
        request: RpcRequest::ExecutionPayloadEnvelopesByRange(req),
    });

    let fork_digest = [1, 2, 3, 4];
    let producer_cache = TCache::multi_producer("env_rpc_in", 1024 * 1024);
    let mut producer = producer_cache.clone();
    let mut responses = vec![];
    store
        .file_io(|_| fork_digest, &mut producer, &mut |s| {
            if let IoEvent::P2pSend(s) = s {
                responses.push(s);
            }
        })
        .unwrap();

    assert_eq!(responses.len(), 1, "empty envelope response is just Complete");
    assert!(matches!(
        &responses[0],
        P2pSend::Rpc(RpcOutbound::Response(RpcResponseOutbound {
            response: RpcResponse::Error { error: 3, .. },
            ..
        }))
    ));
}

#[test]
fn column_fork_persist_serve_promote() {
    use silver_common::{
        P2pSend, P2pStreamId, RpcOutbound, RpcRequest, RpcRequestInbound, RpcResponse,
        RpcResponseOutbound, StreamProtocol, TCache, TCacheProducer, ssz_view::DC_BY_RANGE_REQ_MAX,
    };

    let store_path = format!("/tmp/test_store_colfork_{}", rand::random::<u32>());
    let _ = std::fs::remove_dir_all(&store_path);
    let mut store = load_fulu(store_path.clone());
    let ucol_dir = store.unfinalized_dir(super::Payload::Column);
    let flat_dir = store.finalized_slot_dir(super::Payload::Column, 42);

    let parent_root = [0xCC; 32];
    let root_a = [0xAA; 32];
    let root_b = [0xBB; 32];
    let slot = 42u64;
    let a3 = [0xA3u8; 64];
    let a7 = [0xA7u8; 64];
    let b3 = [0xB3u8; 64];

    // Stage block + column payloads in a tcache.
    let mut tc = TCache::producer("colfork_data", 1 << 20);
    let mut stage = |bytes: &[u8]| {
        let mut r = tc.reserve(bytes.len(), true).unwrap();
        r.write_all(bytes).unwrap();
        r.flush().unwrap();
        r.read()
    };
    let ssz_ba = stage(&[0xA0u8; 100]);
    let ssz_bb = stage(&[0xB0u8; 100]);
    let ssz_a3 = stage(&a3);
    let ssz_a7 = stage(&a7);
    let ssz_b3 = stage(&b3);

    let mut consumer = tc.cache_ref().random_access("colfork_cons", true).unwrap();
    store.add_block(root_a, consumer.acquire(ssz_ba), slot, parent_root);
    store.add_block(root_b, consumer.acquire(ssz_bb), slot, parent_root);
    store.add_data_column(root_a, 3, consumer.acquire(ssz_a3), slot, false);
    store.add_data_column(root_a, 7, consumer.acquire(ssz_a7), slot, false);
    store.add_data_column(root_b, 3, consumer.acquire(ssz_b3), slot, false);
    assert!(store.unfinalized_columns.contains(&root_a));
    assert!(store.unfinalized_columns.contains(&root_b));

    store.update_head(slot, root_a, 0, [0u8; 32]);

    let fork_digest = [9, 9, 9, 9];
    let producer_cache = TCache::multi_producer("colfork_rpc_in", 1 << 20);
    let mut producer = producer_cache.clone();
    store.file_io(|_| fork_digest, &mut producer, &mut |_| {}).unwrap();
    assert!(ucol_dir.join(super::io::unfinalized_column_name(slot, &root_a, 3)).exists());
    assert!(ucol_dir.join(super::io::unfinalized_column_name(slot, &root_a, 7)).exists());
    assert!(ucol_dir.join(super::io::unfinalized_column_name(slot, &root_b, 3)).exists());

    let mut read_consumer = producer_cache.cache_ref().random_access("colfork_read", true).unwrap();
    let mut assert_col = |resp: &P2pSend, expected: &[u8]| {
        let P2pSend::Rpc(RpcOutbound::Response(RpcResponseOutbound {
            response: RpcResponse::DataColumnSidecar { ssz, .. },
            ..
        })) = resp
        else {
            panic!("expected DataColumnSidecar response, got {resp:?}");
        };
        let acquired = read_consumer.acquire(*ssz);
        let (buf, _) = acquired.buffer().unwrap();
        assert_eq!(buf, expected);
    };

    // DataColumnsByRange [42,43) for columns {3,7}: SSZ container is
    // start_slot | count | offset(=20) | column list (u64 LE each).
    let mut range = [0u8; DC_BY_RANGE_REQ_MAX];
    range[0..8].copy_from_slice(&slot.to_le_bytes());
    range[8..16].copy_from_slice(&1u64.to_le_bytes());
    range[16..20].copy_from_slice(&20u32.to_le_bytes());
    range[20..28].copy_from_slice(&3u64.to_le_bytes());
    range[28..36].copy_from_slice(&7u64.to_le_bytes());
    let sid = P2pStreamId::new(1, 1, StreamProtocol::DataColumnSidecarsByRange, false);

    let mut req_producer = TCache::producer("colfork_req", 1 << 20);
    let mut req_consumer =
        req_producer.cache_ref().random_access("colfork_req_cons", true).unwrap();
    store.rpc_request(&mut req_consumer, RpcRequestInbound {
        stream_id: sid,
        request: RpcRequest::DataColumnsByRange { ssz: range, len: 36 },
    });
    let mut responses = vec![];
    store
        .file_io(|_| fork_digest, &mut producer, &mut |s| match s {
            IoEvent::P2pSend(s) => responses.push(s),
            _ => {}
        })
        .unwrap();
    assert_eq!(responses.len(), 3); // canonical A columns 3 + 7, then Complete
    assert_col(&responses[0], &a3);
    assert_col(&responses[1], &a7);

    // DataColumnsByRoot spanning both roots in one request: A's column 7
    // and non-canonical B's column 3. Wire format is
    // List[DataColumnsByRootIdentifier]: outer offset table (u32 LE per
    // element), then per element root | inner offset(=36) | column list.
    let mut byroot = Vec::new();
    byroot.extend_from_slice(&8u32.to_le_bytes()); // element 0 at 8
    byroot.extend_from_slice(&52u32.to_le_bytes()); // element 1 at 8 + 44
    for (root, column) in [(&root_a, 7u64), (&root_b, 3u64)] {
        byroot.extend_from_slice(root);
        byroot.extend_from_slice(&36u32.to_le_bytes());
        byroot.extend_from_slice(&column.to_le_bytes());
    }
    let mut br_res = req_producer.reserve(byroot.len(), true).unwrap();
    br_res.write_all(&byroot).unwrap();
    br_res.flush().unwrap();
    let byroot_ssz = br_res.read();
    store.rpc_request(&mut req_consumer, RpcRequestInbound {
        stream_id: sid,
        request: RpcRequest::DataColumnsByRoot(byroot_ssz),
    });
    let mut br = vec![];
    store
        .file_io(|_| fork_digest, &mut producer, &mut |s| match s {
            IoEvent::P2pSend(s) => br.push(s),
            _ => {}
        })
        .unwrap();
    assert_eq!(br.len(), 3); // A column 7, B column 3, Complete
    assert_col(&br[0], &a7);
    assert_col(&br[1], &b3);

    // A bare identifier (no outer offset table — the pre-fix encoding) is
    // rejected: no units resolve, the peer still gets an immediate bare
    // Complete rather than a hung stream.
    let mut bare = [0u8; 44];
    bare[0..32].copy_from_slice(&root_b);
    bare[32..36].copy_from_slice(&36u32.to_le_bytes());
    bare[36..44].copy_from_slice(&3u64.to_le_bytes());
    let mut bare_res = req_producer.reserve(44, true).unwrap();
    bare_res.write_all(&bare).unwrap();
    bare_res.flush().unwrap();
    let bare_ssz = bare_res.read();
    store.rpc_request(&mut req_consumer, RpcRequestInbound {
        stream_id: sid,
        request: RpcRequest::DataColumnsByRoot(bare_ssz),
    });
    let mut rejected = vec![];
    store
        .file_io(|_| fork_digest, &mut producer, &mut |s| match s {
            IoEvent::P2pSend(s) => rejected.push(s),
            _ => {}
        })
        .unwrap();
    assert_eq!(rejected.len(), 1, "malformed by-root request answers a bare Complete");
    assert!(matches!(
        &rejected[0],
        P2pSend::Rpc(RpcOutbound::Response(RpcResponseOutbound {
            response: RpcResponse::Complete,
            ..
        }))
    ));

    // Finalize on A at slot 42: promote A's columns, prune B's.
    store.update_head(slot, root_a, slot, root_a);
    assert!(store.unfinalized_columns.is_empty());

    store.file_io(|_| fork_digest, &mut producer, &mut |_| {}).unwrap();
    assert!(flat_dir.join(format!("{slot}_3.ssz")).exists());
    assert!(flat_dir.join(format!("{slot}_7.ssz")).exists());
    assert!(!ucol_dir.join(super::io::unfinalized_column_name(slot, &root_a, 3)).exists());
    assert!(!ucol_dir.join(super::io::unfinalized_column_name(slot, &root_b, 3)).exists());

    // Range still serves A's columns, now from the flat finalized store.
    store.rpc_request(&mut req_consumer, RpcRequestInbound {
        stream_id: sid,
        request: RpcRequest::DataColumnsByRange { ssz: range, len: 36 },
    });
    let mut after = vec![];
    store
        .file_io(|_| fork_digest, &mut producer, &mut |s| match s {
            IoEvent::P2pSend(s) => after.push(s),
            _ => {}
        })
        .unwrap();
    assert_eq!(after.len(), 3);
    assert_col(&after[0], &a3);
    assert_col(&after[1], &a7);

    // Reload: finalized index persisted, unfinalized column index empty.
    let reloaded = load_fulu(store_path.clone());
    assert!(reloaded.unfinalized_columns.is_empty());
    assert_eq!(reloaded.finalized.slot_of(&root_a), Some(slot));

    let _ = std::fs::remove_dir_all(&store_path);
}

#[test]
fn backfill_block_persists_its_index_record() {
    let store_path = format!("/tmp/test_store_backfill_index_{}", rand::random::<u32>());
    let _ = std::fs::remove_dir_all(&store_path);
    let mut store = load_fulu(store_path.clone());

    let slot = 64u64;
    let block = bare_block(slot, [0x42; 32]);
    let block_root = column_util::block_root_fulu(&block);
    let mut staged = stage("backfill_index", &block, 1);

    // Nothing held yet, so the finalized root is what the block must be.
    store.head.finalized_slot = slot;
    store.head.finalized_root = block_root;
    store.backfill_block(staged.consumer.acquire(staged.reads[0]));
    drain(&mut store).unwrap();

    assert_eq!(store.finalized.slot_of(&block_root), Some(slot));
    assert!(
        store
            .finalized_slot_dir(super::Payload::Block, slot)
            .join(format!("{slot}_block.ssz"))
            .exists()
    );

    let reloaded = load_fulu(store_path.clone());
    assert_eq!(reloaded.finalized.slot_of(&block_root), Some(slot));

    let dir = store.finalized_slot_dir(super::Payload::Block, slot);
    assert_eq!(index_records(&dir), vec![super::block_index::Record { block_root, slot }]);

    let _ = std::fs::remove_dir_all(&store_path);
}

#[test]
fn column_already_on_disk_is_not_written_again() {
    let store_path = format!("/tmp/test_store_col_dedupe_{}", rand::random::<u32>());
    let _ = std::fs::remove_dir_all(&store_path);
    let mut store = load_fulu(store_path.clone());

    let (slot, block_root) = (9u64, [3u8; 32]);
    let mut staged = stage("dedupe_data", &[0xC1u8; 64], 2);

    store.add_data_column(block_root, 3, staged.consumer.acquire(staged.reads[0]), slot, false);
    assert_eq!(store.write_queue.len(), 1, "the first copy is written");

    store.add_data_column(block_root, 3, staged.consumer.acquire(staged.reads[1]), slot, false);
    assert_eq!(store.write_queue.len(), 1, "the second is already on disk");

    drain(&mut store).unwrap();
    let _ = std::fs::remove_dir_all(&store_path);
}

/// A failing write is dropped, not retried. The coverage and the report
/// must therefore trail the disk: a block that never landed is neither
/// held nor announced, or the engine would stop asking for a hole.
#[test]
fn failed_write_is_neither_held_nor_reported() {
    use silver_common::TCache;

    let store_path = format!("/tmp/test_store_failed_write_{}", rand::random::<u32>());
    let _ = std::fs::remove_dir_all(&store_path);
    let mut store = load_fulu(store_path.clone());

    let slot = 40u64;
    let block = bare_block(slot, [0x42; 32]);
    let block_root = column_util::block_root_fulu(&block);
    let mut staged = stage("failed_write", &block, 1);

    // A file where the slot directory must go makes `create_dir_all` fail.
    let dir = store.finalized_slot_dir(super::Payload::Block, slot);
    std::fs::create_dir_all(dir.parent().unwrap()).unwrap();
    std::fs::write(&dir, b"in the way").unwrap();
    let facts = super::BlockFacts::of(&block, &store.spec).unwrap();
    let needs = super::backfill::Needs { columns: false, envelope: false };
    store.write_queue.push_back(super::PendingWrite::BackfillBlock {
        block: super::Block::new(facts, needs, slot, block_root),
        ssz: staged.consumer.acquire(staged.reads[0]),
    });

    let mut reported = Vec::new();
    let result = store.file_io(
        |_| [0u8; 4],
        &mut TCache::multi_producer("failed_write_rpc", 1 << 16),
        &mut |io| {
            if let IoEvent::Need(need) = io {
                reported.push(need)
            }
        },
    );

    assert!(result.is_err(), "the write fails");
    assert!(store.write_queue.is_empty(), "and is dropped rather than retried");
    assert!(!store.finalized.coverage().is_complete(slot), "so the coverage does not hold it");
    assert!(
        !reported.iter().any(|n| matches!(n, SyncNeed::Persisted { .. })),
        "and nothing announces it"
    );
    let _ = std::fs::remove_dir_all(&store_path);
}

/// Beacon state announces an envelope again every time it is handed one it
/// already verified — that is how window coverage comes back after it was
/// dropped. Only this store knows whether the bytes got down, so only this
/// store can drop the second copy.
#[test]
fn envelope_already_on_disk_is_not_written_again() {
    let store_path = format!("/tmp/test_store_env_dedupe_{}", rand::random::<u32>());
    let _ = std::fs::remove_dir_all(&store_path);
    let mut store = load_gloas(store_path.clone());

    let (slot, block_root, parent_root) = (9u64, [3u8; 32], [0u8; 32]);
    let mut block = stage("env_dedupe_block", &[0xB0u8; 100], 1);
    let mut envelope = stage("env_dedupe_env", &[0xE1u8; 200], 2);

    store.add_block(block_root, block.consumer.acquire(block.reads[0]), slot, parent_root);
    assert_eq!(store.write_queue.len(), 1, "the block it belongs to");

    assert!(store.is_envelope_owed(&block_root, slot), "nothing on disk for it yet");
    store.add_envelope(block_root, envelope.consumer.acquire(envelope.reads[0]));
    assert_eq!(store.write_queue.len(), 2, "the first copy is written");

    assert!(!store.is_envelope_owed(&block_root, slot), "and now it is not missing");
    store.add_envelope(block_root, envelope.consumer.acquire(envelope.reads[1]));
    assert_eq!(store.write_queue.len(), 2, "the second is already on disk");

    drain(&mut store).unwrap();
    let _ = std::fs::remove_dir_all(&store_path);
}

/// Synthetic fulu `SignedBeaconBlock` carrying blob commitments, so the
/// coverage needs it a custody set. Message at 100, body at 184, commitments
/// spanning body[396..404).
fn blob_block(slot: u64, parent_root: [u8; 32]) -> Vec<u8> {
    let (body_start, body_len) = (184usize, 404usize);
    let mut block = vec![0u8; body_start + body_len];
    block[0..4].copy_from_slice(&100u32.to_le_bytes());
    block[180..184].copy_from_slice(&84u32.to_le_bytes());
    block[100..108].copy_from_slice(&slot.to_le_bytes());
    block[108..116].copy_from_slice(&11u64.to_le_bytes());
    block[116..148].copy_from_slice(&parent_root);
    block[body_start + 388..body_start + 392].copy_from_slice(&396u32.to_le_bytes());
    block[body_start + 392..body_start + 396].copy_from_slice(&404u32.to_le_bytes());
    block
}

fn following(store: &mut super::Store, finalized_slot: u64, finalized_root: [u8; 32]) {
    store.head.root = [1u8; 32];
    store.head.finalized_slot = finalized_slot;
    store.head.finalized_root = finalized_root;
    store.sync_update(SyncUpdate::Following);
}

fn prefills(store: &mut super::Store) -> Vec<Prefill> {
    use silver_common::TCache;
    let mut out = Vec::new();
    store
        .file_io(|_| [0u8; 4], &mut TCache::multi_producer("prefill_rpc", 1 << 16), &mut |io| {
            if let IoEvent::Need(SyncNeed::BackfillPrefill(p)) = io {
                out.push(p)
            }
        })
        .unwrap();
    out
}

fn bit(prefill: &Prefill, field: u32, slot: u64) -> bool {
    field & (1u32 << (slot - prefill.start)) != 0
}

/// A header-only block: no body, so no bid, no blobs, no envelope.
fn bare_block(slot: u64, parent_root: [u8; 32]) -> Vec<u8> {
    let mut block = vec![0u8; 184];
    block[0..4].copy_from_slice(&100u32.to_le_bytes());
    block[180..184].copy_from_slice(&84u32.to_le_bytes());
    block[100..108].copy_from_slice(&slot.to_le_bytes());
    block[116..148].copy_from_slice(&parent_root);
    block
}

/// The bug this rework set out to close: a block finalizes without its
/// envelope.
#[test]
fn promoted_block_missing_its_envelope_becomes_backfill_work() {
    let store_path = format!("/tmp/test_store_promote_hole_{}", rand::random::<u32>());
    let _ = std::fs::remove_dir_all(&store_path);
    let mut store = load_gloas(store_path.clone());

    let slot = 42u64;
    let block = bare_block(slot, [0x31; 32]);
    let root = column_util::block_root(&block, true);
    let mut staged = stage("promote_hole", &block, 1);

    store.sync_update(SyncUpdate::Following);
    store.add_block(root, staged.consumer.acquire(staged.reads[0]), slot, [0x31; 32]);
    // Finality reaches the block; its envelope never arrived.
    store.update_head(slot, root, slot, root);

    let prefill = prefills(&mut store).pop().expect("the promoted slot is missing");
    assert_eq!(prefill.start + 31, slot, "the window ends at it");
    assert!(bit(&prefill, prefill.have_block, slot), "the block is held");
    assert!(!bit(&prefill, prefill.envelopes, slot), "its envelope is the hole");

    let _ = std::fs::remove_dir_all(&store_path);
}

#[test]
fn failed_finalized_promote_leaves_its_slot_unknown() {
    let store_path = format!("/tmp/test_store_failed_top_{}", rand::random::<u32>());
    let _ = std::fs::remove_dir_all(&store_path);
    let mut store = load_fulu(store_path.clone());

    // One block per group directory, so one directory can be blocked.
    let bottom = bare_block(200, [0x31; 32]);
    let root_bottom = column_util::block_root_fulu(&bottom);
    let middle = bare_block(300, root_bottom);
    let root_middle = column_util::block_root_fulu(&middle);
    let top = bare_block(400, root_middle);
    let root_top = column_util::block_root_fulu(&top);
    let mut staged_bottom = stage("failed_top_bottom", &bottom, 1);
    let mut staged_middle = stage("failed_top_middle", &middle, 1);
    let mut staged_top = stage("failed_top_top", &top, 2);

    let dir = store.finalized_slot_dir(super::Payload::Block, 400);
    std::fs::create_dir_all(dir.parent().unwrap()).unwrap();
    std::fs::write(&dir, b"in the way").unwrap();
    store.sync_update(SyncUpdate::Following);
    store.add_block(
        root_bottom,
        staged_bottom.consumer.acquire(staged_bottom.reads[0]),
        200,
        [0x31; 32],
    );
    store.add_block(
        root_middle,
        staged_middle.consumer.acquire(staged_middle.reads[0]),
        300,
        root_bottom,
    );
    store.add_block(root_top, staged_top.consumer.acquire(staged_top.reads[0]), 400, root_middle);
    store.update_head(400, root_top, 400, root_top);
    assert!(drain(&mut store).is_err(), "the finalized block's promote fails");
    assert_eq!(store.finalized.slot_of(&root_top), Some(400), "yet the root stays indexed");
    std::fs::remove_file(&dir).unwrap();
    let mut published = Vec::new();
    while !store.write_queue.is_empty() {
        published.extend(prefills(&mut store));
    }
    published.extend(prefills(&mut store));

    assert!(!store.finalized.holds(400));
    assert_eq!(store.finalized.coverage().wanted_parent(400), None, "the chain stops short");
    let prefill = published.pop().expect("the top is asked for");
    assert_eq!(prefill.start + 31, 400, "the window ends at finality");
    assert!(!bit(&prefill, prefill.known_empty, 400), "400 is not proven empty");
    assert!(!bit(&prefill, prefill.have_block, 400));
    for held in [200, 300] {
        assert!(store.finalized.holds(held), "slot {held} landed");
    }

    store.backfill_block(staged_top.consumer.acquire(staged_top.reads[1]));
    let prefill = prefills(&mut store).pop().expect("the history below");
    assert!(store.finalized.holds(400), "served again and written");
    assert_eq!(prefill.start + 31, 199, "one chain, 200 to 400, wanting below it");
    assert_eq!(store.finalized.coverage().wanted_parent(400), Some([0x31; 32]));
    let _ = std::fs::remove_dir_all(&store_path);
}

/// Bytes staged twice, for a block that is handed to the store twice.
struct Staged {
    reads: Vec<silver_common::TCacheRead>,
    consumer: silver_common::TRandomAccess,
}

fn stage(name: &'static str, block: &[u8], copies: usize) -> Staged {
    use silver_common::{TCache, TCacheProducer};
    let mut tc = TCache::producer(name, 1 << 20);
    let reads = (0..copies)
        .map(|_| {
            let mut res = tc.reserve(block.len(), true).unwrap();
            res.write_all(block).unwrap();
            res.flush().unwrap();
            res.read()
        })
        .collect();
    let consumer = tc.cache_ref().random_access(name, true).unwrap();
    Staged { reads, consumer }
}

fn drain(store: &mut super::Store) -> Result<(), std::io::Error> {
    use silver_common::TCache;
    store.file_io(|_| [0u8; 4], &mut TCache::multi_producer("drain", 1 << 16), &mut |_| {})
}

/// Two finalities queue before the first promotion drains. The span
/// the first opens must reach only the finality it was queued under, or
/// the second promotion lands inside it and its needs are never recorded.
#[test]
fn promotion_draining_under_a_later_finality_keeps_its_needs() {
    let store_path = format!("/tmp/test_store_promote_race_{}", rand::random::<u32>());
    let _ = std::fs::remove_dir_all(&store_path);
    let mut store = load_gloas(store_path.clone());

    let first = bare_block(40, [0x31; 32]);
    let root_first = column_util::block_root(&first, true);
    let second = bare_block(44, root_first);
    let root_second = column_util::block_root(&second, true);
    let mut staged_first = stage("promote_race_first", &first, 1);
    let mut staged_second = stage("promote_race_second", &second, 1);

    let ssz_first = staged_first.consumer.acquire(staged_first.reads[0]);
    let ssz_second = staged_second.consumer.acquire(staged_second.reads[0]);
    store.add_block(root_first, ssz_first, 40, [0x31; 32]);
    store.add_block(root_second, ssz_second, 44, root_first);
    store.update_head(40, root_first, 40, root_first);
    store.update_head(44, root_second, 44, root_second);
    while !store.write_queue.is_empty() {
        drain(&mut store).unwrap();
    }

    assert_eq!(
        store.finalized.coverage().wanted_parent(44),
        Some([0x31; 32]),
        "one chain, 40 through 44, wanting what 40 wants"
    );
    for slot in [40, 44] {
        assert!(
            store.finalized.coverage().envelope_missing(slot),
            "slot {slot} still needs its envelope"
        );
    }
    let _ = std::fs::remove_dir_all(&store_path);
}

/// A column landing for a finalized slot says nothing about a block file, so
/// it must not index its root.
#[test]
fn finalized_column_does_not_index_its_block() {
    let store_path = format!("/tmp/test_store_column_no_index_{}", rand::random::<u32>());
    let _ = std::fs::remove_dir_all(&store_path);
    let mut store = load_fulu(store_path.clone());
    let staged = stage("column_no_index", b"col", 1);
    let mut consumer = staged.consumer;

    store.head.finalized_slot = 64;
    store.add_data_column([0x51; 32], 3, consumer.acquire(staged.reads[0]), 40, true);
    drain(&mut store).unwrap();

    assert!(!store.finalized.contains(&[0x51; 32]));
    assert!(!store.finalized.holds(40));
    assert!(
        store.finalized_slot_dir(super::Payload::Column, 40).join("40_3.ssz").exists(),
        "the column itself is written"
    );
    let _ = std::fs::remove_dir_all(&store_path);
}

/// Written once the queue has drained, not once per turn while it drains.
#[test]
fn coverage_is_persisted_once_the_writes_settle() {
    let store_path = format!("/tmp/test_store_persist_settled_{}", rand::random::<u32>());
    let _ = std::fs::remove_dir_all(&store_path);
    let mut store = load_fulu(store_path.clone());
    let file = std::path::Path::new(&store_path).join("coverage.bin");

    let block = bare_block(40, [0x31; 32]);
    let root = column_util::block_root_fulu(&block);
    let mut staged = stage("persist_settled", &block, 1);
    following(&mut store, 40, root);
    store.backfill_block(staged.consumer.acquire(staged.reads[0]));
    // Enough behind it that one turn cannot drain the queue.
    for _ in 0..super::io::MAX_WRITES_PER_LOOP {
        store.write_queue.push_back(super::PendingWrite::TruncateHistory {
            payload: super::Payload::Block,
            finalized_slot: 0,
        });
    }

    drain(&mut store).unwrap();
    assert!(store.finalized.holds(40), "the block landed");
    assert!(!store.write_queue.is_empty() && !file.exists(), "but the queue is still draining");
    drain(&mut store).unwrap();
    assert!(store.write_queue.is_empty() && file.exists(), "drained, and written once");

    let _ = std::fs::remove_dir_all(&store_path);
}

/// The index gives the blocks, one header read per gap says whether it is
/// empty, and the first read of a group settles what an absent column set
/// means.
#[test]
fn store_without_coverage_is_rebuilt_from_its_files() {
    let store_path = format!("/tmp/test_store_rebuild_{}", rand::random::<u32>());
    let _ = std::fs::remove_dir_all(&store_path);
    let custody = 0b11u128;

    // 960 ← 961 ← 963 is one chain; 966 hangs off a block we never got.
    let bare_960 = bare_block(960, [0x31; 32]);
    let root_960 = column_util::block_root_fulu(&bare_960);
    let blob_961 = blob_block(961, root_960);
    let root_961 = column_util::block_root_fulu(&blob_961);
    let bare_963 = bare_block(963, root_961);
    let root_963 = column_util::block_root_fulu(&bare_963);
    let bare_966 = bare_block(966, [0x77; 32]);
    let root_966 = column_util::block_root_fulu(&bare_966);
    {
        let store = load_fulu(store_path.clone());
        for (slot, block, root) in [
            (960, &bare_960, root_960),
            (961, &blob_961, root_961),
            (963, &bare_963, root_963),
            (966, &bare_966, root_966),
        ] {
            let dir = store.finalized_slot_dir(super::Payload::Block, slot);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join(format!("{slot}_block.ssz")), block).unwrap();
            super::block_index::append(&dir, super::block_index::Record { block_root: root, slot })
                .unwrap();
        }
        // 960's custody set is on disk, 961 has one column of its two, 963 none.
        let columns = store.finalized_slot_dir(super::Payload::Column, 960);
        std::fs::create_dir_all(&columns).unwrap();
        for name in ["960_0", "960_1", "961_0"] {
            std::fs::write(columns.join(format!("{name}.ssz")), b"col").unwrap();
        }
    }

    let mut store =
        super::Store::load(store_path.clone(), super::test_spec(u64::MAX), custody).unwrap();
    assert_eq!(
        store.finalized.coverage().wanted_parent(966),
        Some([0x77; 32]),
        "the top chain wants 965"
    );
    following(&mut store, 966, root_966);

    let mut published = prefills(&mut store);
    assert!(published.is_empty(), "the first step reads a group, not the wire");
    assert_eq!(store.finalized.coverage().examined_below(), 896, "and marks it read");
    for _ in 0..16 {
        if !published.is_empty() {
            break;
        }
        published = prefills(&mut store);
    }
    assert_eq!(store.finalized.coverage().examined_below(), 0, "every group is read first");
    let prefill = published.pop().expect("the hole and 961 are missing");
    assert_eq!(prefill.start + 31, 965, "the window ends under the top chain");
    for held in [960, 961, 963] {
        assert!(bit(&prefill, prefill.have_block, held), "slot {held} is held");
    }
    assert!(bit(&prefill, prefill.known_empty, 962), "963 links over 962");
    for unknown in [964, 965] {
        assert!(
            !bit(&prefill, prefill.have_block, unknown) &&
                !bit(&prefill, prefill.known_empty, unknown),
            "nothing links over {unknown}, so it is asked for"
        );
    }
    assert!(bit(&prefill, prefill.columns_covered, 960), "listed on disk");
    assert!(bit(&prefill, prefill.columns_covered, 963), "no blobs, so nothing to hold");
    assert!(!bit(&prefill, prefill.columns_covered, 961), "a blob block missing a column");
    assert_eq!(store.finalized.coverage().columns_missing(961), 0b10, "only the absent one");
    assert_eq!(prefill.columns_missing, 0b10);
    assert!(
        std::path::Path::new(&store_path).join("coverage.bin").exists(),
        "and the rebuilt coverage is persisted"
    );

    let _ = std::fs::remove_dir_all(&store_path);
}

// Two concurrent range requests must interleave chunk-by-chunk, not
// serialize (head-of-line fairness).
#[test]
fn range_queries_interleave_fairly() {
    use silver_common::{
        P2pSend, P2pStreamId, RpcOutbound, RpcRequest, RpcRequestInbound, RpcResponse,
        RpcResponseOutbound, StreamProtocol, TCache, TCacheProducer,
    };

    let store_path = format!("/tmp/test_store_fair_{}", rand::random::<u32>());
    let _ = std::fs::remove_dir_all(&store_path);
    let mut store = load_fulu(store_path.clone());

    // Chain of two unfinalized blocks: slot 10 (parent CC) ← slot 11.
    let parent = [0xCC; 32];
    let root_10 = [0x10; 32];
    let root_11 = [0x11; 32];
    let mut blocks = TCache::producer("fair_blocks", 1 << 20);
    let mut stage = |bytes: &[u8]| {
        let mut r = blocks.reserve(bytes.len(), true).unwrap();
        r.write_all(bytes).unwrap();
        r.flush().unwrap();
        r.read()
    };
    let ssz_10 = stage(&[0x10u8; 50]);
    let ssz_11 = stage(&[0x11u8; 50]);
    let mut consumer = blocks.cache_ref().random_access("fair_cons", true).unwrap();
    store.add_block(root_10, consumer.acquire(ssz_10), 10, parent);
    store.add_block(root_11, consumer.acquire(ssz_11), 11, root_10);
    store.update_head(11, root_11, 0, [0u8; 32]);

    let fork_digest = [0u8; 4];
    let producer_cache = TCache::multi_producer("fair_rpc_in", 1 << 20);
    let mut producer = producer_cache.clone();
    store.file_io(|_| fork_digest, &mut producer, &mut |_| {}).unwrap(); // flush block writes

    // Two BlocksByRange [10,12) on distinct streams, queued before draining.
    let mut range = [0u8; 24];
    range[0..8].copy_from_slice(&10u64.to_le_bytes());
    range[8..16].copy_from_slice(&2u64.to_le_bytes());
    range[16..24].copy_from_slice(&1u64.to_le_bytes());
    let stream_a = P2pStreamId::new(1, 1, StreamProtocol::BeaconBlocksByRange, false);
    let stream_b = P2pStreamId::new(2, 2, StreamProtocol::BeaconBlocksByRange, false);
    let req_producer = TCache::producer("fair_req", 1 << 20);
    let mut req_consumer = req_producer.cache_ref().random_access("fair_req_cons", true).unwrap();
    store.rpc_request(&mut req_consumer, RpcRequestInbound {
        stream_id: stream_a,
        request: RpcRequest::BlocksByRange(range),
    });
    store.rpc_request(&mut req_consumer, RpcRequestInbound {
        stream_id: stream_b,
        request: RpcRequest::BlocksByRange(range),
    });

    let mut responses = vec![];
    store
        .file_io(|_| fork_digest, &mut producer, &mut |s| match s {
            IoEvent::P2pSend(s) => responses.push(s),
            _ => {}
        })
        .unwrap();

    // Expect A10, B10, A11, B11, A-Complete, B-Complete — strict round-robin.
    let ids: Vec<_> = responses
        .iter()
        .map(|s| {
            let P2pSend::Rpc(RpcOutbound::Response(RpcResponseOutbound { stream_id, .. })) = s
            else {
                panic!("expected RPC response, got {s:?}");
            };
            stream_id.stream_id()
        })
        .collect();
    let (a, b) = (stream_a.stream_id(), stream_b.stream_id());
    assert_ne!(a, b);
    assert_eq!(responses.len(), 6);
    assert_eq!(ids, vec![a, b, a, b, a, b], "responses must interleave across streams");
    for resp in &responses[4..] {
        let P2pSend::Rpc(RpcOutbound::Response(RpcResponseOutbound { response, .. })) = resp else {
            panic!("expected RPC response");
        };
        assert!(matches!(response, RpcResponse::Complete));
    }

    let _ = std::fs::remove_dir_all(&store_path);
}

/// An unfinalized file that vanished before finality is not promoted. The
/// block is a hole and the column is missing, so the walk asks for both
/// instead of recording what is not there.
#[test]
fn vanished_unfinalized_files_stay_missing_at_promotion() {
    use super::backfill::fixtures::{envelope_for, gloas_chain_block};

    let store_path = format!("/tmp/test_store_vanished_{}", rand::random::<u32>());
    let _ = std::fs::remove_dir_all(&store_path);
    let mut store = super::Store::load(store_path.clone(), super::test_spec(0), 0b11).unwrap();

    let blob = gloas_chain_block(40, [0x31; 32], &[0u8; 48]);
    let root_blob = column_util::block_root(&blob, true);
    let middle = gloas_chain_block(44, root_blob, &[]);
    let root_middle = column_util::block_root(&middle, true);
    let top = gloas_chain_block(48, root_middle, &[]);
    let root_top = column_util::block_root(&top, true);
    let mut staged_blob = stage("vanished_blob", &blob, 1);
    let mut staged_middle = stage("vanished_middle", &middle, 1);
    let mut staged_top = stage("vanished_top", &top, 1);
    let mut staged_columns = stage("vanished_columns", b"col", 2);
    let mut env_blob = stage("vanished_env_40", &envelope_for(root_blob), 1);
    let mut env_top = stage("vanished_env_48", &envelope_for(root_top), 1);

    store.add_block(root_blob, staged_blob.consumer.acquire(staged_blob.reads[0]), 40, [0x31; 32]);
    store.add_block(
        root_middle,
        staged_middle.consumer.acquire(staged_middle.reads[0]),
        44,
        root_blob,
    );
    store.add_block(root_top, staged_top.consumer.acquire(staged_top.reads[0]), 48, root_middle);
    for column in [0u64, 1] {
        let ssz = staged_columns.consumer.acquire(staged_columns.reads[column as usize]);
        store.add_data_column(root_blob, column, ssz, 40, column == 1);
    }
    store.add_envelope(root_blob, env_blob.consumer.acquire(env_blob.reads[0]));
    store.add_envelope(root_top, env_top.consumer.acquire(env_top.reads[0]));
    drain(&mut store).unwrap();
    let blocks = store.unfinalized_dir(super::Payload::Block);
    std::fs::remove_file(blocks.join(super::io::unfinalized_name(44, &root_blob, &root_middle)))
        .unwrap();
    let columns = store.unfinalized_dir(super::Payload::Column);
    std::fs::remove_file(columns.join(super::io::unfinalized_column_name(40, &root_blob, 1)))
        .unwrap();
    let envelopes = store.unfinalized_dir(super::Payload::Envelope);
    std::fs::remove_file(envelopes.join(super::io::unfinalized_envelope_name(40, &root_blob)))
        .unwrap();

    store.sync_update(SyncUpdate::Following);
    store.update_head(48, root_top, 48, root_top);
    let mut published = Vec::new();
    while !store.write_queue.is_empty() {
        published.extend(prefills(&mut store));
    }
    published.extend(prefills(&mut store));

    let coverage = store.finalized.coverage();
    assert!(store.finalized.holds(40) && store.finalized.holds(48));
    assert!(!store.finalized.holds(44), "the vanished block is not held");
    assert_eq!(coverage.columns_missing(40), 0b10, "the vanished column is missing");
    assert!(coverage.envelope_missing(40), "the vanished envelope is missing");
    assert!(!coverage.envelope_missing(48));
    let prefill = published.pop().expect("the hole is asked for");
    assert!(!bit(&prefill, prefill.have_block, 44) && !bit(&prefill, prefill.known_empty, 44));
    assert!(bit(&prefill, prefill.have_block, 40));
    assert!(!bit(&prefill, prefill.columns_covered, 40));
    assert!(!bit(&prefill, prefill.envelopes, 40));
    assert_eq!(prefill.columns_missing, 0b10);
    let _ = std::fs::remove_dir_all(&store_path);
}

fn place_block(store_path: &str, slot: u64, block: &[u8], root: [u8; 32]) {
    let dir = slot_dir(store_path, super::Payload::Block, slot);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(format!("{slot}_block.ssz")), block).unwrap();
    super::block_index::append(&dir, super::block_index::Record { block_root: root, slot })
        .unwrap();
}

fn place_column(store_path: &str, slot: u64, column: u64) {
    let path = column_path(store_path, slot, column);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, b"col").unwrap();
}

fn first_prefill(store: &mut super::Store) -> Prefill {
    for _ in 0..32 {
        if let Some(prefill) = prefills(store).pop() {
            return prefill;
        }
    }
    panic!("no window published");
}

#[test]
fn custody_change_rebuilds_and_misses_only_the_new_columns() {
    let store_path = format!("/tmp/test_store_custody_change_{}", rand::random::<u32>());
    let _ = std::fs::remove_dir_all(&store_path);
    let block = blob_block(32, [0x31; 32]);
    let root = column_util::block_root_fulu(&block);
    place_block(&store_path, 32, &block, root);
    place_column(&store_path, 32, 0);

    {
        let mut store = load_fulu_custodying(store_path.clone(), 0b01);
        following(&mut store, 32, root);
        for _ in 0..8 {
            prefills(&mut store);
        }
        assert_eq!(store.finalized.coverage().columns_missing(32), 0, "complete under one column");
        assert!(std::path::Path::new(&store_path).join("coverage.bin").exists());
    }

    let mut store = load_fulu_custodying(store_path.clone(), 0b11);
    following(&mut store, 32, root);
    let prefill = first_prefill(&mut store);
    assert_eq!(store.finalized.coverage().columns_missing(32), 0b10, "only the new column");
    assert_eq!(prefill.columns_missing, 0b10);
    let _ = std::fs::remove_dir_all(&store_path);
}

#[test]
fn rebuild_across_the_fork_misses_envelopes_only_above_it() {
    use super::backfill::fixtures::{envelope_for, gloas_chain_block};

    let store_path = format!("/tmp/test_store_rebuild_fork_{}", rand::random::<u32>());
    let _ = std::fs::remove_dir_all(&store_path);
    let spec = super::test_spec(1);
    assert_eq!(spec.gloas_fork_slot(), 32);

    let fulu_a = bare_block(30, [0x31; 32]);
    let root_a = column_util::block_root_fulu(&fulu_a);
    let fulu_b = bare_block(31, root_a);
    let root_b = column_util::block_root_fulu(&fulu_b);
    let gloas_a = gloas_chain_block(32, root_b, &[]);
    let root_c = column_util::block_root(&gloas_a, true);
    let gloas_b = gloas_chain_block(33, root_c, &[]);
    let root_d = column_util::block_root(&gloas_b, true);
    for (slot, block, root) in [
        (30, &fulu_a, root_a),
        (31, &fulu_b, root_b),
        (32, &gloas_a, root_c),
        (33, &gloas_b, root_d),
    ] {
        place_block(&store_path, slot, block, root);
    }
    let envelope = envelope_path(&store_path, 33);
    std::fs::create_dir_all(envelope.parent().unwrap()).unwrap();
    std::fs::write(envelope, envelope_for(root_d)).unwrap();

    let mut store = super::Store::load(store_path.clone(), spec, 0).unwrap();
    following(&mut store, 33, root_d);
    assert_eq!(store.finalized.coverage().wanted_parent(33), Some([0x31; 32]), "one chain");
    let prefill = first_prefill(&mut store);

    let coverage = store.finalized.coverage();
    assert!(coverage.envelope_missing(32), "a gloas block without its envelope");
    assert!(!coverage.envelope_missing(33) && !coverage.envelope_missing(31));
    assert_eq!(prefill.start + 31, 32, "the window ends at the missing block");
    for below in [30, 31] {
        assert!(bit(&prefill, prefill.envelopes, below), "no envelope existed at {below}");
    }
    assert!(!bit(&prefill, prefill.envelopes, 32));
    let _ = std::fs::remove_dir_all(&store_path);
}
