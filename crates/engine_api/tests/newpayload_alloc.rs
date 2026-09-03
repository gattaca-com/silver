//! Pins the newPayload hot-path invariant: once every buffer is warm (scratch,
//! connection write buffer, JWT token cache, pending-request map), the SSZ→JSON
//! transcode + frame + enqueue path performs zero heap allocations.

use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use silver_engine_api::{
    EngineClient, ReqKind, send_new_payload,
    test_el::{FakeEl, write_jwt},
};
use silver_httpcore::{Readiness, TokenRange};

thread_local! {
    static ALLOCATION_EVENTS: Cell<u64> = const { Cell::new(0) };
}

fn allocation_events() -> u64 {
    ALLOCATION_EVENTS.with(Cell::get)
}

struct CountingAllocator;

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATION_EVENTS.with(|c| c.set(c.get() + 1));
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOCATION_EVENTS.with(|c| c.set(c.get() + 1));
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATION_EVENTS.with(|c| c.set(c.get() + 1));
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

const SIGNED_BLOCK_SSZ: &[u8] = include_bytes!("../testdata/signed_block.ssz");
const NEW_PAYLOAD_VALID: &str =
    r#"{"status":"VALID","latestValidHash":null,"validationError":null}"#;

fn unix_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn complete_round_trip(
    readiness: &mut Readiness,
    client: &mut EngineClient,
    el: &mut FakeEl,
    request_index: usize,
) {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut responded = false;
    let mut done = false;
    while !done {
        assert!(Instant::now() < deadline, "timeout: newPayload round trip {request_index}");
        el.pump();
        if !responded && el.requests.len() > request_index {
            assert_eq!(el.requests[request_index].method, "engine_newPayloadV4");
            el.respond(request_index, NEW_PAYLOAD_VALID);
            responded = true;
        }
        readiness.wait(Duration::ZERO);
        client.dispatch(readiness.events(), |kind, response| {
            assert!(matches!(kind, ReqKind::NewPayload(_)));
            response.expect("newPayload response");
            done = true;
        });
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn warm_new_payload_send_allocates_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let jwt_path = write_jwt(dir.path());
    let socket = dir.path().join("engine.sock");
    let mut el = FakeEl::uds(&socket);
    let mut readiness = Readiness::new(16);
    let mut client = EngineClient::new_uds(
        readiness.registry(),
        TokenRange::whole(),
        &socket,
        jwt_path.to_str().unwrap(),
        4,
        Duration::from_secs(60),
    );

    send_new_payload(&mut client, SIGNED_BLOCK_SSZ, [0u8; 32]).unwrap();
    complete_round_trip(&mut readiness, &mut client, &mut el, 0);
    let mut request_index = 1;
    assert!(allocation_events() > 0, "counting allocator must observe the cold path");

    // The JWT bearer token is cached per wall-clock second, so a warm send and
    // the measured send must land in the same second for the token recompute
    // to stay out of the measured window; retry on the rare rollover.
    for _ in 0..5 {
        let second = unix_secs();
        send_new_payload(&mut client, SIGNED_BLOCK_SSZ, [1u8; 32]).unwrap();
        complete_round_trip(&mut readiness, &mut client, &mut el, request_index);
        request_index += 1;

        let before = allocation_events();
        send_new_payload(&mut client, SIGNED_BLOCK_SSZ, [2u8; 32]).unwrap();
        let events = allocation_events() - before;

        complete_round_trip(&mut readiness, &mut client, &mut el, request_index);
        request_index += 1;
        if unix_secs() == second {
            assert_eq!(events, 0, "warm newPayload send performed {events} heap allocations");
            return;
        }
    }
    panic!("wall clock crossed a second boundary on every attempt");
}
