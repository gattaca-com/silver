use flux::park::Signal;

use super::*;
use crate::network_io::uring_io::futex_wake::{FUTEX_TAG, FutexWake};

#[test]
fn signal_between_snapshot_and_submission_cannot_be_lost() {
    static SIGNAL: Signal = Signal::new();
    let Some(mut io) = receiver(4, 4) else { return };
    io.wake = Some(FutexWake::new(&SIGNAL));
    io.start_loop();
    SIGNAL.signal();
    io.wait_for_completions(Duration::from_secs(2)).unwrap();
    let completion = io.ring.completion().next().expect("futex completion deadline");
    assert_eq!(completion.user_data(), FUTEX_TAG);
    assert_eq!(completion.result(), -libc::EAGAIN);
    io.wake.as_mut().unwrap().complete(completion.result()).unwrap();
    assert!(!io.wake.as_ref().unwrap().is_active());
    io.shutdown().unwrap();
}

#[test]
fn signal_wakes_a_pending_wait_and_can_rearm_after_timeouts() {
    static SIGNAL: Signal = Signal::new();
    let Some(mut io) = receiver(4, 4) else { return };
    io.wake = Some(FutexWake::new(&SIGNAL));
    for _ in 0..3 {
        for _ in 0..4 {
            io.start_loop();
            io.wait_for_completions(Duration::from_millis(2)).unwrap();
            assert!(io.ring.completion().is_empty());
            assert!(io.wake.as_ref().unwrap().is_active());
        }
        let producer = thread::spawn(|| {
            thread::sleep(Duration::from_millis(20));
            SIGNAL.signal();
        });
        io.wait_for_completions(Duration::from_secs(2)).unwrap();
        producer.join().unwrap();
        assert_eq!(io.ring.completion().len(), 1, "more than one futex wait outstanding");
        io.poll(Duration::ZERO, |_, _, _| panic!("unexpected packet")).unwrap();
        assert!(!io.wake.as_ref().unwrap().is_active());
        assert!(io.ring.completion().is_empty());
    }
    io.shutdown().unwrap();
}

#[test]
fn network_completion_does_not_discard_the_spine_wait() {
    static SIGNAL: Signal = Signal::new();
    let Some(mut io) = receiver(4, 4) else { return };
    io.wake = Some(FutexWake::new(&SIGNAL));
    io.start_loop();
    io.wait_for_completions(Duration::from_millis(2)).unwrap();
    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    peer.send_to(b"packet", destination(&io, SocketId::Discovery, false)).unwrap();
    let packets = receive(&mut io, 1);
    assert_eq!(&packets[0].1[..], b"packet");
    assert!(io.wake.as_ref().unwrap().is_active());
    SIGNAL.signal();
    io.wait_for_completions(Duration::from_secs(2)).unwrap();
    io.poll(Duration::ZERO, |_, _, _| panic!("unexpected packet")).unwrap();
    assert!(!io.wake.as_ref().unwrap().is_active());
    io.shutdown().unwrap();
}

#[test]
fn shutdown_cancels_an_idle_spine_wait_without_a_signal() {
    static SIGNAL: Signal = Signal::new();
    let Some(mut io) = receiver(4, 4) else { return };
    io.wake = Some(FutexWake::new(&SIGNAL));
    io.start_loop();
    io.wait_for_completions(Duration::from_millis(2)).unwrap();
    assert!(io.wake.as_ref().unwrap().is_active());
    io.shutdown().unwrap();
    assert!(!io.has_in_flight());
    assert!(!io.wake.as_ref().unwrap().is_active());
}

#[test]
fn full_submission_queue_cannot_claim_to_have_armed_a_wait() {
    static SIGNAL: Signal = Signal::new();
    let mut ring = IoUring::new(2).unwrap();
    let mut wake = FutexWake::new(&SIGNAL);
    let entry = opcode::Nop::new().build();
    // SAFETY: NOP carries no pointers or borrowed resources.
    unsafe {
        ring.submission().push(&entry).unwrap();
        ring.submission().push(&entry).unwrap();
    }
    assert!(!wake.arm(&mut ring));
    assert!(!wake.is_active());
}
