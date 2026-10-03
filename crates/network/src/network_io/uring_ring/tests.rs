use std::{
    thread,
    time::{Duration, Instant},
};

use io_uring::types;

use super::*;

#[test]
fn rejects_invalid_configuration_before_creating_a_ring() {
    let defaults = UringConfig::default();
    let configs = [
        UringConfig { sq_entries: 0, ..defaults.clone() },
        UringConfig { sq_entries: 3, ..defaults.clone() },
        UringConfig { cq_entries: 0, ..defaults.clone() },
        UringConfig { cq_entries: 3, ..defaults.clone() },
        UringConfig { cq_entries: defaults.sq_entries / 2, ..defaults.clone() },
        UringConfig { quic_rx_buffers: 0, ..defaults.clone() },
        UringConfig { quic_rx_buffers: 3, ..defaults.clone() },
        UringConfig { discovery_rx_buffers: 0, ..defaults.clone() },
        UringConfig { discovery_rx_buffers: 32769, ..defaults.clone() },
        UringConfig { quic_tx_buffers: 0, ..defaults.clone() },
        UringConfig { discovery_tx_buffers: 0, ..defaults.clone() },
        UringConfig { sqpoll_idle: Duration::ZERO, ..defaults.clone() },
        UringConfig {
            sqpoll_idle: Duration::from_millis(u64::from(u32::MAX)) + Duration::from_nanos(1),
            ..defaults
        },
    ];
    for config in configs {
        let error = build(&config).err().expect("invalid ring configuration succeeded");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{config:?}: {error}");
    }
}

#[test]
fn idle_duration_rounds_up_without_changing_zero_into_the_kernel_default() {
    for (duration, expected) in [
        (Duration::from_nanos(1), 1),
        (Duration::from_millis(10), 10),
        (Duration::from_millis(10) + Duration::from_nanos(1), 11),
        (Duration::from_millis(u64::from(u32::MAX)), u32::MAX),
    ] {
        let config = UringConfig { sqpoll_idle: duration, ..Default::default() };
        assert_eq!(config.validate().unwrap(), expected);
    }
}

#[test]
fn sqpoll_ring_completes_after_idle_and_can_move_to_the_tile_thread() {
    let config = UringConfig { sq_entries: 8, cq_entries: 64, ..Default::default() };
    let mut ring = match build(&config) {
        Ok(ring) => ring,
        Err(error)
            if matches!(
                error.raw_os_error(),
                Some(libc::EPERM | libc::EACCES | libc::ENOSYS | libc::EOPNOTSUPP)
            ) =>
        {
            eprintln!("SKIP SQPOLL setup test: {error}");
            return;
        }
        Err(error) => panic!("create network SQPOLL ring: {error}"),
    };
    assert!(ring.params().is_setup_sqpoll());
    assert!(!ring.params().is_setup_iopoll());
    assert_eq!(ring.params().sq_entries(), config.sq_entries);
    assert_eq!(ring.params().cq_entries(), config.cq_entries);

    thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(2);
        while !ring.submission().need_wakeup() {
            assert!(Instant::now() < deadline, "SQPOLL thread did not go idle");
            thread::sleep(Duration::from_millis(1));
        }

        let entry = opcode::Nop::new().build().user_data(17);
        // SAFETY: NOP contains no pointers or borrowed resources.
        unsafe { ring.submission().push(&entry).unwrap() };
        let timeout = types::Timespec::from(Duration::from_secs(2));
        let args = types::SubmitArgs::new().timespec(&timeout);
        ring.submitter().submit_with_args(1, &args).expect("SQPOLL completion deadline");
        let completion = ring.completion().next().expect("missing completion");
        assert_eq!(completion.user_data(), 17);
        assert_eq!(completion.result(), 0);
    })
    .join()
    .unwrap();

    let invalid_cpu = UringConfig { sqpoll_cpu: Some(i32::MAX as u32), ..config };
    let error = build(&invalid_cpu).err().expect("invalid SQPOLL CPU was ignored");
    assert_eq!(error.raw_os_error(), Some(libc::EINVAL));
}
