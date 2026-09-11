#![cfg(feature = "thread_park")]

use flux::park::SIGNAL;
use silver_common::{SubLayout, SubReservationError, TCache};

#[test]
fn sub_reservations_notify_once_on_terminal_publication() {
    let mut producer = TCache::producer("", 4096);
    let initial = SIGNAL.read_counter();
    let finished = producer
        .sub_reservation(SubLayout { parts: 0, first_len: 4, second_len: 2 }, b"full", b"")
        .unwrap();
    let abandoned = producer
        .sub_reservation(SubLayout { parts: 1, first_len: 4, second_len: 2 }, b"", b"")
        .unwrap();
    assert_eq!(SIGNAL.read_counter(), initial);
    let view = producer.view_sub_reservation(abandoned).unwrap();
    assert!(matches!(view.finish(), Err(SubReservationError::Incomplete)));
    assert_eq!(SIGNAL.read_counter(), initial);

    let view = producer.view_sub_reservation(finished).unwrap();
    view.finish().unwrap();
    assert_eq!(SIGNAL.read_counter(), initial.wrapping_add(1));
    view.finish().unwrap();
    view.close();
    view.close();
    assert_eq!(SIGNAL.read_counter(), initial.wrapping_add(1));

    let view = producer.view_sub_reservation(abandoned).unwrap();
    view.close();
    assert_eq!(SIGNAL.read_counter(), initial.wrapping_add(2));
    view.close();
    assert!(matches!(view.finish(), Err(SubReservationError::Closed)));
    assert_eq!(SIGNAL.read_counter(), initial.wrapping_add(2));
}
