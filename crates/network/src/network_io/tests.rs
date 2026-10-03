use std::{
    net::{Ipv4Addr, UdpSocket},
    time::Instant,
};

#[cfg(feature = "thread_park")]
use flux::park::SIGNAL;

use super::*;

#[test]
fn routes_datagrams_and_responses_through_their_own_socket() {
    routes_datagrams_and_responses(&NetworkConfig::Mio);
}

#[cfg(all(target_os = "linux", feature = "io-uring"))]
#[test]
fn uring_routes_datagrams_and_responses_through_their_own_socket() {
    routes_datagrams_and_responses(&NetworkConfig::IoUring(Default::default()));
}

fn routes_datagrams_and_responses(config: &NetworkConfig) {
    let addr = "127.0.0.1:0".parse().unwrap();
    let mut io = NetworkIo::new(addr, addr, config).unwrap();
    #[cfg(feature = "thread_park")]
    {
        io.register_spine_waker().unwrap();
        SIGNAL.signal();
    }
    let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let destination = peer.local_addr().unwrap();
    let sockets = [SocketId::Quic, SocketId::Discovery];
    let mut addresses = Vec::new();
    let mut buffer = [0; 16];

    for socket in sockets {
        assert!(io.send(socket, |data| {
            data.push(socket as u8);
            Some(Transmit { destination, size: 1, ecn: None, segment_size: None, src_ip: None })
        }));
        assert!(io.flush(socket));
        let (size, remote) = peer.recv_from(&mut buffer).unwrap();
        assert_eq!(&buffer[..size], &[socket as u8]);
        addresses.push(remote);
        peer.send_to(&buffer[..size], remote).unwrap();
    }
    assert_ne!(addresses[0], addresses[1]);

    let deadline = Instant::now() + Duration::from_secs(2);
    let mut received = [false; 2];
    while !received.iter().all(|seen| *seen) {
        let timeout = deadline.checked_duration_since(Instant::now()).expect("receive deadline");
        io.start_loop();
        io.wait(timeout).unwrap();
        io.recv(|socket, data, remote, scratch| {
            assert_eq!(remote, destination);
            assert_eq!(data.as_ref(), &[socket as u8]);
            assert!(!received[socket as usize], "duplicate datagram");
            received[socket as usize] = true;
            scratch.extend_from_slice(&[socket as u8, 0xff]);
            Some(Transmit {
                destination: remote,
                size: scratch.len(),
                ecn: None,
                segment_size: None,
                src_ip: None,
            })
        })
        .unwrap();
    }

    for socket in sockets {
        assert!(io.flush(socket));
        let (size, remote) = peer.recv_from(&mut buffer).unwrap();
        assert_eq!(remote, addresses[socket as usize]);
        assert_eq!(&buffer[..size], &[socket as u8, 0xff]);
    }
}

#[cfg(not(all(target_os = "linux", feature = "io-uring")))]
#[test]
fn explicit_uring_selection_requires_a_supported_build() {
    let addr = "127.0.0.1:0".parse().unwrap();
    let error = NetworkIo::new(addr, addr, &NetworkConfig::IoUring(Default::default()))
        .err()
        .expect("io_uring silently fell back to Mio");
    assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    assert!(error.to_string().contains("--features io-uring"));
}

#[cfg(all(target_os = "linux", feature = "io-uring"))]
#[test]
fn explicit_uring_selection_rejects_invalid_configuration() {
    use silver_config::UringConfig;

    let addr = "127.0.0.1:0".parse().unwrap();
    let config = NetworkConfig::IoUring(UringConfig { sq_entries: 3, ..Default::default() });
    let error = NetworkIo::new(addr, addr, &config).err().expect("invalid config accepted");
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
}
