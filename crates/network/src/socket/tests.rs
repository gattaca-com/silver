use std::{
    net::{Ipv4Addr, UdpSocket},
    time::Duration,
};

use mio::Events;

use super::*;

#[test]
fn receive_responses_own_their_bytes_until_flush() {
    let mut poll = Poll::new().unwrap();
    let mut socket = Socket::new("127.0.0.1:0".parse().unwrap(), &poll, Token(0)).unwrap();
    let local = (Ipv4Addr::LOCALHOST, socket.socket.local_addr().unwrap().port());
    let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let packets: [&[u8]; 2] = [b"first response", b"second"];
    for packet in packets {
        peer.send_to(packet, local).unwrap();
    }

    poll.poll(&mut Events::with_capacity(8), Some(Duration::from_secs(2))).unwrap();
    let mut scratch = Vec::new();
    let mut received = 0;
    socket.recv(&poll, &mut scratch, |data, remote, reply| {
        assert_eq!(remote, peer.local_addr().unwrap());
        assert_eq!(data.as_ref(), packets[received]);
        received += 1;
        reply.extend_from_slice(&data);
        Some(Transmit {
            destination: remote,
            size: data.len(),
            ecn: None,
            segment_size: None,
            src_ip: None,
        })
    });
    assert_eq!(received, packets.len());
    scratch.clear();
    scratch.resize(2048, 0xff);
    assert!(socket.flush(&poll));

    let mut buffer = [0; 64];
    for packet in packets {
        let (size, _) = peer.recv_from(&mut buffer).unwrap();
        assert_eq!(&buffer[..size], packet);
    }
}

#[test]
fn retained_receive_survives_the_next_batch() {
    let mut poll = Poll::new().unwrap();
    let mut socket = Socket::new("127.0.0.1:0".parse().unwrap(), &poll, Token(0)).unwrap();
    let local = (Ipv4Addr::LOCALHOST, socket.socket.local_addr().unwrap().port());
    let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let packets: [&[u8]; 2] = [b"retained receive", b"next batch"];
    let mut received = Vec::new();
    let mut scratch = Vec::new();

    for packet in packets {
        peer.send_to(packet, local).unwrap();
        poll.poll(&mut Events::with_capacity(8), Some(Duration::from_secs(2))).unwrap();
        socket.recv(&poll, &mut scratch, |data, _, _| {
            received.push(data);
            None
        });
    }

    assert_eq!(received.len(), packets.len());
    for (data, packet) in received.iter().zip(packets) {
        assert_eq!(data.as_ref(), packet);
    }
}

#[test]
fn blocked_or_full_transmit_queue_does_not_consume_producer() {
    let poll = Poll::new().unwrap();
    let mut socket = Socket::new("127.0.0.1:0".parse().unwrap(), &poll, Token(0)).unwrap();
    socket.set_blocked(true, &poll).unwrap();
    assert!(!socket.send(&poll, |_| panic!("blocked queue consumed a transmit")));

    socket.set_blocked(false, &poll).unwrap();
    for _ in 0..socket.tx_batch.bufs.len() {
        socket.tx_batch.commit(&Transmit {
            destination: "127.0.0.1:1".parse().unwrap(),
            size: 0,
            ecn: None,
            segment_size: None,
            src_ip: None,
        });
    }
    assert!(!socket.send(&poll, |_| panic!("full queue consumed a transmit")));
}
