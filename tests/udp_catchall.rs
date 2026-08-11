//! UDP catch-all delivery regression.
//!
//! The lwIP 2.2.1 re-vendor mis-applied the TUN2SOCKS catch-all `break` to
//! `udp_new_port` instead of `udp_input`'s PCB-matching loop, so inbound
//! datagrams to foreign destinations never matched the single catch-all PCB
//! and were dropped as "not for us" while TCP kept flowing. This drives a raw
//! IPv4/UDP datagram through the real stack and asserts both directions:
//! inbound delivery with the original src/dst tuple, and the spoofed-source
//! reply on egress.

use lwip::NetStack;
use std::net::SocketAddr;
use std::sync::Mutex;
use tokio::time::{timeout, Duration};

const CLIENT_IP: [u8; 4] = [10, 0, 0, 2];
const CLIENT_PORT: u16 = 40000;
const FOREIGN_IP: [u8; 4] = [203, 0, 113, 9];
const FOREIGN_PORT: u16 = 5353;
static TEST_LOCK: Mutex<()> = Mutex::new(());

fn ipv4_udp_packet(payload: &[u8]) -> Vec<u8> {
    const IPV4_HEADER: usize = 20;
    const UDP_HEADER: usize = 8;
    let total_length = IPV4_HEADER + UDP_HEADER + payload.len();
    let mut packet = vec![0u8; total_length];

    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_length as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&CLIENT_IP);
    packet[16..20].copy_from_slice(&FOREIGN_IP);

    let udp = &mut packet[IPV4_HEADER..];
    udp[0..2].copy_from_slice(&CLIENT_PORT.to_be_bytes());
    udp[2..4].copy_from_slice(&FOREIGN_PORT.to_be_bytes());
    udp[4..6].copy_from_slice(&((UDP_HEADER + payload.len()) as u16).to_be_bytes());
    // checksum 0 = "no checksum" for IPv4 UDP
    udp[UDP_HEADER..].copy_from_slice(payload);
    packet
}

#[test]
fn udp_catchall_delivers_and_replies_with_original_tuple() {
    let _test_guard = TEST_LOCK.lock().unwrap();
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap()
        .block_on(async {
            let payload = b"udp-catchall-probe";
            let (stack, listener, udp) = NetStack::with_buffer_size(8, 8).unwrap();
            drop(listener);
            let (send_half, mut recv_half) = udp.split();
            let (mut ingress, mut egress) = stack.split();

            // Inbound: a datagram to a foreign destination must reach the
            // catch-all PCB with the original tuple intact.
            ingress.input_batch([ipv4_udp_packet(payload)]);
            let (packet, src, dst) = timeout(Duration::from_secs(1), recv_half.recv_from())
                .await
                .expect("catch-all UDP PCB never saw the datagram")
                .expect("udp socket closed before delivering the datagram");

            let expected_src: SocketAddr = (std::net::IpAddr::from(CLIENT_IP), CLIENT_PORT).into();
            let expected_dst: SocketAddr =
                (std::net::IpAddr::from(FOREIGN_IP), FOREIGN_PORT).into();
            assert_eq!(&packet[..], payload, "payload must survive the stack");
            assert_eq!(src, expected_src, "original source tuple must be preserved");
            assert_eq!(
                dst, expected_dst,
                "original destination tuple must be preserved"
            );

            // Reply: sending with the foreign tuple as source must egress an
            // IPv4/UDP packet spoofing that source back to the client.
            let reply_payload = b"udp-catchall-reply";
            send_half
                .send_to(reply_payload, &expected_dst, &expected_src)
                .expect("spoofed-source UDP reply send failed");
            let reply = timeout(Duration::from_secs(1), egress.recv())
                .await
                .expect("lwIP did not emit the UDP reply")
                .expect("lwIP egress closed before the UDP reply");

            assert_eq!(reply[9], 17, "reply must be UDP");
            assert_eq!(
                &reply[12..16],
                &FOREIGN_IP,
                "reply source IP must be spoofed"
            );
            assert_eq!(&reply[16..20], &CLIENT_IP, "reply must target the client");
            assert_eq!(
                u16::from_be_bytes([reply[20], reply[21]]),
                FOREIGN_PORT,
                "reply source port must be spoofed"
            );
            assert_eq!(
                u16::from_be_bytes([reply[22], reply[23]]),
                CLIENT_PORT,
                "reply destination port must be the client port"
            );
            assert_eq!(&reply[28..], reply_payload);
        });
}

#[test]
fn udp_send_reports_a_full_egress_queue_instead_of_silently_dropping() {
    let _test_guard = TEST_LOCK.lock().unwrap();
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap()
        .block_on(async {
            let (stack, listener, udp) = NetStack::with_buffer_size(1, 1).unwrap();
            drop(listener);
            let (send_half, _recv_half) = udp.split();
            let (_ingress, _egress) = stack.split();
            let source: SocketAddr = (std::net::IpAddr::from(FOREIGN_IP), FOREIGN_PORT).into();
            let destination: SocketAddr = (std::net::IpAddr::from(CLIENT_IP), CLIENT_PORT).into();

            send_half
                .send_to(b"fills-egress", &source, &destination)
                .expect("the first datagram must occupy the only egress slot");
            let error = send_half
                .send_to(b"must-not-disappear", &source, &destination)
                .expect_err("a full egress queue must not report a dropped datagram as sent");

            assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
        });
}

#[test]
fn fragmented_udp_send_is_atomic_when_egress_lacks_slots() {
    let _test_guard = TEST_LOCK.lock().unwrap();
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap()
        .block_on(async {
            let (stack, listener, udp) = NetStack::with_buffer_size(3, 1).unwrap();
            drop(listener);
            let (send_half, _recv_half) = udp.split();
            let (_ingress, mut egress) = stack.split();
            let source: SocketAddr = (std::net::IpAddr::from(FOREIGN_IP), FOREIGN_PORT).into();
            let destination: SocketAddr = (std::net::IpAddr::from(CLIENT_IP), CLIENT_PORT).into();
            let payload = vec![0x5a; 3000];

            send_half
                .send_to(b"prefill", &source, &destination)
                .expect("the prefill datagram must occupy one egress slot");
            let error = send_half
                .send_to(&payload, &source, &destination)
                .expect_err("all fragments must wait until the bounded queue has enough slots");
            assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
            let prefill = timeout(Duration::from_secs(1), egress.recv())
                .await
                .expect("the prefill datagram was not emitted")
                .expect("lwIP egress closed before the prefill datagram");
            assert_eq!(&prefill[28..], b"prefill");
            assert!(
                timeout(Duration::from_millis(10), egress.recv())
                    .await
                    .is_err(),
                "a failed atomic send must not leak an initial fragment"
            );
        });
}

#[test]
fn fragmented_udp_send_emits_every_fragment_in_order() {
    let _test_guard = TEST_LOCK.lock().unwrap();
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap()
        .block_on(async {
            let (stack, listener, udp) = NetStack::with_buffer_size(3, 1).unwrap();
            drop(listener);
            let (send_half, _recv_half) = udp.split();
            let (_ingress, mut egress) = stack.split();
            let source: SocketAddr = (std::net::IpAddr::from(FOREIGN_IP), FOREIGN_PORT).into();
            let destination: SocketAddr = (std::net::IpAddr::from(CLIENT_IP), CLIENT_PORT).into();
            let payload = vec![0x5a; 3000];

            send_half
                .send_to_wait(&payload, &source, &destination)
                .await
                .expect("a three-slot queue must atomically accept all three fragments");

            let mut reassembled = vec![0u8; payload.len() + 8];
            for expected_index in 0..3 {
                let fragment = timeout(Duration::from_secs(1), egress.recv())
                    .await
                    .expect("a UDP fragment was not emitted")
                    .expect("lwIP egress closed before every fragment was emitted");
                let total_len = usize::from(u16::from_be_bytes([fragment[2], fragment[3]]));
                let flags_offset = u16::from_be_bytes([fragment[6], fragment[7]]);
                let offset = usize::from(flags_offset & 0x1fff) * 8;
                let more_fragments = flags_offset & 0x2000 != 0;
                assert_eq!(offset, expected_index * 1480);
                assert_eq!(more_fragments, expected_index < 2);
                reassembled[offset..offset + total_len - 20]
                    .copy_from_slice(&fragment[20..total_len]);
            }

            assert_eq!(&reassembled[8..], payload.as_slice());
            assert_eq!(
                u16::from_be_bytes([reassembled[4], reassembled[5]]),
                (payload.len() + 8) as u16
            );
        });
}

#[test]
fn fragmented_udp_send_fails_when_one_datagram_exceeds_queue_capacity() {
    let _test_guard = TEST_LOCK.lock().unwrap();
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap()
        .block_on(async {
            let (stack, listener, udp) = NetStack::with_buffer_size(2, 1).unwrap();
            drop(listener);
            let (send_half, _recv_half) = udp.split();
            let (_ingress, mut egress) = stack.split();
            let source: SocketAddr = (std::net::IpAddr::from(FOREIGN_IP), FOREIGN_PORT).into();
            let destination: SocketAddr = (std::net::IpAddr::from(CLIENT_IP), CLIENT_PORT).into();
            let payload = vec![0x5a; 3000];

            let error = timeout(
                Duration::from_secs(1),
                send_half.send_to_wait(&payload, &source, &destination),
            )
            .await
            .expect("an impossible reservation must fail instead of waiting forever")
            .expect_err("a two-slot queue cannot atomically hold three fragments");
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
            assert!(
                timeout(Duration::from_millis(10), egress.recv())
                    .await
                    .is_err(),
                "a rejected oversized reservation must not emit partial fragments"
            );
        });
}

#[test]
fn udp_send_waits_for_egress_capacity_and_preserves_order() {
    let _test_guard = TEST_LOCK.lock().unwrap();
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap()
        .block_on(async {
            let (stack, listener, udp) = NetStack::with_buffer_size(1, 1).unwrap();
            drop(listener);
            let (send_half, _recv_half) = udp.split();
            let (_ingress, mut egress) = stack.split();
            let source: SocketAddr = (std::net::IpAddr::from(FOREIGN_IP), FOREIGN_PORT).into();
            let destination: SocketAddr = (std::net::IpAddr::from(CLIENT_IP), CLIENT_PORT).into();

            send_half
                .send_to(b"first", &source, &destination)
                .expect("the first datagram must occupy the only egress slot");
            let send_task = tokio::spawn(async move {
                send_half
                    .send_to_wait(b"second", &source, &destination)
                    .await
            });
            tokio::task::yield_now().await;
            assert!(
                !send_task.is_finished(),
                "the second send must wait while the bounded egress queue is full"
            );

            let first = timeout(Duration::from_secs(1), egress.recv())
                .await
                .expect("the first datagram was not emitted")
                .expect("lwIP egress closed before the first datagram");
            assert_eq!(&first[28..], b"first");

            timeout(Duration::from_secs(1), send_task)
                .await
                .expect("the waiting send was not woken after capacity became available")
                .expect("the waiting send task panicked")
                .expect("the waiting send failed");
            let second = timeout(Duration::from_secs(1), egress.recv())
                .await
                .expect("the second datagram was not emitted")
                .expect("lwIP egress closed before the second datagram");
            assert_eq!(&second[28..], b"second");
        });
}

#[test]
fn udp_send_wait_returns_broken_pipe_when_egress_is_closed() {
    let _test_guard = TEST_LOCK.lock().unwrap();
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap()
        .block_on(async {
            let (stack, listener, udp) = NetStack::with_buffer_size(1, 1).unwrap();
            drop(listener);
            let (send_half, _recv_half) = udp.split();
            let (_ingress, egress) = stack.split();
            drop(egress);
            let source: SocketAddr = (std::net::IpAddr::from(FOREIGN_IP), FOREIGN_PORT).into();
            let destination: SocketAddr = (std::net::IpAddr::from(CLIENT_IP), CLIENT_PORT).into();

            let error = send_half
                .send_to_wait(b"closed", &source, &destination)
                .await
                .expect_err("a closed egress queue must fail");
            assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
        });
}
