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
use tokio::time::{timeout, Duration};

const CLIENT_IP: [u8; 4] = [10, 0, 0, 2];
const CLIENT_PORT: u16 = 40000;
const FOREIGN_IP: [u8; 4] = [203, 0, 113, 9];
const FOREIGN_PORT: u16 = 5353;

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

            let expected_src: SocketAddr =
                (std::net::IpAddr::from(CLIENT_IP), CLIENT_PORT).into();
            let expected_dst: SocketAddr =
                (std::net::IpAddr::from(FOREIGN_IP), FOREIGN_PORT).into();
            assert_eq!(&packet[..], payload, "payload must survive the stack");
            assert_eq!(src, expected_src, "original source tuple must be preserved");
            assert_eq!(dst, expected_dst, "original destination tuple must be preserved");

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
            assert_eq!(&reply[12..16], &FOREIGN_IP, "reply source IP must be spoofed");
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
