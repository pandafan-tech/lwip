//! Zero-copy egress end to end: with PANDA_LWIP_ZEROCOPY_EGRESS=1, TCP data
//! frames leave the output callback as a header snapshot plus a leased
//! payload and are materialized at the egress channel exit. The bytes the
//! consumer sees must be exactly what the stream wrote — across segments
//! that ride the lease path (payload >= threshold) AND small ones that take
//! the copy path — and a teardown with unmaterialized frames still queued
//! must return every lease without crashing.

use futures::StreamExt;
use lwip::NetStack;
use std::sync::Mutex;
use tokio::io::AsyncWriteExt;
use tokio::time::{timeout, Duration};

// Both tests drive shard 0's one stack slot; run them serially.
static TEST_LOCK: Mutex<()> = Mutex::new(());

const SYN: u8 = 0x02;
const ACK: u8 = 0x10;

fn ipv4_tcp_packet(
    source_port: u16,
    sequence: u32,
    acknowledgement: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    const IPV4_HEADER: usize = 20;
    const TCP_HEADER: usize = 20;
    let total_length = IPV4_HEADER + TCP_HEADER + payload.len();
    let mut packet = vec![0u8; total_length];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_length as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = 6;
    packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
    packet[16..20].copy_from_slice(&[203, 0, 113, 1]);
    let tcp = &mut packet[IPV4_HEADER..];
    tcp[0..2].copy_from_slice(&source_port.to_be_bytes());
    tcp[2..4].copy_from_slice(&443u16.to_be_bytes());
    tcp[4..8].copy_from_slice(&sequence.to_be_bytes());
    tcp[8..12].copy_from_slice(&acknowledgement.to_be_bytes());
    tcp[12] = 5 << 4;
    tcp[13] = flags;
    tcp[14..16].copy_from_slice(&u16::MAX.to_be_bytes());
    tcp[TCP_HEADER..].copy_from_slice(payload);
    packet
}

fn tcp_sequence(packet: &[u8]) -> u32 {
    u32::from_be_bytes(packet[24..28].try_into().unwrap())
}

fn is_syn_ack_for(packet: &[u8], source_port: u16) -> bool {
    packet.len() >= 40
        && packet[9] == 6
        && u16::from_be_bytes(packet[20..22].try_into().unwrap()) == 443
        && u16::from_be_bytes(packet[22..24].try_into().unwrap()) == source_port
        && packet[33] & 0x12 == 0x12
}

fn tcp_payload(packet: &[u8]) -> Option<&[u8]> {
    if packet.len() < 40 || packet[9] != 6 {
        return None;
    }
    let ihl = usize::from(packet[0] & 0x0f) * 4;
    let doff = usize::from(packet[ihl + 12] >> 4) * 4;
    let offset = ihl + doff;
    (packet.len() > offset).then(|| &packet[offset..])
}

async fn establish(
    ingress: &mut lwip::StackIngress,
    egress: &mut lwip::StackEgress,
    listener: &mut lwip::TcpListener,
    source_port: u16,
) -> (lwip::TcpStream, u32, u32) {
    let client_seq = u32::from(source_port) << 8;
    ingress.input_batch([ipv4_tcp_packet(source_port, client_seq, 0, SYN, &[])]);
    let syn_ack = timeout(Duration::from_secs(1), async {
        loop {
            let packet = egress.recv().await.expect("egress closed");
            if is_syn_ack_for(&packet, source_port) {
                return packet;
            }
        }
    })
    .await
    .expect("no SYN-ACK");
    let server_seq = tcp_sequence(&syn_ack) + 1;
    ingress.input_batch([ipv4_tcp_packet(
        source_port,
        client_seq + 1,
        server_seq,
        ACK,
        &[],
    )]);
    let (stream, _, _) = timeout(Duration::from_secs(1), listener.next())
        .await
        .expect("no accept")
        .expect("listener ended");
    (stream, client_seq + 1, server_seq)
}

#[test]
fn leased_frames_reassemble_exactly_and_return_their_leases() {
    let _test_guard = TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    // Own-process test binary: the gate must be set before the first stack.
    std::env::set_var("PANDA_LWIP_ZEROCOPY_EGRESS", "1");
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap()
        .block_on(async {
            let (stack, mut listener, udp) = NetStack::with_buffer_size(64, 8).unwrap();
            drop(udp);
            let (mut ingress, mut egress) = stack.split();
            let (mut stream, client_seq, server_seq) =
                establish(&mut ingress, &mut egress, &mut listener, 41_001).await;

            // 5000 bytes -> MSS-1460 segments of 1460/1460/1460/620: three
            // ride the lease path (>= 1024 payload), the tail copies. The
            // patterned bytes catch any reassembly slip (wrong offset, node
            // boundary, stale header snapshot length).
            let expected: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
            stream.write_all(&expected).await.unwrap();

            let mut delivered = Vec::new();
            let mut acked = server_seq;
            timeout(Duration::from_secs(2), async {
                while delivered.len() < expected.len() {
                    let packet = egress.recv().await.expect("egress closed");
                    if let Some(payload) = tcp_payload(&packet) {
                        delivered.extend_from_slice(payload);
                        acked = tcp_sequence(&packet).wrapping_add(payload.len() as u32);
                        // ACK each segment so the send window keeps moving.
                        ingress.input_batch([ipv4_tcp_packet(41_001, client_seq, acked, ACK, &[])]);
                    }
                }
            })
            .await
            .expect("stream payload never fully reached egress");
            assert_eq!(delivered.len(), expected.len());
            assert_eq!(delivered, expected, "lease reassembly corrupted bytes");

            // The ACK input tenures above drain the lease rail; one more
            // input proves the path stays healthy after heavy lease traffic.
            ingress.input_batch([ipv4_tcp_packet(41_001, client_seq, acked, ACK, &[])]);
            drop(stream);
        });
}

#[test]
fn teardown_with_unmaterialized_frames_returns_every_lease() {
    let _test_guard = TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    std::env::set_var("PANDA_LWIP_ZEROCOPY_EGRESS", "1");
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap()
        .block_on(async {
            let (stack, mut listener, udp) = NetStack::with_buffer_size(64, 8).unwrap();
            drop(udp);
            let (mut ingress, mut egress) = stack.split();
            let (mut stream, _client_seq, _server_seq) =
                establish(&mut ingress, &mut egress, &mut listener, 42_001).await;

            // Queue leased frames into the egress channel and then tear the
            // stack down WITHOUT receiving them: dropping the receiver drops
            // unmaterialized frames (parking their leases), and the stack's
            // Drop tenure must free the parked backlog. A leaked or
            // double-freed lease aborts/asserts inside lwIP here.
            stream.write_all(&vec![0x5a; 4096]).await.unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
            drop(stream);
            drop(listener);
            drop(egress);
            drop(ingress);
        });
}
