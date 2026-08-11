//! Two complete stacks on different shards, one process, real TCP traffic.
//!
//! shard_isolation proves the C globals are separate at the symbol level;
//! this proves the whole wrapper path — handshake, accept, payload delivery,
//! egress — runs on both shards CONCURRENTLY, with each connection's packets
//! confined to its own shard's ingress/egress pair.

use futures::StreamExt;
use lwip::NetStack;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{timeout, Duration};

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
    assert!(packet.len() >= 40, "lwIP emitted a truncated TCP packet");
    u32::from_be_bytes(packet[24..28].try_into().unwrap())
}

fn is_syn_ack_for(packet: &[u8], source_port: u16) -> bool {
    packet.len() >= 40
        && u16::from_be_bytes(packet[20..22].try_into().unwrap()) == 443
        && u16::from_be_bytes(packet[22..24].try_into().unwrap()) == source_port
        && packet[33] & 0x12 == 0x12
}

fn tcp_payload(packet: &[u8]) -> Option<&[u8]> {
    if packet.len() < 40 || packet[9] != 6 {
        return None;
    }
    let tcp_header_len = usize::from(packet[32] >> 4) * 4;
    let payload_offset = 20 + tcp_header_len;
    (packet.len() > payload_offset).then(|| &packet[payload_offset..])
}

async fn next_syn_ack(egress: &mut lwip::StackEgress, source_port: u16) -> lwip::IpPacket {
    timeout(Duration::from_secs(1), async {
        loop {
            let packet = egress
                .recv()
                .await
                .expect("lwIP egress closed unexpectedly");
            if is_syn_ack_for(&packet, source_port) {
                return packet;
            }
        }
    })
    .await
    .expect("lwIP did not emit an expected SYN-ACK")
}

struct ShardLane {
    ingress: lwip::StackIngress,
    egress: lwip::StackEgress,
    listener: lwip::TcpListener,
    source_port: u16,
}

impl ShardLane {
    fn new(shard_id: usize, source_port: u16) -> Self {
        let (stack, listener, udp) =
            NetStack::new_sharded(shard_id, 8, 8, 1500).expect("shard stack creation failed");
        drop(udp);
        let (ingress, egress) = stack.split();
        ShardLane {
            ingress,
            egress,
            listener,
            source_port,
        }
    }
}

#[test]
fn two_shards_carry_independent_tcp_connections_concurrently() {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap()
        .block_on(async {
            let mut lane0 = ShardLane::new(0, 40_001);
            let mut lane1 = ShardLane::new(1, 40_002);

            // Interleave the handshakes across the two stacks: SYNs first,
            // then each ACK, so neither connection completes before the other
            // stack has started working.
            let seq0 = u32::from(lane0.source_port) << 8;
            let seq1 = u32::from(lane1.source_port) << 8;
            lane0
                .ingress
                .input_batch([ipv4_tcp_packet(lane0.source_port, seq0, 0, SYN, &[])]);
            lane1
                .ingress
                .input_batch([ipv4_tcp_packet(lane1.source_port, seq1, 0, SYN, &[])]);
            let syn_ack0 = next_syn_ack(&mut lane0.egress, lane0.source_port).await;
            let syn_ack1 = next_syn_ack(&mut lane1.egress, lane1.source_port).await;
            let srv0 = tcp_sequence(&syn_ack0) + 1;
            let srv1 = tcp_sequence(&syn_ack1) + 1;
            lane0.ingress.input_batch([ipv4_tcp_packet(
                lane0.source_port,
                seq0 + 1,
                srv0,
                ACK,
                &[],
            )]);
            lane1.ingress.input_batch([ipv4_tcp_packet(
                lane1.source_port,
                seq1 + 1,
                srv1,
                ACK,
                &[],
            )]);

            let (mut stream0, _, _) = timeout(Duration::from_secs(1), lane0.listener.next())
                .await
                .expect("shard 0 did not accept its handshake")
                .expect("shard 0 listener ended");
            let (mut stream1, _, _) = timeout(Duration::from_secs(1), lane1.listener.next())
                .await
                .expect("shard 1 did not accept its handshake")
                .expect("shard 1 listener ended");

            // Client -> server payloads, again interleaved. Each must arrive
            // on its own stream with its own bytes.
            let payload0 = b"shard-zero-inbound".as_slice();
            let payload1 = b"shard-one-inbound".as_slice();
            lane0.ingress.input_batch([ipv4_tcp_packet(
                lane0.source_port,
                seq0 + 1,
                srv0,
                ACK,
                payload0,
            )]);
            lane1.ingress.input_batch([ipv4_tcp_packet(
                lane1.source_port,
                seq1 + 1,
                srv1,
                ACK,
                payload1,
            )]);

            let mut buf0 = vec![0u8; payload0.len()];
            let mut buf1 = vec![0u8; payload1.len()];
            timeout(Duration::from_secs(1), stream0.read_exact(&mut buf0))
                .await
                .expect("shard 0 payload never reached the stream")
                .unwrap();
            timeout(Duration::from_secs(1), stream1.read_exact(&mut buf1))
                .await
                .expect("shard 1 payload never reached the stream")
                .unwrap();
            assert_eq!(buf0, payload0);
            assert_eq!(buf1, payload1);

            // Server -> client: each reply must egress from ITS shard only,
            // carrying its own bytes.
            let reply0 = b"shard-zero-outbound".as_slice();
            let reply1 = b"shard-one-outbound".as_slice();
            stream0.write_all(reply0).await.unwrap();
            stream1.write_all(reply1).await.unwrap();

            let emitted0 = timeout(Duration::from_secs(1), async {
                loop {
                    let packet = lane0.egress.recv().await.expect("shard 0 egress closed");
                    if let Some(payload) = tcp_payload(&packet) {
                        return payload.to_vec();
                    }
                }
            })
            .await
            .expect("shard 0 never emitted its reply");
            let emitted1 = timeout(Duration::from_secs(1), async {
                loop {
                    let packet = lane1.egress.recv().await.expect("shard 1 egress closed");
                    if let Some(payload) = tcp_payload(&packet) {
                        return payload.to_vec();
                    }
                }
            })
            .await
            .expect("shard 1 never emitted its reply");
            assert_eq!(emitted0, reply0, "shard 0 reply corrupted or crossed");
            assert_eq!(emitted1, reply1, "shard 1 reply corrupted or crossed");

            drop(stream0);
            drop(stream1);
        });
}

#[test]
fn out_of_range_shard_is_rejected() {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap()
        .block_on(async {
            let error = NetStack::new_sharded(lwip::shard_count(), 8, 8, 1500)
                .err()
                .expect("an out-of-range shard id must be rejected");
            assert!(matches!(error, lwip::Error::RuntimeConfig(_)));
        });
}
