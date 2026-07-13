//! TCP receive-queue churn regression.
//!
//! This drives the real lwIP TCP state machine with raw IPv4 packets. Each
//! connection completes the handshake, queues one receive window without the
//! Rust consumer reading it, and is then dropped. Repeating that cycle proves
//! that the unbounded Tokio channel is flow-control bounded and, critically,
//! that dropping a stream releases every queued packet/channel allocation.

use futures::StreamExt;
use lwip::NetStack;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::time::{timeout, Duration};

struct CountingAlloc;
static ALLOCS: AtomicUsize = AtomicUsize::new(0);
static DEALLOCS: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::SeqCst);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        DEALLOCS.fetch_add(1, Ordering::SeqCst);
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAlloc = CountingAlloc;

fn live_allocations() -> i64 {
    ALLOCS.load(Ordering::SeqCst) as i64 - DEALLOCS.load(Ordering::SeqCst) as i64
}

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

async fn one_unread_window(
    ingress: &mut lwip::StackIngress,
    egress: &mut lwip::StackEgress,
    listener: &mut lwip::TcpListener,
    source_port: u16,
) {
    const SYN: u8 = 0x02;
    const ACK: u8 = 0x10;
    const PSH_ACK: u8 = 0x18;
    const SEGMENT_BYTES: usize = 1_400;
    const SEGMENTS: usize = 32;

    let client_sequence = u32::from(source_port) << 16;
    ingress.input_batch([ipv4_tcp_packet(source_port, client_sequence, 0, SYN, &[])]);
    let syn_ack = next_syn_ack(egress, source_port).await;
    let server_sequence = tcp_sequence(&syn_ack);

    ingress.input_batch([ipv4_tcp_packet(
        source_port,
        client_sequence + 1,
        server_sequence + 1,
        ACK,
        &[],
    )]);
    let (stream, _, _) = timeout(Duration::from_secs(1), listener.next())
        .await
        .expect("lwIP did not accept the completed TCP handshake")
        .expect("lwIP TCP listener ended unexpectedly");

    let payload = [0x5au8; SEGMENT_BYTES];
    let mut next_sequence = client_sequence + 1;
    for _ in 0..SEGMENTS {
        ingress.input_batch([ipv4_tcp_packet(
            source_port,
            next_sequence,
            server_sequence + 1,
            PSH_ACK,
            &payload,
        )]);
        next_sequence += SEGMENT_BYTES as u32;
    }

    let queued = lwip::tcp_runtime_stats();
    assert_eq!(queued.active_streams, 1);
    assert_eq!(queued.queued_packets, SEGMENTS);
    assert_eq!(queued.queued_bytes, SEGMENTS * SEGMENT_BYTES);

    // The receive side was never polled, so every payload is still owned by
    // TcpStreamImpl's channel here. Dropping the stream must release them all.
    drop(stream);
    let released = lwip::tcp_runtime_stats();
    assert_eq!(released.active_streams, 0);
    assert_eq!(released.queued_packets, 0);
    assert_eq!(released.queued_bytes, 0);
}

#[test]
fn dropping_unread_tcp_windows_has_zero_retention_slope() {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap()
        .block_on(run_unread_tcp_churn());
}

async fn run_unread_tcp_churn() {
    const WARMUP: u16 = 100;
    const MEASURE: u16 = 2_000;
    const MAX_RETAINED_ALLOCS_PER_CONNECTION: f64 = 0.02;

    let (stack, mut listener, udp) = NetStack::with_buffer_size(128, 8).unwrap();
    drop(udp);
    let (mut ingress, mut egress) = stack.split();

    for index in 0..WARMUP {
        one_unread_window(&mut ingress, &mut egress, &mut listener, 10_000 + index).await;
    }
    let before = live_allocations();
    for index in 0..MEASURE {
        one_unread_window(&mut ingress, &mut egress, &mut listener, 20_000 + index).await;
    }
    let after = live_allocations();
    let slope = (after - before) as f64 / f64::from(MEASURE);
    println!(
        "lwIP unread TCP churn: {MEASURE} connections, live {before} -> {after}, \
         slope={slope:+.5} retained allocations/connection"
    );

    assert!(
        slope < MAX_RETAINED_ALLOCS_PER_CONNECTION,
        "dropping an unread lwIP TCP stream retained {slope:.5} allocations/connection"
    );
}
