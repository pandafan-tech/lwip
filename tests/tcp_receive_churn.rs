//! TCP receive-queue churn regression.
//!
//! This drives the real lwIP TCP state machine with raw IPv4 packets. Each
//! connection completes the handshake, queues one receive window without the
//! Rust consumer reading it, and is then dropped. Repeating that cycle proves
//! that the Rust receive queue is flow-control bounded and, critically, that
//! dropping a stream releases every queued packet allocation.

use futures::{SinkExt, StreamExt};
use lwip::NetStack;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::task::Poll;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{timeout, Duration};

struct CountingAlloc;
static ALLOCS: AtomicUsize = AtomicUsize::new(0);
static DEALLOCS: AtomicUsize = AtomicUsize::new(0);
static TEST_LOCK: Mutex<()> = Mutex::new(());

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

fn ipv4_icmp_echo_request(payload: &[u8]) -> Vec<u8> {
    const IPV4_HEADER: usize = 20;
    const ICMP_ECHO_HEADER: usize = 8;
    let total_length = IPV4_HEADER + ICMP_ECHO_HEADER + payload.len();
    let mut packet = vec![0u8; total_length];

    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_length as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = 1;
    packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
    packet[16..20].copy_from_slice(&[203, 0, 113, 1]);

    let icmp = &mut packet[IPV4_HEADER..];
    icmp[0] = 8;
    icmp[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
    icmp[6..8].copy_from_slice(&1u16.to_be_bytes());
    icmp[ICMP_ECHO_HEADER..].copy_from_slice(payload);
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

fn tcp_mss_option(packet: &[u8]) -> Option<u16> {
    let ip_header_len = usize::from(packet.first()? & 0x0f) * 4;
    let tcp_header_len = usize::from(*packet.get(ip_header_len + 12)? >> 4) * 4;
    if tcp_header_len < 20 || packet.len() < ip_header_len + tcp_header_len {
        return None;
    }

    let mut offset = ip_header_len + 20;
    let end = ip_header_len + tcp_header_len;
    while offset < end {
        match packet[offset] {
            0 => break,
            1 => offset += 1,
            kind => {
                let length = usize::from(*packet.get(offset + 1)?);
                if length < 2 || offset + length > end {
                    return None;
                }
                if kind == 2 && length == 4 {
                    return Some(u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]));
                }
                offset += length;
            }
        }
    }
    None
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

#[test]
fn configured_mtu_controls_advertised_tcp_mss() {
    let _test_guard = TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap()
        .block_on(async {
            const SYN: u8 = 0x02;
            const ACK: u8 = 0x10;
            let (stack, mut listener, udp) =
                NetStack::with_buffer_size_and_mtu(8, 8, 9000).unwrap();
            drop(udp);
            let (mut ingress, mut egress) = stack.split();
            let source_port = 10_001;

            ingress.input_batch([ipv4_tcp_packet(source_port, 1, 0, SYN, &[])]);
            let syn_ack = next_syn_ack(&mut egress, source_port).await;

            assert_eq!(tcp_mss_option(&syn_ack), Some(8960));
            ingress.input_batch([ipv4_tcp_packet(
                source_port,
                2,
                tcp_sequence(&syn_ack) + 1,
                ACK,
                &[],
            )]);
            let (stream, _, _) = timeout(Duration::from_secs(1), listener.next())
                .await
                .expect("lwIP did not accept the MTU test connection")
                .expect("lwIP TCP listener ended during the MTU test");
            drop(stream);
        });
}

async fn establish_tcp_stream(
    ingress: &mut lwip::StackIngress,
    egress: &mut lwip::StackEgress,
    listener: &mut lwip::TcpListener,
    source_port: u16,
) -> (lwip::TcpStream, u32, u32) {
    const SYN: u8 = 0x02;
    const ACK: u8 = 0x10;

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

    (stream, client_sequence + 1, server_sequence + 1)
}

#[test]
fn accepted_tcp_write_is_not_reported_as_failed_when_egress_is_full() {
    let _test_guard = TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap()
        .block_on(async {
            let (stack, mut listener, udp) = NetStack::with_buffer_size(1, 8).unwrap();
            drop(udp);
            let (mut ingress, mut egress) = stack.split();
            let source_port = 20_001;
            let (mut stream, _, _) =
                establish_tcp_stream(&mut ingress, &mut egress, &mut listener, source_port).await;

            ingress.input_batch([ipv4_icmp_echo_request(b"fills-egress")]);
            let payload = b"accepted-before-output-pressure";
            let written = stream
                .write(payload)
                .await
                .expect("tcp_write accepted bytes must not be reported as failed");
            assert_eq!(written, payload.len());

            let prefill = timeout(Duration::from_secs(1), egress.recv())
                .await
                .expect("the egress prefill packet was not emitted")
                .expect("lwIP egress closed before the prefill packet");
            assert_eq!(prefill[9], 1);
            let emitted_payload = timeout(Duration::from_secs(1), async {
                loop {
                    let packet = egress
                        .recv()
                        .await
                        .expect("lwIP egress closed before retrying the queued TCP segment");
                    if packet[9] != 6 {
                        continue;
                    }
                    let tcp_header_len = usize::from(packet[32] >> 4) * 4;
                    let payload_offset = 20 + tcp_header_len;
                    if packet.len() > payload_offset {
                        return packet[payload_offset..].to_vec();
                    }
                }
            })
            .await
            .expect("lwIP did not retry the queued TCP segment after egress drained");
            assert_eq!(emitted_payload, payload);
        });
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
    // TcpStreamImpl's queue here. Dropping the stream must release them all.
    drop(stream);
    let released = lwip::tcp_runtime_stats();
    assert_eq!(released.active_streams, 0);
    assert_eq!(released.queued_packets, 0);
    assert_eq!(released.queued_bytes, 0);
}

#[test]
fn dropping_unread_tcp_windows_has_zero_retention_slope() {
    let _test_guard = TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
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
        "dropping an unread lwIP TCP stream or its custom input pbufs retained \
         {slope:.5} allocations/connection"
    );
}

#[test]
fn custom_input_pbufs_have_zero_retention_through_batch_and_sink() {
    let _test_guard = TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap()
        .block_on(async {
            const WARMUP: usize = 32;
            const MEASURE: usize = 1_000;

            fn invalid_ipv4_packet() -> Vec<u8> {
                let mut packet = vec![0u8; 20];
                packet[0] = 0x50;
                packet[2..4].copy_from_slice(&20u16.to_be_bytes());
                packet
            }

            let (stack, listener, udp) = NetStack::with_buffer_size(128, 8).unwrap();
            drop(udp);
            let (mut ingress, egress) = stack.split();
            for _ in 0..WARMUP {
                ingress.input_batch([invalid_ipv4_packet()]);
            }
            let before_batch = live_allocations();
            for _ in 0..MEASURE {
                ingress.input_batch([invalid_ipv4_packet()]);
            }
            let after_batch = live_allocations();
            assert!(
                after_batch <= before_batch,
                "batch input retained an owned input Vec/custom pbuf: {before_batch} -> {after_batch}"
            );
            drop(listener);
            drop(ingress);
            drop(egress);

            let (mut stack, listener, udp) = NetStack::with_buffer_size(128, 8).unwrap();
            drop(udp);
            for _ in 0..WARMUP {
                stack.send(invalid_ipv4_packet()).await.unwrap();
            }
            let before_sink = live_allocations();
            for _ in 0..MEASURE {
                stack.send(invalid_ipv4_packet()).await.unwrap();
            }
            let after_sink = live_allocations();
            assert!(
                after_sink <= before_sink,
                "Sink input retained an owned input Vec/custom pbuf: {before_sink} -> {after_sink}"
            );
            drop(listener);
            drop(stack);
        });
}

#[test]
fn custom_input_pbuf_preserves_ipv4_icmp_echo_replies() {
    let _test_guard = TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap()
        .block_on(async {
            let payload = b"custom-pbuf-echo";
            let (stack, listener, udp) = NetStack::with_buffer_size(8, 8).unwrap();
            drop(listener);
            drop(udp);
            let (mut ingress, mut egress) = stack.split();

            ingress.input_batch([ipv4_icmp_echo_request(payload)]);
            let reply = timeout(Duration::from_secs(1), egress.recv())
                .await
                .expect("lwIP did not emit an ICMP echo reply")
                .expect("lwIP egress closed before the ICMP echo reply");

            assert_eq!(reply[9], 1);
            assert_eq!(&reply[12..16], &[203, 0, 113, 1]);
            assert_eq!(&reply[16..20], &[10, 0, 0, 2]);
            assert_eq!(reply[20], 0);
            assert_eq!(&reply[28..], payload);
        });
}

#[test]
fn payload_is_read_before_fin_becomes_sticky_eof() {
    let _test_guard = TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap()
        .block_on(async {
            const PSH_ACK: u8 = 0x18;
            const FIN_ACK: u8 = 0x11;
            let payload = [0xabu8; 1_400];
            let (stack, mut listener, udp) = NetStack::with_buffer_size(128, 8).unwrap();
            drop(udp);
            let (mut ingress, mut egress) = stack.split();
            let source_port = 50_000;
            let (mut stream, client_sequence, server_sequence) =
                establish_tcp_stream(&mut ingress, &mut egress, &mut listener, source_port).await;

            ingress.input_batch([
                ipv4_tcp_packet(
                    source_port,
                    client_sequence,
                    server_sequence,
                    PSH_ACK,
                    &payload,
                ),
                ipv4_tcp_packet(
                    source_port,
                    client_sequence + payload.len() as u32,
                    server_sequence,
                    FIN_ACK,
                    &[],
                ),
            ]);

            let mut received = vec![0u8; payload.len() * 2];
            let payload_read = timeout(Duration::from_secs(1), stream.read(&mut received))
                .await
                .expect("payload read timed out")
                .expect("payload read failed");
            assert_eq!(payload_read, payload.len());
            assert_eq!(&received[..payload_read], payload);
            assert_eq!(lwip::tcp_runtime_stats().queued_packets, 0);
            assert_eq!(lwip::tcp_runtime_stats().queued_bytes, 0);

            let first_eof = stream.read(&mut received).await.unwrap();
            let second_eof = stream.read(&mut received).await.unwrap();
            assert_eq!(first_eof, 0);
            assert_eq!(second_eof, 0);
        });
}

#[test]
fn one_large_read_drains_all_queued_packets_and_counters() {
    let _test_guard = TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap()
        .block_on(async {
            const PSH_ACK: u8 = 0x18;
            const SEGMENT_BYTES: usize = 1_400;
            const SEGMENTS: usize = 4;
            let (stack, mut listener, udp) = NetStack::with_buffer_size(128, 8).unwrap();
            drop(udp);
            let (mut ingress, mut egress) = stack.split();
            let source_port = 50_005;
            let (mut stream, client_sequence, server_sequence) =
                establish_tcp_stream(&mut ingress, &mut egress, &mut listener, source_port).await;

            ingress.input_batch((0..SEGMENTS).map(|index| {
                let payload = [index as u8; SEGMENT_BYTES];
                ipv4_tcp_packet(
                    source_port,
                    client_sequence + (index * SEGMENT_BYTES) as u32,
                    server_sequence,
                    PSH_ACK,
                    &payload,
                )
            }));
            let queued = lwip::tcp_runtime_stats();
            assert_eq!(queued.queued_packets, SEGMENTS);
            assert_eq!(queued.queued_bytes, SEGMENTS * SEGMENT_BYTES);

            let mut received = vec![0u8; SEGMENTS * SEGMENT_BYTES];
            let read = stream.read(&mut received).await.unwrap();
            assert_eq!(read, received.len());
            for (index, segment) in received.chunks_exact(SEGMENT_BYTES).enumerate() {
                assert!(segment.iter().all(|byte| *byte == index as u8));
            }

            let drained = lwip::tcp_runtime_stats();
            assert_eq!(drained.queued_packets, 0);
            assert_eq!(drained.queued_bytes, 0);
        });
}

#[test]
fn remote_fin_is_sticky_eof() {
    let _test_guard = TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap()
        .block_on(async {
            const FIN_ACK: u8 = 0x11;
            let (stack, mut listener, udp) = NetStack::with_buffer_size(128, 8).unwrap();
            drop(udp);
            let (mut ingress, mut egress) = stack.split();
            let source_port = 50_001;
            let (mut stream, client_sequence, server_sequence) =
                establish_tcp_stream(&mut ingress, &mut egress, &mut listener, source_port).await;

            ingress.input_batch([ipv4_tcp_packet(
                source_port,
                client_sequence,
                server_sequence,
                FIN_ACK,
                &[],
            )]);

            let mut byte = [0u8; 1];
            let first = timeout(Duration::from_secs(1), stream.read(&mut byte))
                .await
                .expect("first EOF read timed out")
                .expect("first EOF read failed");
            assert_eq!(first, 0);

            let second = timeout(Duration::from_millis(100), stream.read(&mut byte))
                .await
                .expect("EOF must remain ready on every subsequent read")
                .expect("second EOF read failed");
            assert_eq!(second, 0);
        });
}

#[test]
fn remote_fin_is_not_a_queued_packet() {
    let _test_guard = TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap()
        .block_on(async {
            const FIN_ACK: u8 = 0x11;
            let (stack, mut listener, udp) = NetStack::with_buffer_size(128, 8).unwrap();
            drop(udp);
            let (mut ingress, mut egress) = stack.split();
            let source_port = 50_002;
            let (stream, client_sequence, server_sequence) =
                establish_tcp_stream(&mut ingress, &mut egress, &mut listener, source_port).await;

            assert_eq!(lwip::tcp_runtime_stats().queued_packets, 0);
            ingress.input_batch([ipv4_tcp_packet(
                source_port,
                client_sequence,
                server_sequence,
                FIN_ACK,
                &[],
            )]);

            let after_fin = lwip::tcp_runtime_stats();
            assert_eq!(after_fin.queued_packets, 0);
            assert_eq!(after_fin.queued_bytes, 0);
            drop(stream);
        });
}

#[test]
fn partial_read_continues_into_the_next_queued_packet() {
    let _test_guard = TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap()
        .block_on(async {
            const PSH_ACK: u8 = 0x18;
            const SEGMENT_BYTES: usize = 1_400;
            let (stack, mut listener, udp) = NetStack::with_buffer_size(128, 8).unwrap();
            drop(udp);
            let (mut ingress, mut egress) = stack.split();
            let source_port = 50_003;
            let (mut stream, client_sequence, server_sequence) =
                establish_tcp_stream(&mut ingress, &mut egress, &mut listener, source_port).await;
            let first_payload = [0x11u8; SEGMENT_BYTES];
            let second_payload = [0x22u8; SEGMENT_BYTES];
            ingress.input_batch([
                ipv4_tcp_packet(
                    source_port,
                    client_sequence,
                    server_sequence,
                    PSH_ACK,
                    &first_payload,
                ),
                ipv4_tcp_packet(
                    source_port,
                    client_sequence + SEGMENT_BYTES as u32,
                    server_sequence,
                    PSH_ACK,
                    &second_payload,
                ),
            ]);

            let mut first_byte = [0u8; 1];
            assert_eq!(stream.read(&mut first_byte).await.unwrap(), 1);
            assert_eq!(first_byte, [0x11]);

            let mut remaining = vec![0u8; SEGMENT_BYTES * 2 - 1];
            let read = stream.read(&mut remaining).await.unwrap();
            assert_eq!(
                read,
                remaining.len(),
                "a ready packet after a partial packet must fill the caller's remaining capacity"
            );
            assert!(remaining[..SEGMENT_BYTES - 1]
                .iter()
                .all(|byte| *byte == 0x11));
            assert!(remaining[SEGMENT_BYTES - 1..]
                .iter()
                .all(|byte| *byte == 0x22));
        });
}

#[test]
fn rst_wakes_a_pending_reader() {
    let _test_guard = TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap()
        .block_on(async {
            const RST_ACK: u8 = 0x14;
            let (stack, mut listener, udp) = NetStack::with_buffer_size(128, 8).unwrap();
            drop(udp);
            let (mut ingress, mut egress) = stack.split();
            let source_port = 50_004;
            let (mut stream, client_sequence, server_sequence) =
                establish_tcp_stream(&mut ingress, &mut egress, &mut listener, source_port).await;

            let mut byte = [0u8; 1];
            let mut pending_read = Box::pin(stream.read(&mut byte));
            assert!(matches!(
                futures::poll!(pending_read.as_mut()),
                Poll::Pending
            ));

            ingress.input_batch([ipv4_tcp_packet(
                source_port,
                client_sequence,
                server_sequence,
                RST_ACK,
                &[],
            )]);

            let error = timeout(Duration::from_secs(1), pending_read)
                .await
                .expect("RST did not wake the pending reader")
                .expect_err("RST must fail the pending read");
            assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
        });
}
