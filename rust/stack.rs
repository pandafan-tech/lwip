use std::{io, pin::Pin};

use futures::sink::Sink;
use futures::stream::Stream;
use futures::task::{Context, Poll};
use tokio::sync::mpsc::Receiver;

use super::shard;
use super::stack_impl::{retry_backpressured_tcp_output, NetStackImpl, DEFAULT_MTU};
use super::tcp_listener::TcpListener;
use super::udp::UdpSocket;
use crate::{Error, IpPacket};

pub struct NetStack(Box<NetStackImpl>);

impl NetStack {
    pub fn new() -> Result<(Self, TcpListener, Box<UdpSocket>), Error> {
        Self::build(shard::primary(), 512, 64, DEFAULT_MTU)
    }

    pub fn with_buffer_size(
        stack_buffer_size: usize,
        udp_buffer_size: usize,
    ) -> Result<(Self, TcpListener, Box<UdpSocket>), Error> {
        Self::build(
            shard::primary(),
            stack_buffer_size,
            udp_buffer_size,
            DEFAULT_MTU,
        )
    }

    pub fn with_buffer_size_and_mtu(
        stack_buffer_size: usize,
        udp_buffer_size: usize,
        mtu: u16,
    ) -> Result<(Self, TcpListener, Box<UdpSocket>), Error> {
        Self::build(shard::primary(), stack_buffer_size, udp_buffer_size, mtu)
    }

    /// A complete, independent stack instance on the given shard (0 =
    /// primary; ids up to [`crate::shard_count`]` - 1` address the extra
    /// symbol-prefixed copies of lwIP). Stacks on different shards share no
    /// state — no lock, no pools, no pcb lists — so they run fully in
    /// parallel; the caller owns steering each flow's packets to the shard
    /// that carries it.
    pub fn new_sharded(
        shard_id: usize,
        stack_buffer_size: usize,
        udp_buffer_size: usize,
        mtu: u16,
    ) -> Result<(Self, TcpListener, Box<UdpSocket>), Error> {
        let shard = shard::get(shard_id).ok_or_else(|| {
            Error::RuntimeConfig(format!(
                "shard {shard_id} out of range; this build carries {} stacks",
                shard::shard_count()
            ))
        })?;
        Self::build(shard, stack_buffer_size, udp_buffer_size, mtu)
    }

    fn build(
        shard: shard::ShardRef,
        stack_buffer_size: usize,
        udp_buffer_size: usize,
        mtu: u16,
    ) -> Result<(Self, TcpListener, Box<UdpSocket>), Error> {
        let stack = NetStackImpl::new_with_mtu(stack_buffer_size, mtu, shard);
        let udp = UdpSocket::new(udp_buffer_size, stack.egress_sender(), mtu, shard)?;
        Ok((NetStack(stack), TcpListener::new(shard)?, udp))
    }

    /// Split into an ingress half (batch input into lwIP) and an egress half
    /// (a plain channel of packets leaving lwIP). The two halves can be
    /// driven from different tasks so TUN read and TUN write directions no
    /// longer serialize on one driver task.
    pub fn split(mut self) -> (StackIngress, StackEgress) {
        let shard = self.0.shard;
        let rx = self.0.take_egress();
        (StackIngress(self.0), StackEgress(rx, shard))
    }
}

/// Ingress half: feeds whole read batches into lwIP under one lock hold.
/// Dropping it tears the stack down (it owns the `NetStackImpl`).
pub struct StackIngress(Box<NetStackImpl>);

impl StackIngress {
    /// Push a batch of raw IP packets into lwIP. One `LWIP_MUTEX` acquisition
    /// covers the whole batch.
    pub fn input_batch<I>(&mut self, items: I)
    where
        I: IntoIterator<Item = Vec<u8>>,
    {
        self.0.input_batch(items);
    }
}

/// Egress half: packets leaving lwIP toward the TUN device. Ends (returns
/// `None`) after the ingress half is dropped.
pub struct StackEgress(Receiver<IpPacket>, shard::ShardRef);

impl StackEgress {
    pub async fn recv(&mut self) -> Option<IpPacket> {
        let mut packet = self.0.recv().await;
        if let Some(packet) = packet.as_mut() {
            // Materialize a zero-copy frame here, on the consumer's task —
            // this memcpy is exactly the one the output callback no longer
            // spends shard-lock tenure on.
            packet.finalize();
            retry_backpressured_tcp_output(self.1);
        }
        packet
    }

    /// Receive up to `limit` packets in one call, awaiting until at least one
    /// is available. Returns the number received (0 = channel closed).
    pub async fn recv_many(&mut self, buffer: &mut Vec<IpPacket>, limit: usize) -> usize {
        let received_from = buffer.len();
        let count = self.0.recv_many(buffer, limit).await;
        for packet in &mut buffer[received_from..] {
            packet.finalize();
        }
        if count > 0 {
            retry_backpressured_tcp_output(self.1);
        }
        count
    }
}

impl Stream for NetStack {
    type Item = io::Result<IpPacket>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.0).poll_next(cx)
    }
}

impl Sink<Vec<u8>> for NetStack {
    type Error = io::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.0).poll_ready(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, item: Vec<u8>) -> Result<(), Self::Error> {
        Pin::new(&mut self.0).start_send(item)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.0).poll_close(cx)
    }
}
