use std::{io, pin::Pin};

use futures::sink::Sink;
use futures::stream::Stream;
use futures::task::{Context, Poll};
use tokio::sync::mpsc::Receiver;

use super::stack_impl::NetStackImpl;
use super::tcp_listener::TcpListener;
use super::udp::UdpSocket;
use crate::{Error, IpPacket};

pub struct NetStack(Box<NetStackImpl>);

impl NetStack {
    pub fn new() -> Result<(Self, TcpListener, Box<UdpSocket>), Error> {
        Ok((
            NetStack(NetStackImpl::new(512)),
            TcpListener::new()?,
            UdpSocket::new(64)?,
        ))
    }

    pub fn with_buffer_size(
        stack_buffer_size: usize,
        udp_buffer_size: usize,
    ) -> Result<(Self, TcpListener, Box<UdpSocket>), Error> {
        Ok((
            NetStack(NetStackImpl::new(stack_buffer_size)),
            TcpListener::new()?,
            UdpSocket::new(udp_buffer_size)?,
        ))
    }

    /// Split into an ingress half (batch input into lwIP) and an egress half
    /// (a plain channel of packets leaving lwIP). The two halves can be
    /// driven from different tasks so TUN read and TUN write directions no
    /// longer serialize on one driver task.
    pub fn split(mut self) -> (StackIngress, StackEgress) {
        let rx = self.0.take_egress();
        (StackIngress(self.0), StackEgress(rx))
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
pub struct StackEgress(Receiver<IpPacket>);

impl StackEgress {
    pub async fn recv(&mut self) -> Option<IpPacket> {
        self.0.recv().await
    }

    /// Receive up to `limit` packets in one call, awaiting until at least one
    /// is available. Returns the number received (0 = channel closed).
    pub async fn recv_many(&mut self, buffer: &mut Vec<IpPacket>, limit: usize) -> usize {
        self.0.recv_many(buffer, limit).await
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
