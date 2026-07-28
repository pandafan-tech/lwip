use std::{
    io,
    net::SocketAddr,
    os::raw,
    pin::Pin,
    sync::atomic::{AtomicU64, Ordering},
};

use futures::stream::Stream;
use futures::task::{Context, Poll, Waker};
use futures::StreamExt;
use log::{error, warn};
use tokio::sync::{
    mpsc::{channel, error::TryRecvError, error::TrySendError, Receiver, Sender, WeakSender},
    Mutex as AsyncMutex,
};

use super::lwip::*;
use super::packet::{IpPacket, PacketPool};
use super::util;
use crate::Error;

const UDP_HEADER_LEN: usize = 8;
const IPV4_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const IPV6_FRAGMENT_HEADER_LEN: usize = 8;
const IPV6_MINIMUM_MTU: usize = 1280;
static UDP_INGRESS_QUEUE_DROPS: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UdpRuntimeStats {
    pub ingress_queue_drops: u64,
}

pub fn udp_runtime_stats() -> UdpRuntimeStats {
    UdpRuntimeStats {
        ingress_queue_drops: UDP_INGRESS_QUEUE_DROPS.load(Ordering::Relaxed),
    }
}

fn udp_egress_slots(data_len: usize, destination: &SocketAddr, mtu: u16) -> io::Result<usize> {
    let transport_len = data_len
        .checked_add(UDP_HEADER_LEN)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "UDP datagram is too large"))?;
    let mtu = usize::from(mtu);
    let (ip_header_len, fragment_header_len, fragment_mtu) = if destination.is_ipv6() {
        (
            IPV6_HEADER_LEN,
            IPV6_FRAGMENT_HEADER_LEN,
            mtu.min(IPV6_MINIMUM_MTU),
        )
    } else {
        (IPV4_HEADER_LEN, 0, mtu)
    };
    let total_len = transport_len
        .checked_add(ip_header_len)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "UDP datagram is too large"))?;
    if total_len <= mtu {
        return Ok(1);
    }

    let headers_len = ip_header_len + fragment_header_len;
    let fragment_payload = fragment_mtu
        .checked_sub(headers_len)
        .map(|length| length & !7)
        .filter(|length| *length > 0)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("MTU {mtu} is too small for UDP fragmentation"),
            )
        })?;
    transport_len
        .checked_add(fragment_payload - 1)
        .map(|length| length / fragment_payload)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "UDP datagram is too large"))
}

pub unsafe extern "C" fn udp_recv_cb(
    arg: *mut raw::c_void,
    _pcb: *mut udp_pcb,
    p: *mut pbuf,
    addr: *const ip_addr_t,
    port: u16_t,
    dst_addr: *const ip_addr_t,
    dst_port: u16_t,
) {
    if arg.is_null() {
        warn!("udp socket has been closed");
        return;
    }
    let socket = &mut *(arg as *mut UdpSocket);
    let src_addr = util::to_socket_addr(&*addr, port);
    let dst_addr = util::to_socket_addr(&*dst_addr, dst_port);
    let tot_len = std::ptr::read_unaligned(p).tot_len;
    let mut packet = socket.packet_pool.acquire(tot_len as usize);
    let copied = {
        let spare = packet.spare_capacity_mut();
        pbuf_copy_partial(p, spare.as_mut_ptr().cast(), tot_len, 0)
    };
    pbuf_free(p);
    if copied != tot_len {
        warn!("short lwIP UDP pbuf copy: {copied}/{tot_len}");
        return;
    }
    packet.set_len(tot_len as usize);
    match socket.tx.try_send((packet, src_addr, dst_addr)) {
        Ok(()) => {}
        Err(TrySendError::Full(_)) => {
            let drops = UDP_INGRESS_QUEUE_DROPS.fetch_add(1, Ordering::Relaxed) + 1;
            if drops.is_power_of_two() {
                error!("lwIP UDP ingress queue full; dropped datagrams={drops}");
            }
        }
        Err(TrySendError::Closed(_)) => {
            warn!("lwIP UDP ingress queue closed; dropping datagram");
        }
    }
    if let Some(waker) = socket.waker.as_ref() {
        waker.wake_by_ref();
    }
}

fn send_udp(
    src_addr: &SocketAddr,
    dst_addr: &SocketAddr,
    pcb: usize,
    data: &[u8],
    egress_tx: &Sender<IpPacket>,
    required_slots: usize,
) -> io::Result<()> {
    unsafe {
        let _g = super::LWIP_MUTEX.lock();
        if required_slots > egress_tx.max_capacity() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "UDP datagram requires {required_slots} egress slots but the queue capacity is {}",
                    egress_tx.max_capacity()
                ),
            ));
        }
        if egress_tx.capacity() < required_slots {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                format!(
                    "UDP datagram requires {required_slots} egress slots but only {} are available",
                    egress_tx.capacity()
                ),
            ));
        }
        let pbuf =
            pbuf_alloc_reference(data.as_ptr() as *mut _, data.len() as _, pbuf_type_PBUF_REF);
        let src_ip = util::to_ip_addr_t(src_addr.ip());
        let dst_ip = util::to_ip_addr_t(dst_addr.ip());
        let err = lwip_rs_udp_sendto(
            pcb as *mut udp_pcb,
            pbuf,
            &dst_ip as *const _,
            dst_addr.port(),
            &src_ip as *const _,
            src_addr.port(),
        );
        pbuf_free(pbuf);
        if err != err_enum_t_ERR_OK as err_t {
            let kind = match err {
                value if value == err_enum_t_ERR_ABRT as err_t => io::ErrorKind::BrokenPipe,
                _ => io::ErrorKind::Other,
            };
            return Err(io::Error::new(kind, format!("udp_sendto error: {}", err)));
        }
        Ok(())
    }
}

pub type UdpPkt = (IpPacket, SocketAddr, SocketAddr);

pub struct UdpSocket {
    pcb: usize,
    waker: Option<Waker>,
    tx: Sender<UdpPkt>,
    rx: Receiver<UdpPkt>,
    egress_tx: WeakSender<IpPacket>,
    mtu: u16,
    packet_pool: std::sync::Arc<PacketPool>,
}

impl UdpSocket {
    pub(crate) fn new(
        buffer_size: usize,
        egress_tx: WeakSender<IpPacket>,
        mtu: u16,
    ) -> Result<Box<Self>, Error> {
        unsafe {
            let pcb = udp_new();
            let (tx, rx): (Sender<UdpPkt>, Receiver<UdpPkt>) = channel(buffer_size);
            let packet_pool = PacketPool::new(buffer_size.clamp(1, 256), 4 * 1024);
            let socket = Box::new(Self {
                pcb: pcb as usize,
                waker: None,
                tx,
                rx,
                egress_tx,
                mtu,
                packet_pool,
            });
            let err = udp_bind(pcb, &ip_addr_any_type, 0);
            if err != err_enum_t_ERR_OK as err_t {
                error!("bind UDP failed: {}", err);
                return Err(Error::LwIP(err));
            }
            let arg = &*socket as *const UdpSocket as *mut raw::c_void;
            udp_recv(pcb, Some(udp_recv_cb), arg);
            Ok(socket)
        }
    }

    pub fn split(self: Box<Self>) -> (SendHalf, RecvHalf) {
        (
            SendHalf {
                pcb: self.pcb,
                egress_tx: self.egress_tx.clone(),
                mtu: self.mtu,
                send_gate: AsyncMutex::new(()),
            },
            RecvHalf { socket: self },
        )
    }

    pub fn local_addr(&self) -> SocketAddr {
        unsafe {
            let pcb = self.pcb as *mut udp_pcb;
            let mut ip = std::mem::zeroed();
            let mut port = 0;
            lwip_rs_udp_local_endpoint(pcb, &mut ip, &mut port);
            util::to_socket_addr(&ip, port)
        }
    }
}

impl Drop for UdpSocket {
    fn drop(&mut self) {
        unsafe {
            udp_recv(self.pcb as *mut udp_pcb, None, std::ptr::null_mut());
            udp_remove(self.pcb as *mut udp_pcb);
        }
    }
}

impl Stream for UdpSocket {
    type Item = UdpPkt;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        let _g = super::LWIP_MUTEX.lock();
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(pkt)) => Poll::Ready(Some(pkt)),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => {
                self.waker.replace(cx.waker().clone());
                Poll::Pending
            }
        }
    }
}

pub struct SendHalf {
    pub(crate) pcb: usize,
    egress_tx: WeakSender<IpPacket>,
    mtu: u16,
    send_gate: AsyncMutex<()>,
}

impl SendHalf {
    pub fn send_to(
        &self,
        data: &[u8],
        src_addr: &SocketAddr,
        dst_addr: &SocketAddr,
    ) -> io::Result<()> {
        let required_slots = udp_egress_slots(data.len(), dst_addr, self.mtu)?;
        let sender = self.egress_tx.upgrade().ok_or_else(|| {
            io::Error::new(io::ErrorKind::BrokenPipe, "lwIP egress queue is closed")
        })?;
        send_udp(src_addr, dst_addr, self.pcb, data, &sender, required_slots)
    }

    /// Send a datagram without dropping it when the bounded stack-egress
    /// queue is temporarily full. Capacity is awaited outside LWIP_MUTEX;
    /// the synchronous callback still returns immediately with ERR_MEM.
    pub async fn send_to_wait(
        &self,
        data: &[u8],
        src_addr: &SocketAddr,
        dst_addr: &SocketAddr,
    ) -> io::Result<()> {
        let _send_guard = self.send_gate.lock().await;
        let required_slots = udp_egress_slots(data.len(), dst_addr, self.mtu)?;
        loop {
            let sender = self.egress_tx.upgrade().ok_or_else(|| {
                io::Error::new(io::ErrorKind::BrokenPipe, "lwIP egress queue is closed")
            })?;
            if required_slots > sender.max_capacity() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "UDP datagram requires {required_slots} egress slots but the queue capacity is {}",
                        sender.max_capacity()
                    ),
                ));
            }
            let permits = sender.reserve_many(required_slots).await.map_err(|_| {
                io::Error::new(io::ErrorKind::BrokenPipe, "lwIP egress queue is closed")
            })?;
            drop(permits);

            match send_udp(src_addr, dst_addr, self.pcb, data, &sender, required_slots) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                result => return result,
            }
        }
    }
}

pub struct RecvHalf {
    pub(crate) socket: Box<UdpSocket>,
}

impl RecvHalf {
    pub async fn recv_from(&mut self) -> io::Result<UdpPkt> {
        match self.socket.next().await {
            Some(pkt) => Ok(pkt),
            None => Err(io::Error::new(
                io::ErrorKind::Other,
                "recv_from udp socket faied: tx closed",
            )),
        }
    }

    pub fn try_recv_from(&mut self) -> io::Result<Option<UdpPkt>> {
        let _guard = super::LWIP_MUTEX.lock();
        match self.socket.rx.try_recv() {
            Ok(packet) => Ok(Some(packet)),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "lwIP UDP ingress queue is closed",
            )),
        }
    }

    pub fn try_recv_many(&mut self, buffer: &mut Vec<UdpPkt>, limit: usize) -> io::Result<usize> {
        let _guard = super::LWIP_MUTEX.lock();
        let initial_len = buffer.len();
        while buffer.len() - initial_len < limit {
            match self.socket.rx.try_recv() {
                Ok(packet) => buffer.push(packet),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) if buffer.len() == initial_len => {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "lwIP UDP ingress queue is closed",
                    ));
                }
                Err(TryRecvError::Disconnected) => break,
            }
        }
        Ok(buffer.len() - initial_len)
    }
}

impl Stream for RecvHalf {
    type Item = UdpPkt;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.socket).poll_next(cx)
    }
}
