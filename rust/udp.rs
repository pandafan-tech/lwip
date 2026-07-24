use std::{io, net::SocketAddr, os::raw, pin::Pin};

use futures::stream::Stream;
use futures::task::{Context, Poll, Waker};
use futures::StreamExt;
use log::{error, warn};
use tokio::sync::mpsc::{channel, Receiver, Sender};

use super::lwip::*;
use super::packet::{IpPacket, PacketPool};
use super::util;
use crate::Error;

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
    if socket.tx.try_send((packet, src_addr, dst_addr)).is_err() {
        // log::trace!("try send udp pkt failed (netstack): {}", e);
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
) -> io::Result<()> {
    unsafe {
        let _g = super::LWIP_MUTEX.lock();
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
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("udp_sendto error: {}", err),
            ));
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
    packet_pool: std::sync::Arc<PacketPool>,
}

impl UdpSocket {
    pub(crate) fn new(buffer_size: usize) -> Result<Box<Self>, Error> {
        unsafe {
            let pcb = udp_new();
            let (tx, rx): (Sender<UdpPkt>, Receiver<UdpPkt>) = channel(buffer_size);
            let packet_pool = PacketPool::new(buffer_size.clamp(1, 256), 4 * 1024);
            let socket = Box::new(Self {
                pcb: pcb as usize,
                waker: None,
                tx,
                rx,
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
        (SendHalf { pcb: self.pcb }, RecvHalf { socket: self })
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
}

impl SendHalf {
    pub fn send_to(
        &self,
        data: &[u8],
        src_addr: &SocketAddr,
        dst_addr: &SocketAddr,
    ) -> io::Result<()> {
        send_udp(src_addr, dst_addr, self.pcb, data)
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
}

impl Stream for RecvHalf {
    type Item = UdpPkt;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.socket).poll_next(cx)
    }
}
