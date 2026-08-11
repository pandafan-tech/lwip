use std::{
    io,
    net::SocketAddr,
    os::raw,
    pin::Pin,
    sync::atomic::{AtomicU64, Ordering},
};

#[cfg(any(windows, test))]
use std::ffi::OsStr;
#[cfg(windows)]
use std::sync::OnceLock;

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
use super::shard::ShardRef;
use super::util;
use crate::Error;

const UDP_HEADER_LEN: usize = 8;
const IPV4_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const IPV6_FRAGMENT_HEADER_LEN: usize = 8;
const IPV6_MINIMUM_MTU: usize = 1280;
static UDP_INGRESS_QUEUE_DROPS: AtomicU64 = AtomicU64::new(0);

#[cfg(windows)]
const UDP_NOTIFY_ENV: &str = "PANDA_WINDOWS_LWIP_UDP_NOTIFY";
#[cfg(windows)]
const UDP_RESERVE_ENV: &str = "PANDA_WINDOWS_LWIP_UDP_RESERVE";
#[cfg(windows)]
const UDP_SEND_GATE_ENV: &str = "PANDA_WINDOWS_LWIP_UDP_SEND_GATE";

#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WindowsUdpNotifyMode {
    Legacy,
    Mpsc,
}

#[cfg(windows)]
impl WindowsUdpNotifyMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Legacy => "legacy",
            Self::Mpsc => "mpsc",
        }
    }
}

#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WindowsUdpReserveMode {
    Always,
    OnBlock,
}

#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WindowsUdpSendGateMode {
    Always,
    OnBlock,
}

#[cfg(windows)]
impl WindowsUdpReserveMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Always => "always",
            Self::OnBlock => "on-block",
        }
    }
}

#[cfg(windows)]
impl WindowsUdpSendGateMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Always => "always",
            Self::OnBlock => "on-block",
        }
    }
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct WindowsUdpRuntimeConfig {
    notify: WindowsUdpNotifyMode,
    reserve: WindowsUdpReserveMode,
    send_gate: WindowsUdpSendGateMode,
}

#[cfg(windows)]
static WINDOWS_UDP_RUNTIME_CONFIG: OnceLock<std::result::Result<WindowsUdpRuntimeConfig, String>> =
    OnceLock::new();

#[cfg(any(windows, test))]
fn parse_windows_udp_notify_mode(raw: Option<&OsStr>) -> Result<WindowsUdpNotifyMode, String> {
    let Some(raw) = raw else {
        return Ok(WindowsUdpNotifyMode::Legacy);
    };
    match raw
        .to_str()
        .ok_or_else(|| "value must be valid UTF-8".to_owned())?
    {
        "legacy" => Ok(WindowsUdpNotifyMode::Legacy),
        "mpsc" => Ok(WindowsUdpNotifyMode::Mpsc),
        value => Err(format!("value must be legacy or mpsc, got {value:?}")),
    }
}

#[cfg(any(windows, test))]
fn parse_windows_udp_reserve_mode(raw: Option<&OsStr>) -> Result<WindowsUdpReserveMode, String> {
    let Some(raw) = raw else {
        return Ok(WindowsUdpReserveMode::OnBlock);
    };
    match raw
        .to_str()
        .ok_or_else(|| "value must be valid UTF-8".to_owned())?
    {
        "always" => Ok(WindowsUdpReserveMode::Always),
        "on-block" => Ok(WindowsUdpReserveMode::OnBlock),
        value => Err(format!("value must be always or on-block, got {value:?}")),
    }
}

#[cfg(any(windows, test))]
fn parse_windows_udp_send_gate_mode(raw: Option<&OsStr>) -> Result<WindowsUdpSendGateMode, String> {
    let Some(raw) = raw else {
        return Ok(WindowsUdpSendGateMode::Always);
    };
    match raw
        .to_str()
        .ok_or_else(|| "value must be valid UTF-8".to_owned())?
    {
        "always" => Ok(WindowsUdpSendGateMode::Always),
        "on-block" => Ok(WindowsUdpSendGateMode::OnBlock),
        value => Err(format!("value must be always or on-block, got {value:?}")),
    }
}

#[cfg(windows)]
pub(crate) fn initialize_windows_udp_runtime_config() -> super::Result<()> {
    WINDOWS_UDP_RUNTIME_CONFIG
        .get_or_init(|| {
            let notify = parse_windows_udp_notify_mode(std::env::var_os(UDP_NOTIFY_ENV).as_deref())
                .map_err(|error| format!("{UDP_NOTIFY_ENV}: {error}"))?;
            let reserve =
                parse_windows_udp_reserve_mode(std::env::var_os(UDP_RESERVE_ENV).as_deref())
                    .map_err(|error| format!("{UDP_RESERVE_ENV}: {error}"))?;
            let send_gate =
                parse_windows_udp_send_gate_mode(std::env::var_os(UDP_SEND_GATE_ENV).as_deref())
                    .map_err(|error| format!("{UDP_SEND_GATE_ENV}: {error}"))?;
            log::info!("{UDP_NOTIFY_ENV} resolved to {}", notify.as_str());
            log::info!("{UDP_RESERVE_ENV} resolved to {}", reserve.as_str());
            log::info!("{UDP_SEND_GATE_ENV} resolved to {}", send_gate.as_str());
            Ok(WindowsUdpRuntimeConfig {
                notify,
                reserve,
                send_gate,
            })
        })
        .clone()
        .map(|_| ())
        .map_err(super::Error::RuntimeConfig)
}

#[cfg(windows)]
fn windows_udp_runtime_config() -> WindowsUdpRuntimeConfig {
    match WINDOWS_UDP_RUNTIME_CONFIG.get() {
        Some(Ok(config)) => *config,
        Some(Err(error)) => panic!("invalid Windows UDP runtime configuration: {error}"),
        None => panic!("Windows UDP runtime configuration was not initialized"),
    }
}

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

#[cfg(any(windows, test))]
fn enqueue_windows_udp_packet(
    tx: &Sender<UdpPkt>,
    legacy_waker: Option<&Waker>,
    packet: UdpPkt,
    mode: WindowsUdpNotifyMode,
    drop_counter: &AtomicU64,
) {
    match tx.try_send(packet) {
        Ok(()) => {}
        Err(TrySendError::Full(_)) => {
            let drops = drop_counter.fetch_add(1, Ordering::Relaxed) + 1;
            if drops.is_power_of_two() {
                error!("lwIP UDP ingress queue full; dropped datagrams={drops}");
            }
        }
        Err(TrySendError::Closed(_)) => {
            warn!("lwIP UDP ingress queue closed; dropping datagram");
        }
    }
    if mode == WindowsUdpNotifyMode::Legacy {
        if let Some(waker) = legacy_waker {
            waker.wake_by_ref();
        }
    }
}

#[cfg(any(windows, test))]
fn poll_windows_udp_receiver(
    rx: &mut Receiver<UdpPkt>,
    legacy_waker: &mut Option<Waker>,
    cx: &mut Context<'_>,
    mode: WindowsUdpNotifyMode,
) -> Poll<Option<UdpPkt>> {
    match rx.poll_recv(cx) {
        Poll::Ready(packet) => Poll::Ready(packet),
        Poll::Pending => {
            if mode == WindowsUdpNotifyMode::Legacy {
                legacy_waker.replace(cx.waker().clone());
            }
            Poll::Pending
        }
    }
}

pub type UdpPkt = (IpPacket, SocketAddr, SocketAddr);

#[cfg(any(windows, test))]
type WindowsUdpIngressHandler = Box<dyn Fn(UdpPkt) + Send + Sync + 'static>;

unsafe fn copy_udp_packet(
    socket: &UdpSocket,
    p: *mut pbuf,
    addr: *const ip_addr_t,
    port: u16_t,
    dst_addr: *const ip_addr_t,
    dst_port: u16_t,
) -> Option<UdpPkt> {
    let src_addr = util::to_socket_addr(&*addr, port);
    let dst_addr = util::to_socket_addr(&*dst_addr, dst_port);
    let tot_len = std::ptr::read_unaligned(p).tot_len;
    let mut packet = socket.packet_pool.acquire(tot_len as usize);
    let copied = {
        let spare = packet.spare_capacity_mut();
        (socket.shard.vt.pbuf_copy_partial)(p, spare.as_mut_ptr().cast(), tot_len, 0)
    };
    (socket.shard.vt.pbuf_free)(p);
    if copied != tot_len {
        warn!("short lwIP UDP pbuf copy: {copied}/{tot_len}");
        return None;
    }
    packet.set_len(tot_len as usize);
    Some((packet, src_addr, dst_addr))
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
    let Some(packet) = copy_udp_packet(socket, p, addr, port, dst_addr, dst_port) else {
        return;
    };

    #[cfg(windows)]
    {
        enqueue_windows_udp_packet(
            &socket.tx,
            socket.waker.as_ref(),
            packet,
            socket.notify_mode,
            &UDP_INGRESS_QUEUE_DROPS,
        );
    }
    #[cfg(not(windows))]
    {
        match socket.tx.try_send(packet) {
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
}

#[cfg(any(windows, test))]
unsafe extern "C" fn udp_recv_direct_cb(
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
    let Some(packet) = copy_udp_packet(socket, p, addr, port, dst_addr, dst_port) else {
        return;
    };
    let handler = socket
        .direct_ingress_handler
        .as_ref()
        .expect("the direct UDP callback is registered only with a handler");
    handler(packet);
}

fn send_udp(
    shard: ShardRef,
    src_addr: &SocketAddr,
    dst_addr: &SocketAddr,
    pcb: usize,
    data: &[u8],
    egress_tx: &Sender<IpPacket>,
    required_slots: usize,
) -> io::Result<()> {
    unsafe {
        let _g = shard.mutex.lock();
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
        let pbuf = (shard.vt.pbuf_alloc_reference)(
            data.as_ptr() as *mut _,
            data.len() as _,
            pbuf_type_PBUF_REF,
        );
        let src_ip = util::to_ip_addr_t(src_addr.ip());
        let dst_ip = util::to_ip_addr_t(dst_addr.ip());
        let err = (shard.vt.lwip_rs_udp_sendto)(
            pcb as *mut udp_pcb,
            pbuf,
            &dst_ip as *const _,
            dst_addr.port(),
            &src_ip as *const _,
            src_addr.port(),
        );
        (shard.vt.pbuf_free)(pbuf);
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

pub struct UdpSocket {
    shard: ShardRef,
    pcb: usize,
    waker: Option<Waker>,
    #[cfg(windows)]
    notify_mode: WindowsUdpNotifyMode,
    #[cfg(windows)]
    reserve_mode: WindowsUdpReserveMode,
    #[cfg(windows)]
    send_gate_mode: WindowsUdpSendGateMode,
    #[cfg(any(windows, test))]
    direct_ingress_handler: Option<WindowsUdpIngressHandler>,
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
        shard: ShardRef,
    ) -> Result<Box<Self>, Error> {
        #[cfg(windows)]
        let runtime_config = windows_udp_runtime_config();
        let _guard = shard.mutex.lock();
        unsafe {
            let pcb = (shard.vt.udp_new)();
            if pcb.is_null() {
                error!("create UDP PCB failed: out of lwIP memory");
                return Err(Error::LwIP(err_enum_t_ERR_MEM as err_t));
            }
            let err = (shard.vt.udp_bind)(pcb, &ip_addr_any_type, 0);
            if err != err_enum_t_ERR_OK as err_t {
                error!("bind UDP failed: {}", err);
                (shard.vt.udp_remove)(pcb);
                return Err(Error::LwIP(err));
            }
            let (tx, rx): (Sender<UdpPkt>, Receiver<UdpPkt>) = channel(buffer_size);
            let packet_pool = PacketPool::new(buffer_size.clamp(1, 256), 4 * 1024);
            let socket = Box::new(Self {
                shard,
                pcb: pcb as usize,
                waker: None,
                #[cfg(windows)]
                notify_mode: runtime_config.notify,
                #[cfg(windows)]
                reserve_mode: runtime_config.reserve,
                #[cfg(windows)]
                send_gate_mode: runtime_config.send_gate,
                #[cfg(any(windows, test))]
                direct_ingress_handler: None,
                tx,
                rx,
                egress_tx,
                mtu,
                packet_pool,
            });
            let arg = &*socket as *const UdpSocket as *mut raw::c_void;
            (shard.vt.udp_recv)(pcb, Some(udp_recv_cb), arg);
            Ok(socket)
        }
    }

    pub fn split(self: Box<Self>) -> (SendHalf, RecvHalf) {
        (
            SendHalf {
                shard: self.shard,
                pcb: self.pcb,
                egress_tx: self.egress_tx.clone(),
                mtu: self.mtu,
                send_gate: AsyncMutex::new(()),
                #[cfg(windows)]
                reserve_mode: self.reserve_mode,
                #[cfg(windows)]
                send_gate_mode: self.send_gate_mode,
            },
            RecvHalf { socket: self },
        )
    }

    pub fn local_addr(&self) -> SocketAddr {
        unsafe {
            let pcb = self.pcb as *mut udp_pcb;
            let mut ip = std::mem::zeroed();
            let mut port = 0;
            (self.shard.vt.lwip_rs_udp_local_endpoint)(pcb, &mut ip, &mut port);
            util::to_socket_addr(&ip, port)
        }
    }
}

impl Drop for UdpSocket {
    fn drop(&mut self) {
        let _guard = self.shard.mutex.lock();
        unsafe {
            (self.shard.vt.udp_recv)(self.pcb as *mut udp_pcb, None, std::ptr::null_mut());
            (self.shard.vt.udp_remove)(self.pcb as *mut udp_pcb);
        }
    }
}

impl Stream for UdpSocket {
    type Item = UdpPkt;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        let _g = self.shard.mutex.lock();
        #[cfg(any(windows, test))]
        if self.direct_ingress_handler.is_some() {
            return Poll::Pending;
        }

        #[cfg(windows)]
        {
            let socket = &mut *self;
            poll_windows_udp_receiver(&mut socket.rx, &mut socket.waker, cx, socket.notify_mode)
        }
        #[cfg(not(windows))]
        {
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
}

pub struct SendHalf {
    shard: ShardRef,
    pub(crate) pcb: usize,
    egress_tx: WeakSender<IpPacket>,
    mtu: u16,
    send_gate: AsyncMutex<()>,
    #[cfg(windows)]
    reserve_mode: WindowsUdpReserveMode,
    #[cfg(windows)]
    send_gate_mode: WindowsUdpSendGateMode,
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
        send_udp(
            self.shard,
            src_addr,
            dst_addr,
            self.pcb,
            data,
            &sender,
            required_slots,
        )
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
        #[cfg(windows)]
        {
            return self
                .send_to_wait_with_runtime_modes(
                    data,
                    src_addr,
                    dst_addr,
                    self.reserve_mode,
                    self.send_gate_mode,
                    #[cfg(test)]
                    None,
                    #[cfg(test)]
                    None,
                )
                .await;
        }
        #[cfg(not(windows))]
        {
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

                match send_udp(
                    self.shard,
                    src_addr,
                    dst_addr,
                    self.pcb,
                    data,
                    &sender,
                    required_slots,
                ) {
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    result => return result,
                }
            }
        }
    }

    #[cfg(any(windows, test))]
    async fn send_to_wait_with_runtime_modes(
        &self,
        data: &[u8],
        src_addr: &SocketAddr,
        dst_addr: &SocketAddr,
        reserve_mode: WindowsUdpReserveMode,
        send_gate_mode: WindowsUdpSendGateMode,
        #[cfg(test)] reservation_counter: Option<&std::sync::atomic::AtomicUsize>,
        #[cfg(test)] send_gate_counter: Option<&std::sync::atomic::AtomicUsize>,
    ) -> io::Result<()> {
        let required_slots = udp_egress_slots(data.len(), dst_addr, self.mtu)?;
        if send_gate_mode == WindowsUdpSendGateMode::OnBlock {
            let sender = self.egress_tx.upgrade().ok_or_else(|| {
                io::Error::new(io::ErrorKind::BrokenPipe, "lwIP egress queue is closed")
            })?;
            match send_udp(
                self.shard,
                src_addr,
                dst_addr,
                self.pcb,
                data,
                &sender,
                required_slots,
            ) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                result => return result,
            }
        }

        #[cfg(test)]
        if let Some(counter) = send_gate_counter {
            counter.fetch_add(1, Ordering::Relaxed);
        }
        let _send_guard = self.send_gate.lock().await;
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

            if reserve_mode == WindowsUdpReserveMode::OnBlock {
                match send_udp(
                    self.shard,
                    src_addr,
                    dst_addr,
                    self.pcb,
                    data,
                    &sender,
                    required_slots,
                ) {
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    result => return result,
                }
            }

            #[cfg(test)]
            if let Some(counter) = reservation_counter {
                counter.fetch_add(1, Ordering::Relaxed);
            }
            let permits = sender.reserve_many(required_slots).await.map_err(|_| {
                io::Error::new(io::ErrorKind::BrokenPipe, "lwIP egress queue is closed")
            })?;
            drop(permits);

            match send_udp(
                self.shard,
                src_addr,
                dst_addr,
                self.pcb,
                data,
                &sender,
                required_slots,
            ) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                result => return result,
            }
        }
    }

    #[cfg(test)]
    async fn send_to_wait_with_reserve_mode_for_test(
        &self,
        data: &[u8],
        src_addr: &SocketAddr,
        dst_addr: &SocketAddr,
        mode: WindowsUdpReserveMode,
        reservation_counter: &std::sync::atomic::AtomicUsize,
    ) -> io::Result<()> {
        self.send_to_wait_with_runtime_modes(
            data,
            src_addr,
            dst_addr,
            mode,
            WindowsUdpSendGateMode::Always,
            Some(reservation_counter),
            None,
        )
        .await
    }

    #[cfg(test)]
    async fn send_to_wait_with_runtime_modes_for_test(
        &self,
        data: &[u8],
        src_addr: &SocketAddr,
        dst_addr: &SocketAddr,
        reserve_mode: WindowsUdpReserveMode,
        send_gate_mode: WindowsUdpSendGateMode,
        reservation_counter: &std::sync::atomic::AtomicUsize,
        send_gate_counter: &std::sync::atomic::AtomicUsize,
    ) -> io::Result<()> {
        self.send_to_wait_with_runtime_modes(
            data,
            src_addr,
            dst_addr,
            reserve_mode,
            send_gate_mode,
            Some(reservation_counter),
            Some(send_gate_counter),
        )
        .await
    }
}

pub struct RecvHalf {
    pub(crate) socket: Box<UdpSocket>,
}

impl RecvHalf {
    #[cfg(any(windows, test))]
    pub fn set_windows_direct_ingress_handler<F>(&mut self, handler: F) -> io::Result<()>
    where
        F: Fn(UdpPkt) + Send + Sync + 'static,
    {
        let _guard = self.socket.shard.mutex.lock();
        if self.socket.direct_ingress_handler.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "lwIP UDP direct ingress handler is already configured",
            ));
        }
        self.socket.direct_ingress_handler = Some(Box::new(handler));
        unsafe {
            let pcb = self.socket.pcb as *mut udp_pcb;
            let arg = &*self.socket as *const UdpSocket as *mut raw::c_void;
            (self.socket.shard.vt.udp_recv)(pcb, Some(udp_recv_direct_cb), arg);
        }
        Ok(())
    }

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
        let _guard = self.socket.shard.mutex.lock();
        #[cfg(any(windows, test))]
        if self.socket.direct_ingress_handler.is_some() {
            return Ok(None);
        }
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
        let _guard = self.socket.shard.mutex.lock();
        #[cfg(any(windows, test))]
        if self.socket.direct_ingress_handler.is_some() {
            return Ok(0);
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{stack_impl::LWIP_TEST_LOCK, NetStack};
    use std::ffi::OsString;
    use std::sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc,
    };
    use std::task::{Wake, Waker};
    use tokio::time::{timeout, Duration};

    struct WakeCounter(AtomicUsize);

    impl Wake for WakeCounter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn udp_packet(value: u8) -> UdpPkt {
        (
            vec![value].into(),
            "192.0.2.1:1000".parse().unwrap(),
            "198.51.100.2:2000".parse().unwrap(),
        )
    }

    fn udp_ipv4_frame(value: u8) -> Vec<u8> {
        let mut packet = vec![
            0x45, 0, 0, 29, 0, 0, 0, 0, 64, 17, 0, 0, 192, 0, 2, 1, 198, 51, 100, 2, 0x03, 0xe8,
            0x07, 0xd0, 0, 9, 0, 0, value,
        ];
        let mut sum = 0_u32;
        for pair in packet[..20].chunks_exact(2) {
            sum += u16::from_be_bytes([pair[0], pair[1]]) as u32;
        }
        while sum > u16::MAX as u32 {
            sum = (sum & u16::MAX as u32) + (sum >> 16);
        }
        packet[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
        packet
    }

    #[test]
    fn windows_udp_runtime_axis_parsers_are_strict_and_use_supported_defaults() {
        assert_eq!(
            parse_windows_udp_notify_mode(None).unwrap(),
            WindowsUdpNotifyMode::Legacy
        );
        assert_eq!(
            parse_windows_udp_notify_mode(Some("legacy".as_ref())).unwrap(),
            WindowsUdpNotifyMode::Legacy
        );
        assert_eq!(
            parse_windows_udp_notify_mode(Some("mpsc".as_ref())).unwrap(),
            WindowsUdpNotifyMode::Mpsc
        );
        assert_eq!(
            parse_windows_udp_reserve_mode(None).unwrap(),
            WindowsUdpReserveMode::OnBlock
        );
        assert_eq!(
            parse_windows_udp_reserve_mode(Some("always".as_ref())).unwrap(),
            WindowsUdpReserveMode::Always
        );
        assert_eq!(
            parse_windows_udp_reserve_mode(Some("on-block".as_ref())).unwrap(),
            WindowsUdpReserveMode::OnBlock
        );
        assert_eq!(
            parse_windows_udp_send_gate_mode(None).unwrap(),
            WindowsUdpSendGateMode::Always
        );
        assert_eq!(
            parse_windows_udp_send_gate_mode(Some("always".as_ref())).unwrap(),
            WindowsUdpSendGateMode::Always
        );
        assert_eq!(
            parse_windows_udp_send_gate_mode(Some("on-block".as_ref())).unwrap(),
            WindowsUdpSendGateMode::OnBlock
        );

        for invalid in ["", "Legacy", "mpsc ", "manual", "0"] {
            assert!(
                parse_windows_udp_notify_mode(Some(invalid.as_ref())).is_err(),
                "{invalid:?} must be rejected"
            );
        }
        for invalid in ["", "Always", "on_block", "never", "0"] {
            assert!(
                parse_windows_udp_reserve_mode(Some(invalid.as_ref())).is_err(),
                "{invalid:?} must be rejected"
            );
            assert!(
                parse_windows_udp_send_gate_mode(Some(invalid.as_ref())).is_err(),
                "{invalid:?} must be rejected"
            );
        }

        #[cfg(unix)]
        let invalid_utf8 = {
            use std::os::unix::ffi::OsStringExt;
            OsString::from_vec(vec![0xff])
        };
        #[cfg(windows)]
        let invalid_utf8 = {
            use std::os::windows::ffi::OsStringExt;
            OsString::from_wide(&[0xd800])
        };
        assert!(parse_windows_udp_notify_mode(Some(&invalid_utf8)).is_err());
        assert!(parse_windows_udp_reserve_mode(Some(&invalid_utf8)).is_err());
        assert!(parse_windows_udp_send_gate_mode(Some(&invalid_utf8)).is_err());
    }

    #[test]
    fn mpsc_notify_removes_only_the_redundant_wake_and_preserves_fifo_and_drop() {
        for (mode, expected_wakes) in [
            (WindowsUdpNotifyMode::Legacy, 9),
            (WindowsUdpNotifyMode::Mpsc, 1),
        ] {
            let (tx, mut rx) = channel(8);
            let counter = Arc::new(WakeCounter(AtomicUsize::new(0)));
            let waker = Waker::from(Arc::clone(&counter));
            let mut context = Context::from_waker(&waker);
            let mut legacy_waker = None;
            let drops = AtomicU64::new(0);

            assert!(matches!(
                poll_windows_udp_receiver(&mut rx, &mut legacy_waker, &mut context, mode),
                Poll::Pending
            ));
            for value in 0..8 {
                enqueue_windows_udp_packet(
                    &tx,
                    legacy_waker.as_ref(),
                    udp_packet(value),
                    mode,
                    &drops,
                );
            }
            assert_eq!(counter.0.load(Ordering::Relaxed), expected_wakes);
            assert_eq!(drops.load(Ordering::Relaxed), 0);
            for expected in 0..8 {
                assert_eq!(rx.try_recv().unwrap().0.as_ref(), &[expected]);
            }
        }

        let (tx, mut rx) = channel(1);
        let counter = Arc::new(WakeCounter(AtomicUsize::new(0)));
        let waker = Waker::from(Arc::clone(&counter));
        let mut context = Context::from_waker(&waker);
        let mut legacy_waker = None;
        let drops = AtomicU64::new(0);
        assert!(matches!(
            poll_windows_udp_receiver(
                &mut rx,
                &mut legacy_waker,
                &mut context,
                WindowsUdpNotifyMode::Mpsc,
            ),
            Poll::Pending
        ));
        assert!(legacy_waker.is_none());
        enqueue_windows_udp_packet(
            &tx,
            legacy_waker.as_ref(),
            udp_packet(1),
            WindowsUdpNotifyMode::Mpsc,
            &drops,
        );
        enqueue_windows_udp_packet(
            &tx,
            legacy_waker.as_ref(),
            udp_packet(2),
            WindowsUdpNotifyMode::Mpsc,
            &drops,
        );

        assert_eq!(counter.0.load(Ordering::Relaxed), 1);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
        assert_eq!(rx.try_recv().unwrap().0.as_ref(), &[1]);
        assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
        drop(rx);
        enqueue_windows_udp_packet(
            &tx,
            legacy_waker.as_ref(),
            udp_packet(3),
            WindowsUdpNotifyMode::Mpsc,
            &drops,
        );
        assert_eq!(counter.0.load(Ordering::Relaxed), 1);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn direct_flow_ingress_bypasses_the_relay_queue_and_preserves_the_packet() {
        let _test_guard = LWIP_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap()
            .block_on(async {
                let (stack, listener, udp) = NetStack::with_buffer_size(1, 1).unwrap();
                drop(listener);
                let (_send_half, mut recv_half) = udp.split();
                let (mut ingress, _egress) = stack.split();
                let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
                let handler_seen = Arc::clone(&seen);

                recv_half
                    .set_windows_direct_ingress_handler(move |packet| {
                        handler_seen.lock().unwrap().push(packet);
                    })
                    .unwrap();
                ingress.input_batch([7, 23, 91].map(udp_ipv4_frame));

                let seen = seen.lock().unwrap();
                assert_eq!(seen.len(), 3);
                assert_eq!(
                    seen.iter()
                        .map(|packet| packet.0.as_ref()[0])
                        .collect::<Vec<_>>(),
                    [7, 23, 91]
                );
                for packet in seen.iter() {
                    assert_eq!(packet.1, "192.0.2.1:1000".parse().unwrap());
                    assert_eq!(packet.2, "198.51.100.2:2000".parse().unwrap());
                }
                drop(seen);
                assert!(recv_half.try_recv_from().unwrap().is_none());
                assert_eq!(
                    recv_half
                        .set_windows_direct_ingress_handler(|_| {})
                        .unwrap_err()
                        .kind(),
                    io::ErrorKind::AlreadyExists
                );
            });
    }

    #[test]
    fn udp_socket_drop_waits_for_the_lwip_callback_boundary() {
        let _test_guard = LWIP_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap()
            .block_on(async {
                let (_stack, listener, udp) = NetStack::with_buffer_size(1, 1).unwrap();
                drop(listener);
                let (_send_half, recv_half) = udp.split();
                let callback_guard = crate::LWIP_MUTEX.lock();
                let (started_tx, started_rx) = std::sync::mpsc::channel();
                let (finished_tx, finished_rx) = std::sync::mpsc::channel();
                let drop_thread = std::thread::spawn(move || {
                    started_tx.send(()).unwrap();
                    drop(recv_half);
                    finished_tx.send(()).unwrap();
                });

                started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
                assert!(
                    finished_rx
                        .recv_timeout(Duration::from_millis(25))
                        .is_err(),
                    "UdpSocket::drop must wait until an in-flight lwIP callback releases the global lock"
                );
                drop(callback_guard);
                finished_rx.recv_timeout(Duration::from_secs(1)).unwrap();
                drop_thread.join().unwrap();
            });
    }

    #[test]
    fn udp_socket_creation_waits_for_the_lwip_timer_boundary() {
        let _test_guard = LWIP_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap()
            .block_on(async {
                let (_stack, listener, udp) = NetStack::with_buffer_size(1, 1).unwrap();
                drop(listener);
                drop(udp);
                let (egress_tx, _egress_rx) = channel(1);
                let weak_egress = egress_tx.downgrade();
                let timer_guard = crate::LWIP_MUTEX.lock();
                let (started_tx, started_rx) = std::sync::mpsc::channel();
                let (finished_tx, finished_rx) = std::sync::mpsc::channel();
                let create_thread = std::thread::spawn(move || {
                    started_tx.send(()).unwrap();
                    let socket = UdpSocket::new(1, weak_egress, 1500, crate::shard::primary());
                    finished_tx.send(socket.is_ok()).unwrap();
                    drop(socket);
                });

                started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
                assert!(
                    finished_rx.recv_timeout(Duration::from_millis(25)).is_err(),
                    "UdpSocket::new must not mutate lwIP while its timer boundary is active"
                );
                drop(timer_guard);
                assert!(finished_rx.recv_timeout(Duration::from_secs(1)).unwrap());
                create_thread.join().unwrap();
            });
    }

    #[test]
    fn direct_mode_receive_checks_wait_for_the_lwip_callback_boundary() {
        let _test_guard = LWIP_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap()
            .block_on(async {
                let (_stack, listener, udp) = NetStack::with_buffer_size(1, 1).unwrap();
                drop(listener);
                let (_send_half, mut recv_half) = udp.split();
                recv_half
                    .set_windows_direct_ingress_handler(|_| {})
                    .unwrap();
                let callback_guard = crate::LWIP_MUTEX.lock();
                let (started_tx, started_rx) = std::sync::mpsc::channel();
                let (finished_tx, finished_rx) = std::sync::mpsc::channel();
                let receive_thread = std::thread::spawn(move || {
                    started_tx.send(()).unwrap();
                    let result = recv_half.try_recv_from();
                    finished_tx.send(result).unwrap();
                    drop(recv_half);
                });

                started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
                assert!(
                    finished_rx.recv_timeout(Duration::from_millis(25)).is_err(),
                    "direct-mode receive checks must not alias an in-flight lwIP callback"
                );
                drop(callback_guard);
                assert!(finished_rx
                    .recv_timeout(Duration::from_secs(1))
                    .unwrap()
                    .unwrap()
                    .is_none());
                receive_thread.join().unwrap();
            });
    }

    #[test]
    fn on_block_send_gate_locks_only_after_the_fast_send_would_block() {
        let _test_guard = LWIP_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap()
            .block_on(async {
                let source: SocketAddr = "198.51.100.2:2000".parse().unwrap();
                let destination: SocketAddr = "192.0.2.1:1000".parse().unwrap();
                let (stack, listener, udp) = NetStack::with_buffer_size(1, 1).unwrap();
                drop(listener);
                let (send_half, _recv_half) = udp.split();
                let (_ingress, mut egress) = stack.split();
                let reservations = AtomicUsize::new(0);
                let send_gate_locks = AtomicUsize::new(0);

                send_half
                    .send_to_wait_with_runtime_modes_for_test(
                        b"fast",
                        &source,
                        &destination,
                        WindowsUdpReserveMode::OnBlock,
                        WindowsUdpSendGateMode::OnBlock,
                        &reservations,
                        &send_gate_locks,
                    )
                    .await
                    .unwrap();
                assert_eq!(send_gate_locks.load(Ordering::Relaxed), 0);
                assert_eq!(reservations.load(Ordering::Relaxed), 0);
                assert_eq!(&egress.recv().await.unwrap()[28..], b"fast");

                send_half.send_to(b"fill", &source, &destination).unwrap();
                let send_task = async {
                    send_half
                        .send_to_wait_with_runtime_modes_for_test(
                            b"blocked",
                            &source,
                            &destination,
                            WindowsUdpReserveMode::OnBlock,
                            WindowsUdpSendGateMode::OnBlock,
                            &reservations,
                            &send_gate_locks,
                        )
                        .await
                };
                tokio::pin!(send_task);
                assert!(timeout(Duration::from_millis(10), &mut send_task)
                    .await
                    .is_err());
                assert_eq!(send_gate_locks.load(Ordering::Relaxed), 1);
                assert_eq!(reservations.load(Ordering::Relaxed), 1);
                assert_eq!(&egress.recv().await.unwrap()[28..], b"fill");
                timeout(Duration::from_secs(1), &mut send_task)
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(&egress.recv().await.unwrap()[28..], b"blocked");
                drop(egress);
                drop(_ingress);
            });
    }

    #[test]
    fn on_block_reserve_counts_only_real_waits_and_preserves_send_behavior() {
        let _test_guard = LWIP_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap()
            .block_on(async {
                let source: SocketAddr = "198.51.100.2:2000".parse().unwrap();
                let destination: SocketAddr = "192.0.2.1:1000".parse().unwrap();

                // An empty queue needs no reservation in on-block mode, while
                // the legacy always mode performs exactly one.
                let (stack, listener, udp) = NetStack::with_buffer_size(1, 1).unwrap();
                drop(listener);
                let (send_half, _recv_half) = udp.split();
                let (_ingress, mut egress) = stack.split();
                let reservations = AtomicUsize::new(0);
                send_half
                    .send_to_wait_with_reserve_mode_for_test(
                        b"on-block-empty",
                        &source,
                        &destination,
                        WindowsUdpReserveMode::OnBlock,
                        &reservations,
                    )
                    .await
                    .unwrap();
                assert_eq!(reservations.load(Ordering::Relaxed), 0);
                assert_eq!(
                    &egress.recv().await.unwrap()[28..],
                    b"on-block-empty".as_slice()
                );

                send_half
                    .send_to_wait_with_reserve_mode_for_test(
                        b"always-empty",
                        &source,
                        &destination,
                        WindowsUdpReserveMode::Always,
                        &reservations,
                    )
                    .await
                    .unwrap();
                assert_eq!(reservations.load(Ordering::Relaxed), 1);
                assert_eq!(
                    &egress.recv().await.unwrap()[28..],
                    b"always-empty".as_slice()
                );
                drop(egress);
                drop(_ingress);

                // A full queue makes on-block perform one real reservation
                // and resume in FIFO order once capacity becomes available.
                let (stack, listener, udp) = NetStack::with_buffer_size(1, 1).unwrap();
                drop(listener);
                let (send_half, _recv_half) = udp.split();
                let (_ingress, mut egress) = stack.split();
                send_half.send_to(b"first", &source, &destination).unwrap();
                let reservations = Arc::new(AtomicUsize::new(0));
                let task_reservations = Arc::clone(&reservations);
                let send_task = tokio::spawn(async move {
                    send_half
                        .send_to_wait_with_reserve_mode_for_test(
                            b"second",
                            &source,
                            &destination,
                            WindowsUdpReserveMode::OnBlock,
                            &task_reservations,
                        )
                        .await
                });
                tokio::task::yield_now().await;
                assert!(!send_task.is_finished());
                assert_eq!(reservations.load(Ordering::Relaxed), 1);
                assert_eq!(&egress.recv().await.unwrap()[28..], b"first");
                timeout(Duration::from_secs(1), send_task)
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap();
                assert_eq!(&egress.recv().await.unwrap()[28..], b"second");
                drop(egress);
                drop(_ingress);

                // A fragmented datagram can take all available slots directly
                // in on-block mode, while always still reserves all three.
                let (stack, listener, udp) = NetStack::with_buffer_size(3, 1).unwrap();
                drop(listener);
                let (send_half, _recv_half) = udp.split();
                let (_ingress, mut egress) = stack.split();
                let payload = vec![0x5a; 3000];
                let reservations = AtomicUsize::new(0);
                send_half
                    .send_to_wait_with_reserve_mode_for_test(
                        &payload,
                        &source,
                        &destination,
                        WindowsUdpReserveMode::OnBlock,
                        &reservations,
                    )
                    .await
                    .unwrap();
                assert_eq!(reservations.load(Ordering::Relaxed), 0);
                for expected_offset in [0, 1480, 2960] {
                    let fragment = egress.recv().await.unwrap();
                    let flags_offset = u16::from_be_bytes([fragment[6], fragment[7]]);
                    assert_eq!(usize::from(flags_offset & 0x1fff) * 8, expected_offset);
                }
                send_half
                    .send_to_wait_with_reserve_mode_for_test(
                        &payload,
                        &source,
                        &destination,
                        WindowsUdpReserveMode::Always,
                        &reservations,
                    )
                    .await
                    .unwrap();
                assert_eq!(reservations.load(Ordering::Relaxed), 1);
                for _ in 0..3 {
                    egress.recv().await.unwrap();
                }
                drop(egress);
                drop(_ingress);

                // Closed egress fails directly in on-block mode and through
                // the reservation boundary in always mode.
                for (mode, expected_reservations) in [
                    (WindowsUdpReserveMode::OnBlock, 0),
                    (WindowsUdpReserveMode::Always, 1),
                ] {
                    let (stack, listener, udp) = NetStack::with_buffer_size(1, 1).unwrap();
                    drop(listener);
                    let (send_half, _recv_half) = udp.split();
                    let (_ingress, egress) = stack.split();
                    drop(egress);
                    let reservations = AtomicUsize::new(0);
                    let error = send_half
                        .send_to_wait_with_reserve_mode_for_test(
                            b"closed",
                            &source,
                            &destination,
                            mode,
                            &reservations,
                        )
                        .await
                        .unwrap_err();
                    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
                    assert_eq!(reservations.load(Ordering::Relaxed), expected_reservations);
                    drop(_ingress);
                }
            });
    }
}
