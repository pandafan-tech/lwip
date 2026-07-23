use futures::task::Waker;
use std::{
    cell::UnsafeCell,
    collections::VecDeque,
    net::SocketAddr,
    ops::{Deref, DerefMut},
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

use super::packet::IpPacket;
use super::LWIPMutexGuard;

const TCP_READ_QUEUE_INITIAL_CAPACITY: usize = 32;

static ACTIVE_TCP_STREAMS: AtomicUsize = AtomicUsize::new(0);
static TCP_QUEUED_PACKETS: AtomicUsize = AtomicUsize::new(0);
static TCP_QUEUED_BYTES: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TcpRuntimeStats {
    pub active_streams: usize,
    pub queued_packets: usize,
    pub queued_bytes: usize,
}

pub fn tcp_runtime_stats() -> TcpRuntimeStats {
    TcpRuntimeStats {
        active_streams: ACTIVE_TCP_STREAMS.load(Ordering::Relaxed),
        queued_packets: TCP_QUEUED_PACKETS.load(Ordering::Relaxed),
        queued_bytes: TCP_QUEUED_BYTES.load(Ordering::Relaxed),
    }
}

pub struct QueuedTcpPacket {
    packet: IpPacket,
}

impl QueuedTcpPacket {
    pub fn new(packet: IpPacket) -> Self {
        TCP_QUEUED_PACKETS.fetch_add(1, Ordering::Relaxed);
        TCP_QUEUED_BYTES.fetch_add(packet.len(), Ordering::Relaxed);
        Self { packet }
    }
}

impl Deref for QueuedTcpPacket {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.packet
    }
}

impl Drop for QueuedTcpPacket {
    fn drop(&mut self) {
        TCP_QUEUED_PACKETS.fetch_sub(1, Ordering::Relaxed);
        TCP_QUEUED_BYTES.fetch_sub(self.packet.len(), Ordering::Relaxed);
    }
}

pub struct ActiveTcpStream;

impl ActiveTcpStream {
    pub fn new() -> Self {
        ACTIVE_TCP_STREAMS.fetch_add(1, Ordering::Relaxed);
        Self
    }
}

impl Drop for ActiveTcpStream {
    fn drop(&mut self) {
        ACTIVE_TCP_STREAMS.fetch_sub(1, Ordering::Relaxed);
    }
}

pub struct TcpStreamContextInner {
    pub local_addr: SocketAddr,
    pub read_queue: VecDeque<QueuedTcpPacket>,
    pub read_waker: Option<Waker>,
    pub read_eof: bool,
    pub errored: bool,
    pub closed: bool,
    pub write_waker: Option<Waker>,
}

#[repr(transparent)]
pub struct TcpStreamContextRef<'a> {
    ctx: &'a TcpStreamContext,
}

impl<'a> Deref for TcpStreamContextRef<'a> {
    type Target = TcpStreamContextInner;
    fn deref(&self) -> &Self::Target {
        unsafe { &*self.ctx.inner.get() }
    }
}

impl<'a> DerefMut for TcpStreamContextRef<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.ctx.inner.get() }
    }
}

impl<'a> Drop for TcpStreamContextRef<'a> {
    fn drop(&mut self) {
        self.ctx.borrowed.store(false, Ordering::Release);
    }
}

/// Context shared by TcpStreamImpl and lwIP callbacks.
pub struct TcpStreamContext {
    inner: UnsafeCell<TcpStreamContextInner>,
    borrowed: AtomicBool,
}

// Users must hold a lwip_mutex to get the mutable reference to inner data,
// or go through unsafe interfaces.
unsafe impl Sync for TcpStreamContext {}

impl TcpStreamContext {
    pub fn new(local_addr: SocketAddr) -> Self {
        TcpStreamContext {
            inner: UnsafeCell::new(TcpStreamContextInner {
                local_addr,
                read_queue: VecDeque::with_capacity(TCP_READ_QUEUE_INITIAL_CAPACITY),
                read_waker: None,
                read_eof: false,
                errored: false,
                closed: false,
                write_waker: None,
            }),
            borrowed: AtomicBool::new(false),
        }
    }

    /// Access to inner data with lwip_mutex locked.
    ///
    /// # Panics
    ///
    /// Panics if another reference to inner data exists.
    pub fn with_lock<'a>(&'a self, _guard: &'a LWIPMutexGuard) -> TcpStreamContextRef<'a> {
        if self.borrowed.swap(true, Ordering::Acquire) {
            panic!("TcpStreamContext locked twice within a locked period")
        }
        TcpStreamContextRef { ctx: self }
    }

    /// Access to inner data within a lwIP callback where lwip_mutex is guaranteed to be locked.
    ///
    /// # Panics
    ///
    /// Panics if another reference to inner data exists.
    pub unsafe fn assume_locked<'a>(ptr: *const Self) -> TcpStreamContextRef<'a> {
        TcpStreamContextRef { ctx: &*ptr }
    }
}
