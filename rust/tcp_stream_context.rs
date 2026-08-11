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
    // True while this stream sits in TCP_MEM_PRESSURE, invariantly matching
    // exactly one queue entry. Only park/remove/unpark below touch it.
    pub pressure_parked: bool,
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
                pressure_parked: false,
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

// ---------------------------------------------------------------------------
// Global TCP memory-pressure wait queue.
//
// tcp_write returns ERR_MEM while send-buffer space remains when a *shared*
// resource — the MEMP_TCP_SEG pool or the lwIP heap — is exhausted, usually
// by other connections. lwIP only ever invokes the failing pcb's own
// sent/poll callbacks, so without a global wake source a writer parked on
// shared-pool exhaustion sleeps until its tcp_poll tick (8 slow-timer
// intervals = 4 seconds) even though capacity was freed immediately. Under
// 16 bulk flows this starved streams for entire measurement windows while
// the remaining flows thrashed the lock (the 2026-08-11 Linux TUN P16
// collapse).
//
// Every path that returns capacity to the shared pools hands it to the
// longest-parked writer: ACK processing frees acked segments before invoking
// tcp_sent_cb (wake one, proportional to the steady free rate), while pcb
// teardown (TcpStreamImpl::drop, tcp_err_cb) and timer-driven frees
// (sys_check_timeouts: reaps, retransmit consolidation, ooseq trimming)
// release bulk capacity with no per-free callback (wake all).
//
// All access happens under LWIP_MUTEX. The raw context pointers stay valid
// because TcpStreamImpl::drop and tcp_err_cb remove the context under the
// same lock before the stream can be freed.
struct TcpMemPressureQueue {
    inner: UnsafeCell<VecDeque<*const TcpStreamContext>>,
}

// SAFETY: the queue is only touched under LWIP_MUTEX (callers pass the guard
// or run inside lwIP callbacks where it is already held).
unsafe impl Sync for TcpMemPressureQueue {}

static TCP_MEM_PRESSURE: TcpMemPressureQueue = TcpMemPressureQueue {
    inner: UnsafeCell::new(VecDeque::new()),
};

/// Park a stream whose write failed on shared-pool exhaustion. The caller
/// must have stored the task's waker in `inner.write_waker` and must hold
/// LWIP_MUTEX (witnessed by the exclusive `inner` borrow).
pub(crate) unsafe fn pressure_park_locked(
    ctx: *const TcpStreamContext,
    inner: &mut TcpStreamContextInner,
) {
    if inner.pressure_parked {
        return;
    }
    inner.pressure_parked = true;
    (*TCP_MEM_PRESSURE.inner.get()).push_back(ctx);
}

/// Remove a stream from the queue before its context can become invalid
/// (teardown) or stop being pollable (fatal error).
pub(crate) unsafe fn pressure_remove_locked(
    ctx: *const TcpStreamContext,
    inner: &mut TcpStreamContextInner,
) {
    if !inner.pressure_parked {
        return;
    }
    inner.pressure_parked = false;
    (*TCP_MEM_PRESSURE.inner.get()).retain(|parked| !std::ptr::eq(*parked, ctx));
}

/// Hand one freed unit of pool capacity to the longest-parked writer.
///
/// The caller must hold LWIP_MUTEX and must not hold any TcpStreamContext
/// borrow — this walks foreign contexts.
pub(crate) unsafe fn pressure_unpark_one_locked() {
    let queue = &mut *TCP_MEM_PRESSURE.inner.get();
    while let Some(ptr) = queue.pop_front() {
        let mut inner = TcpStreamContext::assume_locked(ptr);
        if !inner.pressure_parked {
            continue;
        }
        inner.pressure_parked = false;
        if let Some(waker) = inner.write_waker.take() {
            waker.wake();
            return;
        }
        // The waker was already consumed by this pcb's own callback, so the
        // writer is scheduled regardless and will re-park if it still cannot
        // proceed. Keep scanning so this capacity event still wakes someone.
    }
}

/// Hand bulk freed capacity (pcb teardown, timer reaps) to every parked
/// writer. Same locking contract as [`pressure_unpark_one_locked`].
pub(crate) unsafe fn pressure_unpark_all_locked() {
    let queue = &mut *TCP_MEM_PRESSURE.inner.get();
    while let Some(ptr) = queue.pop_front() {
        let mut inner = TcpStreamContext::assume_locked(ptr);
        if !inner.pressure_parked {
            continue;
        }
        inner.pressure_parked = false;
        if let Some(waker) = inner.write_waker.take() {
            waker.wake();
        }
    }
}

#[cfg(test)]
pub(crate) unsafe fn pressure_queue_len_locked() -> usize {
    (*TCP_MEM_PRESSURE.inner.get()).len()
}
