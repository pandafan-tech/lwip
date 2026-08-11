use std::{cmp::min, io, net::SocketAddr, os::raw, pin::Pin};

use futures::task::{Context, Poll};
use log::*;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::lwip::*;
use super::shard::ShardRef;
use super::tcp_stream_context::{
    pressure_park_locked, pressure_remove_locked, pressure_unpark_all_locked,
    pressure_unpark_one_locked, ActiveTcpStream, QueuedPbuf, TcpStreamContext,
};
use super::util;

#[allow(unused_variables)]
pub unsafe extern "C" fn tcp_recv_cb(
    arg: *mut raw::c_void,
    tpcb: *mut tcp_pcb,
    p: *mut pbuf,
    err: err_t,
) -> err_t {
    if arg.is_null() {
        warn!("tcp connection has been closed");
        return err_enum_t_ERR_CONN as err_t;
    }

    // SAFETY: tcp_recv_cb is called from tcp_input or sys_check_timeouts only when
    // a data packet or previously refused data is received. Thus lwip_mutex must be locked.
    // See also `<NetStackImpl as AsyncWrite>::poll_write`.
    let shard = (*(arg as *const TcpStreamContext)).shard();
    let ctx = &mut *TcpStreamContext::assume_locked(arg as *const TcpStreamContext);

    if p.is_null() {
        trace!("netstack tcp eof {}", ctx.local_addr);
        ctx.read_eof = true;
        if let Some(waker) = ctx.read_waker.take() {
            waker.wake();
        }
        return err_enum_t_ERR_OK as err_t;
    }

    // Hand the chain to the reader instead of copying it: the memcpy then
    // runs in poll_read's unlocked phase on the reader's worker, off both
    // the global critical section and the ingress path. lwIP transferred
    // ownership of `p` to this callback; the reader returns it via
    // free_locked in a later locked phase.
    if std::ptr::read_unaligned(p).tot_len == 0 {
        // tcp_recv_cb runs under the shard's mutex (called from tcp_input),
        // so the immediate free is already serialized.
        (shard.vt.pbuf_free)(p);
        return err_enum_t_ERR_OK as err_t;
    }
    ctx.read_queue.push_back(QueuedPbuf::new(p, shard));
    if let Some(waker) = ctx.read_waker.take() {
        waker.wake();
    }

    err_enum_t_ERR_OK as err_t
}

#[allow(unused_variables)]
pub extern "C" fn tcp_sent_cb(arg: *mut raw::c_void, tpcb: *mut tcp_pcb, len: u16_t) -> err_t {
    // SAFETY: tcp_sent_cb is called from tcp_input only when
    // an ACK packet is received. Thus lwip_mutex must be locked.
    // See also `<NetStackImpl as AsyncWrite>::poll_write`.
    let shard = unsafe { (*(arg as *const TcpStreamContext)).shard() };
    {
        let mut ctx = unsafe { TcpStreamContext::assume_locked(arg as *const TcpStreamContext) };
        // trace!("netstack tcp sent {}", &ctx.local_addr);
        if let Some(waker) = ctx.write_waker.take() {
            waker.wake();
        }
    }
    // tcp_input freed this ACK's segments (and their payload memory) before
    // invoking us; hand the capacity to a writer parked on pool exhaustion.
    // The own-context borrow is dropped above: unpark walks foreign contexts.
    unsafe { pressure_unpark_one_locked(shard) };
    err_enum_t_ERR_OK as err_t
}

#[allow(unused_variables)]
pub extern "C" fn tcp_err_cb(arg: *mut ::std::os::raw::c_void, err: err_t) {
    // SAFETY: tcp_err_cb is called from
    // tcp_input, tcp_abandon, tcp_abort, tcp_alloc and tcp_new.
    // Thus lwip_mutex must be locked before calling any of these.
    let shard = unsafe { (*(arg as *const TcpStreamContext)).shard() };
    {
        let mut ctx = unsafe { TcpStreamContext::assume_locked(arg as *const TcpStreamContext) };
        trace!("netstack tcp err {} {}", err, ctx.local_addr);
        ctx.errored = true;
        // An errored stream is done writing; a stale pressure entry must not
        // swallow an unpark meant for a live writer.
        unsafe { pressure_remove_locked(shard, arg as *const TcpStreamContext, &mut ctx) };
        if let Some(waker) = ctx.read_waker.take() {
            waker.wake();
        }
        if let Some(waker) = ctx.write_waker.take() {
            waker.wake();
        }
    }
    // lwIP freed the pcb and everything it had queued before invoking us;
    // that bulk capacity can unblock every parked writer.
    unsafe { pressure_unpark_all_locked(shard) };
}

#[allow(unused_variables)]
pub extern "C" fn tcp_poll_cb(arg: *mut ::std::os::raw::c_void, tpcb: *mut tcp_pcb) -> err_t {
    let mut ctx = unsafe { TcpStreamContext::assume_locked(arg as *const TcpStreamContext) };
    // trace!("netstack tcp poll {}", &ctx.local_addr);
    if let Some(waker) = ctx.write_waker.take() {
        waker.wake();
    }
    err_enum_t_ERR_OK as err_t
}

// The pbuf chain being copied out to the caller, with a cursor into it.
// SAFETY of the Send impl: the chain is exclusively owned (see QueuedPbuf);
// `node` only ever points inside that owned chain.
struct PbufCursor {
    chain: QueuedPbuf,
    node: *mut pbuf,
    node_off: usize,
}

unsafe impl Send for PbufCursor {}
// SAFETY: same as QueuedPbuf — no shared-reference path dereferences `node`.
unsafe impl Sync for PbufCursor {}

pub struct TcpStreamImpl {
    shard: ShardRef,
    src_addr: SocketAddr,
    dest_addr: SocketAddr,
    pcb: usize,
    read_buf: Option<PbufCursor>,
    // Chains already claimed from the shared read_queue but not yet copied
    // out. Draining into this under the lock and copying from it after
    // releasing keeps the memcpy out of the global critical section — with
    // the copy inside it, a relay pulling tens of kilobytes stalls the whole
    // stack's input path for the duration, which on a preemption-prone host
    // is what feeds the spin-yield contention storm.
    staged: std::collections::VecDeque<QueuedPbuf>,
    // Fully copied chains awaiting their locked return to lwIP; freed in the
    // next poll's locked phase (or in Drop). Owned by the single reader
    // task, so no lock guards it.
    spent: Vec<QueuedPbuf>,
    // Bytes copied out to the reader whose tcp_recved window credit has not
    // been granted yet; flushed at the start of the next poll_read's locked
    // phase. Owned by the single reader task, so no lock guards it.
    pending_recved: usize,
    callback_ctx: TcpStreamContext,
    _active: ActiveTcpStream,
}

impl TcpStreamImpl {
    pub fn new(pcb: *mut tcp_pcb, shard: ShardRef) -> Box<Self> {
        unsafe {
            // The receive callback and AsyncRead consumer both run under
            // the shard's mutex, so a direct queue avoids the redundant
            // atomics and per-packet wake path of a thread-safe channel.
            // lwIP owns flow control: we only call tcp_recved after the Rust
            // consumer has actually copied bytes out of this queue.
            let mut remote_ip = std::mem::zeroed();
            let mut remote_port = 0;
            let mut local_ip = std::mem::zeroed();
            let mut local_port = 0;
            (shard.vt.lwip_rs_tcp_endpoints)(
                pcb,
                &mut remote_ip,
                &mut remote_port,
                &mut local_ip,
                &mut local_port,
            );
            let src_addr = util::to_socket_addr(&remote_ip, remote_port);
            let dest_addr = util::to_socket_addr(&local_ip, local_port);
            let stream = Box::new(TcpStreamImpl {
                shard,
                src_addr,
                dest_addr,
                pcb: pcb as usize,
                read_buf: None,
                staged: std::collections::VecDeque::new(),
                spent: Vec::new(),
                pending_recved: 0,
                callback_ctx: TcpStreamContext::new(src_addr, shard),
                _active: ActiveTcpStream::new(shard),
            });
            let arg = &stream.callback_ctx as *const _;
            (shard.vt.tcp_arg)(pcb, arg as *mut raw::c_void);
            (shard.vt.tcp_recv)(pcb, Some(tcp_recv_cb));
            (shard.vt.tcp_sent)(pcb, Some(tcp_sent_cb));
            (shard.vt.tcp_err)(pcb, Some(tcp_err_cb));
            (shard.vt.tcp_poll)(pcb, Some(tcp_poll_cb), 8 as _);
            stream.apply_pcb_opts();
            trace!("netstack tcp new {}", stream.local_addr());
            stream
        }
    }

    fn apply_pcb_opts(&self) {
        unsafe {
            (self.shard.vt.lwip_rs_tcp_apply_options)(
                self.pcb as *mut tcp_pcb,
                cfg!(target_os = "ios") as i32,
            );
        }
    }

    pub fn local_addr(&self) -> &SocketAddr {
        &self.src_addr
    }

    pub fn remote_addr(&self) -> &SocketAddr {
        &self.dest_addr
    }

    fn send_buf_size(&self) -> usize {
        unsafe { (self.shard.vt.lwip_rs_tcp_send_buffer)(self.pcb as *const tcp_pcb) as usize }
    }
}

fn broken_pipe() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "broken pipe")
}

impl AsyncRead for TcpStreamImpl {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf,
    ) -> Poll<io::Result<()>> {
        let me = &mut *self;

        // Locked phase one: return the chains consumed by the previous poll,
        // flush that poll's receive-window credit, claim everything queued,
        // and register the waker if there is nothing to deliver. No copying
        // happens under the lock. Folding tcp_recved into this tenure
        // (instead of a dedicated post-copy lock) halves the reader's lock
        // entries; the window opens one poll later, which a 256-MSS receive
        // window never notices, and a reader that stalls on upstream
        // backpressure keeps the window closed — which is exactly the flow
        // control lwIP should see.
        let read_eof;
        {
            let shard = me.shard;
            let guard = shard.mutex.lock_at(super::mutex::lock_stats::SITE_READ);
            for chain in me.spent.drain(..) {
                chain.free_locked(shard, &guard);
            }
            let ctx = &mut *me.callback_ctx.with_lock(&guard);
            if ctx.errored {
                return Poll::Ready(Err(broken_pipe()));
            }
            while me.pending_recved > 0 {
                let acknowledged = me.pending_recved.min(usize::from(u16::MAX));
                unsafe {
                    (shard.vt.tcp_recved)(me.pcb as *mut tcp_pcb, acknowledged as u16_t);
                }
                me.pending_recved -= acknowledged;
            }
            while let Some(chain) = ctx.read_queue.pop_front() {
                me.staged.push_back(chain);
            }
            read_eof = ctx.read_eof;
            if me.read_buf.is_none() && me.staged.is_empty() && !read_eof {
                let should_replace = ctx
                    .read_waker
                    .as_ref()
                    .map(|waker| !waker.will_wake(cx.waker()))
                    .unwrap_or(true);
                if should_replace {
                    ctx.read_waker = Some(cx.waker().clone());
                }
                return Poll::Pending;
            }
        }

        // Unlocked phase: copy into the caller's buffer straight from the
        // owned pbuf chains. Safe without the lock: lwIP surrendered every
        // reference to these chains in the receive callback.
        let mut consumed = 0usize;
        let result = loop {
            if buf.remaining() == 0 {
                break Poll::Ready(Ok(()));
            }

            let cursor = match me.read_buf.as_mut() {
                Some(cursor) => cursor,
                None => match me.staged.pop_front() {
                    Some(chain) => {
                        let node = chain.head();
                        me.read_buf.insert(PbufCursor {
                            chain,
                            node,
                            node_off: 0,
                        })
                    }
                    None => {
                        // Everything staged was delivered; either this poll
                        // made progress or the peer closed.
                        debug_assert!(read_eof || consumed > 0);
                        break Poll::Ready(Ok(()));
                    }
                },
            };

            let (payload, node_len, next) = unsafe {
                let node = std::ptr::read_unaligned(cursor.node);
                (node.payload.cast::<u8>(), usize::from(node.len), node.next)
            };
            let to_read = min(buf.remaining(), node_len - cursor.node_off);
            if to_read > 0 {
                unsafe {
                    buf.put_slice(std::slice::from_raw_parts(
                        payload.add(cursor.node_off),
                        to_read,
                    ));
                }
                cursor.node_off += to_read;
                consumed += to_read;
            }
            if cursor.node_off == node_len {
                if next.is_null() {
                    let finished = me.read_buf.take().expect("cursor just borrowed");
                    me.spent.push(finished.chain);
                } else {
                    cursor.node = next;
                    cursor.node_off = 0;
                }
            }
        };

        // The receive-window credit for these bytes is granted during the
        // next poll's locked phase; phase one re-checks pcb liveness first.
        me.pending_recved += consumed;

        result
    }
}

impl Drop for TcpStreamImpl {
    fn drop(&mut self) {
        let shard = self.shard;
        let guard = shard.mutex.lock();
        // Return every pbuf chain this stream still owns while the lock is
        // held: undelivered (staged), mid-copy (read_buf), consumed-but-not-
        // yet-returned (spent), and never-claimed (ctx.read_queue below).
        for chain in self.staged.drain(..) {
            chain.free_locked(shard, &guard);
        }
        if let Some(cursor) = self.read_buf.take() {
            cursor.chain.free_locked(shard, &guard);
        }
        for chain in self.spent.drain(..) {
            chain.free_locked(shard, &guard);
        }
        {
            let mut ctx = self.callback_ctx.with_lock(&guard);
            trace!("netstack tcp drop {}", ctx.local_addr);
            for chain in ctx.read_queue.drain(..) {
                chain.free_locked(shard, &guard);
            }
            // The context is about to be freed with the stream; it must leave
            // the pressure queue while the pointer is still valid.
            unsafe {
                pressure_remove_locked(shard, &self.callback_ctx as *const _, &mut ctx);
            }
            if !ctx.errored {
                unsafe {
                    (shard.vt.tcp_arg)(self.pcb as *mut tcp_pcb, std::ptr::null_mut());
                    (shard.vt.tcp_recv)(self.pcb as *mut tcp_pcb, None);
                    (shard.vt.tcp_sent)(self.pcb as *mut tcp_pcb, None);
                    (shard.vt.tcp_err)(self.pcb as *mut tcp_pcb, None);
                    (shard.vt.tcp_poll)(self.pcb as *mut tcp_pcb, None, 0);
                    if !ctx.closed {
                        (shard.vt.tcp_abort)(self.pcb as *mut tcp_pcb);
                    } else {
                        // poll_shutdown already half-closed TX (tcp_shutdown
                        // rx=0 tx=1), so the pcb is in FIN_WAIT_1/2 awaiting
                        // the peer's FIN. Without TF_RXCLOSED, lwIP's slowtmr
                        // never reaps a FIN_WAIT_2 pcb — a peer that vanishes
                        // without FINing (suspended iOS app, dead link) leaks
                        // the pcb plus its unacked segments forever. tcp_close
                        // on an already TX-shut pcb just sets TF_RXCLOSED,
                        // enabling the TCP_FIN_WAIT_TIMEOUT (20 s) reap; it
                        // frees nothing we still reference. Fall back to abort
                        // if it errors.
                        if (shard.vt.tcp_close)(self.pcb as *mut tcp_pcb)
                            != err_enum_t_ERR_OK as err_t
                        {
                            (shard.vt.tcp_abort)(self.pcb as *mut tcp_pcb);
                        }
                    }
                }
            }
        }
        // The abort above returned the pcb's queued segments and payload
        // memory to the shared pools; that bulk capacity can unblock every
        // parked writer. The own-context borrow ended with the scope.
        unsafe { pressure_unpark_all_locked(shard) };
    }
}

impl AsyncWrite for TcpStreamImpl {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context, buf: &[u8]) -> Poll<io::Result<usize>> {
        let shard = self.shard;
        let guard = shard.mutex.lock_at(super::mutex::lock_stats::SITE_WRITE);
        let ctx = &mut *self.callback_ctx.with_lock(&guard);
        if ctx.errored {
            return Poll::Ready(Err(broken_pipe()));
        }
        // tcp_write takes a u16 length; without the clamp a >64 KiB caller
        // buffer would silently truncate through the `as u16_t` cast below.
        let to_write = buf
            .len()
            .min(self.send_buf_size())
            .min(usize::from(u16::MAX));
        if to_write == 0 {
            ctx.write_waker.replace(cx.waker().clone());
            return Poll::Pending;
        }
        let err = unsafe {
            (shard.vt.tcp_write)(
                self.pcb as *mut tcp_pcb,
                buf.as_ptr() as *const raw::c_void,
                to_write as u16_t,
                TCP_WRITE_FLAG_COPY as u8,
            )
        };
        if err == err_enum_t_ERR_OK as err_t {
            let output_err = unsafe { (shard.vt.tcp_output)(self.pcb as *mut tcp_pcb) };
            if output_err != err_enum_t_ERR_OK as err_t {
                // tcp_write already accepted these bytes into lwIP's unsent
                // queue. Reporting an error would make AsyncWrite callers
                // retry the same bytes and duplicate the stream; lwIP keeps
                // the segment queued and retries it from its normal output
                // path once the temporary pressure clears.
                debug!("netstack tcp_output deferred after accepted write: {output_err}");
            }
            Poll::Ready(Ok(to_write))
        } else if err == err_enum_t_ERR_MEM as err_t {
            // ERR_MEM while send-buffer space remains means a shared pool
            // (MEMP_TCP_SEG or the lwIP heap) is exhausted — usually by other
            // connections, whose frees never invoke this pcb's callbacks.
            // Park on the global pressure queue so freed capacity wakes this
            // writer instead of leaving it to the 4-second tcp_poll fallback.
            ctx.write_waker.replace(cx.waker().clone());
            unsafe { pressure_park_locked(shard, &self.callback_ctx as *const _, ctx) };
            Poll::Pending
        } else {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::Interrupted,
                format!("netstack tcp_write error {}", err),
            )))
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        let guard = self
            .shard
            .mutex
            .lock_at(super::mutex::lock_stats::SITE_FLUSH);
        if self.callback_ctx.with_lock(&guard).errored {
            return Poll::Ready(Err(broken_pipe()));
        }
        let err = unsafe { (self.shard.vt.tcp_output)(self.pcb as *mut tcp_pcb) };
        if err != err_enum_t_ERR_OK as err_t {
            // Transmission deferrals, not stream errors: pool exhaustion,
            // egress-channel backpressure (the netif output hook returns
            // ERR_MEM when the channel is full), or a route lost during
            // teardown. The bytes are already queued on the pcb and lwIP
            // retries them from its ACK/timer paths — poll_write treats the
            // identical condition the same way. Surfacing an error here made
            // relays abort healthy connections exactly when the stack was
            // busiest; fatal states arrive via tcp_err_cb instead.
            debug!("netstack tcp_output deferred in flush: {err}");
        }
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        let guard = self.shard.mutex.lock();
        let ctx = &mut *self.callback_ctx.with_lock(&guard);
        if ctx.errored {
            return Poll::Ready(Err(broken_pipe()));
        }
        trace!("netstack tcp shutdown {}", ctx.local_addr);
        let err = unsafe { (self.shard.vt.tcp_shutdown)(self.pcb as *mut tcp_pcb, 0, 1) };
        if err != err_enum_t_ERR_OK as err_t {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::Interrupted,
                format!("netstack tcp_shutdown tx error {}", err),
            )))
        } else {
            ctx.closed = true;
            Poll::Ready(Ok(()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shard::primary;
    use crate::stack_impl::LWIP_TEST_LOCK;
    use crate::LWIP_MUTEX;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::task::{Wake, Waker};

    struct WakeCounter(AtomicUsize);

    impl Wake for WakeCounter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Drains the shared MEMP_TCP_SEG pool and returns every slot on drop,
    /// so a failing assertion cannot leak an exhausted pool into the tests
    /// that run after it.
    struct SegPoolHoard(Vec<*mut raw::c_void>);

    impl SegPoolHoard {
        fn exhaust() -> Self {
            let _guard = LWIP_MUTEX.lock();
            let mut slots = Vec::new();
            loop {
                let seg = unsafe { memp_malloc(memp_t_MEMP_TCP_SEG) };
                if seg.is_null() {
                    break;
                }
                slots.push(seg);
            }
            assert_eq!(
                slots.len(),
                MEMP_NUM_TCP_SEG as usize,
                "the whole compiled segment pool must be hoardable"
            );
            Self(slots)
        }

        fn release_one(&mut self) {
            let _guard = LWIP_MUTEX.lock();
            let seg = self.0.pop().expect("hoard is empty");
            unsafe { memp_free(memp_t_MEMP_TCP_SEG, seg) };
        }
    }

    impl Drop for SegPoolHoard {
        fn drop(&mut self) {
            let _guard = LWIP_MUTEX.lock();
            for seg in self.0.drain(..) {
                unsafe { memp_free(memp_t_MEMP_TCP_SEG, seg) };
            }
        }
    }

    unsafe fn fake_established_pcb() -> *mut tcp_pcb {
        let pcb = tcp_new();
        assert!(!pcb.is_null(), "TCP PCB pool exhausted");
        (*pcb).state = tcp_state_ESTABLISHED;
        pcb
    }

    fn counting_waker() -> (Arc<WakeCounter>, Waker) {
        let counter = Arc::new(WakeCounter(AtomicUsize::new(0)));
        let waker = Waker::from(Arc::clone(&counter));
        (counter, waker)
    }

    /// The P16 collapse repro: a writer that hits ERR_MEM because *other*
    /// connections exhausted the shared segment pool must be woken by the
    /// capacity those connections release. The only runtime signal on that
    /// path is some pcb's sent callback (an ACK freeing segments), so a
    /// foreign ACK event after a free must reach the parked writer instead
    /// of leaving it to the 4-second tcp_poll fallback.
    #[test]
    fn foreign_ack_wakes_writer_parked_on_shared_pool_exhaustion() {
        let _test_guard = LWIP_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        crate::stack_impl::initialize_lwip(primary());

        let mut hoard = SegPoolHoard::exhaust();
        let mut victim = {
            let _guard = LWIP_MUTEX.lock();
            unsafe { TcpStreamImpl::new(fake_established_pcb(), primary()) }
        };

        let (victim_wakes, waker) = counting_waker();
        let mut cx = Context::from_waker(&waker);
        let poll = Pin::new(&mut *victim).poll_write(&mut cx, &[0u8; 4096]);
        assert!(
            matches!(poll, Poll::Pending),
            "a write against an exhausted segment pool must park, got {poll:?}"
        );

        // Another connection's teardown/ACK returns one segment to the pool,
        // and its sent callback fires — exactly what tcp_input does after
        // freeing acked segments.
        hoard.release_one();
        let foreign_ctx = TcpStreamContext::new("127.0.0.1:9999".parse().unwrap(), primary());
        {
            let _guard = LWIP_MUTEX.lock();
            let foreign_ptr = std::ptr::from_ref(&foreign_ctx).cast_mut().cast();
            tcp_sent_cb(foreign_ptr, std::ptr::null_mut(), 1);
        }

        assert_eq!(
            victim_wakes.0.load(Ordering::Relaxed),
            1,
            "the freed capacity never reached the parked writer"
        );
    }

    /// A dropped stream must leave the pressure queue before its context is
    /// freed; a later capacity event must neither crash nor consume a wake
    /// on the dead entry.
    #[test]
    fn drop_removes_the_stream_from_the_pressure_queue() {
        let _test_guard = LWIP_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        crate::stack_impl::initialize_lwip(primary());

        let _hoard = SegPoolHoard::exhaust();
        let mut victim = {
            let _guard = LWIP_MUTEX.lock();
            unsafe { TcpStreamImpl::new(fake_established_pcb(), primary()) }
        };

        let (_victim_wakes, waker) = counting_waker();
        let mut cx = Context::from_waker(&waker);
        let poll = Pin::new(&mut *victim).poll_write(&mut cx, &[0u8; 4096]);
        assert!(matches!(poll, Poll::Pending));
        {
            let _guard = LWIP_MUTEX.lock();
            assert_eq!(
                unsafe { crate::tcp_stream_context::pressure_queue_len_locked(primary()) },
                1
            );
        }

        drop(victim);
        {
            let _guard = LWIP_MUTEX.lock();
            assert_eq!(
                unsafe { crate::tcp_stream_context::pressure_queue_len_locked(primary()) },
                0
            );
        }

        let foreign_ctx = TcpStreamContext::new("127.0.0.1:9999".parse().unwrap(), primary());
        {
            let _guard = LWIP_MUTEX.lock();
            let foreign_ptr = std::ptr::from_ref(&foreign_ctx).cast_mut().cast();
            tcp_sent_cb(foreign_ptr, std::ptr::null_mut(), 1);
        }
    }

    /// tcp_output failures during flush are transmission deferrals — the
    /// bytes are already queued on the pcb and lwIP retries them from its
    /// ACK/timer paths (poll_write already treats the same condition that
    /// way). Fatal connection states arrive via tcp_err_cb, never here.
    #[test]
    fn poll_flush_defers_transient_output_errors() {
        let _test_guard = LWIP_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        crate::stack_impl::initialize_lwip(primary());

        struct NetifListRestore(*mut netif);
        impl Drop for NetifListRestore {
            fn drop(&mut self) {
                let _guard = LWIP_MUTEX.lock();
                unsafe { netif_list = self.0 };
            }
        }

        let mut stream = {
            let _guard = LWIP_MUTEX.lock();
            unsafe { TcpStreamImpl::new(fake_established_pcb(), primary()) }
        };

        let (_, waker) = counting_waker();
        let mut cx = Context::from_waker(&waker);
        let wrote = Pin::new(&mut *stream).poll_write(&mut cx, &[0u8; 512]);
        assert!(matches!(wrote, Poll::Ready(Ok(512))), "got {wrote:?}");

        // Force the transmit attempt itself to fail deterministically: with
        // no routable netif, tcp_output returns ERR_RTE while the 512 bytes
        // stay queued on the pcb — the same shape as egress backpressure
        // (whose netif hook returns ERR_MEM with the segment retained).
        let _restore = {
            let _guard = LWIP_MUTEX.lock();
            let restore = NetifListRestore(unsafe { netif_list });
            unsafe { netif_list = std::ptr::null_mut() };
            restore
        };
        let flush = Pin::new(&mut *stream).poll_flush(&mut cx);
        assert!(
            matches!(flush, Poll::Ready(Ok(()))),
            "a deferred transmission is not a stream error, got {flush:?}"
        );
    }

    #[test]
    fn tcp_sent_consumes_the_registered_write_waker() {
        let context = TcpStreamContext::new("127.0.0.1:1234".parse().unwrap(), primary());
        let wake_counter = Arc::new(WakeCounter(AtomicUsize::new(0)));
        {
            let guard = LWIP_MUTEX.lock();
            context.with_lock(&guard).write_waker = Some(Waker::from(Arc::clone(&wake_counter)));
        }

        let _guard = LWIP_MUTEX.lock();
        let context_ptr = std::ptr::from_ref(&context).cast_mut().cast();
        tcp_sent_cb(context_ptr, std::ptr::null_mut(), 1);
        tcp_sent_cb(context_ptr, std::ptr::null_mut(), 1);

        assert_eq!(wake_counter.0.load(Ordering::Relaxed), 1);
        assert!(unsafe { TcpStreamContext::assume_locked(&context) }
            .write_waker
            .is_none());
    }

    /// The receive-window credit for delivered bytes is granted during the
    /// NEXT poll's locked phase instead of a dedicated post-copy lock; the
    /// deferral must neither leak credit nor grant it early.
    #[test]
    fn read_window_credit_is_granted_on_the_next_poll() {
        let _test_guard = LWIP_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        crate::stack_impl::initialize_lwip(primary());

        let (mut stream, pcb) = {
            let _guard = LWIP_MUTEX.lock();
            let pcb = unsafe { fake_established_pcb() };
            (TcpStreamImpl::new(pcb, primary()), pcb)
        };

        let wnd_start = {
            let _guard = LWIP_MUTEX.lock();
            unsafe {
                // Deliver 2000 bytes the way tcp_input does, shrinking the
                // window as lwIP would have when it accepted the segments.
                let ctx_ptr = std::ptr::from_ref(&stream.callback_ctx)
                    .cast_mut()
                    .cast::<raw::c_void>();
                for _ in 0..2 {
                    let p = pbuf_alloc(pbuf_layer_PBUF_RAW, 1000, pbuf_type_PBUF_RAM);
                    assert!(!p.is_null());
                    tcp_recv_cb(ctx_ptr, pcb, p, err_enum_t_ERR_OK as err_t);
                }
                (*pcb).rcv_wnd -= 2000;
                (*pcb).rcv_wnd
            }
        };

        let (_, waker) = counting_waker();
        let mut cx = Context::from_waker(&waker);
        let mut scratch = [0u8; 4096];
        let mut read_buf = ReadBuf::new(&mut scratch);
        let poll = Pin::new(&mut *stream).poll_read(&mut cx, &mut read_buf);
        assert!(matches!(poll, Poll::Ready(Ok(()))));
        assert_eq!(read_buf.filled().len(), 2000);
        {
            let _guard = LWIP_MUTEX.lock();
            assert_eq!(
                unsafe { (*pcb).rcv_wnd },
                wnd_start,
                "credit must not be granted in the same poll"
            );
        }

        let mut read_buf = ReadBuf::new(&mut scratch);
        let poll = Pin::new(&mut *stream).poll_read(&mut cx, &mut read_buf);
        assert!(matches!(poll, Poll::Pending));
        {
            let _guard = LWIP_MUTEX.lock();
            assert_eq!(
                unsafe { (*pcb).rcv_wnd },
                wnd_start + 2000,
                "the next poll's locked phase grants the deferred credit"
            );
        }
    }

    /// Payload bytes must survive the pbuf handoff exactly — including a
    /// chained delivery read out through a buffer smaller than either node,
    /// which forces cursor advances both inside a node and across the link.
    #[test]
    fn chained_pbuf_delivery_survives_partial_reads() {
        let _test_guard = LWIP_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        crate::stack_impl::initialize_lwip(primary());

        let (mut stream, pcb) = {
            let _guard = LWIP_MUTEX.lock();
            let pcb = unsafe { fake_established_pcb() };
            (TcpStreamImpl::new(pcb, primary()), pcb)
        };

        const FIRST: usize = 1100;
        const SECOND: usize = 900;
        let mut expected = Vec::with_capacity(FIRST + SECOND);
        expected.extend((0..FIRST).map(|i| (i % 251) as u8));
        expected.extend((0..SECOND).map(|i| (i.wrapping_mul(7) % 253) as u8));

        {
            let _guard = LWIP_MUTEX.lock();
            unsafe {
                let a = pbuf_alloc(pbuf_layer_PBUF_RAW, FIRST as u16, pbuf_type_PBUF_RAM);
                let b = pbuf_alloc(pbuf_layer_PBUF_RAW, SECOND as u16, pbuf_type_PBUF_RAM);
                assert!(!a.is_null() && !b.is_null());
                std::ptr::copy_nonoverlapping(expected.as_ptr(), (*a).payload.cast::<u8>(), FIRST);
                std::ptr::copy_nonoverlapping(
                    expected.as_ptr().add(FIRST),
                    (*b).payload.cast::<u8>(),
                    SECOND,
                );
                pbuf_cat(a, b);
                let ctx_ptr = std::ptr::from_ref(&stream.callback_ctx)
                    .cast_mut()
                    .cast::<raw::c_void>();
                tcp_recv_cb(ctx_ptr, pcb, a, err_enum_t_ERR_OK as err_t);
            }
        }

        let (_, waker) = counting_waker();
        let mut cx = Context::from_waker(&waker);
        let mut delivered = Vec::new();
        // 700 divides into neither node length: reads land mid-node, at the
        // node boundary's far side, and across the final tail.
        let mut scratch = [0u8; 700];
        loop {
            let mut read_buf = ReadBuf::new(&mut scratch);
            match Pin::new(&mut *stream).poll_read(&mut cx, &mut read_buf) {
                Poll::Ready(Ok(())) if read_buf.filled().is_empty() => break,
                Poll::Ready(Ok(())) => delivered.extend_from_slice(read_buf.filled()),
                Poll::Pending => break,
                other => panic!("unexpected poll result: {other:?}"),
            }
            if delivered.len() >= expected.len() {
                break;
            }
        }
        assert_eq!(delivered.len(), expected.len());
        assert_eq!(delivered, expected, "handoff must not reorder or corrupt");
    }

    /// Chains handed to the reader are returned to lwIP on the NEXT poll's
    /// locked phase, and teardown returns everything still queued — the
    /// global queued-packet accounting must come back to its baseline.
    #[test]
    fn handed_off_chains_are_returned_on_next_poll_and_teardown() {
        let _test_guard = LWIP_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        crate::stack_impl::initialize_lwip(primary());
        let baseline = crate::tcp_stream_context::tcp_runtime_stats();

        let (mut stream, pcb) = {
            let _guard = LWIP_MUTEX.lock();
            let pcb = unsafe { fake_established_pcb() };
            (TcpStreamImpl::new(pcb, primary()), pcb)
        };

        let deliver = |stream: &TcpStreamImpl, bytes: u16| {
            let _guard = LWIP_MUTEX.lock();
            unsafe {
                let p = pbuf_alloc(pbuf_layer_PBUF_RAW, bytes, pbuf_type_PBUF_RAM);
                assert!(!p.is_null());
                let ctx_ptr = std::ptr::from_ref(&stream.callback_ctx)
                    .cast_mut()
                    .cast::<raw::c_void>();
                tcp_recv_cb(ctx_ptr, pcb, p, err_enum_t_ERR_OK as err_t);
            }
        };

        deliver(&stream, 640);
        let after_first = crate::tcp_stream_context::tcp_runtime_stats();
        assert_eq!(after_first.queued_packets, baseline.queued_packets + 1);
        assert_eq!(after_first.queued_bytes, baseline.queued_bytes + 640);

        let (_, waker) = counting_waker();
        let mut cx = Context::from_waker(&waker);
        let mut scratch = [0u8; 4096];
        let mut read_buf = ReadBuf::new(&mut scratch);
        let poll = Pin::new(&mut *stream).poll_read(&mut cx, &mut read_buf);
        assert!(matches!(poll, Poll::Ready(Ok(()))));
        assert_eq!(read_buf.filled().len(), 640);
        // Fully consumed, but the chain rides in `spent` until the next
        // locked phase returns it.
        let mut read_buf = ReadBuf::new(&mut scratch);
        let _ = Pin::new(&mut *stream).poll_read(&mut cx, &mut read_buf);
        let after_return = crate::tcp_stream_context::tcp_runtime_stats();
        assert_eq!(after_return.queued_packets, baseline.queued_packets);
        assert_eq!(after_return.queued_bytes, baseline.queued_bytes);

        // Teardown with undelivered chains still queued must return them too.
        deliver(&stream, 512);
        deliver(&stream, 256);
        drop(stream);
        let after_drop = crate::tcp_stream_context::tcp_runtime_stats();
        assert_eq!(after_drop.queued_packets, baseline.queued_packets);
        assert_eq!(after_drop.queued_bytes, baseline.queued_bytes);
        assert_eq!(after_drop.active_streams, baseline.active_streams);
    }
}
