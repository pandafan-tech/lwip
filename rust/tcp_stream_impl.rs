use std::{cmp::min, io, net::SocketAddr, os::raw, pin::Pin, sync::Arc, sync::OnceLock};

use futures::task::{Context, Poll};
use log::*;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::lwip::*;
use super::packet::PacketPool;
use super::tcp_stream_context::{
    pressure_park_locked, pressure_remove_locked, pressure_unpark_all_locked,
    pressure_unpark_one_locked, ActiveTcpStream, QueuedTcpPacket, TcpStreamContext,
};
use super::util;
use super::LWIP_MUTEX;

const TCP_PACKET_CACHE: usize = 16;
const TCP_PACKET_MAX_CAPACITY: usize = u16::MAX as usize;
static TCP_PACKET_POOL: OnceLock<Arc<PacketPool>> = OnceLock::new();

fn tcp_packet_pool() -> &'static Arc<PacketPool> {
    TCP_PACKET_POOL.get_or_init(|| PacketPool::new(TCP_PACKET_CACHE, TCP_PACKET_MAX_CAPACITY))
}

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
    let ctx = &mut *TcpStreamContext::assume_locked(arg as *const TcpStreamContext);

    if p.is_null() {
        trace!("netstack tcp eof {}", ctx.local_addr);
        ctx.read_eof = true;
        if let Some(waker) = ctx.read_waker.take() {
            waker.wake();
        }
        return err_enum_t_ERR_OK as err_t;
    }

    let pbuflen = std::ptr::read_unaligned(p).tot_len;
    let mut packet = tcp_packet_pool().acquire(pbuflen as usize);
    let copied = pbuf_copy_partial(
        p,
        packet.spare_capacity_mut().as_mut_ptr().cast(),
        pbuflen,
        0,
    );
    pbuf_free(p);
    if copied != pbuflen {
        warn!("short lwIP TCP pbuf copy: {copied}/{pbuflen}");
        return err_enum_t_ERR_OK as err_t;
    }
    packet.set_len(pbuflen as usize);

    if !packet.is_empty() {
        ctx.read_queue.push_back(QueuedTcpPacket::new(packet));
        if let Some(waker) = ctx.read_waker.take() {
            waker.wake();
        }
    }

    err_enum_t_ERR_OK as err_t
}

#[allow(unused_variables)]
pub extern "C" fn tcp_sent_cb(arg: *mut raw::c_void, tpcb: *mut tcp_pcb, len: u16_t) -> err_t {
    // SAFETY: tcp_sent_cb is called from tcp_input only when
    // an ACK packet is received. Thus lwip_mutex must be locked.
    // See also `<NetStackImpl as AsyncWrite>::poll_write`.
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
    unsafe { pressure_unpark_one_locked() };
    err_enum_t_ERR_OK as err_t
}

#[allow(unused_variables)]
pub extern "C" fn tcp_err_cb(arg: *mut ::std::os::raw::c_void, err: err_t) {
    // SAFETY: tcp_err_cb is called from
    // tcp_input, tcp_abandon, tcp_abort, tcp_alloc and tcp_new.
    // Thus lwip_mutex must be locked before calling any of these.
    {
        let mut ctx = unsafe { TcpStreamContext::assume_locked(arg as *const TcpStreamContext) };
        trace!("netstack tcp err {} {}", err, ctx.local_addr);
        ctx.errored = true;
        // An errored stream is done writing; a stale pressure entry must not
        // swallow an unpark meant for a live writer.
        unsafe { pressure_remove_locked(arg as *const TcpStreamContext, &mut ctx) };
        if let Some(waker) = ctx.read_waker.take() {
            waker.wake();
        }
        if let Some(waker) = ctx.write_waker.take() {
            waker.wake();
        }
    }
    // lwIP freed the pcb and everything it had queued before invoking us;
    // that bulk capacity can unblock every parked writer.
    unsafe { pressure_unpark_all_locked() };
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

pub struct TcpStreamImpl {
    src_addr: SocketAddr,
    dest_addr: SocketAddr,
    pcb: usize,
    read_buf: Option<(QueuedTcpPacket, usize)>,
    // Segments already claimed from the shared read_queue but not yet copied
    // out. Draining into this under the lock and copying from it after
    // releasing keeps the memcpy out of the global critical section — with
    // the copy inside it, a relay pulling tens of kilobytes stalls the whole
    // stack's input path for the duration, which on a preemption-prone host
    // is what feeds the spin-yield contention storm.
    staged: std::collections::VecDeque<QueuedTcpPacket>,
    // Bytes copied out to the reader whose tcp_recved window credit has not
    // been granted yet; flushed at the start of the next poll_read's locked
    // phase. Owned by the single reader task, so no lock guards it.
    pending_recved: usize,
    callback_ctx: TcpStreamContext,
    _active: ActiveTcpStream,
}

impl TcpStreamImpl {
    pub fn new(pcb: *mut tcp_pcb) -> Box<Self> {
        unsafe {
            // The receive callback and AsyncRead consumer both run under
            // LWIP_MUTEX, so a direct queue avoids the redundant atomics and
            // per-packet wake path of a thread-safe channel. lwIP owns flow
            // control: we only call tcp_recved after the Rust consumer has
            // actually copied bytes out of this queue.
            let mut remote_ip = std::mem::zeroed();
            let mut remote_port = 0;
            let mut local_ip = std::mem::zeroed();
            let mut local_port = 0;
            lwip_rs_tcp_endpoints(
                pcb,
                &mut remote_ip,
                &mut remote_port,
                &mut local_ip,
                &mut local_port,
            );
            let src_addr = util::to_socket_addr(&remote_ip, remote_port);
            let dest_addr = util::to_socket_addr(&local_ip, local_port);
            let stream = Box::new(TcpStreamImpl {
                src_addr,
                dest_addr,
                pcb: pcb as usize,
                read_buf: None,
                staged: std::collections::VecDeque::new(),
                pending_recved: 0,
                callback_ctx: TcpStreamContext::new(src_addr),
                _active: ActiveTcpStream::new(),
            });
            let arg = &stream.callback_ctx as *const _;
            tcp_arg(pcb, arg as *mut raw::c_void);
            tcp_recv(pcb, Some(tcp_recv_cb));
            tcp_sent(pcb, Some(tcp_sent_cb));
            tcp_err(pcb, Some(tcp_err_cb));
            tcp_poll(pcb, Some(tcp_poll_cb), 8 as _);
            stream.apply_pcb_opts();
            trace!("netstack tcp new {}", stream.local_addr());
            stream
        }
    }

    fn apply_pcb_opts(&self) {
        unsafe {
            lwip_rs_tcp_apply_options(self.pcb as *mut tcp_pcb, cfg!(target_os = "ios") as i32);
        }
    }

    pub fn local_addr(&self) -> &SocketAddr {
        &self.src_addr
    }

    pub fn remote_addr(&self) -> &SocketAddr {
        &self.dest_addr
    }

    fn send_buf_size(&self) -> usize {
        unsafe { lwip_rs_tcp_send_buffer(self.pcb as *const tcp_pcb) as usize }
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

        // Locked phase one: flush the receive-window credit from the previous
        // poll, claim everything queued, and register the waker if there is
        // nothing to deliver. No copying happens under the lock. Folding
        // tcp_recved into this tenure (instead of a dedicated post-copy lock)
        // halves the reader's lock entries; the window opens one poll later,
        // which a 256-MSS receive window never notices, and a reader that
        // stalls on upstream backpressure keeps the window closed — which is
        // exactly the flow control lwIP should see.
        let read_eof;
        {
            let guard = LWIP_MUTEX.lock_at(super::mutex::lock_stats::SITE_READ);
            let ctx = &mut *me.callback_ctx.with_lock(&guard);
            if ctx.errored {
                return Poll::Ready(Err(broken_pipe()));
            }
            while me.pending_recved > 0 {
                let acknowledged = me.pending_recved.min(usize::from(u16::MAX));
                unsafe {
                    tcp_recved(me.pcb as *mut tcp_pcb, acknowledged as u16_t);
                }
                me.pending_recved -= acknowledged;
            }
            while let Some(data) = ctx.read_queue.pop_front() {
                me.staged.push_back(data);
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

        // Unlocked phase: copy into the caller's buffer.
        let mut consumed = 0usize;
        let result = loop {
            if buf.remaining() == 0 {
                break Poll::Ready(Ok(()));
            }

            if me.read_buf.is_none() {
                if let Some(data) = me.staged.pop_front() {
                    me.read_buf = Some((data, 0));
                } else {
                    // Everything staged was delivered; either this poll made
                    // progress or the peer closed.
                    debug_assert!(read_eof || consumed > 0);
                    break Poll::Ready(Ok(()));
                }
            }

            let (data, offset) = me
                .read_buf
                .as_mut()
                .expect("TCP read buffer is present after dequeue");
            let to_read = min(buf.remaining(), data.len() - *offset);
            buf.put_slice(&data[*offset..*offset + to_read]);
            *offset += to_read;
            consumed += to_read;
            if *offset == data.len() {
                me.read_buf.take();
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
        let guard = LWIP_MUTEX.lock();
        {
            let mut ctx = self.callback_ctx.with_lock(&guard);
            trace!("netstack tcp drop {}", ctx.local_addr);
            // The context is about to be freed with the stream; it must leave
            // the pressure queue while the pointer is still valid.
            unsafe {
                pressure_remove_locked(&self.callback_ctx as *const _, &mut ctx);
            }
            if !ctx.errored {
                unsafe {
                    tcp_arg(self.pcb as *mut tcp_pcb, std::ptr::null_mut());
                    tcp_recv(self.pcb as *mut tcp_pcb, None);
                    tcp_sent(self.pcb as *mut tcp_pcb, None);
                    tcp_err(self.pcb as *mut tcp_pcb, None);
                    tcp_poll(self.pcb as *mut tcp_pcb, None, 0);
                    if !ctx.closed {
                        tcp_abort(self.pcb as *mut tcp_pcb);
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
                        if tcp_close(self.pcb as *mut tcp_pcb) != err_enum_t_ERR_OK as err_t {
                            tcp_abort(self.pcb as *mut tcp_pcb);
                        }
                    }
                }
            }
        }
        // The abort above returned the pcb's queued segments and payload
        // memory to the shared pools; that bulk capacity can unblock every
        // parked writer. The own-context borrow ended with the scope.
        unsafe { pressure_unpark_all_locked() };
    }
}

impl AsyncWrite for TcpStreamImpl {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context, buf: &[u8]) -> Poll<io::Result<usize>> {
        let guard = LWIP_MUTEX.lock_at(super::mutex::lock_stats::SITE_WRITE);
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
            tcp_write(
                self.pcb as *mut tcp_pcb,
                buf.as_ptr() as *const raw::c_void,
                to_write as u16_t,
                TCP_WRITE_FLAG_COPY as u8,
            )
        };
        if err == err_enum_t_ERR_OK as err_t {
            let output_err = unsafe { tcp_output(self.pcb as *mut tcp_pcb) };
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
            unsafe { pressure_park_locked(&self.callback_ctx as *const _, ctx) };
            Poll::Pending
        } else {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::Interrupted,
                format!("netstack tcp_write error {}", err),
            )))
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        let guard = LWIP_MUTEX.lock_at(super::mutex::lock_stats::SITE_FLUSH);
        if self.callback_ctx.with_lock(&guard).errored {
            return Poll::Ready(Err(broken_pipe()));
        }
        let err = unsafe { tcp_output(self.pcb as *mut tcp_pcb) };
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
        let guard = LWIP_MUTEX.lock();
        let ctx = &mut *self.callback_ctx.with_lock(&guard);
        if ctx.errored {
            return Poll::Ready(Err(broken_pipe()));
        }
        trace!("netstack tcp shutdown {}", ctx.local_addr);
        let err = unsafe { tcp_shutdown(self.pcb as *mut tcp_pcb, 0, 1) };
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
    use crate::stack_impl::LWIP_TEST_LOCK;
    use std::sync::atomic::{AtomicUsize, Ordering};
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
        crate::stack_impl::initialize_lwip();

        let mut hoard = SegPoolHoard::exhaust();
        let mut victim = {
            let _guard = LWIP_MUTEX.lock();
            unsafe { TcpStreamImpl::new(fake_established_pcb()) }
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
        let foreign_ctx = TcpStreamContext::new("127.0.0.1:9999".parse().unwrap());
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
        crate::stack_impl::initialize_lwip();

        let _hoard = SegPoolHoard::exhaust();
        let mut victim = {
            let _guard = LWIP_MUTEX.lock();
            unsafe { TcpStreamImpl::new(fake_established_pcb()) }
        };

        let (_victim_wakes, waker) = counting_waker();
        let mut cx = Context::from_waker(&waker);
        let poll = Pin::new(&mut *victim).poll_write(&mut cx, &[0u8; 4096]);
        assert!(matches!(poll, Poll::Pending));
        {
            let _guard = LWIP_MUTEX.lock();
            assert_eq!(
                unsafe { crate::tcp_stream_context::pressure_queue_len_locked() },
                1
            );
        }

        drop(victim);
        {
            let _guard = LWIP_MUTEX.lock();
            assert_eq!(
                unsafe { crate::tcp_stream_context::pressure_queue_len_locked() },
                0
            );
        }

        let foreign_ctx = TcpStreamContext::new("127.0.0.1:9999".parse().unwrap());
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
        crate::stack_impl::initialize_lwip();

        struct NetifListRestore(*mut netif);
        impl Drop for NetifListRestore {
            fn drop(&mut self) {
                let _guard = LWIP_MUTEX.lock();
                unsafe { netif_list = self.0 };
            }
        }

        let mut stream = {
            let _guard = LWIP_MUTEX.lock();
            unsafe { TcpStreamImpl::new(fake_established_pcb()) }
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
        let context = TcpStreamContext::new("127.0.0.1:1234".parse().unwrap());
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
        crate::stack_impl::initialize_lwip();

        let (mut stream, pcb) = {
            let _guard = LWIP_MUTEX.lock();
            let pcb = unsafe { fake_established_pcb() };
            (TcpStreamImpl::new(pcb), pcb)
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
}
