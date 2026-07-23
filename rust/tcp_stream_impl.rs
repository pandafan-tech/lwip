use std::{cmp::min, io, net::SocketAddr, os::raw, pin::Pin, sync::Arc, sync::OnceLock};

use futures::task::{Context, Poll};
use log::*;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::lwip::*;
use super::packet::PacketPool;
use super::tcp_stream_context::{ActiveTcpStream, QueuedTcpPacket, TcpStreamContext};
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
    let ctx = &*unsafe { TcpStreamContext::assume_locked(arg as *const TcpStreamContext) };
    // trace!("netstack tcp sent {}", &ctx.local_addr);
    if let Some(waker) = ctx.write_waker.as_ref() {
        waker.wake_by_ref();
    }
    err_enum_t_ERR_OK as err_t
}

#[allow(unused_variables)]
pub extern "C" fn tcp_err_cb(arg: *mut ::std::os::raw::c_void, err: err_t) {
    // SAFETY: tcp_err_cb is called from
    // tcp_input, tcp_abandon, tcp_abort, tcp_alloc and tcp_new.
    // Thus lwip_mutex must be locked before calling any of these.
    let ctx = &mut *unsafe { TcpStreamContext::assume_locked(arg as *const TcpStreamContext) };
    trace!("netstack tcp err {} {}", err, ctx.local_addr);
    ctx.errored = true;
    if let Some(waker) = ctx.read_waker.take() {
        waker.wake();
    }
    if let Some(waker) = ctx.write_waker.as_ref() {
        waker.wake_by_ref();
    }
}

#[allow(unused_variables)]
pub extern "C" fn tcp_poll_cb(arg: *mut ::std::os::raw::c_void, tpcb: *mut tcp_pcb) -> err_t {
    let ctx = &*unsafe { TcpStreamContext::assume_locked(arg as *const TcpStreamContext) };
    // trace!("netstack tcp poll {}", &ctx.local_addr);
    if let Some(waker) = ctx.write_waker.as_ref() {
        waker.wake_by_ref();
    }
    err_enum_t_ERR_OK as err_t
}

pub struct TcpStreamImpl {
    src_addr: SocketAddr,
    dest_addr: SocketAddr,
    pcb: usize,
    read_buf: Option<(QueuedTcpPacket, usize)>,
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
        let guard = LWIP_MUTEX.lock();
        let ctx = &mut *me.callback_ctx.with_lock(&guard);
        if ctx.errored {
            return Poll::Ready(Err(broken_pipe()));
        }

        let mut consumed = 0usize;
        let result = loop {
            if buf.remaining() == 0 {
                break Poll::Ready(Ok(()));
            }

            if me.read_buf.is_none() {
                if let Some(data) = ctx.read_queue.pop_front() {
                    me.read_buf = Some((data, 0));
                } else if ctx.read_eof || consumed > 0 {
                    break Poll::Ready(Ok(()));
                } else {
                    let should_replace = ctx
                        .read_waker
                        .as_ref()
                        .map(|waker| !waker.will_wake(cx.waker()))
                        .unwrap_or(true);
                    if should_replace {
                        ctx.read_waker = Some(cx.waker().clone());
                    }
                    break Poll::Pending;
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

        let mut unacknowledged = consumed;
        while unacknowledged > 0 {
            let acknowledged = unacknowledged.min(u16::MAX as usize);
            unsafe {
                tcp_recved(me.pcb as *mut tcp_pcb, acknowledged as u16_t);
            }
            unacknowledged -= acknowledged;
        }

        result
    }
}

impl Drop for TcpStreamImpl {
    fn drop(&mut self) {
        let guard = LWIP_MUTEX.lock();
        let ctx = &*self.callback_ctx.with_lock(&guard);
        trace!("netstack tcp drop {}", ctx.local_addr);
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
                    // poll_shutdown already half-closed TX (tcp_shutdown rx=0
                    // tx=1), so the pcb is in FIN_WAIT_1/2 awaiting the peer's
                    // FIN. Without TF_RXCLOSED, lwIP's slowtmr never reaps a
                    // FIN_WAIT_2 pcb — a peer that vanishes without FINing
                    // (suspended iOS app, dead link) leaks the pcb plus its
                    // unacked segments forever. tcp_close on an already
                    // TX-shut pcb just sets TF_RXCLOSED, enabling the
                    // TCP_FIN_WAIT_TIMEOUT (20 s) reap; it frees nothing we
                    // still reference. Fall back to abort if it errors.
                    if tcp_close(self.pcb as *mut tcp_pcb) != err_enum_t_ERR_OK as err_t {
                        tcp_abort(self.pcb as *mut tcp_pcb);
                    }
                }
            }
        }
    }
}

impl AsyncWrite for TcpStreamImpl {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context, buf: &[u8]) -> Poll<io::Result<usize>> {
        let guard = LWIP_MUTEX.lock();
        let ctx = &mut *self.callback_ctx.with_lock(&guard);
        if ctx.errored {
            return Poll::Ready(Err(broken_pipe()));
        }
        let to_write = buf.len().min(self.send_buf_size());
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
            // Call output in case of mem err?
            let err = unsafe { tcp_output(self.pcb as *mut tcp_pcb) };
            if err == err_enum_t_ERR_OK as err_t {
                Poll::Ready(Ok(to_write))
            } else {
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    format!("netstack tcp_output error {}", err),
                )))
            }
        } else if err == err_enum_t_ERR_MEM as err_t {
            // trace!("netstack tcp err_mem on {}", &local_addr);
            ctx.write_waker.replace(cx.waker().clone());
            Poll::Pending
        } else {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::Interrupted,
                format!("netstack tcp_write error {}", err),
            )))
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        let guard = LWIP_MUTEX.lock();
        if self.callback_ctx.with_lock(&guard).errored {
            return Poll::Ready(Err(broken_pipe()));
        }
        let err = unsafe { tcp_output(self.pcb as *mut tcp_pcb) };
        if err != err_enum_t_ERR_OK as err_t {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::Interrupted,
                format!("netstack tcp_output error {}", err),
            )))
        } else {
            Poll::Ready(Ok(()))
        }
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
