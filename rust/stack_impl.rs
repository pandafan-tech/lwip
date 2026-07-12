use std::{io, os::raw, pin::Pin, sync::Once, time};

use futures::sink::Sink;
use futures::stream::Stream;
use futures::task::{Context, Poll};
use tokio::sync::mpsc::{channel, Receiver, Sender};

use super::lwip::*;
use super::output::{output_ip4, output_ip6, OUTPUT_CB_PTR};
use super::packet::{IpPacket, PacketPool, PacketPoolStats};
use super::LWIP_MUTEX;

static LWIP_INIT: Once = Once::new();
const OUTPUT_PACKET_CACHE: usize = 256;
const OUTPUT_PACKET_MAX_CAPACITY: usize = 2048;

pub struct NetStackImpl {
    tx: Sender<IpPacket>,
    // Taken by `take_egress()` so a consumer can drain egress packets from a
    // dedicated task while another task feeds ingress through the Sink half.
    rx: Option<Receiver<IpPacket>>,
    output_pool: std::sync::Arc<PacketPool>,
    sink_buf: Option<Vec<u8>>, // We're flushing per item, no need large buffer.
    // Drives lwIP's sys_check_timeouts; aborted in Drop. Without the abort,
    // every NetStackImpl ever created leaks an immortal 250 ms timer task.
    // A consumer that restarts its stack on network changes (e.g. an iOS
    // packet tunnel cycling on sleep/wake) accumulates them: ~100 leaked
    // tasks contending for the LWIP_MUTEX spin lock every 250 ms saturated
    // both tokio workers — one inside sys_check_timeouts, one spinning —
    // and live-locked the entire runtime (observed on-device 2026-06-07).
    timeout_task: tokio::task::JoinHandle<()>,
}

impl NetStackImpl {
    pub fn new(buffer_size: usize) -> Box<Self> {
        LWIP_INIT.call_once(|| unsafe { lwip_init() });

        unsafe { lwip_rs_configure_netif(Some(output_ip4), Some(output_ip6), 1500) };

        let (tx, rx): (Sender<IpPacket>, Receiver<IpPacket>) = channel(buffer_size);
        let output_pool = PacketPool::new(
            buffer_size.min(OUTPUT_PACKET_CACHE).max(1),
            OUTPUT_PACKET_MAX_CAPACITY,
        );

        let timeout_task = tokio::spawn(async move {
            loop {
                {
                    let _g = LWIP_MUTEX.lock();
                    unsafe { sys_check_timeouts() };
                }
                // The guard is released before this await: abort() can only
                // cancel the task at the await point, so the lock is never
                // abandoned in the locked state.
                tokio::time::sleep(time::Duration::from_millis(250)).await;
            }
        });

        let stack = Box::new(NetStackImpl {
            tx,
            rx: Some(rx),
            output_pool,
            sink_buf: None,
            timeout_task,
        });

        unsafe {
            OUTPUT_CB_PTR = &*stack as *const NetStackImpl as usize;
        }

        stack
    }

    pub(crate) fn acquire_output_packet(&self, length: usize) -> IpPacket {
        self.output_pool.acquire(length)
    }

    pub(crate) fn output(&mut self, pkt: IpPacket) {
        // tokio's mpsc wakes the receiver on try_send; no manual waker is
        // needed, so egress consumers never have to touch LWIP_MUTEX.
        if self.tx.try_send(pkt).is_err() {
            // log::trace!("try send stack output pkt failed: {}", e);
        }
    }

    /// Take the egress receiver so packets leaving lwIP can be drained from a
    /// dedicated task, concurrently with ingress. Panics if taken twice.
    pub(crate) fn take_egress(&mut self) -> Receiver<IpPacket> {
        self.rx
            .take()
            .expect("netstack egress receiver already taken")
    }

    /// Push a whole batch of ingress IP packets into lwIP under a single
    /// LWIP_MUTEX acquisition. Per-packet locking dominated the ingress cost
    /// at high packet rates; a TUN read batch is the natural lock scope.
    pub(crate) fn input_batch<I>(&mut self, items: I)
    where
        I: IntoIterator<Item = Vec<u8>>,
    {
        let _g = LWIP_MUTEX.lock();
        for item in items {
            if item.is_empty() {
                continue;
            }
            unsafe {
                let pbuf = pbuf_alloc(pbuf_layer_PBUF_RAW, item.len() as u16_t, pbuf_type_PBUF_RAM);
                if pbuf.is_null() {
                    // lwIP heap exhaustion: an IP device may drop frames under
                    // memory pressure — the sender retransmits.
                    log::warn!(
                        "pbuf_alloc failed (heap exhausted), dropping {} byte frame",
                        item.len()
                    );
                    continue;
                }
                pbuf_take(
                    pbuf,
                    item.as_ptr() as *const raw::c_void,
                    item.len() as u16_t,
                );
                let err = lwip_rs_netif_input(pbuf);
                if err != err_enum_t_ERR_OK as err_t {
                    pbuf_free(pbuf);
                    log::warn!("netif input rejected frame: {}", err);
                }
            }
        }
    }

    pub(crate) fn output_pool_stats(&self) -> PacketPoolStats {
        self.output_pool.stats()
    }
}

impl Drop for NetStackImpl {
    fn drop(&mut self) {
        log::trace!("drop netstack");
        let stats = self.output_pool_stats();
        log::debug!(
            "lwip output pool: allocations={}, reuses={}, returned={}, discarded={}, cached={}",
            stats.allocations,
            stats.reuses,
            stats.returned,
            stats.discarded,
            stats.cached
        );
        self.timeout_task.abort();
        unsafe {
            let _g = LWIP_MUTEX.lock();
            // Only clear the output hook if it still points at us. If a
            // successor stack was created before this one finished tearing
            // down (a stop/start race in the consumer), unconditionally
            // zeroing here would sever the LIVE stack's egress path.
            if OUTPUT_CB_PTR == self as *const NetStackImpl as usize {
                OUTPUT_CB_PTR = 0x0;
            }
        };
    }
}

impl Stream for NetStackImpl {
    type Item = io::Result<IpPacket>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Plain channel read: the sender side (lwIP output callback) already
        // runs under LWIP_MUTEX, and tokio's mpsc handles waking.
        let rx = self
            .rx
            .as_mut()
            .expect("netstack egress receiver already taken");
        match rx.poll_recv(cx) {
            Poll::Ready(Some(pkt)) => Poll::Ready(Some(Ok(pkt))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Sink<Vec<u8>> for NetStackImpl {
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.sink_buf.is_none() {
            Poll::Ready(Ok(()))
        } else {
            self.poll_flush(cx)
        }
    }

    fn start_send(mut self: Pin<&mut Self>, item: Vec<u8>) -> Result<(), Self::Error> {
        self.sink_buf.replace(item);
        Ok(())
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if let Some(item) = self.sink_buf.take() {
            if item.is_empty() {
                return Poll::Ready(Ok(()));
            }
            unsafe {
                let _g = LWIP_MUTEX.lock();

                let pbuf = pbuf_alloc(pbuf_layer_PBUF_RAW, item.len() as u16_t, pbuf_type_PBUF_RAM);
                if pbuf.is_null() {
                    // lwIP heap exhaustion. Returning Pending here without
                    // registering a waker would park the Sink future forever
                    // (nothing ever re-polls it), deadlocking the netstack
                    // driver task that owns both ingress and egress. An IP
                    // device is allowed to drop frames under memory pressure
                    // — the sender retransmits — so drop and report success.
                    log::warn!(
                        "pbuf_alloc failed (heap exhausted), dropping {} byte frame",
                        item.len()
                    );
                    return Poll::Ready(Ok(()));
                }
                pbuf_take(
                    pbuf,
                    item.as_ptr() as *const raw::c_void,
                    item.len() as u16_t,
                );

                let err = lwip_rs_netif_input(pbuf);
                if err != err_enum_t_ERR_OK as err_t {
                    // A rejected frame is a per-packet event (e.g. ERR_MEM
                    // mid-burst), not a stack-fatal one. Drop it instead of
                    // erroring the Sink: callers treat a Sink error as
                    // fatal and tear down the whole packet path.
                    pbuf_free(pbuf);
                    log::warn!("netif input rejected frame: {}", err);
                }
                Poll::Ready(Ok(()))
            }
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}
