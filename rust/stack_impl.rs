use std::{io, os::raw, pin::Pin, sync::Once, time};

use futures::sink::Sink;
use futures::stream::Stream;
use futures::task::{Context, Poll};
use tokio::sync::mpsc::{channel, Receiver, Sender};

use super::lwip::*;
use super::output::{output_ip4, output_ip6, OUTPUT_CB_PTR};
use super::packet::{IpPacket, PacketPool, PacketPoolStats};
use super::{LWIPMutexGuard, LWIP_MUTEX};

static LWIP_INIT: Once = Once::new();
const DEFAULT_MTU: u16 = 1500;
const OUTPUT_PACKET_CACHE: usize = 256;
const OUTPUT_PACKET_MAX_CAPACITY: usize = 2048;
const _: () = assert!(MEM_ALIGNMENT == 1);

#[repr(C)]
struct OwnedInputPbuf {
    custom: pbuf_custom,
    packet: Vec<u8>,
}

unsafe extern "C" fn release_owned_input_pbuf(pbuf: *mut pbuf) {
    // SAFETY: OwnedInputPbuf is repr(C), `custom` is its first field, and
    // bindgen's repr(C) pbuf_custom has `pbuf` as its first field. Therefore
    // the pbuf pointer returned by pbuf_alloced_custom is also the original
    // Box allocation pointer. lwIP invokes this callback exactly once when
    // the custom pbuf's final reference is released.
    drop(unsafe { Box::from_raw(pbuf.cast::<OwnedInputPbuf>()) });
}

fn input_owned_packet_locked(packet: Vec<u8>, _guard: &LWIPMutexGuard<'_>) -> err_t {
    let Ok(length) = u16_t::try_from(packet.len()) else {
        log::warn!(
            "input frame exceeds the lwIP pbuf length limit: {} bytes",
            packet.len()
        );
        return err_enum_t_ERR_BUF as err_t;
    };

    let custom = pbuf_custom {
        pbuf: unsafe { std::mem::zeroed() },
        custom_free_function: Some(release_owned_input_pbuf),
    };
    let mut owned = Box::new(OwnedInputPbuf { custom, packet });
    let pbuf = unsafe {
        pbuf_alloced_custom(
            pbuf_layer_PBUF_RAW,
            length,
            pbuf_type_PBUF_REF,
            &mut owned.custom,
            owned.packet.as_mut_ptr().cast::<raw::c_void>(),
            length,
        )
    };
    if pbuf.is_null() {
        // PBUF_RAW has no header offset and payload_mem_len equals length, so
        // this indicates an ABI/configuration mismatch rather than pressure:
        // pbuf_alloced_custom itself performs no allocation.
        log::error!("pbuf_alloced_custom rejected a correctly sized PBUF_RAW frame");
        return err_enum_t_ERR_BUF as err_t;
    }

    let owned_ptr = Box::into_raw(owned);
    debug_assert_eq!(pbuf.cast::<OwnedInputPbuf>(), owned_ptr);

    // ERR_OK transfers ownership to lwIP. The IP/TCP/UDP path either releases
    // the pbuf during this call or retains a reference and invokes the custom
    // free callback later.
    let err = unsafe { lwip_rs_netif_input(pbuf) };
    if err != err_enum_t_ERR_OK as err_t {
        // A rejected input has not consumed the caller's reference.
        unsafe {
            pbuf_free(pbuf);
        }
        log::warn!("netif input rejected frame: {}", err);
    }
    err
}

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
        Self::new_with_mtu(buffer_size, DEFAULT_MTU)
    }

    pub(crate) fn new_with_mtu(buffer_size: usize, mtu: u16) -> Box<Self> {
        LWIP_INIT.call_once(|| unsafe { lwip_init() });

        unsafe { lwip_rs_configure_netif(Some(output_ip4), Some(output_ip6), mtu) };

        let (tx, rx): (Sender<IpPacket>, Receiver<IpPacket>) = channel(buffer_size);
        let output_pool = PacketPool::new(
            buffer_size.clamp(1, OUTPUT_PACKET_CACHE),
            OUTPUT_PACKET_MAX_CAPACITY,
        );

        // 250ms matches lwIP's TCP timer granularity, but it is also the only
        // millisecond-scale wait on the whole data path: delayed ACKs flush on
        // tcp_fasttmr, which only this loop drives. A flow that falls into a
        // wait-for-timer rhythm shows up as near-zero CPU with collapsed
        // throughput (measured: 0.66 Gbit/s at 0.01 cores on a Windows
        // guest). Overridable to let that hypothesis be tested per platform.
        let timer_interval = std::env::var("PANDA_LWIP_TIMER_MS")
            .ok()
            .and_then(|raw| raw.parse::<u64>().ok())
            .filter(|ms| (1..=1000).contains(ms))
            .unwrap_or(250);
        let timeout_task = tokio::spawn(async move {
            loop {
                {
                    let _g = LWIP_MUTEX.lock();
                    unsafe { sys_check_timeouts() };
                }
                // The guard is released before this await: abort() can only
                // cancel the task at the await point, so the lock is never
                // abandoned in the locked state.
                tokio::time::sleep(time::Duration::from_millis(timer_interval)).await;
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
        let guard = LWIP_MUTEX.lock();
        for item in items {
            if item.is_empty() {
                continue;
            }
            let _ = input_owned_packet_locked(item, &guard);
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
            let guard = LWIP_MUTEX.lock();
            let _ = input_owned_packet_locked(item, &guard);
            // A rejected frame is a per-packet event, not a stack-fatal one.
            // Callers treat a Sink error as fatal and tear down the packet
            // path, so preserve the IP-device behavior of dropping it.
            Poll::Ready(Ok(()))
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NetifListRestore(*mut netif);

    impl Drop for NetifListRestore {
        fn drop(&mut self) {
            unsafe {
                netif_list = self.0;
            }
        }
    }

    #[test]
    fn netif_rejection_is_reported_without_panicking() {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap()
            .block_on(async {
                let stack = NetStackImpl::new(1);
                {
                    let guard = LWIP_MUTEX.lock();
                    let previous = unsafe { netif_list };
                    let _restore = NetifListRestore(previous);
                    unsafe {
                        netif_list = std::ptr::null_mut();
                    }

                    let err = input_owned_packet_locked(vec![0x45; 20], &guard);
                    assert_eq!(err, err_enum_t_ERR_IF as err_t);
                }
                drop(stack);
            });
    }
}
