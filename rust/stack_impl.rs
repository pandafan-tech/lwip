use std::{
    io,
    os::raw,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Once,
    },
    time,
};

#[cfg(any(windows, test))]
use std::{ffi::OsStr, sync::OnceLock};

use futures::sink::Sink;
use futures::stream::Stream;
use futures::task::{Context, Poll};
use tokio::sync::mpsc::{channel, error::TrySendError, Receiver, Sender, WeakSender};

use super::lwip::*;
use super::output::{output_ip4, output_ip6, OUTPUT_CB_PTR};
use super::packet::{IpPacket, PacketPool, PacketPoolStats};
use super::{LWIPMutexGuard, LWIP_MUTEX};

static LWIP_INIT: Once = Once::new();
static EGRESS_BACKPRESSURED: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
pub(crate) static LWIP_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
pub(crate) const DEFAULT_MTU: u16 = 1500;
const OUTPUT_PACKET_CACHE: usize = 256;
const OUTPUT_PACKET_MAX_CAPACITY: usize = 2048;
const _: () = assert!(MEM_ALIGNMENT == 1);
#[cfg(target_os = "ios")]
const _: () = assert!(MEMP_NUM_TCP_PCB == 1024);
#[cfg(windows)]
const _: () = assert!(TCP_WND == 2872 * PANDA_BASE_TCP_MSS);
#[cfg(windows)]
const _: () = assert!(TCP_WND_RUNTIME_DEFAULT == 512 * PANDA_BASE_TCP_MSS);

#[cfg(windows)]
const TCP_RCV_WND_MSS_ENV: &str = "PANDA_LWIP_TCP_RCV_WND_MSS";
#[cfg(windows)]
static WINDOWS_TCP_RCV_WINDOW: OnceLock<std::result::Result<u32, String>> = OnceLock::new();

#[cfg(any(windows, test))]
fn parse_windows_tcp_rcv_window_mss(
    raw: Option<&OsStr>,
    compiled_max_mss: u32,
    default_mss: u32,
) -> Result<u32, String> {
    let value = match raw {
        Some(raw) => raw
            .to_str()
            .ok_or_else(|| "value must be valid UTF-8".to_owned())?
            .parse::<u32>()
            .map_err(|_| "value must be an unsigned decimal integer".to_owned())?,
        None => default_mss,
    };

    if !(2..=compiled_max_mss).contains(&value) {
        return Err(format!(
            "value must be between 2 and {compiled_max_mss} MSS, got {value}"
        ));
    }

    Ok(value)
}

#[cfg(any(windows, test))]
fn initialize_windows_tcp_rcv_window_once<Read, Apply>(
    config: &OnceLock<std::result::Result<u32, String>>,
    read: Read,
    compiled_max_mss: u32,
    default_mss: u32,
    base_mss: u32,
    apply: Apply,
) -> std::result::Result<u32, String>
where
    Read: FnOnce() -> Option<std::ffi::OsString>,
    Apply: FnOnce(u32) -> std::result::Result<(), String>,
{
    config
        .get_or_init(|| {
            let raw = read();
            let active_mss =
                parse_windows_tcp_rcv_window_mss(raw.as_deref(), compiled_max_mss, default_mss)?;
            let active_window = active_mss
                .checked_mul(base_mss)
                .ok_or_else(|| "active TCP receive window overflowed u32".to_owned())?;
            apply(active_window)?;
            Ok(active_window)
        })
        .clone()
}

/// Validate and apply the Windows lwIP runtime environment exactly once.
///
/// Both success and failure are cached for the process lifetime. Other
/// platforms return success without reading the Windows-only environment.
#[cfg(windows)]
pub fn initialize_windows_runtime_config() -> super::Result<()> {
    let compiled_max_mss = TCP_WND / PANDA_BASE_TCP_MSS;
    let default_mss = TCP_WND_RUNTIME_DEFAULT / PANDA_BASE_TCP_MSS;
    initialize_windows_tcp_rcv_window_once(
        &WINDOWS_TCP_RCV_WINDOW,
        || std::env::var_os(TCP_RCV_WND_MSS_ENV),
        compiled_max_mss,
        default_mss,
        PANDA_BASE_TCP_MSS,
        |active_window| {
            let result = unsafe { tcp_set_wnd_runtime(active_window) };
            if result != err_enum_t_ERR_OK as err_t {
                return Err(format!(
                    "{TCP_RCV_WND_MSS_ENV} produced {active_window} bytes outside the C runtime bounds"
                ));
            }
            log::info!(
                "lwIP TCP receive window: compiled_max={} bytes ({} MSS), active={} bytes ({} MSS)",
                TCP_WND,
                compiled_max_mss,
                active_window,
                active_window / PANDA_BASE_TCP_MSS
            );
            Ok(())
        },
    )
    .map(|_| ())
    .map_err(|error| {
        super::Error::RuntimeConfig(format!("{TCP_RCV_WND_MSS_ENV}: {error}"))
    })?;
    super::udp::initialize_windows_udp_runtime_config()
}

#[cfg(not(windows))]
pub fn initialize_windows_runtime_config() -> super::Result<()> {
    Ok(())
}

fn initialize_lwip() {
    initialize_windows_runtime_config().unwrap_or_else(|error| panic!("{error}"));
    LWIP_INIT.call_once(|| unsafe { lwip_init() });
}

pub(crate) fn mark_egress_backpressured() {
    EGRESS_BACKPRESSURED.store(true, Ordering::Release);
}

pub(crate) fn retry_backpressured_tcp_output() {
    if !EGRESS_BACKPRESSURED.swap(false, Ordering::AcqRel) {
        return;
    }

    let _guard = LWIP_MUTEX.lock();
    let err = unsafe { lwip_rs_retry_tcp_output() };
    if err != err_enum_t_ERR_OK as err_t && !EGRESS_BACKPRESSURED.load(Ordering::Acquire) {
        log::warn!("lwIP deferred TCP output retry failed: {err}");
    }
}

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
        initialize_lwip();

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

    pub(crate) fn egress_sender(&self) -> WeakSender<IpPacket> {
        self.tx.downgrade()
    }

    pub(crate) fn output(&mut self, pkt: IpPacket) -> Result<(), TrySendError<IpPacket>> {
        // tokio's mpsc wakes the receiver on try_send; no manual waker is
        // needed, so egress consumers never have to touch LWIP_MUTEX.
        self.tx.try_send(pkt)
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
        let result = match rx.poll_recv(cx) {
            Poll::Ready(Some(pkt)) => Poll::Ready(Some(Ok(pkt))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        };
        if matches!(&result, Poll::Ready(Some(_))) {
            retry_backpressured_tcp_output();
        }
        result
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
    use std::ffi::OsString;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct NetifListRestore(*mut netif);

    impl Drop for NetifListRestore {
        fn drop(&mut self) {
            unsafe {
                netif_list = self.0;
            }
        }
    }

    #[cfg(not(windows))]
    struct TcpWndRuntimeRestore(tcpwnd_size_t);

    #[cfg(not(windows))]
    impl Drop for TcpWndRuntimeRestore {
        fn drop(&mut self) {
            unsafe {
                assert_eq!(tcp_set_wnd_runtime(self.0), err_enum_t_ERR_OK as err_t);
            }
        }
    }

    #[test]
    fn tcp_pcb_pool_reaches_its_compiled_capacity_before_exhaustion() {
        let _test_guard = LWIP_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _guard = LWIP_MUTEX.lock();
        initialize_lwip();

        unsafe {
            let capacity = MEMP_NUM_TCP_PCB as usize;
            let mut pcbs = Vec::with_capacity(capacity);
            for index in 0..capacity {
                let pcb = tcp_new();
                assert!(
                    !pcb.is_null(),
                    "TCP PCB pool exhausted at {index} of {capacity} configured slots"
                );
                pcbs.push(pcb);
            }

            assert!(
                tcp_new().is_null(),
                "TCP PCB pool exceeded its configured capacity of {capacity}"
            );

            for pcb in pcbs {
                tcp_abort(pcb);
            }
        }
    }

    #[test]
    fn tcp_send_queue_can_segment_the_largest_rust_write_at_1500_mtu() {
        let write_bytes = (TCP_SND_BUF as usize).min(u16::MAX as usize);
        let base_mss = PANDA_BASE_TCP_MSS as usize;
        let required_segments = write_bytes.div_ceil(base_mss);

        assert!(
            TCP_SND_QUEUELEN as usize >= required_segments,
            "TCP_SND_QUEUELEN={} cannot segment the {}-byte write into {}-byte MSS packets; \
             TcpStreamImpl::poll_write would repeat ERR_MEM without sending data",
            TCP_SND_QUEUELEN,
            write_bytes,
            base_mss,
        );
    }

    #[test]
    fn netif_rejection_is_reported_without_panicking() {
        let _test_guard = LWIP_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
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

    #[test]
    fn windows_tcp_receive_window_parser_accepts_only_the_supported_range() {
        assert_eq!(
            parse_windows_tcp_rcv_window_mss(None, 2872, 512).unwrap(),
            512
        );
        assert_eq!(
            parse_windows_tcp_rcv_window_mss(Some("2".as_ref()), 2872, 512).unwrap(),
            2
        );
        assert_eq!(
            parse_windows_tcp_rcv_window_mss(Some("2872".as_ref()), 2872, 512).unwrap(),
            2872
        );

        for invalid in ["", "one", "1", "2873", "2.0", " 512"] {
            assert!(
                parse_windows_tcp_rcv_window_mss(Some(invalid.as_ref()), 2872, 512).is_err(),
                "{invalid:?} must be rejected"
            );
        }
    }

    #[test]
    fn windows_tcp_receive_window_parser_rejects_non_utf8() {
        #[cfg(unix)]
        let invalid = {
            use std::os::unix::ffi::OsStringExt;
            OsString::from_vec(vec![0xff])
        };
        #[cfg(windows)]
        let invalid = {
            use std::os::windows::ffi::OsStringExt;
            OsString::from_wide(&[0xd800])
        };

        assert!(parse_windows_tcp_rcv_window_mss(Some(&invalid), 2872, 512).is_err());
    }

    #[test]
    fn windows_runtime_config_reads_and_applies_once_under_concurrency() {
        let config = std::sync::OnceLock::new();
        let reads = AtomicUsize::new(0);
        let applies = AtomicUsize::new(0);

        std::thread::scope(|scope| {
            let mut tasks = Vec::new();
            for _ in 0..8 {
                tasks.push(scope.spawn(|| {
                    initialize_windows_tcp_rcv_window_once(
                        &config,
                        || {
                            reads.fetch_add(1, Ordering::SeqCst);
                            Some(OsString::from("512"))
                        },
                        2872,
                        512,
                        PANDA_BASE_TCP_MSS,
                        |_| {
                            applies.fetch_add(1, Ordering::SeqCst);
                            Ok(())
                        },
                    )
                }));
            }
            for task in tasks {
                assert_eq!(task.join().unwrap().unwrap(), 512 * PANDA_BASE_TCP_MSS);
            }
        });

        assert_eq!(reads.load(Ordering::SeqCst), 1);
        assert_eq!(applies.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn windows_runtime_config_caches_failure_without_rereading() {
        let config = std::sync::OnceLock::new();
        let reads = AtomicUsize::new(0);
        let applies = AtomicUsize::new(0);

        let first = initialize_windows_tcp_rcv_window_once(
            &config,
            || {
                reads.fetch_add(1, Ordering::SeqCst);
                Some(OsString::from("1"))
            },
            2872,
            512,
            PANDA_BASE_TCP_MSS,
            |_| {
                applies.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        );
        let second = initialize_windows_tcp_rcv_window_once(
            &config,
            || {
                reads.fetch_add(1, Ordering::SeqCst);
                Some(OsString::from("512"))
            },
            2872,
            512,
            PANDA_BASE_TCP_MSS,
            |_| {
                applies.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        );

        assert_eq!(first, second);
        assert!(first.is_err());
        assert_eq!(reads.load(Ordering::SeqCst), 1);
        assert_eq!(applies.load(Ordering::SeqCst), 0);
    }

    #[cfg(not(windows))]
    #[test]
    fn tcp_runtime_receive_window_rejects_values_below_two_base_mss() {
        let _test_guard = LWIP_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _guard = LWIP_MUTEX.lock();
        initialize_lwip();

        unsafe {
            let _restore = TcpWndRuntimeRestore(TCP_WND);
            assert_eq!(
                tcp_set_wnd_runtime((2 * PANDA_BASE_TCP_MSS) - 1),
                err_enum_t_ERR_VAL as err_t
            );
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn tcp_recved_stays_capped_at_the_runtime_receive_window() {
        let _test_guard = LWIP_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _guard = LWIP_MUTEX.lock();
        initialize_lwip();

        unsafe {
            let original_window = TCP_WND;
            assert_eq!(original_window, TCP_WND);

            assert_eq!(tcp_set_wnd_runtime(0), err_enum_t_ERR_VAL as err_t);
            assert_eq!(
                tcp_set_wnd_runtime(TCP_WND + 1),
                err_enum_t_ERR_VAL as err_t
            );
            let unchanged_pcb = tcp_new();
            assert!(!unchanged_pcb.is_null());
            assert_eq!((*unchanged_pcb).rcv_wnd_max, original_window);
            tcp_abort(unchanged_pcb);

            let initial_window = 2 * PANDA_BASE_TCP_MSS;
            assert_eq!(
                tcp_set_wnd_runtime(initial_window),
                err_enum_t_ERR_OK as err_t
            );
            let _restore = TcpWndRuntimeRestore(original_window);

            let initial_pcb = tcp_new();
            assert!(!initial_pcb.is_null());
            assert_eq!((*initial_pcb).rcv_wnd_max, initial_window);
            assert_eq!((*initial_pcb).rcv_wnd, initial_window);
            tcp_abort(initial_pcb);

            let active_window = (128 * PANDA_BASE_TCP_MSS).min(TCP_WND - PANDA_BASE_TCP_MSS);
            assert_eq!(
                tcp_set_wnd_runtime(active_window),
                err_enum_t_ERR_OK as err_t
            );
            let pcb = tcp_new();
            assert!(!pcb.is_null());
            assert_eq!((*pcb).rcv_wnd_max, active_window);
            assert_eq!((*pcb).rcv_wnd, u16::MAX as tcpwnd_size_t);

            assert_eq!(tcp_set_wnd_runtime(TCP_WND), err_enum_t_ERR_OK as err_t);
            assert_eq!((*pcb).rcv_wnd_max, active_window);
            (*pcb).flags |= TF_WND_SCALE as tcpflags_t;
            (*pcb).rcv_wnd = active_window - 1;
            tcp_recved(pcb, u16::MAX);
            assert_eq!((*pcb).rcv_wnd, active_window);
            assert_ne!((*pcb).rcv_wnd, TCP_WND);

            tcp_abort(pcb);
        }
    }
}
