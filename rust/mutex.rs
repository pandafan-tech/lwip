use std::sync::atomic::{AtomicBool, Ordering::*};
use std::time::Instant;

// NOTE (regression revert 2026-06-15): this lock was briefly switched to a
// `parking_lot::Mutex` to "kill the spin-lock livelock". That blocked the tokio
// worker OS thread on contention. Because LWIP_MUTEX is taken on every lwIP
// entry point — including *held across* `poll_recv()` in the stack/UDP/TCP
// poll paths and re-acquired inside `Drop` impls that run on worker threads —
// parking it under post-sleep/wake replay bursts wedged the small (4-worker)
// iOS packet-tunnel runtime: the data path froze while the process/runtime
// stayed alive (VPN connected, RSS flat). It did NOT freeze on the spin-lock
// build. The original livelock's real root cause — a herd of leaked
// `sys_check_timeouts` timer tasks (each NetStackImpl leaked an immortal 250 ms
// task) — was fixed independently by aborting the timer task in
// `NetStackImpl::drop`, so there is now a single timer task and this
// spin-then-yield lock has near-zero contention. Do not reintroduce a blocking
// mutex here without an async-aware redesign of the lwIP core lock.
//
// ALSO MEASURED AND REVERTED (2026-07-26): parking the waiters on desktop.
// The theory was that the Windows guest's contention storm came from
// yield-spinning waiters, which a parking lock cannot do. Paired against
// sing-box on that guest it made things worse, not better: 0.74-0.79 Gbit/s
// single-flow while burning 1.1-2.6 cores — the burn moved from spinning
// into park/unpark futex traffic, a syscall (often a vmexit) per lock
// handoff at per-packet frequency. Go dodges this because goroutines park in
// user space. The spin-then-yield lock stays on every platform; the real
// contention fixes are shorter critical sections (the poll_read staging
// change) and fewer lock entries per packet.
//
// ALSO MEASURED AND REVERTED (2026-08-11): deferring all callback wakes to
// the guard's release (steal a wake list under the lock, wake after the
// release store). The theory was that waking inside the critical section
// sends the woken task straight into a spin on the still-held mutex — the
// 7-8% sched_yield convoy in the 16-flow Linux TUN profile. Measured on
// that exact workload it lost 5-18% throughput at slightly HIGHER CPU:
// the spinning waiter is a hot standby that takes the lock the moment it
// is released, so in-tenure wakes pipeline the next tenure, while deferred
// wakes leave the lock idle for a wake+reschedule round trip between
// tenures. The yield burn is the price of zero-gap lock handoff, not
// waste. Do not retry wake deferral wholesale; if the convoy needs
// shrinking, remove lock *entries* instead.
//
// ALSO MEASURED AND REVERTED (2026-08-11, round 2): TTAS (load-only spin,
// swap on observed-free) plus a 4096-iteration desktop spin budget before
// yielding. Lock-stats telemetry had shown the lock idle 37% of wall time
// on 16-flow bidirectional while waiters averaged 19 µs in the yield loop,
// so the theory was scheduling-latency handoff gaps. Screened interleaved
// A/B/A/B on that workload: download f16 +7% both rounds, bidirectional
// inside testbed noise (+10.8%/-0.4%), CPU +20-26% on bidirectional — and
// the telemetry under the new policy showed TOTAL WAIT UNCHANGED (~1.5
// cores) at util 0.67-0.70. The wait is queueing behind real 4-6 µs
// tenures among ~5 contenders, not post-yield wake latency, so spinning
// hotter only converts yields into burned cycles. Do not raise the spin
// budget again; capacity comes from shorter/fewer tenures or from stack
// sharding (two isolated stacks measured 2.0x aggregate on the same
// testbed). TTAS alone (budget 64) was not screened in isolation and
// remains a legitimate quiet-window candidate.

/// Opt-in lock diagnostics (`PANDA_LWIP_LOCK_STATS=1`), answering the one
/// question profiles cannot: what fraction of wall time the global lock is
/// HELD, and which entry sites own that time. When disabled (the default)
/// the hot path pays a single relaxed load and an untaken branch.
pub mod lock_stats {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};

    pub const SITE_OTHER: usize = 0;
    pub const SITE_INPUT: usize = 1;
    pub const SITE_TIMER: usize = 2;
    pub const SITE_READ: usize = 3;
    pub const SITE_WRITE: usize = 4;
    pub const SITE_FLUSH: usize = 5;
    pub const SITE_RETRY: usize = 6;
    pub const NSITES: usize = 7;
    pub const SITE_NAMES: [&str; NSITES] =
        ["other", "input", "timer", "read", "write", "flush", "retry"];

    pub static ENABLED: AtomicBool = AtomicBool::new(false);

    #[derive(Debug)]
    pub struct SiteStats {
        pub count: AtomicU64,
        pub held_ns: AtomicU64,
        pub wait_ns: AtomicU64,
    }

    #[allow(clippy::declare_interior_mutable_const)]
    const ZERO: SiteStats = SiteStats {
        count: AtomicU64::new(0),
        held_ns: AtomicU64::new(0),
        wait_ns: AtomicU64::new(0),
    };
    pub static SITES: [SiteStats; NSITES] = [ZERO; NSITES];

    /// Reads the env switch once; called from stack initialization.
    pub fn init_from_env() {
        if std::env::var_os("PANDA_LWIP_LOCK_STATS").is_some() {
            ENABLED.store(true, Relaxed);
        }
    }

    /// Delta snapshot since the previous call, formatted for one stderr line.
    pub fn drain_report(elapsed_secs: f64) -> String {
        use std::fmt::Write as _;
        let mut line = String::with_capacity(256);
        let mut total_held = 0u64;
        let mut total_wait = 0u64;
        for (idx, site) in SITES.iter().enumerate() {
            let count = site.count.swap(0, Relaxed);
            let held = site.held_ns.swap(0, Relaxed);
            let wait = site.wait_ns.swap(0, Relaxed);
            total_held += held;
            total_wait += wait;
            if count == 0 {
                continue;
            }
            let _ = write!(
                line,
                " {}: n={} held={:.1}ms avg={}ns wait={:.1}ms;",
                SITE_NAMES[idx],
                count,
                held as f64 / 1e6,
                held / count,
                wait as f64 / 1e6,
            );
        }
        format!(
            "lwip-lock-stats dt={:.1}s util={:.3} wait_total={:.1}ms{}",
            elapsed_secs,
            total_held as f64 / 1e9 / elapsed_secs,
            total_wait as f64 / 1e6,
            line
        )
    }
}

#[derive(Debug)]
pub struct AtomicMutex {
    locked: AtomicBool,
}

#[derive(Debug, Clone, Copy)]
pub struct AtomicMutexErr;

impl std::fmt::Display for AtomicMutexErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Mutex is already locked")
    }
}

impl std::error::Error for AtomicMutexErr {}

pub struct AtomicMutexGuard<'a> {
    mutex: &'a AtomicMutex,
    // Present only while PANDA_LWIP_LOCK_STATS is on: the acquire timestamp
    // and the site index that owns this tenure in the stats table.
    stats: Option<(Instant, usize)>,
}

impl AtomicMutex {
    pub const fn new() -> Self {
        Self {
            locked: AtomicBool::new(false),
        }
    }

    pub fn try_lock(&self) -> Result<AtomicMutexGuard<'_>, AtomicMutexErr> {
        if self.locked.swap(true, Acquire) {
            Err(AtomicMutexErr)
        } else {
            Ok(AtomicMutexGuard {
                mutex: self,
                stats: None,
            })
        }
    }

    pub fn lock(&self) -> AtomicMutexGuard<'_> {
        self.lock_at(lock_stats::SITE_OTHER)
    }

    pub fn lock_at(&self, site: usize) -> AtomicMutexGuard<'_> {
        // Bounded spin, then yield. The previous pure `loop { try_lock }`
        // burned the whole OS thread while waiting: on a small tokio
        // runtime (worker_threads(2) in the iOS packet tunnel), one worker
        // holding the lock in sys_check_timeouts while another spun here
        // meant NO other task could be polled — with enough contenders the
        // runtime live-locked permanently. Yielding lets the OS reschedule
        // the holder (and lets other runtime threads make progress) at the
        // cost of a syscall on the slow path. Unlike a parking mutex, this
        // never blocks the worker thread off the scheduler.
        let started = if lock_stats::ENABLED.load(Relaxed) {
            Some(Instant::now())
        } else {
            None
        };
        let mut spins = 0u32;
        let mut guard = loop {
            if let Ok(m) = self.try_lock() {
                break m;
            }
            spins += 1;
            if spins < 64 {
                std::hint::spin_loop();
            } else {
                std::thread::yield_now();
            }
        };
        if let Some(started) = started {
            let acquired = Instant::now();
            let stats = &lock_stats::SITES[site];
            stats.count.fetch_add(1, Relaxed);
            stats
                .wait_ns
                .fetch_add((acquired - started).as_nanos() as u64, Relaxed);
            guard.stats = Some((acquired, site));
        }
        guard
    }
}

impl Default for AtomicMutex {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> Drop for AtomicMutexGuard<'a> {
    fn drop(&mut self) {
        if let Some((acquired, site)) = self.stats.take() {
            lock_stats::SITES[site]
                .held_ns
                .fetch_add(acquired.elapsed().as_nanos() as u64, Relaxed);
        }
        let _prev = self.mutex.locked.swap(false, Release);
        debug_assert!(_prev);
    }
}
