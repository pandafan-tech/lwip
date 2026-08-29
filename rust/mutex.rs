use std::sync::atomic::{AtomicBool, AtomicU8, Ordering::*};
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

// Spin-then-park escalation (2026-08-29). The pure spin-then-yield wait
// loop was measured burning ~2.0 of 4.3 total cores on the 16-flow MTU-1500
// download (lock-stats: util 2.51 with wait_total ~9.9 s per 5 s window)
// once the 15640-MSS relay writes stretched tenures to ~26 µs — the
// yield-spin price scales with tenure length, and the three historical
// anti-parking verdicts above were all measured in the 4-6 µs-tenure,
// single-global-lock era. The hybrid keeps their lessons: the fast path is
// exactly the old CAS, short tenures still hand off through the bounded
// spin/yield phase with zero-gap pipelining, and only waits that outlive
// that budget park on a futex-class queue (parking_lot_core), freeing the
// worker for other tasks. Mobile keeps the pure spin-then-yield loop: the
// iOS packet-tunnel livelock note above is about parked workers on a tiny
// runtime, and nothing was re-measured there. `PANDA_LWIP_LOCK_PARK=0` is
// the desktop escape hatch back to the old behavior.
const LOCK_SPIN_BUDGET: u32 = 64;
const LOCK_YIELD_BUDGET: u32 = 16;

const PARK_SUPPORTED: bool = cfg!(not(any(
    target_os = "ios",
    target_os = "tvos",
    target_os = "android"
)));

/// Runtime switch for the park escalation, resolved once at stack
/// initialization (`lock_stats::init_from_env` timing). Defaults to the
/// platform gate; `PANDA_LWIP_LOCK_PARK=0`/`1` overrides on supported
/// platforms, and any other value fails loud at parse time.
pub(crate) static PARK_ENABLED: AtomicBool = AtomicBool::new(PARK_SUPPORTED);

pub(crate) fn init_park_from_env() -> Result<(), String> {
    let Some(raw) = std::env::var_os("PANDA_LWIP_LOCK_PARK") else {
        return Ok(());
    };
    match raw.to_str() {
        Some("1") => {
            if !PARK_SUPPORTED {
                return Err(
                    "PANDA_LWIP_LOCK_PARK=1 is not supported on mobile packet tunnels".to_owned(),
                );
            }
            PARK_ENABLED.store(true, Relaxed);
            Ok(())
        }
        Some("0") => {
            PARK_ENABLED.store(false, Relaxed);
            Ok(())
        }
        other => Err(format!(
            "PANDA_LWIP_LOCK_PARK must be \"0\" or \"1\", got {other:?}"
        )),
    }
}

// Lock word protocol (classic three-state futex mutex):
//   0 = free, 1 = held (uncontended), 2 = held with possible parked waiters.
// Fast-path acquirers CAS 0->1; any thread that reaches the park phase
// acquires with 2 instead, so its own unlock keeps waking the queue, and a
// woken waiter re-marks a stolen lock 1->2 before parking again — parked
// threads therefore always have either the mark or an awake guardian.
const UNLOCKED: u8 = 0;
const LOCKED: u8 = 1;
const LOCKED_CONTENDED: u8 = 2;

// One cache line per lock (128 covers Apple Silicon lines and the x86
// adjacent-line prefetcher pair): the per-shard mutexes live in adjacent
// statics, and two shards spin-waiting on one shared line would ping-pong
// it between cores at packet rate.
#[derive(Debug)]
#[repr(align(128))]
pub struct AtomicMutex {
    state: AtomicU8,
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
            state: AtomicU8::new(UNLOCKED),
        }
    }

    pub fn try_lock(&self) -> Result<AtomicMutexGuard<'_>, AtomicMutexErr> {
        if self
            .state
            .compare_exchange(UNLOCKED, LOCKED, Acquire, Relaxed)
            .is_ok()
        {
            Ok(AtomicMutexGuard {
                mutex: self,
                stats: None,
            })
        } else {
            Err(AtomicMutexErr)
        }
    }

    pub fn lock(&self) -> AtomicMutexGuard<'_> {
        self.lock_at(lock_stats::SITE_OTHER)
    }

    pub fn lock_at(&self, site: usize) -> AtomicMutexGuard<'_> {
        // Bounded spin, then yield, then (desktop) park. The pure
        // `loop { try_lock }` history is above: spinning without yields
        // live-locked the small iOS runtime, and unbounded yielding burns
        // a core per waiter once tenures grow past a few microseconds.
        let started = if lock_stats::ENABLED.load(Relaxed) {
            Some(Instant::now())
        } else {
            None
        };
        let mut guard = match self.try_lock() {
            Ok(guard) => guard,
            Err(AtomicMutexErr) => self.lock_contended(),
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

    #[cold]
    fn lock_contended(&self) -> AtomicMutexGuard<'_> {
        let park = PARK_ENABLED.load(Relaxed);
        let mut spins = 0u32;
        // Once this thread has parked it must keep acquiring with the
        // contended mark so its own unlock continues waking the queue.
        let mut acquire_contended = false;
        loop {
            let observed = self.state.load(Relaxed);
            if observed == UNLOCKED {
                let next = if acquire_contended {
                    LOCKED_CONTENDED
                } else {
                    LOCKED
                };
                if self
                    .state
                    .compare_exchange_weak(UNLOCKED, next, Acquire, Relaxed)
                    .is_ok()
                {
                    return AtomicMutexGuard {
                        mutex: self,
                        stats: None,
                    };
                }
                continue;
            }
            spins += 1;
            if spins < LOCK_SPIN_BUDGET {
                std::hint::spin_loop();
                continue;
            }
            if !park || spins < LOCK_SPIN_BUDGET + LOCK_YIELD_BUDGET {
                std::thread::yield_now();
                continue;
            }
            // Escalate: publish the contended mark, then park until an
            // unlock hands the queue a wake. The validate closure re-checks
            // the mark so an unlock racing this park aborts it instead of
            // stranding the thread.
            if observed == LOCKED
                && self
                    .state
                    .compare_exchange(LOCKED, LOCKED_CONTENDED, Relaxed, Relaxed)
                    .is_err()
            {
                continue;
            }
            unsafe {
                let _ = parking_lot_core::park(
                    self.park_key(),
                    || self.state.load(Relaxed) == LOCKED_CONTENDED,
                    || {},
                    |_, _| {},
                    parking_lot_core::DEFAULT_PARK_TOKEN,
                    None,
                );
            }
            acquire_contended = true;
            // Woken (or aborted): retry with a fresh yield budget before
            // the next park so short holder tenures still hand off without
            // another futex round trip.
            spins = LOCK_SPIN_BUDGET;
        }
    }

    fn park_key(&self) -> usize {
        std::ptr::from_ref(self) as usize
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
        let prev = self.mutex.state.swap(UNLOCKED, Release);
        debug_assert!(prev != UNLOCKED);
        if prev == LOCKED_CONTENDED {
            // Someone may be parked; hand the queue one wake. A spurious
            // wake on an already-empty queue is a cheap hash-bucket probe.
            unsafe {
                parking_lot_core::unpark_one(self.mutex.park_key(), |_| {
                    parking_lot_core::DEFAULT_UNPARK_TOKEN
                });
            }
        }
    }
}
