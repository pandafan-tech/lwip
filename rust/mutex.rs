use std::sync::atomic::{AtomicBool, Ordering::*};

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
            Ok(AtomicMutexGuard { mutex: self })
        }
    }

    pub fn lock(&self) -> AtomicMutexGuard<'_> {
        // Bounded spin, then yield. The previous pure `loop { try_lock }`
        // burned the whole OS thread while waiting: on a small tokio
        // runtime (worker_threads(2) in the iOS packet tunnel), one worker
        // holding the lock in sys_check_timeouts while another spun here
        // meant NO other task could be polled — with enough contenders the
        // runtime live-locked permanently. Yielding lets the OS reschedule
        // the holder (and lets other runtime threads make progress) at the
        // cost of a syscall on the slow path. Unlike a parking mutex, this
        // never blocks the worker thread off the scheduler.
        let mut spins = 0u32;
        loop {
            if let Ok(m) = self.try_lock() {
                break m;
            }
            spins += 1;
            if spins < 64 {
                std::hint::spin_loop();
            } else {
                std::thread::yield_now();
            }
        }
    }
}

impl Default for AtomicMutex {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> Drop for AtomicMutexGuard<'a> {
    fn drop(&mut self) {
        let _prev = self.mutex.locked.swap(false, Release);
        debug_assert!(_prev);
    }
}
