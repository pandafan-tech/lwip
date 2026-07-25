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

#[derive(Debug, Clone, Copy)]
pub struct AtomicMutexErr;

impl std::fmt::Display for AtomicMutexErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Mutex is already locked")
    }
}

impl std::error::Error for AtomicMutexErr {}

#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
mod imp {
    use super::AtomicMutexErr;

    #[derive(Debug)]
    pub struct AtomicMutex {
        inner: parking_lot::Mutex<()>,
    }

    pub struct AtomicMutexGuard<'a> {
        _guard: parking_lot::MutexGuard<'a, ()>,
    }

    impl AtomicMutex {
        pub const fn new() -> Self {
            Self {
                inner: parking_lot::const_mutex(()),
            }
        }

        pub fn try_lock(&self) -> Result<AtomicMutexGuard<'_>, AtomicMutexErr> {
            self.inner
                .try_lock()
                .map(|guard| AtomicMutexGuard { _guard: guard })
                .ok_or(AtomicMutexErr)
        }

        pub fn lock(&self) -> AtomicMutexGuard<'_> {
            AtomicMutexGuard {
                _guard: self.inner.lock(),
            }
        }
    }
}

#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
mod imp {
    use super::AtomicMutexErr;
    use std::sync::atomic::{AtomicBool, Ordering::*};

    #[derive(Debug)]
    pub struct AtomicMutex {
        locked: AtomicBool,
    }

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
            // Bounded spin, then yield; see the module comment for why this
            // must never park on the small mobile runtimes.
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

    impl<'a> Drop for AtomicMutexGuard<'a> {
        fn drop(&mut self) {
            let _prev = self.mutex.locked.swap(false, Release);
            debug_assert!(_prev);
        }
    }
}

pub use imp::{AtomicMutex, AtomicMutexGuard};

impl Default for AtomicMutex {
    fn default() -> Self {
        Self::new()
    }
}
