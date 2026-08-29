use lwip::{configure_pbuf_pool_capacity, pbuf_pool_runtime_stats, NetStack, PbufPoolRuntimeStats};
use std::ffi::{c_char, c_void};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};

const ACTIVE_CAPACITY: u16 = 32;

#[repr(C)]
struct Memp {
    next: *mut Memp,
}

#[repr(C)]
struct MempDesc {
    desc: *const c_char,
    size: u16,
    num: u16,
    base: *mut u8,
    tab: *mut *mut Memp,
}

unsafe extern "C" {
    static memp_PBUF_POOL: MempDesc;
    fn memp_malloc_pool(desc: *const MempDesc) -> *mut c_void;
    fn memp_free_pool(desc: *const MempDesc, mem: *mut c_void);
}

unsafe fn pbuf_pool_desc() -> &'static MempDesc {
    unsafe { &*std::ptr::addr_of!(memp_PBUF_POOL) }
}

unsafe fn assert_inactive_slots_untouched(effective: u16, expected_freelist: usize) {
    let desc = unsafe { pbuf_pool_desc() };
    let stride = usize::from(desc.size);
    let inactive_start = unsafe { desc.base.add(usize::from(effective) * stride) };
    let inactive_len = usize::from(desc.num - effective) * stride;
    let inactive = unsafe { std::slice::from_raw_parts(inactive_start, inactive_len) };

    assert!(
        inactive.iter().all(|byte| *byte == 0),
        "initialization dirtied at least one byte in the inactive PBUF_POOL slots"
    );

    let pool_end = unsafe { desc.base.add(usize::from(desc.num) * stride) } as usize;
    let inactive_start = inactive_start as usize;
    let mut inactive_freelist_nodes = 0;
    let mut freelist_len = 0;
    let mut node = unsafe { *desc.tab };
    while !node.is_null() {
        let address = node as usize;
        assert!(
            address >= desc.base as usize && address < pool_end,
            "PBUF_POOL freelist contains an out-of-pool pointer"
        );
        if address >= inactive_start {
            inactive_freelist_nodes += 1;
        }
        freelist_len += 1;
        assert!(
            freelist_len <= usize::from(desc.num),
            "PBUF_POOL freelist is cyclic"
        );
        node = unsafe { std::ptr::read_unaligned(node.cast::<*mut Memp>()) };
    }

    // Lazy carving (2026-08-29): the free list holds only RETURNED
    // elements — after a fresh init it is empty, and it grows as callers
    // free what they carved. The old eager contract (freelist == effective
    // at init) would itself dirty every active element's page.
    assert_eq!(freelist_len, expected_freelist);
    assert!(freelist_len <= usize::from(effective));
    assert_eq!(inactive_freelist_nodes, 0);
}

#[test]
fn pbuf_pool_runtime_limit_leaves_inactive_bss_untouched() {
    assert_eq!(
        pbuf_pool_runtime_stats(),
        PbufPoolRuntimeStats {
            configured: 512,
            effective: 0,
            compile_capacity: 512,
            used: 0,
            max_used: 0,
            alloc_failures: 0,
        }
    );

    for invalid in [0, 31, 513, u16::MAX] {
        assert!(
            configure_pbuf_pool_capacity(invalid).is_err(),
            "out-of-range capacity {invalid} must fail"
        );
    }
    configure_pbuf_pool_capacity(ACTIVE_CAPACITY).unwrap();
    assert_eq!(pbuf_pool_runtime_stats().configured, ACTIVE_CAPACITY);
    assert_eq!(pbuf_pool_runtime_stats().effective, 0);

    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap()
        .block_on(async {
            let stop_reader = Arc::new(AtomicBool::new(false));
            let reader_stop = Arc::clone(&stop_reader);
            let start = Arc::new(Barrier::new(2));
            let reader_start = Arc::clone(&start);
            let stats_reader = std::thread::spawn(move || {
                reader_start.wait();
                while !reader_stop.load(Ordering::Acquire) {
                    let stats = pbuf_pool_runtime_stats();
                    assert_eq!(stats.configured, ACTIVE_CAPACITY);
                    assert!(
                        matches!(stats.effective, 0 | ACTIVE_CAPACITY),
                        "stats observed a partially initialized effective capacity"
                    );
                    std::thread::yield_now();
                }
            });
            start.wait();
            let (stack, listener, udp) = NetStack::new().unwrap();
            stop_reader.store(true, Ordering::Release);
            stats_reader.join().expect("stats reader must not panic");

            let initialized = pbuf_pool_runtime_stats();
            assert_eq!(initialized.configured, ACTIVE_CAPACITY);
            assert_eq!(initialized.effective, ACTIVE_CAPACITY);
            assert_eq!(initialized.compile_capacity, 512);
            unsafe { assert_inactive_slots_untouched(ACTIVE_CAPACITY, 0) };

            configure_pbuf_pool_capacity(ACTIVE_CAPACITY)
                .expect("reapplying the active capacity must be idempotent");
            assert!(
                configure_pbuf_pool_capacity(64).is_err(),
                "capacity changes after lwIP initialization must fail"
            );

            drop(udp);
            drop(listener);
            drop(stack);

            configure_pbuf_pool_capacity(ACTIVE_CAPACITY)
                .expect("a sequential NetStack must accept the shared capacity");
            let (stack, listener, udp) = NetStack::new().unwrap();
            assert_eq!(
                pbuf_pool_runtime_stats().effective,
                ACTIVE_CAPACITY,
                "a sequential NetStack must reuse, not rebuild, the active pool"
            );
            unsafe { assert_inactive_slots_untouched(ACTIVE_CAPACITY, 0) };

            let mut allocated = Vec::new();
            loop {
                let slot = unsafe { memp_malloc_pool(std::ptr::addr_of!(memp_PBUF_POOL)) };
                if slot.is_null() {
                    break;
                }
                allocated.push(slot);
            }
            assert_eq!(allocated.len(), usize::from(ACTIVE_CAPACITY));

            let exhausted = pbuf_pool_runtime_stats();
            assert_eq!(exhausted.used, ACTIVE_CAPACITY);
            assert_eq!(exhausted.max_used, ACTIVE_CAPACITY);
            assert_eq!(exhausted.alloc_failures, 1);

            for slot in allocated {
                unsafe { memp_free_pool(std::ptr::addr_of!(memp_PBUF_POOL), slot) };
            }
            assert_eq!(pbuf_pool_runtime_stats().used, 0);
            unsafe { assert_inactive_slots_untouched(ACTIVE_CAPACITY, usize::from(ACTIVE_CAPACITY)) };

            drop(udp);
            drop(listener);
            drop(stack);
        });
}
