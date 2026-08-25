//! Per-shard access to the N independent lwIP instances compiled by build.rs.
//!
//! The C side gives us `1 + PANDA_LWIP_EXTRA_SHARDS` complete copies of the
//! stack — separate pcb lists, pools, netifs, timers — distinguished only by
//! a symbol prefix (`panda_shard{k}_`, shard 0 unprefixed). This module pairs
//! each copy with the Rust-side state that used to be crate-global: the
//! serializing mutex, the init latch, the egress backpressure flag, the
//! output hook, and the TCP memory-pressure wait queue. Everything that
//! touches lwIP carries a [`ShardRef`] and goes through its vtable, so stacks
//! on different shards run fully in parallel.

use std::sync::{
    atomic::{AtomicBool, AtomicUsize},
    Once,
};

use super::lwip::*;
use super::tcp_stream_context::TcpMemPressureQueue;

/// Must equal `1 + PANDA_LWIP_EXTRA_SHARDS` in build.rs — the number of
/// stack copies actually linked in. The vtable table below is written out
/// for exactly this many shards.
pub(crate) const SHARD_COUNT: usize = 4;

/// How many independent lwIP stack instances this build can host in one
/// process. Shard 0 is the primary; how many of the rest to activate is the
/// application's runtime choice.
pub fn shard_count() -> usize {
    SHARD_COUNT
}

/// Invokes `$callback!` with the complete C API surface the wrapper uses.
/// One list, four expansions: the vtable struct and one extern block per
/// shard prefix. Adding a C call to the wrapper means adding it here once.
macro_rules! with_shard_api {
    ($callback:ident ! ($($args:tt)*)) => {
        $callback! { ($($args)*)
            lwip_init: fn(),
            sys_check_timeouts: fn(),
            lwip_rs_configure_netif: fn(netif_output_fn, netif_output_ip6_fn, u16_t),
            lwip_rs_netif_input: fn(*mut pbuf) -> err_t,
            lwip_rs_retry_tcp_output: fn() -> err_t,
            lwip_rs_set_tcp_tx_partial_checksum: fn(::std::os::raw::c_int),
            tcp_set_wnd_runtime: fn(tcpwnd_size_t) -> err_t,
            tcp_set_snd_buf_runtime: fn(tcpwnd_size_t) -> err_t,
            memp_pbuf_pool_set_capacity: fn(u16_t) -> err_t,
            memp_pbuf_pool_get_runtime_stats: fn(*mut memp_pbuf_pool_runtime_stats),
            pbuf_alloced_custom:
                fn(pbuf_layer, u16_t, pbuf_type, *mut pbuf_custom, *mut ::std::os::raw::c_void, u16_t) -> *mut pbuf,
            pbuf_alloc_reference: fn(*mut ::std::os::raw::c_void, u16_t, pbuf_type) -> *mut pbuf,
            pbuf_free: fn(*mut pbuf) -> u8_t,
            pbuf_ref: fn(*mut pbuf),
            pbuf_copy_partial: fn(*const pbuf, *mut ::std::os::raw::c_void, u16_t, u16_t) -> u16_t,
            tcp_new: fn() -> *mut tcp_pcb,
            tcp_bind: fn(*mut tcp_pcb, *const ip_addr_t, u16_t) -> err_t,
            tcp_listen_with_backlog_and_err: fn(*mut tcp_pcb, u8_t, *mut err_t) -> *mut tcp_pcb,
            tcp_arg: fn(*mut tcp_pcb, *mut ::std::os::raw::c_void),
            tcp_accept: fn(*mut tcp_pcb, tcp_accept_fn),
            tcp_recv: fn(*mut tcp_pcb, tcp_recv_fn),
            tcp_sent: fn(*mut tcp_pcb, tcp_sent_fn),
            tcp_err: fn(*mut tcp_pcb, tcp_err_fn),
            tcp_poll: fn(*mut tcp_pcb, tcp_poll_fn, u8_t),
            tcp_recved: fn(*mut tcp_pcb, u16_t),
            tcp_write: fn(*mut tcp_pcb, *const ::std::os::raw::c_void, u16_t, u8_t) -> err_t,
            tcp_output: fn(*mut tcp_pcb) -> err_t,
            tcp_shutdown: fn(*mut tcp_pcb, ::std::os::raw::c_int, ::std::os::raw::c_int) -> err_t,
            tcp_close: fn(*mut tcp_pcb) -> err_t,
            tcp_abort: fn(*mut tcp_pcb),
            lwip_rs_tcp_endpoints:
                fn(*const tcp_pcb, *mut ip_addr_t, *mut u16_t, *mut ip_addr_t, *mut u16_t),
            lwip_rs_tcp_apply_options: fn(*mut tcp_pcb, ::std::os::raw::c_int),
            lwip_rs_tcp_send_buffer: fn(*const tcp_pcb) -> tcpwnd_size_t,
            udp_new: fn() -> *mut udp_pcb,
            udp_bind: fn(*mut udp_pcb, *const ip_addr_t, u16_t) -> err_t,
            udp_recv: fn(*mut udp_pcb, udp_recv_fn, *mut ::std::os::raw::c_void),
            udp_remove: fn(*mut udp_pcb),
            lwip_rs_udp_sendto:
                fn(*mut udp_pcb, *mut pbuf, *const ip_addr_t, u16_t, *const ip_addr_t, u16_t) -> err_t,
            lwip_rs_udp_local_endpoint: fn(*const udp_pcb, *mut ip_addr_t, *mut u16_t),
        }
    };
}

macro_rules! declare_vt_struct {
    ( () $( $name:ident : fn($($arg:ty),*) $(-> $ret:ty)? ),* $(,)? ) => {
        /// One shard's entry points into its copy of the C stack. Calling a
        /// pcb/pbuf into the WRONG shard's functions corrupts both stacks —
        /// every object in the wrapper carries the shard it was born on.
        // Some entries (e.g. the Windows UDP runtime hooks) are only read on
        // one platform; the vtable stays identical across platforms.
        #[cfg_attr(not(windows), allow(dead_code))]
        pub(crate) struct ShardVt {
            $( pub $name: unsafe extern "C" fn($($arg),*) $(-> $ret)?, )*
        }
    };
}
with_shard_api!(declare_vt_struct!());

macro_rules! declare_shard_vt {
    ( ($prefix:literal) $( $name:ident : fn($($arg:ty),*) $(-> $ret:ty)? ),* $(,)? ) => {
        extern "C" {
            $(
                #[link_name = concat!($prefix, stringify!($name))]
                fn $name($(_: $arg),*) $(-> $ret)?;
            )*
        }
        pub(super) static VT: super::ShardVt = super::ShardVt {
            $( $name, )*
        };
    };
}

mod vt0 {
    use crate::lwip::*;
    with_shard_api!(declare_shard_vt!(""));
}
mod vt1 {
    use crate::lwip::*;
    with_shard_api!(declare_shard_vt!("panda_shard1_"));
}
mod vt2 {
    use crate::lwip::*;
    with_shard_api!(declare_shard_vt!("panda_shard2_"));
}
mod vt3 {
    use crate::lwip::*;
    with_shard_api!(declare_shard_vt!("panda_shard3_"));
}

/// One lwIP instance plus the Rust-side state that serializes and services
/// it. Fields mirror what used to be crate-wide statics, one copy per shard.
/// Cache-line-aligned so adjacent shards' hot atomics (backpressure flag,
/// telemetry counters) never share a line.
#[repr(align(128))]
pub(crate) struct ShardState {
    pub id: usize,
    pub vt: &'static ShardVt,
    pub mutex: &'static super::mutex::AtomicMutex,
    /// Latches this shard's one-time `lwip_init`.
    pub init: Once,
    /// Set by this shard's netif output hook when its egress channel is
    /// full; cleared by the egress consumer, which then retries tcp_output.
    pub egress_backpressured: AtomicBool,
    /// The live `NetStackImpl` this shard's output hook delivers into
    /// (as a usize; 0 = none). Written under `mutex`.
    pub output_cb_ptr: AtomicUsize,
    /// Writers on THIS shard parked on its shared-pool exhaustion.
    pub mem_pressure: TcpMemPressureQueue,
    /// Per-shard TCP telemetry. Split per shard because the queued-packet
    /// pair is bumped for every delivered chain: four stacks doing RMWs on
    /// one shared cache line would serialize on the coherence traffic.
    pub active_tcp_streams: std::sync::atomic::AtomicUsize,
    pub tcp_queued_packets: std::sync::atomic::AtomicUsize,
    pub tcp_queued_bytes: std::sync::atomic::AtomicUsize,
    /// Zero-copy egress lease returns. `pbuf_free` may only run under this
    /// shard's lwIP mutex, but leased frames are finalized (and dropped) on
    /// writer tasks that never hold it — they park the chain pointer here
    /// and the next locked tenure (ingress batch, timer tick, teardown)
    /// frees the backlog. Bounded by the egress channel depth.
    pub pbuf_leases: std::sync::Mutex<Vec<*mut pbuf>>,
}

// SAFETY: raw-pointer-holding fields are only dereferenced under this
// shard's mutex (mem_pressure) or freed under it (pbuf_leases — its own
// std Mutex only serializes the pointer handoff); the rest are
// atomics/Once.
unsafe impl Sync for ShardState {}

impl ShardState {
    /// Park a leased pbuf chain for the next locked tenure to free. Called
    /// from writer tasks and packet Drops that do not hold the lwIP mutex.
    pub(crate) fn park_pbuf_lease(&self, chain: *mut pbuf) {
        self.pbuf_leases
            .lock()
            .expect("pbuf lease rail poisoned")
            .push(chain);
    }

    /// Free every parked lease; the guard witnesses the lwIP mutex.
    pub(crate) fn drain_pbuf_leases(&self, _guard: &super::LWIPMutexGuard) {
        let mut rail = self.pbuf_leases.lock().expect("pbuf lease rail poisoned");
        for chain in rail.drain(..) {
            unsafe { (self.vt.pbuf_free)(chain) };
        }
    }
}

pub(crate) type ShardRef = &'static ShardState;

static EXTRA_MUTEXES: [super::mutex::AtomicMutex; SHARD_COUNT - 1] = [
    super::mutex::AtomicMutex::new(),
    super::mutex::AtomicMutex::new(),
    super::mutex::AtomicMutex::new(),
];

macro_rules! shard_state {
    ($id:expr, $vt:path, $mutex:expr) => {
        ShardState {
            id: $id,
            vt: &$vt,
            mutex: $mutex,
            init: Once::new(),
            egress_backpressured: AtomicBool::new(false),
            output_cb_ptr: AtomicUsize::new(0),
            mem_pressure: TcpMemPressureQueue::new(),
            active_tcp_streams: AtomicUsize::new(0),
            tcp_queued_packets: AtomicUsize::new(0),
            tcp_queued_bytes: AtomicUsize::new(0),
            pbuf_leases: std::sync::Mutex::new(Vec::new()),
        }
    };
}

pub(crate) static SHARDS: [ShardState; SHARD_COUNT] = [
    // Shard 0 keeps the historical LWIP_MUTEX static so the many existing
    // lock sites (tests included) keep meaning "the primary stack's lock".
    shard_state!(0, vt0::VT, &crate::LWIP_MUTEX),
    shard_state!(1, vt1::VT, &EXTRA_MUTEXES[0]),
    shard_state!(2, vt2::VT, &EXTRA_MUTEXES[1]),
    shard_state!(3, vt3::VT, &EXTRA_MUTEXES[2]),
];

/// The primary (shard 0) stack — what every pre-shard API operates on.
pub(crate) fn primary() -> ShardRef {
    &SHARDS[0]
}

/// Resolve a caller-supplied shard id.
pub(crate) fn get(id: usize) -> Option<ShardRef> {
    SHARDS.get(id)
}
