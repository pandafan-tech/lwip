use crossbeam_queue::ArrayQueue;
use std::mem::MaybeUninit;
use std::ops::Deref;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};

use super::shard::ShardRef;

/// Payload segments a zero-copy egress frame still owes the buffer. Captured
/// UNDER the shard lock at output-callback time: lwIP rewrites pbuf node
/// fields (payload pointer, len) in place when it retransmits a segment, so
/// the chain must never be re-walked outside the lock — only these raw
/// (pointer, len) snapshots are read there. The bytes they cover are the
/// application payload, which lwIP never mutates while the segment lives,
/// and the chain refcount taken alongside keeps the memory alive until the
/// lease is returned.
pub(crate) struct PbufTail {
    /// The refcounted chain head, returned to the shard's lease rail.
    chain: *mut super::lwip::pbuf,
    shard: ShardRef,
    /// Raw payload extents; the array bound covers any realistic segment
    /// chain (header node + a few payload nodes).
    segs: [(*const u8, u32); PBUF_TAIL_MAX_SEGS],
    seg_count: u8,
}

pub(crate) const PBUF_TAIL_MAX_SEGS: usize = 4;

impl PbufTail {
    /// # Safety
    /// `chain` must hold a refcount owned by this tail; every `(ptr, len)`
    /// in `segs[..seg_count]` must point at payload bytes kept alive by
    /// that refcount and never mutated by lwIP.
    pub(crate) unsafe fn new(
        chain: *mut super::lwip::pbuf,
        shard: ShardRef,
        segs: [(*const u8, u32); PBUF_TAIL_MAX_SEGS],
        seg_count: u8,
    ) -> Self {
        Self {
            chain,
            shard,
            segs,
            seg_count,
        }
    }
}

// SAFETY: the tail is an exclusively-owned lease; the raw pointers are only
// read (finalize) or handed to the lease rail (drop), never shared.
unsafe impl Send for PbufTail {}
unsafe impl Sync for PbufTail {}

impl PbufTail {
    /// Disarm the parking Drop and surrender the chain — for the one caller
    /// that already holds the shard lock and can free immediately.
    pub(crate) fn into_chain(self) -> *mut super::lwip::pbuf {
        let this = std::mem::ManuallyDrop::new(self);
        this.chain
    }
}

impl Drop for PbufTail {
    fn drop(&mut self) {
        self.shard.park_pbuf_lease(self.chain);
    }
}

fn packet_pool_registry() -> &'static Mutex<Vec<Weak<PacketPool>>> {
    static REGISTRY: OnceLock<Mutex<Vec<Weak<PacketPool>>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(Vec::new()))
}

pub fn trim_packet_pools() -> usize {
    let mut registry = packet_pool_registry()
        .lock()
        .expect("packet pool registry poisoned");
    let mut released = 0;
    registry.retain(|weak| {
        let Some(pool) = weak.upgrade() else {
            return false;
        };
        released += pool.trim();
        true
    });
    released
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PacketPoolsRuntimeStats {
    pub live_pools: usize,
    pub cached_packets: usize,
    pub cached_bytes: usize,
    pub allocations: u64,
    pub reuses: u64,
    pub returned: u64,
    pub discarded: u64,
}

pub fn packet_pool_runtime_stats() -> PacketPoolsRuntimeStats {
    let mut registry = packet_pool_registry()
        .lock()
        .expect("packet pool registry poisoned");
    let mut runtime = PacketPoolsRuntimeStats::default();
    registry.retain(|weak| {
        let Some(pool) = weak.upgrade() else {
            return false;
        };
        let stats = pool.stats();
        runtime.live_pools += 1;
        runtime.cached_packets += stats.cached;
        runtime.cached_bytes += stats.cached_bytes;
        runtime.allocations += stats.allocations;
        runtime.reuses += stats.reuses;
        runtime.returned += stats.returned;
        runtime.discarded += stats.discarded;
        true
    });
    runtime
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PacketPoolStats {
    pub allocations: u64,
    pub reuses: u64,
    pub returned: u64,
    pub discarded: u64,
    pub cached: usize,
    pub cached_bytes: usize,
}

pub struct PacketPool {
    buffers: ArrayQueue<Vec<u8>>,
    max_capacity: usize,
    allocations: AtomicU64,
    reuses: AtomicU64,
    returned: AtomicU64,
    discarded: AtomicU64,
    cached_bytes: AtomicUsize,
}

impl PacketPool {
    pub fn new(max_cached: usize, max_capacity: usize) -> Arc<Self> {
        assert!(max_cached > 0, "packet pool must cache at least one buffer");
        assert!(max_capacity > 0, "packet pool capacity must be non-zero");
        let pool = Arc::new(Self {
            buffers: ArrayQueue::new(max_cached),
            max_capacity,
            allocations: AtomicU64::new(0),
            reuses: AtomicU64::new(0),
            returned: AtomicU64::new(0),
            discarded: AtomicU64::new(0),
            cached_bytes: AtomicUsize::new(0),
        });
        let mut registry = packet_pool_registry()
            .lock()
            .expect("packet pool registry poisoned");
        registry.retain(|weak| weak.strong_count() > 0);
        registry.push(Arc::downgrade(&pool));
        pool
    }

    pub(crate) fn acquire(self: &Arc<Self>, length: usize) -> IpPacket {
        let buffer = self.buffers.pop();
        let mut buffer = match buffer {
            Some(buffer) => {
                self.cached_bytes
                    .fetch_sub(buffer.capacity(), Ordering::Relaxed);
                self.reuses.fetch_add(1, Ordering::Relaxed);
                buffer
            }
            None => {
                self.allocations.fetch_add(1, Ordering::Relaxed);
                Vec::with_capacity(length)
            }
        };
        buffer.clear();
        if buffer.capacity() < length {
            buffer.reserve_exact(length);
        }
        IpPacket {
            buffer: Some(buffer),
            pool: Some(Arc::clone(self)),
            tail: None,
        }
    }

    pub fn copy_from_slice(self: &Arc<Self>, data: &[u8]) -> IpPacket {
        let mut packet = self.acquire(data.len());
        let spare = packet.spare_capacity_mut();
        for (destination, byte) in spare.iter_mut().zip(data) {
            destination.write(*byte);
        }
        // SAFETY: the loop initialized exactly data.len() bytes and acquire
        // guaranteed capacity for that length.
        unsafe { packet.set_len(data.len()) };
        packet
    }

    fn trim(&self) -> usize {
        let mut released = 0;
        while let Some(buffer) = self.buffers.pop() {
            released += buffer.capacity();
            self.cached_bytes
                .fetch_sub(buffer.capacity(), Ordering::Relaxed);
            self.discarded.fetch_add(1, Ordering::Relaxed);
        }
        released
    }

    pub(crate) fn stats(&self) -> PacketPoolStats {
        PacketPoolStats {
            allocations: self.allocations.load(Ordering::Relaxed),
            reuses: self.reuses.load(Ordering::Relaxed),
            returned: self.returned.load(Ordering::Relaxed),
            discarded: self.discarded.load(Ordering::Relaxed),
            cached: self.buffers.len(),
            cached_bytes: self.cached_bytes.load(Ordering::Relaxed),
        }
    }
}

pub struct IpPacket {
    buffer: Option<Vec<u8>>,
    pool: Option<Arc<PacketPool>>,
    /// Zero-copy egress: payload bytes still owed by a leased pbuf chain.
    /// `finalize` (called at the egress channel exit, off the shard lock)
    /// appends them and returns the lease; until then `deref` must not run.
    tail: Option<PbufTail>,
}

impl IpPacket {
    pub(crate) fn spare_capacity_mut(&mut self) -> &mut [MaybeUninit<u8>] {
        self.buffer
            .as_mut()
            .expect("packet buffer already released")
            .spare_capacity_mut()
    }

    pub(crate) unsafe fn set_len(&mut self, length: usize) {
        debug_assert!(length <= self.spare_capacity_mut().len());
        self.buffer
            .as_mut()
            .expect("packet buffer already released")
            .set_len(length);
    }

    pub fn len(&self) -> usize {
        self.deref().len()
    }

    pub fn is_empty(&self) -> bool {
        self.deref().is_empty()
    }

    /// Attach the payload a zero-copy egress frame still owes. The buffer
    /// holds only the header snapshot; capacity for the payload was
    /// reserved by `acquire`.
    pub(crate) fn set_tail(&mut self, tail: PbufTail) {
        debug_assert!(self.tail.is_none());
        self.tail = Some(tail);
    }

    /// Backpressure path: the output callback still holds the shard lock
    /// when a send is refused, so the lease is returned through `free`
    /// right now instead of riding the rail to a later tenure.
    pub(crate) fn drop_tail_for_immediate_free(
        &mut self,
        free: impl FnOnce(*mut super::lwip::pbuf),
    ) {
        if let Some(tail) = self.tail.take() {
            free(tail.into_chain());
        }
    }

    /// Materialize the payload of a zero-copy frame and return its lease.
    /// Runs at the egress channel exit — on the consumer's task, never
    /// under the shard lock — so the memcpy this replaces no longer spends
    /// lock tenure. Idempotent; owned frames are untouched.
    pub(crate) fn finalize(&mut self) {
        let Some(tail) = self.tail.take() else {
            return;
        };
        let buffer = self
            .buffer
            .as_mut()
            .expect("packet buffer already released");
        for (ptr, len) in tail.segs.iter().take(usize::from(tail.seg_count)) {
            // SAFETY: PbufTail::new's contract — the extent is alive under
            // the chain refcount and immutable.
            let bytes = unsafe { std::slice::from_raw_parts(*ptr, *len as usize) };
            buffer.extend_from_slice(bytes);
        }
        // `tail` drops here, parking the chain on the shard's lease rail.
    }
}

impl From<Vec<u8>> for IpPacket {
    fn from(buffer: Vec<u8>) -> Self {
        Self {
            buffer: Some(buffer),
            pool: None,
            tail: None,
        }
    }
}

impl AsRef<[u8]> for IpPacket {
    fn as_ref(&self) -> &[u8] {
        self.deref()
    }
}

impl Deref for IpPacket {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        debug_assert!(
            self.tail.is_none(),
            "zero-copy egress frame dereferenced before finalize"
        );
        self.buffer
            .as_deref()
            .expect("packet buffer already released")
    }
}

impl Drop for IpPacket {
    fn drop(&mut self) {
        let Some(pool) = self.pool.take() else {
            return;
        };
        let Some(mut buffer) = self.buffer.take() else {
            return;
        };
        buffer.clear();
        if buffer.capacity() > pool.max_capacity {
            pool.discarded.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let capacity = buffer.capacity();
        pool.cached_bytes.fetch_add(capacity, Ordering::Relaxed);
        if pool.buffers.push(buffer).is_err() {
            pool.cached_bytes.fetch_sub(capacity, Ordering::Relaxed);
            pool.discarded.fetch_add(1, Ordering::Relaxed);
            return;
        }
        pool.returned.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_pool_reuses_storage_and_stays_bounded() {
        let pool = PacketPool::new(2, 128);

        let first = pool.acquire(64);
        assert_eq!(pool.stats().allocations, 1);
        drop(first);
        assert_eq!(pool.stats().cached, 1);

        let reused = pool.acquire(64);
        assert_eq!(pool.stats().reuses, 1);
        let second = pool.acquire(64);
        let third = pool.acquire(64);
        drop(reused);
        drop(second);
        drop(third);

        let stats = pool.stats();
        assert_eq!(stats.cached, 2);
        assert_eq!(stats.cached_bytes, 128);
        assert_eq!(stats.discarded, 1);
    }

    #[test]
    fn oversized_packet_storage_is_not_retained() {
        let pool = PacketPool::new(2, 128);
        drop(pool.acquire(129));

        let stats = pool.stats();
        assert_eq!(stats.cached, 0);
        assert_eq!(stats.discarded, 1);
    }

    #[test]
    fn copy_from_slice_preserves_bytes_and_reuses_storage() {
        let pool = PacketPool::new(1, 128);
        let packet = pool.copy_from_slice(b"panda");
        assert_eq!(&*packet, b"panda");
        drop(packet);

        let packet = pool.copy_from_slice(b"core");
        assert_eq!(&*packet, b"core");
        assert_eq!(pool.stats().allocations, 1);
        assert_eq!(pool.stats().reuses, 1);
    }

    #[test]
    fn trim_releases_cached_storage() {
        let pool = PacketPool::new(1, 128);
        drop(pool.acquire(64));

        assert!(pool.trim() >= 64);
        assert_eq!(pool.stats().cached, 0);
        assert_eq!(pool.stats().cached_bytes, 0);
    }
}
