use crossbeam_queue::ArrayQueue;
use std::mem::MaybeUninit;
use std::ops::Deref;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};

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
pub struct PacketPoolStats {
    pub allocations: u64,
    pub reuses: u64,
    pub returned: u64,
    pub discarded: u64,
    pub cached: usize,
}

pub struct PacketPool {
    buffers: ArrayQueue<Vec<u8>>,
    max_capacity: usize,
    allocations: AtomicU64,
    reuses: AtomicU64,
    returned: AtomicU64,
    discarded: AtomicU64,
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
        }
    }
}

pub struct IpPacket {
    buffer: Option<Vec<u8>>,
    pool: Option<Arc<PacketPool>>,
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
}

impl From<Vec<u8>> for IpPacket {
    fn from(buffer: Vec<u8>) -> Self {
        Self {
            buffer: Some(buffer),
            pool: None,
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
        if pool.buffers.push(buffer).is_err() {
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
    }
}
