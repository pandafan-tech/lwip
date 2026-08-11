use super::lwip::{
    err_enum_t_ERR_OK, err_enum_t_ERR_USE, err_enum_t_ERR_VAL, memp_pbuf_pool_runtime_stats,
    MEMP_PBUF_POOL_RUNTIME_MIN, PBUF_POOL_SIZE,
};
use super::shard;
use super::{Error, Result};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PbufPoolRuntimeStats {
    pub configured: u16,
    pub effective: u16,
    pub compile_capacity: u16,
    pub used: u16,
    pub max_used: u16,
    pub alloc_failures: u32,
}

/// Select the active PBUF_POOL capacity before the first `NetStack` is made.
///
/// The compile-time backing allocation is unchanged. Reapplying the same value
/// after lwIP initialization succeeds, which lets sequential `NetStack`
/// instances apply one shared tuning profile. Changing the value requires a
/// new process. One tuning profile governs the whole process, so the value is
/// applied to every shard's pool.
pub fn configure_pbuf_pool_capacity(capacity: u16) -> Result<()> {
    const ERR_OK: i32 = err_enum_t_ERR_OK;
    const ERR_USE: i32 = err_enum_t_ERR_USE;
    const ERR_VAL: i32 = err_enum_t_ERR_VAL;

    for shard in shard::SHARDS.iter() {
        let _guard = shard.mutex.lock();
        let result = unsafe { (shard.vt.memp_pbuf_pool_set_capacity)(capacity) } as i32;
        match result {
            ERR_OK => {}
            ERR_VAL => {
                return Err(Error::RuntimeConfig(format!(
                    "PBUF_POOL capacity must be between {} and {}, got {capacity}",
                    MEMP_PBUF_POOL_RUNTIME_MIN, PBUF_POOL_SIZE
                )))
            }
            ERR_USE => {
                return Err(Error::RuntimeConfig(
                    "PBUF_POOL capacity must be configured before the first NetStack; restart the process to change it"
                        .to_owned(),
                ))
            }
            error => {
                return Err(Error::RuntimeConfig(format!(
                    "PBUF_POOL capacity configuration failed with lwIP error {error}"
                )))
            }
        }
    }
    Ok(())
}

pub fn pbuf_pool_runtime_stats() -> PbufPoolRuntimeStats {
    pbuf_pool_runtime_stats_sharded(0).expect("shard 0 always exists")
}

/// Per-shard view of the PBUF_POOL runtime counters; `None` when `shard_id`
/// is out of range for this build.
pub fn pbuf_pool_runtime_stats_sharded(shard_id: usize) -> Option<PbufPoolRuntimeStats> {
    let shard = shard::get(shard_id)?;
    let _guard = shard.mutex.lock();
    let mut stats = memp_pbuf_pool_runtime_stats {
        configured: 0,
        effective: 0,
        compile_capacity: 0,
        used: 0,
        max_used: 0,
        alloc_failures: 0,
    };
    unsafe { (shard.vt.memp_pbuf_pool_get_runtime_stats)(&mut stats) };
    Some(PbufPoolRuntimeStats {
        configured: stats.configured,
        effective: stats.effective,
        compile_capacity: stats.compile_capacity,
        used: stats.used,
        max_used: stats.max_used,
        alloc_failures: stats.alloc_failures,
    })
}
