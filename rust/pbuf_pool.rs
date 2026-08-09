use super::lwip::{
    err_enum_t_ERR_OK, err_enum_t_ERR_USE, err_enum_t_ERR_VAL, memp_pbuf_pool_get_runtime_stats,
    memp_pbuf_pool_runtime_stats, memp_pbuf_pool_set_capacity, MEMP_PBUF_POOL_RUNTIME_MIN,
    PBUF_POOL_SIZE,
};
use super::{Error, Result, LWIP_MUTEX};

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
/// new process.
pub fn configure_pbuf_pool_capacity(capacity: u16) -> Result<()> {
    const ERR_OK: i32 = err_enum_t_ERR_OK;
    const ERR_USE: i32 = err_enum_t_ERR_USE;
    const ERR_VAL: i32 = err_enum_t_ERR_VAL;

    let _guard = LWIP_MUTEX.lock();
    let result = unsafe { memp_pbuf_pool_set_capacity(capacity) } as i32;
    match result {
        ERR_OK => Ok(()),
        ERR_VAL => Err(Error::RuntimeConfig(format!(
            "PBUF_POOL capacity must be between {} and {}, got {capacity}",
            MEMP_PBUF_POOL_RUNTIME_MIN, PBUF_POOL_SIZE
        ))),
        ERR_USE => Err(Error::RuntimeConfig(
            "PBUF_POOL capacity must be configured before the first NetStack; restart the process to change it"
                .to_owned(),
        )),
        error => Err(Error::RuntimeConfig(format!(
            "PBUF_POOL capacity configuration failed with lwIP error {error}"
        ))),
    }
}

pub fn pbuf_pool_runtime_stats() -> PbufPoolRuntimeStats {
    let _guard = LWIP_MUTEX.lock();
    let mut stats = memp_pbuf_pool_runtime_stats {
        configured: 0,
        effective: 0,
        compile_capacity: 0,
        used: 0,
        max_used: 0,
        alloc_failures: 0,
    };
    unsafe { memp_pbuf_pool_get_runtime_stats(&mut stats) };
    PbufPoolRuntimeStats {
        configured: stats.configured,
        effective: stats.effective,
        compile_capacity: stats.compile_capacity,
        used: stats.used,
        max_used: stats.max_used,
        alloc_failures: stats.alloc_failures,
    }
}
