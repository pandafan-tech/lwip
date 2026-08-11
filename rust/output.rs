use super::lwip::*;
use super::shard::{SHARDS, SHARD_COUNT};
use super::stack_impl::NetStackImpl;
use std::sync::atomic::Ordering;
use tokio::sync::mpsc::error::TrySendError;

// Monomorphized per shard: lwIP's netif output hook carries no user argument,
// so the shard identity must be baked into the function pointer itself. Each
// instance reads its own shard's output_cb_ptr/backpressure state — runs
// under that shard's mutex (netif output is only invoked from stack entry
// points that hold it).
fn output<const K: usize>(_netif: *mut netif, p: *mut pbuf) -> err_t {
    unsafe {
        let shard = &SHARDS[K];
        let cb_ptr = shard.output_cb_ptr.load(Ordering::Relaxed);
        if cb_ptr == 0x0 {
            return err_enum_t_ERR_ABRT as err_t;
        }
        let stack = &mut *(cb_ptr as *mut NetStackImpl);
        let pbuflen = std::ptr::read_unaligned(p).tot_len;
        let mut packet = stack.acquire_output_packet(pbuflen as usize);
        let copied = {
            let spare = packet.spare_capacity_mut();
            (shard.vt.pbuf_copy_partial)(p, spare.as_mut_ptr().cast(), pbuflen, 0)
        };
        if copied != pbuflen {
            return err_enum_t_ERR_BUF as err_t;
        }
        packet.set_len(pbuflen as usize);
        match stack.output(packet) {
            Ok(()) => err_enum_t_ERR_OK as err_t,
            Err(TrySendError::Full(_)) => {
                shard.egress_backpressured.store(true, Ordering::Release);
                err_enum_t_ERR_MEM as err_t
            }
            Err(TrySendError::Closed(_)) => err_enum_t_ERR_ABRT as err_t,
        }
    }
}

extern "C" fn output_ip4<const K: usize>(
    netif: *mut netif,
    p: *mut pbuf,
    _ipaddr: *const ip4_addr_t,
) -> err_t {
    output::<K>(netif, p)
}

extern "C" fn output_ip6<const K: usize>(
    netif: *mut netif,
    p: *mut pbuf,
    _ipaddr: *const ip6_addr_t,
) -> err_t {
    output::<K>(netif, p)
}

type OutputIp4Fn = extern "C" fn(*mut netif, *mut pbuf, *const ip4_addr_t) -> err_t;
type OutputIp6Fn = extern "C" fn(*mut netif, *mut pbuf, *const ip6_addr_t) -> err_t;

const OUTPUT_IP4: [OutputIp4Fn; SHARD_COUNT] = [
    output_ip4::<0>,
    output_ip4::<1>,
    output_ip4::<2>,
    output_ip4::<3>,
];
const OUTPUT_IP6: [OutputIp6Fn; SHARD_COUNT] = [
    output_ip6::<0>,
    output_ip6::<1>,
    output_ip6::<2>,
    output_ip6::<3>,
];

pub(crate) fn output_fns_for(shard_id: usize) -> (OutputIp4Fn, OutputIp6Fn) {
    (OUTPUT_IP4[shard_id], OUTPUT_IP6[shard_id])
}
