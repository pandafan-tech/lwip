use super::lwip::*;
use super::stack_impl::{mark_egress_backpressured, NetStackImpl};
use tokio::sync::mpsc::error::TrySendError;

pub static mut OUTPUT_CB_PTR: usize = 0x0;

fn output(_netif: *mut netif, p: *mut pbuf) -> err_t {
    unsafe {
        if OUTPUT_CB_PTR == 0x0 {
            return err_enum_t_ERR_ABRT as err_t;
        }
        let stack = &mut *(OUTPUT_CB_PTR as *mut NetStackImpl);
        let pbuflen = std::ptr::read_unaligned(p).tot_len;
        let mut packet = stack.acquire_output_packet(pbuflen as usize);
        let copied = {
            let spare = packet.spare_capacity_mut();
            pbuf_copy_partial(p, spare.as_mut_ptr().cast(), pbuflen, 0)
        };
        if copied != pbuflen {
            return err_enum_t_ERR_BUF as err_t;
        }
        packet.set_len(pbuflen as usize);
        match stack.output(packet) {
            Ok(()) => err_enum_t_ERR_OK as err_t,
            Err(TrySendError::Full(_)) => {
                mark_egress_backpressured();
                err_enum_t_ERR_MEM as err_t
            }
            Err(TrySendError::Closed(_)) => err_enum_t_ERR_ABRT as err_t,
        }
    }
}

#[allow(unused_variables)]
pub extern "C" fn output_ip4(netif: *mut netif, p: *mut pbuf, ipaddr: *const ip4_addr_t) -> err_t {
    output(netif, p)
}

#[allow(unused_variables)]
#[allow(unused)]
pub extern "C" fn output_ip6(netif: *mut netif, p: *mut pbuf, ipaddr: *const ip6_addr_t) -> err_t {
    output(netif, p)
}
