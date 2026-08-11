use super::lwip::*;
use super::packet::{PbufTail, PBUF_TAIL_MAX_SEGS};
use super::shard::{SHARDS, SHARD_COUNT};
use super::stack_impl::NetStackImpl;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::mpsc::error::TrySendError;

/// PANDA_LWIP_ZEROCOPY_EGRESS=1: egress TCP data frames leave the callback
/// as a header snapshot plus a refcounted payload lease instead of a full
/// copy, moving the payload memcpy off the shard lock onto the consumer's
/// task. Default off — the copying path below stays byte-identical.
pub(crate) static ZEROCOPY_EGRESS: AtomicBool = AtomicBool::new(false);

/// Only frames with at least this much payload ride the lease path; control
/// packets (ACKs, handshakes) copy — the lease round trip costs more than a
/// small memcpy.
const ZEROCOPY_MIN_PAYLOAD: u16 = 1024;

/// Headers of a borrowed frame are snapshotted because lwIP rewrites them
/// in place on retransmission; the payload extents are pointer/len pairs
/// captured under the lock for the same reason. Returns None when the frame
/// must take the copy path (non-TCP, small, fragmented, or an over-long
/// chain).
fn borrowable_tcp_header_len(packet_head: &[u8]) -> Option<u16> {
    match packet_head.first().map(|byte| byte >> 4) {
        Some(4) => {
            let ihl = usize::from(packet_head[0] & 0x0f) * 4;
            if packet_head.len() < ihl + 20 || ihl < 20 || packet_head[9] != 6 {
                return None;
            }
            if packet_head[6] & 0x3f != 0 || packet_head[7] != 0 {
                return None;
            }
            let doff = usize::from(packet_head[ihl + 12] >> 4) * 4;
            if doff < 20 {
                return None;
            }
            u16::try_from(ihl + doff).ok()
        }
        Some(6) => {
            if packet_head.len() < 60 || packet_head[6] != 6 {
                return None;
            }
            let doff = usize::from(packet_head[52] >> 4) * 4;
            if doff < 20 {
                return None;
            }
            u16::try_from(40 + doff).ok()
        }
        _ => None,
    }
}

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

        // Zero-copy path: snapshot only the headers here (lwIP rewrites
        // them in place on retransmit), lease the chain, and record raw
        // payload extents for the consumer to copy off-lock. The chain
        // refcount keeps the payload bytes alive until the lease returns
        // through the shard's rail. TCP only: UDP frames reference
        // caller-owned memory (pbuf_alloc_reference) that dies when the
        // send call returns — a refcount cannot extend it.
        if ZEROCOPY_EGRESS.load(Ordering::Relaxed) {
            if let Some(header_len) = borrowed_frame_header_len(p, pbuflen) {
                if let Some(segs) = payload_extents(p, header_len) {
                    let copied = {
                        let spare = packet.spare_capacity_mut();
                        (shard.vt.pbuf_copy_partial)(
                            p,
                            spare.as_mut_ptr().cast(),
                            u16_t::from(header_len),
                            0,
                        )
                    };
                    if copied != u16_t::from(header_len) {
                        return err_enum_t_ERR_BUF as err_t;
                    }
                    packet.set_len(usize::from(header_len));
                    (shard.vt.pbuf_ref)(p);
                    packet.set_tail(PbufTail::new(p, shard, segs.0, segs.1));
                    return match stack.output(packet) {
                        Ok(()) => err_enum_t_ERR_OK as err_t,
                        Err(TrySendError::Full(mut frame)) => {
                            // Dropping the tail would park the lease for a
                            // LATER tenure; we hold the lock right now, so
                            // return the ref immediately instead.
                            frame.drop_tail_for_immediate_free(|chain| {
                                (shard.vt.pbuf_free)(chain);
                            });
                            shard.egress_backpressured.store(true, Ordering::Release);
                            err_enum_t_ERR_MEM as err_t
                        }
                        Err(TrySendError::Closed(mut frame)) => {
                            frame.drop_tail_for_immediate_free(|chain| {
                                (shard.vt.pbuf_free)(chain);
                            });
                            err_enum_t_ERR_ABRT as err_t
                        }
                    };
                }
            }
        }

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

/// Header length of a frame eligible for the lease path, reading only the
/// first pbuf node (lwIP keeps the full header there).
unsafe fn borrowed_frame_header_len(p: *mut pbuf, tot_len: u16_t) -> Option<u16> {
    let node = std::ptr::read_unaligned(p);
    let head = std::slice::from_raw_parts(node.payload.cast::<u8>(), usize::from(node.len));
    let header_len = borrowable_tcp_header_len(head)?;
    if header_len > node.len {
        // Headers split across nodes: not worth the complexity, copy.
        return None;
    }
    let payload = tot_len.checked_sub(header_len)?;
    (payload >= ZEROCOPY_MIN_PAYLOAD).then_some(header_len)
}

/// Raw (pointer, len) payload extents past the headers, captured under the
/// lock. None when the chain is longer than the fixed bound.
unsafe fn payload_extents(
    p: *mut pbuf,
    header_len: u16,
) -> Option<([(*const u8, u32); PBUF_TAIL_MAX_SEGS], u8)> {
    let mut segs = [(std::ptr::null(), 0u32); PBUF_TAIL_MAX_SEGS];
    let mut count = 0usize;
    let mut skip = usize::from(header_len);
    let mut node_ptr = p;
    while !node_ptr.is_null() {
        let node = std::ptr::read_unaligned(node_ptr);
        let len = usize::from(node.len);
        if skip >= len {
            skip -= len;
        } else {
            if count == PBUF_TAIL_MAX_SEGS {
                return None;
            }
            segs[count] = (
                node.payload.cast::<u8>().add(skip).cast_const(),
                (len - skip) as u32,
            );
            count += 1;
            skip = 0;
        }
        node_ptr = node.next;
    }
    Some((segs, count as u8))
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
