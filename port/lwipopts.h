/**
 * @file lwipopts.h
 * @author Ambroz Bizjak <ambrop7@gmail.com>
 *
 * @section LICENSE
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the author nor the
 *    names of its contributors may be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef LWIP_CUSTOM_LWIPOPTS_H
#define LWIP_CUSTOM_LWIPOPTS_H

// Clang emits large tentative arrays as Mach-O common symbols and infers a
// 32 KiB alignment that exceeds macOS's 16 KiB segment limit. These globals
// are zero-initialized by definition, so make that explicit and keep them in
// BSS with their actual lwIP alignment requirement.
#if defined(__APPLE__)
#define LWIP_DECLARE_MEMORY_ALIGNED(variable_name, size) \
  u8_t variable_name[LWIP_MEM_ALIGN_BUFFER(size)] = {0}
#endif

// enable tun2socks logic
#define TUN2SOCKS 1

#define NO_SYS 1
#define LWIP_TIMERS 1

#define IP_DEFAULT_TTL 64
#define LWIP_ARP 0
#define ARP_QUEUEING 0
#define IP_FORWARD 0
#define LWIP_ICMP 1
#define LWIP_RAW 1
#define LWIP_DHCP 0
#define LWIP_AUTOIP 0
#define LWIP_SNMP 0
#define LWIP_IGMP 0
#define LWIP_DNS 0
#define LWIP_UDP 1
#define LWIP_UDPLITE 0
#define LWIP_TCP 1
#define LWIP_CALLBACK_API 1
#define LWIP_NETIF_API 0
#define LWIP_NETIF_LOOPBACK 0
#define LWIP_HAVE_LOOPIF 1
#define LWIP_HAVE_SLIPIF 0
#define LWIP_NETCONN 0
#define LWIP_SOCKET 0
#define PPP_SUPPORT 0
#define LWIP_IPV6 1
#define LWIP_IPV6_MLD 0
#define LWIP_IPV6_AUTOCONFIG 1

#if defined __APPLE__
#include <TargetConditionals.h>

#if TARGET_OS_IPHONE
#define LWIP_TCP_KEEPALIVE 1
// Each slot is 264 bytes on arm64. 1024 active PCBs reserve 264 KiB while
// leaving the Network Extension's TCP windows and 512 KiB heap unchanged.
#define MEMP_NUM_TCP_PCB 1024
#else
#define MEMP_NUM_TCP_PCB 1024
#endif
#elif defined __linux__
#include <endian.h>

// BYTE_ORDER by default is LITTLE_ENDIAN if undefined,
// detects only big endian here.
#if defined __BYTE_ORDER && defined __BIG_ENDIAN
#if _BYTE_ORDER == __BIG_ENDIAN
#define BYTE_ORDER BIG_ENDIAN
#endif
#endif

#define MEMP_NUM_TCP_PCB 1024
#else
#define MEMP_NUM_TCP_PCB 1024
#endif

// disable checksum checks
#define CHECKSUM_CHECK_IP 0
#define CHECKSUM_CHECK_UDP 0
#define CHECKSUM_CHECK_TCP 0
#define CHECKSUM_CHECK_ICMP 0
#define CHECKSUM_CHECK_ICMP6 0

#if defined(__linux__) && !defined(__ANDROID__) && \
    !defined(PANDA_LWIP_ANDROID_PROFILE)
// Desktop Linux hands TCP TX checksums to the kernel through the TUN vnet
// header (virtio NEEDS_CSUM partial checksums, see panda_tcp_tx_partial_chksum
// in tcp_out.c), so computing payload checksums during tcp_write would be
// wasted work — lwip_chksum_copy alone was 7.2% of CPU in the 16-flow
// bidirectional profile (2026-08-11). If the runtime flag is off (TX GSO
// experiments, non-vnet writers) the full checksum is still generated at
// output time from the same CHECKSUM_GEN_TCP site.
#define LWIP_CHECKSUM_ON_COPY 0
#else
#define LWIP_CHECKSUM_ON_COPY 1
#endif
#define LWIP_CHKSUM_ALGORITHM 3

#define PANDA_BASE_TCP_MSS 1460
#define TCP_WND_RUNTIME_MIN (2 * PANDA_BASE_TCP_MSS)
// The smallest effective MSS any runtime MTU can produce (RFC 879 default;
// TCP_CALCULATE_EFF_SEND_MSS floors there). Queue limits sized with this
// divisor stay sufficient for EVERY runtime MTU — sizing them in units of
// the compile-time ceiling instead is the classic tun2socks failure mode
// where a small-MTU run needs more segments per buffer than the queue
// allows and every tcp_write dies on ERR_MEM.
#define PANDA_MIN_EFF_TCP_MSS 536
#if defined __APPLE__ && TARGET_OS_IPHONE
// Mobile ceiling stays at the 9000-MTU value: NE runs at 1500 so only the
// ceiling-derived sanity margins matter, and keeping it fixed keeps the
// mobile memory profile byte-identical.
#define TCP_MSS 8960
// Network Extension has a tight process-memory ceiling. The ACTIVE budget
// stays at the historical conservative values via the RUNTIME_DEFAULTs
// below, so the default memory profile is unchanged; the compile ceilings
// are the validated Android tier so the app-exposed runtime knobs
// (resources.lwip-tcp-*-mss) have headroom for throughput testing.
// Windows/buffers are budgets, not allocations — raising only the ceiling
// costs no memory until a knob actually uses it.
#define LWIP_WND_SCALE 1
#define TCP_RCV_SCALE 2
#define TCP_WND (128 * PANDA_BASE_TCP_MSS)
#define TCP_WND_RUNTIME_DEFAULT (32 * PANDA_BASE_TCP_MSS)
#define TCP_SND_BUF (64 * PANDA_BASE_TCP_MSS)
#define TCP_SND_BUF_RUNTIME_DEFAULT (16 * PANDA_BASE_TCP_MSS)
#define TCP_SND_BUF_RUNTIME_MIN (4 * PANDA_BASE_TCP_MSS)
// The upstream default derives this from the compile-time TCP_WND; pin it
// to the runtime-default window so raising only the ceiling keeps the
// historical explicit-window-update cadence (a larger threshold would
// delay reopening announcements at the unchanged 32-MSS active window).
#define TCP_WND_UPDATE_THRESHOLD \
  LWIP_MIN((TCP_WND_RUNTIME_DEFAULT / 4), (TCP_MSS * 4))
// TCP_MSS is compiled for a possible 9000-byte desktop TUN, but mobile runs
// at 1500 MTU. The lwIP default derives this queue from the oversized compile
// MSS and cannot represent one full Rust write, causing tcp_write(ERR_MEM) to
// repeat forever before any packet exists to produce an ACK/wakeup.
#define TCP_SND_QUEUELEN \
  ((4 * TCP_SND_BUF + (PANDA_BASE_TCP_MSS - 1)) / PANDA_BASE_TCP_MSS)
#elif defined(__ANDROID__) || defined(PANDA_LWIP_ANDROID_PROFILE)
// Host-side regression builds define PANDA_LWIP_ANDROID_PROFILE so the
// runnable Linux TUN harness exercises Android's TCP memory limits without
// pretending to be bionic at the libc-header boundary.
#define TCP_MSS 8960
#define LWIP_WND_SCALE 1
#define TCP_RCV_SCALE 2
#define TCP_WND (128 * PANDA_BASE_TCP_MSS)
#define TCP_SND_BUF (64 * PANDA_BASE_TCP_MSS)
#define TCP_SND_QUEUELEN \
  ((4 * TCP_SND_BUF + (PANDA_BASE_TCP_MSS - 1)) / PANDA_BASE_TCP_MSS)
#else
// Desktop system TCP stacks auto-tune into much larger windows.
//
// TCP_SND_BUF bounds the reverse (downlink) path: measured on the macOS
// loopback TUN benchmark, the write->ACK loop turns around in ~50us, so the
// old 64*MSS (91 KiB) send buffer capped reverse throughput at ~15 Gbit/s
// with the core mostly idle. 256*MSS lifts that ceiling without touching the
// mobile tiers. TCP_SND_QUEUELEN must cover the
// 1460-byte runtime MSS of 1500-MTU TUNs (256 segments per full buffer),
// where the default formula in units of the 8960 compile-time MSS would
// starve the queue before the buffer fills.
#define LWIP_WND_SCALE 1
// The usable receive window is min(active window, 65535 << TCP_RCV_SCALE), so
// scale 3 silently capped it at 512 KiB while the configuration asked for 2.2 MiB.
// Nobody noticed on low-RTT paths, but a capture on a virtualised Windows
// guest (where host scheduling inflates the TUN round trip to 3-6 ms) showed
// the whole "deep-latency" degraded mode was just this: a smooth,
// stall-free, window-limited flow at 512KiB/RTT — 0.65-0.96 Gbit/s with
// near-zero CPU, raw window field topping out at 46720 (~373 KiB effective).
// Scale 6 raises the advertised-window ceiling to 4,194,240 bytes. Windows
// needs a receive budget above 384 MSS to cross the virtualized TUN feedback
// knee: same-window ABBA measured 384 MSS at 7.75-8.57 Gbit/s and 512 MSS at
// 18.37-19.45 Gbit/s. Windows compiles the largest whole-MSS window that fits
// scale 6 so runtime sweeps do not require rebuilding, while keeping 512 MSS
// as the active default. PANDA_LWIP_TCP_RCV_WND_MSS selects the active value
// once at process startup. macOS and Linux keep their existing fixed budget.
//
// Desktop MSS ceiling: the effective MSS is min(TCP_MSS, netif->mtu - 40)
// per connection, so this only sets how far the runtime `tun.mtu` knob can
// reach. 16382 is the LARGEST value upstream lwIP's sanity checks admit —
// beyond it, init.c #errors because parts of the TCP machinery still do
// u16 arithmetic in MSS multiples: TCP_MSS must stay under 16383, and
// TCP_SNDLOWAT + 4*TCP_MSS must stay under 65535, which with our 2920-byte
// SNDLOWAT caps the ceiling at 15653. Going to a 64K-class ceiling
// therefore requires auditing that machinery first, not just raising this
// number. Windows/buffers are sized in
// PANDA_BASE_TCP_MSS byte units on purpose: they do NOT scale with this
// ceiling, so raising it costs no memory at small runtime MTUs.
// (A 2026-07-25 measurement concluded a 65095 MSS "gains nothing" — that
// predates the libc-malloc heap, the pressure queue, checksum offload, RX
// handoff, and sharding; in that regime the producer was serialization-
// bound at ~0.5 cores. After those landed, MTU 4000->9000 alone DOUBLED
// bidirectional throughput, so the segment-size lever is live again and
// the ceiling is runtime-selectable up to the sanity-check limit:
// tun.mtu 576..15680 all map to working configurations at runtime.)
#define TCP_MSS 15640
#define TCP_RCV_SCALE 6
#if defined(_WIN32)
#define TCP_WND (2872 * PANDA_BASE_TCP_MSS)
#define TCP_WND_RUNTIME_DEFAULT (512 * PANDA_BASE_TCP_MSS)
// The send buffer bounds the DOWNLOAD direction the way the receive window
// bounds upload, and the lwIP tuning guidance is explicit that it must
// cover the window to reach full throughput. Windows tuned its receive
// side to the 512-MSS class but left the send buffer at 256 MSS
// (373 KiB): on the virtualized-TUN 3-6 ms RTT that caps a single
// download flow at ~600 Mbit/s (373 KiB per round trip) regardless of
// CPU. Match the active window class; per-connection payload memory is
// heap-on-demand (MEM_LIBC_MALLOC), not a static allocation.
#define TCP_SND_BUF (512 * PANDA_BASE_TCP_MSS)
#else
#define TCP_WND (256 * PANDA_BASE_TCP_MSS)
#define TCP_SND_BUF (256 * PANDA_BASE_TCP_MSS)
#endif
// Sized for the smallest runtime MSS (see PANDA_MIN_EFF_TCP_MSS): a full
// send buffer at MSS 536 needs ~698 segments and interleaved partial
// segments push past that; the previous fixed 512 starved exactly there
// (any tun.mtu below ~1000 could wedge tcp_write on ERR_MEM with the
// buffer nowhere near full). This is a limit, not an allocation — the
// segment pool (MEMP_NUM_TCP_SEG) still bounds real memory.
#define TCP_SND_QUEUELEN \
  ((4 * TCP_SND_BUF + (PANDA_MIN_EFF_TCP_MSS - 1)) / PANDA_MIN_EFF_TCP_MSS)
#endif
#define TCP_SNDLOWAT (2 * PANDA_BASE_TCP_MSS)
#define TCP_KEEPIDLE_DEFAULT 30000UL
#define TCP_KEEPINTVL_DEFAULT 10000UL
#define TCP_KEEPCNT_DEFAULT 2U

#if defined __APPLE__
#include <TargetConditionals.h>
#if TARGET_OS_IPHONE
// The fixed lwIP heap is a deliberate hard cap on the Network Extension's
// TCP payload memory (jetsam budget); mobile stays on mem.c. 2 MiB matches
// the validated Android tier and covers the raised window/send-buffer
// ceilings; the heap is a BSS array, so pages the default-budget workload
// never touches stay clean and do not move the jetsam footprint.
#define MEM_SIZE (2 * 1024 * 1024)
#endif
#elif defined(__ANDROID__) || defined(PANDA_LWIP_ANDROID_PROFILE)
// Mobile budget: keep the Android heap at its validated size.
#define MEM_SIZE (2 * 1024 * 1024)
#endif

#if (defined __APPLE__ && TARGET_OS_IPHONE) || defined(__ANDROID__) || \
    defined(PANDA_LWIP_ANDROID_PROFILE)
// Mobile keeps the validated pool; its small per-pcb send buffers (16-64
// MSS) never sit at the pool boundary the way desktop's do. The small
// mobile heaps also bound mem.c's scan cost to a few hundred blocks.
#define MEMP_NUM_TCP_SEG 4096
#else
// Desktop tcp_write(COPY) payloads go through libc malloc instead of lwIP's
// own heap. mem.c's mem_malloc is a first-fit scan from `lfree` across
// every heap block; at 16 interleaved bulk flows (~4k live payload blocks
// at ~340k allocs/s) that scan became the CPU sink behind the Linux TUN
// P16 producer collapse — 0.84 Gbit/s at 251% CPU against sing-box's 6.2,
// independent of worker count. Switching the heap to libc malloc lifted
// download f16 to 7.5-10.0 Gbit/s on the same harness (2026-08-11); RSS
// peaked ~5 MB higher. Mobile keeps mem.c as a hard memory cap.
#define MEM_LIBC_MALLOC 1
// 16 bulk flows * 256-MSS send buffers consume 4096 segments nominally —
// the previous pool size exactly, with zero slack — and partial segments
// (tcp_output interleaving with tcp_write) push demand past it, so every
// tcp_write at 16 flows lived on the shared-pool ERR_MEM path. 16384 puts
// realistic flow counts well inside the pool; beyond it the pressure-queue
// wakeups in the Rust port degrade throughput gracefully instead of
// starving streams. The pool is a static BSS array of ~30-byte entries
// (~500 KiB); untouched pages stay clean.
#define MEMP_NUM_TCP_SEG 16384
#endif
#define PBUF_POOL_SIZE 512

// #define TCP_MSS 1460
// #define TCP_WND (16 * TCP_MSS)
// #define TCP_SND_BUF (8 * TCP_MSS)
// #define MEM_LIBC_MALLOC 1
// #define MEMP_MEM_MALLOC 1

#define SYS_LIGHTWEIGHT_PROT 0
#define LWIP_DONT_PROVIDE_BYTEORDER_FUNCTIONS

// needed on 64-bit systems, enable it always so that the same configuration
// is used regardless of the platform
#define IPV6_FRAG_COPYHEADER 1

#define LWIP_DEBUG 0
#define LWIP_DBG_MIN_LEVEL LWIP_DBG_LEVEL_ALL
#define LWIP_DBG_TYPES_ON LWIP_DBG_OFF
#define NETIF_DEBUG LWIP_DBG_OFF
#define PBUF_DEBUG LWIP_DBG_OFF
#define INET_DEBUG LWIP_DBG_OFF
#define IP_DEBUG LWIP_DBG_OFF
#define IP_REASS_DEBUG LWIP_DBG_OFF
#define RAW_DEBUG LWIP_DBG_OFF
#define MEM_DEBUG LWIP_DBG_OFF
#define MEMP_DEBUG LWIP_DBG_OFF
#define SYS_DEBUG LWIP_DBG_OFF
#define TIMERS_DEBUG LWIP_DBG_OFF
#define TCP_DEBUG LWIP_DBG_ON
#define TCP_INPUT_DEBUG LWIP_DBG_OFF
#define TCP_RTO_DEBUG LWIP_DBG_OFF
#define TCP_CWND_DEBUG LWIP_DBG_OFF
#define TCP_WND_DEBUG LWIP_DBG_OFF
#define TCP_RST_DEBUG LWIP_DBG_ON
#define TCP_QLEN_DEBUG LWIP_DBG_ON
#define TCP_OUTPUT_DEBUG LWIP_DBG_ON
#define UDP_DEBUG LWIP_DBG_OFF
#define TCPIP_DEBUG LWIP_DBG_OFF
#define IP6_DEBUG LWIP_DBG_OFF

#define LWIP_STATS 0
#define LWIP_STATS_DISPLAY 0
#define LWIP_PERF 0

#endif
