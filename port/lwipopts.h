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
#define MEMP_NUM_TCP_PCB 256
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

#define LWIP_CHECKSUM_ON_COPY 1
#define LWIP_CHKSUM_ALGORITHM 3

#define PANDA_BASE_TCP_MSS 1460
// Compile for the largest MSS used by the default desktop TUN MTU (9000).
// The effective MSS is still capped at runtime by netif->mtu, so mobile and
// 1500-byte TUNs continue to advertise 1460.
#define TCP_MSS 8960
#if defined __APPLE__ && TARGET_OS_IPHONE
// Network Extension has a tight process-memory ceiling. Keep the mobile
// receive/send budget conservative; the device-side TUN RTT is tiny.
#define TCP_WND (32 * PANDA_BASE_TCP_MSS)
#define TCP_SND_BUF (16 * PANDA_BASE_TCP_MSS)
#elif defined __ANDROID__
#define LWIP_WND_SCALE 1
#define TCP_RCV_SCALE 2
#define TCP_WND (128 * PANDA_BASE_TCP_MSS)
#define TCP_SND_BUF (64 * PANDA_BASE_TCP_MSS)
#else
// Desktop system TCP stacks auto-tune into much larger windows. Keep PandaCore
// at the kernel's 256 KiB congestion-window scale without increasing either
// mobile platform's per-flow memory budget.
//
// TCP_SND_BUF bounds the reverse (downlink) path: measured on the macOS
// loopback TUN benchmark, the write->ACK loop turns around in ~50us, so the
// old 64*MSS (91 KiB) send buffer capped reverse throughput at ~15 Gbit/s
// with the core mostly idle. 256*MSS matches TCP_WND and lifts the ceiling
// without touching the mobile tiers. TCP_SND_QUEUELEN must cover the
// 1460-byte runtime MSS of 1500-MTU TUNs (256 segments per full buffer),
// where the default formula in units of the 8960 compile-time MSS would
// starve the queue before the buffer fills.
#define LWIP_WND_SCALE 1
#define TCP_RCV_SCALE 3
#define TCP_WND (256 * PANDA_BASE_TCP_MSS)
#define TCP_SND_BUF (256 * PANDA_BASE_TCP_MSS)
#define TCP_SND_QUEUELEN 512
#endif
#define TCP_SNDLOWAT (2 * PANDA_BASE_TCP_MSS)
#define TCP_KEEPIDLE_DEFAULT 30000UL
#define TCP_KEEPINTVL_DEFAULT 10000UL
#define TCP_KEEPCNT_DEFAULT 2U

#if defined __APPLE__
#include <TargetConditionals.h>
#if TARGET_OS_IPHONE
#define MEM_SIZE (512 * 1024)
#else
// tcp_write(COPY) payloads live in this heap, so the desktop heap must hold
// several 256*MSS send buffers of in-flight bulk data at once. The heap is
// BSS: untouched pages stay clean, idle RSS does not grow.
#define MEM_SIZE (8 * 1024 * 1024)
#endif
#elif defined __ANDROID__
// Mobile budget: keep the Android heap at its validated size; the desktop
// send-buffer bump above does not apply to this tier either.
#define MEM_SIZE (2 * 1024 * 1024)
#else
#define MEM_SIZE (8 * 1024 * 1024)
#endif

#define MEMP_NUM_TCP_SEG 4096
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
