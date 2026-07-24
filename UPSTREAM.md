# Upstream source

`src/` is vendored from the official
[`lwip-tcpip/lwip`](https://github.com/lwip-tcpip/lwip) tag
`STABLE-2_2_1_RELEASE` (commit `77dcd25a`).

PandaCore-specific integration lives in `port/`. The small TUN interception
patches that must be carried when syncing a newer upstream release are confined
to:

- `src/core/ipv4/ip4.c`
- `src/core/ipv6/ip6.c`
- `src/core/tcp_in.c`
- `src/core/udp.c`
- `src/include/lwip/udp.h`

`build.rs` compiles `src/`, not the removed legacy `old-src/` snapshot.
