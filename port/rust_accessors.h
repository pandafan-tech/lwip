#ifndef LWIP_RUST_ACCESSORS_H
#define LWIP_RUST_ACCESSORS_H

#include "lwip/netif.h"
#include "lwip/tcp.h"
#include "lwip/udp.h"

void lwip_rs_configure_netif(netif_output_fn output,
                             netif_output_ip6_fn output_ip6,
                             u16_t mtu);
err_t lwip_rs_netif_input(struct pbuf *p);

void lwip_rs_tcp_endpoints(const struct tcp_pcb *pcb,
                           ip_addr_t *remote_ip,
                           u16_t *remote_port,
                           ip_addr_t *local_ip,
                           u16_t *local_port);
void lwip_rs_tcp_apply_options(struct tcp_pcb *pcb, int keepalive);
tcpwnd_size_t lwip_rs_tcp_send_buffer(const struct tcp_pcb *pcb);
err_t lwip_rs_retry_tcp_output(void);

void lwip_rs_udp_local_endpoint(const struct udp_pcb *pcb,
                                ip_addr_t *local_ip,
                                u16_t *local_port);
err_t lwip_rs_udp_sendto(struct udp_pcb *pcb,
                         struct pbuf *p,
                         const ip_addr_t *dst_ip,
                         u16_t dst_port,
                         const ip_addr_t *src_ip,
                         u16_t src_port);

#endif
