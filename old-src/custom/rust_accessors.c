#include "rust_accessors.h"

void lwip_rs_configure_netif(netif_output_fn output,
                             netif_output_ip6_fn output_ip6,
                             u16_t mtu) {
  LWIP_ASSERT("netif_list must be initialized", netif_list != NULL);
  netif_list->output = output;
  netif_list->output_ip6 = output_ip6;
  netif_list->mtu = mtu;
}

err_t lwip_rs_netif_input(struct pbuf *p) {
  if ((netif_list == NULL) || (netif_list->input == NULL)) {
    return ERR_IF;
  }
  return netif_list->input(p, netif_list);
}

void lwip_rs_tcp_endpoints(const struct tcp_pcb *pcb,
                           ip_addr_t *remote_ip,
                           u16_t *remote_port,
                           ip_addr_t *local_ip,
                           u16_t *local_port) {
  LWIP_ASSERT("tcp pcb must not be NULL", pcb != NULL);
  *remote_ip = pcb->remote_ip;
  *remote_port = pcb->remote_port;
  *local_ip = pcb->local_ip;
  *local_port = pcb->local_port;
}

void lwip_rs_tcp_apply_options(struct tcp_pcb *pcb, int keepalive) {
  LWIP_ASSERT("tcp pcb must not be NULL", pcb != NULL);
  if (keepalive) {
    pcb->so_options |= SOF_KEEPALIVE;
  }
  pcb->flags |= TF_NODELAY;
}

tcpwnd_size_t lwip_rs_tcp_send_buffer(const struct tcp_pcb *pcb) {
  LWIP_ASSERT("tcp pcb must not be NULL", pcb != NULL);
  return pcb->snd_buf;
}

void lwip_rs_udp_local_endpoint(const struct udp_pcb *pcb,
                                ip_addr_t *local_ip,
                                u16_t *local_port) {
  LWIP_ASSERT("udp pcb must not be NULL", pcb != NULL);
  *local_ip = pcb->local_ip;
  *local_port = pcb->local_port;
}
