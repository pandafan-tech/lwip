#include "rust_accessors.h"
#include "lwip/ip.h"
#include "lwip/priv/tcp_priv.h"

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

err_t lwip_rs_retry_tcp_output(void) {
  struct tcp_pcb *pcb;

  for (pcb = tcp_active_pcbs; pcb != NULL; pcb = pcb->next) {
    err_t err = tcp_output(pcb);
    if (err != ERR_OK) {
      return err;
    }
  }
  return ERR_OK;
}

void lwip_rs_udp_local_endpoint(const struct udp_pcb *pcb,
                                ip_addr_t *local_ip,
                                u16_t *local_port) {
  LWIP_ASSERT("udp pcb must not be NULL", pcb != NULL);
  *local_ip = pcb->local_ip;
  *local_port = pcb->local_port;
}

err_t lwip_rs_udp_sendto(struct udp_pcb *pcb,
                         struct pbuf *p,
                         const ip_addr_t *dst_ip,
                         u16_t dst_port,
                         const ip_addr_t *src_ip,
                         u16_t src_port) {
  struct netif *netif;
  u16_t previous_port;
  err_t err;

  LWIP_ERROR("lwip_rs_udp_sendto: invalid pcb", pcb != NULL, return ERR_ARG);
  netif = ip_route(src_ip, dst_ip);
  if (netif == NULL) {
    return ERR_RTE;
  }

  previous_port = pcb->local_port;
  pcb->local_port = src_port;
  err = udp_sendto_if_src(pcb, p, dst_ip, dst_port, netif, src_ip);
  pcb->local_port = previous_port;
  return err;
}
