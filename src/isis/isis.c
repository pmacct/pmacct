/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2012 by Paolo Lucente
*/

/*
    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

/* defines */
#define __ISIS_C

/* includes */
#include "pmacct.h"
#include "isis.h"
#include "thread_pool.h"

#include "linklist.h"
#include "stream.h"
#include "hash.h"
#include "prefix.h"

#include "dict.h"
#include "thread.h"
#include "iso.h"
#include "table.h"
#include "isis_constants.h"
#include "isis_common.h"
#include "isis_adjacency.h"
#include "isis_circuit.h"
#include "isis_network.h"
#include "isis_misc.h"
#include "isis_flags.h"
#include "isis_tlv.h"
#include "isisd.h"
#include "isis_dynhn.h"
#include "isis_lsp.h"
#include "isis_pdu.h"
#include "iso_checksum.h"
#include "isis_csm.h"
#include "isis_events.h"
#include "isis_spf.h"
#include "isis_route.h"

/* variables to be exported away */
thread_pool_t *isis_pool;

/* Functions */
#if defined ENABLE_THREADS
void nfacctd_isis_wrapper()
{
  /* initialize threads pool */
  isis_pool = allocate_thread_pool(1);
  assert(isis_pool);
  Log(LOG_DEBUG, "DEBUG ( default/core/ISIS ): %d thread(s) initialized\n", 1);

  /* giving a kick to the BGP thread */
  send_to_pool(isis_pool, skinny_isis_daemon, NULL);
}
#endif

void skinny_isis_daemon()
{
  char errbuf[PCAP_ERRBUF_SIZE];
  struct pcap_device device;
  struct pcap_isis_callback_data cb_data;
  struct host_addr addr;
  struct prefix_ipv4 *ipv4;
  int index, ret;

  char area_tag[] = "default";
  struct isis_area *area;
  struct isis_circuit *circuit;
  struct interface interface;

  memset(&device, 0, sizeof(struct pcap_device));
  memset(&cb_data, 0, sizeof(cb_data));
  memset(&interface, 0, sizeof(interface));
  memset(&isis_spf_deadline, 0, sizeof(isis_spf_deadline));

  /* initializing IS-IS structures */
  isis_init();
  dyn_cache_init();

  /* thread master */
  master = thread_master_create();

  if (!config.nfacctd_isis_iface) {
    Log(LOG_ERR, "ERROR ( default/core/ISIS ): 'isis_daemon_iface' value is not specified. Terminating thread.\n");
    exit(1);
  }

  // XXX: MTU set by config?
  if ((device.dev_desc = pcap_open_live(config.nfacctd_isis_iface, 1500, 0, 1000, errbuf)) == NULL) {
    Log(LOG_ERR, "ERROR ( default/core/ISIS ): pcap_open_live(): %s\n", errbuf);
    exit(1);
  }

  device.link_type = pcap_datalink(device.dev_desc);
  for (index = 0; _isis_devices[index].link_type != -1; index++) {
    if (device.link_type == _isis_devices[index].link_type)
      device.data = &_isis_devices[index];
  }

  if (device.data == NULL) {
    Log(LOG_ERR, "ERROR ( default/core/ISIS ): data link not supported: %d\n", device.link_type);
    return;
  }
  else {
    Log(LOG_INFO, "OK ( default/core/ISIS ): link type is: %d\n", device.link_type);
    cb_data.device = &device;
  }

  area = isis_area_create();
  area->area_tag = area_tag;
  area->is_type = IS_LEVEL_2;
  area->newmetric = TRUE;
  listnode_add(isis->area_list, area);
  if (config.debug) Log(LOG_DEBUG, "DEBUG ( default/core/ISIS ): New IS-IS area instance %s\n", area->area_tag);
  if (config.nfacctd_isis_net) area_net_title(area, config.nfacctd_isis_net);
  else {
    Log(LOG_ERR, "ERROR ( default/core/ISIS ): 'isis_daemon_net' value is not specified. Terminating thread.\n");
    exit_all(1);
  }

  circuit = isis_circuit_new();
  circuit->circ_type = CIRCUIT_T_P2P;
  circuit->fd = pcap_fileno(device.dev_desc);
  circuit->tx = isis_send_pdu_p2p;
  circuit->interface = &interface;
  circuit->state = C_STATE_UP;

  if (config.nfacctd_isis_ip) {
    trim_spaces(config.nfacctd_isis_ip);
    ret = str_to_addr(config.nfacctd_isis_ip, &addr);
    if (!ret) {
      Log(LOG_ERR, "ERROR ( default/core/ISIS ): 'nfacctd_isis_ip' value is not a valid IPv4/IPv6 address. Terminating thread.\n");
      exit_all(1);
    }
  }
  else {
    Log(LOG_ERR, "ERROR ( default/core/ISIS ): 'nfacctd_isis_ip' value is not specified. Terminating thread.\n");
    exit_all(1);
  }

  circuit->ip_router = addr.address.ipv4.s_addr;
  ipv4 = isis_prefix_ipv4_new();
  ipv4->prefixlen = 32;
  ipv4->prefix.s_addr = addr.address.ipv4.s_addr;
  circuit->ip_addrs = list_new();
  listnode_add(circuit->ip_addrs, ipv4);

  circuit_update_nlpids(circuit);
  isis_circuit_configure(circuit, area);
  cb_data.circuit = circuit;

  area->ip_circuits = 1;
  memcpy(circuit->interface->name, config.nfacctd_isis_iface, strlen(config.nfacctd_isis_iface));
  circuit->interface->ifindex = if_nametoindex(config.nfacctd_isis_iface);

  for (;;) {
    /* XXX: should get a select() here at some stage? */
    pcap_loop(device.dev_desc, -1, isis_pdu_runner, (u_char *) &cb_data);

    break;
  }

  pcap_close(device.dev_desc);
}

void isis_pdu_runner(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *buf)
{
  struct pcap_isis_callback_data *cb_data = (struct pcap_isis_callback_data *) user;
  struct pcap_device *device = cb_data->device;
  struct isis_circuit *circuit = cb_data->circuit;
  struct packet_ptrs pptrs;
  struct thread thread;
  int ret;

  struct stream stm;
  char *ssnpa;

  /* Let's export a time reference */
  memcpy(&isis_now, &pkthdr->ts, sizeof(struct timeval));

  /* check if we have to expire adjacency first */
  if (circuit && circuit->u.p2p.neighbor) {
    if (timeval_cmp(&isis_now, &circuit->u.p2p.neighbor->expire) >= 0)
      isis_adj_expire(circuit->u.p2p.neighbor);
  }

  memset(&pptrs, 0, sizeof(pptrs));
  memset(&stm, 0, sizeof(stm));

  if (buf) {
    pptrs.pkthdr = (struct pcap_pkthdr *) pkthdr;
    pptrs.packet_ptr = (u_char *) buf;

    (*device->data->handler)(pkthdr, &pptrs);
    if (pptrs.iph_ptr) {
      if ((*pptrs.l3_handler)(&pptrs)) {

	/*assembling handover to isis_handle_pdu() */
	stm.data = pptrs.iph_ptr;
	stm.getp = 0;
	stm.endp = pkthdr->caplen - (pptrs.iph_ptr - pptrs.packet_ptr);
	stm.size = pkthdr->caplen - (pptrs.iph_ptr - pptrs.packet_ptr);
	ssnpa = pptrs.packet_ptr;
	circuit->rcv_stream = &stm;

	/* Let's match ISO MTU based on a remote node Hello (typically padded) */ 
	if (!circuit->interface->mtu)
	  circuit->interface->mtu = pkthdr->caplen - (pptrs.iph_ptr - pptrs.packet_ptr);

	/* process IS-IS packet */
	isis_handle_pdu (circuit, ssnpa);
      }
    }
  }

  /* check if it's time to run SPF */
  if (timeval_cmp(&isis_now, &isis_spf_deadline) >= 0) {
    if (circuit->area->is_type & IS_LEVEL_1) {
      if (circuit->area->ip_circuits) {
	ret = isis_run_spf(circuit->area, 1, AF_INET);
	isis_route_validate_table (circuit->area, circuit->area->route_table[0]);
      }
      /* XXX: IPv6 handled here */
    }

    if (circuit->area->is_type & IS_LEVEL_2) {
      if (circuit->area->ip_circuits) {
	ret = isis_run_spf(circuit->area, 2, AF_INET);
	isis_route_validate_table (circuit->area, circuit->area->route_table[1]);
      }
      /* XXX: IPv6 handled here */
    }

    isis_route_validate_merge (circuit->area, AF_INET);

    dyn_cache_cleanup();

    isis_spf_deadline.tv_sec = isis_now.tv_sec + isis_jitter(PERIODIC_SPF_INTERVAL, 10);
    isis_spf_deadline.tv_usec = 0;
  }

  if (timeval_cmp(&isis_now, &isis_psnp_deadline) >= 0) {
    send_psnp(1, circuit);
    send_psnp(2, circuit);

    isis_psnp_deadline.tv_sec = isis_now.tv_sec + isis_jitter(PSNP_INTERVAL, PSNP_JITTER);
    isis_psnp_deadline.tv_usec = 0;
  }
}

void isis_sll_handler(const struct pcap_pkthdr *h, register struct packet_ptrs *pptrs)
{
  register const struct sll_header *sllp;
  u_int caplen = h->caplen;
  u_int16_t etype, nl;
  u_char *p;

  if (caplen < SLL_HDR_LEN) {
    pptrs->iph_ptr = NULL;
    return;
  }

  p = pptrs->packet_ptr;

  sllp = (const struct sll_header *) pptrs->packet_ptr;
  etype = ntohs(sllp->sll_protocol);
  nl = SLL_HDR_LEN;

  if (etype == ETHERTYPE_GRE_ISO) {
    pptrs->l3_proto = ETHERTYPE_GRE_ISO;
    pptrs->l3_handler = iso_handler;
    pptrs->iph_ptr = (u_char *)(pptrs->packet_ptr + nl);
    return;
  }

  pptrs->l3_proto = 0;
  pptrs->l3_handler = NULL;
  pptrs->iph_ptr = NULL;
}

int iso_handler(register struct packet_ptrs *pptrs)
{
}

void isis_srcdst_lookup(struct packet_ptrs *pptrs)
{
  struct route_node *result;
  struct isis_area *area;
  char area_tag[] = "default";
  int level;
  struct in_addr pref4;
#if defined ENABLE_IPV6
  struct in6_addr pref6;
#endif

  pptrs->igp_src = NULL;
  pptrs->igp_dst = NULL;
  pptrs->igp_src_info = NULL;
  pptrs->igp_dst_info = NULL;

  area = isis_area_lookup(area_tag);

  if (area) {
    level = MAX(area->is_type, 2);

    if (pptrs->l3_proto == ETHERTYPE_IP) {
      if (!pptrs->igp_src) {
	memcpy(&pref4, &((struct my_iphdr *)pptrs->iph_ptr)->ip_src, sizeof(struct in_addr));
	result = route_node_match_ipv4(area->route_table[level-1], &pref4);

	if (result) {
	  pptrs->igp_src = (char *) &result->p;
	  pptrs->igp_src_info = (char *) result->info;
	}
      }

      if (!pptrs->igp_dst) {
	memcpy(&pref4, &((struct my_iphdr *)pptrs->iph_ptr)->ip_dst, sizeof(struct in_addr));
	result = route_node_match_ipv4(area->route_table[level-1], &pref4);

	if (result) {
          pptrs->igp_dst = (char *) &result->p;
          pptrs->igp_dst_info = (char *) result->info;
	}
      }
    }
#if defined ENABLE_IPV6
    else if (area && pptrs->l3_proto == ETHERTYPE_IPV6) {
      if (!pptrs->igp_src) {
        memcpy(&pref6, &((struct ip6_hdr *)pptrs->iph_ptr)->ip6_src, sizeof(struct in6_addr));
        result = route_node_match_ipv6(area->route_table6[level-1], &pref6);

        pptrs->igp_src = (char *) &result->p;
        pptrs->igp_src_info = (char *) result->info;
      }

      if (!pptrs->igp_dst) {
        memcpy(&pref6, &((struct ip6_hdr *)pptrs->iph_ptr)->ip6_dst, sizeof(struct in6_addr));
        result = route_node_match_ipv6(area->route_table6[level-1], &pref6);

        pptrs->igp_dst = (char *) &result->p;
        pptrs->igp_dst_info = (char *) result->info;
      }
    }
#endif
  }
}
