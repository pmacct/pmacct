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
  int index;

  memset(&device, 0, sizeof(struct pcap_device));
  memset(&cb_data, 0, sizeof(cb_data));

  if ((device.dev_desc = pcap_open_live("ospf_test", 1500, 0, 1000, errbuf)) == NULL) {
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

  for (;;) {
    pcap_loop(device.dev_desc, -1, isis_pdu_runner, (u_char *) &cb_data);

    break;
  }

  pcap_close(device.dev_desc);
}

void isis_pdu_runner(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *buf)
{
  struct pcap_isis_callback_data *cb_data = (struct pcap_isis_callback_data *) user;
  struct pcap_device *device = cb_data->device;
  struct packet_ptrs pptrs;

  struct isis_circuit circuit;
  struct stream stm;
  char *ssnpa;

  memset(&pptrs, 0, sizeof(pptrs));
  memset(&circuit, 0, sizeof(circuit));
  memset(&stm, 0, sizeof(stm));

  if (buf) {
    pptrs.pkthdr = (struct pcap_pkthdr *) pkthdr;
    pptrs.packet_ptr = (u_char *) buf;

    (*device->data->handler)(pkthdr, &pptrs);
    if (pptrs.iph_ptr) {
      if ((*pptrs.l3_handler)(&pptrs)) {
	printf("CI PASSO: Wee wee!\n");

	/*assembling handover to isis_handle_pdu() */
	stm.data = pptrs.packet_ptr;
	stm.getp = (pptrs.iph_ptr - pptrs.packet_ptr);
	stm.endp = pkthdr->caplen;
	stm.size = 1500; // XXX 
	ssnpa = pptrs.packet_ptr; // XXX
	circuit.rcv_stream = &stm;

	// XXX: process IS-IS packet
	isis_handle_pdu (&circuit, ssnpa);
      }
    }
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
  printf("CI PASSO: ISO\n");
}
