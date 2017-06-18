/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2017 by Paolo Lucente
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
#define __NFV8_HANDLERS_C

/* includes */
#include "pmacct.h"
#include "nfacctd.h"
#include "pmacct-data.h"
#include "nfv8_handlers.h"

void load_nfv8_handlers()
{
  memset(&v8_handlers, 0, sizeof(v8_handlers));

  v8_handlers[1].fh = v8_1_filter_handler;
  v8_handlers[1].max_flows = V8_1_MAXFLOWS;
  v8_handlers[1].exp_size = sizeof(struct struct_export_v8_1);

  v8_handlers[2].fh = v8_2_filter_handler;
  v8_handlers[2].max_flows = V8_2_MAXFLOWS;
  v8_handlers[2].exp_size = sizeof(struct struct_export_v8_2);

  v8_handlers[3].fh = v8_3_filter_handler;
  v8_handlers[3].max_flows = V8_3_MAXFLOWS;
  v8_handlers[3].exp_size = sizeof(struct struct_export_v8_3);

  v8_handlers[4].fh = v8_4_filter_handler;
  v8_handlers[4].max_flows = V8_4_MAXFLOWS;
  v8_handlers[4].exp_size = sizeof(struct struct_export_v8_4);

  v8_handlers[5].fh = v8_5_filter_handler;
  v8_handlers[5].max_flows = V8_5_MAXFLOWS;
  v8_handlers[5].exp_size = sizeof(struct struct_export_v8_5);

  v8_handlers[6].fh = v8_6_filter_handler;
  v8_handlers[6].max_flows = V8_6_MAXFLOWS;
  v8_handlers[6].exp_size = sizeof(struct struct_export_v8_6);

  v8_handlers[7].fh = v8_7_filter_handler;
  v8_handlers[7].max_flows = V8_7_MAXFLOWS;
  v8_handlers[7].exp_size = sizeof(struct struct_export_v8_7);

  v8_handlers[8].fh = v8_8_filter_handler;
  v8_handlers[8].max_flows = V8_8_MAXFLOWS;
  v8_handlers[8].exp_size = sizeof(struct struct_export_v8_8);

  v8_handlers[9].fh = v8_9_filter_handler;
  v8_handlers[9].max_flows = V8_9_MAXFLOWS;
  v8_handlers[9].exp_size = sizeof(struct struct_export_v8_9);

  v8_handlers[10].fh = v8_10_filter_handler;
  v8_handlers[10].max_flows = V8_10_MAXFLOWS;
  v8_handlers[10].exp_size = sizeof(struct struct_export_v8_10);

  v8_handlers[11].fh = v8_11_filter_handler;
  v8_handlers[11].max_flows = V8_11_MAXFLOWS;
  v8_handlers[11].exp_size = sizeof(struct struct_export_v8_11);

  v8_handlers[12].fh = v8_12_filter_handler;
  v8_handlers[12].max_flows = V8_12_MAXFLOWS;
  v8_handlers[12].exp_size = sizeof(struct struct_export_v8_12);

  v8_handlers[13].fh = v8_13_filter_handler;
  v8_handlers[13].max_flows = V8_13_MAXFLOWS;
  v8_handlers[13].exp_size = sizeof(struct struct_export_v8_13);

  v8_handlers[14].fh = v8_14_filter_handler;
  v8_handlers[14].max_flows = V8_14_MAXFLOWS;
  v8_handlers[14].exp_size = sizeof(struct struct_export_v8_14);
}

void v8_1_filter_handler(struct packet_ptrs *pptrs, void *data)
{
  struct struct_export_v8_1 *exp = (struct struct_export_v8_1 *) data;

  /* It contains just AS informations; no filtering chances */
}

void v8_2_filter_handler(struct packet_ptrs *pptrs, void *data)
{
  struct struct_export_v8_2 *exp = (struct struct_export_v8_2 *) data;

  Assign8(((struct pm_iphdr *)pptrs->iph_ptr)->ip_p, exp->prot);
  Assign16(((struct pm_tlhdr *)pptrs->tlh_ptr)->src_port, exp->srcport);
  Assign16(((struct pm_tlhdr *)pptrs->tlh_ptr)->dst_port, exp->dstport);
}

void v8_3_filter_handler(struct packet_ptrs *pptrs, void *data)
{
  struct struct_export_v8_3 *exp = (struct struct_export_v8_3 *) data;

  Assign32(((struct pm_iphdr *)pptrs->iph_ptr)->ip_src.s_addr, exp->src_prefix);
}

void v8_4_filter_handler(struct packet_ptrs *pptrs, void *data)
{
  struct struct_export_v8_4 *exp = (struct struct_export_v8_4 *) data;

  Assign32(((struct pm_iphdr *)pptrs->iph_ptr)->ip_dst.s_addr, exp->dst_prefix);
}

void v8_5_filter_handler(struct packet_ptrs *pptrs, void *data)
{
  struct struct_export_v8_5 *exp = (struct struct_export_v8_5 *) data;

  Assign32(((struct pm_iphdr *)pptrs->iph_ptr)->ip_src.s_addr, exp->src_prefix);
  Assign32(((struct pm_iphdr *)pptrs->iph_ptr)->ip_dst.s_addr, exp->dst_prefix);
}

void v8_6_filter_handler(struct packet_ptrs *pptrs, void *data)
{
  struct struct_export_v8_6 *exp = (struct struct_export_v8_6 *) data;

  Assign32(((struct pm_iphdr *)pptrs->iph_ptr)->ip_dst.s_addr, exp->dstaddr);
  Assign8(((struct pm_iphdr *)pptrs->iph_ptr)->ip_tos, exp->tos);
}

void v8_7_filter_handler(struct packet_ptrs *pptrs, void *data)
{
  struct struct_export_v8_7 *exp = (struct struct_export_v8_7 *) data;

  Assign32(((struct pm_iphdr *)pptrs->iph_ptr)->ip_src.s_addr, exp->srcaddr);
  Assign32(((struct pm_iphdr *)pptrs->iph_ptr)->ip_dst.s_addr, exp->dstaddr);
  Assign8(((struct pm_iphdr *)pptrs->iph_ptr)->ip_tos, exp->tos);
}

void v8_8_filter_handler(struct packet_ptrs *pptrs, void *data)
{
  struct struct_export_v8_8 *exp = (struct struct_export_v8_8 *) data;

  Assign32(((struct pm_iphdr *)pptrs->iph_ptr)->ip_src.s_addr, exp->srcaddr);
  Assign32(((struct pm_iphdr *)pptrs->iph_ptr)->ip_dst.s_addr, exp->dstaddr);
  Assign8(((struct pm_iphdr *)pptrs->iph_ptr)->ip_p, exp->prot);
  Assign8(((struct pm_iphdr *)pptrs->iph_ptr)->ip_tos, exp->tos);
  Assign16(((struct pm_tlhdr *)pptrs->tlh_ptr)->src_port, exp->srcport);
  Assign16(((struct pm_tlhdr *)pptrs->tlh_ptr)->dst_port, exp->dstport);
}

void v8_9_filter_handler(struct packet_ptrs *pptrs, void *data)
{
  struct struct_export_v8_9 *exp = (struct struct_export_v8_9 *) data;

  Assign8(((struct pm_iphdr *)pptrs->iph_ptr)->ip_tos, exp->tos);
}

void v8_10_filter_handler(struct packet_ptrs *pptrs, void *data)
{
  struct struct_export_v8_10 *exp = (struct struct_export_v8_10 *) data;

  Assign8(((struct pm_iphdr *)pptrs->iph_ptr)->ip_p, exp->prot);
  Assign8(((struct pm_iphdr *)pptrs->iph_ptr)->ip_tos, exp->tos);
  Assign16(((struct pm_tlhdr *)pptrs->tlh_ptr)->src_port, exp->srcport);
  Assign16(((struct pm_tlhdr *)pptrs->tlh_ptr)->dst_port, exp->dstport);
}

void v8_11_filter_handler(struct packet_ptrs *pptrs, void *data)
{
  struct struct_export_v8_11 *exp = (struct struct_export_v8_11 *) data;

  Assign32(((struct pm_iphdr *)pptrs->iph_ptr)->ip_src.s_addr, exp->src_prefix);
  Assign8(((struct pm_iphdr *)pptrs->iph_ptr)->ip_tos, exp->tos);
}

void v8_12_filter_handler(struct packet_ptrs *pptrs, void *data)
{
  struct struct_export_v8_12 *exp = (struct struct_export_v8_12 *) data;

  Assign32(((struct pm_iphdr *)pptrs->iph_ptr)->ip_dst.s_addr, exp->dst_prefix);
  Assign8(((struct pm_iphdr *)pptrs->iph_ptr)->ip_tos, exp->tos);
}

void v8_13_filter_handler(struct packet_ptrs *pptrs, void *data)
{
  struct struct_export_v8_13 *exp = (struct struct_export_v8_13 *) data;

  Assign32(((struct pm_iphdr *)pptrs->iph_ptr)->ip_src.s_addr, exp->src_prefix);
  Assign32(((struct pm_iphdr *)pptrs->iph_ptr)->ip_dst.s_addr, exp->dst_prefix);
  Assign8(((struct pm_iphdr *)pptrs->iph_ptr)->ip_tos, exp->tos);
}

void v8_14_filter_handler(struct packet_ptrs *pptrs, void *data)
{
  struct struct_export_v8_14 *exp = (struct struct_export_v8_14 *) data;

  Assign32(((struct pm_iphdr *)pptrs->iph_ptr)->ip_src.s_addr, exp->src_prefix);
  Assign32(((struct pm_iphdr *)pptrs->iph_ptr)->ip_dst.s_addr, exp->dst_prefix);
  Assign8(((struct pm_iphdr *)pptrs->iph_ptr)->ip_p, exp->prot);
  Assign8(((struct pm_iphdr *)pptrs->iph_ptr)->ip_tos, exp->tos);
  Assign16(((struct pm_tlhdr *)pptrs->tlh_ptr)->src_port, exp->srcport);
  Assign16(((struct pm_tlhdr *)pptrs->tlh_ptr)->dst_port, exp->dstport);
}
