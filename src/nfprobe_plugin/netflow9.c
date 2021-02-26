/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2021 by Paolo Lucente
*/

/*
 * Originally based on softflowd which is:
 *
 * Copyright 2002 Damien Miller <djm@mindrot.org> All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* $Id$ */

#include "common.h"
#include "treetype.h"
#include "nfprobe_plugin.h"
#include "ip_flow.h"
#include "classifier.h"

/* Netflow v.9 */
struct NF9_HEADER {
	u_int16_t version, flows;
	u_int32_t uptime_ms, time_sec;
	u_int32_t package_sequence, source_id;
} __attribute__ ((packed));
struct IPFIX_HEADER {
        u_int16_t version, len;
        u_int32_t time_sec;
        u_int32_t package_sequence, source_id;
} __attribute__ ((packed));
struct NF9_FLOWSET_HEADER_COMMON {
	u_int16_t flowset_id, length;
} __attribute__ ((packed));
struct NF9_TEMPLATE_FLOWSET_HEADER {
	struct NF9_FLOWSET_HEADER_COMMON c;
	u_int16_t template_id, count;
} __attribute__ ((packed));
struct NF9_OPTIONS_TEMPLATE_FLOWSET_HEADER {
        struct NF9_FLOWSET_HEADER_COMMON c;
        u_int16_t template_id, scope_len;
        u_int16_t option_len;
} __attribute__ ((packed));
struct NF9_TEMPLATE_FLOWSET_RECORD {
	u_int16_t type, length;
} __attribute__ ((packed));
struct IPFIX_PEN_TEMPLATE_FLOWSET_RECORD {
        u_int16_t type;
	u_int16_t length;
        u_int32_t pen;
} __attribute__ ((packed));
struct NF9_DATA_FLOWSET_HEADER {
	struct NF9_FLOWSET_HEADER_COMMON c;
} __attribute__ ((packed));
#define NF9_TEMPLATE_FLOWSET_ID		0
#define NF9_OPTIONS_FLOWSET_ID		1
#define IPFIX_TEMPLATE_FLOWSET_ID	2
#define IPFIX_OPTIONS_FLOWSET_ID	3
#define IPFIX_VLEN_REC_SHORT		1
#define IPFIX_VLEN_REC_LONG		2
#define IPFIX_VLEN_REC_SHORT_MAXLEN	254 /* rfc 5101 says less than 255 octets */
#define NF9_MIN_RECORD_FLOWSET_ID	256

#define PMACCT_PEN			43874
#define IPFIX_PEN_LEN			4
#define IPFIX_TPL_EBIT                  0x8000 /* IPFIX telmplate enterprise bit */
#define IPFIX_VARIABLE_LENGTH		65535
#define NULL_CHAR_LEN			1

/* Flowset record types the we care about */
#define NF9_IN_BYTES			1
#define NF9_IN_PACKETS			2
#define NF9_FLOWS			3
#define NF9_IN_PROTOCOL			4
#define NF9_SRC_TOS                     5
#define NF9_TCP_FLAGS			6
#define NF9_L4_SRC_PORT			7
#define NF9_IPV4_SRC_ADDR		8
#define NF9_SRC_MASK                    9
#define NF9_INPUT_SNMP                  10
/* ... */
#define NF9_L4_DST_PORT			11
#define NF9_IPV4_DST_ADDR		12
#define NF9_DST_MASK                    13
#define NF9_OUTPUT_SNMP                 14
/* ... */
#define NF9_SRC_AS                      16
#define NF9_DST_AS                      17
#define NF9_BGP_IPV4_NEXT_HOP           18
/* ... */
#define NF9_LAST_SWITCHED		21
#define NF9_FIRST_SWITCHED		22
#define NF9_OUT_BYTES                   23
#define NF9_OUT_PACKETS                 24
/* ... */
#define NF9_IPV6_SRC_ADDR		27
#define NF9_IPV6_DST_ADDR		28
#define NF9_IPV6_SRC_MASK               29
#define NF9_IPV6_DST_MASK               30
/* ... */
#define NF9_FLOW_SAMPLER_ID             48
#define NF9_FLOW_SAMPLER_MODE           49
#define NF9_FLOW_SAMPLER_INTERVAL       50
#define NF9_IN_SRC_MAC                  56 //
#define NF9_OUT_DST_MAC                 57
#define NF9_SRC_VLAN                    58
#define NF9_DST_VLAN                    59
#define NF9_IP_PROTOCOL_VERSION		60
#define NF9_DIRECTION                   61
/* ... */
#define NF9_BGP_IPV6_NEXT_HOP           63
/* ... */
#define NF9_MPLS_LABEL_1                70
/* ... */
#define NF9_IN_DST_MAC                  80 //
#define NF9_OUT_SRC_MAC                 81
/* ... */
#define NF9_FLOW_APPLICATION_DESC	94
#define NF9_FLOW_APPLICATION_ID		95
#define NF9_FLOW_APPLICATION_NAME	96
/* ... */
#define NF9_EXPORTER_IPV4_ADDRESS       130
#define NF9_EXPORTER_IPV6_ADDRESS       131
/* ... */
#define NF9_FLOW_EXPORTER		144
/* ... */
#define NF9_FIRST_SWITCHED_MSEC         152
#define NF9_LAST_SWITCHED_MSEC          153
#define NF9_FIRST_SWITCHED_USEC         154
#define NF9_LAST_SWITCHED_USEC          155
/* ... */

/* CUSTOM TYPES START HERE: supported in IPFIX only with pmacct PEN */
#define NF9_CUST_TAG			1
#define NF9_CUST_TAG2			2
#define NF9_CUST_LABEL			3
/* CUSTOM TYPES END HERE */

/* OPTION SCOPES */
#define NF9_OPT_SCOPE_SYSTEM            1

/* Stuff pertaining to the templates that softflowd uses */
#define NF9_SOFTFLOWD_TEMPLATE_NRECORDS	35
struct NF9_SOFTFLOWD_TEMPLATE {
	struct NF9_TEMPLATE_FLOWSET_HEADER h;
	struct NF9_TEMPLATE_FLOWSET_RECORD r[NF9_SOFTFLOWD_TEMPLATE_NRECORDS];
	u_int16_t tot_len;
} __attribute__ ((packed));

struct IPFIX_PEN_TEMPLATE_ADDENDUM {
        struct IPFIX_PEN_TEMPLATE_FLOWSET_RECORD r[NF9_SOFTFLOWD_TEMPLATE_NRECORDS];
        u_int16_t tot_len;
} __attribute__ ((packed));

#define NF9_OPTIONS_TEMPLATE_NRECORDS 4
struct NF9_OPTIONS_TEMPLATE {
        struct NF9_OPTIONS_TEMPLATE_FLOWSET_HEADER h;
        struct NF9_TEMPLATE_FLOWSET_RECORD r[NF9_OPTIONS_TEMPLATE_NRECORDS];
        u_int16_t tot_len;
} __attribute__ ((packed));

typedef int (*flow_to_flowset_handler) (char *, const struct FLOW *, int, int);
struct NF9_INTERNAL_TEMPLATE_RECORD {
  flow_to_flowset_handler handler;
  u_int16_t length;
};

struct NF9_INTERNAL_TEMPLATE {
	struct NF9_INTERNAL_TEMPLATE_RECORD r[NF9_SOFTFLOWD_TEMPLATE_NRECORDS];
	u_int16_t tot_rec_len;
};

struct NF9_INTERNAL_OPTIONS_TEMPLATE {
        struct NF9_INTERNAL_TEMPLATE_RECORD r[NF9_OPTIONS_TEMPLATE_NRECORDS];
        u_int16_t tot_rec_len;
};

/* Local data: templates and counters */
#define NF9_SOFTFLOWD_MAX_PACKET_SIZE	512
#define NF9_SOFTFLOWD_V4_TEMPLATE_ID	1024
#define NF9_SOFTFLOWD_V6_TEMPLATE_ID	2048
#define NF9_OPTIONS_TEMPLATE_ID		4096

#define NF9_DEFAULT_TEMPLATE_INTERVAL	18

static struct NF9_SOFTFLOWD_TEMPLATE v4_template;
static struct IPFIX_PEN_TEMPLATE_ADDENDUM v4_pen_template;
static struct NF9_INTERNAL_TEMPLATE v4_int_template;
static struct NF9_INTERNAL_TEMPLATE v4_pen_int_template;
static struct NF9_SOFTFLOWD_TEMPLATE v4_template_out;
static struct IPFIX_PEN_TEMPLATE_ADDENDUM v4_pen_template_out;
static struct NF9_INTERNAL_TEMPLATE v4_int_template_out;
static struct NF9_INTERNAL_TEMPLATE v4_pen_int_template_out;
static struct NF9_SOFTFLOWD_TEMPLATE v6_template;
static struct IPFIX_PEN_TEMPLATE_ADDENDUM v6_pen_template;
static struct NF9_INTERNAL_TEMPLATE v6_int_template;
static struct NF9_INTERNAL_TEMPLATE v6_pen_int_template;
static struct NF9_SOFTFLOWD_TEMPLATE v6_template_out;
static struct IPFIX_PEN_TEMPLATE_ADDENDUM v6_pen_template_out;
static struct NF9_INTERNAL_TEMPLATE v6_int_template_out;
static struct NF9_INTERNAL_TEMPLATE v6_pen_int_template_out;
static struct NF9_OPTIONS_TEMPLATE sampling_option_template;
static struct NF9_INTERNAL_OPTIONS_TEMPLATE sampling_option_int_template;
static struct NF9_OPTIONS_TEMPLATE class_option_template;
static struct NF9_INTERNAL_OPTIONS_TEMPLATE class_option_int_template;
static struct NF9_OPTIONS_TEMPLATE exporter_option_template;
static struct NF9_INTERNAL_OPTIONS_TEMPLATE exporter_option_int_template;
static char ftoft_buf_0[NF9_SOFTFLOWD_MAX_PACKET_SIZE*2];
static char ftoft_buf_1[NF9_SOFTFLOWD_MAX_PACKET_SIZE*2];
static char packet[NF9_SOFTFLOWD_MAX_PACKET_SIZE];

static int nf9_pkts_until_template = -1;
static u_int8_t send_options = FALSE;
static u_int8_t send_sampling_option = FALSE;
static u_int8_t send_class_option = FALSE;
static u_int8_t send_exporter_option = FALSE;

static int
flow_to_flowset_input_handler(char *flowset, const struct FLOW *flow, int idx, int size)
{
  u_int32_t rec32, tmp32;

  rec32 = flow->ifindex[idx]; 
  tmp32 = htonl(rec32);
  memcpy(flowset, &tmp32, size);

  return 0;
}

static int
flow_to_flowset_output_handler(char *flowset, const struct FLOW *flow, int idx, int size)
{
  u_int32_t rec32, tmp32;

  rec32 = flow->ifindex[idx ^ 1];
  tmp32 = htonl(rec32);
  memcpy(flowset, &tmp32, size);

  return 0;
}

static int
flow_to_flowset_direction_handler(char *flowset, const struct FLOW *flow, int idx, int size)
{
  u_int8_t rec8;

  rec8 = flow->direction[idx] ? (flow->direction[idx]-1) : 0;

  memcpy(flowset, &rec8, size);

  return 0;
}

static int
flow_to_flowset_flows_handler(char *flowset, const struct FLOW *flow, int idx, int size)
{
  u_int32_t rec32;

  rec32 = htonl(flow->flows[idx]);
  memcpy(flowset, &rec32, size);

  return 0;
}

static int
flow_to_flowset_src_host_v4_handler(char *flowset, const struct FLOW *flow, int idx, int size)
{
  memcpy(flowset, &flow->addr[idx].v4, size);

  return 0;
}

static int
flow_to_flowset_dst_host_v4_handler(char *flowset, const struct FLOW *flow, int idx, int size)
{
  memcpy(flowset, &flow->addr[idx ^ 1].v4, size);

  return 0;
}

static int
flow_to_flowset_bgp_next_hop_v4_handler(char *flowset, const struct FLOW *flow, int idx, int size)
{
  memcpy(flowset, &flow->bgp_next_hop[idx].v4, size);

  return 0;
}

static int
flow_to_flowset_src_nmask_handler(char *flowset, const struct FLOW *flow, int idx, int size)
{
  memcpy(flowset, &flow->mask[idx], size);

  return 0;
}

static int
flow_to_flowset_dst_nmask_handler(char *flowset, const struct FLOW *flow, int idx, int size)
{
  memcpy(flowset, &flow->mask[idx ^ 1], size);

  return 0;
}

static int
flow_to_flowset_src_host_v6_handler(char *flowset, const struct FLOW *flow, int idx, int size)
{
  memcpy(flowset, &flow->addr[idx].v6, size);

  return 0;
}

static int
flow_to_flowset_dst_host_v6_handler(char *flowset, const struct FLOW *flow, int idx, int size)
{
  memcpy(flowset, &flow->addr[idx ^ 1].v6, size);

  return 0;
}

static int
flow_to_flowset_bgp_next_hop_v6_handler(char *flowset, const struct FLOW *flow, int idx, int size)
{
  memcpy(flowset, &flow->bgp_next_hop[idx].v6, size);

  return 0;
}

static int
flow_to_flowset_src_port_handler(char *flowset, const struct FLOW *flow, int idx, int size)
{
  memcpy(flowset, &flow->port[idx], size);

  return 0;
}

static int
flow_to_flowset_dst_port_handler(char *flowset, const struct FLOW *flow, int idx, int size)
{
  memcpy(flowset, &flow->port[idx ^ 1], size);

  return 0;
}

static int
flow_to_flowset_ip_tos_handler(char *flowset, const struct FLOW *flow, int idx, int size)
{
  memcpy(flowset, &flow->tos[idx], size);

  return 0;
}

static int
flow_to_flowset_tcp_flags_handler(char *flowset, const struct FLOW *flow, int idx, int size)
{
  memcpy(flowset, &flow->tcp_flags[idx], size);

  return 0;
}

static int
flow_to_flowset_ip_proto_handler(char *flowset, const struct FLOW *flow, int idx, int size)
{
  memcpy(flowset, &flow->protocol, size);

  return 0;
}

static int
flow_to_flowset_src_as_handler(char *flowset, const struct FLOW *flow, int idx, int size)
{
  memcpy(flowset, &flow->as[idx], size);

  return 0;
}

static int
flow_to_flowset_dst_as_handler(char *flowset, const struct FLOW *flow, int idx, int size)
{
  memcpy(flowset, &flow->as[idx ^ 1], size);

  return 0;
}

static int
flow_to_flowset_src_mac_handler(char *flowset, const struct FLOW *flow, int idx, int size)
{
  memcpy(flowset, &flow->mac[idx], size);

  return 0;
}

static int
flow_to_flowset_dst_mac_handler(char *flowset, const struct FLOW *flow, int idx, int size)
{
  memcpy(flowset, &flow->mac[idx ^ 1], size);

  return 0;
}

static int
flow_to_flowset_vlan_handler(char *flowset, const struct FLOW *flow, int idx, int size)
{
  memcpy(flowset, &flow->vlan, size);

  return 0;
}

static int
flow_to_flowset_mpls_label_top_handler(char *flowset, const struct FLOW *flow, int idx, int size)
{
  encode_mpls_label(flowset, flow->mpls_label[idx]);
  // memcpy(flowset, &flow->mpls_label[idx], size);

  return 0;
}

static int
flow_to_flowset_class_handler(char *flowset, const struct FLOW *flow, int idx, int size)
{
  memcpy(flowset, &flow->class, size);

  return 0;
}

#if defined (WITH_NDPI)
static int
flow_to_flowset_ndpi_class_handler(char *flowset, const struct FLOW *flow, int idx, int size)
{
  u_int8_t ie95_classId = 0x16; /* nDPI */
  u_int32_t ie95_selectId = htonl(flow->ndpi_class.app_protocol);

  if (size == 5) {
    memcpy(flowset, &ie95_classId, 1);
    memcpy((flowset + 1), &ie95_selectId, 4);
  }

  return 0;
}
#endif

static int
flow_to_flowset_tag_handler(char *flowset, const struct FLOW *flow, int idx, int size)
{
  pm_id_t tag;

  tag = pm_htonll(flow->tag[idx]);
  memcpy(flowset, &tag, size);

  return 0;
}

static int
flow_to_flowset_tag2_handler(char *flowset, const struct FLOW *flow, int idx, int size)
{
  pm_id_t tag;

  tag = pm_htonll(flow->tag2[idx]);
  memcpy(flowset, &tag, size);

  return 0;
}

static int
flow_to_flowset_label_handler(char *flowset, const struct FLOW *flow, int idx, int size)
{
  char null_char = '\0', *label_ptr = NULL;
  int add_len = IPFIX_VLEN_REC_SHORT;
  u_int8_t len = 0;

  vlen_prims_get(flow->pvlen[idx], COUNT_INT_LABEL, &label_ptr);
  if (!label_ptr) {
    len = NULL_CHAR_LEN;
    label_ptr = &null_char;
  }
  else len = MIN(IPFIX_VLEN_REC_SHORT_MAXLEN, strlen(label_ptr) + 1); // XXX: check available len?

  add_len += len;
  memcpy(flowset, &len, IPFIX_VLEN_REC_SHORT); 
  flowset += IPFIX_VLEN_REC_SHORT;
  memcpy(flowset, label_ptr, len); 
  flowset[len] = '\0';

  return add_len;
}

static int
flow_to_flowset_sampler_id_handler(char *flowset, const struct FLOW *flow, int idx, int size)
{
  u_int8_t rec8;

  rec8 = 1;
  memcpy(flowset, &rec8, size);

  return 0;
}

static int
flow_to_flowset_cp_handler(char *flowset, const struct FLOW *flow, int idx, int size)
{
  struct custom_primitive_ptrs *cp_entry;
  char *label_ptr, null_char = '\0';
  int cp_idx, add_len = 0;
  u_int8_t len = 0;

  for (cp_idx = 0; cp_idx < config.cpptrs.num; cp_idx++) {
    cp_entry = &config.cpptrs.primitive[cp_idx];

    if (!cp_entry->ptr->pen) {
      if (cp_entry->ptr->len != PM_VARIABLE_LENGTH) {
        if (flow->pcust[idx] && cp_entry->ptr->field_type) {
          if (cp_entry->ptr->semantics == CUSTOM_PRIMITIVE_TYPE_RAW) {
            serialize_bin((flow->pcust[idx] + cp_entry->off), (u_char *)flowset, strlen((char *)(flow->pcust[idx] + cp_entry->off)));
          }
          else {
	    memcpy(flowset, (flow->pcust[idx] + cp_entry->off), cp_entry->ptr->len);
	  }
	}
        else {
          memset(flowset, 0, cp_entry->ptr->len);
	}

        flowset += cp_entry->ptr->len;
      }
      else {
	if (config.nfprobe_version == 10) {
          vlen_prims_get(flow->pvlen[idx], cp_entry->ptr->type, &label_ptr);
          if (!label_ptr) {
	    len = NULL_CHAR_LEN;
	    label_ptr = &null_char;
          }
          else len = MIN(IPFIX_VLEN_REC_SHORT_MAXLEN, strlen(label_ptr) + 1); // XXX: check available len?

          memcpy(flowset, &len, IPFIX_VLEN_REC_SHORT);
          flowset += IPFIX_VLEN_REC_SHORT;
          add_len += IPFIX_VLEN_REC_SHORT;

          memcpy(flowset, label_ptr, len);
          flowset[len] = '\0';
          flowset += len;
          add_len += len;
	}
      }
    }
  }

  return add_len;
}

static int
flow_to_flowset_cp_pen_handler(char *flowset, const struct FLOW *flow, int idx, int size)
{
  struct custom_primitive_ptrs *cp_entry;
  char *label_ptr, null_char = '\0';
  int cp_idx, add_len = 0;
  u_int8_t len = 0;

  for (cp_idx = 0; cp_idx < config.cpptrs.num; cp_idx++) {
    cp_entry = &config.cpptrs.primitive[cp_idx];

    if (config.nfprobe_version == 10 && cp_entry->ptr->pen) {
      if (cp_entry->ptr->len != PM_VARIABLE_LENGTH) {
        if (flow->pcust[idx] && cp_entry->ptr->field_type) {
	  if (cp_entry->ptr->semantics == CUSTOM_PRIMITIVE_TYPE_RAW) {
	    serialize_bin((flow->pcust[idx] + cp_entry->off), (u_char *)flowset, strlen((char *)(flow->pcust[idx] + cp_entry->off)));
	  }
          else {
	    memcpy(flowset, (flow->pcust[idx] + cp_entry->off), cp_entry->ptr->len);
	  }
	}
        else {
          memset(flowset, 0, cp_entry->ptr->len);
	}

        flowset += cp_entry->ptr->len;
      }
      else {
        vlen_prims_get(flow->pvlen[idx], cp_entry->ptr->type, &label_ptr);
        if (!label_ptr) {
          len = NULL_CHAR_LEN;
          label_ptr = &null_char;
        }
        else len = MIN(IPFIX_VLEN_REC_SHORT_MAXLEN, strlen(label_ptr) + 1); // XXX: check available len?

        memcpy(flowset, &len, IPFIX_VLEN_REC_SHORT);
        flowset += IPFIX_VLEN_REC_SHORT;
        add_len += IPFIX_VLEN_REC_SHORT;

        memcpy(flowset, label_ptr, len);
        flowset[len] = '\0';
        flowset += len;
        add_len += len;
      }
    }
  }

  return add_len;
}

int nf9_init_cp_template(struct NF9_SOFTFLOWD_TEMPLATE *tpl, struct NF9_SOFTFLOWD_TEMPLATE *tpl_out,
			 struct NF9_INTERNAL_TEMPLATE *tpl_int, struct NF9_INTERNAL_TEMPLATE *tpl_int_out,
			 int rcount)
{
  struct NF9_INTERNAL_TEMPLATE_RECORD *cp_first_record = NULL, *cp_first_record_out = NULL;
  struct custom_primitive_ptrs *cp_entry;
  int cp_idx, cp_first = FALSE, cp_len = 0;

  for (cp_idx = 0; cp_idx < config.cpptrs.num; cp_idx++) {
    cp_entry = &config.cpptrs.primitive[cp_idx];

    if (cp_entry->ptr->field_type) {
      if (!cp_entry->ptr->pen) {
	if (cp_entry->ptr->len != PM_VARIABLE_LENGTH || config.nfprobe_version == 10) { 
	  tpl->r[rcount].type = htons(cp_entry->ptr->field_type);
	  tpl->r[rcount].length = htons(cp_entry->ptr->len);
	  tpl_int->r[rcount].length = 0;
	  tpl_out->r[rcount].type = htons(cp_entry->ptr->field_type);
	  tpl_out->r[rcount].length = htons(cp_entry->ptr->len);
	  tpl_int_out->r[rcount].length = 0;
	  cp_len += cp_entry->ptr->len;

	  if (!cp_first) {
	    tpl_int->r[rcount].handler = flow_to_flowset_cp_handler;
	    tpl_int_out->r[rcount].handler = flow_to_flowset_cp_handler;

	    cp_first_record = &tpl_int->r[rcount];
	    cp_first_record_out = &tpl_int_out->r[rcount];
	    cp_first = TRUE;
	  }
	  else {
	    tpl_int->r[rcount].handler = NULL;
	    tpl_int_out->r[rcount].handler = NULL;
	  }

	  rcount++;
        }
      }
    }
  }

  if (cp_first_record) cp_first_record->length = cp_len;
  if (cp_first_record_out) cp_first_record_out->length = cp_len;

  return rcount; 
}

int nf9_init_cp_pen_template(struct IPFIX_PEN_TEMPLATE_ADDENDUM *tpl, struct IPFIX_PEN_TEMPLATE_ADDENDUM *tpl_out,
			     struct NF9_INTERNAL_TEMPLATE *tpl_int, struct NF9_INTERNAL_TEMPLATE *tpl_int_out,
			     int rcount_pen)
{
  struct NF9_INTERNAL_TEMPLATE_RECORD *cp_pen_first_record = NULL, *cp_pen_first_record_out = NULL;
  struct custom_primitive_ptrs *cp_entry;
  int cp_idx, cp_pen_first = FALSE, cp_pen_len = 0;

  for (cp_idx = 0; cp_idx < config.cpptrs.num; cp_idx++) {
    cp_entry = &config.cpptrs.primitive[cp_idx];

    if (config.nfprobe_version == 10 && cp_entry->ptr->pen) {
      tpl->r[rcount_pen].type = htons(IPFIX_TPL_EBIT | cp_entry->ptr->field_type);
      tpl->r[rcount_pen].pen = htonl(cp_entry->ptr->pen);
      tpl->r[rcount_pen].length = htons(cp_entry->ptr->len);
      tpl_int->r[rcount_pen].length = 0;
      tpl_out->r[rcount_pen].type = htons(IPFIX_TPL_EBIT | cp_entry->ptr->field_type);
      tpl_out->r[rcount_pen].pen = htonl(cp_entry->ptr->pen);
      tpl_out->r[rcount_pen].length = htons(cp_entry->ptr->len);
      tpl_int_out->r[rcount_pen].length = 0;
      cp_pen_len += cp_entry->ptr->len;

      if (!cp_pen_first) {
        tpl_int->r[rcount_pen].handler = flow_to_flowset_cp_pen_handler;
        tpl_int_out->r[rcount_pen].handler = flow_to_flowset_cp_pen_handler;

        cp_pen_first_record = &tpl_int->r[rcount_pen];
        cp_pen_first_record_out = &tpl_int_out->r[rcount_pen];
        cp_pen_first = TRUE;
      }
      else {
        tpl_int->r[rcount_pen].handler = NULL;
        tpl_int_out->r[rcount_pen].handler = NULL;
      }

      rcount_pen++;
    }
  }

  if (cp_pen_first_record) cp_pen_first_record->length = cp_pen_len;
  if (cp_pen_first_record_out) cp_pen_first_record_out->length = cp_pen_len;

  return rcount_pen; 
}

static void
nf9_init_template(void)
{
	int rcount, rcount_pen, idx, flowset_id = 0; 

	/* Let's enforce some defaults; if we are launched without an
	 * aggregation, then let's choose one. If we don't have one or
	 * more flow-distinguishing primitives, then let's add flow
	 * aggregation info to the template */
	if (!config.nfprobe_what_to_count && !config.nfprobe_what_to_count_2) {
	  config.nfprobe_what_to_count |= COUNT_SRC_HOST;
	  config.nfprobe_what_to_count |= COUNT_DST_HOST;
	  config.nfprobe_what_to_count |= COUNT_SRC_PORT;
	  config.nfprobe_what_to_count |= COUNT_DST_PORT;
	  config.nfprobe_what_to_count |= COUNT_IP_PROTO;
	  config.nfprobe_what_to_count |= COUNT_IP_TOS;
	}
	
	rcount = 0; rcount_pen = 0;
	bzero(&v4_template, sizeof(v4_template));
	bzero(&v4_int_template, sizeof(v4_int_template));
	bzero(&v4_pen_template, sizeof(v4_pen_template));
	bzero(&v4_pen_int_template, sizeof(v4_pen_int_template));
	bzero(&v4_template_out, sizeof(v4_template_out));
	bzero(&v4_int_template_out, sizeof(v4_int_template_out));
	bzero(&v4_pen_template_out, sizeof(v4_pen_template_out));
	bzero(&v4_pen_int_template_out, sizeof(v4_pen_int_template_out));

	if (config.nfprobe_version == 9) flowset_id = NF9_TEMPLATE_FLOWSET_ID;
	else if (config.nfprobe_version == 10) flowset_id = IPFIX_TEMPLATE_FLOWSET_ID;

	if (config.nfprobe_version == 9 && config.timestamps_secs) {
	  v4_template.r[rcount].type = htons(NF9_LAST_SWITCHED);
	  v4_template.r[rcount].length = htons(4);
	  v4_int_template.r[rcount].length = 4;
	  v4_template_out.r[rcount].type = htons(NF9_LAST_SWITCHED);
	  v4_template_out.r[rcount].length = htons(4);
	  v4_int_template_out.r[rcount].length = 4;
	  rcount++;
	  v4_template.r[rcount].type = htons(NF9_FIRST_SWITCHED);
	  v4_template.r[rcount].length = htons(4);
	  v4_int_template.r[rcount].length = 4;
          v4_template_out.r[rcount].type = htons(NF9_FIRST_SWITCHED);
          v4_template_out.r[rcount].length = htons(4);
          v4_int_template_out.r[rcount].length = 4;
	  rcount++;
	}
	else if ((config.nfprobe_version == 9 && !config.timestamps_secs) || config.nfprobe_version == 10) {
	  if (!config.nfprobe_tstamp_usec) {
	    v4_template.r[rcount].type = htons(NF9_LAST_SWITCHED_MSEC);
	    v4_template.r[rcount].length = htons(8);
	    v4_int_template.r[rcount].length = 8;
	    v4_template_out.r[rcount].type = htons(NF9_LAST_SWITCHED_MSEC);
	    v4_template_out.r[rcount].length = htons(8);
	    v4_int_template_out.r[rcount].length = 8;
	    rcount++;
	    v4_template.r[rcount].type = htons(NF9_FIRST_SWITCHED_MSEC);
	    v4_template.r[rcount].length = htons(8);
	    v4_int_template.r[rcount].length = 8;
	    v4_template_out.r[rcount].type = htons(NF9_FIRST_SWITCHED_MSEC);
	    v4_template_out.r[rcount].length = htons(8);
	    v4_int_template_out.r[rcount].length = 8;
	    rcount++;
	  }
	  else {
	    v4_template.r[rcount].type = htons(NF9_LAST_SWITCHED_USEC);
	    v4_template.r[rcount].length = htons(16);
	    v4_int_template.r[rcount].length = 16;
	    v4_template_out.r[rcount].type = htons(NF9_LAST_SWITCHED_USEC);
	    v4_template_out.r[rcount].length = htons(16);
	    v4_int_template_out.r[rcount].length = 16;
	    rcount++;
	    v4_template.r[rcount].type = htons(NF9_FIRST_SWITCHED_USEC);
	    v4_template.r[rcount].length = htons(16);
	    v4_int_template.r[rcount].length = 16;
	    v4_template_out.r[rcount].type = htons(NF9_FIRST_SWITCHED_USEC);
	    v4_template_out.r[rcount].length = htons(16);
	    v4_int_template_out.r[rcount].length = 16;
	    rcount++;
	  }
	}
        v4_template.r[rcount].type = htons(NF9_IN_BYTES);
        v4_template.r[rcount].length = htons(8);
        v4_int_template.r[rcount].length = 8;
        v4_template_out.r[rcount].type = htons(NF9_IN_BYTES);
        v4_template_out.r[rcount].length = htons(8);
        v4_int_template_out.r[rcount].length = 8;
        rcount++;
        v4_template.r[rcount].type = htons(NF9_IN_PACKETS);
        v4_template.r[rcount].length = htons(8);
        v4_int_template.r[rcount].length = 8;
        v4_template_out.r[rcount].type = htons(NF9_IN_PACKETS);
        v4_template_out.r[rcount].length = htons(8);
        v4_int_template_out.r[rcount].length = 8;
        rcount++;
	v4_template.r[rcount].type = htons(NF9_IP_PROTOCOL_VERSION);
	v4_template.r[rcount].length = htons(1);
	v4_int_template.r[rcount].length = 1;
        v4_template_out.r[rcount].type = htons(NF9_IP_PROTOCOL_VERSION);
        v4_template_out.r[rcount].length = htons(1);
        v4_int_template_out.r[rcount].length = 1;
	rcount++;
        v4_template.r[rcount].type = htons(NF9_INPUT_SNMP);
        v4_template.r[rcount].length = htons(4);
	v4_int_template.r[rcount].handler = flow_to_flowset_input_handler;
        v4_int_template.r[rcount].length = 4;
        v4_template_out.r[rcount].type = htons(NF9_INPUT_SNMP);
        v4_template_out.r[rcount].length = htons(4);
        v4_int_template_out.r[rcount].handler = flow_to_flowset_input_handler;
        v4_int_template_out.r[rcount].length = 4;
        rcount++;
        v4_template.r[rcount].type = htons(NF9_OUTPUT_SNMP);
        v4_template.r[rcount].length = htons(4);
	v4_int_template.r[rcount].handler = flow_to_flowset_output_handler;
        v4_int_template.r[rcount].length = 4;
        v4_template_out.r[rcount].type = htons(NF9_OUTPUT_SNMP);
        v4_template_out.r[rcount].length = htons(4);
        v4_int_template_out.r[rcount].handler = flow_to_flowset_output_handler;
        v4_int_template_out.r[rcount].length = 4;
        rcount++;
        v4_template.r[rcount].type = htons(NF9_DIRECTION);
        v4_template.r[rcount].length = htons(1);
        v4_int_template.r[rcount].handler = flow_to_flowset_direction_handler;
        v4_int_template.r[rcount].length = 1;
        v4_template_out.r[rcount].type = htons(NF9_DIRECTION);
        v4_template_out.r[rcount].length = htons(1);
        v4_int_template_out.r[rcount].handler = flow_to_flowset_direction_handler;
        v4_int_template_out.r[rcount].length = 1;
        rcount++;
	if (config.nfprobe_what_to_count & COUNT_FLOWS) { 
	  v4_template.r[rcount].type = htons(NF9_FLOWS);
	  v4_template.r[rcount].length = htons(4);
	  v4_int_template.r[rcount].handler = flow_to_flowset_flows_handler;
	  v4_int_template.r[rcount].length = 4;
          v4_template_out.r[rcount].type = htons(NF9_FLOWS);
          v4_template_out.r[rcount].length = htons(4);
          v4_int_template_out.r[rcount].handler = flow_to_flowset_flows_handler;
          v4_int_template_out.r[rcount].length = 4;
	  rcount++;
	}
	if (config.nfprobe_what_to_count & COUNT_SRC_HOST) { 
	  v4_template.r[rcount].type = htons(NF9_IPV4_SRC_ADDR);
	  v4_template.r[rcount].length = htons(4);
	  v4_int_template.r[rcount].handler = flow_to_flowset_src_host_v4_handler;
	  v4_int_template.r[rcount].length = 4;
          v4_template_out.r[rcount].type = htons(NF9_IPV4_SRC_ADDR);
          v4_template_out.r[rcount].length = htons(4);
          v4_int_template_out.r[rcount].handler = flow_to_flowset_src_host_v4_handler;
          v4_int_template_out.r[rcount].length = 4;
	  rcount++;
	}
	if (config.nfprobe_what_to_count & COUNT_DST_HOST) {
	  v4_template.r[rcount].type = htons(NF9_IPV4_DST_ADDR);
	  v4_template.r[rcount].length = htons(4);
	  v4_int_template.r[rcount].handler = flow_to_flowset_dst_host_v4_handler;
	  v4_int_template.r[rcount].length = 4;
          v4_template_out.r[rcount].type = htons(NF9_IPV4_DST_ADDR);
          v4_template_out.r[rcount].length = htons(4);
          v4_int_template_out.r[rcount].handler = flow_to_flowset_dst_host_v4_handler;
          v4_int_template_out.r[rcount].length = 4;
	  rcount++;
	}
        if (config.nfprobe_what_to_count & COUNT_PEER_DST_IP) {
          v4_template.r[rcount].type = htons(NF9_BGP_IPV4_NEXT_HOP);
          v4_template.r[rcount].length = htons(4);
          v4_int_template.r[rcount].handler = flow_to_flowset_bgp_next_hop_v4_handler;
          v4_int_template.r[rcount].length = 4;
          v4_template_out.r[rcount].type = htons(NF9_BGP_IPV4_NEXT_HOP);
          v4_template_out.r[rcount].length = htons(4);
          v4_int_template_out.r[rcount].handler = flow_to_flowset_bgp_next_hop_v4_handler;
          v4_int_template_out.r[rcount].length = 4;
          rcount++;
        }
        if (config.nfprobe_what_to_count & COUNT_SRC_NMASK) {
          v4_template.r[rcount].type = htons(NF9_SRC_MASK);
          v4_template.r[rcount].length = htons(1);
          v4_int_template.r[rcount].handler = flow_to_flowset_src_nmask_handler;
          v4_int_template.r[rcount].length = 1;
          v4_template_out.r[rcount].type = htons(NF9_SRC_MASK);
          v4_template_out.r[rcount].length = htons(1);
          v4_int_template_out.r[rcount].handler = flow_to_flowset_src_nmask_handler;
          v4_int_template_out.r[rcount].length = 1;
          rcount++;
        }
        if (config.nfprobe_what_to_count & COUNT_DST_NMASK) {
          v4_template.r[rcount].type = htons(NF9_DST_MASK);
          v4_template.r[rcount].length = htons(1);
          v4_int_template.r[rcount].handler = flow_to_flowset_dst_nmask_handler;
          v4_int_template.r[rcount].length = 1;
          v4_template_out.r[rcount].type = htons(NF9_DST_MASK);
          v4_template_out.r[rcount].length = htons(1);
          v4_int_template_out.r[rcount].handler = flow_to_flowset_dst_nmask_handler;
          v4_int_template_out.r[rcount].length = 1;
          rcount++;
        }
	if (config.nfprobe_what_to_count & COUNT_SRC_PORT) {
	  v4_template.r[rcount].type = htons(NF9_L4_SRC_PORT);
	  v4_template.r[rcount].length = htons(2);
	  v4_int_template.r[rcount].handler = flow_to_flowset_src_port_handler;
	  v4_int_template.r[rcount].length = 2;
          v4_template_out.r[rcount].type = htons(NF9_L4_SRC_PORT);
          v4_template_out.r[rcount].length = htons(2);
          v4_int_template_out.r[rcount].handler = flow_to_flowset_src_port_handler;
          v4_int_template_out.r[rcount].length = 2;
	  rcount++;
	}
	if (config.nfprobe_what_to_count & COUNT_DST_PORT) {
	  v4_template.r[rcount].type = htons(NF9_L4_DST_PORT);
	  v4_template.r[rcount].length = htons(2);
	  v4_int_template.r[rcount].handler = flow_to_flowset_dst_port_handler;
	  v4_int_template.r[rcount].length = 2;
          v4_template_out.r[rcount].type = htons(NF9_L4_DST_PORT);
          v4_template_out.r[rcount].length = htons(2);
          v4_int_template_out.r[rcount].handler = flow_to_flowset_dst_port_handler;
          v4_int_template_out.r[rcount].length = 2;
	  rcount++;
	}
	if (config.nfprobe_what_to_count & (COUNT_IP_TOS)) {
	  v4_template.r[rcount].type = htons(NF9_SRC_TOS);
	  v4_template.r[rcount].length = htons(1);
	  v4_int_template.r[rcount].handler = flow_to_flowset_ip_tos_handler;
	  v4_int_template.r[rcount].length = 1;
          v4_template_out.r[rcount].type = htons(NF9_SRC_TOS);
          v4_template_out.r[rcount].length = htons(1);
          v4_int_template_out.r[rcount].handler = flow_to_flowset_ip_tos_handler;
          v4_int_template_out.r[rcount].length = 1;
	  rcount++;
	}
	if (config.nfprobe_what_to_count & (COUNT_SRC_PORT|COUNT_DST_PORT)) {
	  v4_template.r[rcount].type = htons(NF9_TCP_FLAGS);
	  v4_template.r[rcount].length = htons(1);
	  v4_int_template.r[rcount].handler = flow_to_flowset_tcp_flags_handler;
	  v4_int_template.r[rcount].length = 1;
          v4_template_out.r[rcount].type = htons(NF9_TCP_FLAGS);
          v4_template_out.r[rcount].length = htons(1);
          v4_int_template_out.r[rcount].handler = flow_to_flowset_tcp_flags_handler;
          v4_int_template_out.r[rcount].length = 1;
	  rcount++;
	}
	if (config.nfprobe_what_to_count & COUNT_IP_PROTO) {
	  v4_template.r[rcount].type = htons(NF9_IN_PROTOCOL);
	  v4_template.r[rcount].length = htons(1);
	  v4_int_template.r[rcount].handler = flow_to_flowset_ip_proto_handler;
	  v4_int_template.r[rcount].length = 1;
          v4_template_out.r[rcount].type = htons(NF9_IN_PROTOCOL);
          v4_template_out.r[rcount].length = htons(1);
          v4_int_template_out.r[rcount].handler = flow_to_flowset_ip_proto_handler;
          v4_int_template_out.r[rcount].length = 1;
	  rcount++;
	}
	if (config.nfprobe_what_to_count & COUNT_SRC_AS) {
	  v4_template.r[rcount].type = htons(NF9_SRC_AS);
	  v4_template.r[rcount].length = htons(4);
	  v4_int_template.r[rcount].handler = flow_to_flowset_src_as_handler;
	  v4_int_template.r[rcount].length = 4;
          v4_template_out.r[rcount].type = htons(NF9_SRC_AS);
          v4_template_out.r[rcount].length = htons(4);
          v4_int_template_out.r[rcount].handler = flow_to_flowset_src_as_handler;
          v4_int_template_out.r[rcount].length = 4;
	  rcount++;
	}
	if (config.nfprobe_what_to_count & COUNT_DST_AS) {
	  v4_template.r[rcount].type = htons(NF9_DST_AS);
	  v4_template.r[rcount].length = htons(4);
	  v4_int_template.r[rcount].handler = flow_to_flowset_dst_as_handler;
	  v4_int_template.r[rcount].length = 4;
          v4_template_out.r[rcount].type = htons(NF9_DST_AS);
          v4_template_out.r[rcount].length = htons(4);
          v4_int_template_out.r[rcount].handler = flow_to_flowset_dst_as_handler;
          v4_int_template_out.r[rcount].length = 4;
	  rcount++;
	}
	if (config.nfprobe_what_to_count & COUNT_SRC_MAC) {
	  v4_template.r[rcount].type = htons(NF9_IN_SRC_MAC);
	  v4_template.r[rcount].length = htons(6);
	  v4_int_template.r[rcount].handler = flow_to_flowset_src_mac_handler;
	  v4_int_template.r[rcount].length = 6;
          v4_template_out.r[rcount].type = htons(NF9_OUT_SRC_MAC);
          v4_template_out.r[rcount].length = htons(6);
          v4_int_template_out.r[rcount].handler = flow_to_flowset_src_mac_handler;
          v4_int_template_out.r[rcount].length = 6;
	  rcount++;
	}
	if (config.nfprobe_what_to_count & COUNT_DST_MAC) {
	  v4_template.r[rcount].type = htons(NF9_IN_DST_MAC);
	  v4_template.r[rcount].length = htons(6);
	  v4_int_template.r[rcount].handler = flow_to_flowset_dst_mac_handler;
	  v4_int_template.r[rcount].length = 6;
          v4_template_out.r[rcount].type = htons(NF9_OUT_DST_MAC);
          v4_template_out.r[rcount].length = htons(6);
          v4_int_template_out.r[rcount].handler = flow_to_flowset_dst_mac_handler;
          v4_int_template_out.r[rcount].length = 6;
	  rcount++;
	}
	if (config.nfprobe_what_to_count & COUNT_VLAN) {
	  v4_template.r[rcount].type = htons(NF9_SRC_VLAN);
	  v4_template.r[rcount].length = htons(2);
	  v4_int_template.r[rcount].handler = flow_to_flowset_vlan_handler;
	  v4_int_template.r[rcount].length = 2;
          v4_template_out.r[rcount].type = htons(NF9_DST_VLAN);
          v4_template_out.r[rcount].length = htons(2);
          v4_int_template_out.r[rcount].handler = flow_to_flowset_vlan_handler;
          v4_int_template_out.r[rcount].length = 2;
	  rcount++;
	}
        if (config.nfprobe_what_to_count_2 & COUNT_MPLS_LABEL_TOP) {
          v4_template.r[rcount].type = htons(NF9_MPLS_LABEL_1);
          v4_template.r[rcount].length = htons(3);
          v4_int_template.r[rcount].handler = flow_to_flowset_mpls_label_top_handler;
          v4_int_template.r[rcount].length = 3;
          v4_template_out.r[rcount].type = htons(NF9_MPLS_LABEL_1);
          v4_template_out.r[rcount].length = htons(3);
          v4_int_template_out.r[rcount].handler = flow_to_flowset_mpls_label_top_handler;
          v4_int_template_out.r[rcount].length = 3;
          rcount++;
        }
	if (config.nfprobe_version == 10 && config.nfprobe_what_to_count & COUNT_TAG) {
	  int rlen = sizeof(pm_id_t);

	  v4_pen_template.r[rcount_pen].type = htons(IPFIX_TPL_EBIT | NF9_CUST_TAG);
	  v4_pen_template.r[rcount_pen].pen = htonl(PMACCT_PEN);
	  v4_pen_template.r[rcount_pen].length = htons(rlen);
	  v4_pen_int_template.r[rcount_pen].handler = flow_to_flowset_tag_handler;
	  v4_pen_int_template.r[rcount_pen].length = rlen;
          v4_pen_template_out.r[rcount_pen].type = htons(IPFIX_TPL_EBIT | NF9_CUST_TAG);
	  v4_pen_template_out.r[rcount_pen].pen = htonl(PMACCT_PEN);
          v4_pen_template_out.r[rcount_pen].length = htons(rlen);
          v4_pen_int_template_out.r[rcount_pen].handler = flow_to_flowset_tag_handler;
          v4_pen_int_template_out.r[rcount_pen].length = rlen;
	  rcount_pen++;
	}
        if (config.nfprobe_version == 10 && config.nfprobe_what_to_count & COUNT_TAG2) {
	  int rlen = sizeof(pm_id_t);

          v4_pen_template.r[rcount_pen].type = htons(IPFIX_TPL_EBIT | NF9_CUST_TAG2);
	  v4_pen_template.r[rcount_pen].pen = htonl(PMACCT_PEN);
          v4_pen_template.r[rcount_pen].length = htons(rlen);
          v4_pen_int_template.r[rcount_pen].handler = flow_to_flowset_tag2_handler;
          v4_pen_int_template.r[rcount_pen].length = rlen;
          v4_pen_template_out.r[rcount_pen].type = htons(IPFIX_TPL_EBIT | NF9_CUST_TAG2);
          v4_pen_template_out.r[rcount_pen].pen = htonl(PMACCT_PEN);
          v4_pen_template_out.r[rcount_pen].length = htons(rlen);
          v4_pen_int_template_out.r[rcount_pen].handler = flow_to_flowset_tag2_handler;
          v4_pen_int_template_out.r[rcount_pen].length = rlen;
          rcount_pen++;
        }
        if (config.nfprobe_version == 10 && config.nfprobe_what_to_count_2 & COUNT_LABEL) {
          v4_pen_template.r[rcount_pen].type = htons(IPFIX_TPL_EBIT | NF9_CUST_LABEL);
          v4_pen_template.r[rcount_pen].pen = htonl(PMACCT_PEN);
          v4_pen_template.r[rcount_pen].length = htons(IPFIX_VARIABLE_LENGTH);
          v4_pen_int_template.r[rcount_pen].handler = flow_to_flowset_label_handler;
          v4_pen_int_template.r[rcount_pen].length = IPFIX_VARIABLE_LENGTH;
          v4_pen_template_out.r[rcount_pen].type = htons(IPFIX_TPL_EBIT | NF9_CUST_LABEL);
          v4_pen_template_out.r[rcount_pen].pen = htonl(PMACCT_PEN);
          v4_pen_template_out.r[rcount_pen].length = htons(IPFIX_VARIABLE_LENGTH);
          v4_pen_int_template_out.r[rcount_pen].handler = flow_to_flowset_label_handler;
          v4_pen_int_template_out.r[rcount_pen].length = IPFIX_VARIABLE_LENGTH;
          rcount_pen++;
        }
        if (config.sampling_rate || config.ext_sampling_rate) {
          v4_template.r[rcount].type = htons(NF9_FLOW_SAMPLER_ID);
          v4_template.r[rcount].length = htons(1);
          v4_int_template.r[rcount].handler = flow_to_flowset_sampler_id_handler;
          v4_int_template.r[rcount].length = 1;
          v4_template_out.r[rcount].type = htons(NF9_FLOW_SAMPLER_ID);
          v4_template_out.r[rcount].length = htons(1);
          v4_int_template_out.r[rcount].handler = flow_to_flowset_sampler_id_handler;
          v4_int_template_out.r[rcount].length = 1;
          rcount++;
        }
        if (config.nfprobe_what_to_count & COUNT_CLASS) {
          v4_template.r[rcount].type = htons(NF9_FLOW_APPLICATION_ID);
          v4_template.r[rcount].length = htons(4);
          v4_int_template.r[rcount].handler = flow_to_flowset_class_handler;
          v4_int_template.r[rcount].length = 4;
          v4_template_out.r[rcount].type = htons(NF9_FLOW_APPLICATION_ID);
          v4_template_out.r[rcount].length = htons(4);
          v4_int_template_out.r[rcount].handler = flow_to_flowset_class_handler;
          v4_int_template_out.r[rcount].length = 4;
          rcount++;
        }
#if defined (WITH_NDPI)
	if (config.nfprobe_what_to_count_2 & COUNT_NDPI_CLASS) { 
	  v4_template.r[rcount].type = htons(NF9_FLOW_APPLICATION_ID);
	  v4_template.r[rcount].length = htons(5);
	  v4_int_template.r[rcount].handler = flow_to_flowset_ndpi_class_handler;
	  v4_int_template.r[rcount].length = 5;
	  v4_template_out.r[rcount].type = htons(NF9_FLOW_APPLICATION_ID);
	  v4_template_out.r[rcount].length = htons(5);
	  v4_int_template_out.r[rcount].handler = flow_to_flowset_ndpi_class_handler;
	  v4_int_template_out.r[rcount].length = 5;
	  rcount++;
	}
#endif

        /* all custom primitives printed here: must be kept last since
	   only the first field will also have a corresponding handler */
	rcount = nf9_init_cp_template(&v4_template, &v4_template_out, &v4_int_template, &v4_int_template_out, rcount);
	rcount_pen = nf9_init_cp_pen_template(&v4_pen_template, &v4_pen_template_out, &v4_pen_int_template, &v4_pen_int_template_out, rcount_pen);

	v4_template.h.c.flowset_id = htons(flowset_id);
	v4_template.h.c.length = htons( sizeof(struct NF9_TEMPLATE_FLOWSET_HEADER) + (sizeof(struct NF9_TEMPLATE_FLOWSET_RECORD) * rcount) +
				 (sizeof(struct IPFIX_PEN_TEMPLATE_FLOWSET_RECORD) * rcount_pen) );
	v4_template.h.template_id = htons(NF9_SOFTFLOWD_V4_TEMPLATE_ID + config.nfprobe_id);
	v4_template.h.count = htons(rcount + rcount_pen);
	v4_template.tot_len = sizeof(struct NF9_TEMPLATE_FLOWSET_HEADER) + (sizeof(struct NF9_TEMPLATE_FLOWSET_RECORD) * rcount);
	v4_pen_template.tot_len = sizeof(struct IPFIX_PEN_TEMPLATE_FLOWSET_RECORD) * rcount_pen;

        v4_template_out.h.c.flowset_id = htons(flowset_id);
        v4_template_out.h.c.length = htons( sizeof(struct NF9_TEMPLATE_FLOWSET_HEADER) + (sizeof(struct NF9_TEMPLATE_FLOWSET_RECORD) * rcount) +
				     (sizeof(struct IPFIX_PEN_TEMPLATE_FLOWSET_RECORD) * rcount_pen) );
        v4_template_out.h.template_id = htons(NF9_SOFTFLOWD_V4_TEMPLATE_ID + config.nfprobe_id + 1);
        v4_template_out.h.count = htons(rcount + rcount_pen);
        v4_template_out.tot_len = sizeof(struct NF9_TEMPLATE_FLOWSET_HEADER) + (sizeof(struct NF9_TEMPLATE_FLOWSET_RECORD) * rcount);
	v4_pen_template_out.tot_len = sizeof(struct IPFIX_PEN_TEMPLATE_FLOWSET_RECORD) * rcount_pen;

	assert(rcount + rcount_pen < NF9_SOFTFLOWD_TEMPLATE_NRECORDS);

	for (idx = 0, v4_int_template.tot_rec_len = 0, v4_int_template_out.tot_rec_len = 0; idx < rcount; idx++) {
	  if (config.nfprobe_version == 10 && v4_int_template.r[idx].length == IPFIX_VARIABLE_LENGTH);
	  else v4_int_template.tot_rec_len += v4_int_template.r[idx].length;

	  if (config.nfprobe_version == 10 && v4_int_template_out.r[idx].length == IPFIX_VARIABLE_LENGTH);
	  else v4_int_template_out.tot_rec_len += v4_int_template_out.r[idx].length;
	}

        for (idx = 0, v4_pen_int_template.tot_rec_len = 0, v4_pen_int_template_out.tot_rec_len = 0; idx < rcount_pen; idx++) {
          if (config.nfprobe_version == 10 && v4_pen_int_template.r[idx].length == IPFIX_VARIABLE_LENGTH);
	  else v4_pen_int_template.tot_rec_len += v4_pen_int_template.r[idx].length;

          if (config.nfprobe_version == 10 && v4_pen_int_template_out.r[idx].length == IPFIX_VARIABLE_LENGTH);
	  else v4_pen_int_template_out.tot_rec_len += v4_pen_int_template_out.r[idx].length;
        }

	rcount = 0; rcount_pen = 0;
	bzero(&v6_template, sizeof(v6_template));
	bzero(&v6_pen_template, sizeof(v6_pen_template));
	bzero(&v6_int_template, sizeof(v6_int_template));
	bzero(&v6_pen_int_template, sizeof(v6_pen_int_template));
        bzero(&v6_template_out, sizeof(v6_template_out));
        bzero(&v6_pen_template_out, sizeof(v6_pen_template_out));
        bzero(&v6_int_template_out, sizeof(v6_int_template_out));
        bzero(&v6_pen_int_template_out, sizeof(v6_pen_int_template_out));

        if (config.nfprobe_version == 9 && config.timestamps_secs) {
	  v6_template.r[rcount].type = htons(NF9_LAST_SWITCHED);
	  v6_template.r[rcount].length = htons(4);
	  v6_int_template.r[rcount].length = 4;
          v6_template_out.r[rcount].type = htons(NF9_LAST_SWITCHED);
          v6_template_out.r[rcount].length = htons(4);
          v6_int_template_out.r[rcount].length = 4;
	  rcount++;
	  v6_template.r[rcount].type = htons(NF9_FIRST_SWITCHED);
	  v6_template.r[rcount].length = htons(4);
	  v6_int_template.r[rcount].length = 4;
          v6_template_out.r[rcount].type = htons(NF9_FIRST_SWITCHED);
          v6_template_out.r[rcount].length = htons(4);
          v6_int_template_out.r[rcount].length = 4;
	  rcount++;
        }
        else if ((config.nfprobe_version == 9 && !config.timestamps_secs) || config.nfprobe_version == 10) {
	  if (!config.nfprobe_tstamp_usec) {
	    v6_template.r[rcount].type = htons(NF9_LAST_SWITCHED_MSEC);
	    v6_template.r[rcount].length = htons(8);
	    v6_int_template.r[rcount].length = 8;
	    v6_template_out.r[rcount].type = htons(NF9_LAST_SWITCHED_MSEC);
	    v6_template_out.r[rcount].length = htons(8);
	    v6_int_template_out.r[rcount].length = 8;
	    rcount++;
	    v6_template.r[rcount].type = htons(NF9_FIRST_SWITCHED_MSEC);
	    v6_template.r[rcount].length = htons(8);
	    v6_int_template.r[rcount].length = 8;
	    v6_template_out.r[rcount].type = htons(NF9_FIRST_SWITCHED_MSEC);
	    v6_template_out.r[rcount].length = htons(8);
	    v6_int_template_out.r[rcount].length = 8;
	    rcount++;
	  }
	  else {
	    v6_template.r[rcount].type = htons(NF9_LAST_SWITCHED_USEC);
	    v6_template.r[rcount].length = htons(16);
	    v6_int_template.r[rcount].length = 16;
	    v6_template_out.r[rcount].type = htons(NF9_LAST_SWITCHED_USEC);
	    v6_template_out.r[rcount].length = htons(16);
	    v6_int_template_out.r[rcount].length = 16;
	    rcount++;
	    v6_template.r[rcount].type = htons(NF9_FIRST_SWITCHED_USEC);
	    v6_template.r[rcount].length = htons(16);
	    v6_int_template.r[rcount].length = 16;
	    v6_template_out.r[rcount].type = htons(NF9_FIRST_SWITCHED_USEC);
	    v6_template_out.r[rcount].length = htons(16);
	    v6_int_template_out.r[rcount].length = 16;
	    rcount++;
	  }
        }
        v6_template.r[rcount].type = htons(NF9_IN_BYTES);
        v6_template.r[rcount].length = htons(8);
        v6_int_template.r[rcount].length = 8;
        v6_template_out.r[rcount].type = htons(NF9_IN_BYTES);
        v6_template_out.r[rcount].length = htons(8);
        v6_int_template_out.r[rcount].length = 8;
        rcount++;
        v6_template.r[rcount].type = htons(NF9_IN_PACKETS);
        v6_template.r[rcount].length = htons(8);
        v6_int_template.r[rcount].length = 8;
        v6_template_out.r[rcount].type = htons(NF9_IN_PACKETS);
        v6_template_out.r[rcount].length = htons(8);
        v6_int_template_out.r[rcount].length = 8;
        rcount++;
	v6_template.r[rcount].type = htons(NF9_IP_PROTOCOL_VERSION);
	v6_template.r[rcount].length = htons(1);
	v6_int_template.r[rcount].length = 1;
        v6_template_out.r[rcount].type = htons(NF9_IP_PROTOCOL_VERSION);
        v6_template_out.r[rcount].length = htons(1);
        v6_int_template_out.r[rcount].length = 1;
	rcount++;
        v6_template.r[rcount].type = htons(NF9_INPUT_SNMP);
        v6_template.r[rcount].length = htons(4);
	v6_int_template.r[rcount].handler = flow_to_flowset_input_handler;
        v6_int_template.r[rcount].length = 4;
        v6_template_out.r[rcount].type = htons(NF9_INPUT_SNMP);
        v6_template_out.r[rcount].length = htons(4);
        v6_int_template_out.r[rcount].handler = flow_to_flowset_input_handler;
        v6_int_template_out.r[rcount].length = 4;
        rcount++;
        v6_template.r[rcount].type = htons(NF9_OUTPUT_SNMP);
        v6_template.r[rcount].length = htons(4);
	v6_int_template.r[rcount].handler = flow_to_flowset_output_handler;
        v6_int_template.r[rcount].length = 4;
        v6_template_out.r[rcount].type = htons(NF9_OUTPUT_SNMP);
        v6_template_out.r[rcount].length = htons(4);
        v6_int_template_out.r[rcount].handler = flow_to_flowset_output_handler;
        v6_int_template_out.r[rcount].length = 4;
        rcount++;
        v6_template.r[rcount].type = htons(NF9_DIRECTION);
        v6_template.r[rcount].length = htons(1);
        v6_int_template.r[rcount].handler = flow_to_flowset_direction_handler;
        v6_int_template.r[rcount].length = 1;
        v6_template_out.r[rcount].type = htons(NF9_DIRECTION);
        v6_template_out.r[rcount].length = htons(1);
        v6_int_template_out.r[rcount].handler = flow_to_flowset_direction_handler;
        v6_int_template_out.r[rcount].length = 1;
        rcount++;
	if (config.nfprobe_what_to_count & COUNT_FLOWS) { 
	  v6_template.r[rcount].type = htons(NF9_FLOWS);
	  v6_template.r[rcount].length = htons(4);
	  v6_int_template.r[rcount].handler = flow_to_flowset_flows_handler;
	  v6_int_template.r[rcount].length = 4;
          v6_template_out.r[rcount].type = htons(NF9_FLOWS);
          v6_template_out.r[rcount].length = htons(4);
          v6_int_template_out.r[rcount].handler = flow_to_flowset_flows_handler;
          v6_int_template_out.r[rcount].length = 4;
	  rcount++;
	}
	if (config.nfprobe_what_to_count & COUNT_SRC_HOST) { 
	  v6_template.r[rcount].type = htons(NF9_IPV6_SRC_ADDR);
	  v6_template.r[rcount].length = htons(16);
	  v6_int_template.r[rcount].handler = flow_to_flowset_src_host_v6_handler;
	  v6_int_template.r[rcount].length = 16;
          v6_template_out.r[rcount].type = htons(NF9_IPV6_SRC_ADDR);
          v6_template_out.r[rcount].length = htons(16);
          v6_int_template_out.r[rcount].handler = flow_to_flowset_src_host_v6_handler;
          v6_int_template_out.r[rcount].length = 16;
	  rcount++;
	}
	if (config.nfprobe_what_to_count & COUNT_DST_HOST) {
	  v6_template.r[rcount].type = htons(NF9_IPV6_DST_ADDR);
	  v6_template.r[rcount].length = htons(16);
	  v6_int_template.r[rcount].handler = flow_to_flowset_dst_host_v6_handler;
	  v6_int_template.r[rcount].length = 16;
          v6_template_out.r[rcount].type = htons(NF9_IPV6_DST_ADDR);
          v6_template_out.r[rcount].length = htons(16);
          v6_int_template_out.r[rcount].handler = flow_to_flowset_dst_host_v6_handler;
          v6_int_template_out.r[rcount].length = 16;
	  rcount++;
	}
        if (config.nfprobe_what_to_count & COUNT_PEER_DST_IP) {
          v6_template.r[rcount].type = htons(NF9_BGP_IPV6_NEXT_HOP);
          v6_template.r[rcount].length = htons(16);
          v6_int_template.r[rcount].handler = flow_to_flowset_bgp_next_hop_v6_handler;
          v6_int_template.r[rcount].length = 16;
          v6_template_out.r[rcount].type = htons(NF9_BGP_IPV6_NEXT_HOP);
          v6_template_out.r[rcount].length = htons(16);
          v6_int_template_out.r[rcount].handler = flow_to_flowset_bgp_next_hop_v6_handler;
          v6_int_template_out.r[rcount].length = 16;
          rcount++;
        }
        if (config.nfprobe_what_to_count & COUNT_SRC_NMASK) {
          v6_template.r[rcount].type = htons(NF9_IPV6_SRC_MASK);
          v6_template.r[rcount].length = htons(1);
          v6_int_template.r[rcount].handler = flow_to_flowset_src_nmask_handler;
          v6_int_template.r[rcount].length = 1;
          v6_template_out.r[rcount].type = htons(NF9_IPV6_SRC_MASK);
          v6_template_out.r[rcount].length = htons(1);
          v6_int_template_out.r[rcount].handler = flow_to_flowset_src_nmask_handler;
          v6_int_template_out.r[rcount].length = 1;
          rcount++;
        }
        if (config.nfprobe_what_to_count & COUNT_DST_NMASK) {
          v6_template.r[rcount].type = htons(NF9_IPV6_DST_MASK);
          v6_template.r[rcount].length = htons(1);
          v6_int_template.r[rcount].handler = flow_to_flowset_dst_nmask_handler;
          v6_int_template.r[rcount].length = 1;
          v6_template_out.r[rcount].type = htons(NF9_IPV6_DST_MASK);
          v6_template_out.r[rcount].length = htons(1);
          v6_int_template_out.r[rcount].handler = flow_to_flowset_dst_nmask_handler;
          v6_int_template_out.r[rcount].length = 1;
          rcount++;
        }
	if (config.nfprobe_what_to_count & (COUNT_IP_TOS)) {
	  v6_template.r[rcount].type = htons(NF9_SRC_TOS);
	  v6_template.r[rcount].length = htons(1);
	  v6_int_template.r[rcount].handler = flow_to_flowset_ip_tos_handler;
	  v6_int_template.r[rcount].length = 1;
          v6_template_out.r[rcount].type = htons(NF9_SRC_TOS);
          v6_template_out.r[rcount].length = htons(1);
          v6_int_template_out.r[rcount].handler = flow_to_flowset_ip_tos_handler;
          v6_int_template_out.r[rcount].length = 1;
	  rcount++;
	}
	if (config.nfprobe_what_to_count & COUNT_SRC_PORT) {
	  v6_template.r[rcount].type = htons(NF9_L4_SRC_PORT);
	  v6_template.r[rcount].length = htons(2);
	  v6_int_template.r[rcount].handler = flow_to_flowset_src_port_handler;
	  v6_int_template.r[rcount].length = 2;
          v6_template_out.r[rcount].type = htons(NF9_L4_SRC_PORT);
          v6_template_out.r[rcount].length = htons(2);
          v6_int_template_out.r[rcount].handler = flow_to_flowset_src_port_handler;
          v6_int_template_out.r[rcount].length = 2;
	  rcount++;
	}
	if (config.nfprobe_what_to_count & COUNT_DST_PORT) {
	  v6_template.r[rcount].type = htons(NF9_L4_DST_PORT);
	  v6_template.r[rcount].length = htons(2);
	  v6_int_template.r[rcount].handler = flow_to_flowset_dst_port_handler;
	  v6_int_template.r[rcount].length = 2;
          v6_template_out.r[rcount].type = htons(NF9_L4_DST_PORT);
          v6_template_out.r[rcount].length = htons(2);
          v6_int_template_out.r[rcount].handler = flow_to_flowset_dst_port_handler;
          v6_int_template_out.r[rcount].length = 2;
	  rcount++;
	}
	if (config.nfprobe_what_to_count & (COUNT_SRC_PORT|COUNT_DST_PORT)) {
	  v6_template.r[rcount].type = htons(NF9_TCP_FLAGS);
	  v6_template.r[rcount].length = htons(1);
	  v6_int_template.r[rcount].handler = flow_to_flowset_tcp_flags_handler;
	  v6_int_template.r[rcount].length = 1;
          v6_template_out.r[rcount].type = htons(NF9_TCP_FLAGS);
          v6_template_out.r[rcount].length = htons(1);
          v6_int_template_out.r[rcount].handler = flow_to_flowset_tcp_flags_handler;
          v6_int_template_out.r[rcount].length = 1;
	  rcount++;
	}
	if (config.nfprobe_what_to_count & COUNT_IP_PROTO) {
	  v6_template.r[rcount].type = htons(NF9_IN_PROTOCOL);
	  v6_template.r[rcount].length = htons(1);
	  v6_int_template.r[rcount].handler = flow_to_flowset_ip_proto_handler;
	  v6_int_template.r[rcount].length = 1;
          v6_template_out.r[rcount].type = htons(NF9_IN_PROTOCOL);
          v6_template_out.r[rcount].length = htons(1);
          v6_int_template_out.r[rcount].handler = flow_to_flowset_ip_proto_handler;
          v6_int_template_out.r[rcount].length = 1;
	  rcount++;
	}
	if (config.nfprobe_what_to_count & COUNT_SRC_AS) {
	  v6_template.r[rcount].type = htons(NF9_SRC_AS);
	  v6_template.r[rcount].length = htons(4);
	  v6_int_template.r[rcount].handler = flow_to_flowset_src_as_handler;
	  v6_int_template.r[rcount].length = 4;
          v6_template_out.r[rcount].type = htons(NF9_SRC_AS);
          v6_template_out.r[rcount].length = htons(4);
          v6_int_template_out.r[rcount].handler = flow_to_flowset_src_as_handler;
          v6_int_template_out.r[rcount].length = 4;
	  rcount++;
	}
	if (config.nfprobe_what_to_count & COUNT_DST_AS) {
	  v6_template.r[rcount].type = htons(NF9_DST_AS);
	  v6_template.r[rcount].length = htons(4);
	  v6_int_template.r[rcount].handler = flow_to_flowset_dst_as_handler;
	  v6_int_template.r[rcount].length = 4;
          v6_template_out.r[rcount].type = htons(NF9_DST_AS);
          v6_template_out.r[rcount].length = htons(4);
          v6_int_template_out.r[rcount].handler = flow_to_flowset_dst_as_handler;
          v6_int_template_out.r[rcount].length = 4;
	  rcount++;
	}
	if (config.nfprobe_what_to_count & COUNT_SRC_MAC) {
	  v6_template.r[rcount].type = htons(NF9_IN_SRC_MAC);
	  v6_template.r[rcount].length = htons(6);
	  v6_int_template.r[rcount].handler = flow_to_flowset_src_mac_handler;
	  v6_int_template.r[rcount].length = 6;
          v6_template_out.r[rcount].type = htons(NF9_OUT_SRC_MAC);
          v6_template_out.r[rcount].length = htons(6);
          v6_int_template_out.r[rcount].handler = flow_to_flowset_src_mac_handler;
          v6_int_template_out.r[rcount].length = 6;
	  rcount++;
	}
	if (config.nfprobe_what_to_count & COUNT_DST_MAC) {
	  v6_template.r[rcount].type = htons(NF9_IN_DST_MAC);
	  v6_template.r[rcount].length = htons(6);
	  v6_int_template.r[rcount].handler = flow_to_flowset_dst_mac_handler;
	  v6_int_template.r[rcount].length = 6;
          v6_template_out.r[rcount].type = htons(NF9_OUT_DST_MAC);
          v6_template_out.r[rcount].length = htons(6);
          v6_int_template_out.r[rcount].handler = flow_to_flowset_dst_mac_handler;
          v6_int_template_out.r[rcount].length = 6;
	  rcount++;
	}
	if (config.nfprobe_what_to_count & COUNT_VLAN) {
	  v6_template.r[rcount].type = htons(NF9_SRC_VLAN);
	  v6_template.r[rcount].length = htons(2);
	  v6_int_template.r[rcount].handler = flow_to_flowset_vlan_handler;
	  v6_int_template.r[rcount].length = 2;
          v6_template_out.r[rcount].type = htons(NF9_DST_VLAN);
          v6_template_out.r[rcount].length = htons(2);
          v6_int_template_out.r[rcount].handler = flow_to_flowset_vlan_handler;
          v6_int_template_out.r[rcount].length = 2;
	  rcount++;
	}
        if (config.nfprobe_what_to_count_2 & COUNT_MPLS_LABEL_TOP) {
          v6_template.r[rcount].type = htons(NF9_MPLS_LABEL_1);
          v6_template.r[rcount].length = htons(3);
          v6_int_template.r[rcount].handler = flow_to_flowset_mpls_label_top_handler;
          v6_int_template.r[rcount].length = 3;
          v6_template_out.r[rcount].type = htons(NF9_MPLS_LABEL_1);
          v6_template_out.r[rcount].length = htons(3);
          v6_int_template_out.r[rcount].handler = flow_to_flowset_mpls_label_top_handler;
          v6_int_template_out.r[rcount].length = 3;
          rcount++;
        }
        if (config.nfprobe_version == 10 && config.nfprobe_what_to_count & COUNT_TAG) {
          int rlen = sizeof(pm_id_t);

	  v6_pen_template.r[rcount_pen].type = htons(IPFIX_TPL_EBIT | NF9_CUST_TAG);
	  v6_pen_template.r[rcount_pen].pen = htonl(PMACCT_PEN);
	  v6_pen_template.r[rcount_pen].length = htons(rlen);
	  v6_pen_int_template.r[rcount_pen].handler = flow_to_flowset_tag_handler;
	  v6_pen_int_template.r[rcount_pen].length = rlen;
          v6_pen_template_out.r[rcount_pen].type = htons(IPFIX_TPL_EBIT | NF9_CUST_TAG);
	  v6_pen_template_out.r[rcount_pen].pen = htonl(PMACCT_PEN);
          v6_pen_template_out.r[rcount_pen].length = htons(rlen);
          v6_pen_int_template_out.r[rcount_pen].handler = flow_to_flowset_tag_handler;
          v6_pen_int_template_out.r[rcount_pen].length = rlen;
	  rcount_pen++;
	}
        if (config.nfprobe_version == 10 && config.nfprobe_what_to_count & COUNT_TAG2) {
          int rlen = sizeof(pm_id_t);

          v6_pen_template.r[rcount_pen].type = htons(IPFIX_TPL_EBIT | NF9_CUST_TAG2);
	  v6_pen_template.r[rcount_pen].pen = htonl(PMACCT_PEN);
          v6_pen_template.r[rcount_pen].length = htons(rlen);
          v6_pen_int_template.r[rcount_pen].handler = flow_to_flowset_tag2_handler;
          v6_pen_int_template.r[rcount_pen].length = rlen;
          v6_pen_template_out.r[rcount_pen].type = htons(IPFIX_TPL_EBIT | NF9_CUST_TAG2);
	  v6_pen_template_out.r[rcount_pen].pen = htonl(PMACCT_PEN);
          v6_pen_template_out.r[rcount_pen].length = htons(rlen);
          v6_pen_int_template_out.r[rcount_pen].handler = flow_to_flowset_tag2_handler;
          v6_pen_int_template_out.r[rcount_pen].length = rlen;
          rcount_pen++;
        }
        if (config.nfprobe_version == 10 && config.nfprobe_what_to_count_2 & COUNT_LABEL) {
          v6_pen_template.r[rcount_pen].type = htons(IPFIX_TPL_EBIT | NF9_CUST_LABEL);
          v6_pen_template.r[rcount_pen].pen = htonl(PMACCT_PEN);
          v6_pen_template.r[rcount_pen].length = htons(IPFIX_VARIABLE_LENGTH);
          v6_pen_int_template.r[rcount_pen].handler = flow_to_flowset_label_handler;
          v6_pen_int_template.r[rcount_pen].length = IPFIX_VARIABLE_LENGTH;
          v6_pen_template_out.r[rcount_pen].type = htons(IPFIX_TPL_EBIT | NF9_CUST_LABEL);
          v6_pen_template_out.r[rcount_pen].pen = htonl(PMACCT_PEN);
          v6_pen_template_out.r[rcount_pen].length = htons(IPFIX_VARIABLE_LENGTH);
          v6_pen_int_template_out.r[rcount_pen].handler = flow_to_flowset_label_handler;
          v6_pen_int_template_out.r[rcount_pen].length = IPFIX_VARIABLE_LENGTH;
          rcount_pen++;
        }
        if (config.sampling_rate || config.ext_sampling_rate) {
          v6_template.r[rcount].type = htons(NF9_FLOW_SAMPLER_ID);
          v6_template.r[rcount].length = htons(1);
          v6_int_template.r[rcount].handler = flow_to_flowset_sampler_id_handler;
          v6_int_template.r[rcount].length = 1;
          v6_template_out.r[rcount].type = htons(NF9_FLOW_SAMPLER_ID);
          v6_template_out.r[rcount].length = htons(1);
          v6_int_template_out.r[rcount].handler = flow_to_flowset_sampler_id_handler;
          v6_int_template_out.r[rcount].length = 1;
          rcount++;
        }
        if (config.nfprobe_what_to_count & COUNT_CLASS) { 
          v6_template.r[rcount].type = htons(NF9_FLOW_APPLICATION_ID);
          v6_template.r[rcount].length = htons(4);
          v6_int_template.r[rcount].handler = flow_to_flowset_class_handler;
          v6_int_template.r[rcount].length = 4;
          v6_template_out.r[rcount].type = htons(NF9_FLOW_APPLICATION_ID);
          v6_template_out.r[rcount].length = htons(4);
          v6_int_template_out.r[rcount].handler = flow_to_flowset_class_handler;
          v6_int_template_out.r[rcount].length = 4;
          rcount++;
        }
#if defined (WITH_NDPI)
	if (config.nfprobe_what_to_count_2 & COUNT_NDPI_CLASS) { 
	  v6_template.r[rcount].type = htons(NF9_FLOW_APPLICATION_ID);
	  v6_template.r[rcount].length = htons(5);
	  v6_int_template.r[rcount].handler = flow_to_flowset_ndpi_class_handler;
	  v6_int_template.r[rcount].length = 5;
	  v6_template_out.r[rcount].type = htons(NF9_FLOW_APPLICATION_ID);
	  v6_template_out.r[rcount].length = htons(5);
	  v6_int_template_out.r[rcount].handler = flow_to_flowset_ndpi_class_handler;
	  v6_int_template_out.r[rcount].length = 5;
	  rcount++;
	}
#endif

        /* all custom primitives printed here: must be kept last since
           only the first field will also have a corresponding handler */
        rcount = nf9_init_cp_template(&v6_template, &v6_template_out, &v6_int_template, &v6_int_template_out, rcount);
        rcount_pen = nf9_init_cp_pen_template(&v6_pen_template, &v6_pen_template_out, &v6_pen_int_template, &v6_pen_int_template_out, rcount_pen);

	v6_template.h.c.flowset_id = htons(flowset_id);
	v6_template.h.c.length = htons( sizeof(struct NF9_TEMPLATE_FLOWSET_HEADER) + (sizeof(struct NF9_TEMPLATE_FLOWSET_RECORD) * rcount) +
				 (sizeof(struct IPFIX_PEN_TEMPLATE_FLOWSET_RECORD) * rcount_pen) );
	v6_template.h.template_id = htons(NF9_SOFTFLOWD_V6_TEMPLATE_ID + config.nfprobe_id);
	v6_template.h.count = htons(rcount + rcount_pen);
	v6_template.tot_len = sizeof(struct NF9_TEMPLATE_FLOWSET_HEADER) + (sizeof(struct NF9_TEMPLATE_FLOWSET_RECORD) * rcount);
	v6_pen_template.tot_len = sizeof(struct IPFIX_PEN_TEMPLATE_FLOWSET_RECORD) * rcount_pen;

        v6_template_out.h.c.flowset_id = htons(flowset_id);
        v6_template_out.h.c.length = htons( sizeof(struct NF9_TEMPLATE_FLOWSET_HEADER) + (sizeof(struct NF9_TEMPLATE_FLOWSET_RECORD) * rcount) +
				     (sizeof(struct IPFIX_PEN_TEMPLATE_FLOWSET_RECORD) * rcount_pen) );
        v6_template_out.h.template_id = htons(NF9_SOFTFLOWD_V6_TEMPLATE_ID + config.nfprobe_id + 1);
        v6_template_out.h.count = htons(rcount + rcount_pen);
        v6_template_out.tot_len = sizeof(struct NF9_TEMPLATE_FLOWSET_HEADER) + (sizeof(struct NF9_TEMPLATE_FLOWSET_RECORD) * rcount);
        v6_pen_template_out.tot_len = sizeof(struct IPFIX_PEN_TEMPLATE_FLOWSET_RECORD) * rcount_pen; 

	assert(rcount + rcount_pen < NF9_SOFTFLOWD_TEMPLATE_NRECORDS);

	for (idx = 0, v6_int_template.tot_rec_len = 0, v6_int_template_out.tot_rec_len = 0; idx < rcount; idx++) {
	  if (config.nfprobe_version == 10 && v6_int_template.r[idx].length == IPFIX_VARIABLE_LENGTH);
	  else v6_int_template.tot_rec_len += v6_int_template.r[idx].length;

	  if (config.nfprobe_version == 10 && v6_int_template_out.r[idx].length == IPFIX_VARIABLE_LENGTH);
	  else v6_int_template_out.tot_rec_len += v6_int_template_out.r[idx].length;
	}

        for (idx = 0, v6_pen_int_template.tot_rec_len = 0, v6_pen_int_template_out.tot_rec_len = 0; idx < rcount_pen; idx++) {
          if (config.nfprobe_version == 10 && v6_pen_int_template.r[idx].length == IPFIX_VARIABLE_LENGTH);
	  else v6_pen_int_template.tot_rec_len += v6_pen_int_template.r[idx].length;

	  if (config.nfprobe_version == 10 && v6_pen_int_template_out.r[idx].length == IPFIX_VARIABLE_LENGTH);
          else v6_pen_int_template_out.tot_rec_len += v6_pen_int_template_out.r[idx].length;
        }
}

static void
nf9_init_options_template(void)
{
	int rcount, idx, slen = 0, flowset_id = 0, scope = 0;

	switch (config.nfprobe_source_ha.family) {
	case AF_INET:
	  slen = 4;
	  break;
	case AF_INET6:
	  slen = 16;
	  break;
	default:
	  slen = 4;
	  break;
	}

        rcount = 0;
        bzero(&sampling_option_template, sizeof(sampling_option_template));
        bzero(&sampling_option_int_template, sizeof(sampling_option_int_template));

        if (config.nfprobe_version == 9) {
	  flowset_id = NF9_OPTIONS_FLOWSET_ID;
	  scope = NF9_OPT_SCOPE_SYSTEM;
	}
        else if (config.nfprobe_version == 10) {
	  flowset_id = IPFIX_OPTIONS_FLOWSET_ID;
	  scope = NF9_FLOW_EXPORTER;
	}
 
        sampling_option_template.r[rcount].type = htons(scope);
        sampling_option_template.r[rcount].length = htons(slen);
        sampling_option_int_template.r[rcount].length = slen;
        rcount++;
        sampling_option_template.r[rcount].type = htons(NF9_FLOW_SAMPLER_ID);
        sampling_option_template.r[rcount].length = htons(1);
        sampling_option_int_template.r[rcount].length = 1;
        rcount++;
        sampling_option_template.r[rcount].type = htons(NF9_FLOW_SAMPLER_MODE);
        sampling_option_template.r[rcount].length = htons(1);
        sampling_option_int_template.r[rcount].length = 1;
        rcount++;
        sampling_option_template.r[rcount].type = htons(NF9_FLOW_SAMPLER_INTERVAL);
        sampling_option_template.r[rcount].length = htons(4);
        sampling_option_int_template.r[rcount].length = 4;
        rcount++;
        sampling_option_template.h.c.flowset_id = htons(flowset_id);
        sampling_option_template.h.c.length = htons( sizeof(struct NF9_OPTIONS_TEMPLATE_FLOWSET_HEADER) + (sizeof(struct NF9_TEMPLATE_FLOWSET_RECORD) * rcount) );
        sampling_option_template.h.template_id = htons(NF9_OPTIONS_TEMPLATE_ID + config.nfprobe_id );
        if (config.nfprobe_version == 9) {
          sampling_option_template.h.scope_len = htons(4); /* NF9_OPT_SCOPE_SYSTEM */
          sampling_option_template.h.option_len = htons(12); /* NF9_FLOW_SAMPLER_ID + NF9_FLOW_SAMPLER_MODE + NF9_FLOW_SAMPLER_INTERVAL */
	}
	else if (config.nfprobe_version == 10) {
          sampling_option_template.h.scope_len = htons(3+1); /* IPFIX twist: NF9_FLOW_SAMPLER_ID + NF9_FLOW_SAMPLER_MODE + NF9_FLOW_SAMPLER_INTERVAL + NF9_OPT_SCOPE_SYSTEM */ 
          sampling_option_template.h.option_len = htons(1); /* IPFIX twist: NF9_OPT_SCOPE_SYSTEM */ 
	}
        sampling_option_template.tot_len = sizeof(struct NF9_OPTIONS_TEMPLATE_FLOWSET_HEADER) + (sizeof(struct NF9_TEMPLATE_FLOWSET_RECORD) * rcount);

        for (idx = 0, sampling_option_int_template.tot_rec_len = 0; idx < rcount; idx++)
          sampling_option_int_template.tot_rec_len += sampling_option_int_template.r[idx].length;

        rcount = 0;
        bzero(&class_option_template, sizeof(class_option_template));
        bzero(&class_option_int_template, sizeof(class_option_int_template));

        class_option_template.r[rcount].type = htons(scope);
        class_option_template.r[rcount].length = htons(4);
        class_option_int_template.r[rcount].length = 4;
        rcount++;
        class_option_template.r[rcount].type = htons(NF9_FLOW_APPLICATION_ID);
        class_option_template.r[rcount].length = htons(5);
        class_option_int_template.r[rcount].length = 5;
        rcount++;
        class_option_template.r[rcount].type = htons(NF9_FLOW_APPLICATION_NAME);
        class_option_template.r[rcount].length = htons(MAX_PROTOCOL_LEN);
        class_option_int_template.r[rcount].length = MAX_PROTOCOL_LEN;
        rcount++;
        class_option_template.h.c.flowset_id = htons(flowset_id);
        class_option_template.h.c.length = htons( sizeof(struct NF9_OPTIONS_TEMPLATE_FLOWSET_HEADER) + (sizeof(struct NF9_TEMPLATE_FLOWSET_RECORD) * rcount) );
        class_option_template.h.template_id = htons(NF9_OPTIONS_TEMPLATE_ID + 1 + config.nfprobe_id );
	if (config.nfprobe_version == 9) {
          class_option_template.h.scope_len = htons(4); /* NF9_OPT_SCOPE_SYSTEM */
          class_option_template.h.option_len = htons(8); /* NF9_FLOW_APPLICATION_ID + NF9_FLOW_APPLICATION_NAME */
	}
	else if (config.nfprobe_version == 10) {
          class_option_template.h.scope_len = htons(2+1); /* IPFIX twist: NF9_FLOW_APPLICATION_ID + NF9_FLOW_APPLICATION_NAME + NF9_OPT_SCOPE_SYSTEM */
          class_option_template.h.option_len = htons(1); /* IPFIX twist: NF9_OPT_SCOPE_SYSTEM */ 
	}
        class_option_template.tot_len = sizeof(struct NF9_OPTIONS_TEMPLATE_FLOWSET_HEADER) + (sizeof(struct NF9_TEMPLATE_FLOWSET_RECORD) * rcount);

        for (idx = 0, class_option_int_template.tot_rec_len = 0; idx < rcount; idx++)
          class_option_int_template.tot_rec_len += class_option_int_template.r[idx].length;

        rcount = 0;
        bzero(&exporter_option_template, sizeof(exporter_option_template));
        bzero(&exporter_option_int_template, sizeof(exporter_option_int_template));

        if (config.nfprobe_version == 9) {
	  flowset_id = NF9_OPTIONS_FLOWSET_ID;
	  scope = NF9_OPT_SCOPE_SYSTEM;
	}
        else if (config.nfprobe_version == 10) {
	  flowset_id = IPFIX_OPTIONS_FLOWSET_ID;
	  scope = NF9_FLOW_EXPORTER;
	}
 
        exporter_option_template.r[rcount].type = htons(scope);
        exporter_option_template.r[rcount].length = htons(slen);
        exporter_option_int_template.r[rcount].length = slen;
        rcount++;
        exporter_option_template.r[rcount].type = htons(NF9_EXPORTER_IPV4_ADDRESS);
        exporter_option_template.r[rcount].length = htons(4);
        exporter_option_int_template.r[rcount].length = 4;
        rcount++;
        exporter_option_template.r[rcount].type = htons(NF9_EXPORTER_IPV6_ADDRESS);
        exporter_option_template.r[rcount].length = htons(16);
        exporter_option_int_template.r[rcount].length = 16;
        rcount++;
        exporter_option_template.h.c.flowset_id = htons(flowset_id);
        exporter_option_template.h.c.length = htons( sizeof(struct NF9_OPTIONS_TEMPLATE_FLOWSET_HEADER) + (sizeof(struct NF9_TEMPLATE_FLOWSET_RECORD) * rcount) );
        exporter_option_template.h.template_id = htons(NF9_OPTIONS_TEMPLATE_ID + 2 + config.nfprobe_id );
        if (config.nfprobe_version == 9) {
          exporter_option_template.h.scope_len = htons(4); /* NF9_OPT_SCOPE_SYSTEM */
          exporter_option_template.h.option_len = htons(8); /* NF9_EXPORTER_IPV4_ADDRESS + NF9_EXPORTER_IPV6_ADDRESS */
	}
	else if (config.nfprobe_version == 10) {
          exporter_option_template.h.scope_len = htons(2+1); /* IPFIX twist: NF9_EXPORTER_IPV4_ADDRESS + NF9_EXPORTER_IPV6_ADDRESS + NF9_OPT_SCOPE_SYSTEM */ 
          exporter_option_template.h.option_len = htons(1); /* IPFIX twist: NF9_OPT_SCOPE_SYSTEM */
	}
        exporter_option_template.tot_len = sizeof(struct NF9_OPTIONS_TEMPLATE_FLOWSET_HEADER) + (sizeof(struct NF9_TEMPLATE_FLOWSET_RECORD) * rcount);

        for (idx = 0, exporter_option_int_template.tot_rec_len = 0; idx < rcount; idx++)
          exporter_option_int_template.tot_rec_len += exporter_option_int_template.r[idx].length;
}

static void
nf_flow_to_flowset_inc_len(char **ftoft_ptr, int *add_len, int orig_len, int elem_len)
{
  if (!elem_len) *ftoft_ptr += orig_len;
  else {
    /* hmm, what if sum of all orig_len elements != PM_VARIABLE_LENGTH
       gets >= PM_VARIABLE_LENGTH ? Unlikely but we may hit a problem .. */
    *ftoft_ptr += ((orig_len % PM_VARIABLE_LENGTH) + elem_len);
    *add_len += elem_len;
  }
}

static int
nf_flow_to_flowset(const struct FLOW *flow, u_char *packet, u_int len,
    const struct timeval *system_boot_time, u_int *len_used, int direction)
{
	u_int freclen_0 = 0, freclen_1 = 0, ret_len, nflows, idx;
	u_int64_t rec64;
	u_int32_t rec32 = 0;
	u_int8_t rec8;
	char *ftoft_ptr_0 = ftoft_buf_0;
	char *ftoft_ptr_1 = ftoft_buf_1;
	int flow_direction[2], elem_len, add_len;

	bzero(ftoft_buf_0, sizeof(ftoft_buf_0));
	bzero(ftoft_buf_1, sizeof(ftoft_buf_1));
	*len_used = nflows = ret_len = 0;
	flow_direction[0] = (flow->direction[0] == DIRECTION_UNKNOWN) ? DIRECTION_IN : flow->direction[0];
	flow_direction[1] = (flow->direction[1] == DIRECTION_UNKNOWN) ? DIRECTION_IN : flow->direction[1];
	
	if (direction == flow_direction[0]) {
	  if (config.nfprobe_version == 9 && config.timestamps_secs) {
	    rec32 = htonl(timeval_sub_ms(&flow->flow_last, system_boot_time));
	    memcpy(ftoft_ptr_0, &rec32, 4);
	    ftoft_ptr_0 += 4;

	    rec32 = htonl(timeval_sub_ms(&flow->flow_start, system_boot_time));
	    memcpy(ftoft_ptr_0, &rec32, 4);
	    ftoft_ptr_0 += 4;
	  }
	  else if ((config.nfprobe_version == 9 && !config.timestamps_secs) || config.nfprobe_version == 10) {
	    if (!config.nfprobe_tstamp_usec) {
	      u_int64_t tstamp_msec;

	      tstamp_msec = flow->flow_last.tv_sec;
	      tstamp_msec = tstamp_msec * 1000;
	      tstamp_msec += (flow->flow_last.tv_usec / 1000);
              rec64 = pm_htonll(tstamp_msec);
              memcpy(ftoft_ptr_0, &rec64, 8);
              ftoft_ptr_0 += 8;

              tstamp_msec = flow->flow_start.tv_sec;
              tstamp_msec = tstamp_msec * 1000;
              tstamp_msec += (flow->flow_start.tv_usec / 1000);
              rec64 = pm_htonll(tstamp_msec);
              memcpy(ftoft_ptr_0, &rec64, 8);
              ftoft_ptr_0 += 8;
	    }
	    else {
	      rec64 = pm_htonll(flow->flow_last.tv_sec);
	      memcpy(ftoft_ptr_0, &rec64, 8);
	      ftoft_ptr_0 += 8;
	      rec64 = pm_htonll(flow->flow_last.tv_usec);
	      memcpy(ftoft_ptr_0, &rec64, 8);
	      ftoft_ptr_0 += 8;

	      rec64 = pm_htonll(flow->flow_start.tv_sec);
	      memcpy(ftoft_ptr_0, &rec64, 8);
	      ftoft_ptr_0 += 8;
	      rec64 = pm_htonll(flow->flow_start.tv_usec);
	      memcpy(ftoft_ptr_0, &rec64, 8);
	      ftoft_ptr_0 += 8;
	    }
	  }

          rec64 = pm_htonll(flow->octets[0]);
          memcpy(ftoft_ptr_0, &rec64, 8);
          ftoft_ptr_0 += 8;

          rec64 = pm_htonll(flow->packets[0]);
          memcpy(ftoft_ptr_0, &rec64, 8);
          ftoft_ptr_0 += 8;

          switch (flow->af) {
          case AF_INET:
                rec8 = 4;
                memcpy(ftoft_ptr_0, &rec8, 1);
                ftoft_ptr_0 += 1;
		if (flow_direction[0] == DIRECTION_IN) {
                  for (idx = 5, add_len = 0; v4_int_template.r[idx].handler; idx++) {
                    elem_len = v4_int_template.r[idx].handler(ftoft_ptr_0, flow, 0, v4_int_template.r[idx].length);
		    nf_flow_to_flowset_inc_len(&ftoft_ptr_0, &add_len, v4_int_template.r[idx].length, elem_len); 
                  }
                  freclen_0 = v4_int_template.tot_rec_len;

		  for (idx = 0; v4_pen_int_template.r[idx].handler; idx++) {
                    elem_len = v4_pen_int_template.r[idx].handler(ftoft_ptr_0, flow, 0, v4_pen_int_template.r[idx].length);
		    nf_flow_to_flowset_inc_len(&ftoft_ptr_0, &add_len, v4_pen_int_template.r[idx].length, elem_len);
                  }
                  freclen_0 += (v4_pen_int_template.tot_rec_len + add_len);
		}
		else if (flow_direction[0] == DIRECTION_OUT) {
                  for (idx = 5, add_len = 0; v4_int_template_out.r[idx].handler; idx++) {
                    elem_len = v4_int_template_out.r[idx].handler(ftoft_ptr_0, flow, 0, v4_int_template_out.r[idx].length);
		    nf_flow_to_flowset_inc_len(&ftoft_ptr_0, &add_len, v4_int_template_out.r[idx].length, elem_len);
                  }
                  freclen_0 = v4_int_template_out.tot_rec_len;

                  for (idx = 0; v4_pen_int_template_out.r[idx].handler; idx++) {
                    elem_len = v4_pen_int_template_out.r[idx].handler(ftoft_ptr_0, flow, 0, v4_pen_int_template_out.r[idx].length);
		    nf_flow_to_flowset_inc_len(&ftoft_ptr_0, &add_len, v4_pen_int_template_out.r[idx].length, elem_len);
                  }
                  freclen_0 += (v4_pen_int_template_out.tot_rec_len + add_len);
		}
                break;
          case AF_INET6:
                rec8 = 6;
                memcpy(ftoft_ptr_0, &rec8, 1);
                ftoft_ptr_0 += 1;
		if (flow_direction[0] == DIRECTION_IN) {
                  for (idx = 5, add_len = 0; v6_int_template.r[idx].handler; idx++) {
                    elem_len = v6_int_template.r[idx].handler(ftoft_ptr_0, flow, 0, v6_int_template.r[idx].length);
		    nf_flow_to_flowset_inc_len(&ftoft_ptr_0, &add_len, v6_int_template.r[idx].length, elem_len);
                  }
                  freclen_0 = v6_int_template.tot_rec_len;

                  for (idx = 0; v6_pen_int_template.r[idx].handler; idx++) {
                    elem_len = v6_pen_int_template.r[idx].handler(ftoft_ptr_0, flow, 0, v6_pen_int_template.r[idx].length);
		    nf_flow_to_flowset_inc_len(&ftoft_ptr_0, &add_len, v6_pen_int_template.r[idx].length, elem_len);
                  }
                  freclen_0 += (v6_pen_int_template.tot_rec_len + add_len);
		}
		else if (flow_direction[0] == DIRECTION_OUT) {
                  for (idx = 5, add_len = 0; v6_int_template_out.r[idx].handler; idx++) {
                    elem_len = v6_int_template_out.r[idx].handler(ftoft_ptr_0, flow, 0, v6_int_template_out.r[idx].length);
		    nf_flow_to_flowset_inc_len(&ftoft_ptr_0, &add_len, v6_int_template_out.r[idx].length, elem_len);
                  }
                  freclen_0 = v6_int_template_out.tot_rec_len;

                  for (idx = 0; v6_pen_int_template_out.r[idx].handler; idx++) {
                    elem_len = v6_pen_int_template_out.r[idx].handler(ftoft_ptr_0, flow, 0, v6_pen_int_template_out.r[idx].length);
		    nf_flow_to_flowset_inc_len(&ftoft_ptr_0, &add_len, v6_pen_int_template_out.r[idx].length, elem_len);
                  }
                  freclen_0 += (v6_pen_int_template_out.tot_rec_len + add_len);
		}
                break;
          default:
                return (-1);
          }
	}

	if (direction == flow_direction[1]) {
	  if (config.nfprobe_version == 9 && config.timestamps_secs) {
	    rec32 = htonl(timeval_sub_ms(&flow->flow_last, system_boot_time));
	    memcpy(ftoft_ptr_1, &rec32, 4);
	    ftoft_ptr_1 += 4;
	
	    rec32 = htonl(timeval_sub_ms(&flow->flow_start, system_boot_time));
	    memcpy(ftoft_ptr_1, &rec32, 4);
	    ftoft_ptr_1 += 4;
	  }
          else if ((config.nfprobe_version == 9 && !config.timestamps_secs) || config.nfprobe_version == 10) {
	    if (!config.nfprobe_tstamp_usec) {
              u_int64_t tstamp_msec;

              tstamp_msec = flow->flow_last.tv_sec;
              tstamp_msec = tstamp_msec * 1000;
              tstamp_msec += (flow->flow_last.tv_usec / 1000);
              rec64 = pm_htonll(tstamp_msec);
              memcpy(ftoft_ptr_1, &rec64, 8);
              ftoft_ptr_1 += 8;

              tstamp_msec = flow->flow_start.tv_sec;
              tstamp_msec = tstamp_msec * 1000;
              tstamp_msec += (flow->flow_start.tv_usec / 1000);
              rec64 = pm_htonll(tstamp_msec);
              memcpy(ftoft_ptr_1, &rec64, 8);
              ftoft_ptr_1 += 8;
	    }
	    else {
	      rec64 = pm_htonll(flow->flow_last.tv_sec);
	      memcpy(ftoft_ptr_1, &rec64, 8);
	      ftoft_ptr_1 += 8;
	      rec64 = pm_htonll(flow->flow_last.tv_usec);
	      memcpy(ftoft_ptr_1, &rec64, 8);
	      ftoft_ptr_1 += 8;

	      rec64 = pm_htonll(flow->flow_start.tv_sec);
	      memcpy(ftoft_ptr_1, &rec64, 8);
	      ftoft_ptr_1 += 8;
	      rec64 = pm_htonll(flow->flow_start.tv_usec);
	      memcpy(ftoft_ptr_1, &rec64, 8);
	      ftoft_ptr_1 += 8;
	    }
          }

          rec64 = pm_htonll(flow->octets[1]);
          memcpy(ftoft_ptr_1, &rec64, 8);
          ftoft_ptr_1 += 8;

          rec64 = pm_htonll(flow->packets[1]);
          memcpy(ftoft_ptr_1, &rec64, 8);
          ftoft_ptr_1 += 8;

          switch (flow->af) {
          case AF_INET:
                rec8 = 4;
                memcpy(ftoft_ptr_1, &rec8, 1);
                ftoft_ptr_1 += 1;
		if (flow_direction[1] == DIRECTION_IN) {
                  for (idx = 5, add_len = 0; v4_int_template.r[idx].handler; idx++) {
                    elem_len = v4_int_template.r[idx].handler(ftoft_ptr_1, flow, 1, v4_int_template.r[idx].length);
		    nf_flow_to_flowset_inc_len(&ftoft_ptr_1, &add_len, v4_int_template.r[idx].length, elem_len);
                  }
                  freclen_1 = v4_int_template.tot_rec_len;

                  for (idx = 0; v4_pen_int_template.r[idx].handler; idx++) {
                    elem_len = v4_pen_int_template.r[idx].handler(ftoft_ptr_1, flow, 1, v4_pen_int_template.r[idx].length);
		    nf_flow_to_flowset_inc_len(&ftoft_ptr_1, &add_len, v4_pen_int_template.r[idx].length, elem_len);
                  }
                  freclen_1 += (v4_pen_int_template.tot_rec_len + add_len);
		}
		else if (flow_direction[1] == DIRECTION_OUT) {
                  for (idx = 5, add_len = 0; v4_int_template_out.r[idx].handler; idx++) {
                    elem_len = v4_int_template_out.r[idx].handler(ftoft_ptr_1, flow, 1, v4_int_template_out.r[idx].length);
		    nf_flow_to_flowset_inc_len(&ftoft_ptr_1, &add_len, v4_int_template_out.r[idx].length, elem_len);
                  }
                  freclen_1 = v4_int_template_out.tot_rec_len;

                  for (idx = 0; v4_pen_int_template_out.r[idx].handler; idx++) {
                    elem_len = v4_pen_int_template_out.r[idx].handler(ftoft_ptr_1, flow, 1, v4_pen_int_template_out.r[idx].length);
		    nf_flow_to_flowset_inc_len(&ftoft_ptr_1, &add_len, v4_pen_int_template_out.r[idx].length, elem_len);
                  }
                  freclen_1 += (v4_pen_int_template_out.tot_rec_len + add_len);
		}
                break;
          case AF_INET6:
                rec8 = 6;
                memcpy(ftoft_ptr_1, &rec8, 1);
                ftoft_ptr_1 += 1;
		if (flow_direction[1] == DIRECTION_IN) {
                  for (idx = 5, add_len = 0; v6_int_template.r[idx].handler; idx++) {
                    elem_len = v6_int_template.r[idx].handler(ftoft_ptr_1, flow, 1, v6_int_template.r[idx].length);
		    nf_flow_to_flowset_inc_len(&ftoft_ptr_1, &add_len, v6_int_template.r[idx].length, elem_len);
                  }
                  freclen_1 = v6_int_template.tot_rec_len;

                  for (idx = 0; v6_pen_int_template.r[idx].handler; idx++) {
                    elem_len = v6_pen_int_template.r[idx].handler(ftoft_ptr_1, flow, 1, v6_pen_int_template.r[idx].length);
		    nf_flow_to_flowset_inc_len(&ftoft_ptr_1, &add_len, v6_pen_int_template.r[idx].length, elem_len);
                  }
                  freclen_1 += (v6_pen_int_template.tot_rec_len + add_len);
		}
		else if (flow_direction[1] == DIRECTION_OUT) {
                  for (idx = 5, add_len = 0; v6_int_template_out.r[idx].handler; idx++) {
                    elem_len = v6_int_template_out.r[idx].handler(ftoft_ptr_1, flow, 1, v6_int_template_out.r[idx].length);
		    nf_flow_to_flowset_inc_len(&ftoft_ptr_1, &add_len, v6_int_template_out.r[idx].length, elem_len);
                  }
                  freclen_1 = v6_int_template_out.tot_rec_len;

                  for (idx = 0; v6_pen_int_template_out.r[idx].handler; idx++) {
                    elem_len = v6_pen_int_template_out.r[idx].handler(ftoft_ptr_1, flow, 1, v6_pen_int_template_out.r[idx].length);
		    nf_flow_to_flowset_inc_len(&ftoft_ptr_1, &add_len, v6_pen_int_template_out.r[idx].length, elem_len);
                  }
                  freclen_1 += (v6_pen_int_template_out.tot_rec_len + add_len);
		}
                break;
          default:
                return (-1);
          }
	}

	if (flow->octets[0] > 0 && direction == flow_direction[0]) {
		if (ret_len + freclen_0 > len)
			return (-1);
		memcpy(packet + ret_len, ftoft_buf_0, freclen_0);
		ret_len += freclen_0;
		nflows++;
	}
	if (flow->octets[1] > 0 && direction == flow_direction[1]) {
		if (ret_len + freclen_1 > len)
			return (-1);
		memcpy(packet + ret_len, ftoft_buf_1, freclen_1);
		ret_len += freclen_1;
		nflows++;
	}

	*len_used = ret_len;
	return (nflows);
}

static int
nf_sampling_option_to_flowset(u_char *packet, u_int len, const struct timeval *system_boot_time, u_int *len_used)
{
        u_int freclen, ret_len, nflows;
        u_int32_t rec32 = 0;
        u_int8_t rec8;
        char *ftoft_ptr_0 = ftoft_buf_0;

        bzero(ftoft_buf_0, sizeof(ftoft_buf_0));
        *len_used = nflows = ret_len = 0;

        /* NF9_OPT_SCOPE_SYSTEM */
        switch (config.nfprobe_source_ha.family) {
        case AF_INET:
          memcpy(ftoft_ptr_0, &config.nfprobe_source_ha.address.ipv4, 4);
          ftoft_ptr_0 += 4;
          break;
        case AF_INET6:
          memcpy(ftoft_ptr_0, &config.nfprobe_source_ha.address.ipv6, 16);
          ftoft_ptr_0 += 16;
          break;
        default:
          memset(ftoft_ptr_0, 0, 4);
          ftoft_ptr_0 += 4;
          break;
	}

        rec8 = 1; /* NF9_FLOW_SAMPLER_ID */ 
        memcpy(ftoft_ptr_0, &rec8, 1);
        ftoft_ptr_0 += 1;

        rec8 = 0x02; /* NF9_FLOW_SAMPLER_MODE */
        memcpy(ftoft_ptr_0, &rec8, 1);
        ftoft_ptr_0 += 1;

	if (config.sampling_rate)
          rec32 = htonl(config.sampling_rate); /* NF9_FLOW_SAMPLER_INTERVAL */
	else if (config.ext_sampling_rate)
          rec32 = htonl(config.ext_sampling_rate); /* NF9_FLOW_SAMPLER_INTERVAL */
        memcpy(ftoft_ptr_0, &rec32, 4);
        ftoft_ptr_0 += 4;

	freclen = sampling_option_int_template.tot_rec_len;

	if (ret_len + freclen > len)
		return (-1);

	memcpy(packet + ret_len, ftoft_buf_0, freclen);
	ret_len += freclen;
	nflows++;

        *len_used = ret_len;
        return (nflows);
}

static int
nf_class_option_to_flowset(u_int idx, u_char *packet, u_int len, const struct timeval *system_boot_time, u_int *len_used)
{
	u_int freclen, ret_len, nflows;
        char *ftoft_ptr_0 = ftoft_buf_0;

        bzero(ftoft_buf_0, sizeof(ftoft_buf_0));
        *len_used = nflows = ret_len = 0;

        /* NF9_OPT_SCOPE_SYSTEM */
        switch (config.nfprobe_source_ha.family) {
        case AF_INET:
          memcpy(ftoft_ptr_0, &config.nfprobe_source_ha.address.ipv4, 4);
          ftoft_ptr_0 += 4;
          break;
        case AF_INET6:
          memcpy(ftoft_ptr_0, &config.nfprobe_source_ha.address.ipv6, 16);
          ftoft_ptr_0 += 16;
          break;
        default:
          memset(ftoft_ptr_0, 0, 4);
          ftoft_ptr_0 += 4;
          break;
        }

        /* NF9_FLOW_APPLICATION_ID (ClassID) */
        {
	  u_int8_t ie95_classId = 0x16; /* nDPI */

          memcpy(ftoft_ptr_0, &ie95_classId, 1);
          ftoft_ptr_0 += 1;
        }

        /* NF9_FLOW_APPLICATION_ID (SelectID) */
        {
	  u_int32_t ie95_selectId = htonl(class[idx].id);

	  memcpy(ftoft_ptr_0, &ie95_selectId, 4);
          ftoft_ptr_0 += 4;
	}

        /* NF9_FLOW_APPLICATION_NAME */
        strlcpy(ftoft_ptr_0, class[idx].protocol, MAX_PROTOCOL_LEN);
        ftoft_ptr_0 += MAX_PROTOCOL_LEN;

        freclen = class_option_int_template.tot_rec_len;

        if (ret_len + freclen > len)
          return (-1);

        memcpy(packet + ret_len, ftoft_buf_0, freclen);

        ret_len += freclen;
        nflows++;

        *len_used = ret_len;
        return (nflows);
}

static int
nf_exporter_option_to_flowset(u_char *packet, u_int len, const struct timeval *system_boot_time, u_int *len_used)
{
  u_int freclen, ret_len, nflows;
  char *ftoft_ptr_0 = ftoft_buf_0;

  memset(ftoft_buf_0, 0, sizeof(ftoft_buf_0));
  *len_used = nflows = ret_len = 0;

  /* NF9_OPT_SCOPE_SYSTEM */
  switch (config.nfprobe_source_ha.family) {
  case AF_INET:
    memcpy(ftoft_ptr_0, &config.nfprobe_source_ha.address.ipv4, 4);
    ftoft_ptr_0 += 4;
    break;
  case AF_INET6:
    memcpy(ftoft_ptr_0, &config.nfprobe_source_ha.address.ipv6, 16);
    ftoft_ptr_0 += 16;
    break;
  default:
    memset(ftoft_ptr_0, 0, 4);
    ftoft_ptr_0 += 4;
    break;
  }

  switch (config.nfprobe_source_ha.family) {
  /* NF9_EXPORTER_IPV4_ADDRESS */
  case AF_INET:
    memcpy(ftoft_ptr_0, &config.nfprobe_source_ha.address.ipv4, 4);
    ftoft_ptr_0 += 4;

    memset(ftoft_ptr_0, 0, 16);
    ftoft_ptr_0 += 16;

    break;
  /* NF9_EXPORTER_IPV6_ADDRESS */
  case AF_INET6:
    memset(ftoft_ptr_0, 0, 4);
    ftoft_ptr_0 += 4;

    memcpy(ftoft_ptr_0, &config.nfprobe_source_ha.address.ipv6, 16);
    ftoft_ptr_0 += 16;

    break;
  default:
    memset(ftoft_ptr_0, 0, 4);
    ftoft_ptr_0 += 4;

    memset(ftoft_ptr_0, 0, 16);
    ftoft_ptr_0 += 16;

    break;
  }

  freclen = exporter_option_int_template.tot_rec_len;

  if (ret_len + freclen > len) return (ERR);

  memcpy(packet + ret_len, ftoft_buf_0, freclen);
  ret_len += freclen;
  nflows++;

  *len_used = ret_len;
  return (nflows);
}

/*
 * Given an array of expired flows, send netflow v9 report packets
 * Returns number of packets sent or -1 on error
 */
int
send_netflow_v9(struct FLOW **flows, int num_flows, int nfsock, void *dtls,
    u_int64_t *flows_exported, struct timeval *system_boot_time,
    int verbose_flag, u_int8_t unused, u_int32_t source_id)
{
	struct NF9_HEADER *nf9;
	struct IPFIX_HEADER *nf10;
	struct NF9_DATA_FLOWSET_HEADER *dh;
	struct timeval now;
	u_int offset, last_af, flow_j, num_packets, inc, last_valid;
	u_int num_class, class_j;
	int direction, new_direction;
	socklen_t errsz;
	int err, r, flow_i, class_i, ret;

#ifdef WITH_GNUTLS
        pm_dtls_peer_t *dtls_peer = dtls;
#endif

	memset(packet, 0, sizeof(packet));
	gettimeofday(&now, NULL);

	if (nf9_pkts_until_template == -1) {
		nf9_init_template();
		nf9_init_options_template();
		nf9_pkts_until_template = 0;
	}		

        
        offset = 0;
        r = 0;
	num_packets = 0;
	num_class = pmct_find_first_free(); 

	for (direction = DIRECTION_IN; direction <= DIRECTION_OUT; direction++) {
	  last_valid = 0; new_direction = TRUE;

	  for (flow_j = 0, class_j = 0; flow_j < num_flows;) {
		bzero(packet, sizeof(packet));
		if (config.nfprobe_version == 9) {
		  nf9 = (struct NF9_HEADER *)packet;

		  nf9->version = htons(9);
		  nf9->flows = 0; /* Filled as we go, htons at end */
		  nf9->uptime_ms = htonl(timeval_sub_ms(&now, system_boot_time));
		  nf9->time_sec = htonl(time(NULL));
		  nf9->package_sequence = htonl(++(*flows_exported));
		  nf9->source_id = htonl(source_id);

		  offset = sizeof(*nf9);
		}
		else if (config.nfprobe_version == 10) {
                  nf10 = (struct IPFIX_HEADER *)packet;

                  nf10->version = htons(10);
                  nf10->len = 0;
                  nf10->time_sec = htonl(time(NULL));
                  nf10->package_sequence = htonl(*flows_exported);
                  nf10->source_id = htonl(source_id);

                  offset = sizeof(*nf10);
		}

		/* Refresh template headers if we need to */
		if (nf9_pkts_until_template <= 0) {
			u_int16_t flows = 0, tot_len = 0;

			memcpy(packet + offset, &v4_template, v4_template.tot_len);
			offset += v4_template.tot_len;
			memcpy(packet + offset, &v4_pen_template, v4_pen_template.tot_len);
			offset += v4_pen_template.tot_len;
			flows++;
			tot_len += v4_template.tot_len + v4_pen_template.tot_len;

                        memcpy(packet + offset, &v4_template_out, v4_template_out.tot_len);
                        offset += v4_template_out.tot_len;
                        memcpy(packet + offset, &v4_pen_template_out, v4_pen_template_out.tot_len);
                        offset += v4_pen_template_out.tot_len;
                        flows++;
			tot_len += v4_template_out.tot_len + v4_pen_template_out.tot_len;
			memcpy(packet + offset, &v6_template, v6_template.tot_len);
			offset += v6_template.tot_len; 
			memcpy(packet + offset, &v6_pen_template, v6_pen_template.tot_len);
			offset += v6_pen_template.tot_len; 
			flows++;
			tot_len += v6_template.tot_len + v6_pen_template.tot_len; 

                        memcpy(packet + offset, &v6_template_out, v6_template_out.tot_len);
                        offset += v6_template_out.tot_len;
                        memcpy(packet + offset, &v6_pen_template_out, v6_pen_template_out.tot_len);
                        offset += v6_pen_template_out.tot_len;
                        flows++;
			tot_len += v6_template_out.tot_len + v6_pen_template_out.tot_len; 

			if (config.sampling_rate || config.ext_sampling_rate) {
                          memcpy(packet + offset, &sampling_option_template, sampling_option_template.tot_len);
                          offset += sampling_option_template.tot_len;
			  flows++;
			  tot_len += sampling_option_template.tot_len; 
			  send_options = TRUE;
			  send_sampling_option = TRUE;
			}
			if (((config.nfprobe_what_to_count & COUNT_CLASS)
#if defined (WITH_NDPI) 
			    || (config.nfprobe_what_to_count_2 & COUNT_NDPI_CLASS)
#endif
			    ) && num_class > 0) {
                          memcpy(packet + offset, &class_option_template, class_option_template.tot_len);
                          offset += class_option_template.tot_len;
                          flows++;
			  tot_len += class_option_template.tot_len;
			  send_options = TRUE;
			  send_options = TRUE;
                          send_class_option = TRUE;
			}
                        if (config.nfprobe_source_ip) {
                          memcpy(packet + offset, &exporter_option_template, exporter_option_template.tot_len);
                          offset += exporter_option_template.tot_len;
                          flows++;
                          tot_len += exporter_option_template.tot_len;
                          send_options = TRUE;
                          send_exporter_option = TRUE;
                        }
			nf9_pkts_until_template = NF9_DEFAULT_TEMPLATE_INTERVAL;

			if (config.nfprobe_version == 9) nf9->flows = flows;
		}

		dh = NULL;
		last_af = 0;
		for (flow_i = 0, class_i = 0; flow_i + flow_j < num_flows; flow_i++) {
			/* Shall we send a new flowset header? */
			if (dh == NULL || (!send_options && (flows[flow_i + flow_j]->af != last_af || new_direction)) ||
			    send_sampling_option || send_exporter_option || (send_class_option && !class_i) ) {
				if (dh != NULL) {
					if (offset % 4 != 0) {
						/* Pad to multiple of 4 */
						dh->c.length += 4 - (offset % 4);
						offset += 4 - (offset % 4);
					}
					/* Finalise last header */
					dh->c.length = htons(dh->c.length);
				}
				if (offset + sizeof(*dh) > sizeof(packet)) {
					/* Mark header is finished */
					dh = NULL;
					break;
				}
				dh = (struct NF9_DATA_FLOWSET_HEADER *)
				    (packet + offset);
				if (send_options) {
				  if (send_sampling_option) {
				    dh->c.flowset_id = sampling_option_template.h.template_id;
				    // last_af = 0; new_direction = TRUE;
				  }
				  else if (send_class_option) {
				    dh->c.flowset_id = class_option_template.h.template_id;
				    // last_af = 0; new_direction = TRUE;
				  }
				  else if (send_exporter_option) {
				    dh->c.flowset_id = exporter_option_template.h.template_id;
				    // last_af = 0; new_direction = TRUE;
				  }
				}
				else {
				  if (flows[flow_i + flow_j]->af == AF_INET) {
				    if (direction == DIRECTION_IN)
				      dh->c.flowset_id = v4_template.h.template_id;
				    else if (direction == DIRECTION_OUT)
				      dh->c.flowset_id = v4_template_out.h.template_id;
				  }
				  else if (flows[flow_i + flow_j]->af == AF_INET6) {
				    if (direction == DIRECTION_IN)
				      dh->c.flowset_id = v6_template.h.template_id;
				    else if (direction == DIRECTION_OUT)
				      dh->c.flowset_id = v6_template_out.h.template_id;
				  }
				  // last_af = flows[flow_i + flow_j]->af; /* XXX */
				}
				last_valid = offset;
				new_direction = FALSE;
				dh->c.length = sizeof(*dh); /* Filled as we go */
				offset += sizeof(*dh);
			}

			/* Send flowset data over */
			if (send_options) {
			  if (send_sampling_option) {
                            r = nf_sampling_option_to_flowset((u_char *)(packet + offset),
                              sizeof(packet) - offset, system_boot_time, &inc);
			    send_sampling_option = FALSE;
			  }
			  else if (send_class_option) {
                            r = nf_class_option_to_flowset(class_i + class_j, (u_char *)(packet + offset),
                              sizeof(packet) - offset, system_boot_time, &inc);

			    if (r > 0) class_i += r;
			    if (class_i + class_j >= num_class) send_class_option = FALSE;
			  }
			  else if (send_exporter_option) {
                            r = nf_exporter_option_to_flowset((u_char *)(packet + offset),
                              sizeof(packet) - offset, system_boot_time, &inc);
			    send_exporter_option = FALSE;
			  }
			}
			else 
			  r = nf_flow_to_flowset(flows[flow_i + flow_j], (u_char *)(packet + offset),
			    sizeof(packet) - offset, system_boot_time, &inc, direction);

			/* Wrap up */
			if (r <= 0) {
				/* yank off data header, if we had to go back */
				if (last_valid)
				  offset = last_valid;
				if (r < 0) break;
			}
			else {
			  offset += inc;
			  dh->c.length += inc;

			  if (config.nfprobe_version == 9) nf9->flows += r;
			  else if (config.nfprobe_version == 10) *flows_exported += r;

			  last_valid = 0; /* Don't clobber this header now */
			  if (verbose_flag) {
			    if (config.nfprobe_version == 9) {
			      Log(LOG_DEBUG, "DEBUG ( %s/%s ): Building NetFlow v9 packet: offset = %d, template ID = %d, total len = %d, # elements = %d\n", 
				 config.name, config.type, offset, ntohs(dh->c.flowset_id), dh->c.length, nf9->flows);
			    }
			    else if (config.nfprobe_version == 10) {
                              Log(LOG_DEBUG, "DEBUG ( %s/%s ): Building IPFIX packet: offset = %d, template ID = %d, total len = %d\n",
                                 config.name, config.type, offset, ntohs(dh->c.flowset_id), dh->c.length);
			    }
			  }

			  if (send_options) {
			    if (!send_sampling_option &&
				!send_class_option &&
				!send_exporter_option) {
			      send_options = FALSE;
			    }
			    flow_i--;
			  }
			  else last_af = flows[flow_i + flow_j]->af; /* XXX */
			}
		}
		/* Don't finish header if it has already been done */
		if (dh != NULL) {
			if (offset % 4 != 0) {
				/* Pad to multiple of 4 */
				dh->c.length += 4 - (offset % 4);
				offset += 4 - (offset % 4);
			}
			/* Finalise last header */
			dh->c.length = htons(dh->c.length);
		}
		if ((config.nfprobe_version == 9 && nf9->flows > 0) ||
		    (config.nfprobe_version == 10 && offset > 20)) { /* 20: IPFIX header + IPFIX Flowset header */ 

		  if (config.nfprobe_version == 9) nf9->flows = htons(nf9->flows);
		  else if (config.nfprobe_version == 10) nf10->len = htons(offset);

		  if (verbose_flag)
		    Log(LOG_DEBUG, "DEBUG ( %s/%s ): Sending NetFlow v9/IPFIX packet: len = %d\n", config.name, config.type, offset);
		  errsz = sizeof(err);
		  /* Clear ICMP errors */
		  getsockopt(nfsock, SOL_SOCKET, SO_ERROR, &err, &errsz); 

		  if (!config.nfprobe_dtls) {
		    ret = send(nfsock, packet, (size_t)offset, 0);

		    if (ret == ERR) {
		      Log(LOG_WARNING, "WARN ( %s/%s ): send() failed: %s\n", config.name, config.type, strerror(errno));
		      return ret;
		    }
		  }
#ifdef WITH_GNUTLS
		  else {
		    ret = pm_dtls_client_send(dtls_peer, packet, (size_t)offset);
		    if (ret < 0) return ret;
		  }
#endif

		  num_packets++;
		  nf9_pkts_until_template--;
		}
		else {
		  if (config.nfprobe_version == 9) --(*flows_exported);
		}

		class_j += class_i;
		flow_j += flow_i;
	  }
	}

	return (num_packets);
}
