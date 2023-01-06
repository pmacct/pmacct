/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2023 by Paolo Lucente
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

#ifndef NFV9_TEMPLATE_H
#define NFV9_TEMPLATE_H

#define IPFIX_TPL_EBIT                  0x8000 /* IPFIX telmplate enterprise bit */
#define IPFIX_VARIABLE_LENGTH           65535

/* PENs */
#define HUAWEI_PEN                      2011
#define PMACCT_PEN                      43874

/* NetFlow V9 stuff */
#define NF9_TEMPLATE_FLOWSET_ID         0
#define NF9_OPTIONS_FLOWSET_ID          1
#define NF9_MIN_RECORD_FLOWSET_ID       256
#define NF9_MAX_DEFINED_FIELD           384

#define TEMPLATE_CACHE_ENTRIES          1021
#define IES_PER_TPL_EXT_DB_ENTRY        32
#define TPL_EXT_DB_ENTRIES              8
#define TPL_LIST_ENTRIES                256
#define TPL_TYPE_LEGACY                 0
#define TPL_TYPE_EXT_DB                 1

/* Flowset record types we care about */
#define NF9_IN_BYTES                    1
#define NF9_IN_PACKETS                  2
#define NF9_FLOWS                       3
#define NF9_L4_PROTOCOL                 4
#define NF9_SRC_TOS                     5
#define NF9_TCP_FLAGS                   6
#define NF9_L4_SRC_PORT                 7
#define NF9_IPV4_SRC_ADDR               8
#define NF9_SRC_MASK                    9
#define NF9_INPUT_SNMP                  10
#define NF9_L4_DST_PORT                 11
#define NF9_IPV4_DST_ADDR               12
#define NF9_DST_MASK                    13
#define NF9_OUTPUT_SNMP                 14
#define NF9_IPV4_NEXT_HOP               15
#define NF9_SRC_AS                      16
#define NF9_DST_AS                      17
#define NF9_BGP_IPV4_NEXT_HOP           18
#define NF9_MUL_DST_PKTS                19
#define NF9_MUL_DST_BYTES               20
/* ... */
#define NF9_LAST_SWITCHED               21
#define NF9_FIRST_SWITCHED              22
#define NF9_OUT_BYTES                   23
#define NF9_OUT_PACKETS                 24
/* ... */
#define NF9_IPV6_SRC_ADDR               27
#define NF9_IPV6_DST_ADDR               28
#define NF9_IPV6_SRC_MASK               29
#define NF9_IPV6_DST_MASK               30
#define NF9_IPV6_FLOW_LABEL             31
#define NF9_ICMP_TYPE                   32
/* ... */
#define NF9_ENGINE_TYPE                 38
#define NF9_ENGINE_ID                   39
/* ... */
#define NF9_IPV4_SRC_PREFIX             44
#define NF9_IPV4_DST_PREFIX             45
/* ... */
#define NF9_MPLS_TOP_LABEL_ADDR         47
/* ... */
#define NF9_IN_SRC_MAC                  56
#define NF9_OUT_DST_MAC                 57
#define NF9_IN_VLAN                     58
#define NF9_OUT_VLAN                    59
#define NF9_IP_PROTOCOL_VERSION         60
#define NF9_DIRECTION                   61
#define NF9_IPV6_NEXT_HOP               62
#define NF9_BGP_IPV6_NEXT_HOP           63
/* ... */
#define NF9_MPLS_LABEL_1                70
#define NF9_MPLS_LABEL_2                71
#define NF9_MPLS_LABEL_3                72
#define NF9_MPLS_LABEL_4                73
#define NF9_MPLS_LABEL_5                74
#define NF9_MPLS_LABEL_6                75
#define NF9_MPLS_LABEL_7                76
#define NF9_MPLS_LABEL_8                77
#define NF9_MPLS_LABEL_9                78
#define NF9_MPLS_LABEL_10               79
#define NF9_IN_DST_MAC                  80
#define NF9_OUT_SRC_MAC                 81
/* ... */
#define NF9_FLOW_BYTES                  85
#define NF9_FLOW_PACKETS                86
/* ... */
#define NF9_FWD_STATUS                  89
#define NF9_MPLS_VPN_RD                 90
/* ... */
#define NF9_LAYER2_PKT_SECTION_DATA     104
/* ... */
#define NF9_PEER_DST_AS                 128
#define NF9_PEER_SRC_AS                 129
#define NF9_EXPORTER_IPV4_ADDRESS       130
#define NF9_EXPORTER_IPV6_ADDRESS       131
/* ... */
#define NF9_MPLS_TOP_LABEL_IPV6_ADDR    140
/* ... */
#define NF9_FIRST_SWITCHED_SEC          150
#define NF9_LAST_SWITCHED_SEC           151
#define NF9_FIRST_SWITCHED_MSEC         152
#define NF9_LAST_SWITCHED_MSEC          153
#define NF9_FIRST_SWITCHED_USEC         154
#define NF9_LAST_SWITCHED_USEC          155
/* ... */
#define NF9_FIRST_SWITCHED_DELTA_MICRO  158
#define NF9_LAST_SWITCHED_DELTA_MICRO   159
#define NF9_SYS_UPTIME_MSEC             160
/* ... */
#define NF9_IPV6_DST_PREFIX             169
#define NF9_IPV6_SRC_PREFIX             170
/* ... */
#define NF9_UDP_SRC_PORT                180
#define NF9_UDP_DST_PORT                181
#define NF9_TCP_SRC_PORT                182
#define NF9_TCP_DST_PORT                183
/* ... */
#define NF9_POST_NAT_IPV4_SRC_ADDR      225
#define NF9_POST_NAT_IPV4_DST_ADDR      226
#define NF9_POST_NAT_IPV4_SRC_PORT      227
#define NF9_POST_NAT_IPV4_DST_PORT      228
/* ... */
#define NF9_NAT_EVENT                   230
/* ... */
#define NF9_INITIATOR_OCTETS            231
#define NF9_RESPONDER_OCTETS            232
#define NF9_FW_EVENT                    233
#define NF9_INGRESS_VRFID               234
#define NF9_EGRESS_VRFID                235
/* ... */
#define NF9_DOT1QVLANID                 243
#define NF9_DOT1QPRIORITY               244
#define NF9_DOT1QCVLANID                245
/* ... */
#define NF9_PSEUDOWIREID                249
/* ... */
#define NF9_INPUT_PHYSINT               252
#define NF9_OUTPUT_PHYSINT              253
#define NF9_POST_DOT1QVLANID            254
#define NF9_POST_DOT1QCVLANID           255
#define NF9_ETHERTYPE                   256
/* ... */
#define NF9_DATALINK_FRAME_SECTION      315
/* ... */
#define NF9_OBSERVATION_TIME_SEC        322
#define NF9_OBSERVATION_TIME_MSEC       323
/* ... */
#define NF9_LAYER2_SEGMENT_ID           351
#define NF9_LAYER2OCTETDELTACOUNT       352
/* ... */
#define NF9_staMacAddress               365
#define NF9_staIPv4Address              366
/* ... */
#define NF9_DATALINK_FRAME_TYPE         408
/* ... */
#define NF9_srhSegmentIPv6ListSection   505
/* ... */
#define NF9_ASA_XLATE_IPV4_SRC_ADDR     40001
#define NF9_ASA_XLATE_IPV4_DST_ADDR     40002
#define NF9_ASA_XLATE_L4_SRC_PORT       40003
#define NF9_ASA_XLATE_L4_DST_PORT       40004
#define NF9_ASA_XLATE_EVENT             40005

/* Sampling */
#define NF9_SAMPLING_INTERVAL           34
#define NF9_SAMPLING_ALGORITHM          35
#define NF9_FLOW_SAMPLER_ID             48
#define NF9_FLOW_SAMPLER_MODE           49
#define NF9_FLOW_SAMPLER_INTERVAL       50
#define NF9_SELECTOR_ID                 302
#define NF9_SELECTOR_ALGORITHM          304
#define NF9_SAMPLING_PKT_INTERVAL       305
#define NF9_SAMPLING_PKT_SPACE          306

/* Classification */
#define NF9_APPLICATION_DESC            94
#define NF9_APPLICATION_ID              95
#define NF9_APPLICATION_NAME            96

/* Options scoping: NetFlow v9 */
#define NF9_OPT_SCOPE_SYSTEM            1
#define NF9_OPT_SCOPE_IF                2
#define NF9_OPT_SCOPE_LC                3
#define NF9_OPT_SCOPE_CACHE             4
#define NF9_OPT_SCOPE_TPL               5

/* Options scoping: IPFIX */
#define IPFIX_SCOPE_OBS_POINT_ID        138
#define IPFIX_SCOPE_LINECARD_ID         141
#define IPFIX_SCOPE_PORT_ID             142
#define IPFIX_SCOPE_METER_PROCESS_ID    143
#define IPFIX_SCOPE_EXPORT_PROCESS_ID   144
#define IPFIX_SCOPE_TEMPLATE_ID         145
#define IPFIX_SCOPE_OBS_DOMAIN_ID       149

/* dataLinkFrameType */
#define NF9_DL_F_TYPE_UNKNOWN           0
#define NF9_DL_F_TYPE_ETHERNET          1
#define NF9_DL_F_TYPE_802DOT11          2

/* layer2SegmentId */
#define NF9_L2_SID_RESERVED             0x00
#define NF9_L2_SID_VXLAN                0x01
#define NF9_L2_SID_NVGRE                0x02

/* CUSTOM TYPES START HERE: supported in IPFIX only with pmacct PEN */
#define NF9_CUST_TAG                    1
#define NF9_CUST_TAG2                   2
#define NF9_CUST_LABEL                  3
/* CUSTOM TYPES END HERE */

/* NetFlow Export version 9 */
struct template_field_v9 {
  u_int16_t type;
  u_int16_t len;
};

struct template_hdr_v9 {
  u_int16_t template_id;
  u_int16_t num;
};

struct options_template_hdr_v9 {
  u_int16_t template_id;
  u_int16_t scope_len;
  u_int16_t option_len;
};

/* Ordered Template field */
struct otpl_field {
  u_int16_t off;
  u_int16_t len;
  u_int16_t tpl_len;
};

/* Unsorted Template field */
struct utpl_field {
  u_int32_t pen;
  u_int16_t type;
  u_int16_t off;
  u_int16_t len;
  u_int16_t tpl_len;
  u_int8_t repeat_id;
};

/* Template field database */
struct tpl_field_db {
  struct utpl_field ie[IES_PER_TPL_EXT_DB_ENTRY];
};

/* Template field ordered list */
struct tpl_field_list {
  u_int8_t type;
  char *ptr;
};

struct template_cache_entry {
  struct host_addr agent;               /* NetFlow Exporter agent */
  u_int32_t source_id;                  /* Exporter Observation Domain */
  u_int16_t template_id;                /* template ID */
  u_int16_t template_type;              /* Data = 0, Options = 1 */
  u_int16_t num;                        /* number of fields described into template */
  u_int16_t len;                        /* total length of the described flowset */
  u_int8_t vlen;                        /* flag for variable-length fields */
  struct otpl_field tpl[NF9_MAX_DEFINED_FIELD];
  struct tpl_field_db ext_db[TPL_EXT_DB_ENTRIES];
  struct tpl_field_list list[TPL_LIST_ENTRIES];
  struct template_cache_entry *next;
};

/* functions */
extern void init_template_cache(void);
extern int init_template_cache_v2(void);
extern struct template_cache_entry *find_template(u_int16_t, struct sockaddr *, u_int16_t, u_int32_t);
extern struct template_cache_entry *handle_template(struct template_hdr_v9 *, struct packet_ptrs *, u_int16_t, u_int32_t, u_int16_t *, u_int16_t, u_int32_t);
extern struct template_cache_entry *handle_template_v2(struct template_hdr_v9 *, struct packet_ptrs *, u_int16_t, u_int32_t, u_int16_t *, u_int16_t, u_int32_t);
extern int resolve_vlen_template(u_char *, u_int16_t, struct template_cache_entry *);
extern void load_templates_from_file(char *);
extern u_int16_t calc_template_keylen(void);
extern struct utpl_field *ext_db_get_ie(struct template_cache_entry *, u_int32_t, u_int16_t, u_int8_t);
extern void notify_malf_packet(short int, char *, char *, struct sockaddr *, u_int32_t);

#endif // NFV9_TEMPLATE_H
