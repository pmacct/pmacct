/*  
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2021 by Paolo Lucente
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
#ifndef NFACCTD_H
#define NFACCTD_H

/*  NetFlow Export Version 5 Header Format  */
struct struct_header_v5 {
  u_int16_t version;		/* Version = 5 */
  u_int16_t count;		/* The number of records in PDU. */
  u_int32_t SysUptime;		/* Current time in msecs since router booted */
  u_int32_t unix_secs;		/* Current seconds since 0000 UTC 1970 */
  u_int32_t unix_nsecs;		/* Residual nanoseconds since 0000 UTC 1970 */
  u_int32_t flow_sequence;	/* Sequence number of total flows seen */
  unsigned char engine_type;    /* Type of flow switching engine (RP,VIP,etc.) */
  unsigned char engine_id;      /* Slot number of the flow switching engine */
  u_int16_t sampling;
};

/*  NetFlow Export Version 9 Header Format  */
struct struct_header_v9 {
  u_int16_t version;		/* version = 9 */
  u_int16_t count;		/* The number of records in PDU. */
  u_int32_t SysUptime;		/* Current time in msecs since router booted */
  u_int32_t unix_secs;		/* Current seconds since 0000 UTC 1970 */
  u_int32_t flow_sequence;	/* Sequence number of total flows seen */
  u_int32_t source_id;		/* Source id */
};

struct struct_header_ipfix {
  u_int16_t version;            /* version = 10 */
  u_int16_t len;                /* Total length of the IPFIX Message */
  u_int32_t unix_secs;          /* Current seconds since 0000 UTC 1970 */
  u_int32_t flow_sequence;      /* Sequence number of total flows seen */
  u_int32_t source_id;          /* Source id */
};

/* NetFlow Export version 5 */
struct struct_export_v5 {
  struct in_addr srcaddr;       /* Source IP Address */
  struct in_addr dstaddr;       /* Destination IP Address */
  struct in_addr nexthop;       /* Next hop router's IP Address */
  u_int16_t input;   		/* Input interface index */
  u_int16_t output;  		/* Output interface index */
  u_int32_t dPkts;    		/* Packets sent in Duration (milliseconds between 1st & last packet in this flow) */
  u_int32_t dOctets;  		/* Octets sent in Duration (milliseconds between 1st & last packet in this flow) */
  u_int32_t First;    		/* SysUptime at start of flow */
  u_int32_t Last;     		/* and of last packet of the flow */
  u_int16_t srcport; 		/* TCP/UDP source port number (.e.g, FTP, Telnet, etc.,or equivalent) */
  u_int16_t dstport; 		/* TCP/UDP destination port number (.e.g, FTP, Telnet, etc.,or equivalent) */
  unsigned char pad;          	/* pad to word boundary */
  unsigned char tcp_flags;    	/* Cumulative OR of tcp flags */
  unsigned char prot;         	/* IP protocol, e.g., 6=TCP, 17=UDP, etc... */
  unsigned char tos;          	/* IP Type-of-Service */
  u_int16_t src_as;  		/* source peer/origin Autonomous System */
  u_int16_t dst_as;  		/* dst peer/origin Autonomous System */
  unsigned char src_mask;       /* source route's mask bits */ 
  unsigned char dst_mask;       /* destination route's mask bits */
  u_int16_t pad_1;   		/* pad to word boundary */
};

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

/* IPFIX: option field count and scope field count apparently inverted compared to NetFlow v9 */
struct options_template_hdr_ipfix {
  u_int16_t template_id;
  u_int16_t option_count;
  u_int16_t scope_count;
};

struct data_hdr_v9 {
  u_int16_t flow_id; /* == 0: template; == 1: options template; >= 256: data */
  u_int16_t flow_len;
};

/* defines */
#define DEFAULT_NFACCTD_PORT 2100
#define NETFLOW_MSG_SIZE PKT_MSG_SIZE
#define V5_MAXFLOWS 30  /* max records in V5 packet */
#define TEMPLATE_CACHE_ENTRIES 1021

#define NF_TIME_MSECS 0 /* times are in msecs */
#define NF_TIME_SECS 1 /* times are in secs */ 
#define NF_TIME_NEW 2 /* ignore netflow engine times and generate new ones */ 

#define IPFIX_TPL_EBIT                  0x8000 /* IPFIX telmplate enterprise bit */
#define IPFIX_VARIABLE_LENGTH           65535
#define PMACCT_PEN                      43874

/* NetFlow V9 stuff */
#define NF9_TEMPLATE_FLOWSET_ID         0
#define NF9_OPTIONS_FLOWSET_ID          1
#define NF9_MIN_RECORD_FLOWSET_ID       256
#define NF9_MAX_DEFINED_FIELD		384

#define IES_PER_TPL_EXT_DB_ENTRY        32
#define TPL_EXT_DB_ENTRIES              8
#define TPL_LIST_ENTRIES                256
#define TPL_TYPE_LEGACY                 0
#define TPL_TYPE_EXT_DB                 1

/* Flowset record types the we care about */
#define NF9_IN_BYTES			1
#define NF9_IN_PACKETS			2
#define NF9_FLOWS			3
#define NF9_L4_PROTOCOL			4
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
#define NF9_BGP_IPV4_NEXT_HOP		18
#define NF9_MUL_DST_PKTS                19
#define NF9_MUL_DST_BYTES               20
/* ... */
#define NF9_LAST_SWITCHED               21
#define NF9_FIRST_SWITCHED              22
#define NF9_OUT_BYTES			23
#define NF9_OUT_PACKETS			24
/* ... */
#define NF9_IPV6_SRC_ADDR               27
#define NF9_IPV6_DST_ADDR               28
#define NF9_IPV6_SRC_MASK               29
#define NF9_IPV6_DST_MASK               30
#define NF9_ICMP_TYPE                   32
/* ... */
#define NF9_ENGINE_TYPE                 38
#define NF9_ENGINE_ID                   39
/* ... */
#define NF9_IPV4_SRC_PREFIX		44
#define NF9_IPV4_DST_PREFIX		45
/* ... */
#define NF9_MPLS_TOP_LABEL_ADDR		47
/* ... */
#define NF9_IN_SRC_MAC                  56
#define NF9_OUT_DST_MAC                 57
#define NF9_IN_VLAN                     58
#define NF9_OUT_VLAN                    59
#define NF9_IP_PROTOCOL_VERSION         60
#define NF9_DIRECTION                   61
#define NF9_IPV6_NEXT_HOP		62
#define NF9_BGP_IPV6_NEXT_HOP		63
/* ... */
#define NF9_MPLS_LABEL_1		70
#define NF9_MPLS_LABEL_2		71
#define NF9_MPLS_LABEL_3		72
#define NF9_MPLS_LABEL_4		73
#define NF9_MPLS_LABEL_5		74
#define NF9_MPLS_LABEL_6		75
#define NF9_MPLS_LABEL_7		76
#define NF9_MPLS_LABEL_8		77
#define NF9_MPLS_LABEL_9		78
#define NF9_MPLS_LABEL_10		79
#define NF9_IN_DST_MAC			80 
#define NF9_OUT_SRC_MAC			81 
/* ... */
#define NF9_FLOW_BYTES			85 
#define NF9_FLOW_PACKETS		86 

#define NF9_FORWARDING_STATUS           89
#define NF9_MPLS_VPN_RD			90
/* ... */
#define NF9_LAYER2_PKT_SECTION_DATA	104
/* ... */
#define NF9_PEER_DST_AS			128
#define NF9_PEER_SRC_AS			129
#define NF9_EXPORTER_IPV4_ADDRESS	130
#define NF9_EXPORTER_IPV6_ADDRESS	131
/* ... */
#define NF9_MPLS_TOP_LABEL_IPV6_ADDR	140
/* ... */
#define NF9_FIRST_SWITCHED_SEC		150
#define NF9_LAST_SWITCHED_SEC		151
#define NF9_FIRST_SWITCHED_MSEC		152
#define NF9_LAST_SWITCHED_MSEC		153
#define NF9_FIRST_SWITCHED_USEC		154
#define NF9_LAST_SWITCHED_USEC		155
/* ... */
#define NF9_FIRST_SWITCHED_DELTA_MICRO	158
#define NF9_LAST_SWITCHED_DELTA_MICRO	159
#define NF9_SYS_UPTIME_MSEC		160
/* ... */
#define NF9_IPV6_DST_PREFIX		169
#define NF9_IPV6_SRC_PREFIX		170
/* ... */
#define NF9_UDP_SRC_PORT                180
#define NF9_UDP_DST_PORT                181
#define NF9_TCP_SRC_PORT                182
#define NF9_TCP_DST_PORT                183
/* ... */
#define NF9_POST_NAT_IPV4_SRC_ADDR	225
#define NF9_POST_NAT_IPV4_DST_ADDR	226
#define NF9_POST_NAT_IPV4_SRC_PORT	227
#define NF9_POST_NAT_IPV4_DST_PORT	228
/* ... */
#define NF9_NAT_EVENT			230
/* ... */
#define NF9_INITIATOR_OCTETS		231
#define NF9_RESPONDER_OCTETS		232
/* ... */
#define NF9_INGRESS_VRFID		234
#define NF9_EGRESS_VRFID		235
/* ... */
#define NF9_DOT1QVLANID			243
#define NF9_DOT1QPRIORITY		244
#define NF9_DOT1QCVLANID		245
/* ... */
#define NF9_PSEUDOWIREID		249
/* ... */
#define NF9_INPUT_PHYSINT		252
#define NF9_OUTPUT_PHYSINT		253
#define NF9_POST_DOT1QVLANID		254
#define NF9_POST_DOT1QCVLANID		255
#define NF9_ETHERTYPE			256
/* ... */
#define NF9_DATALINK_FRAME_SECTION	315
/* ... */
#define NF9_OBSERVATION_TIME_SEC	322
#define NF9_OBSERVATION_TIME_MSEC	323
/* ... */
#define NF9_LAYER2_SEGMENT_ID		351
#define NF9_LAYER2OCTETDELTACOUNT	352
/* ... */
#define NF9_DATALINK_FRAME_TYPE		408
/* ... */
#define NF9_ASA_XLATE_IPV4_SRC_ADDR	40001
#define NF9_ASA_XLATE_IPV4_DST_ADDR	40002
#define NF9_ASA_XLATE_L4_SRC_PORT	40003
#define NF9_ASA_XLATE_L4_DST_PORT	40004
#define NF9_ASA_XLATE_EVENT		40005

/* Sampling */
#define NF9_SAMPLING_INTERVAL		34
#define NF9_SAMPLING_ALGORITHM		35
#define NF9_FLOW_SAMPLER_ID		48
#define NF9_FLOW_SAMPLER_MODE		49
#define NF9_FLOW_SAMPLER_INTERVAL	50
#define NF9_SELECTOR_ID			302
#define NF9_SELECTOR_ALGORITHM		304
#define NF9_SAMPLING_PKT_INTERVAL	305
#define NF9_SAMPLING_PKT_SPACE		306

/* Classification */
#define NF9_APPLICATION_DESC		94
#define NF9_APPLICATION_ID		95
#define NF9_APPLICATION_NAME		96

/* Options scoping: NetFlow v9 */
#define NF9_OPT_SCOPE_SYSTEM		1
#define NF9_OPT_SCOPE_IF		2
#define NF9_OPT_SCOPE_LC		3
#define NF9_OPT_SCOPE_CACHE		4
#define NF9_OPT_SCOPE_TPL		5

/* Options scoping: IPFIX */
#define IPFIX_SCOPE_OBS_POINT_ID	138
#define IPFIX_SCOPE_LINECARD_ID		141
#define IPFIX_SCOPE_PORT_ID		142
#define IPFIX_SCOPE_METER_PROCESS_ID	143
#define IPFIX_SCOPE_EXPORT_PROCESS_ID	144
#define IPFIX_SCOPE_TEMPLATE_ID 	145
#define IPFIX_SCOPE_OBS_DOMAIN_ID	149

/* dataLinkFrameType */
#define NF9_DL_F_TYPE_UNKNOWN		0
#define NF9_DL_F_TYPE_ETHERNET		1
#define NF9_DL_F_TYPE_802DOT11		2

/* layer2SegmentId */
#define NF9_L2_SID_RESERVED		0x00
#define NF9_L2_SID_VXLAN		0x01
#define NF9_L2_SID_NVGRE		0x02

/* CUSTOM TYPES START HERE: supported in IPFIX only with pmacct PEN */
#define NF9_CUST_TAG                    1
#define NF9_CUST_TAG2                   2
#define NF9_CUST_LABEL			3
/* CUSTOM TYPES END HERE */

#define MAX_TPL_DESC_LIST 90
static char __attribute__((unused)) *tpl_desc_list[] = {
  "",
  "in bytes",
  "in packets",
  "flows",
  "L4 protocol",
  "tos",
  "tcp flags",
  "L4 src port",
  "IPv4 src addr",
  "IPv4 src mask",
  "input snmp",
  "L4 dst port",
  "IPv4 dst addr",
  "IPv4 dst mask",
  "output snmp",
  "IPv4 next hop",
  "src as",
  "dst as",
  "BGP IPv4 next hop",
  "", "",
  "last switched",
  "first switched",
  "out bytes",
  "out packets",
  "", "",
  "IPv6 src addr",
  "IPv6 dst addr",
  "IPv6 src mask",
  "IPv6 dst mask",
  "",
  "icmp type", 
  "",
  "sampling interval",
  "sampling algorithm",
  "",
  "", "", "", "",
  "", "", "", "",
  "", "", "",
  "sampler ID",
  "sampler mode",
  "sampler interval",
  "", "", "", "",
  "",
  "in src mac",
  "out dst mac",
  "", "",
  "ip version",
  "direction",
  "IPv6 next hop",
  "IPv6 BGP next hop",
  "",
  "", "", "", "",
  "",
  "mpls label 1",
  "mpls label 2",
  "mpls label 3",
  "mpls label 4",
  "mpls label 5",
  "mpls label 6",
  "mpls label 7",
  "mpls label 8",
  "mpls label 9",
  "mpls label 10",
  "in dst mac",
  "out src mac",
  "", "", "", "",
  "", "", "",
  "forwarding status",
  "mpls vpn rd"
};

#define MAX_OPT_TPL_DESC_LIST 100
static char __attribute__((unused)) *opt_tpl_desc_list[] = {
  "",
  "scope", "", "",
  "", "", "",
  "", "", "",
  "", "", "",
  "", "", "",
  "", "", "",
  "", "", "",
  "", "", "",
  "", "", "",
  "", "", "",
  "", "", "",
  "", "", "",
  "", "", "",
  "", "", "",
  "", "", "",
  "", "", "sampler ID",
  "sampler algorithm", "sampler interval", "",
  "", "", "",
  "", "", "",
  "", "", "",
  "", "", "",
  "", "", "",
  "", "", "",
  "", "", "",
  "", "", "",
  "", "", "",
  "", "", "",
  "", "", "sampler name",
  "", "", "",
  "", "", "",
  "", "", "",
  "app desc", "app id", "app name",
  "", "", "",
  ""
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

struct template_cache {
  u_int16_t num;
  struct template_cache_entry *c[TEMPLATE_CACHE_ENTRIES];
};

struct NF_dissect {
  u_int8_t hdrVersion;
  u_int16_t hdrCount; /* NetFlow v5 and v5 and v5 and v5 and v5 and v9 */
  u_char *hdrBasePtr;
  u_char *hdrEndPtr;
  u_int32_t hdrLen;
  u_char *flowSetBasePtr;
  u_char *flowSetEndPtr;
  u_int32_t flowSetLen;
  u_char *elemBasePtr;
  u_char *elemEndPtr;
  u_int32_t elemLen;
};

/* functions */
extern void process_v5_packet(unsigned char *, u_int16_t, struct packet_ptrs *, struct plugin_requests *, u_int16_t, struct NF_dissect *);
extern void process_v9_packet(unsigned char *, u_int16_t, struct packet_ptrs_vector *, struct plugin_requests *, u_int16_t, struct NF_dissect *, int *);
extern void process_raw_packet(unsigned char *, u_int16_t, struct packet_ptrs_vector *, struct plugin_requests *);
extern void NF_evaluate_flow_type(struct flow_chars *, struct template_cache_entry *, struct packet_ptrs *);
extern u_int16_t NF_evaluate_direction(struct template_cache_entry *, struct packet_ptrs *);
extern void NF_process_classifiers(struct packet_ptrs *, struct packet_ptrs *, unsigned char *, struct template_cache_entry *);
extern pm_class_t NF_evaluate_classifiers(struct xflow_status_entry_class *, pm_class_t *, struct xflow_status_entry *);
extern void reset_mac(struct packet_ptrs *);
extern void reset_mac_vlan(struct packet_ptrs *);
extern void reset_ip4(struct packet_ptrs *);
extern void reset_ip6(struct packet_ptrs *);
extern void reset_dummy_v4(struct packet_ptrs *, u_char *);
extern void notify_malf_packet(short int, char *, char *, struct sockaddr *, u_int32_t);
extern int NF_find_id(struct id_table *, struct packet_ptrs *, pm_id_t *, pm_id_t *);
extern void NF_compute_once();

extern struct xflow_status_entry *nfv5_check_status(struct packet_ptrs *);
extern struct xflow_status_entry *nfv9_check_status(struct packet_ptrs *, u_int32_t, u_int32_t, u_int32_t, u_int8_t);
extern void nfv9_datalink_frame_section_handler(struct packet_ptrs *);

extern struct template_cache tpl_cache;
extern struct host_addr debug_a;
extern char debug_agent_addr[50];
extern u_int16_t debug_agent_port;

extern u_int16_t modulo_template(u_int16_t, struct sockaddr *, u_int16_t);
extern struct template_cache_entry *handle_template(struct template_hdr_v9 *, struct packet_ptrs *, u_int16_t, u_int32_t, u_int16_t *, u_int16_t, u_int32_t);
extern struct template_cache_entry *find_template(u_int16_t, struct sockaddr *, u_int16_t, u_int32_t);
extern struct template_cache_entry *insert_template(struct template_hdr_v9 *, struct packet_ptrs *, u_int16_t, u_int32_t, u_int16_t *, u_int8_t, u_int16_t, u_int32_t);
extern struct template_cache_entry *refresh_template(struct template_hdr_v9 *, struct template_cache_entry *, struct packet_ptrs *, u_int16_t, u_int32_t, u_int16_t *, u_int8_t, u_int16_t, u_int32_t);
extern void log_template_header(struct template_cache_entry *, struct packet_ptrs *, u_int16_t, u_int32_t, u_int8_t);
extern void log_opt_template_field(u_int8_t, u_int32_t *, u_int16_t, u_int16_t, u_int16_t, u_int8_t);
extern void log_template_field(u_int8_t, u_int32_t *, u_int16_t, u_int16_t, u_int16_t, u_int8_t);
extern void log_template_footer(struct template_cache_entry *, u_int16_t, u_int8_t);
extern struct template_cache_entry *insert_opt_template(void *, struct packet_ptrs *, u_int16_t, u_int32_t, u_int16_t *, u_int8_t, u_int16_t, u_int32_t);
extern struct template_cache_entry *refresh_opt_template(void *, struct template_cache_entry *, struct packet_ptrs *, u_int16_t, u_int32_t, u_int16_t *, u_int8_t, u_int16_t, u_int32_t);
extern struct utpl_field *ext_db_get_ie(struct template_cache_entry *, u_int32_t, u_int16_t, u_int8_t);
extern struct utpl_field *ext_db_get_next_ie(struct template_cache_entry *, u_int16_t, u_int8_t *);

extern int resolve_vlen_template(u_char *, u_int16_t, struct template_cache_entry *);
extern int get_ipfix_vlen(u_char *, u_int16_t, u_int16_t *);

extern struct template_cache_entry *nfacctd_offline_read_json_template(char *, char *, int);
extern void load_templates_from_file(char *);
extern void save_template(struct template_cache_entry *, char *);

#ifdef WITH_KAFKA
extern void NF_init_kafka_host(void *);
#endif

#ifdef WITH_ZMQ
extern void NF_init_zmq_host(void *, int *);
#endif

extern struct utpl_field *(*get_ext_db_ie_by_type)(struct template_cache_entry *, u_int32_t, u_int16_t, u_int8_t);
#endif //NFACCTD_H
