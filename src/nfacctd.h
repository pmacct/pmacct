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

#ifndef NFACCTD_H
#define NFACCTD_H

/* includes */
#include "nfv9_template.h"

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

struct data_hdr_v9 {
  u_int16_t flow_id; /* == 0: template; == 1: options template; >= 256: data */
  u_int16_t flow_len;
};

/* defines */
#define DEFAULT_NFACCTD_PORT 2100
#define NETFLOW_MSG_SIZE PKT_MSG_SIZE
#define V5_MAXFLOWS 30  /* max records in V5 packet */

#define NF_TIME_MSECS 0 /* times are in msecs */
#define NF_TIME_SECS 1 /* times are in secs */ 
#define NF_TIME_NEW 2 /* ignore netflow engine times and generate new ones */ 

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
extern int NF_find_id(struct id_table *, struct packet_ptrs *, pm_id_t *, pm_id_t *);
extern void NF_compute_once();

extern struct xflow_status_entry *nfv5_check_status(struct packet_ptrs *);
extern struct xflow_status_entry *nfv9_check_status(struct packet_ptrs *, u_int32_t, u_int32_t, u_int32_t, u_int8_t);
extern void nfv9_datalink_frame_section_handler(struct packet_ptrs *);

extern struct host_addr debug_a;
extern char debug_agent_addr[50];
extern u_int16_t debug_agent_port;

#ifdef WITH_KAFKA
extern void NF_init_kafka_host(void *);
#endif

#ifdef WITH_ZMQ
extern void NF_init_zmq_host(void *, int *);
#endif

extern void NF_mpls_vpn_rd_from_map(struct packet_ptrs *);
extern void NF_mpls_vpn_rd_from_ie90(struct packet_ptrs *);
extern void NF_mpls_vpn_rd_from_options(struct packet_ptrs *);

extern struct utpl_field *(*get_ext_db_ie_by_type)(struct template_cache_entry *, u_int32_t, u_int16_t, u_int8_t);
#endif //NFACCTD_H
