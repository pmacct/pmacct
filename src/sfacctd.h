/*  
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2025 by Paolo Lucente
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

/* 
    much of the sflow v2/v4/v5 definitions are based on sFlow toolkit 3.8 and
    later which is Copyright (C) InMon Corporation 2001 ALL RIGHTS RESERVED
*/

#ifndef SFACCTD_H
#define SFACCTD_H

#include "sflow.h"

/* defines */
#define DEFAULT_SFACCTD_PORT 6343 
#define SFLOW_MIN_MSG_SIZE 200 
#define SFLOW_MAX_MSG_SIZE 65536 /* inflated ? */
#define MAX_SF_CNT_LOG_ENTRIES 1024

enum INMPacket_information_type {
  INMPACKETTYPE_HEADER  = 1,      /* Packet headers are sampled */
  INMPACKETTYPE_IPV4    = 2,      /* IP version 4 data */
  INMPACKETTYPE_IPV6    = 3       /* IP version 6 data */
};

enum INMExtended_information_type {
  INMEXTENDED_SWITCH    = 1,      /* Extended switch information */
  INMEXTENDED_ROUTER    = 2,      /* Extended router information */
  INMEXTENDED_GATEWAY   = 3,      /* Extended gateway router information */
  INMEXTENDED_USER      = 4,      /* Extended TACAS/RADIUS user information */
  INMEXTENDED_URL       = 5       /* Extended URL information */
};

enum INMCounters_version {
  INMCOUNTERSVERSION_GENERIC      = 1,
  INMCOUNTERSVERSION_ETHERNET     = 2,
  INMCOUNTERSVERSION_TOKENRING    = 3,
  INMCOUNTERSVERSION_FDDI         = 4,
  INMCOUNTERSVERSION_VG           = 5,
  INMCOUNTERSVERSION_WAN          = 6,
  INMCOUNTERSVERSION_VLAN         = 7
};

extern u_int8_t SF_evaluate_flow_type(struct packet_ptrs *);
extern void set_vector_sample_type(struct packet_ptrs_vector *, u_int32_t);
extern void reset_mac(struct packet_ptrs *);
extern void reset_mac_vlan(struct packet_ptrs *);
extern void reset_ip4(struct packet_ptrs *);
extern void reset_ip6(struct packet_ptrs *);
extern void SF_notify_malf_packet(short int, char *, char *, struct sockaddr *);
extern int SF_find_id(struct id_table *, struct packet_ptrs *, pm_id_t *, pm_id_t *);
extern void SF_compute_once();

extern void process_SFv2v4_packet(SFSample *, struct packet_ptrs_vector *, struct plugin_requests *, struct sockaddr *);
extern void process_SFv5_packet(SFSample *, struct packet_ptrs_vector *, struct plugin_requests *, struct sockaddr *);
extern void process_SF_raw_packet(SFSample *, struct packet_ptrs_vector *, struct plugin_requests *, struct sockaddr *);

extern int sf_cnt_log_msg(struct bgp_peer *, SFSample *, int, u_int32_t, char *, int, u_int32_t);
extern int readCounters_generic(struct bgp_peer *, SFSample *, char *, int, void *);
extern int readCounters_ethernet(struct bgp_peer *, SFSample *, char *, int, void *);
extern int readCounters_vlan(struct bgp_peer *, SFSample *, char *, int, void *);
extern void sfacctd_counter_init_amqp_host();
extern int sfacctd_counter_init_kafka_host();
extern void sf_cnt_link_misc_structs(struct bgp_misc_structs *);
extern void sf_flow_sample_hdr_decode(SFSample *);

extern struct xflow_status_entry *sfv245_check_status(SFSample *spp, struct packet_ptrs *, struct sockaddr *);
extern void sfv245_check_counter_log_init(struct packet_ptrs *);

extern void usage_daemon(char *);
extern void compute_once();

#ifdef WITH_KAFKA
extern void SF_init_kafka_host(void *);
#endif

#ifdef WITH_ZMQ
extern void SF_init_zmq_host(void *, int *);
#endif

/* global variables */
extern int sfacctd_counter_backend_methods;
extern struct bgp_misc_structs *sf_cnt_misc_db;
extern struct host_addr debug_a;
extern char debug_agent_addr[50];
extern u_int16_t debug_agent_port;

#endif //SFACCTD_H
