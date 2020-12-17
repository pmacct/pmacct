/*  
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2020 by Paolo Lucente
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

#ifndef TELEMETRY_H
#define TELEMETRY_H

/* includes */
#include "base64.h"

/* defines */
#define TELEMETRY_TCP_PORT		1620
#define TELEMETRY_UDP_PORT		1620
#define TELEMETRY_MAX_PEERS_DEFAULT	100
#define TELEMETRY_PEER_TIMEOUT_DEFAULT	300
#define TELEMETRY_PEER_TIMEOUT_INTERVAL	60
#define TELEMETRY_UDP_MAXMSG		65535
#define TELEMETRY_LOG_STATS_INTERVAL	120	
#define TELEMETRY_KAFKA_FD		INT_MAX	

#define TELEMETRY_DECODER_UNKNOWN	0
#define TELEMETRY_DECODER_JSON		1
#define TELEMETRY_DECODER_GPB		2
#define TELEMETRY_DECODER_CISCO_V0	3
#define TELEMETRY_DECODER_CISCO_V1	4

#define TELEMETRY_DATA_DECODER_UNKNOWN	0
#define TELEMETRY_DATA_DECODER_JSON	1
#define TELEMETRY_DATA_DECODER_GPB	2

#define TELEMETRY_CISCO_VERSION_0		0
#define TELEMETRY_CISCO_HDR_LEN_V0		12
#define TELEMETRY_CISCO_VERSION_1		1
#define TELEMETRY_CISCO_HDR_LEN_V1		12

#define TELEMETRY_CISCO_RESET_COMPRESSOR	1
#define TELEMETRY_CISCO_JSON			2
#define TELEMETRY_CISCO_GPB_COMPACT		3
#define TELEMETRY_CISCO_GPB_KV			4

#define TELEMETRY_CISCO_V1_TYPE_UNUSED		0
#define TELEMETRY_CISCO_V1_TYPE_DATA		1
#define TELEMETRY_CISCO_V1_TYPE_HBEAT		2

#define TELEMETRY_CISCO_V1_ENCAP_UNUSED		0
#define TELEMETRY_CISCO_V1_ENCAP_GPB		1
#define TELEMETRY_CISCO_V1_ENCAP_JSON		2
#define TELEMETRY_CISCO_V1_ENCAP_GPV_CPT	3
#define TELEMETRY_CISCO_V1_ENCAP_GPB_KV		4

#define TELEMETRY_LOGDUMP_ET_NONE	BGP_LOGDUMP_ET_NONE
#define TELEMETRY_LOGDUMP_ET_LOG	BGP_LOGDUMP_ET_LOG
#define TELEMETRY_LOGDUMP_ET_DUMP	BGP_LOGDUMP_ET_DUMP

struct telemetry_cisco_hdr_v0 {
  u_int32_t type;
  u_int32_t flags;
  u_int32_t len;
} __attribute__ ((packed));

struct telemetry_cisco_hdr_v1 {
  u_int16_t type;
  u_int16_t encap;
  u_int16_t version;
  u_int16_t flags;
  u_int32_t len;
} __attribute__ ((packed));

typedef struct bgp_peer_stats telemetry_stats;

struct telemetry_data {
  int is_thread;
  char *log_str;
#if defined WITH_ZMQ
  void *zmq_host;
#endif
#if defined WITH_KAFKA
  void *kafka_msg;
#endif

  telemetry_stats global_stats;
  time_t now;
};

struct _telemetry_peer_cache {
  struct host_addr addr;
  int index;
};

struct _telemetry_peer_timeout {
  time_t last_msg;
};

struct _telemetry_dump_se {
  int decoder;
  u_int32_t len;
  u_int64_t seq;
  void *data;
};

struct _telemetry_dump_se_ll_elem {
  struct _telemetry_dump_se rec;
  struct _telemetry_dump_se_ll_elem *next;
};

struct _telemetry_dump_se_ll {
  struct _telemetry_dump_se_ll_elem *start;
  struct _telemetry_dump_se_ll_elem *last;
};

typedef struct bgp_peer telemetry_peer;
typedef struct bgp_peer_log telemetry_peer_log;
typedef struct bgp_misc_structs telemetry_misc_structs;
typedef struct _telemetry_dump_se_ll telemetry_dump_se_ll;
typedef struct _telemetry_dump_se_ll_elem telemetry_dump_se_ll_elem;
typedef struct _telemetry_peer_cache telemetry_peer_cache;
typedef struct _telemetry_peer_timeout telemetry_peer_timeout;

/* more includes */
#include "telemetry_logdump.h"
#include "telemetry_msg.h"
#include "telemetry_util.h"

/* prototypes */
extern void telemetry_wrapper();
extern int telemetry_daemon(void *);
extern void telemetry_prepare_thread(struct telemetry_data *);
extern void telemetry_prepare_daemon(struct telemetry_data *);

/* global variables */
extern telemetry_misc_structs *telemetry_misc_db; 

extern telemetry_peer *telemetry_peers;
extern void *telemetry_peers_cache;
extern telemetry_peer_timeout *telemetry_peers_timeout; 
extern int zmq_input, kafka_input;
#endif //TELEMETRY_H
