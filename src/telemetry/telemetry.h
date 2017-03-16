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

/* includes */
#include "base64.h"

/* defines */
#define TELEMETRY_TCP_PORT		1620
#define TELEMETRY_UDP_PORT		1620
#define TELEMETRY_MAX_PEERS_DEFAULT	100
#define TELEMETRY_UDP_TIMEOUT_DEFAULT	300
#define TELEMETRY_UDP_TIMEOUT_INTERVAL	60
#define TELEMETRY_UDP_MAXMSG		65535
#define TELEMETRY_CISCO_HDR_LEN		12
#define TELEMETRY_LOG_STATS_INTERVAL	120	

#define TELEMETRY_DECODER_UNKNOWN	0
#define TELEMETRY_DECODER_JSON		1
#define TELEMETRY_DECODER_ZJSON		2
#define TELEMETRY_DECODER_CISCO		3
#define TELEMETRY_DECODER_CISCO_JSON	4
#define TELEMETRY_DECODER_CISCO_ZJSON	5
#define TELEMETRY_DECODER_CISCO_GPB	6
#define TELEMETRY_DECODER_CISCO_GPB_KV	7

#define TELEMETRY_DATA_DECODER_UNKNOWN	0
#define TELEMETRY_DATA_DECODER_JSON	1
#define TELEMETRY_DATA_DECODER_GPB	2

#define TELEMETRY_CISCO_RESET_COMPRESSOR	1
#define TELEMETRY_CISCO_JSON			2
#define TELEMETRY_CISCO_GPB_COMPACT		3
#define TELEMETRY_CISCO_GPB_KV			4

#define TELEMETRY_LOGDUMP_ET_NONE	BGP_LOGDUMP_ET_NONE
#define TELEMETRY_LOGDUMP_ET_LOG	BGP_LOGDUMP_ET_LOG
#define TELEMETRY_LOGDUMP_ET_DUMP	BGP_LOGDUMP_ET_DUMP

typedef struct bgp_peer_stats telemetry_stats;

struct telemetry_data {
  int is_thread;
  char *log_str;

  telemetry_stats global_stats;
  time_t now;
};

struct _telemetry_peer_z {
  char inflate_buf[BGP_BUFFER_SIZE];
#if defined (HAVE_ZLIB)
  z_stream stm;
#endif
};

struct _telemetry_peer_udp_cache {
  struct host_addr addr;
  int index;
};

struct _telemetry_peer_udp_timeout {
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
typedef struct _telemetry_peer_z telemetry_peer_z;
typedef struct _telemetry_peer_udp_cache telemetry_peer_udp_cache;
typedef struct _telemetry_peer_udp_timeout telemetry_peer_udp_timeout;

/* more includes */
#include "telemetry_logdump.h"
#include "telemetry_msg.h"
#include "telemetry_util.h"

/* prototypes */
#if (!defined __TELEMETRY_C)
#define EXT extern
#else
#define EXT
#endif
EXT void telemetry_wrapper();
EXT void telemetry_daemon(void *);
EXT void telemetry_prepare_thread(struct telemetry_data *);
EXT void telemetry_prepare_daemon(struct telemetry_data *);
#undef EXT

/* global variables */
#if !defined(__TELEMETRY_C)
#define EXT extern
#else
#define EXT
#endif
EXT telemetry_misc_structs *telemetry_misc_db; 

EXT telemetry_peer *telemetry_peers;
EXT telemetry_peer_z *telemetry_peers_z;
EXT void *telemetry_peers_udp_cache;
EXT telemetry_peer_udp_timeout *telemetry_peers_udp_timeout; 
#undef EXT
