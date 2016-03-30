/*  
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2016 by Paolo Lucente
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
#include "../bgp/bgp.h"
#include "../bmp/bmp.h"
#if defined (HAVE_ZLIB)
#include <zlib.h>
#endif

/* defines */
#define TELEMETRY_TCP_PORT		1620
#define TELEMETRY_UDP_PORT		1620
#define TELEMETRY_MAX_PEERS_DEFAULT	100
#define TELEMETRY_UDP_TIMEOUT		300
#define TELEMETRY_UDP_MAXMSG		65535
#define TELEMETRY_CISCO_HDR_LEN		12

#define TELEMETRY_DECODER_UNKNOWN	0
#define TELEMETRY_DECODER_JSON		1
#define TELEMETRY_DECODER_ZJSON		2
#define TELEMETRY_DECODER_CISCO_JSON	3
#define TELEMETRY_DECODER_CISCO_ZJSON	4

#define TELEMETRY_LOGDUMP_ET_NONE	BGP_LOGDUMP_ET_NONE
#define TELEMETRY_LOGDUMP_ET_LOG	BGP_LOGDUMP_ET_LOG
#define TELEMETRY_LOGDUMP_ET_DUMP	BGP_LOGDUMP_ET_DUMP

struct telemetry_data {
  int is_thread;
  char *log_str;
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

struct _telemetry_dump_se {
  u_int32_t len;
  void *data;
};

struct _telemetry_dump_se_ll_elem {
  struct _telemetry_dump_se rec; // XXX: fix, prevents reusability
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
EXT void telemetry_process_data(telemetry_peer *, struct telemetry_data *);

EXT int telemetry_peer_init(telemetry_peer *, int);
EXT int telemetry_peer_z_init(telemetry_peer_z *);
EXT void telemetry_peer_close(telemetry_peer *, int);
EXT void telemetry_peer_z_close(telemetry_peer_z *);
EXT void telemetry_peer_log_seq_init(u_int64_t *);
EXT int telemetry_peer_log_init(telemetry_peer *, int, int);
EXT void telemetry_peer_log_dynname(char *, int, char *, telemetry_peer *);
EXT int telemetry_peer_dump_init(telemetry_peer *, int, int);
EXT int telemetry_peer_dump_close(telemetry_peer *, int, int);
EXT void telemetry_dump_init_peer(telemetry_peer *);
EXT void telemetry_dump_se_ll_destroy(telemetry_dump_se_ll *);
EXT void telemetry_dump_se_ll_append(telemetry_peer *, struct telemetry_data *);
EXT int telemetry_log_msg(telemetry_peer *, struct telemetry_data *, void *, u_int32_t, char *, int);

EXT int telemetry_recv_generic(telemetry_peer *, u_int32_t);
EXT int telemetry_recv_json(telemetry_peer *, u_int32_t, int *);
EXT int telemetry_recv_zjson(telemetry_peer *, telemetry_peer_z *, u_int32_t, int *);
EXT int telemetry_recv_cisco_json(telemetry_peer *, int *);
EXT int telemetry_recv_cisco_zjson(telemetry_peer *, telemetry_peer_z *, int *);
EXT u_int32_t telemetry_cisco_hdr_get_len(telemetry_peer *);
EXT void telemetry_basic_process_json(telemetry_peer *);
EXT int telemetry_basic_validate_json(telemetry_peer *);
EXT int telemetry_is_zjson(int);

EXT void telemetry_link_misc_structs(telemetry_misc_structs *);

EXT void telemetry_handle_dump_event(struct telemetry_data *);
EXT void telemetry_daemon_msglog_init_amqp_host();
EXT void telemetry_dump_init_amqp_host();
EXT int telemetry_daemon_msglog_init_kafka_host();
EXT int telemetry_dump_init_kafka_host();
EXT void telemetry_handle_dump_event();

EXT int telemetry_tpuc_addr_cmp(const void *, const void *);

EXT void telemetry_dummy();
#undef EXT

/* global variables */
#if (!defined __TELEMETRY_C)
#define EXT extern
#else
#define EXT
#endif
EXT telemetry_peer *telemetry_peers;
EXT telemetry_peer_z *telemetry_peers_z;
EXT telemetry_misc_structs *telemetry_misc_db; 
EXT void *telemetry_peers_udp_cache;
#undef EXT
