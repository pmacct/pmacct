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

#define TELEMETRY_DECODER_UNKNOWN	0
#define TELEMETRY_DECODER_JSON		1
#define TELEMETRY_DECODER_ZJSON		2

struct telemetry_data {
  int is_thread;
  char *log_str;
};

typedef struct bgp_peer telemetry_peer;
typedef struct bgp_peer_log telemetry_peer_log;
typedef struct bgp_misc_structs telemetry_misc_structs;
typedef struct bmp_dump_se_ll telemetry_dump_se_ll;
typedef struct bmp_dump_se_ll_elem telemetry_dump_se_ll_elem;

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

EXT int telemetry_peer_init(telemetry_peer *, int);
EXT void telemetry_peer_close(telemetry_peer *, int);
EXT void telemetry_peer_log_seq_init(u_int64_t *);
EXT int telemetry_peer_log_init(telemetry_peer *, int, int);
EXT void telemetry_peer_log_dynname(char *, int, char *, telemetry_peer *);
EXT int telemetry_peer_dump_init(telemetry_peer *, int, int);
EXT int telemetry_peer_dump_close(telemetry_peer *, int, int);
EXT void telemetry_dump_init_peer(telemetry_peer *);
EXT void telemetry_dump_se_ll_destroy(telemetry_dump_se_ll *);

EXT int telemetry_recv_generic(telemetry_peer *);
EXT int telemetry_recv_json(telemetry_peer *, int *);
EXT int telemetry_recv_zjson(telemetry_peer *, int *);
EXT int telemetry_basic_validate_json(telemetry_peer *);

EXT void telemetry_link_misc_structs(telemetry_misc_structs *);

EXT void telemetry_handle_dump_event(struct telemetry_data *);
EXT void telemetry_daemon_msglog_init_amqp_host();
EXT void telemetry_dump_init_amqp_host();
EXT int telemetry_daemon_msglog_init_kafka_host();
EXT int telemetry_dump_init_kafka_host();
EXT void telemetry_handle_dump_event();

EXT void telemetry_dummy();
#undef EXT

/* global variables */
#if (!defined __TELEMETRY_C)
#define EXT extern
#else
#define EXT
#endif
EXT telemetry_peer *telemetry_peers;
EXT telemetry_misc_structs *telemetry_misc_db; 
#undef EXT
