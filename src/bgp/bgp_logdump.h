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

#ifndef _BGP_LOGDUMP_H_
#define _BGP_LOGDUMP_H_

/* defines */
#define BGP_LOGDUMP_ET_NONE	0
#define BGP_LOGDUMP_ET_LOG	1
#define BGP_LOGDUMP_ET_DUMP	2

#define BGP_LOG_TYPE_MISC	0
#define BGP_LOG_TYPE_UPDATE	1
#define BGP_LOG_TYPE_WITHDRAW	2
#define BGP_LOG_TYPE_DELETE	3
#define BGP_LOG_TYPE_OPEN	4
#define BGP_LOG_TYPE_CLOSE	5

struct bgp_peer_log {
  FILE *fd;
  int refcnt;
  char filename[SRVBUFLEN];
  void *amqp_host;
  void *kafka_host;
};

struct bgp_dump_stats {
  u_int64_t entries;
  u_int32_t tables;
};

/* prototypes */
#if (!defined __BGP_LOGDUMP_C)
#define EXT extern
#else
#define EXT
#endif
EXT int bgp_peer_log_init(struct bgp_peer *, int, int);
EXT int bgp_peer_log_close(struct bgp_peer *, int, int);
EXT void bgp_peer_log_seq_init(u_int64_t *);
EXT void bgp_peer_log_seq_increment(u_int64_t *);
EXT void bgp_peer_log_dynname(char *, int, char *, struct bgp_peer *);
EXT int bgp_peer_log_msg(struct bgp_node *, struct bgp_info *, afi_t, safi_t, char *, int, int);
EXT int bgp_peer_dump_init(struct bgp_peer *, int, int);
EXT int bgp_peer_dump_close(struct bgp_peer *, struct bgp_dump_stats *, int, int);
EXT void bgp_handle_dump_event();
EXT void bgp_daemon_msglog_init_amqp_host();
EXT void bgp_table_dump_init_amqp_host();
EXT int bgp_daemon_msglog_init_kafka_host();
EXT int bgp_table_dump_init_kafka_host();
#undef EXT
#endif 
