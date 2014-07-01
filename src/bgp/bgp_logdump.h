/*  
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2014 by Paolo Lucente
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
struct bgp_peer_log {
  FILE *fd;
  int refcnt;
  char filename[SRVBUFLEN];
  void *amqp_host;
};

/* prototypes */
#if (!defined __BGP_LOGDUMP_C)
#define EXT extern
#else
#define EXT
#endif
EXT int bgp_peer_log_init(struct bgp_peer *, int);
EXT int bgp_peer_log_close(struct bgp_peer *, int);
EXT void bgp_peer_log_seq_init();
EXT void bgp_peer_log_seq_increment();
EXT void bgp_peer_log_dynname(char *, int, char *, struct bgp_peer *);
EXT int bgp_peer_log_msg(struct bgp_node *, struct bgp_info *, safi_t, char *, int);
EXT int bgp_peer_dump_init(struct bgp_peer *, int);
EXT int bgp_peer_dump_close(struct bgp_peer *, int);
EXT void bgp_handle_dump_event();
EXT void bgp_daemon_msglog_init_amqp_host();
EXT void bgp_table_dump_init_amqp_host();

/* global variables */
EXT struct bgp_peer_log *peers_log;
EXT u_int64_t log_seq;
EXT struct timeval log_tstamp;
EXT char log_tstamp_str[SRVBUFLEN];

#undef EXT
#endif 
