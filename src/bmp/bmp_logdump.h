/*  
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2015 by Paolo Lucente
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

#ifndef _BMP_LOGDUMP_H_
#define _BMP_LOGDUMP_H_

/* defines */
#define	BMP_LOG_TYPE_STATS	1
#define BMP_LOG_TYPE_INIT	2
#define BMP_LOG_TYPE_TERM	3
#define BMP_LOG_TYPE_PEER_UP	4
#define BMP_LOG_TYPE_PEER_DOWN	5
#define BMP_LOG_TYPE_ROUTE	6

struct bmp_log_stats {
  u_int16_t cnt_type;
  u_int64_t cnt_data;
  u_int8_t got_data;
};

struct bmp_log_init {
  u_int16_t type; 
  u_int16_t len;
  char *val;
};

struct bmp_log_term {
  u_int16_t type;
  u_int16_t len;
  char *val;
  u_int16_t reas_type;
};

struct bmp_log_peer_up {
  struct host_addr local_ip;
  u_int16_t loc_port;
  u_int16_t rem_port;
};

struct bmp_log_peer_down {
  u_char reason;
  u_int16_t loc_code;
};

struct bmp_dump_se {
  struct bmp_data bdata;
  int se_type;
  union {
    struct bmp_log_stats stats;
    struct bmp_log_init init;
    struct bmp_log_term term;
    struct bmp_log_peer_up peer_up;
    struct bmp_log_peer_down peer_down;
  } se;
};

struct bmp_dump_se_ll_elem {
  struct bmp_dump_se rec; 
  struct bmp_dump_se_ll_elem *next;
};

struct bmp_dump_se_ll {
  struct bmp_dump_se_ll_elem *start;
  struct bmp_dump_se_ll_elem *last;
};

/* prototypes */
#if (!defined __BMP_LOGDUMP_C)
#define EXT extern
#else
#define EXT
#endif
EXT void bmp_daemon_msglog_init_amqp_host();
EXT void bmp_dump_init_amqp_host();
EXT void bmp_dump_init_peer(struct bgp_peer *);
EXT void bmp_dump_close_peer(struct bgp_peer *);

EXT int bmp_log_msg(struct bgp_peer *, struct bmp_data *, void *, char *, int, int);
EXT int bmp_log_msg_stats(struct bgp_peer *, struct bmp_data *, struct bmp_log_stats *, char *, int, void *);
EXT int bmp_log_msg_init(struct bgp_peer *, struct bmp_data *, struct bmp_log_init *, char *, int, void *);
EXT int bmp_log_msg_term(struct bgp_peer *, struct bmp_data *, struct bmp_log_term *, char *, int, void *);
EXT int bmp_log_msg_peer_up(struct bgp_peer *, struct bmp_data *, struct bmp_log_peer_up *, char *, int, void *);
EXT int bmp_log_msg_peer_down(struct bgp_peer *, struct bmp_data *, struct bmp_log_peer_down *, char *, int, void *);

EXT void bmp_dump_se_ll_append(struct bgp_peer *, struct bmp_data *, void *, int);
EXT void bmp_dump_se_ll_destroy(struct bmp_dump_se_ll *);

EXT void bmp_handle_dump_event();

/* global variables */
EXT struct bgp_peer_log *bmp_peers_log;
EXT u_int64_t bmp_log_seq;
EXT struct timeval bmp_log_tstamp;
EXT char bmp_log_tstamp_str[SRVBUFLEN];
#undef EXT
#endif
