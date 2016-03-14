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

/* defines */
#define TELEMETRY_TCP_PORT		1620
#define TELEMETRY_MAX_PEERS_DEFAULT	100

struct telemetry_data {
  int is_thread;
  char *log_str;
};

struct telemetry_peer {
  int fd;
  struct host_addr addr;
  char addr_str[INET6_ADDRSTRLEN];
  u_int16_t tcp_port;
  u_int32_t msglen;
/* XXX:
  struct bgp_peer_buf buf;
  struct bgp_peer_log *log;
*/
  void *telemetry_se;
};

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
#if (!defined __TELEMETRY_C)
#define EXT extern
#else
#define EXT
#endif
EXT struct telemetry_peer *telemetry_peers;
#undef EXT
