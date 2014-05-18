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

/* includes */
#include <amqp.h>
#include <amqp_tcp_socket.h>

/* structures */
struct p_amqp_host {
  char *user;
  char *passwd;
  char *exchange;
  char *exhange_type;
  char *routing_key;
  int persistent_msg;

  amqp_connection_state_t conn;
  amqp_socket_t *socket;
  amqp_rpc_reply_t ret;
};

/* prototypes */
#if (!defined __AMQP_COMMON_C)
#define EXT extern
#else
#define EXT
#endif

EXT void p_amqp_init_host(struct p_amqp_host *);

/* global vars */
#undef EXT
