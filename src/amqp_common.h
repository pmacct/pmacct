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
#include <amqp.h>
#include <amqp_tcp_socket.h>
#define	__PLUGIN_COMMON_EXPORT
#include "plugin_common.h"
#undef	__PLUGIN_COMMON_EXPORT

/* defines */
#define AMQP_DEFAULT_RETRY	60
#define PM_AMQP_MIN_FRAME_SIZE	4096

/* structures */
struct p_amqp_host {
  char *user;
  char *passwd;
  char *exchange;
  char *exchange_type;
  char *routing_key;
  struct p_table_rr rk_rr;
  char *host;
  char *vhost;
  int persistent_msg;
  u_int8_t content_type;
  u_int32_t frame_max;
  int heartbeat_interval;

  amqp_connection_state_t conn;
  amqp_socket_t *socket;
  amqp_rpc_reply_t ret;
  amqp_bytes_t queue;
  struct amqp_basic_properties_t_ msg_props;
  int status;

  struct p_broker_timers btimers;
};

/* prototypes */
#if (!defined __AMQP_COMMON_C)
#define EXT extern
#else
#define EXT
#endif

EXT void p_amqp_init_host(struct p_amqp_host *);
EXT void p_amqp_init_routing_key_rr(struct p_amqp_host *);

EXT void p_amqp_set_user(struct p_amqp_host *, char *);
EXT void p_amqp_set_passwd(struct p_amqp_host *, char *);
EXT void p_amqp_set_exchange(struct p_amqp_host *, char *);
EXT void p_amqp_set_routing_key(struct p_amqp_host *, char *);
EXT void p_amqp_set_routing_key_rr(struct p_amqp_host *, int);
EXT void p_amqp_set_exchange_type(struct p_amqp_host *, char *);
EXT void p_amqp_set_host(struct p_amqp_host *, char *);
EXT void p_amqp_set_vhost(struct p_amqp_host *, char *);
EXT void p_amqp_set_persistent_msg(struct p_amqp_host *, int);
EXT void p_amqp_set_frame_max(struct p_amqp_host *, u_int32_t);
EXT void p_amqp_set_heartbeat_interval(struct p_amqp_host *, int);
EXT void p_amqp_set_content_type_json(struct p_amqp_host *);
EXT void p_amqp_set_content_type_binary(struct p_amqp_host *);

EXT char *p_amqp_get_routing_key(struct p_amqp_host *);
EXT int p_amqp_get_routing_key_rr(struct p_amqp_host *);
EXT int p_amqp_get_sockfd(struct p_amqp_host *);

EXT void p_amqp_unset_routing_key(struct p_amqp_host *);

EXT int p_amqp_connect_to_publish(struct p_amqp_host *);
EXT int p_amqp_connect_to_consume(struct p_amqp_host *);
EXT int p_amqp_publish_string(struct p_amqp_host *, char *);
EXT int p_amqp_publish_binary(struct p_amqp_host *, void *, u_int32_t);
EXT int p_amqp_consume_binary(struct p_amqp_host *, void *, u_int32_t);
EXT void p_amqp_close(struct p_amqp_host *, int);
EXT int p_amqp_is_alive(struct p_amqp_host *);

/* global vars */
EXT struct p_amqp_host amqpp_amqp_host;
EXT struct p_amqp_host bgp_daemon_msglog_amqp_host;
EXT struct p_amqp_host bgp_table_dump_amqp_host;
EXT struct p_amqp_host bmp_daemon_msglog_amqp_host;
EXT struct p_amqp_host bmp_dump_amqp_host;
EXT struct p_amqp_host sfacctd_counter_amqp_host;

static char rabbitmq_user[] = "guest";
static char rabbitmq_pwd[] = "guest";
static char default_amqp_exchange[] = "pmacct";
static char default_amqp_exchange_type[] = "direct";
static char default_amqp_routing_key[] = "acct";
static char default_amqp_host[] = "127.0.0.1";
static char default_amqp_vhost[] = "/";
#undef EXT
