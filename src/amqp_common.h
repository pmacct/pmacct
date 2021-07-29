/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2021 by Paolo Lucente
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

#ifndef AMQP_COMMON_H
#define AMQP_COMMON_H

/* includes */
#include <amqp.h>
#include <amqp_tcp_socket.h>
#include "plugin_common.h"

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
extern void p_amqp_init_host(struct p_amqp_host *);
extern void p_amqp_init_routing_key_rr(struct p_amqp_host *);

extern void p_amqp_set_user(struct p_amqp_host *, char *);
extern void p_amqp_set_passwd(struct p_amqp_host *, char *);
extern void p_amqp_set_exchange(struct p_amqp_host *, char *);
extern void p_amqp_set_routing_key(struct p_amqp_host *, char *);
extern void p_amqp_set_routing_key_rr(struct p_amqp_host *, int);
extern void p_amqp_set_exchange_type(struct p_amqp_host *, char *);
extern void p_amqp_set_host(struct p_amqp_host *, char *);
extern void p_amqp_set_vhost(struct p_amqp_host *, char *);
extern void p_amqp_set_persistent_msg(struct p_amqp_host *, int);
extern void p_amqp_set_frame_max(struct p_amqp_host *, u_int32_t);
extern void p_amqp_set_heartbeat_interval(struct p_amqp_host *, int);
extern void p_amqp_set_content_type_json(struct p_amqp_host *);
extern void p_amqp_set_content_type_binary(struct p_amqp_host *);

extern char *p_amqp_get_routing_key(struct p_amqp_host *);
extern int p_amqp_get_routing_key_rr(struct p_amqp_host *);
extern int p_amqp_get_sockfd(struct p_amqp_host *);
extern void p_amqp_get_version();

extern void p_amqp_unset_routing_key(struct p_amqp_host *);

extern int p_amqp_connect_to_publish(struct p_amqp_host *);
extern int p_amqp_publish_string(struct p_amqp_host *, char *);
extern int p_amqp_publish_binary(struct p_amqp_host *, void *, u_int32_t);
extern void p_amqp_close(struct p_amqp_host *, int);
extern int p_amqp_is_alive(struct p_amqp_host *);

extern int write_and_free_json_amqp(void *, void *);
extern int write_binary_amqp(void *, void *, size_t);
extern int write_string_amqp(void *, char *);

/* global vars */
extern struct p_amqp_host amqpp_amqp_host;
extern struct p_amqp_host bgp_daemon_msglog_amqp_host;
extern struct p_amqp_host bmp_daemon_msglog_amqp_host;
extern struct p_amqp_host sfacctd_counter_amqp_host;
extern struct p_amqp_host telemetry_daemon_msglog_amqp_host;

extern char rabbitmq_user[];
extern char rabbitmq_pwd[];
extern char default_amqp_exchange[];
extern char default_amqp_exchange_type[];
extern char default_amqp_routing_key[];
extern char default_amqp_host[];
extern char default_amqp_vhost[];

#endif //AMQP_COMMON_H
