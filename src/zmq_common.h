/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2020 by Paolo Lucente
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
#include <zmq.h>

/* defines */
#define PLUGIN_PIPE_ZMQ_NONE		0
#define PLUGIN_PIPE_ZMQ_MICRO		1
#define PLUGIN_PIPE_ZMQ_SMALL		2
#define PLUGIN_PIPE_ZMQ_MEDIUM		3
#define PLUGIN_PIPE_ZMQ_LARGE		4
#define PLUGIN_PIPE_ZMQ_XLARGE		5

#define PLUGIN_PIPE_ZMQ_MICRO_SIZE	0
#define PLUGIN_PIPE_ZMQ_SMALL_SIZE	10000
#define PLUGIN_PIPE_ZMQ_MEDIUM_SIZE	100000
#define PLUGIN_PIPE_ZMQ_LARGE_SIZE	1000000
#define PLUGIN_PIPE_ZMQ_XLARGE_SIZE	10000000

#define PM_ZMQ_EVENTS_RETRIES		3
#define PM_ZMQ_DEFAULT_RETRY		1000 /* 1 sec */
#define PM_ZMQ_DEFAULT_FLOW_HWM		100000 /* ~150MB @ 1500 bytes/packet */

/* structures */
struct p_zmq_sock {
  void *obj; /* XXX: to be removed */
  void *obj_tx;
  void *obj_rx;
  char str[SHORTBUFLEN];
};

struct p_zmq_zap {
  struct p_zmq_sock sock;
  void *thread; 
  char username[SHORTBUFLEN];
  char password[SHORTBUFLEN];
};

struct p_zmq_router_worker {
  void **threads;
  void (*func)(void *, void *);
};

struct p_zmq_host {
  void *ctx;
  struct p_zmq_zap zap;
  char log_id[SHORTBUFLEN];

  struct p_zmq_sock sock;
  struct p_zmq_sock sock_inproc;
  struct p_zmq_router_worker router_worker;

  u_int8_t topic;
  int hwm;
};

/* prototypes */
extern void p_zmq_set_address(struct p_zmq_host *, char *);
extern void p_zmq_set_topic(struct p_zmq_host *, u_int8_t);
extern void p_zmq_set_retry_timeout(struct p_zmq_host *, int);
extern void p_zmq_set_username(struct p_zmq_host *, char *);
extern void p_zmq_set_password(struct p_zmq_host *, char *);
extern void p_zmq_set_random_username(struct p_zmq_host *);
extern void p_zmq_set_random_password(struct p_zmq_host *);
extern void p_zmq_set_hwm(struct p_zmq_host *, int);
extern void p_zmq_set_log_id(struct p_zmq_host *, char *);

extern char *p_zmq_get_address(struct p_zmq_host *);
extern u_int8_t p_zmq_get_topic(struct p_zmq_host *);
extern void *p_zmq_get_sock(struct p_zmq_host *);
extern int p_zmq_get_fd(struct p_zmq_host *);

extern int p_zmq_connect(struct p_zmq_host *);
extern int p_zmq_bind(struct p_zmq_host *);

extern void p_zmq_init_pub(struct p_zmq_host *, char *, u_int8_t);
extern void p_zmq_init_sub(struct p_zmq_host *);
extern void p_zmq_init_push(struct p_zmq_host *, char *);
extern void p_zmq_init_pull(struct p_zmq_host *);
extern int p_zmq_recv_poll(struct p_zmq_sock *, int);
extern int p_zmq_topic_recv(struct p_zmq_host *, void *, u_int64_t);
extern int p_zmq_topic_send(struct p_zmq_host *, void *, u_int64_t);
extern void p_zmq_close(struct p_zmq_host *);

extern void p_zmq_plugin_pipe_init_core(struct p_zmq_host *, u_int8_t, char *, char *);
extern void p_zmq_plugin_pipe_init_plugin(struct p_zmq_host *);
extern int p_zmq_plugin_pipe_set_profile(struct configuration *, char *);
extern void p_zmq_ctx_setup(struct p_zmq_host *);
extern void p_zmq_pull_setup(struct p_zmq_host *);
extern void p_zmq_pull_bind_setup(struct p_zmq_host *);
extern void p_zmq_sub_setup(struct p_zmq_host *);
extern void p_zmq_push_setup(struct p_zmq_host *);
extern void p_zmq_push_connect_setup(struct p_zmq_host *);
extern void p_zmq_pub_setup(struct p_zmq_host *);
extern void p_zmq_zap_setup(struct p_zmq_host *);
extern void p_zmq_recv_setup(struct p_zmq_host *, int, int);
extern void p_zmq_send_setup(struct p_zmq_host *, int, int);

extern void p_zmq_router_setup(struct p_zmq_host *, char *, int);
extern void p_zmq_dealer_inproc_setup(struct p_zmq_host *);
extern void p_zmq_proxy_setup(struct p_zmq_host *);
extern void p_zmq_router_backend_setup(struct p_zmq_host *, int);
extern void p_zmq_router_worker(void *);

extern char *p_zmq_recv_str(struct p_zmq_sock *);
extern int p_zmq_send_str(struct p_zmq_sock *, char *);
extern int p_zmq_sendmore_str(struct p_zmq_sock *, char *);
extern int p_zmq_recv_bin(struct p_zmq_sock *, void *, size_t);
extern int p_zmq_send_bin(struct p_zmq_sock *, void *, size_t, int);
extern int p_zmq_sendmore_bin(struct p_zmq_sock *, void *, size_t, int);

extern void p_zmq_zap_handler(void *);

/* global vars */
extern struct p_zmq_host nfacctd_zmq_host;
extern struct p_zmq_host telemetry_zmq_host;
