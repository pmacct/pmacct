/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2018 by Paolo Lucente
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

/* structures */
struct p_zmq_sock {
  void *obj;
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
#if (!defined __ZMQ_COMMON_C)
#define EXT extern
#else
#define EXT
#endif
EXT void p_zmq_set_address(struct p_zmq_host *, char *);
EXT void p_zmq_set_topic(struct p_zmq_host *, u_int8_t);
EXT void p_zmq_set_retry_timeout(struct p_zmq_host *, int);
EXT void p_zmq_set_username(struct p_zmq_host *, char *);
EXT void p_zmq_set_password(struct p_zmq_host *, char *);
EXT void p_zmq_set_random_username(struct p_zmq_host *);
EXT void p_zmq_set_random_password(struct p_zmq_host *);
EXT void p_zmq_set_hwm(struct p_zmq_host *, int);
EXT void p_zmq_set_log_id(struct p_zmq_host *, char *);

EXT char *p_zmq_get_address(struct p_zmq_host *);
EXT u_int8_t p_zmq_get_topic(struct p_zmq_host *);
EXT void *p_zmq_get_sock(struct p_zmq_host *);
EXT int p_zmq_get_fd(struct p_zmq_host *);

EXT void p_zmq_init_pub(struct p_zmq_host *, char *, u_int8_t);
EXT void p_zmq_init_sub(struct p_zmq_host *);
EXT void p_zmq_init_push(struct p_zmq_host *, char *);
EXT void p_zmq_init_pull(struct p_zmq_host *);
EXT int p_zmq_recv_poll(struct p_zmq_host *, int);
EXT int p_zmq_topic_recv(struct p_zmq_host *, void *, u_int64_t);
EXT int p_zmq_topic_send(struct p_zmq_host *, void *, u_int64_t);
EXT void p_zmq_close(struct p_zmq_host *);

EXT void p_zmq_plugin_pipe_init_core(struct p_zmq_host *, u_int8_t);
EXT void p_zmq_plugin_pipe_init_plugin(struct p_zmq_host *);
EXT int p_zmq_plugin_pipe_set_profile(struct configuration *, char *);
EXT void p_zmq_pull_setup(struct p_zmq_host *);
EXT void p_zmq_sub_setup(struct p_zmq_host *);
EXT void p_zmq_push_setup(struct p_zmq_host *);
EXT void p_zmq_pub_setup(struct p_zmq_host *);
EXT void p_zmq_zap_setup(struct p_zmq_host *);
EXT void p_zmq_recv_setup(struct p_zmq_host *, int);
EXT void p_zmq_send_setup(struct p_zmq_host *, int);

EXT void p_zmq_router_setup(struct p_zmq_host *, char *, int);
EXT void p_zmq_dealer_inproc_setup(struct p_zmq_host *, char *);
EXT void p_zmq_proxy_setup(struct p_zmq_host *);
EXT void p_zmq_router_backend_setup(struct p_zmq_host *, int, char *);
EXT void p_zmq_router_worker(void *);

EXT char *p_zmq_recv_str(struct p_zmq_sock *);
EXT int p_zmq_send_str(struct p_zmq_sock *, char *);
EXT int p_zmq_sendmore_str(struct p_zmq_sock *, char *);
EXT int p_zmq_recv_bin(struct p_zmq_sock *, void *, int);
EXT int p_zmq_send_bin(struct p_zmq_sock *, void *, int);
EXT int p_zmq_sendmore_bin(struct p_zmq_sock *, void *, int);

EXT void p_zmq_zap_handler(void *);

/* global vars */
EXT struct p_zmq_host nfacctd_zmq_host;
EXT struct p_zmq_host telemetry_zmq_host;
#undef EXT
