/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2019 by Paolo Lucente
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
#include "pmacct.h"
#include "pmacct-data.h"
#include "zmq_common.h"

/* Global variables */
struct p_zmq_host nfacctd_zmq_host;
struct p_zmq_host telemetry_zmq_host;

/* Functions */
void p_zmq_set_address(struct p_zmq_host *zmq_host, char *address)
{
  char proto[] = "://", tcp_proto[] = "tcp://", inproc_proto[] = "inproc://";

  if (zmq_host && address) {
    if (!strstr(address, proto)) {
      snprintf(zmq_host->sock.str, sizeof(zmq_host->sock.str), "tcp://%s", address);
    }
    else {
      if (strstr(address, tcp_proto)) {
	snprintf(zmq_host->sock.str, sizeof(zmq_host->sock.str), "%s", address);
      }
      else if (strstr(address, inproc_proto)) {
	snprintf(zmq_host->sock_inproc.str, sizeof(zmq_host->sock_inproc.str), "%s", address);
      }
      else {
	Log(LOG_ERR, "ERROR ( %s ): p_zmq_set_address() unsupported protocol in '%s'.\nExiting.\n",
	    zmq_host->log_id, address);
	exit_gracefully(1);
      }
    }
  }
}

void p_zmq_set_topic(struct p_zmq_host *zmq_host, u_int8_t topic)
{
  if (zmq_host) zmq_host->topic = topic;
}

void p_zmq_set_retry_timeout(struct p_zmq_host *zmq_host, int tout)
{
  int ret;

  if (zmq_host) {
    ret = zmq_setsockopt(zmq_host->sock.obj, ZMQ_RECONNECT_IVL, &tout, sizeof(tout));
    if (ret != 0) {
      Log(LOG_ERR, "ERROR ( %s ): zmq_setsockopt() RECONNECT_IVL failed for topic %u: %s\nExiting.\n",
	  zmq_host->log_id, zmq_host->topic, zmq_strerror(errno));
      exit_gracefully(1);
    }
  }
}

void p_zmq_set_username(struct p_zmq_host *zmq_host, char *username)
{
  if (zmq_host) {
    if (strlen(username) >= sizeof(zmq_host->zap.username)) {
      Log(LOG_ERR, "ERROR ( %s ): p_zmq_set_username(): username '%s' too long (maximum %lu chars). Exiting.\n",
	  zmq_host->log_id, username, (sizeof(zmq_host->zap.username) - 1));
      exit_gracefully(1);
    }
    else strlcpy(zmq_host->zap.username, username, sizeof(zmq_host->zap.username));
  }
}

void p_zmq_set_password(struct p_zmq_host *zmq_host, char *password)
{
  if (zmq_host) {
    if (strlen(password) >= sizeof(zmq_host->zap.password)) {
      Log(LOG_ERR, "ERROR ( %s ): p_zmq_set_password(): password '%s' too long (maximum %lu chars). Exiting.\n",
	  zmq_host->log_id, password, (sizeof(zmq_host->zap.password) - 1));
      exit_gracefully(1);
    }
    else strlcpy(zmq_host->zap.password, password, sizeof(zmq_host->zap.password));
  }
}

void p_zmq_set_random_username(struct p_zmq_host *zmq_host)
{
  if (zmq_host) generate_random_string(zmq_host->zap.username, (sizeof(zmq_host->zap.username) - 1));
}

void p_zmq_set_random_password(struct p_zmq_host *zmq_host)
{
  if (zmq_host) generate_random_string(zmq_host->zap.password, (sizeof(zmq_host->zap.password) - 1));
}

void p_zmq_set_hwm(struct p_zmq_host *zmq_host, int hwm)
{
  if (zmq_host) zmq_host->hwm = hwm;  
}

void p_zmq_set_log_id(struct p_zmq_host *zmq_host, char *log_id)
{
  if (zmq_host) strlcpy(zmq_host->log_id, log_id, sizeof(zmq_host->log_id));
}

char *p_zmq_get_address(struct p_zmq_host *zmq_host)
{
  if (zmq_host) {
    if (strlen(zmq_host->sock.str)) return zmq_host->sock.str;
    else if (strlen(zmq_host->sock_inproc.str)) return zmq_host->sock_inproc.str;
  }

  return NULL;
}

u_int8_t p_zmq_get_topic(struct p_zmq_host *zmq_host)
{
  if (zmq_host) return zmq_host->topic;

  return 0;
}

void *p_zmq_get_sock(struct p_zmq_host *zmq_host)
{
  if (zmq_host) return zmq_host->sock.obj; 

  return NULL;
}

int p_zmq_get_fd(struct p_zmq_host *zmq_host)
{
  int fd = ERR;
  size_t len = sizeof(fd);

  if (zmq_host) {
    zmq_getsockopt(zmq_host->sock.obj, ZMQ_FD, &fd, &len);
  }

  return fd;
}

void p_zmq_init_push(struct p_zmq_host *zmq_host, char *address)
{
  if (zmq_host) {
    memset(zmq_host, 0, sizeof(struct p_zmq_host));
    p_zmq_set_address(zmq_host, address);
  }
}

void p_zmq_init_pub(struct p_zmq_host *zmq_host, char *address, u_int8_t topic)
{
  if (zmq_host) {
    memset(zmq_host, 0, sizeof(struct p_zmq_host));
    p_zmq_set_address(zmq_host, address);
    p_zmq_set_topic(zmq_host, topic);
  }
}

void p_zmq_plugin_pipe_init_core(struct p_zmq_host *zmq_host, u_int8_t plugin_id, char *username, char *password)
{
  if (zmq_host) {
    p_zmq_init_pub(zmq_host, NULL, plugin_id);

    if (!username) p_zmq_set_random_username(zmq_host);
    else p_zmq_set_username(zmq_host, username);

    if (!password) p_zmq_set_random_password(zmq_host);
    else p_zmq_set_password(zmq_host, password);
  }
}

void p_zmq_init_sub(struct p_zmq_host *zmq_host)
{
  p_zmq_plugin_pipe_init_plugin(zmq_host);
}

void p_zmq_init_pull(struct p_zmq_host *zmq_host)
{
  p_zmq_plugin_pipe_init_plugin(zmq_host);
}

void p_zmq_plugin_pipe_init_plugin(struct p_zmq_host *zmq_host)
{
  if (zmq_host) {

/*
    if (zmq_host->sock.obj) {
      zmq_unbind(zmq_host->sock.obj, zmq_host->sock.str);
      zmq_close(zmq_host->sock.obj);
    }

    if (zmq_host->zap.sock.obj) zmq_close(zmq_host->zap.sock.obj);
    if (zmq_host->zap.thread) zmq_threadclose(zmq_host->zap.thread);

    if (zmq_host->ctx) {
      zmq_ctx_shutdown(zmq_host->ctx);
      zmq_ctx_term(zmq_host->ctx);
      zmq_host->ctx = NULL;
    }
*/

    zmq_host->ctx = NULL;
  }
}

int p_zmq_plugin_pipe_set_profile(struct configuration *cfg, char *value)
{
  if (!strcmp("micro", value)) {
    cfg->pipe_zmq_profile = PLUGIN_PIPE_ZMQ_MICRO;
    cfg->buffer_size = PLUGIN_PIPE_ZMQ_MICRO_SIZE;
  }
  else if (!strcmp("small", value)) {
    cfg->pipe_zmq_profile = PLUGIN_PIPE_ZMQ_SMALL;
    cfg->buffer_size = PLUGIN_PIPE_ZMQ_SMALL_SIZE;
  }
  else if (!strcmp("medium", value)) {
    cfg->pipe_zmq_profile = PLUGIN_PIPE_ZMQ_MEDIUM;
    cfg->buffer_size = PLUGIN_PIPE_ZMQ_MEDIUM_SIZE;
  }
  else if (!strcmp("large", value)) {
    cfg->pipe_zmq_profile = PLUGIN_PIPE_ZMQ_LARGE;
    cfg->buffer_size = PLUGIN_PIPE_ZMQ_LARGE_SIZE;
  }
  else if (!strcmp("xlarge", value)) {
    cfg->pipe_zmq_profile = PLUGIN_PIPE_ZMQ_XLARGE;
    cfg->buffer_size = PLUGIN_PIPE_ZMQ_XLARGE_SIZE;
  }
  else return ERR;

  return SUCCESS;
}

int p_zmq_bind(struct p_zmq_host *zmq_host)
{
  int ret = 0, as_server = TRUE;
  size_t sock_strlen;

  if (strlen(zmq_host->zap.username) && strlen(zmq_host->zap.password)) {
    ret = zmq_setsockopt(zmq_host->sock.obj, ZMQ_PLAIN_SERVER, &as_server, sizeof(int));
    if (ret == ERR) {
      Log(LOG_ERR, "ERROR ( %s ): zmq_setsockopt() ZMQ_PLAIN_SERVER failed for topic %u: %s\nExiting.\n",
          zmq_host->log_id, zmq_host->topic, zmq_strerror(errno));
      exit_gracefully(1);
    }
  }

  if (strlen(zmq_host->sock_inproc.str)) {
    if (zmq_host->sock_inproc.obj_rx) {
      ret = zmq_bind(zmq_host->sock_inproc.obj_rx, zmq_host->sock_inproc.str);
    }
    else {
      ret = zmq_bind(zmq_host->sock_inproc.obj, zmq_host->sock_inproc.str);
    }
  }
  else if (strlen(zmq_host->sock.str)) {
    ret = zmq_bind(zmq_host->sock.obj, zmq_host->sock.str);
  }
  else {
    ret = zmq_bind(zmq_host->sock.obj, "tcp://127.0.0.1:*");
  }

  if (ret == ERR) {
    Log(LOG_ERR, "ERROR ( %s ): zmq_bind() failed for topic %u: %s\nExiting.\n",
        zmq_host->log_id, zmq_host->topic, zmq_strerror(errno));
    exit_gracefully(1);
  }

  if (!strlen(zmq_host->sock.str) && !strlen(zmq_host->sock_inproc.str)) {
    sock_strlen = sizeof(zmq_host->sock.str);
    ret = zmq_getsockopt(zmq_host->sock.obj, ZMQ_LAST_ENDPOINT, zmq_host->sock.str, &sock_strlen);
    if (ret == ERR) {
      Log(LOG_ERR, "ERROR ( %s ): zmq_getsockopt() ZMQ_LAST_ENDPOINT failed for topic %u: %s\nExiting.\n",
	  zmq_host->log_id, zmq_host->topic, zmq_strerror(errno));
      exit_gracefully(1);
    }
  }

  return ret;
}

int p_zmq_connect(struct p_zmq_host *zmq_host)
{
  int ret = 0;

  if (strlen(zmq_host->zap.username) && strlen(zmq_host->zap.password)) {
    ret = zmq_setsockopt(zmq_host->sock.obj, ZMQ_PLAIN_USERNAME, zmq_host->zap.username, strlen(zmq_host->zap.username));
    if (ret == ERR) {
      Log(LOG_ERR, "ERROR ( %s ): zmq_setsockopt() ZMQ_PLAIN_USERNAME failed: %s\nExiting.\n",
	  zmq_host->log_id, zmq_strerror(errno));
      exit_gracefully(1);
    }

    ret = zmq_setsockopt(zmq_host->sock.obj, ZMQ_PLAIN_PASSWORD, zmq_host->zap.password, strlen(zmq_host->zap.password));
    if (ret == ERR) {
      Log(LOG_ERR, "ERROR ( %s ): zmq_setsockopt() ZMQ_PLAIN_PASSWORD failed: %s\nExiting.\n",
	  zmq_host->log_id, zmq_strerror(errno));
      exit_gracefully(1);
    }
  }

  if (strlen(zmq_host->sock.str)) {
    ret = zmq_connect(zmq_host->sock.obj, zmq_host->sock.str);
  }
  else if (strlen(zmq_host->sock_inproc.str)) {
    if (zmq_host->sock_inproc.obj_tx) {
      ret = zmq_connect(zmq_host->sock_inproc.obj_tx, zmq_host->sock_inproc.str);
    }
    else {
      ret = zmq_connect(zmq_host->sock_inproc.obj, zmq_host->sock_inproc.str);
    }
  }

  if (ret == ERR) {
    Log(LOG_ERR, "ERROR ( %s ): zmq_connect() failed: %s (%s)\nExiting.\n",
        zmq_host->log_id, (strlen(zmq_host->sock.str) ? zmq_host->sock.str : zmq_host->sock_inproc.str),
        zmq_strerror(errno));
    exit_gracefully(1);
  }

  return ret;
}

void p_zmq_ctx_setup(struct p_zmq_host *zmq_host)
{
  if (!zmq_host->ctx) zmq_host->ctx = zmq_ctx_new();
}

void p_zmq_zap_setup(struct p_zmq_host *zmq_host)
{
  zmq_host->zap.thread = zmq_threadstart(&p_zmq_zap_handler, zmq_host);
}

void p_zmq_pub_setup(struct p_zmq_host *zmq_host)
{
  p_zmq_send_setup(zmq_host, ZMQ_PUB, FALSE);
}

void p_zmq_push_setup(struct p_zmq_host *zmq_host)
{
  p_zmq_send_setup(zmq_host, ZMQ_PUSH, FALSE);
}

void p_zmq_push_connect_setup(struct p_zmq_host *zmq_host)
{
  p_zmq_send_setup(zmq_host, ZMQ_PUSH, TRUE);
}

void p_zmq_send_setup(struct p_zmq_host *zmq_host, int type, int do_connect)
{
  int ret, only_one = 1;
  void *sock;

  if (!zmq_host) return;
  if (type != ZMQ_PUB && type != ZMQ_PUSH) return;

  if (!zmq_host->ctx) zmq_host->ctx = zmq_ctx_new();

  if (!do_connect) {
    if (strlen(zmq_host->zap.username) && strlen(zmq_host->zap.password)) {
      p_zmq_zap_setup(zmq_host);
    }
  }

  sock = zmq_socket(zmq_host->ctx, type);
  if (!sock) {
    Log(LOG_ERR, "ERROR ( %s ): zmq_socket() failed for topic %u: %s\nExiting.\n",
        zmq_host->log_id, zmq_host->topic, zmq_strerror(errno));
    exit_gracefully(1);
  }

  ret = zmq_setsockopt(sock, ZMQ_SNDHWM, &zmq_host->hwm, sizeof(int));
  if (ret == ERR) {
    Log(LOG_ERR, "ERROR ( %s ): zmq_setsockopt() ZMQ_SNDHWM failed for topic %u: %s\nExiting.\n",
	zmq_host->log_id, zmq_host->topic, zmq_strerror(errno));
    exit_gracefully(1);
  }

  ret = zmq_setsockopt(sock, ZMQ_BACKLOG, &only_one, sizeof(int));
  if (ret == ERR) {
    Log(LOG_ERR, "ERROR ( %s ): zmq_setsockopt() ZMQ_BACKLOG failed for topic %u: %s\nExiting.\n",
	zmq_host->log_id, zmq_host->topic, zmq_strerror(errno));
    exit_gracefully(1);
  }

  if (strlen(zmq_host->sock_inproc.str)) {
    zmq_host->sock_inproc.obj = sock;

    if (do_connect) {
      zmq_host->sock_inproc.obj_tx = zmq_host->sock_inproc.obj;
    }
    else {
      zmq_host->sock_inproc.obj_rx = zmq_host->sock_inproc.obj;
    }
  }
  else {
    zmq_host->sock.obj = sock;
  }

  if (!do_connect) p_zmq_bind(zmq_host);
  else p_zmq_connect(zmq_host);

  Log(LOG_DEBUG, "DEBUG ( %s ): p_zmq_send_setup() addr=%s username=%s password=%s\n",
      zmq_host->log_id, (strlen(zmq_host->sock.str) ? zmq_host->sock.str : zmq_host->sock_inproc.str),
      zmq_host->zap.username, zmq_host->zap.password);
}

void p_zmq_sub_setup(struct p_zmq_host *zmq_host)
{
  p_zmq_recv_setup(zmq_host, ZMQ_SUB, FALSE);
}

void p_zmq_pull_setup(struct p_zmq_host *zmq_host)
{
  p_zmq_recv_setup(zmq_host, ZMQ_PULL, FALSE);
}

void p_zmq_pull_bind_setup(struct p_zmq_host *zmq_host)
{
  p_zmq_recv_setup(zmq_host, ZMQ_PULL, TRUE);
}

void p_zmq_recv_setup(struct p_zmq_host *zmq_host, int type, int do_bind)
{
  int ret;
  void *sock;

  if (!zmq_host) return;
  if (type != ZMQ_SUB && type != ZMQ_PULL) return;

  if (!zmq_host->ctx) zmq_host->ctx = zmq_ctx_new();

  if (do_bind) {
    if (strlen(zmq_host->zap.username) && strlen(zmq_host->zap.password)) {
      p_zmq_zap_setup(zmq_host);
    }
  }

  sock = zmq_socket(zmq_host->ctx, type);
  if (!sock) {
    Log(LOG_ERR, "ERROR ( %s ): zmq_socket() failed for topic %u: %s\nExiting.\n",
        zmq_host->log_id, zmq_host->topic, zmq_strerror(errno));
    exit_gracefully(1);
  }

  ret = zmq_setsockopt(sock, ZMQ_RCVHWM, &zmq_host->hwm, sizeof(int));
  if (ret == ERR) {
    Log(LOG_ERR, "ERROR ( %s ): zmq_setsockopt() ZMQ_RCVHWM failed for topic %u: %s\nExiting.\n",
        zmq_host->log_id, zmq_host->topic, zmq_strerror(errno));
    exit_gracefully(1);
  }

  if (strlen(zmq_host->sock_inproc.str)) {
    zmq_host->sock_inproc.obj = sock;

    if (!do_bind) {
      zmq_host->sock_inproc.obj_tx = zmq_host->sock_inproc.obj;
    }
    else {
      zmq_host->sock_inproc.obj_rx = zmq_host->sock_inproc.obj; 
    }
  }
  else zmq_host->sock.obj = sock;

  if (!do_bind) ret = p_zmq_connect(zmq_host);
  else ret = p_zmq_bind(zmq_host);

  if (type == ZMQ_SUB) {
    if (zmq_host->topic) {
      ret = zmq_setsockopt(sock, ZMQ_SUBSCRIBE, &zmq_host->topic, sizeof(zmq_host->topic));
      if (ret == ERR) {
	Log(LOG_ERR, "ERROR ( %s ): zmq_setsockopt() SUBSCRIBE failed for topic %u: %s\nExiting.\n",
	    zmq_host->log_id, zmq_host->topic, zmq_strerror(errno));
	exit_gracefully(1);
      }
    }
    /* subscribe to all topics */
    else zmq_setsockopt(sock, ZMQ_SUBSCRIBE, NULL, 0);
  }

  Log(LOG_DEBUG, "DEBUG ( %s ): p_zmq_recv_setup() addr=%s username=%s password=%s\n",
      zmq_host->log_id, (strlen(zmq_host->sock.str) ? zmq_host->sock.str : zmq_host->sock_inproc.str),
      zmq_host->zap.username, zmq_host->zap.password);
}

int p_zmq_topic_send(struct p_zmq_host *zmq_host, void *buf, u_int64_t len)
{
  int ret;

  ret = zmq_send(zmq_host->sock.obj, &zmq_host->topic, sizeof(zmq_host->topic), ZMQ_SNDMORE);
  if (ret == ERR) {
    Log(LOG_ERR, "ERROR ( %s ): publishing topic to ZMQ: zmq_send(): %s [topic=%u]\n",
	zmq_host->log_id, zmq_strerror(errno), zmq_host->topic);
    return ret;
  }

  ret = zmq_send(zmq_host->sock.obj, buf, len, 0);
  if (ret == ERR) {
    Log(LOG_ERR, "ERROR ( %s ): publishing data to ZMQ: zmq_send(): %s [topic=%u]\n",
	zmq_host->log_id, zmq_strerror(errno), zmq_host->topic);
    return ret;
  }

  return ret;
}

int p_zmq_recv_poll(struct p_zmq_sock *sock, int timeout)
{
  zmq_pollitem_t item[1];
  void *s;

  if (sock->obj_rx) s = sock->obj_rx;
  else s = sock->obj;

  item[0].socket = s;
  item[0].events = ZMQ_POLLIN;

  return zmq_poll(item, 1, timeout);
}

int p_zmq_topic_recv(struct p_zmq_host *zmq_host, void *buf, u_int64_t len)
{
  int ret = 0, events;
  size_t elen = sizeof(events);
  u_int8_t topic, retries = 0;

  zmq_events_again:
  ret = zmq_getsockopt(zmq_host->sock.obj, ZMQ_EVENTS, &events, &elen); 
  if (ret == ERR) {
    if (retries < PM_ZMQ_EVENTS_RETRIES) {
      Log(LOG_DEBUG, "DEBUG ( %s ): consuming topic from ZMQ: zmq_getsockopt() for ZMQ_EVENTS: %s [topic=%u]\n",
	zmq_host->log_id, zmq_strerror(errno), zmq_host->topic);
      retries++;
      goto zmq_events_again;
    }
    else {
      Log(LOG_ERR, "ERROR ( %s ): consuming topic from ZMQ: zmq_getsockopt() for ZMQ_EVENTS: %s [topic=%u]\n",
	zmq_host->log_id, zmq_strerror(errno), zmq_host->topic);

      return ret;
    }
  }

  if (events & ZMQ_POLLIN) {
    ret = zmq_recv(zmq_host->sock.obj, &topic, 1, 0); /* read topic first */
    if (ret == ERR) {
      Log(LOG_ERR, "ERROR ( %s ): consuming topic from ZMQ: zmq_recv(): %s [topic=%u]\n",
	  zmq_host->log_id, zmq_strerror(errno), zmq_host->topic);
      return ret;
    }

    ret = zmq_recv(zmq_host->sock.obj, buf, len, 0); /* read actual data then */
    if (ret == ERR)
      Log(LOG_ERR, "ERROR ( %s ): consuming data from ZMQ: zmq_recv(): %s [topic=%u]\n",
	  zmq_host->log_id, zmq_strerror(errno), zmq_host->topic);
    else if (ret > len) {
      Log(LOG_ERR, "ERROR ( %s ): consuming data from ZMQ: zmq_recv(): buffer overrun [topic=%u]\n",
	  zmq_host->log_id, zmq_host->topic);
      ret = ERR;
    }
  }

  return ret;
}

char *p_zmq_recv_str(struct p_zmq_sock *sock)
{
  char buf[SRVBUFLEN];
  int len;
  void *s;

  if (sock->obj_rx) s = sock->obj_rx;
  else s = sock->obj;

  memset(buf, 0, sizeof(buf)); 
  len = zmq_recv(s, buf, (sizeof(buf) - 1), 0);
  if (len == ERR) return NULL;
  else return strndup(buf, sizeof(buf));
}

int p_zmq_send_str(struct p_zmq_sock *sock, char *buf)
{
  int len;
  void *s;

  if (sock->obj_rx) s = sock->obj_rx;
  else s = sock->obj;

  len = zmq_send(s, buf, strlen(buf), 0);

  return len;
}

int p_zmq_sendmore_str(struct p_zmq_sock *sock, char *buf)
{
  int len;
  void *s;

  if (sock->obj_rx) s = sock->obj_rx;
  else s = sock->obj;

  len = zmq_send(s, buf, strlen(buf), ZMQ_SNDMORE);

  return len;
}

int p_zmq_recv_bin(struct p_zmq_sock *sock, void *buf, size_t len)
{
  int rcvlen;
  void *s;

  if (sock->obj_rx) s = sock->obj_rx;
  else s = sock->obj;

  rcvlen = zmq_recv(s, buf, len, 0);

  return rcvlen;
}

int p_zmq_send_bin(struct p_zmq_sock *sock, void *buf, size_t len, int nonblock)
{
  int sndlen;
  void *s;

  if (sock->obj_tx) s = sock->obj_tx;
  else s = sock->obj;

  if (!nonblock) sndlen = zmq_send(s, buf, len, 0);
  else sndlen = zmq_send(s, buf, len, ZMQ_DONTWAIT);

  return sndlen;
}

int p_zmq_sendmore_bin(struct p_zmq_sock *sock, void *buf, size_t len, int nonblock)
{
  int sndlen;
  void *s;

  if (sock->obj_tx) s = sock->obj_tx;
  else s = sock->obj;

  if (!nonblock) sndlen = zmq_send(s, buf, len, ZMQ_SNDMORE);
  else sndlen = zmq_send(s, buf, len, (ZMQ_SNDMORE|ZMQ_DONTWAIT));

  return sndlen;
}

void p_zmq_zap_handler(void *zh)
{
  struct p_zmq_host *zmq_host = (struct p_zmq_host *) zh;
  struct p_zmq_sock zmq_sock;
  int ret;

  memset(&zmq_sock, 0, sizeof(zmq_sock));

  zmq_sock.obj = zmq_socket(zmq_host->ctx, ZMQ_REP);
  if (!zmq_sock.obj) {
    Log(LOG_ERR, "ERROR ( %s ): zmq_socket() ZAP failed (%s)\nExiting.\n",
        zmq_host->log_id, zmq_strerror(errno));
    exit_gracefully(1);
  }

  snprintf(zmq_sock.str, sizeof(zmq_sock.str), "%s", "inproc://zeromq.zap.01");
  ret = zmq_bind(zmq_sock.obj, zmq_sock.str);
  if (ret == ERR) {
    Log(LOG_ERR, "ERROR ( %s ): zmq_bind() ZAP failed (%s)\nExiting.\n",
        zmq_host->log_id, zmq_strerror(errno));
    exit_gracefully(1);
  }

  while (TRUE) {
    char *version, *sequence, *domain, *address, *identity;
    char *mechanism, *username, *password;

    version = p_zmq_recv_str(&zmq_sock);
    if (!version) break;

    sequence = p_zmq_recv_str(&zmq_sock);
    domain = p_zmq_recv_str(&zmq_sock);
    address = p_zmq_recv_str(&zmq_sock);
    identity = p_zmq_recv_str(&zmq_sock);
    mechanism = p_zmq_recv_str(&zmq_sock);

    if (!strcmp(version, "1.0") && !strcmp(mechanism, "PLAIN")) {
      username = p_zmq_recv_str(&zmq_sock);
      password = p_zmq_recv_str(&zmq_sock);

      p_zmq_sendmore_str(&zmq_sock, version);
      p_zmq_sendmore_str(&zmq_sock, sequence);

      if (!strcmp(username, zmq_host->zap.username) &&
	  !strcmp(password, zmq_host->zap.password)) {
        p_zmq_sendmore_str(&zmq_sock, "200");
        p_zmq_sendmore_str(&zmq_sock, "OK");
        p_zmq_sendmore_str(&zmq_sock, "anonymous");
        p_zmq_send_str(&zmq_sock, "");
      }
      else {
        p_zmq_sendmore_str(&zmq_sock, "400");
        p_zmq_sendmore_str(&zmq_sock, "Invalid username or password");
        p_zmq_sendmore_str(&zmq_sock, "");
        p_zmq_send_str(&zmq_sock, "");
      }

      free(username);
      free(password);
    }
    else {
      p_zmq_sendmore_str(&zmq_sock, version);
      p_zmq_sendmore_str(&zmq_sock, sequence);
      p_zmq_sendmore_str(&zmq_sock, "400");
      p_zmq_sendmore_str(&zmq_sock, "Unsupported auth mechanism");
      p_zmq_sendmore_str(&zmq_sock, "");
      p_zmq_send_str(&zmq_sock, "");
    }

    free(version);
    free(sequence);
    free(domain);
    free(address);
    free(identity);
    free(mechanism);
  }

  zmq_close(zmq_sock.obj);
}

void p_zmq_router_setup(struct p_zmq_host *zmq_host, char *host, int port)
{
  char server_str[SHORTBUFLEN];
  int ret, as_server = TRUE;

  if (!zmq_host->ctx) zmq_host->ctx = zmq_ctx_new();

  zmq_host->sock.obj = zmq_socket(zmq_host->ctx, ZMQ_ROUTER);
  if (!zmq_host->sock.obj) {
    Log(LOG_ERR, "ERROR ( %s ): zmq_socket() failed for ZMQ_ROUTER: %s\nExiting.\n",
	zmq_host->log_id, zmq_strerror(errno));
    exit_gracefully(1);
  }

  if (strlen(zmq_host->zap.username) && strlen(zmq_host->zap.password)) {
    p_zmq_zap_setup(zmq_host);

    ret = zmq_setsockopt(zmq_host->sock.obj, ZMQ_PLAIN_SERVER, &as_server, sizeof(int));
    if (ret == ERR) {
      Log(LOG_ERR, "ERROR ( %s ): zmq_setsockopt() ZMQ_PLAIN_SERVER failed for topic %u: %s\nExiting.\n",
	  zmq_host->log_id, zmq_host->topic, zmq_strerror(errno));
      exit_gracefully(1);
    }
  }

  snprintf(server_str, SHORTBUFLEN, "tcp://%s:%u", host, port);

  ret = zmq_bind(zmq_host->sock.obj, server_str);
  if (ret == ERR) {
    Log(LOG_ERR, "ERROR ( %s ): zmq_bind() failed for ZMQ_ROUTER: %s\nExiting.\n",
	zmq_host->log_id, zmq_strerror(errno));
    exit_gracefully(1);
  }
}

void p_zmq_dealer_inproc_setup(struct p_zmq_host *zmq_host)
{
  int ret;

  if (!zmq_host->ctx) zmq_host->ctx = zmq_ctx_new();

  zmq_host->sock_inproc.obj = zmq_socket(zmq_host->ctx, ZMQ_DEALER);
  if (!zmq_host->sock_inproc.obj) {
    Log(LOG_ERR, "ERROR ( %s ): zmq_socket() failed for ZMQ_DEALER: %s\nExiting.\n",
	zmq_host->log_id, zmq_strerror(errno));
    exit_gracefully(1);
  }

  ret = zmq_bind(zmq_host->sock_inproc.obj, zmq_host->sock_inproc.str);
  if (ret == ERR) {
    Log(LOG_ERR, "ERROR ( %s ): zmq_bind() failed for ZMQ_DEALER: %s\nExiting.\n",
	zmq_host->log_id, zmq_strerror(errno));
    exit_gracefully(1);
  }
}

void p_zmq_proxy_setup(struct p_zmq_host *zmq_host)
{
  int ret;

  ret = zmq_proxy(zmq_host->sock.obj, zmq_host->sock_inproc.obj, NULL);
  if (ret == ERR) {
    Log(LOG_ERR, "ERROR ( %s ): zmq_proxy() failed: %s\nExiting.\n",
	zmq_host->log_id, zmq_strerror(errno));
    exit_gracefully(1);
  }
}

void p_zmq_router_backend_setup(struct p_zmq_host *zmq_host, int thread_nbr)
{
  int idx;

  p_zmq_dealer_inproc_setup(zmq_host);
  zmq_host->router_worker.threads = malloc(sizeof(void *) * thread_nbr);

  for (idx = 0; idx < thread_nbr; idx++) {
    zmq_host->router_worker.threads[thread_nbr] = zmq_threadstart(&p_zmq_router_worker, zmq_host);
  }

  p_zmq_proxy_setup(zmq_host);
}

void p_zmq_router_worker(void *zh)
{
  struct p_zmq_host *zmq_host = (struct p_zmq_host *) zh;
  struct p_zmq_sock sock;
  int ret;

  assert(zmq_host);
  memset(&sock, 0, sizeof(sock));

  sock.obj = zmq_socket(zmq_host->ctx, ZMQ_REP);
  if (!sock.obj) {
    Log(LOG_ERR, "ERROR ( %s ): p_zmq_router_worker zmq_socket() failed: %s (%s)\nExiting.\n",
        zmq_host->log_id, zmq_host->sock_inproc.str, zmq_strerror(errno));
    exit_gracefully(1);
  }

  ret = zmq_connect(sock.obj, zmq_host->sock_inproc.str);
  if (ret == ERR) {
    Log(LOG_ERR, "ERROR ( %s ): p_zmq_router_worker zmq_connect() failed: %s (%s)\nExiting.\n",
        zmq_host->log_id, zmq_host->sock_inproc.str, zmq_strerror(errno));
    exit_gracefully(1);
  }

  zmq_host->router_worker.func(zmq_host, &sock);
}

void p_zmq_close(struct p_zmq_host *zmq_host)
{
  p_zmq_plugin_pipe_init_plugin(zmq_host);
}
