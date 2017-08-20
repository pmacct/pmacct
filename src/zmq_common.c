/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2017 by Paolo Lucente
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

#define __ZMQ_COMMON_C

/* includes */
#include "pmacct.h"
#include "pmacct-data.h"
#include "zmq_common.h"

/* Functions */
void p_zmq_set_topic(struct p_zmq_host *zmq_host, u_int8_t topic)
{
  if (zmq_host) zmq_host->topic = topic;
}

void p_zmq_set_retry_timeout(struct p_zmq_host *zmq_host, int tout)
{
  int ret;

  if (zmq_host) {
    zmq_setsockopt(zmq_host->sock, ZMQ_RECONNECT_IVL, &tout, sizeof(tout));
    if (ret != 0) {
      Log(LOG_ERR, "ERROR ( %s/%s ): zmq_setsockopt() RECONNECT_IVL failed for topic %u: %s\nExiting.\n",
	config.name, config.type, zmq_host->topic, zmq_strerror(errno));
      exit_plugin(1);
    }
  }
}

void p_zmq_set_username(struct p_zmq_host *zmq_host)
{
  if (zmq_host) generate_random_string(zmq_host->zap.username, (sizeof(zmq_host->zap.username) - 1));
}

void p_zmq_set_password(struct p_zmq_host *zmq_host)
{
  if (zmq_host) generate_random_string(zmq_host->zap.password, (sizeof(zmq_host->zap.password) - 1));
}

int p_zmq_get_fd(struct p_zmq_host *zmq_host)
{
  int fd = ERR;
  size_t len = sizeof(fd);

  if (zmq_host) {
    zmq_getsockopt(zmq_host->sock, ZMQ_FD, &fd, &len);
  }

  return fd;
}

void p_zmq_plugin_pipe_init_core(struct p_zmq_host *zmq_host, u_int8_t plugin_id)
{
  int ret;

  if (zmq_host) {
    memset(zmq_host, 0, sizeof(struct p_zmq_host));
    p_zmq_set_topic(zmq_host, plugin_id);
    p_zmq_set_username(zmq_host);
    p_zmq_set_password(zmq_host);
  }
}

void p_zmq_plugin_pipe_init_plugin(struct p_zmq_host *zmq_host)
{
  if (zmq_host) {
    if (zmq_host->sock) {
      zmq_unbind(zmq_host->sock, zmq_host->bind_str);
      zmq_close(zmq_host->sock);
    }

    if (zmq_host->zap.sock) zmq_close(zmq_host->zap.sock);
    if (zmq_host->zap.thread) zmq_threadclose(zmq_host->zap.thread);

    if (zmq_host->ctx) {
      zmq_ctx_shutdown(zmq_host->ctx);
      zmq_ctx_term(zmq_host->ctx);
      zmq_host->ctx = NULL;
    }
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

void p_zmq_plugin_pipe_publish(struct p_zmq_host *zmq_host)
{
  int ret, as_server = TRUE, only_one = 1, no_hwm = 0;
  size_t bind_strlen;

  if (!zmq_host->ctx) zmq_host->ctx = zmq_ctx_new();

  if (!zmq_host->zap.sock) {
    zmq_host->zap.sock = zmq_socket(zmq_host->ctx, ZMQ_REP);

    ret = zmq_bind(zmq_host->zap.sock, "inproc://zeromq.zap.01");
    if (ret == ERR) {
      Log(LOG_ERR, "ERROR ( %s/%s ): zmq_bind() failed binding ZAP (%s)\nExiting.\n",
	config.name, config.type, zmq_strerror(errno));
      exit(1);
    }

    zmq_host->zap.thread = zmq_threadstart(&p_zmq_zap_handler, zmq_host);
  }

  zmq_host->sock = zmq_socket(zmq_host->ctx, ZMQ_PUB);

  ret = zmq_setsockopt(zmq_host->sock, ZMQ_SNDHWM, &no_hwm, sizeof(int));
  if (ret == ERR) {
    Log(LOG_ERR, "ERROR ( %s/%s ): zmq_setsockopt() ZMQ_SNDHWM failed for topic %u: %s\nExiting.\n",
        config.name, config.type, zmq_host->topic, zmq_strerror(errno));
    exit(1);
  }

  ret = zmq_setsockopt(zmq_host->sock, ZMQ_BACKLOG, &only_one, sizeof(int));
  if (ret == ERR) {
    Log(LOG_ERR, "ERROR ( %s/%s ): zmq_setsockopt() ZMQ_BACKLOG failed for topic %u: %s\nExiting.\n",
        config.name, config.type, zmq_host->topic, zmq_strerror(errno));
    exit(1);
  }

  ret = zmq_setsockopt(zmq_host->sock, ZMQ_PLAIN_SERVER, &as_server, sizeof(int));
  if (ret == ERR) {
    Log(LOG_ERR, "ERROR ( %s/%s ): zmq_setsockopt() ZMQ_PLAIN_SERVER failed for topic %u: %s\nExiting.\n",
	config.name, config.type, zmq_host->topic, zmq_strerror(errno));
    exit(1);
  }

  ret = zmq_bind(zmq_host->sock, "tcp://127.0.0.1:*");
  if (ret == ERR) {
    Log(LOG_ERR, "ERROR ( %s/%s ): zmq_bind() failed for topic %u: %s\nExiting.\n",
	config.name, config.type, zmq_host->topic, zmq_strerror(errno));
    exit(1);
  }

  bind_strlen = sizeof(zmq_host->bind_str);
  ret = zmq_getsockopt(zmq_host->sock, ZMQ_LAST_ENDPOINT, zmq_host->bind_str, &bind_strlen);
  if (ret == ERR) {
    Log(LOG_ERR, "ERROR ( %s/%s ): zmq_getsockopt() ZMQ_LAST_ENDPOINT failed for topic %u: %s\nExiting.\n",
        config.name, config.type, zmq_host->topic, zmq_strerror(errno));
    exit(1);
  }
}

void p_zmq_plugin_pipe_consume(struct p_zmq_host *zmq_host)
{
  int ret, no_hwm = 0;

  if (!zmq_host->ctx) zmq_host->ctx = zmq_ctx_new();

  zmq_host->sock = zmq_socket(zmq_host->ctx, ZMQ_SUB);

  ret = zmq_setsockopt(zmq_host->sock, ZMQ_RCVHWM, &no_hwm, sizeof(int));
  if (ret == ERR) {
    Log(LOG_ERR, "ERROR ( %s/%s ): zmq_setsockopt() ZMQ_RCVHWM failed for topic %u: %s\nExiting.\n",
        config.name, config.type, zmq_host->topic, zmq_strerror(errno));
    exit(1);
  }

  ret = zmq_setsockopt(zmq_host->sock, ZMQ_PLAIN_USERNAME, zmq_host->zap.username, strlen(zmq_host->zap.username));
  if (ret == ERR) {
    Log(LOG_ERR, "ERROR ( %s/%s ): zmq_setsockopt() ZMQ_PLAIN_USERNAME failed: %s\nExiting.\n",
	config.name, config.type, zmq_strerror(errno));
    exit_plugin(1);
  }

  ret = zmq_setsockopt(zmq_host->sock, ZMQ_PLAIN_PASSWORD, zmq_host->zap.password, strlen(zmq_host->zap.password));
  if (ret == ERR) {
    Log(LOG_ERR, "ERROR ( %s/%s ): zmq_setsockopt() ZMQ_PLAIN_PASSWORD failed: %s\nExiting.\n",
	config.name, config.type, zmq_strerror(errno));
    exit_plugin(1);
  }

  ret = zmq_connect(zmq_host->sock, zmq_host->bind_str);
  if (ret == ERR) {
    Log(LOG_ERR, "ERROR ( %s/%s ): zmq_connect() failed: %s (%s)\nExiting.\n",
	config.name, config.type, zmq_host->bind_str, zmq_strerror(errno));
    exit_plugin(1);
  }

  ret = zmq_setsockopt(zmq_host->sock, ZMQ_SUBSCRIBE, &zmq_host->topic, sizeof(zmq_host->topic));
  if (ret == ERR) {
    Log(LOG_ERR, "ERROR ( %s/%s ): zmq_setsockopt() SUBSCRIBE failed for topic %u: %s\nExiting.\n",
        config.name, config.type, zmq_host->topic, zmq_strerror(errno));
    exit_plugin(1);
  }
}

int p_zmq_plugin_pipe_send(struct p_zmq_host *zmq_host, void *buf, u_int64_t len)
{
  zmq_msg_t topic, msg;
  int ret;

  ret = zmq_send(zmq_host->sock, &zmq_host->topic, sizeof(zmq_host->topic), ZMQ_SNDMORE);
  if (ret == ERR) {
    Log(LOG_ERR, "ERROR ( %s/%s ): publishing topic to ZMQ: p_zmq_send(): %s [topic=%u]\n",
		config.name, config.type, zmq_strerror(errno), zmq_host->topic);
    return ret;
  }

  ret = zmq_send(zmq_host->sock, buf, len, 0);
  if (ret == ERR) {
    Log(LOG_ERR, "ERROR ( %s/%s ): publishing data to ZMQ: p_zmq_send(): %s [topic=%u]\n",
		config.name, config.type, zmq_strerror(errno), zmq_host->topic);
    return ret;
  }

  return ret;
}

int p_zmq_plugin_pipe_recv(struct p_zmq_host *zmq_host, void *buf, u_int64_t len)
{
  int ret = 0, events;
  size_t elen = sizeof(events);
  u_int8_t topic;

  zmq_getsockopt(zmq_host->sock, ZMQ_EVENTS, &events, &elen); 

  if (events & ZMQ_POLLIN) {
    ret = zmq_recv(zmq_host->sock, &topic, 1, 0); /* read topic first */
    if (ret == ERR) {
      Log(LOG_ERR, "ERROR ( %s/%s ): consuming topic from ZMQ: p_zmq_recv(): %s [topic=%u]\n",
		config.name, config.type, zmq_strerror(errno), zmq_host->topic);
      return ret;
    }

    ret = zmq_recv(zmq_host->sock, buf, len, 0); /* read actual data then */
    if (ret == ERR)
      Log(LOG_ERR, "ERROR ( %s/%s ): consuming data from ZMQ: p_zmq_recv(): %s [topic=%u]\n",
		config.name, config.type, zmq_strerror(errno), zmq_host->topic);
    else if (ret > len) {
      Log(LOG_ERR, "ERROR ( %s/%s ): consuming data from ZMQ: p_zmq_recv(): buffer overrun [topic=%u]\n",
		config.name, config.type, zmq_host->topic);
      ret = ERR;
    }
  }

  return ret;
}

char *p_zmq_recv_str(void *sock)
{
  char buf[SRVBUFLEN];
  int len;

  memset(buf, 0, sizeof(buf)); 
  len = zmq_recv(sock, buf, (sizeof(buf) - 1), 0);
  if (len == ERR) return NULL;
  else return strndup(buf, sizeof(buf));
}

int p_zmq_send_str(void *sock, char *buf)
{
  int len;

  len = zmq_send(sock, buf, strlen(buf), 0);

  return len;
}

int p_zmq_sendmore_str(void *sock, char *buf)
{
  int len;

  len = zmq_send(sock, buf, strlen(buf), ZMQ_SNDMORE);

  return len;
}

void p_zmq_zap_handler(void *zh)
{
  struct p_zmq_host *zmq_host = (struct p_zmq_host *) zh;

  while (TRUE) {
    char *version, *sequence, *domain, *address, *identity;
    char *mechanism, *username, *password;

    version = p_zmq_recv_str(zmq_host->zap.sock);
    if (!version) break;

    sequence = p_zmq_recv_str(zmq_host->zap.sock);
    domain = p_zmq_recv_str(zmq_host->zap.sock);
    address = p_zmq_recv_str(zmq_host->zap.sock);
    identity = p_zmq_recv_str(zmq_host->zap.sock);
    mechanism = p_zmq_recv_str(zmq_host->zap.sock);

    if (!strcmp(version, "1.0") && !strcmp(mechanism, "PLAIN")) {
      username = p_zmq_recv_str(zmq_host->zap.sock);
      password = p_zmq_recv_str(zmq_host->zap.sock);

      p_zmq_sendmore_str(zmq_host->zap.sock, version);
      p_zmq_sendmore_str(zmq_host->zap.sock, sequence);

      if (!strcmp(username, zmq_host->zap.username) &&
	  !strcmp(password, zmq_host->zap.password)) {
        p_zmq_sendmore_str(zmq_host->zap.sock, "200");
        p_zmq_sendmore_str(zmq_host->zap.sock, "OK");
        p_zmq_sendmore_str(zmq_host->zap.sock, "anonymous");
        p_zmq_send_str(zmq_host->zap.sock, "");
      }
      else {
        p_zmq_sendmore_str(zmq_host->zap.sock, "400");
        p_zmq_sendmore_str(zmq_host->zap.sock, "Invalid username or password");
        p_zmq_sendmore_str(zmq_host->zap.sock, "");
        p_zmq_send_str(zmq_host->zap.sock, "");
      }

      free(username);
      free(password);
    }
    else {
      p_zmq_sendmore_str(zmq_host->zap.sock, version);
      p_zmq_sendmore_str(zmq_host->zap.sock, sequence);
      p_zmq_sendmore_str(zmq_host->zap.sock, "400");
      p_zmq_sendmore_str(zmq_host->zap.sock, "Unsupported auth mechanism");
      p_zmq_sendmore_str(zmq_host->zap.sock, "");
      p_zmq_send_str(zmq_host->zap.sock, "");
    }

    free(version);
    free(sequence);
    free(domain);
    free(address);
    free(identity);
    free(mechanism);
  }

  zmq_close(zmq_host->zap.sock);
}
