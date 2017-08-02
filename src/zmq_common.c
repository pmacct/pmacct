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
void p_zmq_set_port(struct p_zmq_host *zmq_host, int port)
{
  if (zmq_host) zmq_host->port = port;
}

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
	config.name, config.type, zmq_host->topic, strerror(errno));
      exit_plugin(1);
    }
  }
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

void p_zmq_plugin_pipe_publish(struct p_zmq_host *zmq_host)
{
  char bind_str[VERYSHORTBUFLEN];
  int ret;

  if (!zmq_host->ctx) zmq_host->ctx = zmq_ctx_new();

  zmq_host->sock = zmq_socket(zmq_host->ctx, ZMQ_PUB);

  snprintf(bind_str, VERYSHORTBUFLEN, "%s:%u", "tcp://127.0.0.1", zmq_host->port);
  ret = zmq_bind(zmq_host->sock, bind_str);
  if (ret == ERR) {
    Log(LOG_ERR, "ERROR ( %s/%s ): zmq_bind() failed binding for topic %u: %s (%s)\nExiting.\n",
	config.name, config.type, zmq_host->topic, bind_str, strerror(errno));
    exit(1);
  }
}

void p_zmq_plugin_pipe_consume(struct p_zmq_host *zmq_host)
{
  char bind_str[VERYSHORTBUFLEN];
  int ret;

  if (!zmq_host->ctx) zmq_host->ctx = zmq_ctx_new();

  zmq_host->sock = zmq_socket(zmq_host->ctx, ZMQ_SUB);

  snprintf(bind_str, VERYSHORTBUFLEN, "%s:%u", "tcp://127.0.0.1", zmq_host->port);
  ret = zmq_connect(zmq_host->sock, bind_str);
  if (ret == ERR) {
    Log(LOG_ERR, "ERROR ( %s/%s ): zmq_connect() failed: %s (%s)\nExiting.\n",
	config.name, config.type, bind_str, strerror(errno));
    exit_plugin(1);
  }

  ret = zmq_setsockopt(zmq_host->sock, ZMQ_SUBSCRIBE, &zmq_host->topic, sizeof(zmq_host->topic));
  if (ret == ERR) {
    Log(LOG_ERR, "ERROR ( %s/%s ): zmq_setsockopt() SUBSCRIBE failed for topic %u: %s\nExiting.\n",
        config.name, config.type, zmq_host->topic, strerror(errno));
    exit_plugin(1);
  }
}

int p_zmq_send(struct p_zmq_host *zmq_host, void *data, u_int32_t data_len)
{
  zmq_msg_t topic, msg;
  int ret;

  ret = zmq_send(zmq_host->sock, &zmq_host->topic, sizeof(zmq_host->topic), ZMQ_SNDMORE);
  if (ret == ERR) {
    Log(LOG_ERR, "ERROR ( %s/%s ): publishing topic to ZMQ: p_zmq_send(): %s [topic=%u]\n",
		config.name, config.type, strerror(errno), zmq_host->topic);
    return ret;
  }

  ret = zmq_send(zmq_host->sock, data, data_len, 0);
  if (ret == ERR) {
    Log(LOG_ERR, "ERROR ( %s/%s ): publishing data to ZMQ: p_zmq_send(): %s [topic=%u]\n",
		config.name, config.type, strerror(errno), zmq_host->topic);
    return ret;
  }

  return ret;
}

int p_zmq_recv(struct p_zmq_host *zmq_host, char *buf, u_int64_t len)
{
  int ret = 0, events;
  size_t elen = sizeof(events);
  u_int8_t topic;

  zmq_getsockopt(zmq_host->sock, ZMQ_EVENTS, &events, &elen); 

  if (events & ZMQ_POLLIN) {
    ret = zmq_recv(zmq_host->sock, &topic, 1, 0); /* read topic first */
    if (ret == ERR) {
      Log(LOG_ERR, "ERROR ( %s/%s ): consuming topic from ZMQ: p_zmq_recv(): %s [topic=%u]\n",
		config.name, config.type, strerror(errno), zmq_host->topic);
      return ret;
    }

    ret = zmq_recv(zmq_host->sock, buf, len, 0); /* read actual data then */
    if (ret == ERR)
      Log(LOG_ERR, "ERROR ( %s/%s ): consuming data from ZMQ: p_zmq_recv(): %s [topic=%u]\n",
		config.name, config.type, strerror(errno), zmq_host->topic);
    else if (ret > len) {
      Log(LOG_ERR, "ERROR ( %s/%s ): consuming data from ZMQ: p_zmq_recv(): buffer overrun [topic=%u]\n",
		config.name, config.type, zmq_host->topic);
      ret = ERR;
    }
  }

  return ret;
}
