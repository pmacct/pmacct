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

void p_zmq_set_plugin_name(struct p_zmq_host *zmq_host, char *pname)
{
  if (zmq_host) zmq_host->pname = pname;
}

void p_zmq_set_plugin_type(struct p_zmq_host *zmq_host, char *ptype)
{
  if (zmq_host) zmq_host->ptype = ptype;
}

void p_zmq_plugin_pipe_publish(struct p_zmq_host *zmq_host)
{
  char bind_str[VERYSHORTBUFLEN];
  int ret;

  if (!zmq_host->ctx) zmq_host->ctx = zmq_ctx_new();

  zmq_host->sock = zmq_socket(zmq_host->ctx, ZMQ_PUB);

  snprintf(bind_str, VERYSHORTBUFLEN, "%s:%u", "tcp://127.0.0.1", zmq_host->port);
  ret = zmq_bind(zmq_host->sock, bind_str);
  if (ret != 0) {
    Log(LOG_ERR, "ERROR ( %s/%s ): zmq_bind() failed binding: %s (%s)\nExiting.\n",
	zmq_host->pname, zmq_host->ptype, bind_str, strerror(errno));
    exit(1);
  }
}

void p_zmq_plugin_pipe_consume(struct p_zmq_host *zmq_host)
{
  char bind_str[VERYSHORTBUFLEN], filter[SRVBUFLEN];
  int ret;

  if (!zmq_host->ctx) zmq_host->ctx = zmq_ctx_new();

  zmq_host->sock = zmq_socket(zmq_host->ctx, ZMQ_SUB);

  snprintf(bind_str, VERYSHORTBUFLEN, "%s:%u", "tcp://127.0.0.1", zmq_host->port);
  ret = zmq_connect(zmq_host->sock, bind_str);
  if (ret != 0) {
    Log(LOG_ERR, "ERROR ( %s/%s ): zmq_connect() failed: %s (%s)\nExiting.\n",
	zmq_host->pname, zmq_host->ptype, bind_str, strerror(errno));
    exit_plugin(1);
  }

  snprintf(filter, SRVBUFLEN, "%s/%s", zmq_host->pname, zmq_host->ptype);
  ret = zmq_setsockopt(zmq_host->sock, ZMQ_SUBSCRIBE, filter, strlen(filter));
  if (ret != 0) {
    Log(LOG_ERR, "ERROR ( %s/%s ): zmq_setsockopt() failed %s\nExiting.\n",
        zmq_host->pname, zmq_host->ptype, strerror(errno));
    exit_plugin(1);
  }
}
