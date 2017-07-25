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

/* defines */

/* structures */
struct p_zmq_host {
  void *ctx;
  void *sock;

  int port;
  char *pname;
  char *ptype;
};

/* prototypes */
#if (!defined __ZMQ_COMMON_C)
#define EXT extern
#else
#define EXT
#endif
EXT void p_zmq_set_port(struct p_zmq_host *, int);
EXT void p_zmq_set_plugin_name(struct p_zmq_host *, char *);
EXT void p_zmq_set_plugin_type(struct p_zmq_host *, char *);

EXT void p_zmq_plugin_pipe_publish(struct p_zmq_host *);
EXT void p_zmq_plugin_pipe_consume(struct p_zmq_host *);

/* global vars */
#undef EXT
