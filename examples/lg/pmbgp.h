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

#define __PMBGP_H
#ifdef WITH_ZMQ

/* defines */
#define ARGS_PMBGP "hVa:d:r:R:z:Z:u:p:g"
#define PMBGP_USAGE_HEADER "pmacct BGP Looking Glass client, pmbgp"

/* prototypes */
#if !defined(__PMBGP_C)
#define EXT extern
#else
#define EXT
EXT void usage_pmbgp(char *);
EXT void version_pmbgp(char *);

EXT void pmbgp_zmq_req_setup(struct p_zmq_host *, char *, int);
EXT char *pmbgp_zmq_recv_str(struct p_zmq_sock *);
EXT int pmbgp_zmq_send_str(struct p_zmq_sock *, char *);
EXT int pmbgp_zmq_sendmore_str(struct p_zmq_sock *, char *);
#endif
#undef EXT
#endif /* WITH_ZMQ */
