/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2010 by Paolo Lucente
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
    along with this program; if no, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

/* includes */
#include <sys/poll.h>
#include <sys/socket.h>
#include <netdb.h>

/* defines */
#define DEFAULT_TEE_REFRESH_TIME 10

/* prototypes */
#if (!defined __TEE_PLUGIN_C)
#define EXT extern
#else
#define EXT
#endif

EXT void Tee_exit_now(int);
EXT void Tee_send(struct pkt_msg *, int);
EXT int Tee_prepare_sock(struct sockaddr_storage *, socklen_t);
EXT void Tee_parse_hostport(const char *s, struct sockaddr *addr, socklen_t *len);

#undef EXT
