/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2013 by Paolo Lucente
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
#define MAX_TEE_POOLS 128 
#define MAX_TEE_RECEIVERS 32 

#define TEE_BALANCE_NONE	0
#define TEE_BALANCE_RR		1
#define TEE_BALANCE_HASH_AGENT	2
#define TEE_BALANCE_HASH_TAG	3

typedef struct tee_receiver *(*tee_balance_algorithm) (void *, struct pkt_msg *);

/* structures */
struct tee_receiver {
  struct sockaddr dest;
  socklen_t dest_len;
  int fd;
};

struct tee_balance {
  int type;				/* Balancing algorithm: id */
  tee_balance_algorithm func;		/* Balancing algorithm: handler */
  int next;				/* RR algorithm: next receiver */
};

struct tee_receivers_pool {
  struct tee_receiver *receivers;
  u_int32_t id;				/* Pool ID */
  struct pretag_filter tag_filter; 	/* filter datagrams basing on a pre_tag_map */
  struct tee_balance balance;		/* balance datagrams basing on supported algorithm */
  int num;				/* Number of receivers in the pool */
};

struct tee_receivers {
  struct tee_receivers_pool *pools;
  int num;
};

/* prototypes */
#if (!defined __TEE_PLUGIN_C)
#define EXT extern
#else
#define EXT
#endif

EXT void Tee_exit_now(int);
EXT void Tee_init_socks();
EXT void Tee_destroy_recvs();
EXT void Tee_send(struct pkt_msg *, struct sockaddr *, int);
EXT int Tee_prepare_sock(struct sockaddr *, socklen_t);
EXT int Tee_parse_hostport(const char *, struct sockaddr *, socklen_t *);
EXT struct tee_receiver *Tee_rr_balance(void *, struct pkt_msg *);
EXT struct tee_receiver *Tee_hash_agent_balance(void *, struct pkt_msg *);
EXT struct tee_receiver *Tee_hash_tag_balance(void *, struct pkt_msg *);

/* global variables */
EXT char tee_send_buf[65535];
EXT struct tee_receivers receivers; 
EXT int err_cant_bridge_af;

#undef EXT
