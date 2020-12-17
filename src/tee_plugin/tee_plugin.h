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
    along with this program; if no, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#ifndef TEE_PLUGIN_H
#define TEE_PLUGIN_H

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
  struct sockaddr_storage dest;
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
  u_int16_t src_port;			/* Non transparent mode: source UDP port to use for replication */

  char kafka_broker[SRVBUFLEN];		/* Emitting to Kafka: broker string */
  char kafka_topic[SRVBUFLEN];		/* Emitting to Kafka: topic */
#ifdef WITH_KAFKA
  struct p_kafka_host kafka_host;	/* Emitting to Kafka: librdkafka structs */ 
#endif

  char zmq_address[SHORTBUFLEN];	/* Emitting via ZeroMQ: server address */
#ifdef WITH_ZMQ
  struct p_zmq_host zmq_host;		/* Emitting via ZeroMQ: libzmq structs */ 
#endif

  int num;				/* Number of receivers in the pool */
};

struct tee_receivers {
  struct tee_receivers_pool *pools;
  int num;
};

/* prototypes */
extern void Tee_exit_now(int);
extern void Tee_init_socks();
extern void Tee_destroy_recvs();
extern size_t Tee_craft_transparent_msg(struct pkt_msg *, struct sockaddr *);
extern void Tee_send(struct pkt_msg *, struct sockaddr *, int, int);
extern int Tee_prepare_sock(struct sockaddr *, socklen_t, u_int16_t, int, int);
extern int Tee_parse_hostport(const char *, struct sockaddr *, socklen_t *, int);
extern struct tee_receiver *Tee_rr_balance(void *, struct pkt_msg *);
extern struct tee_receiver *Tee_hash_agent_balance(void *, struct pkt_msg *);
extern struct tee_receiver *Tee_hash_agent_crc32(void *, struct pkt_msg *);
extern struct tee_receiver *Tee_hash_tag_balance(void *, struct pkt_msg *);
extern void Tee_select_templates(unsigned char *, int, int, unsigned char *, int *);

#ifdef WITH_KAFKA
extern void Tee_kafka_send(struct pkt_msg *, struct tee_receivers_pool *);
extern void Tee_init_kafka_host(struct p_kafka_host *, char *, char *, u_int32_t);
#endif

#ifdef WITH_ZMQ
extern void Tee_zmq_send(struct pkt_msg *, struct tee_receivers_pool *); 
extern void Tee_init_zmq_host(struct p_zmq_host *, char *, u_int32_t);
#endif

/* global variables */
extern char tee_send_buf[65535];
extern struct tee_receivers receivers; 
extern int err_cant_bridge_af;

#endif //TEE_PLUGIN_H
