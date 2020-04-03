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
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#ifndef _BGP_LOGDUMP_H_
#define _BGP_LOGDUMP_H_

/* defines */
#define BGP_LOGDUMP_ET_NONE	0
#define BGP_LOGDUMP_ET_LOG	1
#define BGP_LOGDUMP_ET_DUMP	2
#define BGP_LOGDUMP_ET_LG	3

#define BGP_LOG_TYPE_MISC	0
#define BGP_LOG_TYPE_UPDATE	1
#define BGP_LOG_TYPE_WITHDRAW	2
#define BGP_LOG_TYPE_DELETE	3

#define BGP_LOG_TYPE_LOGINIT	65500
#define BGP_LOG_TYPE_LOGCLOSE	65501
#define BGP_LOG_TYPE_DUMPINIT	65502
#define BGP_LOG_TYPE_DUMPCLOSE	65503
#define BGP_LOG_TYPE_MAX 	65503

#define BGP_LOGSEQ_ROLLOVER_BIT	0x8000000000000000ULL
#define BGP_LOGSEQ_MASK		0x7FFFFFFFFFFFFFFFULL	

struct bgp_peer_log {
  FILE *fd;
  int refcnt;
  char filename[SRVBUFLEN];
  void *amqp_host;
  void *kafka_host;
};

struct bgp_dump_stats {
  u_int64_t entries;
  u_int32_t tables;
};

/* prototypes */
extern int bgp_peer_log_init(struct bgp_peer *, int, int);
extern int bgp_peer_log_close(struct bgp_peer *, int, int);
extern int bgp_peer_log_dynname(char *, int, char *, struct bgp_peer *);
extern int bgp_peer_log_msg(struct bgp_node *, struct bgp_info *, afi_t, safi_t, char *, int, char **, int);

extern void bgp_peer_log_seq_init(u_int64_t *);
extern void bgp_peer_log_seq_increment(u_int64_t *);
extern u_int64_t bgp_peer_log_seq_get(u_int64_t *);
extern void bgp_peer_log_seq_set(u_int64_t *, u_int64_t);
extern int bgp_peer_log_seq_has_ro_bit(u_int64_t *);

extern int bgp_peer_dump_init(struct bgp_peer *, int, int);
extern int bgp_peer_dump_close(struct bgp_peer *, struct bgp_dump_stats *, int, int);
extern void bgp_handle_dump_event();
extern void bgp_daemon_msglog_init_amqp_host();
extern void bgp_table_dump_init_amqp_host();
extern int bgp_daemon_msglog_init_kafka_host();
extern int bgp_table_dump_init_kafka_host();

#if defined WITH_AVRO
extern avro_schema_t p_avro_schema_build_bgp(int, char *);
extern avro_schema_t p_avro_schema_build_bgp_log_initclose(int, char *);
extern avro_schema_t p_avro_schema_build_bgp_dump_init(int, char *);
extern avro_schema_t p_avro_schema_build_bgp_dump_close(int, char *);
extern void p_avro_schema_init_bgp(avro_schema_t *, avro_schema_t *, avro_schema_t *, avro_schema_t *, int, char *);
extern void p_avro_schema_build_bgp_common(avro_schema_t *, avro_schema_t *, avro_schema_t *, avro_schema_t *, int);
extern void p_avro_schema_build_bgp_route(avro_schema_t *, avro_schema_t *, avro_schema_t *, avro_schema_t *);
#endif

#endif 
