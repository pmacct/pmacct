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

#ifndef _BMP_LOGDUMP_H_
#define _BMP_LOGDUMP_H_

/* defines */
#define BMP_LOG_TYPE_STATS	BMP_MSG_STATS
#define BMP_LOG_TYPE_INIT	BMP_MSG_INIT
#define BMP_LOG_TYPE_TERM	BMP_MSG_TERM
#define BMP_LOG_TYPE_PEER_UP	BMP_MSG_PEER_UP
#define BMP_LOG_TYPE_PEER_DOWN	BMP_MSG_PEER_DOWN
#define BMP_LOG_TYPE_ROUTE	BMP_MSG_ROUTE_MONITOR
#define BMP_LOG_TYPE_RPAT	BMP_MSG_TMP_RPAT

#define BMP_LOG_TYPE_LOGINIT    BGP_LOG_TYPE_LOGINIT
#define BMP_LOG_TYPE_LOGCLOSE	BGP_LOG_TYPE_LOGCLOSE
#define BMP_LOG_TYPE_DUMPINIT   BGP_LOG_TYPE_DUMPINIT
#define BMP_LOG_TYPE_DUMPCLOSE	BGP_LOG_TYPE_DUMPCLOSE
#define BMP_LOG_TYPE_MAX	BGP_LOG_TYPE_DUMPCLOSE

struct bmp_log_stats {
  u_int16_t cnt_type;
  afi_t cnt_afi;
  safi_t cnt_safi;
  u_int64_t cnt_data;
};

struct bmp_log_tlv {
  u_int32_t pen;
  u_int16_t type;
  u_int16_t len;
  void *val;
};

struct bmp_log_peer_up {
  struct host_addr local_ip;
  u_int16_t loc_port;
  u_int16_t rem_port;
};

struct bmp_log_peer_down {
  u_char reason;
  u_int16_t loc_code;
};

struct bmp_dump_se {
  struct bmp_data bdata;
  u_int64_t seq;
  int se_type;
  union {
    struct bmp_log_stats stats;
    struct bmp_log_peer_up peer_up;
    struct bmp_log_peer_down peer_down;
  } se;
  struct pm_list *tlvs;
};

struct bmp_dump_se_ll_elem {
  struct bmp_dump_se rec; 
  struct bmp_dump_se_ll_elem *next;
};

struct bmp_dump_se_ll {
  struct bmp_dump_se_ll_elem *start;
  struct bmp_dump_se_ll_elem *last;
};

/* prototypes */
extern void bmp_daemon_msglog_init_amqp_host();
extern void bmp_dump_init_amqp_host();
extern void bmp_dump_init_peer(struct bgp_peer *);
extern void bmp_dump_close_peer(struct bgp_peer *);

extern int bmp_log_msg(struct bgp_peer *, struct bmp_data *, struct pm_list *tlvs, void *, u_int64_t, char *, int, int);
extern int bmp_log_msg_stats(struct bgp_peer *, struct bmp_data *, struct pm_list *, struct bmp_log_stats *, char *, int, void *);
extern int bmp_log_msg_init(struct bgp_peer *, struct bmp_data *, struct pm_list *, char *, int, void *);
extern int bmp_log_msg_term(struct bgp_peer *, struct bmp_data *, struct pm_list *, char *, int, void *);
extern int bmp_log_msg_peer_up(struct bgp_peer *, struct bmp_data *, struct pm_list *, struct bmp_log_peer_up *, char *, int, void *);
extern int bmp_log_msg_peer_down(struct bgp_peer *, struct bmp_data *, struct pm_list *, struct bmp_log_peer_down *, char *, int, void *);
extern int bmp_log_msg_route_monitor_tlv(struct pm_list *, int, void *);
extern int bmp_log_rm_tlv_path_marking(struct bgp_peer *, struct bmp_data *, void *, void *, char *, int , void *);
extern int bmp_log_rm_tlv_pm_status(u_int32_t, int, void *);

extern void bmp_dump_se_ll_append(struct bgp_peer *, struct bmp_data *, struct pm_list *tlvs, void *, int);
extern void bmp_dump_se_ll_destroy(struct bmp_dump_se_ll *);

extern void bmp_handle_dump_event();
extern void bmp_daemon_msglog_init_amqp_host();
extern void bmp_dump_init_amqp_host();
extern int bmp_daemon_msglog_init_kafka_host();
extern int bmp_dump_init_kafka_host();

#if defined WITH_AVRO
extern avro_schema_t p_avro_schema_build_bmp_rm(int, char *);
extern avro_schema_t p_avro_schema_build_bmp_init(char *);
extern avro_schema_t p_avro_schema_build_bmp_term(char *);
extern avro_schema_t p_avro_schema_build_bmp_peer_up(char *);
extern avro_schema_t p_avro_schema_build_bmp_peer_down(char *);
extern avro_schema_t p_avro_schema_build_bmp_stats(char *);

extern avro_schema_t p_avro_schema_build_bmp_log_initclose(int, char *);
extern avro_schema_t p_avro_schema_build_bmp_dump_init(int, char *);
extern avro_schema_t p_avro_schema_build_bmp_dump_close(int, char *);

extern void p_avro_schema_build_bmp_common(avro_schema_t *, avro_schema_t *, avro_schema_t *, avro_schema_t *);
#endif

#endif
