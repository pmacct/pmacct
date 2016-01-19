/*  
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2016 by Paolo Lucente
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
#define __BGP_LOGDUMP_C

/* includes */
#include "pmacct.h"
#include "bgp.h"
#include "../bmp/bmp.h"
#include "../sfacctd_logdump.h"
#if defined WITH_RABBITMQ
#include "amqp_common.h"
#endif
#ifdef WITH_KAFKA
#include "kafka_common.h"
#endif
#ifdef WITH_JANSSON
#include <jansson.h>
#endif

int bgp_peer_log_msg(struct bgp_node *route, struct bgp_info *ri, safi_t safi, char *event_type, int output, int log_type)
{
  char log_rk[SRVBUFLEN];
  struct bgp_peer *peer;
  struct bgp_attr *attr;
  int ret = 0, amqp_ret = 0, kafka_ret = 0, etype = BGP_LOGDUMP_ET_NONE;

  if (!ri || !ri->peer || !ri->peer->log || !event_type) return ERR;

  peer = ri->peer;
  attr = ri->attr;

  if (!strcmp(event_type, "dump")) etype = BGP_LOGDUMP_ET_DUMP;
  else if (!strcmp(event_type, "log")) etype = BGP_LOGDUMP_ET_LOG;

#ifdef WITH_RABBITMQ
  if ((config.nfacctd_bgp_msglog_amqp_routing_key && etype == BGP_LOGDUMP_ET_LOG) ||
      (config.bgp_table_dump_amqp_routing_key && etype == BGP_LOGDUMP_ET_DUMP))
    p_amqp_set_routing_key(peer->log->amqp_host, peer->log->filename);
#endif

#ifdef WITH_KAFKA
  if ((config.nfacctd_bgp_msglog_kafka_topic && etype == BGP_LOGDUMP_ET_LOG) ||
      (config.bgp_table_dump_kafka_topic && etype == BGP_LOGDUMP_ET_DUMP))
    p_kafka_set_topic(peer->log->kafka_host, peer->log->filename);
#endif

  if (output == PRINT_OUTPUT_JSON) {
#ifdef WITH_JANSSON
    char ip_address[INET6_ADDRSTRLEN];
    json_t *obj = json_object(), *kv;

    char empty[] = "";
    char prefix_str[INET6_ADDRSTRLEN], nexthop_str[INET6_ADDRSTRLEN];
    char *aspath;

    /* no need for seq and timestamp for "dump" event_type */
    if (etype == BGP_LOGDUMP_ET_LOG) {
      kv = json_pack("{sI}", "seq", log_seq);
      json_object_update_missing(obj, kv);
      json_decref(kv);
      bgp_peer_log_seq_increment(&log_seq);

      kv = json_pack("{ss}", "timestamp", log_tstamp_str);
      json_object_update_missing(obj, kv);
      json_decref(kv);

      switch (log_type) {
      case BGP_LOG_TYPE_UPDATE:
	kv = json_pack("{ss}", "log_type", "update");
	break;
      case BGP_LOG_TYPE_WITHDRAW:
	kv = json_pack("{ss}", "log_type", "withdraw");
	break;
      case BGP_LOG_TYPE_DELETE:
	kv = json_pack("{ss}", "log_type", "delete");
	break;
      default:
	kv = json_pack("{sI}", "log_type", log_type);
	break;
      }
      json_object_update_missing(obj, kv);
      json_decref(kv);
    }

    addr_to_str(ip_address, &peer->addr);
    kv = json_pack("{ss}", "peer_ip_src", ip_address);
    json_object_update_missing(obj, kv);
    json_decref(kv);

    kv = json_pack("{ss}", "event_type", event_type);
    json_object_update_missing(obj, kv);
    json_decref(kv);

    if (route) {
      memset(prefix_str, 0, INET6_ADDRSTRLEN);
      prefix2str(&route->p, prefix_str, INET6_ADDRSTRLEN);
      kv = json_pack("{ss}", "ip_prefix", prefix_str);
      json_object_update_missing(obj, kv);
      json_decref(kv);
    }

    if (ri && ri->extra && ri->extra->path_id) {
      kv = json_pack("{sI}", "as_path_id", ri->extra->path_id);
      json_object_update_missing(obj, kv);
      json_decref(kv);
    }

    if (attr) {
      memset(nexthop_str, 0, INET6_ADDRSTRLEN);
      if (attr->mp_nexthop.family) addr_to_str(nexthop_str, &attr->mp_nexthop);
      else inet_ntop(AF_INET, &attr->nexthop, nexthop_str, INET6_ADDRSTRLEN);
      kv = json_pack("{ss}", "bgp_nexthop", nexthop_str);
      json_object_update_missing(obj, kv);
      json_decref(kv);

      aspath = attr->aspath ? attr->aspath->str : empty;
      kv = json_pack("{ss}", "as_path", aspath);
      json_object_update_missing(obj, kv);
      json_decref(kv);

      if (attr->community) {
        kv = json_pack("{ss}", "comms", attr->community->str);
        json_object_update_missing(obj, kv);
        json_decref(kv);
      }

      if (attr->ecommunity) {
        kv = json_pack("{ss}", "ecomms", attr->ecommunity->str);
        json_object_update_missing(obj, kv);
        json_decref(kv);
      }

      kv = json_pack("{sI}", "origin", attr->origin);
      json_object_update_missing(obj, kv);
      json_decref(kv);

      kv = json_pack("{sI}", "local_pref", attr->local_pref);
      json_object_update_missing(obj, kv);
      json_decref(kv);

      if (attr->med) {
        kv = json_pack("{sI}", "med", attr->med);
        json_object_update_missing(obj, kv);
        json_decref(kv);
      }
    }

    if (safi == SAFI_MPLS_VPN) {
      u_char rd_str[SRVBUFLEN];

      bgp_rd2str(rd_str, &ri->extra->rd);
      kv = json_pack("{ss}", "rd", rd_str);
      json_object_update_missing(obj, kv);
      json_decref(kv);
    }

    if ((config.nfacctd_bgp_msglog_file && etype == BGP_LOGDUMP_ET_LOG) ||
	(config.bgp_table_dump_file && etype == BGP_LOGDUMP_ET_DUMP))
      write_and_free_json(peer->log->fd, obj);

#ifdef WITH_RABBITMQ
    if ((config.nfacctd_bgp_msglog_amqp_routing_key && etype == BGP_LOGDUMP_ET_LOG) ||
	(config.bgp_table_dump_amqp_routing_key && etype == BGP_LOGDUMP_ET_DUMP)) {
      amqp_ret = write_and_free_json_amqp(peer->log->amqp_host, obj);
      p_amqp_unset_routing_key(peer->log->amqp_host);
    }
#endif

#ifdef WITH_KAFKA
    if ((config.nfacctd_bgp_msglog_kafka_topic && etype == BGP_LOGDUMP_ET_LOG) ||
        (config.bgp_table_dump_kafka_topic && etype == BGP_LOGDUMP_ET_DUMP)) {
      kafka_ret = write_and_free_json_kafka(peer->log->kafka_host, obj);
      p_kafka_unset_topic(peer->log->kafka_host);
    }
#endif
#endif
  }

  return (ret | amqp_ret | kafka_ret);
}

int bgp_peer_log_init(struct bgp_peer *peer, int output, int type)
{
  int peer_idx, have_it, ret = 0, amqp_ret = 0, kafka_ret = 0;
  char log_filename[SRVBUFLEN], event_type[] = "log_init";
  char peer_ip_src[] = "peer_ip_src", bmp_router[] = "bmp_router";
#ifdef WITH_RABBITMQ
  struct p_amqp_host *pah = NULL;
#endif
#ifdef WITH_KAFKA
  struct p_kafka_host *pkh = NULL;
#endif

  /* pointers to BGP or BMP vars */
  struct bgp_peer_log **bpl;
  char *file, *amqp_routing_key, *kafka_topic, *lts, *pa_str;
  int amqp_routing_key_rr, kafka_topic_rr, max_peers;
  u_int64_t *ls;

  if (type == FUNC_TYPE_BGP) {
    file = config.nfacctd_bgp_msglog_file;
#ifdef WITH_RABBITMQ
    pah = &bgp_daemon_msglog_amqp_host;
    amqp_routing_key = config.nfacctd_bgp_msglog_amqp_routing_key;
    amqp_routing_key_rr = config.nfacctd_bgp_msglog_amqp_routing_key_rr;
#endif
#ifdef WITH_KAFKA
    pkh = &bgp_daemon_msglog_kafka_host;
    kafka_topic = config.nfacctd_bgp_msglog_kafka_topic;
    kafka_topic_rr = config.nfacctd_bgp_msglog_kafka_topic_rr;
#endif
    max_peers = config.nfacctd_bgp_max_peers;
    
    pa_str = peer_ip_src;
    lts = log_tstamp_str;
    ls = &log_seq;
    bpl = &peers_log;
  }
  else if (type == FUNC_TYPE_BMP) {
    file = config.nfacctd_bmp_msglog_file;
#ifdef WITH_RABBITMQ
    pah = &bmp_daemon_msglog_amqp_host;
    amqp_routing_key = config.nfacctd_bmp_msglog_amqp_routing_key;
    amqp_routing_key_rr = config.nfacctd_bmp_msglog_amqp_routing_key_rr;
#endif
#ifdef WITH_KAFKA
    pkh = &bmp_daemon_msglog_kafka_host;
    kafka_topic = config.nfacctd_bmp_msglog_kafka_topic;
    kafka_topic_rr = config.nfacctd_bmp_msglog_kafka_topic_rr;
#endif
    max_peers = config.nfacctd_bmp_max_peers;

    pa_str = bmp_router;
    lts = bmp_log_tstamp_str;
    ls = &bmp_log_seq;
    bpl = &bmp_peers_log;
  }
  else if (type == FUNC_TYPE_SFLOW_COUNTER) {
    file = config.sfacctd_counter_file;
#ifdef WITH_RABBITMQ
    pah = &sfacctd_counter_amqp_host;
    amqp_routing_key = config.sfacctd_counter_amqp_routing_key;
#endif
#ifdef WITH_KAFKA
    pkh = &sfacctd_counter_kafka_host;
    kafka_topic = config.sfacctd_counter_kafka_topic;
#endif
    max_peers = config.sfacctd_counter_max_nodes;

    pa_str = peer_ip_src;
    lts = sf_cnt_log_tstamp_str;
    ls = &sf_cnt_log_seq;
    bpl = &sf_cnt_log;
  }
  else return ERR;

  if (!(*bpl) || !peer || peer->log) return ERR;

  if (file)
    bgp_peer_log_dynname(log_filename, SRVBUFLEN, file, peer); 

  if (amqp_routing_key) {
    bgp_peer_log_dynname(log_filename, SRVBUFLEN, amqp_routing_key, peer); 
  }

  if (kafka_topic) {
    bgp_peer_log_dynname(log_filename, SRVBUFLEN, kafka_topic, peer); 
  }

  for (peer_idx = 0, have_it = 0; peer_idx < max_peers; peer_idx++) {
    if (!(*bpl)[peer_idx].refcnt) {
      if (file) {
	(*bpl)[peer_idx].fd = open_logfile(log_filename, "a");
	setlinebuf((*bpl)[peer_idx].fd);
      }

#ifdef WITH_RABBITMQ
      if (amqp_routing_key)
        (*bpl)[peer_idx].amqp_host = pah;
#endif

#ifdef WITH_KAFKA
      if (kafka_topic)
        (*bpl)[peer_idx].kafka_host = pkh;
#endif
      
      strcpy((*bpl)[peer_idx].filename, log_filename);
      have_it = TRUE;
      break;
    }
    else if (!strcmp(log_filename, (*bpl)[peer_idx].filename)) {
      have_it = TRUE;
      break;
    }
  }

  if (have_it) {
    peer->log = &(*bpl)[peer_idx];
    (*bpl)[peer_idx].refcnt++;

#ifdef WITH_RABBITMQ
    if (amqp_routing_key)
      p_amqp_set_routing_key(peer->log->amqp_host, peer->log->filename);

    if (amqp_routing_key_rr && !p_amqp_get_routing_key_rr(peer->log->amqp_host)) {
      p_amqp_init_routing_key_rr(peer->log->amqp_host);
      p_amqp_set_routing_key_rr(peer->log->amqp_host, amqp_routing_key_rr);
    }
#endif

#ifdef WITH_KAFKA
    if (kafka_topic)
      p_kafka_set_topic(peer->log->amqp_host, peer->log->filename);

    if (kafka_topic_rr && !p_kafka_get_topic_rr(peer->log->kafka_host)) {
      p_kafka_init_topic_rr(peer->log->kafka_host);
      p_kafka_set_topic_rr(peer->log->kafka_host, kafka_topic_rr);
    }
#endif

    if (output == PRINT_OUTPUT_JSON) {
#ifdef WITH_JANSSON
      char ip_address[INET6_ADDRSTRLEN];
      json_t *obj = json_object(), *kv;

      kv = json_pack("{sI}", "seq", (*ls));
      json_object_update_missing(obj, kv);
      json_decref(kv);
      bgp_peer_log_seq_increment(ls);

      kv = json_pack("{ss}", "timestamp", lts);
      json_object_update_missing(obj, kv);
      json_decref(kv);

      addr_to_str(ip_address, &peer->addr);
      kv = json_pack("{ss}", pa_str, ip_address);
      json_object_update_missing(obj, kv);
      json_decref(kv);

      kv = json_pack("{ss}", "event_type", event_type);
      json_object_update_missing(obj, kv);
      json_decref(kv);

      if (file)
	write_and_free_json(peer->log->fd, obj);

#ifdef WITH_RABBITMQ
      if (amqp_routing_key) {
	amqp_ret = write_and_free_json_amqp(peer->log->amqp_host, obj); 
	p_amqp_unset_routing_key(peer->log->amqp_host);
      }
#endif

#ifdef WITH_KAFKA
      if (kafka_topic) {
        kafka_ret = write_and_free_json_kafka(peer->log->kafka_host, obj);
        p_kafka_unset_topic(peer->log->kafka_host);
      }
#endif
#endif
    }
  }

  return (ret | amqp_ret | kafka_ret);
}

int bgp_peer_log_close(struct bgp_peer *peer, int output, int type)
{
  char event_type[] = "log_close", peer_ip_src[] = "peer_ip_src", bmp_router[] = "bmp_router";
  struct bgp_peer_log *log_ptr;
  void *amqp_log_ptr, *kafka_log_ptr;
  int ret = 0, amqp_ret = 0, kafka_ret = 0;

  /* pointers to BGP or BMP vars */
  char *file, *amqp_routing_key, *kafka_topic, *lts, *pa_str;
  u_int64_t *ls;

  if (type == FUNC_TYPE_BGP) {
    file = config.nfacctd_bgp_msglog_file;
    amqp_routing_key = config.nfacctd_bgp_msglog_amqp_routing_key;
    kafka_topic = config.nfacctd_bgp_msglog_kafka_topic;

    pa_str = peer_ip_src;
    lts = log_tstamp_str;
    ls = &log_seq;
  }
  else if (type == FUNC_TYPE_BMP) {
    file = config.nfacctd_bmp_msglog_file;
    amqp_routing_key = config.nfacctd_bmp_msglog_amqp_routing_key;
    kafka_topic = config.nfacctd_bmp_msglog_kafka_topic;

    pa_str = bmp_router;
    lts = bmp_log_tstamp_str;
    ls = &bmp_log_seq;
  }
  else return ERR;

  if (!peer || !peer->log) return ERR;

#ifdef WITH_RABBITMQ
  if (amqp_routing_key)
    p_amqp_set_routing_key(peer->log->amqp_host, peer->log->filename);
#endif

#ifdef WITH_KAFKA
  if (kafka_topic)
    p_kafka_set_topic(peer->log->kafka_host, peer->log->filename);
#endif

  log_ptr = peer->log;
  amqp_log_ptr = peer->log->amqp_host;
  kafka_log_ptr = peer->log->kafka_host;

  assert(peer->log->refcnt);
  peer->log->refcnt--;
  peer->log = NULL;

  if (output == PRINT_OUTPUT_JSON) {
#ifdef WITH_JANSSON
    char ip_address[INET6_ADDRSTRLEN];
    json_t *obj = json_object(), *kv;

    kv = json_pack("{sI}", "seq", (*ls));
    json_object_update_missing(obj, kv);
    json_decref(kv);
    bgp_peer_log_seq_increment(ls);

    kv = json_pack("{ss}", "timestamp", lts);
    json_object_update_missing(obj, kv);
    json_decref(kv);

    addr_to_str(ip_address, &peer->addr);
    kv = json_pack("{ss}", pa_str, ip_address);
    json_object_update_missing(obj, kv);
    json_decref(kv);

    kv = json_pack("{ss}", "event_type", event_type);
    json_object_update_missing(obj, kv);
    json_decref(kv);

    if (file)
      write_and_free_json(log_ptr->fd, obj);

#ifdef WITH_RABBITMQ
    if (amqp_routing_key) {
      amqp_ret = write_and_free_json_amqp(amqp_log_ptr, obj);
      p_amqp_unset_routing_key(amqp_log_ptr);
    }
#endif

#ifdef WITH_KAFKA
    if (kafka_topic) {
      kafka_ret = write_and_free_json_kafka(kafka_log_ptr, obj);
      p_kafka_unset_topic(kafka_log_ptr);
    }
#endif
#endif
  }

  if (!log_ptr->refcnt) {
    if (file && !log_ptr->refcnt) {
      fclose(log_ptr->fd);
      memset(log_ptr, 0, sizeof(struct bgp_peer_log));
    }
  }

  return (ret | amqp_ret | kafka_ret);
}

void bgp_peer_log_seq_init(u_int64_t *seq)
{
  if (seq) (*seq) = 0;
}

void bgp_peer_log_seq_increment(u_int64_t *seq)
{
  /* Jansson does not support unsigned 64 bit integers, let's wrap at 2^63-1 */
  if (seq) {
    if ((*seq) == INT64T_THRESHOLD) (*seq) = 0;
    else (*seq)++;
  }
}

void bgp_peer_log_dynname(char *new, int newlen, char *old, struct bgp_peer *peer)
{
  int oldlen;
  char psi_string[] = "$peer_src_ip";
  char *ptr_start, *ptr_end;

  if (!new || !old || !peer) return;

  oldlen = strlen(old);
  if (oldlen <= newlen) strcpy(new, old);

  ptr_start = strstr(new, psi_string);
  if (ptr_start) {
    char empty_peer_src_ip[] = "null";
    char peer_src_ip[SRVBUFLEN];
    char buf[newlen];
    int len, howmany;

    len = strlen(ptr_start);
    ptr_end = ptr_start;
    ptr_end += strlen(psi_string);
    len -= strlen(psi_string);

    if (peer->addr.family) addr_to_str(peer_src_ip, &peer->addr);
    else strlcpy(peer_src_ip, empty_peer_src_ip, strlen(peer_src_ip));

    escape_ip_uscores(peer_src_ip);
    snprintf(buf, newlen, "%s", peer_src_ip);
    strncat(buf, ptr_end, len);

    len = strlen(buf);
    *ptr_start = '\0';
    strncat(new, buf, len);
  }
}

int bgp_peer_dump_init(struct bgp_peer *peer, int output, int type)
{
  char event_type[] = "dump_init", peer_ip_src[] = "peer_ip_src", bmp_router[] = "bmp_router";
  int ret = 0, amqp_ret = 0, kafka_ret = 0;

  /* pointers to BGP or BMP vars */
  struct timeval *lt;
  char *amqp_routing_key, *kafka_topic, *file, *pa_str, *lts;
  int amqp_routing_key_rr, kafka_topic_rr;

  if (!peer || !peer->log) return ERR;

  if (type == FUNC_TYPE_BGP) {
    amqp_routing_key = config.bgp_table_dump_amqp_routing_key;
    amqp_routing_key_rr = config.bgp_table_dump_amqp_routing_key_rr;
    kafka_topic = config.bgp_table_dump_kafka_topic;
    kafka_topic_rr = config.bgp_table_dump_kafka_topic_rr;
    file = config.bgp_table_dump_file;

    pa_str = peer_ip_src;
    lt = &log_tstamp;
    lts = log_tstamp_str; 
  }
  else if (type == FUNC_TYPE_BMP) {
    amqp_routing_key = config.bmp_dump_amqp_routing_key;
    amqp_routing_key_rr = config.bmp_dump_amqp_routing_key_rr;
    kafka_topic = config.bmp_dump_kafka_topic;
    kafka_topic_rr = config.bmp_dump_kafka_topic_rr;
    file = config.bmp_dump_file;

    pa_str = bmp_router;
    lt = &bmp_log_tstamp;
    lts = bmp_log_tstamp_str;
  }
  else return ERR;

  gettimeofday(lt, NULL);
  compose_timestamp(lts, SRVBUFLEN, lt, TRUE, config.sql_history_since_epoch);

#ifdef WITH_RABBITMQ
  if (amqp_routing_key)
    p_amqp_set_routing_key(peer->log->amqp_host, peer->log->filename);

  if (amqp_routing_key_rr && !p_amqp_get_routing_key_rr(peer->log->amqp_host)) {
    p_amqp_init_routing_key_rr(peer->log->amqp_host);
    p_amqp_set_routing_key_rr(peer->log->amqp_host, amqp_routing_key_rr);
  }
#endif

#ifdef WITH_KAFKA
  if (kafka_topic)
    p_kafka_set_topic(peer->log->kafka_host, peer->log->filename);

  if (kafka_topic_rr && !p_kafka_get_topic_rr(peer->log->kafka_host)) {
    p_kafka_init_topic_rr(peer->log->kafka_host);
    p_kafka_set_topic_rr(peer->log->kafka_host, kafka_topic_rr);
  }
#endif

  if (output == PRINT_OUTPUT_JSON) {
#ifdef WITH_JANSSON
    char ip_address[INET6_ADDRSTRLEN];
    json_t *obj = json_object(), *kv;

    kv = json_pack("{ss}", "timestamp", lts);
    json_object_update_missing(obj, kv);
    json_decref(kv);

    addr_to_str(ip_address, &peer->addr);
    kv = json_pack("{ss}", pa_str, ip_address);
    json_object_update_missing(obj, kv);
    json_decref(kv);

    kv = json_pack("{ss}", "event_type", event_type);
    json_object_update_missing(obj, kv);
    json_decref(kv);

    if (file)
      write_and_free_json(peer->log->fd, obj);

#ifdef WITH_RABBITMQ
    if (amqp_routing_key) {
      amqp_ret = write_and_free_json_amqp(peer->log->amqp_host, obj);
      p_amqp_unset_routing_key(peer->log->amqp_host);
    }
#endif

#ifdef WITH_KAFKA
    if (kafka_topic) {
      kafka_ret = write_and_free_json_kafka(peer->log->kafka_host, obj);
      p_kafka_unset_topic(peer->log->kafka_host);
    }
#endif
#endif
  }

  return (ret | amqp_ret | kafka_ret);
}

int bgp_peer_dump_close(struct bgp_peer *peer, struct bgp_dump_stats *bds, int output, int type)
{
  char event_type[] = "dump_close", peer_src_ip[] = "peer_src_ip", bmp_router[] = "bmp_router";
  int ret = 0, amqp_ret = 0, kafka_ret = 0;

  /* pointers to BGP or BMP vars */
  struct timeval *lt;
  char *amqp_routing_key, *kafka_topic, *file, *pa_str, *lts;

  if (!peer || !peer->log) return ERR;

  if (type == FUNC_TYPE_BGP) {
    amqp_routing_key = config.bgp_table_dump_amqp_routing_key; 
    kafka_topic = config.bgp_table_dump_kafka_topic; 
    file = config.bgp_table_dump_file;

    pa_str = peer_src_ip;
    lt = &log_tstamp;
    lts = log_tstamp_str;
  }
  else if (type == FUNC_TYPE_BMP) {
    amqp_routing_key = config.bmp_dump_amqp_routing_key;
    kafka_topic = config.bmp_dump_kafka_topic;
    file = config.bmp_dump_file;

    pa_str = bmp_router;
    lt = &bmp_log_tstamp;
    lts = bmp_log_tstamp_str;
  }
  else return ERR;

  gettimeofday(lt, NULL);
  compose_timestamp(lts, SRVBUFLEN, lt, TRUE, config.sql_history_since_epoch);

#ifdef WITH_RABBITMQ
  if (amqp_routing_key)
    p_amqp_set_routing_key(peer->log->amqp_host, peer->log->filename);
#endif

#ifdef WITH_KAFKA
  if (kafka_topic)
    p_kafka_set_topic(peer->log->kafka_host, peer->log->filename);
#endif

  if (output == PRINT_OUTPUT_JSON) {
#ifdef WITH_JANSSON
    char ip_address[INET6_ADDRSTRLEN];
    json_t *obj = json_object(), *kv;

    kv = json_pack("{ss}", "timestamp", lts);
    json_object_update_missing(obj, kv);
    json_decref(kv);

    addr_to_str(ip_address, &peer->addr);
    kv = json_pack("{ss}", "peer_ip_src", ip_address);
    json_object_update_missing(obj, kv);
    json_decref(kv);

    kv = json_pack("{ss}", "event_type", event_type);
    json_object_update_missing(obj, kv);
    json_decref(kv);

    if (bds) {
      kv = json_pack("{sI}", "entries", bds->entries);
      json_object_update_missing(obj, kv);
      json_decref(kv);

      kv = json_pack("{sI}", "tables", bds->tables);
      json_object_update_missing(obj, kv);
      json_decref(kv);
    }

    if (file)
      write_and_free_json(peer->log->fd, obj);

#ifdef WITH_RABBITMQ
    if (amqp_routing_key) {
      amqp_ret = write_and_free_json_amqp(peer->log->amqp_host, obj);
      p_amqp_unset_routing_key(peer->log->amqp_host);
    }
#endif

#ifdef WITH_KAFKA
    if (kafka_topic) {
      kafka_ret = write_and_free_json_kafka(peer->log->kafka_host, obj);
      p_kafka_unset_topic(peer->log->kafka_host);
    }
#endif
#endif
  }

  return (ret | amqp_ret | kafka_ret);
}

void bgp_handle_dump_event()
{
  char current_filename[SRVBUFLEN], last_filename[SRVBUFLEN], tmpbuf[SRVBUFLEN];
  char latest_filename[SRVBUFLEN], event_type[] = "dump", *fd_buf = NULL;
  int ret, peers_idx, duration, tables_num;
  struct bgp_peer *peer, *saved_peer;
  struct bgp_table *table;
  struct bgp_node *node;
  struct bgp_peer_log peer_log;
  struct bgp_dump_stats bds;
  afi_t afi;
  safi_t safi;
  pid_t dumper_pid;
  time_t start;
  u_int64_t dump_elems;

  /* pre-flight check */
  if (!bgp_table_dump_backend_methods || !config.bgp_table_dump_refresh_time)
    return;

  switch (ret = fork()) {
  case 0: /* Child */
    /* we have to ignore signals to avoid loops: because we are already forked */
    signal(SIGINT, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    pm_setproctitle("%s %s [%s]", config.type, "Core Process -- BGP Dump Writer", config.name);
    memset(last_filename, 0, sizeof(last_filename));
    memset(current_filename, 0, sizeof(current_filename));
    memset(&peer_log, 0, sizeof(struct bgp_peer_log));
    memset(&bds, 0, sizeof(struct bgp_dump_stats));
    fd_buf = malloc(BGP_LOG_BUFSZ);

#ifdef WITH_RABBITMQ
    if (config.bgp_table_dump_amqp_routing_key) {
      bgp_table_dump_init_amqp_host();
      ret = p_amqp_connect_to_publish(&bgp_table_dump_amqp_host);
      if (ret) exit(ret);
    }
#endif

#ifdef WITH_KAFKA
    if (config.bgp_table_dump_kafka_topic) {
      ret = bgp_table_dump_init_kafka_host();
      if (ret) exit(ret);
    }
#endif

    dumper_pid = getpid();
    Log(LOG_INFO, "INFO ( %s/core/BGP ): *** Dumping BGP tables - START (PID: %u) ***\n", config.name, dumper_pid);
    start = time(NULL);
    tables_num = 0;

    for (peer = NULL, saved_peer = NULL, peers_idx = 0; peers_idx < config.nfacctd_bgp_max_peers; peers_idx++) {
      if (peers[peers_idx].fd) {
        peer = &peers[peers_idx];
	peer->log = &peer_log; /* abusing struct bgp_peer a bit, but we are in a child */

	if (config.bgp_table_dump_file)
	  bgp_peer_log_dynname(current_filename, SRVBUFLEN, config.bgp_table_dump_file, peer);

	if (config.bgp_table_dump_amqp_routing_key)
	  bgp_peer_log_dynname(current_filename, SRVBUFLEN, config.bgp_table_dump_amqp_routing_key, peer);

	if (config.bgp_table_dump_kafka_topic)
	  bgp_peer_log_dynname(current_filename, SRVBUFLEN, config.bgp_table_dump_kafka_topic, peer);

	strftime_same(current_filename, SRVBUFLEN, tmpbuf, &log_tstamp.tv_sec);

	/*
	   we close last_filename and open current_filename in case they differ;
	   we are safe with this approach until $peer_src_ip is the only variable
	   supported as part of bgp_table_dump_file configuration directive.
        */
	if (config.bgp_table_dump_file) {
	  if (strcmp(last_filename, current_filename)) {
	    if (saved_peer && saved_peer->log && strlen(last_filename)) {
	      close_logfile(saved_peer->log->fd);

	      if (config.bgp_table_dump_latest_file) {
		bgp_peer_log_dynname(latest_filename, SRVBUFLEN, config.bgp_table_dump_latest_file, saved_peer);
		link_latest_logfile(latest_filename, last_filename);
	      }
	    }
	    peer->log->fd = open_logfile(current_filename, "w");
	    if (fd_buf) {
	      setbuffer(peer->log->fd, fd_buf, BGP_LOG_BUFSZ);
	      memset(fd_buf, 0, BGP_LOG_BUFSZ); 
	    }
	  }
	}

	/*
	   a bit pedantic maybe but should come at little cost and emulating
	   bgp_table_dump_file behaviour will work
	*/ 
#ifdef WITH_RABBITMQ
	if (config.bgp_table_dump_amqp_routing_key) {
	  peer->log->amqp_host = &bgp_table_dump_amqp_host;
	  strcpy(peer->log->filename, current_filename);
	}
#endif

#ifdef WITH_KAFKA
	if (config.bgp_table_dump_kafka_topic) {
	  peer->log->kafka_host = &bgp_table_dump_kafka_host;
	  strcpy(peer->log->filename, current_filename);
	}
#endif

	bgp_peer_dump_init(peer, config.bgp_table_dump_output, FUNC_TYPE_BGP);
	dump_elems = 0;

	for (afi = AFI_IP; afi < AFI_MAX; afi++) {
	  for (safi = SAFI_UNICAST; safi < SAFI_MAX; safi++) {
	    table = rib[afi][safi];
	    node = bgp_table_top(table);

	    while (node) {
	      u_int32_t modulo = bgp_route_info_modulo(peer, NULL);
	      u_int32_t peer_buckets;
	      struct bgp_info *ri;

	      for (peer_buckets = 0; peer_buckets < config.bgp_table_per_peer_buckets; peer_buckets++) {
	        for (ri = node->info[modulo+peer_buckets]; ri; ri = ri->next) {
		  if (ri->peer == peer) {
	            bgp_peer_log_msg(node, ri, safi, event_type, config.bgp_table_dump_output, BGP_LOG_TYPE_MISC);
	            dump_elems++;
		  }
		}
	      }

	      node = bgp_route_next(node);
	    }
	  }
	}

        saved_peer = peer;
	tables_num++;

        strlcpy(last_filename, current_filename, SRVBUFLEN);
	bds.entries = dump_elems;
	bds.tables = tables_num;
        bgp_peer_dump_close(peer, &bds, config.bgp_table_dump_output, FUNC_TYPE_BGP);
      }
    }

#ifdef WITH_RABBITMQ
    if (config.bgp_table_dump_amqp_routing_key)
      p_amqp_close(&bgp_table_dump_amqp_host, FALSE);
#endif

#ifdef WITH_KAFKA
    if (config.bgp_table_dump_kafka_topic)
      p_kafka_close(&bgp_table_dump_kafka_host, FALSE);
#endif

    if (config.bgp_table_dump_latest_file && peer) {
      bgp_peer_log_dynname(latest_filename, SRVBUFLEN, config.bgp_table_dump_latest_file, peer);
      link_latest_logfile(latest_filename, last_filename);
    }

    duration = time(NULL)-start;
    Log(LOG_INFO, "INFO ( %s/core/BGP ): *** Dumping BGP tables - END (PID: %u, TABLES: %u ET: %u) ***\n",
		config.name, dumper_pid, tables_num, duration);

    exit(0);
  default: /* Parent */
    if (ret == -1) { /* Something went wrong */
      Log(LOG_WARNING, "WARN ( %s/core/BGP ): Unable to fork BGP table dump writer: %s\n", config.name, strerror(errno));
    }

    break;
  }
}

#if defined WITH_RABBITMQ
void bgp_daemon_msglog_init_amqp_host()
{
  p_amqp_init_host(&bgp_daemon_msglog_amqp_host);

  if (!config.nfacctd_bgp_msglog_amqp_user) config.nfacctd_bgp_msglog_amqp_user = rabbitmq_user;
  if (!config.nfacctd_bgp_msglog_amqp_passwd) config.nfacctd_bgp_msglog_amqp_passwd = rabbitmq_pwd;
  if (!config.nfacctd_bgp_msglog_amqp_exchange) config.nfacctd_bgp_msglog_amqp_exchange = default_amqp_exchange;
  if (!config.nfacctd_bgp_msglog_amqp_exchange_type) config.nfacctd_bgp_msglog_amqp_exchange_type = default_amqp_exchange_type;
  if (!config.nfacctd_bgp_msglog_amqp_host) config.nfacctd_bgp_msglog_amqp_host = default_amqp_host;
  if (!config.nfacctd_bgp_msglog_amqp_vhost) config.nfacctd_bgp_msglog_amqp_vhost = default_amqp_vhost;
  if (!config.nfacctd_bgp_msglog_amqp_retry) config.nfacctd_bgp_msglog_amqp_retry = AMQP_DEFAULT_RETRY;

  p_amqp_set_user(&bgp_daemon_msglog_amqp_host, config.nfacctd_bgp_msglog_amqp_user);
  p_amqp_set_passwd(&bgp_daemon_msglog_amqp_host, config.nfacctd_bgp_msglog_amqp_passwd);
  p_amqp_set_exchange(&bgp_daemon_msglog_amqp_host, config.nfacctd_bgp_msglog_amqp_exchange);
  p_amqp_set_exchange_type(&bgp_daemon_msglog_amqp_host, config.nfacctd_bgp_msglog_amqp_exchange_type);
  p_amqp_set_host(&bgp_daemon_msglog_amqp_host, config.nfacctd_bgp_msglog_amqp_host);
  p_amqp_set_vhost(&bgp_daemon_msglog_amqp_host, config.nfacctd_bgp_msglog_amqp_vhost);
  p_amqp_set_persistent_msg(&bgp_daemon_msglog_amqp_host, config.nfacctd_bgp_msglog_amqp_persistent_msg);
  p_amqp_set_frame_max(&bgp_daemon_msglog_amqp_host, config.nfacctd_bgp_msglog_amqp_frame_max);
  p_amqp_set_content_type_json(&bgp_daemon_msglog_amqp_host);
  p_amqp_set_heartbeat_interval(&bgp_daemon_msglog_amqp_host, config.nfacctd_bgp_msglog_amqp_heartbeat_interval);
  P_broker_timers_set_retry_interval(&bgp_daemon_msglog_amqp_host.btimers, config.nfacctd_bgp_msglog_amqp_retry);
}
#else
void bgp_daemon_msglog_init_amqp_host()
{
}
#endif

#if defined WITH_RABBITMQ
void bgp_table_dump_init_amqp_host()
{
  p_amqp_init_host(&bgp_table_dump_amqp_host);

  if (!config.bgp_table_dump_amqp_user) config.bgp_table_dump_amqp_user = rabbitmq_user;
  if (!config.bgp_table_dump_amqp_passwd) config.bgp_table_dump_amqp_passwd = rabbitmq_pwd;
  if (!config.bgp_table_dump_amqp_exchange) config.bgp_table_dump_amqp_exchange = default_amqp_exchange;
  if (!config.bgp_table_dump_amqp_exchange_type) config.bgp_table_dump_amqp_exchange_type = default_amqp_exchange_type;
  if (!config.bgp_table_dump_amqp_host) config.bgp_table_dump_amqp_host = default_amqp_host;
  if (!config.bgp_table_dump_amqp_vhost) config.bgp_table_dump_amqp_vhost = default_amqp_vhost;

  p_amqp_set_user(&bgp_table_dump_amqp_host, config.bgp_table_dump_amqp_user);
  p_amqp_set_passwd(&bgp_table_dump_amqp_host, config.bgp_table_dump_amqp_passwd);
  p_amqp_set_exchange(&bgp_table_dump_amqp_host, config.bgp_table_dump_amqp_exchange);
  p_amqp_set_exchange_type(&bgp_table_dump_amqp_host, config.bgp_table_dump_amqp_exchange_type);
  p_amqp_set_host(&bgp_table_dump_amqp_host, config.bgp_table_dump_amqp_host);
  p_amqp_set_vhost(&bgp_table_dump_amqp_host, config.bgp_table_dump_amqp_vhost);
  p_amqp_set_persistent_msg(&bgp_table_dump_amqp_host, config.bgp_table_dump_amqp_persistent_msg);
  p_amqp_set_frame_max(&bgp_table_dump_amqp_host, config.bgp_table_dump_amqp_frame_max);
  p_amqp_set_content_type_json(&bgp_table_dump_amqp_host);
  p_amqp_set_heartbeat_interval(&bgp_table_dump_amqp_host, config.bgp_table_dump_amqp_heartbeat_interval);
}
#else
void bgp_table_dump_init_amqp_host()
{
}
#endif

#if defined WITH_KAFKA
int bgp_daemon_msglog_init_kafka_host()
{
  int ret;

  p_kafka_init_host(&bgp_daemon_msglog_kafka_host);
  ret = p_kafka_connect_to_produce(&bgp_daemon_msglog_kafka_host);

  if (!config.nfacctd_bgp_msglog_kafka_broker_host) config.nfacctd_bgp_msglog_kafka_broker_host = default_kafka_broker_host;
  if (!config.nfacctd_bgp_msglog_kafka_broker_port) config.nfacctd_bgp_msglog_kafka_broker_port = default_kafka_broker_port;
  if (!config.nfacctd_bgp_msglog_kafka_retry) config.nfacctd_bgp_msglog_kafka_retry = PM_KAFKA_DEFAULT_RETRY;

  p_kafka_set_broker(&bgp_daemon_msglog_kafka_host, config.nfacctd_bgp_msglog_kafka_broker_host, config.nfacctd_bgp_msglog_kafka_broker_port);
  p_kafka_set_topic(&bgp_daemon_msglog_kafka_host, config.nfacctd_bgp_msglog_kafka_topic);
  p_kafka_set_partition(&bgp_daemon_msglog_kafka_host, config.nfacctd_bgp_msglog_kafka_partition);
  p_kafka_set_content_type(&bgp_daemon_msglog_kafka_host, PM_KAFKA_CNT_TYPE_STR);
  P_broker_timers_set_retry_interval(&bgp_daemon_msglog_kafka_host.btimers, config.nfacctd_bgp_msglog_kafka_retry);

  return ret;
}
#else
int bgp_daemon_msglog_init_kafka_host()
{
  return ERR;
}
#endif

#if defined WITH_KAFKA
int bgp_table_dump_init_kafka_host()
{
  int ret;

  p_kafka_init_host(&bgp_table_dump_kafka_host);
  ret = p_kafka_connect_to_produce(&bgp_table_dump_kafka_host);

  if (!config.bgp_table_dump_kafka_broker_host) config.bgp_table_dump_kafka_broker_host = default_kafka_broker_host;
  if (!config.bgp_table_dump_kafka_broker_port) config.bgp_table_dump_kafka_broker_port = default_kafka_broker_port;

  p_kafka_set_broker(&bgp_table_dump_kafka_host, config.bgp_table_dump_kafka_broker_host, config.bgp_table_dump_kafka_broker_port);
  p_kafka_set_topic(&bgp_table_dump_kafka_host, config.bgp_table_dump_kafka_topic);
  p_kafka_set_partition(&bgp_table_dump_kafka_host, config.bgp_table_dump_kafka_partition);
  p_kafka_set_content_type(&bgp_table_dump_kafka_host, PM_KAFKA_CNT_TYPE_STR);

  return ret;
}
#else
int bgp_table_dump_init_kafka_host()
{
  return ERR;
}
#endif
