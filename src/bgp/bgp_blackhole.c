/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2026 by Paolo Lucente
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

/* includes */
#include "pmacct.h"
#include "bgp.h"
#include "bgp_blackhole.h"
#include "thread_pool.h"
#if defined WITH_ZMQ
#include "zmq_common.h"
#endif
#if defined WITH_RABBITMQ
#include "amqp_common.h"
#endif
#ifdef WITH_KAFKA
#include "kafka_common.h"
#endif

/* Global variables */
thread_pool_t *bgp_blackhole_pool;
struct bgp_rt_structs *bgp_blackhole_db;
struct bgp_misc_structs *bgp_blackhole_misc_db;
struct bgp_peer bgp_blackhole_peer;
struct bloom *bgp_blackhole_filter;
struct community *bgp_blackhole_comms;

/* Functions */
void bgp_blackhole_daemon_wrapper()
{
#if defined WITH_ZMQ
  struct p_zmq_host *bgp_blackhole_zmq_host = NULL;
  char inproc_blackhole_str[] = "inproc://bgp_blackhole";

  /* initialize threads pool */
  bgp_blackhole_pool = allocate_thread_pool(1);
  assert(bgp_blackhole_pool);
  Log(LOG_DEBUG, "DEBUG ( %s/core/BH ): %d thread(s) initialized\n", config.name, 1);

  bgp_blackhole_prepare_filter();
  bgp_blackhole_prepare_thread();

  bgp_blackhole_zmq_host = malloc(sizeof(struct p_zmq_host));
  if (!bgp_blackhole_zmq_host) {
    Log(LOG_ERR, "ERROR ( %s/core/BH ): Unable to malloc() bgp_blackhole_zmq_host. Terminating thread.\n", config.name);
    exit_gracefully(1);
  }
  else memset(bgp_blackhole_zmq_host, 0, sizeof(struct p_zmq_host));

  p_zmq_set_log_id(bgp_blackhole_zmq_host, bgp_blackhole_misc_db->log_str);
  p_zmq_set_address(bgp_blackhole_zmq_host, inproc_blackhole_str);
  p_zmq_ctx_setup(bgp_blackhole_zmq_host);
  bgp_blackhole_misc_db->bgp_blackhole_zmq_host = bgp_blackhole_zmq_host;

  /* giving a kick to the BGP blackhole thread */
  send_to_pool(bgp_blackhole_pool, bgp_blackhole_daemon, NULL);
#else
  Log(LOG_ERR, "ERROR ( %s/core/BH ): BGP BlackHole feature requires compiling with --enable-zmq.\n", config.name);
  exit_gracefully(1);
#endif
}

#if defined WITH_ZMQ
void bgp_blackhole_prepare_thread()
{
  bgp_blackhole_misc_db = &inter_domain_misc_dbs[FUNC_TYPE_BGP_BLACKHOLE];
  memset(bgp_blackhole_misc_db, 0, sizeof(struct bgp_misc_structs));

  bgp_blackhole_misc_db->is_thread = TRUE;
  bgp_blackhole_misc_db->log_str = malloc(strlen("core/BH") + 1);
  strcpy(bgp_blackhole_misc_db->log_str, "core/BH");
}

void bgp_blackhole_init_dummy_peer(struct bgp_peer *peer)
{
  memset(peer, 0, sizeof(struct bgp_peer));
  peer->type = FUNC_TYPE_BGP_BLACKHOLE;
}

void bgp_blackhole_prepare_filter()
{
  char *stdcomms, *token;

  bgp_blackhole_filter = malloc(sizeof(struct bloom));
  bloom_init(bgp_blackhole_filter, BGP_BLACKHOLE_DEFAULT_BF_ENTRIES, 0.01);

  stdcomms = strdup(config.bgp_blackhole_stdcomm_list);
  bgp_blackhole_comms = community_new(&bgp_blackhole_peer);
 
  while ((token = extract_token(&stdcomms, ','))) {
    u_int32_t stdcomm;
    int ret;

    ret = community_str2com_simple(token, &stdcomm);
    if (ret == ERR) {
      Log(LOG_ERR, "ERROR ( %s/%s ): Invalid community '%s' in 'bgp_blackhole_stdcomm_list'.\n", config.name, bgp_blackhole_misc_db->log_str, token);
      exit_gracefully(1);
    }
    
    bloom_add(bgp_blackhole_filter, &stdcomm, sizeof(stdcomm));
    community_add_val(&bgp_blackhole_peer, bgp_blackhole_comms, stdcomm); 
  }
}

int bgp_blackhole_daemon()
{
  struct bgp_misc_structs *m_data = bgp_blackhole_misc_db;
  struct bgp_blackhole_itc bbitc;
  struct bgp_peer *peer = NULL;

  /* debug vars */
  char bgp_peer_str[INET6_ADDRSTRLEN], prefix_str[PREFIX_STRLEN], nexthop_str[INET6_ADDRSTRLEN];
  char *aspath, empty[] = "";
 
  afi_t afi;
  safi_t safi;
  int ret;

  /* ZeroMQ stuff */
  struct p_zmq_host *bgp_blackhole_zmq_host;
  
  bgp_blackhole_zmq_host = m_data->bgp_blackhole_zmq_host;
  p_zmq_pull_bind_setup(bgp_blackhole_zmq_host);

  /* output stuff */
  bgp_blackhole_init_output(m_data);
  bgp_blackhole_init_dummy_peer(&bgp_blackhole_peer);

  bgp_blackhole_db = &inter_domain_routing_dbs[FUNC_TYPE_BGP_BLACKHOLE];
  memset(bgp_blackhole_db, 0, sizeof(struct bgp_rt_structs));

  bgp_attr_init(HASHTABSIZE, bgp_blackhole_db);

  /* Let's initialize clean shared RIB */
  for (afi = AFI_IP; afi < AFI_MAX; afi++) {
    for (safi = SAFI_UNICAST; safi < SAFI_MAX; safi++) {
      bgp_blackhole_db->rib[afi][safi] = bgp_table_init(afi, safi);
    }
  }

  bgp_blackhole_link_misc_structs(m_data);

  bgp_blackhole_log_init(&bgp_blackhole_peer);

  for (;;) {
    ret = p_zmq_recv_poll(&bgp_blackhole_zmq_host->sock_inproc, (DEFAULT_SLOTH_SLEEP_TIME * 1000));

    switch (ret) {
    case TRUE: /* got data */
      ret = p_zmq_recv_bin(&bgp_blackhole_zmq_host->sock_inproc, &bbitc, sizeof(bbitc));
      if (ret < 0) continue; /* ZMQ_RECONNECT_IVL */
      break;
    case FALSE: /* timeout */
      continue;
      break;
    case ERR: /* error */
    default:
      continue; /* ZMQ_RECONNECT_IVL */
      break;
    }

    if (config.debug) {
      if (bbitc.peer->type == FUNC_TYPE_BMP) {
       peer = inter_domain_misc_dbs[FUNC_TYPE_BMP].bgp_peer_get(bbitc.peer);
      }
      else {
       peer = bbitc.peer;
      }

      bgp_peer_print(peer, bgp_peer_str, INET6_ADDRSTRLEN);
      prefix2str(bbitc.p, prefix_str, PREFIX_STRLEN);

      if (bbitc.attr) {
        if (bbitc.attr->mp_nexthop.family) {
         addr_to_str2(nexthop_str, &bbitc.attr->mp_nexthop, bbitc.attr->mp_nexthop.family);
       }
        else {
         inet_ntop(AF_INET, &bbitc.attr->nexthop, nexthop_str, INET6_ADDRSTRLEN);
       }

        aspath = bbitc.attr->aspath ? bbitc.attr->aspath->str : empty;
      }
      else {
       memset(nexthop_str, 0, INET6_ADDRSTRLEN);
      }

      Log(LOG_DEBUG, "DEBUG ( %s/%s ): [%s] RTBH intercepted prefix=%s nexthop=%s as_path='%s'\n",
         config.name, bgp_blackhole_misc_db->log_str, bgp_peer_str, prefix_str, nexthop_str, aspath);
    }

/*
    XXX:

    ret = bgp_lookup_node_vector_unicast(bbitc.p, bbitc.peer, m_data->bnv);

    bh_state = bgp_blackhole_validate(bbitc.p, bbitc.peer, bbitc.attr, m_data->bnv); 
    // XXX: process state 
*/

    if (bbitc.attr->aspath) aspath_free(bbitc.attr->aspath);
    if (bbitc.attr->community) community_free(bbitc.attr->community);
    if (bbitc.attr->ecommunity) ecommunity_free(bbitc.attr->ecommunity);
    if (bbitc.attr->lcommunity) lcommunity_free(bbitc.attr->lcommunity);
    if (bbitc.attr->tunnel_encap) free(bbitc.attr->tunnel_encap);
    if (bbitc.attr->pmsi_tunnel_id_raw) free(bbitc.attr->pmsi_tunnel_id_raw);
    prefix_free(bbitc.p);
    free(bbitc.attr);
    free(bbitc.peer);
  }

  return SUCCESS;
}

int bgp_blackhole_evaluate_comms(void *a)
{
  struct bgp_attr *attr = (struct bgp_attr *) a;
  struct community *comm;
  int idx, idx2, ret, ret2;
  u_int32_t val, val2;

  if (attr && attr->community && attr->community->val) {
    comm = attr->community;

    for (idx = 0; idx < comm->size; idx++) {
      val = community_val_get(comm, idx);

      ret = bloom_check(bgp_blackhole_filter, &val, sizeof(val)); 
      if (ret) {
	/* let's make sure it is not a false positive */
	for (idx2 = 0; idx2 < bgp_blackhole_comms->size; idx2++) {
	  val2 = community_val_get(bgp_blackhole_comms, idx2);
	  ret2 = community_compare(&val, &val2);
	  if (!ret2) return ret;
	}
	/* if we are here it was a false positive; let's continue our quest */
      }
    }
  }

  return FALSE;
}

int bgp_blackhole_instrument(struct bgp_peer *peer, struct prefix *p, void *a, afi_t afi, safi_t safi)
{
  struct bgp_misc_structs *m_data = bgp_blackhole_misc_db;
  struct bgp_attr *attr_copy, *attr = (struct bgp_attr *) a;
  struct prefix *pcopy;
  struct bgp_peer *peer_copy;
  struct bgp_blackhole_itc bbitc;
  struct p_zmq_host *bgp_blackhole_zmq_host;
  int ret;

  pcopy = prefix_new();
  prefix_copy(pcopy, p);

  attr_copy = malloc(sizeof(struct bgp_attr));
  memcpy(attr_copy, attr, sizeof(struct bgp_attr));

  peer_copy = malloc(sizeof(struct bgp_peer));
  memcpy(peer_copy, peer, sizeof(struct bgp_peer));

  if (attr->aspath) attr_copy->aspath = aspath_dup(attr->aspath);
  if (attr->community) attr_copy->community = community_dup(attr->community);
  if (attr->ecommunity) attr_copy->ecommunity = ecommunity_dup(attr->ecommunity);
  if (attr->lcommunity) attr_copy->lcommunity = lcommunity_dup(attr->lcommunity);
  if (attr->tunnel_encap) attr_copy->tunnel_encap = strdup(attr->tunnel_encap);
  if (attr->pmsi_tunnel_id_raw) attr_copy->pmsi_tunnel_id_raw = strdup(attr->pmsi_tunnel_id_raw);

  memset(&bbitc, 0, sizeof(bbitc));
  bbitc.peer = peer_copy;
  bbitc.afi = afi;
  bbitc.safi = safi;
  bbitc.p = pcopy;
  bbitc.attr = attr_copy;

  bgp_blackhole_zmq_host = m_data->bgp_blackhole_zmq_host;
  ret = p_zmq_send_bin(&bgp_blackhole_zmq_host->sock_inproc, &bbitc, sizeof(bbitc), FALSE);

  if (ret <= 0) return ERR;

  return FALSE;
}

int bgp_blackhole_validate(struct prefix *p, struct bgp_peer *peer, struct bgp_attr *attr, struct bgp_node_vector *bnv)
{
  int idx, bh_state = BGP_BLACKHOLE_STATE_UNKNOWN;

  if (!bnv || !bnv->entries) return bh_state;

  /*
     (bnv->entries - 1) is the blackhole itself
     (bnv->entries - 2) is the covering prefix
  */
  if (bnv->entries >= 2) {
    idx = (bnv->entries - 2);
    (void)idx;
    // XXX
  }
  else {
    // XXX
  }

  return bh_state;
}
#endif

int bgp_blackhole_log_msg(struct bgp_peer *bh_peer, struct bgp_blackhole_itc *bbitc, char *event_type, int log_type)
{
  // struct bgp_peer *peer;
  int ret = 0, amqp_ret = 0, kafka_ret = 0, etype = BGP_LOGDUMP_ET_NONE;

  if (!bbitc || !bbitc->peer || !bbitc->p || !event_type) {
    return ERR; /* missing required parameters */
  }

  if (bbitc->peer->type == FUNC_TYPE_BMP) {
    // peer = inter_domain_misc_dbs[FUNC_TYPE_BMP].bgp_peer_get(bbitc->peer);
  }
  else {
    // peer = bbitc->peer;
  }

  if (!bh_peer->log) {
    return ERR; /* missing any output method */
  }

  if (!strcmp(event_type, "dump")) etype = BGP_LOGDUMP_ET_DUMP;
  else if (!strcmp(event_type, "log")) etype = BGP_LOGDUMP_ET_LOG;

  if ((config.bgp_blackhole_msglog_amqp_routing_key && etype == BGP_LOGDUMP_ET_LOG) ||
      (config.bgp_blackhole_dump_amqp_routing_key && etype == BGP_LOGDUMP_ET_DUMP)) {
#ifdef WITH_RABBITMQ
    p_amqp_set_routing_key(bh_peer->log->amqp_host, bh_peer->log->filename);
#endif
  }

  if ((config.bgp_blackhole_msglog_kafka_topic && etype == BGP_LOGDUMP_ET_LOG) ||
      (config.bgp_blackhole_dump_kafka_topic && etype == BGP_LOGDUMP_ET_DUMP)) {
#ifdef WITH_KAFKA
    p_kafka_set_topic(bh_peer->log->kafka_host, bh_peer->log->filename);
#endif
  }

#ifdef WITH_JANSSON
  {
    json_t *obj = json_object();

    // XXX

    if ((config.bgp_blackhole_msglog_file && etype == BGP_LOGDUMP_ET_LOG) ||
       (config.bgp_blackhole_dump_file && etype == BGP_LOGDUMP_ET_DUMP)) {
      write_and_free_json(bh_peer->log->fd, obj);
    }

    if ((config.bgp_blackhole_msglog_amqp_routing_key && etype == BGP_LOGDUMP_ET_LOG) ||
       (config.bgp_blackhole_dump_amqp_routing_key && etype == BGP_LOGDUMP_ET_DUMP)) {
      // add_writer_name_and_pid_json(obj, &bms->writer_id_tokens);
#ifdef WITH_RABBITMQ
      amqp_ret = write_and_free_json_amqp(bh_peer->log->amqp_host, obj);
      p_amqp_unset_routing_key(bh_peer->log->amqp_host);
#endif
    }

    if ((config.bgp_blackhole_msglog_kafka_topic && etype == BGP_LOGDUMP_ET_LOG) ||
        (config.bgp_blackhole_dump_kafka_topic && etype == BGP_LOGDUMP_ET_DUMP)) {
      // add_writer_name_and_pid_json(obj, &bms->writer_id_tokens);
#ifdef WITH_KAFKA
      kafka_ret = write_and_free_json_kafka(bh_peer->log->kafka_host, obj);
      p_kafka_unset_topic(bh_peer->log->kafka_host);
#endif
    }
  }
#endif

  return (ret | amqp_ret | kafka_ret);
}

void bgp_blackhole_init_output(struct bgp_misc_structs *m_data)
{
  if (config.bgp_blackhole_msglog_file || config.bgp_blackhole_msglog_amqp_routing_key || config.bgp_blackhole_msglog_kafka_topic) {
    if (config.bgp_blackhole_msglog_file) m_data->msglog_backend_methods++;
    if (config.bgp_blackhole_msglog_amqp_routing_key) m_data->msglog_backend_methods++;
    if (config.bgp_blackhole_msglog_kafka_topic) m_data->msglog_backend_methods++;

    if (m_data->msglog_backend_methods > 1) {
      Log(LOG_ERR, "ERROR ( %s/%s ): bgp_blackhole_msglog_file, bgp_blackhole_msglog_amqp_routing_key and bgp_blackhole_msglog_kafka_topic are mutually exclusive. Terminating thread.\n", config.name, m_data->log_str);
      exit_gracefully(1);
    }

    m_data->peers_log = malloc(1 * sizeof(struct bgp_peer_log));
    if (!m_data->peers_log) {
      Log(LOG_ERR, "ERROR ( %s/%s ): Unable to malloc() BGP Blackhole peers log structure. Terminating thread.\n", config.name, m_data->log_str);
      exit_gracefully(1);
    }
    memset(m_data->peers_log, 0, 1 * sizeof(struct bgp_peer_log));
    bgp_peer_log_seq_init(&m_data->log_seq);

    if (config.bgp_blackhole_msglog_amqp_routing_key) {
#ifdef WITH_RABBITMQ
      bgp_daemon_msglog_init_amqp_host(&bgp_blackhole_msglog_amqp_host); // XXX
      p_amqp_connect_to_publish(&bgp_blackhole_msglog_amqp_host);
#else
      Log(LOG_WARNING, "WARN ( %s/%s ): p_amqp_connect_to_publish() not possible due to missing --enable-rabbitmq\n", config.name, m_data->log_str);
#endif
    }

    if (config.bgp_blackhole_msglog_kafka_topic) {
#ifdef WITH_KAFKA
      bgp_daemon_msglog_init_kafka_host(&bgp_blackhole_msglog_kafka_host); // XXX
#else
      Log(LOG_WARNING, "WARN ( %s/%s ): p_kafka_connect_to_produce() not possible due to missing --enable-kafka\n", config.name, m_data->log_str);
#endif
    }
  }

  if (config.bgp_blackhole_dump_file || config.bgp_blackhole_dump_amqp_routing_key || config.bgp_blackhole_dump_kafka_topic) {
    if (config.bgp_blackhole_dump_file) m_data->dump_backend_methods++;
    if (config.bgp_blackhole_dump_amqp_routing_key) m_data->dump_backend_methods++;
    if (config.bgp_blackhole_dump_kafka_topic) m_data->dump_backend_methods++;

    if (m_data->dump_backend_methods > 1) {
      Log(LOG_ERR, "ERROR ( %s/%s ): bgp_blackhole_dump_file, bgp_blackhole_dump_amqp_routing_key and bgp_blackhole_dump_kafka_topic are mutually exclusive. Terminating thread.\n", config.name, m_data->log_str);
      exit_gracefully(1);
    }
  }
}

int bgp_blackhole_log_init(struct bgp_peer *peer)
{
  struct bgp_misc_structs *m_data = bgp_blackhole_misc_db;
  int ret = 0, amqp_ret = 0, kafka_ret = 0;

  if (!peer) return ERR;

  if (config.bgp_blackhole_msglog_file) {
    m_data->peers_log[0].fd = open_output_file(config.bgp_blackhole_msglog_file, "a", FALSE);
    strcpy(m_data->peers_log[0].filename, config.bgp_blackhole_msglog_file);
  }

#ifdef WITH_RABBITMQ
  if (config.bgp_blackhole_msglog_amqp_routing_key) {
    m_data->peers_log[0].amqp_host = m_data->msglog_amqp_host;
    strcpy(m_data->peers_log[0].filename, config.bgp_blackhole_msglog_amqp_routing_key);
  }
#endif

#ifdef WITH_KAFKA
  if (config.bgp_blackhole_msglog_kafka_topic) {
    m_data->peers_log[0].kafka_host = m_data->msglog_kafka_host;
    strcpy(m_data->peers_log[0].filename, config.bgp_blackhole_msglog_kafka_topic);
  }
#endif

  peer->log = &m_data->peers_log[0];
  m_data->peers_log[0].refcnt++;

  #ifdef WITH_RABBITMQ
  if (config.bgp_blackhole_msglog_amqp_routing_key) {
    p_amqp_set_routing_key(peer->log->amqp_host, peer->log->filename);
  }
#endif

#ifdef WITH_KAFKA
  if (config.bgp_blackhole_msglog_kafka_topic) {
    p_kafka_set_topic(peer->log->kafka_host, peer->log->filename);
  }
#endif

#ifdef WITH_JANSSON
  {
    json_t *obj = json_object();

    // XXX
  
    if (config.bgp_blackhole_msglog_file) {
      write_and_free_json(peer->log->fd, obj);
    }

#ifdef WITH_RABBITMQ
    if (config.bgp_blackhole_msglog_amqp_routing_key) {
      // add_writer_name_and_pid_json(obj, &bms->writer_id_tokens);
      amqp_ret = write_and_free_json_amqp(peer->log->amqp_host, obj);
      p_amqp_unset_routing_key(peer->log->amqp_host);
    }
#endif

#ifdef WITH_KAFKA
    if (config.bgp_blackhole_msglog_kafka_topic) {
      // add_writer_name_and_pid_json(obj, &bms->writer_id_tokens);
      kafka_ret = write_and_free_json_kafka(peer->log->kafka_host, obj);
      p_kafka_unset_topic(peer->log->kafka_host);
    }
#endif
  }
#endif

  return (ret | amqp_ret | kafka_ret);
}
