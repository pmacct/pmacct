/*  
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2019 by Paolo Lucente
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
#include "pmacct-data.h"
#include "addr.h"
#include "bgp.h"
#include "rpki/rpki.h"
#if defined WITH_RABBITMQ
#include "amqp_common.h"
#endif
#ifdef WITH_KAFKA
#include "kafka_common.h"
#endif

/* global variables */
#if defined WITH_AVRO
avro_schema_t avro_bgp_msglog_schema, avro_bgp_dump_schema;
char *avro_bgp_buf = NULL;
#endif

/* functions */
int bgp_peer_log_msg(struct bgp_node *route, struct bgp_info *ri, afi_t afi, safi_t safi,
		     char *event_type, int output, char **output_data, int log_type)
{
  struct bgp_misc_structs *bms;
  struct bgp_peer *peer;
  int ret = 0, amqp_ret = 0, kafka_ret = 0, etype = BGP_LOGDUMP_ET_NONE;
  (void)etype;

  if (!ri || !ri->peer || !event_type) return ERR; /* missing required parameters */
  if (!ri->peer->log && !output_data) return ERR; /* missing any output method */

  peer = ri->peer;

  bms = bgp_select_misc_db(peer->type);
  if (!bms) return ERR;

  if (!strcmp(event_type, "dump")) etype = BGP_LOGDUMP_ET_DUMP;
  else if (!strcmp(event_type, "log")) etype = BGP_LOGDUMP_ET_LOG;
  else if (!strcmp(event_type, "lglass")) etype = BGP_LOGDUMP_ET_LG;

#if defined(WITH_KAFKA) || defined(WITH_RABBITMQ)
  pid_t writer_pid = getpid();
#endif

  if ((bms->msglog_amqp_routing_key && etype == BGP_LOGDUMP_ET_LOG) ||
      (bms->dump_amqp_routing_key && etype == BGP_LOGDUMP_ET_DUMP)) {
#ifdef WITH_RABBITMQ
    p_amqp_set_routing_key(peer->log->amqp_host, peer->log->filename);
#endif
#ifdef WITH_KAFKA
    p_kafka_set_topic(peer->log->kafka_host, peer->log->filename);
#endif
  }

  if (output == PRINT_OUTPUT_JSON) {
#ifdef WITH_JANSSON
    struct bgp_attr *attr = ri->attr;
    char ip_address[INET6_ADDRSTRLEN];
    json_t *obj = json_object();

    char empty[] = "";
    char prefix_str[PREFIX_STRLEN], nexthop_str[INET6_ADDRSTRLEN];
    char *aspath;

    if (etype == BGP_LOGDUMP_ET_LOG) {
      json_object_set_new_nocheck(obj, "seq", json_integer((json_int_t) bgp_peer_log_seq_get(&bms->log_seq)));
      bgp_peer_log_seq_increment(&bms->log_seq);

      switch (log_type) {
      case BGP_LOG_TYPE_UPDATE:
	json_object_set_new_nocheck(obj, "log_type", json_string("update"));
	break;
      case BGP_LOG_TYPE_WITHDRAW:
	json_object_set_new_nocheck(obj, "log_type", json_string("withdraw"));
	break;
      case BGP_LOG_TYPE_DELETE:
	json_object_set_new_nocheck(obj, "log_type", json_string("delete"));
	break;
      default:
        json_object_set_new_nocheck(obj, "log_type", json_integer((json_int_t)log_type));
	break;
      }
    }
    else if (etype == BGP_LOGDUMP_ET_DUMP) {
      json_object_set_new_nocheck(obj, "seq", json_integer((json_int_t) bgp_peer_log_seq_get(&bms->log_seq)));
    }

    if (etype == BGP_LOGDUMP_ET_LOG)
      json_object_set_new_nocheck(obj, "timestamp", json_string(bms->log_tstamp_str));
    else if (etype == BGP_LOGDUMP_ET_DUMP)
      json_object_set_new_nocheck(obj, "timestamp", json_string(bms->dump.tstamp_str));

    if (ri && ri->extra && ri->extra->bmed.id && bms->bgp_peer_logdump_extra_data)
      bms->bgp_peer_logdump_extra_data(&ri->extra->bmed, output, obj);

    addr_to_str(ip_address, &peer->addr);
    json_object_set_new_nocheck(obj, bms->peer_str, json_string(ip_address));

    if (bms->peer_port_str) json_object_set_new_nocheck(obj, bms->peer_port_str, json_integer((json_int_t)peer->tcp_port));

    json_object_set_new_nocheck(obj, "event_type", json_string(event_type));

    json_object_set_new_nocheck(obj, "afi", json_integer((json_int_t)afi));

    json_object_set_new_nocheck(obj, "safi", json_integer((json_int_t)safi));

    if (route) {
      memset(prefix_str, 0, PREFIX_STRLEN);
      prefix2str(&route->p, prefix_str, PREFIX_STRLEN);
      json_object_set_new_nocheck(obj, "ip_prefix", json_string(prefix_str));
    }

    if (ri && ri->extra && ri->extra->path_id)
      json_object_set_new_nocheck(obj, "as_path_id", json_integer((json_int_t)ri->extra->path_id));

    if (attr) {
      memset(nexthop_str, 0, INET6_ADDRSTRLEN);
      if (attr->mp_nexthop.family) addr_to_str(nexthop_str, &attr->mp_nexthop);
      else inet_ntop(AF_INET, &attr->nexthop, nexthop_str, INET6_ADDRSTRLEN);
      json_object_set_new_nocheck(obj, "bgp_nexthop", json_string(nexthop_str));

      aspath = attr->aspath ? attr->aspath->str : empty;
      json_object_set_new_nocheck(obj, "as_path", json_string(aspath));

      if (attr->community)
	json_object_set_new_nocheck(obj, "comms", json_string(attr->community->str));

      if (attr->ecommunity)
	json_object_set_new_nocheck(obj, "ecomms", json_string(attr->ecommunity->str));

      if (attr->lcommunity)
	json_object_set_new_nocheck(obj, "lcomms", json_string(attr->lcommunity->str));

      json_object_set_new_nocheck(obj, "origin", json_string(bgp_origin_print(attr->origin)));

      json_object_set_new_nocheck(obj, "local_pref", json_integer((json_int_t)attr->local_pref));

      if (attr->med)
	json_object_set_new_nocheck(obj, "med", json_integer((json_int_t)attr->med));

      if (config.rpki_roas_file || config.rpki_rtr_cache) {
	u_int8_t roa;

	if (etype == BGP_LOGDUMP_ET_LOG) {
	  bms->bnv->entries = 1;
	  bms->bnv->v[0].p = &route->p; 
	  bms->bnv->v[0].info = ri; 
	}
	else if (etype == BGP_LOGDUMP_ET_DUMP) {
	  bgp_lookup_node_vector_unicast(&route->p, peer, bms->bnv);
	}

	roa = rpki_vector_prefix_lookup(bms->bnv);
	json_object_set_new_nocheck(obj, "roa", json_string(rpki_roa_print(roa)));
      }
    }

    if (safi == SAFI_MPLS_LABEL || safi == SAFI_MPLS_VPN) {
      char label_str[SHORTSHORTBUFLEN];

      if (safi == SAFI_MPLS_VPN) {
        char rd_str[SHORTSHORTBUFLEN];

        bgp_rd2str(rd_str, &ri->extra->rd);
	json_object_set_new_nocheck(obj, "rd", json_string(rd_str));
      }

      bgp_label2str(label_str, ri->extra->label);
      json_object_set_new_nocheck(obj, "label", json_string(label_str));
    }

    if (bms->bgp_peer_log_msg_extras) bms->bgp_peer_log_msg_extras(peer, output, obj);

    if ((bms->msglog_file && etype == BGP_LOGDUMP_ET_LOG) ||
	(bms->dump_file && etype == BGP_LOGDUMP_ET_DUMP))
      write_and_free_json(peer->log->fd, obj);

    if (output_data && etype == BGP_LOGDUMP_ET_LG)
      (*output_data) = compose_json_str(obj);

    if ((bms->msglog_amqp_routing_key && etype == BGP_LOGDUMP_ET_LOG) ||
	(bms->dump_amqp_routing_key && etype == BGP_LOGDUMP_ET_DUMP)) {
      add_writer_name_and_pid_json(obj, config.proc_name, writer_pid);

#ifdef WITH_RABBITMQ
      amqp_ret = write_and_free_json_amqp(peer->log->amqp_host, obj);
#endif
#ifdef WITH_KAFKA
      kafka_ret = write_and_free_json_kafka(peer->log->kafka_host, obj);
#endif
    }
#endif
  }
  else if (output == PRINT_OUTPUT_AVRO) {
#ifdef WITH_AVRO
    avro_writer_t avro_writer = {0};
    avro_value_iface_t *avro_iface = NULL;
    avro_value_t avro_obj, avro_field, avro_branch;
    size_t avro_obj_len, avro_len;

    struct bgp_attr *attr = ri->attr;
    char ip_address[INET6_ADDRSTRLEN], log_type_str[SUPERSHORTBUFLEN];
    char prefix_str[PREFIX_STRLEN], nexthop_str[INET6_ADDRSTRLEN];
    char wid[SHORTSHORTBUFLEN], empty_string[] = "", *aspath = NULL;

    avro_writer = avro_writer_memory(avro_bgp_buf, LARGEBUFLEN);

    if (etype == BGP_LOGDUMP_ET_LOG) {
      avro_iface = avro_generic_class_from_schema(avro_bgp_msglog_schema);
    }
    else if (etype == BGP_LOGDUMP_ET_DUMP) {
      avro_iface = avro_generic_class_from_schema(avro_bgp_dump_schema);
    }

    check_i(avro_generic_value_new(avro_iface, &avro_obj));

    if (etype == BGP_LOGDUMP_ET_LOG) {
      check_i(avro_value_get_by_name(&avro_obj, "seq", &avro_field, NULL));
      check_i(avro_value_set_long(&avro_field, bgp_peer_log_seq_get(&bms->log_seq)));
      bgp_peer_log_seq_increment(&bms->log_seq);

      check_i(avro_value_get_by_name(&avro_obj, "log_type", &avro_field, NULL));
      switch (log_type) {
      case BGP_LOG_TYPE_UPDATE:
	check_i(avro_value_set_string(&avro_field, "update"));
        break;
      case BGP_LOG_TYPE_WITHDRAW:
	check_i(avro_value_set_string(&avro_field, "withdraw"));
        break;
      case BGP_LOG_TYPE_DELETE:
	check_i(avro_value_set_string(&avro_field, "delete"));
        break;
      default:
	sprintf(log_type_str, "%u", log_type);
	check_i(avro_value_set_string(&avro_field, log_type_str));
	break;
      }
    }
    else if (etype == BGP_LOGDUMP_ET_DUMP) {
      check_i(avro_value_get_by_name(&avro_obj, "seq", &avro_field, NULL));
      check_i(avro_value_set_long(&avro_field, bgp_peer_log_seq_get(&bms->log_seq)));
    }

    if (etype == BGP_LOGDUMP_ET_LOG) {
      check_i(avro_value_get_by_name(&avro_obj, "timestamp", &avro_field, NULL));
      check_i(avro_value_set_string(&avro_field, bms->log_tstamp_str));
    }
    else if (etype == BGP_LOGDUMP_ET_DUMP) {
      check_i(avro_value_get_by_name(&avro_obj, "timestamp", &avro_field, NULL));
      check_i(avro_value_set_string(&avro_field, bms->dump.tstamp_str)); 
    }

    addr_to_str(ip_address, &peer->addr);
    check_i(avro_value_get_by_name(&avro_obj, bms->peer_str, &avro_field, NULL));
    check_i(avro_value_set_string(&avro_field, ip_address));

    if (bms->peer_port_str) {
      check_i(avro_value_get_by_name(&avro_obj, bms->peer_port_str, &avro_field, NULL));
      check_i(avro_value_set_branch(&avro_field, TRUE, &avro_branch));
      check_i(avro_value_set_int(&avro_field, peer->tcp_port));
    }
    else {
      check_i(avro_value_get_by_name(&avro_obj, bms->peer_port_str, &avro_field, NULL));
      check_i(avro_value_set_branch(&avro_field, FALSE, &avro_branch));
    }

    check_i(avro_value_get_by_name(&avro_obj, "event_type", &avro_field, NULL));
    check_i(avro_value_set_string(&avro_field, event_type));

    check_i(avro_value_get_by_name(&avro_obj, "afi", &avro_field, NULL));
    check_i(avro_value_set_int(&avro_field, afi));

    check_i(avro_value_get_by_name(&avro_obj, "safi", &avro_field, NULL));
    check_i(avro_value_set_int(&avro_field, safi));

    memset(prefix_str, 0, PREFIX_STRLEN);
    prefix2str(&route->p, prefix_str, PREFIX_STRLEN);
    check_i(avro_value_get_by_name(&avro_obj, "ip_prefix", &avro_field, NULL));
    check_i(avro_value_set_string(&avro_field, prefix_str));

    memset(nexthop_str, 0, INET6_ADDRSTRLEN);
    if (attr->mp_nexthop.family) addr_to_str(nexthop_str, &attr->mp_nexthop);
    else inet_ntop(AF_INET, &attr->nexthop, nexthop_str, INET6_ADDRSTRLEN);
    check_i(avro_value_get_by_name(&avro_obj, "bgp_nexthop", &avro_field, NULL));
    check_i(avro_value_set_string(&avro_field, nexthop_str));

    aspath = attr->aspath ? attr->aspath->str : empty_string;
    check_i(avro_value_get_by_name(&avro_obj, "as_path", &avro_field, NULL));
    check_i(avro_value_set_string(&avro_field, aspath));

    check_i(avro_value_get_by_name(&avro_obj, "origin", &avro_field, NULL));
    check_i(avro_value_set_string(&avro_field, bgp_origin_print(attr->origin)));

    check_i(avro_value_get_by_name(&avro_obj, "local_pref", &avro_field, NULL));
    check_i(avro_value_set_int(&avro_field, attr->local_pref));

    if (attr->community) {
      check_i(avro_value_get_by_name(&avro_obj, "comms", &avro_field, NULL));
      check_i(avro_value_set_branch(&avro_field, TRUE, &avro_branch));
      check_i(avro_value_set_string(&avro_field, attr->community->str));
    }
    else {
      check_i(avro_value_get_by_name(&avro_obj, "comms", &avro_field, NULL));
      check_i(avro_value_set_branch(&avro_field, FALSE, &avro_branch));
    }

    if (attr->ecommunity) {
      check_i(avro_value_get_by_name(&avro_obj, "ecomms", &avro_field, NULL));
      check_i(avro_value_set_branch(&avro_field, TRUE, &avro_branch));
      check_i(avro_value_set_string(&avro_field, attr->ecommunity->str));
    }
    else {
      check_i(avro_value_get_by_name(&avro_obj, "ecomms", &avro_field, NULL));
      check_i(avro_value_set_branch(&avro_field, FALSE, &avro_branch));
    }

    if (attr->lcommunity) {
      check_i(avro_value_get_by_name(&avro_obj, "lcomms", &avro_field, NULL));
      check_i(avro_value_set_branch(&avro_field, TRUE, &avro_branch));
      check_i(avro_value_set_string(&avro_field, attr->lcommunity->str));
    }
    else {
      check_i(avro_value_get_by_name(&avro_obj, "lcomms", &avro_field, NULL));
      check_i(avro_value_set_branch(&avro_field, FALSE, &avro_branch));
    }

    if (attr->med) {
      check_i(avro_value_get_by_name(&avro_obj, "med", &avro_field, NULL));
      check_i(avro_value_set_branch(&avro_field, TRUE, &avro_branch));
      check_i(avro_value_set_int(&avro_field, attr->med));
    }
    else {
      check_i(avro_value_get_by_name(&avro_obj, "med", &avro_field, NULL));
      check_i(avro_value_set_branch(&avro_field, FALSE, &avro_branch));
    }

    if (ri && ri->extra && ri->extra->path_id) {
      check_i(avro_value_get_by_name(&avro_obj, "as_path_id", &avro_field, NULL));
      check_i(avro_value_set_branch(&avro_field, TRUE, &avro_branch));
      check_i(avro_value_set_int(&avro_field, ri->extra->path_id));
    }
    else {
      check_i(avro_value_get_by_name(&avro_obj, "as_path_id", &avro_field, NULL));
      check_i(avro_value_set_branch(&avro_field, FALSE, &avro_branch));
    }

    if (safi == SAFI_MPLS_LABEL || safi == SAFI_MPLS_VPN) {
      char label_str[SHORTSHORTBUFLEN];

      if (safi == SAFI_MPLS_VPN) {
        char rd_str[SHORTSHORTBUFLEN];

        bgp_rd2str(rd_str, &ri->extra->rd);
	check_i(avro_value_get_by_name(&avro_obj, "rd", &avro_field, NULL));
	check_i(avro_value_set_branch(&avro_field, TRUE, &avro_branch));
	check_i(avro_value_set_string(&avro_field, rd_str));
      }
      else {
	check_i(avro_value_get_by_name(&avro_obj, "rd", &avro_field, NULL));
	check_i(avro_value_set_branch(&avro_field, FALSE, &avro_branch));
      }

      bgp_label2str(label_str, ri->extra->label);
      check_i(avro_value_get_by_name(&avro_obj, "label", &avro_field, NULL));
      check_i(avro_value_set_branch(&avro_field, TRUE, &avro_branch));
      check_i(avro_value_set_string(&avro_field, label_str));
    }
    else {
      check_i(avro_value_get_by_name(&avro_obj, "rd", &avro_field, NULL));
      check_i(avro_value_set_branch(&avro_field, FALSE, &avro_branch));

      check_i(avro_value_get_by_name(&avro_obj, "label", &avro_field, NULL));
      check_i(avro_value_set_branch(&avro_field, FALSE, &avro_branch));
    }

    if (config.rpki_roas_file || config.rpki_rtr_cache) {
      u_int8_t roa;

      if (etype == BGP_LOGDUMP_ET_LOG) {
        bms->bnv->entries = 1;
        bms->bnv->v[0].p = &route->p;
        bms->bnv->v[0].info = ri;
      }
      else if (etype == BGP_LOGDUMP_ET_DUMP) {
        bgp_lookup_node_vector_unicast(&route->p, peer, bms->bnv);
      }

      roa = rpki_vector_prefix_lookup(bms->bnv);

      check_i(avro_value_get_by_name(&avro_obj, "roa", &avro_field, NULL));
      check_i(avro_value_set_string(&avro_field, rpki_roa_print(roa)));
    }

    check_i(avro_value_get_by_name(&avro_obj, "writer_id", &avro_field, NULL));
    snprintf(wid, SHORTSHORTBUFLEN, "%s/%u", config.proc_name, writer_pid);
    check_i(avro_value_set_string(&avro_field, wid));

    avro_value_sizeof(&avro_obj, &avro_obj_len);
    assert(avro_obj_len < LARGEBUFLEN);

    if (avro_value_write(avro_writer, &avro_obj)) {
      Log(LOG_ERR, "ERROR ( %s/%s ): AVRO: unable to write value: %s\n", config.name, bms->log_str, avro_strerror());
      exit_gracefully(1);
    }

    avro_len = avro_writer_tell(avro_writer);
    avro_value_decref(&avro_obj);
    avro_value_iface_decref(avro_iface);

    if ((bms->msglog_file && etype == BGP_LOGDUMP_ET_LOG) ||
	(bms->dump_file && etype == BGP_LOGDUMP_ET_DUMP))
      write_file_binary(peer->log->fd, avro_bgp_buf, avro_len);

#ifdef WITH_RABBITMQ
    amqp_ret = write_binary_amqp(peer->log->amqp_host, avro_bgp_buf, avro_len);
#endif
#ifdef WITH_KAFKA
    kafka_ret = write_binary_kafka(peer->log->kafka_host, avro_bgp_buf, avro_len);
#endif

    avro_writer_reset(avro_writer);
#endif
  }

  if ((bms->msglog_amqp_routing_key && etype == BGP_LOGDUMP_ET_LOG) ||
      (bms->dump_amqp_routing_key && etype == BGP_LOGDUMP_ET_DUMP)) {
#ifdef WITH_RABBITMQ
    p_amqp_unset_routing_key(peer->log->amqp_host);
#endif
#ifdef WITH_KAFKA
    p_kafka_unset_topic(peer->log->kafka_host);
#endif
  }

  return (ret | amqp_ret | kafka_ret);
}

int bgp_peer_log_init(struct bgp_peer *peer, int output, int type)
{
  struct bgp_misc_structs *bms = bgp_select_misc_db(type);
  int peer_idx, have_it, ret = 0, amqp_ret = 0, kafka_ret = 0;
  char log_filename[SRVBUFLEN];

#if defined(WITH_KAFKA) || defined(WITH_RABBITMQ)
  pid_t writer_pid = getpid();
#endif

  if (!bms || !peer) return ERR;

  if (bms->msglog_file)
    bgp_peer_log_dynname(log_filename, SRVBUFLEN, bms->msglog_file, peer); 

  if (bms->msglog_amqp_routing_key) {
    bgp_peer_log_dynname(log_filename, SRVBUFLEN, bms->msglog_amqp_routing_key, peer); 
  }

  if (bms->msglog_kafka_topic) {
    bgp_peer_log_dynname(log_filename, SRVBUFLEN, bms->msglog_kafka_topic, peer); 
  }

  for (peer_idx = 0, have_it = 0; peer_idx < bms->max_peers; peer_idx++) {
    if (!bms->peers_log[peer_idx].refcnt) {
      if (bms->msglog_file) {
	bms->peers_log[peer_idx].fd = open_output_file(log_filename, "a", FALSE);
	setlinebuf(bms->peers_log[peer_idx].fd);
      }

#ifdef WITH_RABBITMQ
      if (bms->msglog_amqp_routing_key)
        bms->peers_log[peer_idx].amqp_host = bms->msglog_amqp_host;
#endif

#ifdef WITH_KAFKA
      if (bms->msglog_kafka_topic)
        bms->peers_log[peer_idx].kafka_host = bms->msglog_kafka_host;
#endif
      
      strcpy(bms->peers_log[peer_idx].filename, log_filename);
      have_it = TRUE;
      break;
    }
    else if (!strcmp(log_filename, bms->peers_log[peer_idx].filename)) {
      have_it = TRUE;
      break;
    }
  }

  if (have_it) {
    peer->log = &bms->peers_log[peer_idx];
    bms->peers_log[peer_idx].refcnt++;

#ifdef WITH_RABBITMQ
    if (bms->msglog_amqp_routing_key)
      p_amqp_set_routing_key(peer->log->amqp_host, peer->log->filename);

    if (bms->msglog_amqp_routing_key_rr && !p_amqp_get_routing_key_rr(peer->log->amqp_host)) {
      p_amqp_init_routing_key_rr(peer->log->amqp_host);
      p_amqp_set_routing_key_rr(peer->log->amqp_host, bms->msglog_amqp_routing_key_rr);
    }
#endif

#ifdef WITH_KAFKA
    if (bms->msglog_kafka_topic)
      p_kafka_set_topic(peer->log->kafka_host, peer->log->filename);

    if (bms->msglog_kafka_topic_rr && !p_kafka_get_topic_rr(peer->log->kafka_host)) {
      p_kafka_init_topic_rr(peer->log->kafka_host);
      p_kafka_set_topic_rr(peer->log->kafka_host, bms->msglog_kafka_topic_rr);
    }
#endif

    if (output == PRINT_OUTPUT_JSON) {
#ifdef WITH_JANSSON
      char event_type[] = "log_init";
      char ip_address[INET6_ADDRSTRLEN];
      json_t *obj = json_object();

      json_object_set_new_nocheck(obj, "seq", json_integer((json_int_t) bgp_peer_log_seq_get(&bms->log_seq)));
      bgp_peer_log_seq_increment(&bms->log_seq);

      json_object_set_new_nocheck(obj, "timestamp", json_string(bms->log_tstamp_str));

      addr_to_str(ip_address, &peer->addr);
      json_object_set_new_nocheck(obj, bms->peer_str, json_string(ip_address));

      if (bms->peer_port_str) json_object_set_new_nocheck(obj, bms->peer_port_str, json_integer((json_int_t)peer->tcp_port));

      json_object_set_new_nocheck(obj, "event_type", json_string(event_type));

      if (bms->bgp_peer_logdump_initclose_extras)
	bms->bgp_peer_logdump_initclose_extras(peer, output, obj);

      if (bms->bgp_peer_log_msg_extras) bms->bgp_peer_log_msg_extras(peer, output, obj);

      if (bms->msglog_file)
	write_and_free_json(peer->log->fd, obj);

#ifdef WITH_RABBITMQ
      if (bms->msglog_amqp_routing_key) {
	add_writer_name_and_pid_json(obj, config.proc_name, writer_pid);
	amqp_ret = write_and_free_json_amqp(peer->log->amqp_host, obj); 
	p_amqp_unset_routing_key(peer->log->amqp_host);
      }
#endif

#ifdef WITH_KAFKA
      if (bms->msglog_kafka_topic) {
	add_writer_name_and_pid_json(obj, config.proc_name, writer_pid);
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
  struct bgp_misc_structs *bms = bgp_select_misc_db(type);
  struct bgp_peer_log *log_ptr;
  int ret = 0, amqp_ret = 0, kafka_ret = 0;

#if defined WITH_RABBITMQ
  void *amqp_log_ptr = NULL;
#endif
#if defined WITH_KAFKA
  void *kafka_log_ptr = NULL;
#endif

#if defined(WITH_KAFKA) || defined(WITH_RABBITMQ)
  pid_t writer_pid = getpid();
#endif

  if (!bms || !peer || !peer->log) return ERR;

#ifdef WITH_RABBITMQ
  if (bms->msglog_amqp_routing_key)
    p_amqp_set_routing_key(peer->log->amqp_host, peer->log->filename);
#endif

#ifdef WITH_KAFKA
  if (bms->msglog_kafka_topic)
    p_kafka_set_topic(peer->log->kafka_host, peer->log->filename);
#endif

  log_ptr = peer->log;
#ifdef WITH_RABBITMQ
  amqp_log_ptr = peer->log->amqp_host;
#endif
#ifdef WITH_KAFKA
  kafka_log_ptr = peer->log->kafka_host;
#endif

  assert(peer->log->refcnt);
  peer->log->refcnt--;
  peer->log = NULL;

  if (output == PRINT_OUTPUT_JSON) {
#ifdef WITH_JANSSON
    char ip_address[INET6_ADDRSTRLEN];
    json_t *obj = json_object();
    char event_type[] = "log_close";

    json_object_set_new_nocheck(obj, "seq", json_integer((json_int_t) bgp_peer_log_seq_get(&bms->log_seq)));
    bgp_peer_log_seq_increment(&bms->log_seq);

    json_object_set_new_nocheck(obj, "timestamp", json_string(bms->log_tstamp_str));

    addr_to_str(ip_address, &peer->addr);
    json_object_set_new_nocheck(obj, bms->peer_str, json_string(ip_address));

    if (bms->peer_port_str) json_object_set_new_nocheck(obj, bms->peer_port_str, json_integer((json_int_t)peer->tcp_port));

    json_object_set_new_nocheck(obj, "event_type", json_string(event_type));

    if (bms->bgp_peer_logdump_initclose_extras)
      bms->bgp_peer_logdump_initclose_extras(peer, output, obj);

    if (bms->msglog_file)
      write_and_free_json(log_ptr->fd, obj);

#ifdef WITH_RABBITMQ
    if (bms->msglog_amqp_routing_key) {
      add_writer_name_and_pid_json(obj, config.proc_name, writer_pid);
      amqp_ret = write_and_free_json_amqp(amqp_log_ptr, obj);
      p_amqp_unset_routing_key(amqp_log_ptr);
    }
#endif

#ifdef WITH_KAFKA
    if (bms->msglog_kafka_topic) {
      add_writer_name_and_pid_json(obj, config.proc_name, writer_pid);
      kafka_ret = write_and_free_json_kafka(kafka_log_ptr, obj);
      p_kafka_unset_topic(kafka_log_ptr);
    }
#endif
#endif
  }

  if (!log_ptr->refcnt) {
    if (bms->msglog_file && !log_ptr->refcnt) {
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

u_int64_t bgp_peer_log_seq_get(u_int64_t *seq)
{
  u_int64_t ret = 0;

  if (seq) ret = (*seq);

  return ret;
}

void bgp_peer_log_seq_set(u_int64_t *seq, u_int64_t value)
{
  if (seq) (*seq) = value;
}

int bgp_peer_log_seq_has_ro_bit(u_int64_t *seq)
{
  if ((*seq) & BGP_LOGSEQ_ROLLOVER_BIT) return TRUE;
  else return FALSE;
}

/* XXX: 1) inefficient string testing and 2) string aliases can be mixed
   and matched. But as long as this is used for determining filenames for
   large outputs this is fine. To be refined in future */
void bgp_peer_log_dynname(char *new, int newlen, char *old, struct bgp_peer *peer)
{
  int oldlen;
  char psi_string[] = "$peer_src_ip", ptp_string[] = "$peer_tcp_port";
  char br_string[] = "$bmp_router", brp_string[] = "$bmp_router_port";
  char tn_string[] = "$telemetry_node", tnp_string[] = "$telemetry_node_port";
  char *ptr_start, *ptr_end, *string_ptr;

  if (!new || !old || !peer) return;

  oldlen = strlen(old);
  if (oldlen <= newlen) strcpy(new, old);

  ptr_start = NULL;
  string_ptr = NULL; 

  if (!ptr_start) {
    ptr_start = strstr(new, psi_string);
    string_ptr = psi_string;
  }
  if (!ptr_start) {
    ptr_start = strstr(new, br_string);
    string_ptr = br_string;
  }
  if (!ptr_start) {
    ptr_start = strstr(new, tn_string);
    string_ptr = tn_string;
  }

  if (ptr_start) {
    char empty_peer_src_ip[] = "null";
    char peer_src_ip[SRVBUFLEN];
    char buf[newlen];
    int len;

    len = strlen(ptr_start);
    ptr_end = ptr_start;
    ptr_end += strlen(string_ptr);
    len -= strlen(string_ptr);

    if (peer->addr.family) addr_to_str(peer_src_ip, &peer->addr);
    else strlcpy(peer_src_ip, empty_peer_src_ip, strlen(peer_src_ip));

    escape_ip_uscores(peer_src_ip);
    snprintf(buf, newlen, "%s", peer_src_ip);
    strncat(buf, ptr_end, len);

    len = strlen(buf);
    *ptr_start = '\0';
    strncat(new, buf, len);
  }

  ptr_start = NULL;
  string_ptr = NULL; 

  if (!ptr_start) {
    ptr_start = strstr(new, ptp_string);
    string_ptr = ptp_string;
  }
  if (!ptr_start) {
    ptr_start = strstr(new, brp_string);
    string_ptr = brp_string;
  }
  if (!ptr_start) {
    ptr_start = strstr(new, tnp_string);
    string_ptr = tnp_string;
  }

  if (ptr_start) {
    char buf[newlen];
    int len;

    len = strlen(ptr_start);
    ptr_end = ptr_start;
    ptr_end += strlen(string_ptr);
    len -= strlen(string_ptr);

    snprintf(buf, newlen, "%u", peer->tcp_port);
    strncat(buf, ptr_end, len);

    len = strlen(buf);
    *ptr_start = '\0';
    strncat(new, buf, len);
  }
}

int bgp_peer_dump_init(struct bgp_peer *peer, int output, int type)
{
  struct bgp_misc_structs *bms = bgp_select_misc_db(type);
  int ret = 0, amqp_ret = 0, kafka_ret = 0;

#if defined(WITH_KAFKA) || defined(WITH_RABBITMQ)
  pid_t writer_pid = getpid();
#endif

  if (!bms || !peer || !peer->log) return ERR;

#ifdef WITH_RABBITMQ
  if (bms->dump_amqp_routing_key)
    p_amqp_set_routing_key(peer->log->amqp_host, peer->log->filename);

  if (bms->dump_amqp_routing_key_rr && !p_amqp_get_routing_key_rr(peer->log->amqp_host)) {
    p_amqp_init_routing_key_rr(peer->log->amqp_host);
    p_amqp_set_routing_key_rr(peer->log->amqp_host, bms->dump_amqp_routing_key_rr);
  }
#endif

#ifdef WITH_KAFKA
  if (bms->dump_kafka_topic)
    p_kafka_set_topic(peer->log->kafka_host, peer->log->filename);

  if (bms->dump_kafka_topic_rr && !p_kafka_get_topic_rr(peer->log->kafka_host)) {
    p_kafka_init_topic_rr(peer->log->kafka_host);
    p_kafka_set_topic_rr(peer->log->kafka_host, bms->dump_kafka_topic_rr);
  }
#endif

  if (output == PRINT_OUTPUT_JSON) {
#ifdef WITH_JANSSON
    char ip_address[INET6_ADDRSTRLEN];
    json_t *obj = json_object();
    char event_type[] = "dump_init";

    json_object_set_new_nocheck(obj, "timestamp", json_string(bms->dump.tstamp_str));

    addr_to_str(ip_address, &peer->addr);
    json_object_set_new_nocheck(obj, bms->peer_str, json_string(ip_address));

    if (bms->peer_port_str) json_object_set_new_nocheck(obj, bms->peer_port_str, json_integer((json_int_t)peer->tcp_port));

    json_object_set_new_nocheck(obj, "event_type", json_string(event_type));

    json_object_set_new_nocheck(obj, "dump_period", json_integer((json_int_t)bms->dump.period));

    json_object_set_new_nocheck(obj, "seq", json_integer((json_int_t) bgp_peer_log_seq_get(&bms->log_seq)));

    if (bms->bgp_peer_logdump_initclose_extras)
      bms->bgp_peer_logdump_initclose_extras(peer, output, obj);

    if (bms->dump_file)
      write_and_free_json(peer->log->fd, obj);

#ifdef WITH_RABBITMQ
    if (bms->dump_amqp_routing_key) {
      add_writer_name_and_pid_json(obj, config.proc_name, writer_pid);
      amqp_ret = write_and_free_json_amqp(peer->log->amqp_host, obj);
      p_amqp_unset_routing_key(peer->log->amqp_host);
    }
#endif

#ifdef WITH_KAFKA
    if (bms->dump_kafka_topic) {
      add_writer_name_and_pid_json(obj, config.proc_name, writer_pid);
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
  struct bgp_misc_structs *bms = bgp_select_misc_db(type);
  int ret = 0, amqp_ret = 0, kafka_ret = 0;

#if defined(WITH_KAFKA) || defined(WITH_RABBITMQ)
  pid_t writer_pid = getpid();
#endif

  if (!bms || !peer || !peer->log) return ERR;

#ifdef WITH_RABBITMQ
  if (bms->dump_amqp_routing_key)
    p_amqp_set_routing_key(peer->log->amqp_host, peer->log->filename);
#endif

#ifdef WITH_KAFKA
  if (bms->dump_kafka_topic)
    p_kafka_set_topic(peer->log->kafka_host, peer->log->filename);
#endif

  if (output == PRINT_OUTPUT_JSON) {
#ifdef WITH_JANSSON
    char event_type[] = "dump_close";
    char ip_address[INET6_ADDRSTRLEN];
    json_t *obj = json_object();

    json_object_set_new_nocheck(obj, "timestamp", json_string(bms->dump.tstamp_str));

    addr_to_str(ip_address, &peer->addr);
    json_object_set_new_nocheck(obj, bms->peer_str, json_string(ip_address));

    if (bms->peer_port_str) json_object_set_new_nocheck(obj, bms->peer_port_str, json_integer((json_int_t)peer->tcp_port));

    json_object_set_new_nocheck(obj, "event_type", json_string(event_type));

    if (bds) {
      json_object_set_new_nocheck(obj, "entries", json_integer((json_int_t)bds->entries));

      json_object_set_new_nocheck(obj, "tables", json_integer((json_int_t)bds->tables));
    }

    json_object_set_new_nocheck(obj, "seq", json_integer((json_int_t) bgp_peer_log_seq_get(&bms->log_seq)));

    if (bms->bgp_peer_logdump_initclose_extras)
      bms->bgp_peer_logdump_initclose_extras(peer, output, obj);

    if (bms->dump_file)
      write_and_free_json(peer->log->fd, obj);

#ifdef WITH_RABBITMQ
    if (bms->dump_amqp_routing_key) {
      add_writer_name_and_pid_json(obj, config.proc_name, writer_pid);
      amqp_ret = write_and_free_json_amqp(peer->log->amqp_host, obj);
      p_amqp_unset_routing_key(peer->log->amqp_host);
    }
#endif

#ifdef WITH_KAFKA
    if (bms->dump_kafka_topic) {
      add_writer_name_and_pid_json(obj, config.proc_name, writer_pid);
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
  struct bgp_misc_structs *bms = bgp_select_misc_db(FUNC_TYPE_BGP);
  char current_filename[SRVBUFLEN], last_filename[SRVBUFLEN], tmpbuf[SRVBUFLEN];
  char latest_filename[SRVBUFLEN], event_type[] = "dump", *fd_buf = NULL;
  int ret, peers_idx, duration, tables_num;
  struct bgp_rt_structs *inter_domain_routing_db;
  struct bgp_peer *peer, *saved_peer;
  struct bgp_table *table;
  struct bgp_node *node;
  struct bgp_peer_log peer_log;
  struct bgp_dump_stats bds;
  afi_t afi;
  safi_t safi;
  pid_t dumper_pid;
  time_t start;
  u_int64_t dump_elems = 0, dump_seqno;

  /* pre-flight check */
  if (!bms->dump_backend_methods || !config.bgp_table_dump_refresh_time)
    return;

  /* Sequencing the dump event */
  dump_seqno = bgp_peer_log_seq_get(&bms->log_seq);
  bgp_peer_log_seq_increment(&bms->log_seq);

  switch (ret = fork()) {
  case 0: /* Child */
    /* we have to ignore signals to avoid loops: because we are already forked */
    signal(SIGINT, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    pm_setproctitle("%s %s [%s]", config.type, "Core Process -- BGP Dump Writer", config.name, bms->log_str);
    config.is_forked = TRUE;

    memset(last_filename, 0, sizeof(last_filename));
    memset(current_filename, 0, sizeof(current_filename));
    memset(&peer_log, 0, sizeof(struct bgp_peer_log));
    memset(&bds, 0, sizeof(struct bgp_dump_stats));

    fd_buf = malloc(OUTPUT_FILE_BUFSZ);
    bgp_peer_log_seq_set(&bms->log_seq, dump_seqno);

#ifdef WITH_RABBITMQ
    if (config.bgp_table_dump_amqp_routing_key) {
      bgp_table_dump_init_amqp_host();
      ret = p_amqp_connect_to_publish(&bgp_table_dump_amqp_host);
      if (ret) exit_gracefully(ret);
    }
#endif

#ifdef WITH_KAFKA
    if (config.bgp_table_dump_kafka_topic) {
      ret = bgp_table_dump_init_kafka_host();
      if (ret) exit_gracefully(ret);
    }
#endif

    dumper_pid = getpid();
    Log(LOG_INFO, "INFO ( %s/%s ): *** Dumping BGP tables - START (PID: %u) ***\n", config.name, bms->log_str, dumper_pid);
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

	pm_strftime_same(current_filename, SRVBUFLEN, tmpbuf, &bms->dump.tstamp.tv_sec, config.timestamps_utc);

	/*
	   we close last_filename and open current_filename in case they differ;
	   we are safe with this approach until time and BGP peer (IP, port) are
	   the only variables supported as part of bgp_table_dump_file.
        */
	if (config.bgp_table_dump_file) {
	  if (strcmp(last_filename, current_filename)) {
	    if (saved_peer && saved_peer->log && strlen(last_filename)) {
	      close_output_file(saved_peer->log->fd);

	      if (config.bgp_table_dump_latest_file) {
		bgp_peer_log_dynname(latest_filename, SRVBUFLEN, config.bgp_table_dump_latest_file, saved_peer);
		link_latest_output_file(latest_filename, last_filename);
	      }
	    }
	    peer->log->fd = open_output_file(current_filename, "w", TRUE);
	    if (fd_buf) {
	      if (setvbuf(peer->log->fd, fd_buf, _IOFBF, OUTPUT_FILE_BUFSZ))
		Log(LOG_WARNING, "WARN ( %s/%s ): [%s] setvbuf() failed: %s\n",
		    config.name, bms->log_str, current_filename, strerror(errno));
	      else memset(fd_buf, 0, OUTPUT_FILE_BUFSZ); 
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
        inter_domain_routing_db = bgp_select_routing_db(FUNC_TYPE_BGP);
	dump_elems = 0;

	if (!inter_domain_routing_db) return;

	for (afi = AFI_IP; afi < AFI_MAX; afi++) {
	  for (safi = SAFI_UNICAST; safi < SAFI_MAX; safi++) {
	    table = inter_domain_routing_db->rib[afi][safi];
	    node = bgp_table_top(peer, table);

	    while (node) {
	      u_int32_t modulo = bgp_route_info_modulo(peer, NULL, bms->table_per_peer_buckets);
	      u_int32_t peer_buckets;
	      struct bgp_info *ri;

	      for (peer_buckets = 0; peer_buckets < config.bgp_table_per_peer_buckets; peer_buckets++) {
	        for (ri = node->info[modulo+peer_buckets]; ri; ri = ri->next) {
		  if (ri->peer == peer) {
	            bgp_peer_log_msg(node, ri, afi, safi, event_type, config.bgp_table_dump_output, NULL, BGP_LOG_TYPE_MISC);
	            dump_elems++;
		  }
		}
	      }

	      node = bgp_route_next(peer, node);
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
      link_latest_output_file(latest_filename, last_filename);
    }

    duration = time(NULL)-start;
    Log(LOG_INFO, "INFO ( %s/%s ): *** Dumping BGP tables - END (PID: %u TABLES: %u ENTRIES: %" PRIu64 " ET: %u) ***\n",
		config.name, bms->log_str, dumper_pid, tables_num, dump_elems, duration);

    exit_gracefully(0);
  default: /* Parent */
    if (ret == -1) { /* Something went wrong */
      Log(LOG_WARNING, "WARN ( %s/%s ): Unable to fork BGP table dump writer: %s\n", config.name, bms->log_str, strerror(errno));
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

  p_kafka_init_host(&bgp_daemon_msglog_kafka_host, config.nfacctd_bgp_msglog_kafka_config_file);
  ret = p_kafka_connect_to_produce(&bgp_daemon_msglog_kafka_host);

  if (!config.nfacctd_bgp_msglog_kafka_broker_host) config.nfacctd_bgp_msglog_kafka_broker_host = default_kafka_broker_host;
  if (!config.nfacctd_bgp_msglog_kafka_broker_port) config.nfacctd_bgp_msglog_kafka_broker_port = default_kafka_broker_port;
  if (!config.nfacctd_bgp_msglog_kafka_retry) config.nfacctd_bgp_msglog_kafka_retry = PM_KAFKA_DEFAULT_RETRY;

  p_kafka_set_broker(&bgp_daemon_msglog_kafka_host, config.nfacctd_bgp_msglog_kafka_broker_host, config.nfacctd_bgp_msglog_kafka_broker_port);
  p_kafka_set_topic(&bgp_daemon_msglog_kafka_host, config.nfacctd_bgp_msglog_kafka_topic);
  p_kafka_set_partition(&bgp_daemon_msglog_kafka_host, config.nfacctd_bgp_msglog_kafka_partition);
  p_kafka_set_key(&bgp_daemon_msglog_kafka_host, config.nfacctd_bgp_msglog_kafka_partition_key, config.nfacctd_bgp_msglog_kafka_partition_keylen);
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

  p_kafka_init_host(&bgp_table_dump_kafka_host, config.bgp_table_dump_kafka_config_file);
  ret = p_kafka_connect_to_produce(&bgp_table_dump_kafka_host);

  if (!config.bgp_table_dump_kafka_broker_host) config.bgp_table_dump_kafka_broker_host = default_kafka_broker_host;
  if (!config.bgp_table_dump_kafka_broker_port) config.bgp_table_dump_kafka_broker_port = default_kafka_broker_port;

  p_kafka_set_broker(&bgp_table_dump_kafka_host, config.bgp_table_dump_kafka_broker_host, config.bgp_table_dump_kafka_broker_port);
  p_kafka_set_topic(&bgp_table_dump_kafka_host, config.bgp_table_dump_kafka_topic);
  p_kafka_set_partition(&bgp_table_dump_kafka_host, config.bgp_table_dump_kafka_partition);
  p_kafka_set_key(&bgp_table_dump_kafka_host, config.bgp_table_dump_kafka_partition_key, config.bgp_table_dump_kafka_partition_keylen);
  p_kafka_set_content_type(&bgp_table_dump_kafka_host, PM_KAFKA_CNT_TYPE_STR);

  return ret;
}
#else
int bgp_table_dump_init_kafka_host()
{
  return ERR;
}
#endif

#if defined WITH_AVRO
avro_schema_t avro_schema_build_bgp(int type)
{
  struct bgp_misc_structs *bms = bgp_select_misc_db(FUNC_TYPE_BGP);
  char *schema_name = NULL;

  avro_schema_t schema;
  avro_schema_t optlong_s = avro_schema_union();
  avro_schema_t optstr_s = avro_schema_union();
  avro_schema_t optint_s = avro_schema_union();

  if (type != BGP_LOGDUMP_ET_LOG && type != BGP_LOGDUMP_ET_DUMP) return NULL;

  if (type == BGP_LOGDUMP_ET_LOG) {
    schema_name = malloc(strlen("bgp_msglog"));
    sprintf(schema_name, "%s", "bgp_msglog");
  }
  else {
    schema_name = malloc(strlen("bgp_dump"));
    sprintf(schema_name, "%s", "bgp_dump");
  }

  schema = avro_schema_record(schema_name, NULL);
  Log(LOG_INFO, "INFO ( %s/%s ): AVRO: building %s schema.\n", config.name, bms->log_str, schema_name);

  avro_schema_union_append(optlong_s, avro_schema_null());
  avro_schema_union_append(optlong_s, avro_schema_long());

  avro_schema_union_append(optstr_s, avro_schema_null());
  avro_schema_union_append(optstr_s, avro_schema_string());

  avro_schema_union_append(optint_s, avro_schema_null());
  avro_schema_union_append(optint_s, avro_schema_int());

  if (type == BGP_LOGDUMP_ET_LOG) {
    avro_schema_record_field_append(schema, "log_type", avro_schema_string());
  }
  avro_schema_record_field_append(schema, "seq", avro_schema_long());
  avro_schema_record_field_append(schema, "timestamp", avro_schema_string());
  avro_schema_record_field_append(schema, bms->peer_str, avro_schema_string());
  avro_schema_record_field_append(schema, bms->peer_port_str, optint_s);
  avro_schema_record_field_append(schema, "event_type", avro_schema_string());

  avro_schema_record_field_append(schema, "afi", avro_schema_int());
  avro_schema_record_field_append(schema, "safi", avro_schema_int());
  avro_schema_record_field_append(schema, "ip_prefix", avro_schema_string());
  avro_schema_record_field_append(schema, "rd", optstr_s);

  avro_schema_record_field_append(schema, "bgp_nexthop", avro_schema_string());
  avro_schema_record_field_append(schema, "as_path", avro_schema_string());
  avro_schema_record_field_append(schema, "as_path_id", optint_s);
  avro_schema_record_field_append(schema, "comms", optstr_s);
  avro_schema_record_field_append(schema, "ecomms", optstr_s);
  avro_schema_record_field_append(schema, "lcomms", optstr_s);
  avro_schema_record_field_append(schema, "origin", avro_schema_string());
  avro_schema_record_field_append(schema, "local_pref", avro_schema_int());
  avro_schema_record_field_append(schema, "med", optint_s);
  avro_schema_record_field_append(schema, "label", optstr_s);

  if (config.rpki_roas_file || config.rpki_rtr_cache) {
    avro_schema_record_field_append(schema, "roa", avro_schema_string());
  }

  avro_schema_record_field_append(schema, "writer_id", avro_schema_string());

  avro_schema_decref(optlong_s);
  avro_schema_decref(optstr_s);
  avro_schema_decref(optint_s);

  return schema;
}
#endif
