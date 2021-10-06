/*  
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2021 by Paolo Lucente
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
#include "thread_pool.h"
#if defined WITH_RABBITMQ
#include "amqp_common.h"
#endif
#ifdef WITH_KAFKA
#include "kafka_common.h"
#endif
#ifdef WITH_AVRO
#include "plugin_cmn_avro.h"
#endif

/* functions */
int bgp_peer_log_msg(struct bgp_node *route, struct bgp_info *ri, afi_t afi, safi_t safi,
		     char *event_type, int output, char **output_data, int log_type)
{
  struct bgp_misc_structs *bms;
  struct bgp_peer *peer;
  int ret = 0, amqp_ret = 0, kafka_ret = 0, etype = BGP_LOGDUMP_ET_NONE;

  if (!ri || !ri->peer || !event_type) return ERR; /* missing required parameters */
  if (!ri->peer->log && !output_data) return ERR; /* missing any output method */

  peer = ri->peer;

  bms = bgp_select_misc_db(peer->type);
  if (!bms) return ERR;

  if (!strcmp(event_type, "dump")) etype = BGP_LOGDUMP_ET_DUMP;
  else if (!strcmp(event_type, "log")) etype = BGP_LOGDUMP_ET_LOG;
  else if (!strcmp(event_type, "lglass")) etype = BGP_LOGDUMP_ET_LG;

  if ((bms->msglog_amqp_routing_key && etype == BGP_LOGDUMP_ET_LOG) ||
      (bms->dump_amqp_routing_key && etype == BGP_LOGDUMP_ET_DUMP)) {
#ifdef WITH_RABBITMQ
    p_amqp_set_routing_key(peer->log->amqp_host, peer->log->filename);
#endif
  }

  if ((bms->msglog_kafka_topic && etype == BGP_LOGDUMP_ET_LOG) ||
      (bms->dump_kafka_topic && etype == BGP_LOGDUMP_ET_DUMP)) {
#ifdef WITH_KAFKA
    p_kafka_set_topic(peer->log->kafka_host, peer->log->filename);

    if (bms->msglog_kafka_partition_key && etype == BGP_LOGDUMP_ET_LOG) {
      p_kafka_set_key(peer->log->kafka_host, peer->log->partition_key, strlen(peer->log->partition_key));
    }
#endif
  }

  if (output == PRINT_OUTPUT_JSON) {
#ifdef WITH_JANSSON
    struct bgp_attr *attr = ri->attr;
    struct bgp_attr_extra *attr_extra = ri->attr_extra;
    char ip_address[INET6_ADDRSTRLEN], log_type_str[SUPERSHORTBUFLEN];
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
	snprintf(log_type_str, SUPERSHORTBUFLEN, "%d", log_type); 
        json_object_set_new_nocheck(obj, "log_type", json_string(log_type_str));
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

    if (ri && ri->bmed.id && bms->bgp_peer_logdump_extra_data)
      bms->bgp_peer_logdump_extra_data(&ri->bmed, output, obj);

    if (!bms->bgp_peer_log_msg_extras) {
      addr_to_str(ip_address, &peer->addr);
      json_object_set_new_nocheck(obj, bms->peer_str, json_string(ip_address));

      if (bms->peer_port_str) json_object_set_new_nocheck(obj, bms->peer_port_str, json_integer((json_int_t)peer->tcp_port));
    }

    if (config.tmp_bgp_lookup_compare_ports) {
      addr_to_str(ip_address, &peer->id);
      json_object_set_new_nocheck(obj, "peer_id", json_string(ip_address));
    }

    json_object_set_new_nocheck(obj, "event_type", json_string(event_type));

    json_object_set_new_nocheck(obj, "afi", json_integer((json_int_t)afi));

    json_object_set_new_nocheck(obj, "safi", json_integer((json_int_t)safi));

    if (route) {
      memset(prefix_str, 0, PREFIX_STRLEN);
      prefix2str(&route->p, prefix_str, PREFIX_STRLEN);
      json_object_set_new_nocheck(obj, "ip_prefix", json_string(prefix_str));
    }

    if (peer->cap_add_paths[afi][safi] && ri && ri->attr_extra) {
      json_object_set_new_nocheck(obj, "as_path_id", json_integer((json_int_t)ri->attr_extra->path_id));
    }

    if (attr) {
      memset(nexthop_str, 0, INET6_ADDRSTRLEN);
      if (attr->mp_nexthop.family) addr_to_str2(nexthop_str, &attr->mp_nexthop, bgp_afi2family(afi));
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

      if (!config.tmp_bgp_daemon_origin_type_int) {
        json_object_set_new_nocheck(obj, "origin", json_string(bgp_origin_print(attr->origin)));
      }
      else {
	json_object_set_new_nocheck(obj, "origin", json_integer((json_int_t)attr->origin));
      }

      if (attr->bitmap & BGP_BMAP_ATTR_LOCAL_PREF)
        json_object_set_new_nocheck(obj, "local_pref", json_integer((json_int_t)attr->local_pref));

      if (attr->bitmap & BGP_BMAP_ATTR_MULTI_EXIT_DISC)
	json_object_set_new_nocheck(obj, "med", json_integer((json_int_t)attr->med));

      if (attr_extra && (attr_extra->bitmap & BGP_BMAP_ATTR_AIGP))
        json_object_set_new_nocheck(obj, "aigp", json_integer((json_int_t)attr_extra->aigp));

      if (attr_extra && attr_extra->psid_li)
        json_object_set_new_nocheck(obj, "psid_li", json_integer((json_int_t)attr_extra->psid_li));

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

        bgp_rd2str(rd_str, &ri->attr_extra->rd);
	json_object_set_new_nocheck(obj, "rd", json_string(rd_str));
	json_object_set_new_nocheck(obj, "rd_origin", json_string(bgp_rd_origin_print(ri->attr_extra->rd.type)));
      }

      bgp_label2str(label_str, ri->attr_extra->label);
      json_object_set_new_nocheck(obj, "label", json_string(label_str));
    }

    if (bms->bgp_peer_log_msg_extras) bms->bgp_peer_log_msg_extras(peer, etype, log_type, output, obj);

    if ((bms->msglog_file && etype == BGP_LOGDUMP_ET_LOG) ||
	(bms->dump_file && etype == BGP_LOGDUMP_ET_DUMP)) {
      write_and_free_json(peer->log->fd, obj);
    }

    if (output_data && etype == BGP_LOGDUMP_ET_LG) {
      (*output_data) = compose_json_str(obj);
    }

    if ((bms->msglog_amqp_routing_key && etype == BGP_LOGDUMP_ET_LOG) ||
	(bms->dump_amqp_routing_key && etype == BGP_LOGDUMP_ET_DUMP)) {
      add_writer_name_and_pid_json(obj, config.proc_name, getpid());
#ifdef WITH_RABBITMQ
      amqp_ret = write_and_free_json_amqp(peer->log->amqp_host, obj);
      p_amqp_unset_routing_key(peer->log->amqp_host);
#endif
    }

    if ((bms->msglog_kafka_topic && etype == BGP_LOGDUMP_ET_LOG) ||
	(bms->dump_kafka_topic && etype == BGP_LOGDUMP_ET_DUMP)) {
      add_writer_name_and_pid_json(obj, config.proc_name, getpid());
#ifdef WITH_KAFKA
      kafka_ret = write_and_free_json_kafka(peer->log->kafka_host, obj);
      p_kafka_unset_topic(peer->log->kafka_host);
#endif
    }
#endif
  }
  else if ((output == PRINT_OUTPUT_AVRO_BIN) ||
	   (output == PRINT_OUTPUT_AVRO_JSON)) {
#ifdef WITH_AVRO
    avro_writer_t p_avro_writer = {0};
    avro_value_iface_t *p_avro_iface = NULL;
    avro_value_t p_avro_obj, p_avro_field, p_avro_branch;
    size_t p_avro_obj_len, p_avro_len;

    struct bgp_attr *attr = ri->attr;
    struct bgp_attr_extra *attr_extra = ri->attr_extra;
    char ip_address[INET6_ADDRSTRLEN], log_type_str[SUPERSHORTBUFLEN];
    char prefix_str[PREFIX_STRLEN], nexthop_str[INET6_ADDRSTRLEN];
    char wid[SHORTSHORTBUFLEN], empty_string[] = "", *aspath = NULL;
    void *p_avro_local_buf = NULL; 

    p_avro_writer = avro_writer_memory(bms->avro_buf, LARGEBUFLEN);

    if (etype == BGP_LOGDUMP_ET_LOG) {
      p_avro_iface = avro_generic_class_from_schema(bms->msglog_avro_schema[0]);
    }
    else if (etype == BGP_LOGDUMP_ET_DUMP) {
      p_avro_iface = avro_generic_class_from_schema(bms->dump_avro_schema[0]);
    }

    pm_avro_check(avro_generic_value_new(p_avro_iface, &p_avro_obj));

    if (etype == BGP_LOGDUMP_ET_LOG) {
      pm_avro_check(avro_value_get_by_name(&p_avro_obj, "seq", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_long(&p_avro_field, bgp_peer_log_seq_get(&bms->log_seq)));
      bgp_peer_log_seq_increment(&bms->log_seq);

      pm_avro_check(avro_value_get_by_name(&p_avro_obj, "log_type", &p_avro_field, NULL));
      switch (log_type) {
      case BGP_LOG_TYPE_UPDATE:
	pm_avro_check(avro_value_set_string(&p_avro_field, "update"));
        break;
      case BGP_LOG_TYPE_WITHDRAW:
	pm_avro_check(avro_value_set_string(&p_avro_field, "withdraw"));
        break;
      case BGP_LOG_TYPE_DELETE:
	pm_avro_check(avro_value_set_string(&p_avro_field, "delete"));
        break;
      default:
	sprintf(log_type_str, "%u", log_type);
	pm_avro_check(avro_value_set_string(&p_avro_field, log_type_str));
	break;
      }
    }
    else if (etype == BGP_LOGDUMP_ET_DUMP) {
      pm_avro_check(avro_value_get_by_name(&p_avro_obj, "seq", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_long(&p_avro_field, bgp_peer_log_seq_get(&bms->log_seq)));
    }

    if (etype == BGP_LOGDUMP_ET_LOG) {
      pm_avro_check(avro_value_get_by_name(&p_avro_obj, "timestamp", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_string(&p_avro_field, bms->log_tstamp_str));
    }
    else if (etype == BGP_LOGDUMP_ET_DUMP) {
      pm_avro_check(avro_value_get_by_name(&p_avro_obj, "timestamp", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_string(&p_avro_field, bms->dump.tstamp_str)); 
    }

    if (ri && ri->bmed.id && bms->bgp_peer_logdump_extra_data)
      bms->bgp_peer_logdump_extra_data(&ri->bmed, output, &p_avro_obj);

    if (!bms->bgp_peer_log_msg_extras) {
      addr_to_str(ip_address, &peer->addr);
      pm_avro_check(avro_value_get_by_name(&p_avro_obj, bms->peer_str, &p_avro_field, NULL));
      pm_avro_check(avro_value_set_string(&p_avro_field, ip_address));

      if (bms->peer_port_str) {
        pm_avro_check(avro_value_get_by_name(&p_avro_obj, bms->peer_port_str, &p_avro_field, NULL));
        pm_avro_check(avro_value_set_branch(&p_avro_field, TRUE, &p_avro_branch));
        pm_avro_check(avro_value_set_int(&p_avro_branch, peer->tcp_port));
      }
      else {
        pm_avro_check(avro_value_get_by_name(&p_avro_obj, bms->peer_port_str, &p_avro_field, NULL));
        pm_avro_check(avro_value_set_branch(&p_avro_field, FALSE, &p_avro_branch));
      }
    }

    if (config.tmp_bgp_lookup_compare_ports) {
      addr_to_str(ip_address, &peer->id);
      pm_avro_check(avro_value_get_by_name(&p_avro_obj, "peer_id", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_string(&p_avro_field, ip_address));
    }

    pm_avro_check(avro_value_get_by_name(&p_avro_obj, "event_type", &p_avro_field, NULL));
    pm_avro_check(avro_value_set_string(&p_avro_field, event_type));

    pm_avro_check(avro_value_get_by_name(&p_avro_obj, "afi", &p_avro_field, NULL));
    pm_avro_check(avro_value_set_int(&p_avro_field, afi));

    pm_avro_check(avro_value_get_by_name(&p_avro_obj, "safi", &p_avro_field, NULL));
    pm_avro_check(avro_value_set_int(&p_avro_field, safi));

    if (route) {
      memset(prefix_str, 0, PREFIX_STRLEN);
      prefix2str(&route->p, prefix_str, PREFIX_STRLEN);
      pm_avro_check(avro_value_get_by_name(&p_avro_obj, "ip_prefix", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, TRUE, &p_avro_branch));
      pm_avro_check(avro_value_set_string(&p_avro_branch, prefix_str));
    }
    else {
      pm_avro_check(avro_value_get_by_name(&p_avro_obj, "ip_prefix", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, FALSE, &p_avro_branch));
    }

    if (attr) {
      memset(nexthop_str, 0, INET6_ADDRSTRLEN);
      if (attr->mp_nexthop.family) addr_to_str2(nexthop_str, &attr->mp_nexthop, bgp_afi2family(afi));
      else inet_ntop(AF_INET, &attr->nexthop, nexthop_str, INET6_ADDRSTRLEN);
      pm_avro_check(avro_value_get_by_name(&p_avro_obj, "bgp_nexthop", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, TRUE, &p_avro_branch));
      pm_avro_check(avro_value_set_string(&p_avro_branch, nexthop_str));

      aspath = attr->aspath ? attr->aspath->str : empty_string;
      pm_avro_check(avro_value_get_by_name(&p_avro_obj, "as_path", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, TRUE, &p_avro_branch));
      pm_avro_check(avro_value_set_string(&p_avro_branch, aspath));

      pm_avro_check(avro_value_get_by_name(&p_avro_obj, "origin", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, TRUE, &p_avro_branch));
      if (!config.tmp_bgp_daemon_origin_type_int) {
        pm_avro_check(avro_value_set_string(&p_avro_branch, bgp_origin_print(attr->origin)));
      }
      else {
        pm_avro_check(avro_value_set_long(&p_avro_branch, attr->origin));
      }

      if (attr->bitmap & BGP_BMAP_ATTR_LOCAL_PREF) {
        pm_avro_check(avro_value_get_by_name(&p_avro_obj, "local_pref", &p_avro_field, NULL));
        pm_avro_check(avro_value_set_branch(&p_avro_field, TRUE, &p_avro_branch));
        pm_avro_check(avro_value_set_long(&p_avro_branch, attr->local_pref));
      }
      else {
	pm_avro_check(avro_value_get_by_name(&p_avro_obj, "local_pref", &p_avro_field, NULL));
	pm_avro_check(avro_value_set_branch(&p_avro_field, FALSE, &p_avro_branch));
      }

      if (attr->community) {
	pm_avro_check(avro_value_get_by_name(&p_avro_obj, "comms", &p_avro_field, NULL));
	pm_avro_check(avro_value_set_branch(&p_avro_field, TRUE, &p_avro_branch));
	pm_avro_check(avro_value_set_string(&p_avro_branch, attr->community->str));
      }
      else {
	pm_avro_check(avro_value_get_by_name(&p_avro_obj, "comms", &p_avro_field, NULL));
	pm_avro_check(avro_value_set_branch(&p_avro_field, FALSE, &p_avro_branch));
      }

      if (attr->ecommunity) {
	pm_avro_check(avro_value_get_by_name(&p_avro_obj, "ecomms", &p_avro_field, NULL));
	pm_avro_check(avro_value_set_branch(&p_avro_field, TRUE, &p_avro_branch));
	pm_avro_check(avro_value_set_string(&p_avro_branch, attr->ecommunity->str));
      }
      else {
	pm_avro_check(avro_value_get_by_name(&p_avro_obj, "ecomms", &p_avro_field, NULL));
	pm_avro_check(avro_value_set_branch(&p_avro_field, FALSE, &p_avro_branch));
      }

      if (attr->lcommunity) {
	pm_avro_check(avro_value_get_by_name(&p_avro_obj, "lcomms", &p_avro_field, NULL));
	pm_avro_check(avro_value_set_branch(&p_avro_field, TRUE, &p_avro_branch));
	pm_avro_check(avro_value_set_string(&p_avro_branch, attr->lcommunity->str));
      }
      else {
	pm_avro_check(avro_value_get_by_name(&p_avro_obj, "lcomms", &p_avro_field, NULL));
	pm_avro_check(avro_value_set_branch(&p_avro_field, FALSE, &p_avro_branch));
      }

      if (attr->bitmap & BGP_BMAP_ATTR_MULTI_EXIT_DISC) {
	pm_avro_check(avro_value_get_by_name(&p_avro_obj, "med", &p_avro_field, NULL));
	pm_avro_check(avro_value_set_branch(&p_avro_field, TRUE, &p_avro_branch));
	pm_avro_check(avro_value_set_long(&p_avro_branch, attr->med));
      }
      else {
	pm_avro_check(avro_value_get_by_name(&p_avro_obj, "med", &p_avro_field, NULL));
	pm_avro_check(avro_value_set_branch(&p_avro_field, FALSE, &p_avro_branch));
      }

      if (attr_extra && (attr_extra->bitmap & BGP_BMAP_ATTR_AIGP)) {
	pm_avro_check(avro_value_get_by_name(&p_avro_obj, "aigp", &p_avro_field, NULL));
	pm_avro_check(avro_value_set_branch(&p_avro_field, TRUE, &p_avro_branch));
	pm_avro_check(avro_value_set_long(&p_avro_branch, attr_extra->aigp));
      }
      else {
	pm_avro_check(avro_value_get_by_name(&p_avro_obj, "aigp", &p_avro_field, NULL));
	pm_avro_check(avro_value_set_branch(&p_avro_field, FALSE, &p_avro_branch));
      }

      if (attr_extra && attr_extra->psid_li) {
	pm_avro_check(avro_value_get_by_name(&p_avro_obj, "psid_li", &p_avro_field, NULL));
	pm_avro_check(avro_value_set_branch(&p_avro_field, TRUE, &p_avro_branch));
	pm_avro_check(avro_value_set_long(&p_avro_branch, attr_extra->psid_li));
      }
      else {
	pm_avro_check(avro_value_get_by_name(&p_avro_obj, "psid_li", &p_avro_field, NULL));
	pm_avro_check(avro_value_set_branch(&p_avro_field, FALSE, &p_avro_branch));
      }
    }
    else {
      pm_avro_check(avro_value_get_by_name(&p_avro_obj, "bgp_nexthop", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, FALSE, &p_avro_branch));

      pm_avro_check(avro_value_get_by_name(&p_avro_obj, "as_path", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, FALSE, &p_avro_branch));

      pm_avro_check(avro_value_get_by_name(&p_avro_obj, "origin", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, FALSE, &p_avro_branch));

      pm_avro_check(avro_value_get_by_name(&p_avro_obj, "local_pref", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, FALSE, &p_avro_branch));

      pm_avro_check(avro_value_get_by_name(&p_avro_obj, "comms", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, FALSE, &p_avro_branch));

      pm_avro_check(avro_value_get_by_name(&p_avro_obj, "ecomms", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, FALSE, &p_avro_branch));

      pm_avro_check(avro_value_get_by_name(&p_avro_obj, "lcomms", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, FALSE, &p_avro_branch));

      pm_avro_check(avro_value_get_by_name(&p_avro_obj, "med", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, FALSE, &p_avro_branch));

      pm_avro_check(avro_value_get_by_name(&p_avro_obj, "aigp", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, FALSE, &p_avro_branch));

      pm_avro_check(avro_value_get_by_name(&p_avro_obj, "psid_li", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, FALSE, &p_avro_branch));
    }

    if (peer->cap_add_paths[afi][safi] && ri && ri->attr_extra) {
      pm_avro_check(avro_value_get_by_name(&p_avro_obj, "as_path_id", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, TRUE, &p_avro_branch));
      pm_avro_check(avro_value_set_long(&p_avro_branch, ri->attr_extra->path_id));
    }
    else {
      pm_avro_check(avro_value_get_by_name(&p_avro_obj, "as_path_id", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, FALSE, &p_avro_branch));
    }

    if (safi == SAFI_MPLS_LABEL || safi == SAFI_MPLS_VPN) {
      char label_str[SHORTSHORTBUFLEN];

      if (safi == SAFI_MPLS_VPN) {
        char rd_str[SHORTSHORTBUFLEN];

        bgp_rd2str(rd_str, &ri->attr_extra->rd);
	pm_avro_check(avro_value_get_by_name(&p_avro_obj, "rd", &p_avro_field, NULL));
	pm_avro_check(avro_value_set_branch(&p_avro_field, TRUE, &p_avro_branch));
	pm_avro_check(avro_value_set_string(&p_avro_branch, rd_str));

	pm_avro_check(avro_value_get_by_name(&p_avro_obj, "rd_origin", &p_avro_field, NULL));
	pm_avro_check(avro_value_set_branch(&p_avro_field, TRUE, &p_avro_branch));
	pm_avro_check(avro_value_set_string(&p_avro_branch, bgp_rd_origin_print(ri->attr_extra->rd.type)));
      }
      else {
	pm_avro_check(avro_value_get_by_name(&p_avro_obj, "rd", &p_avro_field, NULL));
	pm_avro_check(avro_value_set_branch(&p_avro_field, FALSE, &p_avro_branch));

	pm_avro_check(avro_value_get_by_name(&p_avro_obj, "rd_origin", &p_avro_field, NULL));
	pm_avro_check(avro_value_set_branch(&p_avro_field, FALSE, &p_avro_branch));
      }

      bgp_label2str(label_str, ri->attr_extra->label);
      pm_avro_check(avro_value_get_by_name(&p_avro_obj, "label", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, TRUE, &p_avro_branch));
      pm_avro_check(avro_value_set_string(&p_avro_branch, label_str));
    }
    else {
      int disc = FALSE;

      pm_avro_check(avro_value_get_by_name(&p_avro_obj, "rd", &p_avro_field, NULL));
      avro_value_get_discriminant(&p_avro_field, &disc);

      if (disc != TRUE) {
	pm_avro_check(avro_value_set_branch(&p_avro_field, FALSE, &p_avro_branch));

        pm_avro_check(avro_value_get_by_name(&p_avro_obj, "rd_origin", &p_avro_field, NULL));
	pm_avro_check(avro_value_set_branch(&p_avro_field, FALSE, &p_avro_branch));
      }

      pm_avro_check(avro_value_get_by_name(&p_avro_obj, "label", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, FALSE, &p_avro_branch));
    }

    if (bms->bgp_peer_log_msg_extras) bms->bgp_peer_log_msg_extras(peer, etype, log_type, output, &p_avro_obj);

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

      pm_avro_check(avro_value_get_by_name(&p_avro_obj, "roa", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_string(&p_avro_field, rpki_roa_print(roa)));
    }

    pm_avro_check(avro_value_get_by_name(&p_avro_obj, "writer_id", &p_avro_field, NULL));
    snprintf(wid, SHORTSHORTBUFLEN, "%s/%u", config.proc_name, getpid());
    pm_avro_check(avro_value_set_string(&p_avro_field, wid));

    if (((bms->msglog_file && etype == BGP_LOGDUMP_ET_LOG) ||
	 (bms->dump_file && etype == BGP_LOGDUMP_ET_DUMP) ||
	 (bms->msglog_amqp_routing_key && etype == BGP_LOGDUMP_ET_LOG) ||
	 (bms->dump_amqp_routing_key && etype == BGP_LOGDUMP_ET_DUMP) ||
	 (bms->msglog_kafka_topic && etype == BGP_LOGDUMP_ET_LOG && !bms->msglog_kafka_avro_schema_registry) ||
         (bms->dump_kafka_topic && etype == BGP_LOGDUMP_ET_DUMP && !bms->dump_kafka_avro_schema_registry)) &&
	(output == PRINT_OUTPUT_AVRO_BIN)) {
      avro_value_sizeof(&p_avro_obj, &p_avro_obj_len);
      assert(p_avro_obj_len < LARGEBUFLEN);

      if (avro_value_write(p_avro_writer, &p_avro_obj)) {
	Log(LOG_ERR, "ERROR ( %s/%s ): bgp_peer_log_msg(): avro_value_write() failed: %s\n", config.name, bms->log_str, avro_strerror());
	exit_gracefully(1);
      }

      p_avro_len = avro_writer_tell(p_avro_writer);
      p_avro_local_buf = bms->avro_buf;
    }

    if ((bms->msglog_file && etype == BGP_LOGDUMP_ET_LOG) ||
	(bms->dump_file && etype == BGP_LOGDUMP_ET_DUMP)) {
      if (output == PRINT_OUTPUT_AVRO_BIN) {
        write_file_binary(peer->log->fd, p_avro_local_buf, p_avro_len);
      }
      else if (output == PRINT_OUTPUT_AVRO_JSON) {
	write_avro_json_record_to_file(peer->log->fd, p_avro_obj);
      }
    }

    if ((bms->msglog_amqp_routing_key && etype == BGP_LOGDUMP_ET_LOG) ||
        (bms->dump_amqp_routing_key && etype == BGP_LOGDUMP_ET_DUMP)) {
#ifdef WITH_RABBITMQ
      if (output == PRINT_OUTPUT_AVRO_BIN) {
	amqp_ret = write_binary_amqp(peer->log->amqp_host, p_avro_local_buf, p_avro_len);
      }
      else if (output == PRINT_OUTPUT_AVRO_JSON) {
	char *avro_local_str = NULL;

	avro_value_to_json(&p_avro_obj, TRUE, &avro_local_str);

	if (avro_local_str) {
	  amqp_ret = write_string_amqp(peer->log->amqp_host, avro_local_str);
	  free(avro_local_str);
	}
      }

      p_amqp_unset_routing_key(peer->log->amqp_host);
#endif
    }

    if ((bms->msglog_kafka_topic && etype == BGP_LOGDUMP_ET_LOG) ||
        (bms->dump_kafka_topic && etype == BGP_LOGDUMP_ET_DUMP)) {
#ifdef WITH_KAFKA
      if ((bms->msglog_kafka_avro_schema_registry && etype == BGP_LOGDUMP_ET_LOG) ||
	  (bms->dump_kafka_avro_schema_registry && etype == BGP_LOGDUMP_ET_DUMP)) {
#ifdef WITH_SERDES
	struct p_kafka_host *kafka_host = (struct p_kafka_host *) peer->log->kafka_host;

	if (kafka_host->sd_schema[0]) {
	  if (serdes_schema_serialize_avro(kafka_host->sd_schema[0], &p_avro_obj, &p_avro_local_buf, &p_avro_len,
					 kafka_host->errstr, sizeof(kafka_host->errstr))) {
	    Log(LOG_ERR, "ERROR ( %s/%s ): bgp_peer_log_msg(): serdes_schema_serialize_avro() failed: %s\n", config.name, bms->log_str, kafka_host->errstr);
	    exit_gracefully(1);
	  }
        }
#endif
      }

      if (output == PRINT_OUTPUT_AVRO_BIN) {
	kafka_ret = write_binary_kafka(peer->log->kafka_host, p_avro_local_buf, p_avro_len);
      }
      else if (output == PRINT_OUTPUT_AVRO_JSON) {
	char *avro_local_str = NULL;

	avro_value_to_json(&p_avro_obj, TRUE, &avro_local_str);

	if (avro_local_str) {
	  kafka_ret = write_binary_kafka(peer->log->kafka_host, avro_local_str, (strlen(avro_local_str) + 1));
	  free(avro_local_str);
	}
      }

      p_kafka_unset_topic(peer->log->kafka_host);
#endif
    }

    avro_value_decref(&p_avro_obj);
    avro_value_iface_decref(p_avro_iface);
    avro_writer_reset(p_avro_writer);
    avro_writer_free(p_avro_writer);
    if (bms->dump_kafka_avro_schema_registry) {
      free(p_avro_local_buf);
    }
#endif
  }

  return (ret | amqp_ret | kafka_ret);
}

int bgp_peer_log_init(struct bgp_peer *peer, int output, int type)
{
  struct bgp_misc_structs *bms = bgp_select_misc_db(type);
  int peer_idx, have_it, ret = 0, amqp_ret = 0, kafka_ret = 0;
  char log_filename[SRVBUFLEN], log_partname[SRVBUFLEN];

  if (!bms || !peer) return ERR;

  if (bms->msglog_file) {
    bgp_peer_log_dynname(log_filename, SRVBUFLEN, bms->msglog_file, peer); 
  }

  if (bms->msglog_amqp_routing_key) {
    bgp_peer_log_dynname(log_filename, SRVBUFLEN, bms->msglog_amqp_routing_key, peer); 
  }

  if (bms->msglog_kafka_topic) {
    bgp_peer_log_dynname(log_filename, SRVBUFLEN, bms->msglog_kafka_topic, peer); 
  }

  if (bms->msglog_kafka_partition_key) {
    bgp_peer_log_dynname(log_partname, SRVBUFLEN, bms->msglog_kafka_partition_key, peer);
  }

  for (peer_idx = 0, have_it = 0; peer_idx < bms->max_peers; peer_idx++) {
    if (!bms->peers_log[peer_idx].refcnt) {
      if (bms->msglog_file) {
	bms->peers_log[peer_idx].fd = open_output_file(log_filename, "a", FALSE);
	setlinebuf(bms->peers_log[peer_idx].fd);
      }

#ifdef WITH_RABBITMQ
      if (bms->msglog_amqp_routing_key) {
        bms->peers_log[peer_idx].amqp_host = bms->msglog_amqp_host;
      }
#endif

#ifdef WITH_KAFKA
      if (bms->msglog_kafka_topic) {
        bms->peers_log[peer_idx].kafka_host = bms->msglog_kafka_host;
      }

      if (bms->msglog_kafka_partition_key) {
        strcpy(bms->peers_log[peer_idx].partition_key, log_partname);
      }
#endif
      
      strcpy(bms->peers_log[peer_idx].filename, log_filename);
      have_it = TRUE;
      break;
    }
    else if (!strcmp(log_filename, bms->peers_log[peer_idx].filename)) {
      if (bms->msglog_kafka_partition_key) {
	if (!strcmp(log_partname, bms->peers_log[peer_idx].partition_key)) {
	  have_it = TRUE;
	}
      }
      else {
        have_it = TRUE;
      }

      if (have_it) break;
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
    if (bms->msglog_kafka_topic) {
      p_kafka_set_topic(peer->log->kafka_host, peer->log->filename);
    }

    if (bms->msglog_kafka_topic_rr && !p_kafka_get_topic_rr(peer->log->kafka_host)) {
      p_kafka_init_topic_rr(peer->log->kafka_host);
      p_kafka_set_topic_rr(peer->log->kafka_host, bms->msglog_kafka_topic_rr);
    }

    if (bms->msglog_kafka_partition_key) {
      p_kafka_set_key(peer->log->kafka_host, peer->log->partition_key, strlen(peer->log->partition_key));
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

      if (bms->bgp_peer_logdump_initclose_extras) {
	bms->bgp_peer_logdump_initclose_extras(peer, output, obj);
      }

      if (bms->msglog_file) {
	write_and_free_json(peer->log->fd, obj);
      }

#ifdef WITH_RABBITMQ
      if (bms->msglog_amqp_routing_key) {
	add_writer_name_and_pid_json(obj, config.proc_name, getpid());
	amqp_ret = write_and_free_json_amqp(peer->log->amqp_host, obj); 
	p_amqp_unset_routing_key(peer->log->amqp_host);
      }
#endif

#ifdef WITH_KAFKA
      if (bms->msglog_kafka_topic) {
	add_writer_name_and_pid_json(obj, config.proc_name, getpid());
        kafka_ret = write_and_free_json_kafka(peer->log->kafka_host, obj);
        p_kafka_unset_topic(peer->log->kafka_host);
      }
#endif
#endif
    }
    else if ((output == PRINT_OUTPUT_AVRO_BIN) ||
	     (output == PRINT_OUTPUT_AVRO_JSON)) {
#ifdef WITH_AVRO
      char event_type[] = "log_init";
      char ip_address[INET6_ADDRSTRLEN], wid[SHORTSHORTBUFLEN];

      avro_writer_t p_avro_writer = {0};
      avro_value_iface_t *p_avro_iface = NULL;
      avro_value_t p_avro_obj, p_avro_field, p_avro_branch;
      size_t p_avro_obj_len, p_avro_len;
      void *p_avro_local_buf = NULL;

      p_avro_writer = avro_writer_memory(bms->avro_buf, LARGEBUFLEN);
      p_avro_iface = avro_generic_class_from_schema(bms->msglog_avro_schema[BGP_LOG_TYPE_LOGINIT]);
      pm_avro_check(avro_generic_value_new(p_avro_iface, &p_avro_obj));

      pm_avro_check(avro_value_get_by_name(&p_avro_obj, "seq", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_long(&p_avro_field, bgp_peer_log_seq_get(&bms->log_seq)));
      bgp_peer_log_seq_increment(&bms->log_seq);

      pm_avro_check(avro_value_get_by_name(&p_avro_obj, "timestamp", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_string(&p_avro_field, bms->log_tstamp_str));

      addr_to_str(ip_address, &peer->addr);
      pm_avro_check(avro_value_get_by_name(&p_avro_obj, bms->peer_str, &p_avro_field, NULL));
      pm_avro_check(avro_value_set_string(&p_avro_field, ip_address));

      if (bms->peer_port_str) {
	pm_avro_check(avro_value_get_by_name(&p_avro_obj, bms->peer_port_str, &p_avro_field, NULL));
	pm_avro_check(avro_value_set_branch(&p_avro_field, TRUE, &p_avro_branch));
	pm_avro_check(avro_value_set_int(&p_avro_branch, peer->tcp_port));
      }
      else {
	pm_avro_check(avro_value_get_by_name(&p_avro_obj, bms->peer_port_str, &p_avro_field, NULL));
	pm_avro_check(avro_value_set_branch(&p_avro_field, FALSE, &p_avro_branch));
      }

      pm_avro_check(avro_value_get_by_name(&p_avro_obj, "event_type", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_string(&p_avro_field, event_type));

      pm_avro_check(avro_value_get_by_name(&p_avro_obj, "writer_id", &p_avro_field, NULL));
      snprintf(wid, SHORTSHORTBUFLEN, "%s/%u", config.proc_name, getpid());
      pm_avro_check(avro_value_set_string(&p_avro_field, wid));

      if (bms->bgp_peer_logdump_initclose_extras) {
	bms->bgp_peer_logdump_initclose_extras(peer, output, &p_avro_obj);
      }

      if (!bms->msglog_kafka_avro_schema_registry && output == PRINT_OUTPUT_AVRO_BIN) {
	avro_value_sizeof(&p_avro_obj, &p_avro_obj_len);
	assert(p_avro_obj_len < LARGEBUFLEN);

	if (avro_value_write(p_avro_writer, &p_avro_obj)) {
	  Log(LOG_ERR, "ERROR ( %s/%s ): bgp_peer_log_init(): avro_value_write() failed: %s\n", config.name, bms->log_str, avro_strerror());
	  exit_gracefully(1);
	}	

	p_avro_len = avro_writer_tell(p_avro_writer);
	p_avro_local_buf = bms->avro_buf;
      }

      if (bms->msglog_file) {
	if (output == PRINT_OUTPUT_AVRO_BIN) {
	  write_file_binary(peer->log->fd, p_avro_local_buf, p_avro_len);
	}
	else if (output == PRINT_OUTPUT_AVRO_JSON) {
	  write_avro_json_record_to_file(peer->log->fd, p_avro_obj);
	}
      }

#ifdef WITH_RABBITMQ
      if (bms->msglog_amqp_routing_key) {
	if (output == PRINT_OUTPUT_AVRO_BIN) {
	  amqp_ret = write_binary_amqp(peer->log->amqp_host, p_avro_local_buf, p_avro_len);
	}
	else if (output == PRINT_OUTPUT_AVRO_JSON) {
	  char *avro_local_str = NULL;

	  avro_value_to_json(&p_avro_obj, TRUE, &avro_local_str);

	  if (avro_local_str) {
	    amqp_ret = write_string_amqp(peer->log->amqp_host, avro_local_str);
	    free(avro_local_str);
	  }
	}

	p_amqp_unset_routing_key(peer->log->amqp_host);
      }
#endif

#ifdef WITH_KAFKA
      if (bms->msglog_kafka_topic) {
	if (bms->msglog_kafka_avro_schema_registry) {
#ifdef WITH_SERDES
	  struct p_kafka_host *kafka_host = (struct p_kafka_host *) peer->log->kafka_host;

	  if (kafka_host->sd_schema[BGP_LOG_TYPE_LOGINIT]) {
	    if (serdes_schema_serialize_avro(kafka_host->sd_schema[BGP_LOG_TYPE_LOGINIT], &p_avro_obj, &p_avro_local_buf, &p_avro_len,
					   kafka_host->errstr, sizeof(kafka_host->errstr))) {
	      Log(LOG_ERR, "ERROR ( %s/%s ): bgp_peer_log_init(): serdes_schema_serialize_avro() failed: %s\n", config.name, bms->log_str, kafka_host->errstr);
	      exit_gracefully(1);
	    }
	  }
#endif
	}

	if (output == PRINT_OUTPUT_AVRO_BIN) {
	  kafka_ret = write_binary_kafka(peer->log->kafka_host, p_avro_local_buf, p_avro_len);
	}
	else if (output == PRINT_OUTPUT_AVRO_JSON) {
	  char *avro_local_str = NULL;

	  avro_value_to_json(&p_avro_obj, TRUE, &avro_local_str);

	  if (avro_local_str) {
	    kafka_ret = write_binary_kafka(peer->log->kafka_host, avro_local_str, (strlen(avro_local_str) + 1));
	    free(avro_local_str);
	  }
	}

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

  if (!bms || !peer || !peer->log) return ERR;

#ifdef WITH_RABBITMQ
  if (bms->msglog_amqp_routing_key) {
    p_amqp_set_routing_key(peer->log->amqp_host, peer->log->filename);
  }
#endif

#ifdef WITH_KAFKA
  if (bms->msglog_kafka_topic) {
    p_kafka_set_topic(peer->log->kafka_host, peer->log->filename);
  }

  if (bms->msglog_kafka_partition_key) {
    p_kafka_set_key(peer->log->kafka_host, peer->log->partition_key, strlen(peer->log->partition_key));
  }
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

    if (bms->bgp_peer_logdump_initclose_extras) {
      bms->bgp_peer_logdump_initclose_extras(peer, output, obj);
    }

    if (bms->msglog_file) {
      write_and_free_json(log_ptr->fd, obj);
    }

#ifdef WITH_RABBITMQ
    if (bms->msglog_amqp_routing_key) {
      add_writer_name_and_pid_json(obj, config.proc_name, getpid());
      amqp_ret = write_and_free_json_amqp(amqp_log_ptr, obj);
      p_amqp_unset_routing_key(amqp_log_ptr);
    }
#endif

#ifdef WITH_KAFKA
    if (bms->msglog_kafka_topic) {
      add_writer_name_and_pid_json(obj, config.proc_name, getpid());
      kafka_ret = write_and_free_json_kafka(kafka_log_ptr, obj);
      p_kafka_unset_topic(kafka_log_ptr);
    }
#endif
#endif
  }
  else if ((output == PRINT_OUTPUT_AVRO_BIN) ||
	   (output == PRINT_OUTPUT_AVRO_JSON)) {
#ifdef WITH_AVRO
    char event_type[] = "log_close";
    char ip_address[INET6_ADDRSTRLEN], wid[SHORTSHORTBUFLEN];

    avro_writer_t p_avro_writer = {0};
    avro_value_iface_t *p_avro_iface = NULL;
    avro_value_t p_avro_obj, p_avro_field, p_avro_branch;
    size_t p_avro_obj_len, p_avro_len;
    void *p_avro_local_buf = NULL;

    p_avro_writer = avro_writer_memory(bms->avro_buf, LARGEBUFLEN);
    p_avro_iface = avro_generic_class_from_schema(bms->msglog_avro_schema[BGP_LOG_TYPE_LOGCLOSE]);
    pm_avro_check(avro_generic_value_new(p_avro_iface, &p_avro_obj));

    pm_avro_check(avro_value_get_by_name(&p_avro_obj, "seq", &p_avro_field, NULL));
    pm_avro_check(avro_value_set_long(&p_avro_field, bgp_peer_log_seq_get(&bms->log_seq)));
    bgp_peer_log_seq_increment(&bms->log_seq);

    pm_avro_check(avro_value_get_by_name(&p_avro_obj, "timestamp", &p_avro_field, NULL));
    pm_avro_check(avro_value_set_string(&p_avro_field, bms->log_tstamp_str));

    addr_to_str(ip_address, &peer->addr);
    pm_avro_check(avro_value_get_by_name(&p_avro_obj, bms->peer_str, &p_avro_field, NULL));
    pm_avro_check(avro_value_set_string(&p_avro_field, ip_address));

    if (bms->peer_port_str) {
      pm_avro_check(avro_value_get_by_name(&p_avro_obj, bms->peer_port_str, &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, TRUE, &p_avro_branch));
      pm_avro_check(avro_value_set_int(&p_avro_branch, peer->tcp_port));
    }
    else {
      pm_avro_check(avro_value_get_by_name(&p_avro_obj, bms->peer_port_str, &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, FALSE, &p_avro_branch));
    }

    pm_avro_check(avro_value_get_by_name(&p_avro_obj, "event_type", &p_avro_field, NULL));
    pm_avro_check(avro_value_set_string(&p_avro_field, event_type));

    pm_avro_check(avro_value_get_by_name(&p_avro_obj, "writer_id", &p_avro_field, NULL));
    snprintf(wid, SHORTSHORTBUFLEN, "%s/%u", config.proc_name, getpid());
    pm_avro_check(avro_value_set_string(&p_avro_field, wid));

    if (bms->bgp_peer_logdump_initclose_extras) {
      bms->bgp_peer_logdump_initclose_extras(peer, output, &p_avro_obj);
    }

    if (!bms->msglog_kafka_avro_schema_registry && output == PRINT_OUTPUT_AVRO_BIN) {
      avro_value_sizeof(&p_avro_obj, &p_avro_obj_len);
      assert(p_avro_obj_len < LARGEBUFLEN);

      if (avro_value_write(p_avro_writer, &p_avro_obj)) {
	Log(LOG_ERR, "ERROR ( %s/%s ): bgp_peer_log_close(): avro_value_write() failed: %s\n", config.name, bms->log_str, avro_strerror());
	exit_gracefully(1);
      }	

      p_avro_len = avro_writer_tell(p_avro_writer);
      p_avro_local_buf = bms->avro_buf;
    }

    if (bms->msglog_file) {
      if (output == PRINT_OUTPUT_AVRO_BIN) {
	write_file_binary(peer->log->fd, p_avro_local_buf, p_avro_len);
      }
      else if (output == PRINT_OUTPUT_AVRO_JSON) {
	write_avro_json_record_to_file(peer->log->fd, p_avro_obj);
      }
    }

#ifdef WITH_RABBITMQ
    if (bms->msglog_amqp_routing_key) {
      if (output == PRINT_OUTPUT_AVRO_BIN) {
	amqp_ret = write_binary_amqp(peer->log->amqp_host, p_avro_local_buf, p_avro_len);
      }
      else if (output == PRINT_OUTPUT_AVRO_JSON) {
	char *avro_local_str = NULL;

	avro_value_to_json(&p_avro_obj, TRUE, &avro_local_str);

	if (avro_local_str) {
	  amqp_ret = write_string_amqp(peer->log->amqp_host, avro_local_str);
	  free(avro_local_str);
	}
      }

      p_amqp_unset_routing_key(peer->log->amqp_host);
    }
#endif

#ifdef WITH_KAFKA
    if (bms->msglog_kafka_topic) {
      if (peer->log) {
	if (bms->msglog_kafka_avro_schema_registry) {
#ifdef WITH_SERDES
	  struct p_kafka_host *kafka_host = (struct p_kafka_host *) peer->log->kafka_host;

	  if (kafka_host->sd_schema[BGP_LOG_TYPE_LOGCLOSE]) {
	    if (serdes_schema_serialize_avro(kafka_host->sd_schema[BGP_LOG_TYPE_LOGCLOSE], &p_avro_obj, &p_avro_local_buf, &p_avro_len,
					 kafka_host->errstr, sizeof(kafka_host->errstr))) {
	      Log(LOG_ERR, "ERROR ( %s/%s ): bgp_peer_log_close(): serdes_schema_serialize_avro() failed: %s\n", config.name, bms->log_str, kafka_host->errstr);
	      exit_gracefully(1);
	    }
	  }
#endif
	}

	if (output == PRINT_OUTPUT_AVRO_BIN) {
	  kafka_ret = write_binary_kafka(peer->log->kafka_host, p_avro_local_buf, p_avro_len);
	}
	else if (output == PRINT_OUTPUT_AVRO_JSON) {
	  char *avro_local_str = NULL;

	  avro_value_to_json(&p_avro_obj, TRUE, &avro_local_str);

	  if (avro_local_str) {
	    kafka_ret = write_binary_kafka(peer->log->kafka_host, avro_local_str, (strlen(avro_local_str) + 1));
	    free(avro_local_str);
	  }
	}

	p_kafka_unset_topic(peer->log->kafka_host);
      }
      else {
	char peer_str[INET6_ADDRSTRLEN];

	addr_to_str(peer_str, &peer->addr);
	Log(LOG_WARNING, "WARNING ( %s/%s ): Unable to get kafka_host: %s\n", config.name, bms->log_str, peer_str);
      }
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
int bgp_peer_log_dynname(char *new, int newlen, char *old, struct bgp_peer *peer)
{
  int oldlen, is_dyn = FALSE;
  char psi_string[] = "$peer_src_ip", ptp_string[] = "$peer_tcp_port";
  char br_string[] = "$bmp_router", brp_string[] = "$bmp_router_port";
  char tn_string[] = "$telemetry_node", tnp_string[] = "$telemetry_node_port";
  char *ptr_start, *ptr_end, *string_ptr;

  if (!new || !old || !peer) return FALSE;

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

    is_dyn = TRUE;

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
    strncat(new, buf, newlen);
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

    is_dyn = TRUE;

    len = strlen(ptr_start);
    ptr_end = ptr_start;
    ptr_end += strlen(string_ptr);
    len -= strlen(string_ptr);

    snprintf(buf, newlen, "%u", peer->tcp_port);
    strncat(buf, ptr_end, len);

    len = strlen(buf);
    *ptr_start = '\0';
    strncat(new, buf, newlen);
  }

  return is_dyn;
}

int bgp_peer_dump_init(struct bgp_peer *peer, int output, int type)
{
  struct bgp_misc_structs *bms = bgp_select_misc_db(type);
  int ret = 0, amqp_ret = 0, kafka_ret = 0;

  if (!bms || !peer || !peer->log) return ERR;

#ifdef WITH_RABBITMQ
  if (bms->dump_amqp_routing_key) {
    p_amqp_set_routing_key(peer->log->amqp_host, peer->log->filename);
  }

  if (bms->dump_amqp_routing_key_rr && !p_amqp_get_routing_key_rr(peer->log->amqp_host)) {
    p_amqp_init_routing_key_rr(peer->log->amqp_host);
    p_amqp_set_routing_key_rr(peer->log->amqp_host, bms->dump_amqp_routing_key_rr);
  }
#endif

#ifdef WITH_KAFKA
  if (bms->dump_kafka_topic) {
    p_kafka_set_topic(peer->log->kafka_host, peer->log->filename);
  }

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

    if (bms->bgp_peer_logdump_initclose_extras) {
      bms->bgp_peer_logdump_initclose_extras(peer, output, obj);
    }

    if (bms->dump_file) {
      write_and_free_json(peer->log->fd, obj);
    }

#ifdef WITH_RABBITMQ
    if (bms->dump_amqp_routing_key) {
      add_writer_name_and_pid_json(obj, config.proc_name, getpid());
      amqp_ret = write_and_free_json_amqp(peer->log->amqp_host, obj);
      p_amqp_unset_routing_key(peer->log->amqp_host);
    }
#endif

#ifdef WITH_KAFKA
    if (bms->dump_kafka_topic) {
      add_writer_name_and_pid_json(obj, config.proc_name, getpid());
      kafka_ret = write_and_free_json_kafka(peer->log->kafka_host, obj);
      p_kafka_unset_topic(peer->log->kafka_host);
    }
#endif
#endif
  }
  else if ((output == PRINT_OUTPUT_AVRO_BIN) ||
	   (output == PRINT_OUTPUT_AVRO_JSON)) {
#ifdef WITH_AVRO
    char event_type[] = "dump_init";
    char ip_address[INET6_ADDRSTRLEN], wid[SHORTSHORTBUFLEN];

    avro_writer_t p_avro_writer = {0};
    avro_value_iface_t *p_avro_iface = NULL;
    avro_value_t p_avro_obj, p_avro_field, p_avro_branch;
    size_t p_avro_obj_len, p_avro_len;
    void *p_avro_local_buf = NULL;

    p_avro_writer = avro_writer_memory(bms->avro_buf, LARGEBUFLEN);
    p_avro_iface = avro_generic_class_from_schema(bms->dump_avro_schema[BGP_LOG_TYPE_DUMPINIT]);
    pm_avro_check(avro_generic_value_new(p_avro_iface, &p_avro_obj));

    pm_avro_check(avro_value_get_by_name(&p_avro_obj, "seq", &p_avro_field, NULL));
    pm_avro_check(avro_value_set_long(&p_avro_field, bgp_peer_log_seq_get(&bms->log_seq)));
    bgp_peer_log_seq_increment(&bms->log_seq);

    pm_avro_check(avro_value_get_by_name(&p_avro_obj, "timestamp", &p_avro_field, NULL));
    pm_avro_check(avro_value_set_string(&p_avro_field, bms->log_tstamp_str));

    addr_to_str(ip_address, &peer->addr);
    pm_avro_check(avro_value_get_by_name(&p_avro_obj, bms->peer_str, &p_avro_field, NULL));
    pm_avro_check(avro_value_set_string(&p_avro_field, ip_address));

    if (bms->peer_port_str) {
      pm_avro_check(avro_value_get_by_name(&p_avro_obj, bms->peer_port_str, &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, TRUE, &p_avro_branch));
      pm_avro_check(avro_value_set_int(&p_avro_branch, peer->tcp_port));
    }
    else {
      pm_avro_check(avro_value_get_by_name(&p_avro_obj, bms->peer_port_str, &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, FALSE, &p_avro_branch));
    }

    pm_avro_check(avro_value_get_by_name(&p_avro_obj, "event_type", &p_avro_field, NULL));
    pm_avro_check(avro_value_set_string(&p_avro_field, event_type));

    pm_avro_check(avro_value_get_by_name(&p_avro_obj, "dump_period", &p_avro_field, NULL));
    pm_avro_check(avro_value_set_long(&p_avro_field, bms->dump.period)); 

    pm_avro_check(avro_value_get_by_name(&p_avro_obj, "writer_id", &p_avro_field, NULL));
    snprintf(wid, SHORTSHORTBUFLEN, "%s/%u", config.proc_name, getpid());
    pm_avro_check(avro_value_set_string(&p_avro_field, wid));

    if (bms->bgp_peer_logdump_initclose_extras) {
      bms->bgp_peer_logdump_initclose_extras(peer, output, &p_avro_obj);
    }

    if (!bms->dump_kafka_avro_schema_registry && output == PRINT_OUTPUT_AVRO_BIN) {
      avro_value_sizeof(&p_avro_obj, &p_avro_obj_len);
      assert(p_avro_obj_len < LARGEBUFLEN);

      if (avro_value_write(p_avro_writer, &p_avro_obj)) {
	Log(LOG_ERR, "ERROR ( %s/%s ): bgp_peer_dump_init(): avro_value_write() failed: %s\n", config.name, bms->log_str, avro_strerror());
	exit_gracefully(1);
      }	

      p_avro_len = avro_writer_tell(p_avro_writer);
      p_avro_local_buf = bms->avro_buf;
    }

    if (bms->dump_file) {
      if (output == PRINT_OUTPUT_AVRO_BIN) {
	write_file_binary(peer->log->fd, p_avro_local_buf, p_avro_len);
      }
      else if (output == PRINT_OUTPUT_AVRO_JSON) {
	write_avro_json_record_to_file(peer->log->fd, p_avro_obj);
      }
    }

#ifdef WITH_RABBITMQ
    if (bms->dump_amqp_routing_key) {
      if (output == PRINT_OUTPUT_AVRO_BIN) {
	amqp_ret = write_binary_amqp(peer->log->amqp_host, p_avro_local_buf, p_avro_len);
      }
      else if (output == PRINT_OUTPUT_AVRO_JSON) {
	char *avro_local_str = NULL;

	avro_value_to_json(&p_avro_obj, TRUE, &avro_local_str);

	if (avro_local_str) {
	  amqp_ret = write_string_amqp(peer->log->amqp_host, avro_local_str);
	  free(avro_local_str);
	}
      }

      p_amqp_unset_routing_key(peer->log->amqp_host);
    }
#endif

#ifdef WITH_KAFKA
    if (bms->dump_kafka_topic) {
      if (bms->dump_kafka_avro_schema_registry) {
#ifdef WITH_SERDES
	struct p_kafka_host *kafka_host = (struct p_kafka_host *) peer->log->kafka_host;

	if (kafka_host->sd_schema[BGP_LOG_TYPE_DUMPINIT]) {
	  if (serdes_schema_serialize_avro(kafka_host->sd_schema[BGP_LOG_TYPE_DUMPINIT], &p_avro_obj, &p_avro_local_buf, &p_avro_len,
					 kafka_host->errstr, sizeof(kafka_host->errstr))) {
	    Log(LOG_ERR, "ERROR ( %s/%s ): bgp_peer_dump_init(): serdes_schema_serialize_avro() failed: %s\n", config.name, bms->log_str, kafka_host->errstr);
	    exit_gracefully(1);
	  }
	}
#endif
      }

      if (output == PRINT_OUTPUT_AVRO_BIN) {
	kafka_ret = write_binary_kafka(peer->log->kafka_host, p_avro_local_buf, p_avro_len);
      }
      else if (output == PRINT_OUTPUT_AVRO_JSON) {
	char *avro_local_str = NULL;

	avro_value_to_json(&p_avro_obj, TRUE, &avro_local_str);

	if (avro_local_str) {
	  kafka_ret = write_binary_kafka(peer->log->kafka_host, avro_local_str, (strlen(avro_local_str) + 1));
	  free(avro_local_str);
	}
      }

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

  if (!bms || !peer || !peer->log) return ERR;

#ifdef WITH_RABBITMQ
  if (bms->dump_amqp_routing_key) {
    p_amqp_set_routing_key(peer->log->amqp_host, peer->log->filename);
  }
#endif

#ifdef WITH_KAFKA
  if (bms->dump_kafka_topic) {
    p_kafka_set_topic(peer->log->kafka_host, peer->log->filename);
  }
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

    if (bms->bgp_peer_logdump_initclose_extras) {
      bms->bgp_peer_logdump_initclose_extras(peer, output, obj);
    }

    if (bms->dump_file) {
      write_and_free_json(peer->log->fd, obj);
    }

#ifdef WITH_RABBITMQ
    if (bms->dump_amqp_routing_key) {
      add_writer_name_and_pid_json(obj, config.proc_name, getpid());
      amqp_ret = write_and_free_json_amqp(peer->log->amqp_host, obj);
      p_amqp_unset_routing_key(peer->log->amqp_host);
    }
#endif

#ifdef WITH_KAFKA
    if (bms->dump_kafka_topic) {
      add_writer_name_and_pid_json(obj, config.proc_name, getpid());
      kafka_ret = write_and_free_json_kafka(peer->log->kafka_host, obj);
      p_kafka_unset_topic(peer->log->kafka_host);
    }
#endif
#endif
  }
  else if ((output == PRINT_OUTPUT_AVRO_BIN) ||
	   (output == PRINT_OUTPUT_AVRO_JSON)) {
#ifdef WITH_AVRO
    char event_type[] = "dump_close";
    char ip_address[INET6_ADDRSTRLEN], wid[SHORTSHORTBUFLEN];

    avro_writer_t p_avro_writer = {0};
    avro_value_iface_t *p_avro_iface = NULL;
    avro_value_t p_avro_obj, p_avro_field, p_avro_branch;
    size_t p_avro_obj_len, p_avro_len;
    void *p_avro_local_buf = NULL;

    p_avro_writer = avro_writer_memory(bms->avro_buf, LARGEBUFLEN);
    p_avro_iface = avro_generic_class_from_schema(bms->dump_avro_schema[BGP_LOG_TYPE_DUMPCLOSE]);
    pm_avro_check(avro_generic_value_new(p_avro_iface, &p_avro_obj));

    pm_avro_check(avro_value_get_by_name(&p_avro_obj, "seq", &p_avro_field, NULL));
    pm_avro_check(avro_value_set_long(&p_avro_field, bgp_peer_log_seq_get(&bms->log_seq)));
    bgp_peer_log_seq_increment(&bms->log_seq);

    pm_avro_check(avro_value_get_by_name(&p_avro_obj, "timestamp", &p_avro_field, NULL));
    pm_avro_check(avro_value_set_string(&p_avro_field, bms->log_tstamp_str));

    addr_to_str(ip_address, &peer->addr);
    pm_avro_check(avro_value_get_by_name(&p_avro_obj, bms->peer_str, &p_avro_field, NULL));
    pm_avro_check(avro_value_set_string(&p_avro_field, ip_address));

    if (bms->peer_port_str) {
      pm_avro_check(avro_value_get_by_name(&p_avro_obj, bms->peer_port_str, &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, TRUE, &p_avro_branch));
      pm_avro_check(avro_value_set_int(&p_avro_branch, peer->tcp_port));
    }
    else {
      pm_avro_check(avro_value_get_by_name(&p_avro_obj, bms->peer_port_str, &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, FALSE, &p_avro_branch));
    }

    pm_avro_check(avro_value_get_by_name(&p_avro_obj, "event_type", &p_avro_field, NULL));
    pm_avro_check(avro_value_set_string(&p_avro_field, event_type));

    if (bds) {
      pm_avro_check(avro_value_get_by_name(&p_avro_obj, "entries", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, TRUE, &p_avro_branch));
      pm_avro_check(avro_value_set_long(&p_avro_branch, bds->entries));

      pm_avro_check(avro_value_get_by_name(&p_avro_obj, "tables", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, TRUE, &p_avro_branch));
      pm_avro_check(avro_value_set_int(&p_avro_branch, bds->tables)); 
    }
    else {
      pm_avro_check(avro_value_get_by_name(&p_avro_obj, "entries", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, FALSE, &p_avro_branch));

      pm_avro_check(avro_value_get_by_name(&p_avro_obj, "tables", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, FALSE, &p_avro_branch));
    }

    pm_avro_check(avro_value_get_by_name(&p_avro_obj, "writer_id", &p_avro_field, NULL));
    snprintf(wid, SHORTSHORTBUFLEN, "%s/%u", config.proc_name, getpid());
    pm_avro_check(avro_value_set_string(&p_avro_field, wid));

    if (bms->bgp_peer_logdump_initclose_extras) {
      bms->bgp_peer_logdump_initclose_extras(peer, output, &p_avro_obj);
    }

    if (!bms->dump_kafka_avro_schema_registry && output == PRINT_OUTPUT_AVRO_BIN) {
      avro_value_sizeof(&p_avro_obj, &p_avro_obj_len);
      assert(p_avro_obj_len < LARGEBUFLEN);

      if (avro_value_write(p_avro_writer, &p_avro_obj)) {
	Log(LOG_ERR, "ERROR ( %s/%s ): bgp_peer_dump_close(): avro_value_write() failed: %s\n", config.name, bms->log_str, avro_strerror());
	exit_gracefully(1);
      }	

      p_avro_len = avro_writer_tell(p_avro_writer);
      p_avro_local_buf = bms->avro_buf;
    }

    if (bms->dump_file) {
      if (output == PRINT_OUTPUT_AVRO_BIN) {
	write_file_binary(peer->log->fd, p_avro_local_buf, p_avro_len);
      }
      else if (output == PRINT_OUTPUT_AVRO_JSON) {
	write_avro_json_record_to_file(peer->log->fd, p_avro_obj);
      }
    }

#ifdef WITH_RABBITMQ
    if (bms->dump_amqp_routing_key) {
      if (output == PRINT_OUTPUT_AVRO_BIN) {
	amqp_ret = write_binary_amqp(peer->log->amqp_host, p_avro_local_buf, p_avro_len);
      }
      else if (output == PRINT_OUTPUT_AVRO_JSON) {
	char *avro_local_str = NULL;

	avro_value_to_json(&p_avro_obj, TRUE, &avro_local_str);

	if (avro_local_str) {
	  amqp_ret = write_string_amqp(peer->log->amqp_host, avro_local_str);
	  free(avro_local_str);
	}
      }

      p_amqp_unset_routing_key(peer->log->amqp_host);
    }
#endif

#ifdef WITH_KAFKA
    if (bms->dump_kafka_topic) {
      if (bms->dump_kafka_avro_schema_registry) {
#ifdef WITH_SERDES
	struct p_kafka_host *kafka_host = (struct p_kafka_host *) peer->log->kafka_host;

	if (kafka_host->sd_schema[BGP_LOG_TYPE_DUMPCLOSE]) {
	  if (serdes_schema_serialize_avro(kafka_host->sd_schema[BGP_LOG_TYPE_DUMPCLOSE], &p_avro_obj, &p_avro_local_buf, &p_avro_len,
					 kafka_host->errstr, sizeof(kafka_host->errstr))) {
	    Log(LOG_ERR, "ERROR ( %s/%s ): bgp_peer_dump_close(): serdes_schema_serialize_avro() failed: %s\n", config.name, bms->log_str, kafka_host->errstr);
	    exit_gracefully(1);
	  }
	}
#endif
      }

      if (output == PRINT_OUTPUT_AVRO_BIN) {
	kafka_ret = write_binary_kafka(peer->log->kafka_host, p_avro_local_buf, p_avro_len);
      }
      else if (output == PRINT_OUTPUT_AVRO_JSON) {
	char *avro_local_str = NULL;

	avro_value_to_json(&p_avro_obj, TRUE, &avro_local_str);

	if (avro_local_str) {
	  kafka_ret = write_binary_kafka(peer->log->kafka_host, avro_local_str, (strlen(avro_local_str) + 1));
	  free(avro_local_str);
	}
      }

      p_kafka_unset_topic(peer->log->kafka_host);
    }
#endif
#endif
  }

  return (ret | amqp_ret | kafka_ret);
}

void bgp_handle_dump_event(int max_peers_idx)
{
  struct bgp_misc_structs *bms = bgp_select_misc_db(FUNC_TYPE_BGP);
  thread_pool_t *bgp_table_dump_workers_pool;
  struct pm_dump_runner pdr[config.bgp_table_dump_workers];
  u_int64_t dump_seqno;
  int idx, ret;

  /* pre-flight check */
  if (!bms->dump_backend_methods || !config.bgp_table_dump_refresh_time) {
    return;
  }

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

    /* setting ourselves as read-only */
    bms->is_readonly = TRUE;

    /* Arranging workers data */
    distribute_work(pdr, dump_seqno, config.bgp_table_dump_workers, max_peers_idx);

    /* creating the thread pool */
    bgp_table_dump_workers_pool = allocate_thread_pool(config.bgp_table_dump_workers);
    assert(bgp_table_dump_workers_pool);

    for (idx = 0; idx < config.bgp_table_dump_workers; idx++) {
      if (!pdr[idx].noop) {
        send_to_pool(bgp_table_dump_workers_pool, bgp_table_dump_event_runner, &pdr[idx]);
      }
    }

    deallocate_thread_pool(&bgp_table_dump_workers_pool);
    exit_gracefully(0);
  default: /* Parent */
    if (ret == -1) { /* Something went wrong */
      Log(LOG_WARNING, "WARN ( %s/%s ): Unable to fork BGP table dump writer: %s\n",
	  config.name, bms->log_str, strerror(errno));
    }

    break;
  }
}

int bgp_table_dump_event_runner(struct pm_dump_runner *pdr)
{
  struct bgp_misc_structs *bms = bgp_select_misc_db(FUNC_TYPE_BGP);
  char current_filename[SRVBUFLEN], last_filename[SRVBUFLEN], tmpbuf[SRVBUFLEN];
  char latest_filename[SRVBUFLEN], dump_partition_key[SRVBUFLEN];
  char event_type[] = "dump", *fd_buf = NULL;
  int peers_idx, duration, tables_num;
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
  u_int64_t dump_elems = 0, dump_seqno = pdr->seq;

#ifdef WITH_RABBITMQ
  struct p_amqp_host bgp_table_dump_amqp_host;
#endif

#ifdef WITH_KAFKA
  struct p_kafka_host bgp_table_dump_kafka_host;
#endif

  memset(last_filename, 0, sizeof(last_filename));
  memset(current_filename, 0, sizeof(current_filename));
  memset(&peer_log, 0, sizeof(struct bgp_peer_log));
  memset(&bds, 0, sizeof(struct bgp_dump_stats));

  fd_buf = malloc(OUTPUT_FILE_BUFSZ);
  bgp_peer_log_seq_set(&bms->log_seq, dump_seqno);

#ifdef WITH_RABBITMQ
  if (config.bgp_table_dump_amqp_routing_key) {
    int ret;

    bgp_table_dump_init_amqp_host(&bgp_table_dump_amqp_host);
    ret = p_amqp_connect_to_publish(&bgp_table_dump_amqp_host);
    if (ret) exit_gracefully(ret);
  }
#endif

#ifdef WITH_KAFKA
  if (config.bgp_table_dump_kafka_topic) {
    int ret;

    ret = bgp_table_dump_init_kafka_host(&bgp_table_dump_kafka_host);
    if (ret) exit_gracefully(ret);
  }
#endif

  dumper_pid = getpid();
  Log(LOG_INFO, "INFO ( %s/%s ): *** Dumping BGP tables - START (PID: %u RID: %u) ***\n",
      config.name, bms->log_str, dumper_pid, pdr->id);
  start = time(NULL);
  tables_num = 0;

#ifdef WITH_SERDES
  if (config.bgp_table_dump_kafka_avro_schema_registry) { 
    if (strchr(config.bgp_table_dump_kafka_topic, '$')) {
      Log(LOG_ERR, "ERROR ( %s/%s ): dynamic 'bgp_table_dump_kafka_topic' is not compatible with 'bgp_table_dump_kafka_avro_schema_registry'. Exiting.\n",
	  config.name, bms->log_str);
      exit_gracefully(1);
    }

    bgp_table_dump_kafka_host.sd_schema[0] = compose_avro_schema_registry_name_2(config.bgp_table_dump_kafka_topic, FALSE,
										 bms->dump_avro_schema[0],
										 "bgp", "dump",
										 config.bgp_table_dump_kafka_avro_schema_registry);

    bgp_table_dump_kafka_host.sd_schema[BGP_LOG_TYPE_DUMPINIT] = compose_avro_schema_registry_name_2(config.bgp_table_dump_kafka_topic, FALSE,
										 bms->dump_avro_schema[BGP_LOG_TYPE_DUMPINIT],
										 "bgp", "dumpinit",
										 config.bgp_table_dump_kafka_avro_schema_registry);

    bgp_table_dump_kafka_host.sd_schema[BGP_LOG_TYPE_DUMPCLOSE] = compose_avro_schema_registry_name_2(config.bgp_table_dump_kafka_topic, FALSE,
										 bms->dump_avro_schema[BGP_LOG_TYPE_DUMPCLOSE],
										 "bgp", "dumpclose",
										 config.bgp_table_dump_kafka_avro_schema_registry);
  }
#endif

  for (peer = NULL, saved_peer = NULL, peers_idx = pdr->first; peers_idx <= pdr->last; peers_idx++) {
    if (peers[peers_idx].fd) {
      peer = &peers[peers_idx];
      peer->log = &peer_log; /* abusing struct bgp_peer a bit, but we are in a child */

      if (config.bgp_table_dump_file) {
	bgp_peer_log_dynname(current_filename, SRVBUFLEN, config.bgp_table_dump_file, peer);
      }

      if (config.bgp_table_dump_amqp_routing_key) {
	bgp_peer_log_dynname(current_filename, SRVBUFLEN, config.bgp_table_dump_amqp_routing_key, peer);
      }

      if (config.bgp_table_dump_kafka_topic) {
	bgp_peer_log_dynname(current_filename, SRVBUFLEN, config.bgp_table_dump_kafka_topic, peer);
      }

      if (config.bgp_table_dump_kafka_partition_key) {
	memset(dump_partition_key, 0, SRVBUFLEN);
	bgp_peer_log_dynname(dump_partition_key, SRVBUFLEN, config.bgp_table_dump_kafka_partition_key, peer);
      }

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

	if (config.bgp_table_dump_kafka_partition_key) {
	  p_kafka_set_key(peer->log->kafka_host, dump_partition_key, strlen(dump_partition_key));
	}
      }
#endif

      bgp_peer_dump_init(peer, config.bgp_table_dump_output, FUNC_TYPE_BGP);
      inter_domain_routing_db = bgp_select_routing_db(FUNC_TYPE_BGP);
      bds.entries = 0;
      bds.tables = 0;

      if (!inter_domain_routing_db) return ERR;

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
	          bds.entries++;
		}
	      }
	    }

	    node = bgp_route_next(peer, node);
	  }
	}
      }

      saved_peer = peer;
      tables_num++;
      bds.tables++;

      strlcpy(last_filename, current_filename, SRVBUFLEN);
      bgp_peer_dump_close(peer, &bds, config.bgp_table_dump_output, FUNC_TYPE_BGP);
    }
  }

#ifdef WITH_RABBITMQ
  if (config.bgp_table_dump_amqp_routing_key) {
    p_amqp_close(&bgp_table_dump_amqp_host, FALSE);
  }
#endif

#ifdef WITH_KAFKA
  if (config.bgp_table_dump_kafka_topic) {
    p_kafka_close(&bgp_table_dump_kafka_host, FALSE);
  }
#endif

  if (config.bgp_table_dump_latest_file && peer) {
    bgp_peer_log_dynname(latest_filename, SRVBUFLEN, config.bgp_table_dump_latest_file, peer);
    link_latest_output_file(latest_filename, last_filename);
  }

  duration = time(NULL)-start;
  Log(LOG_INFO, "INFO ( %s/%s ): *** Dumping BGP tables - END (PID: %u RID: %u TABLES: %u ENTRIES: %" PRIu64 " ET: %u) ***\n",
      config.name, bms->log_str, dumper_pid, pdr->id, tables_num, dump_elems, duration);

  return FALSE;
}

#ifdef WITH_RABBITMQ
  struct p_amqp_host bgp_table_dump_amqp_host;
#endif

#ifdef WITH_KAFKA
  struct p_kafka_host bgp_table_dump_kafka_host;
#endif

#if defined WITH_RABBITMQ
void bgp_daemon_msglog_init_amqp_host()
{
  p_amqp_init_host(&bgp_daemon_msglog_amqp_host);

  if (!config.bgp_daemon_msglog_amqp_user) config.bgp_daemon_msglog_amqp_user = rabbitmq_user;
  if (!config.bgp_daemon_msglog_amqp_passwd) config.bgp_daemon_msglog_amqp_passwd = rabbitmq_pwd;
  if (!config.bgp_daemon_msglog_amqp_exchange) config.bgp_daemon_msglog_amqp_exchange = default_amqp_exchange;
  if (!config.bgp_daemon_msglog_amqp_exchange_type) config.bgp_daemon_msglog_amqp_exchange_type = default_amqp_exchange_type;
  if (!config.bgp_daemon_msglog_amqp_host) config.bgp_daemon_msglog_amqp_host = default_amqp_host;
  if (!config.bgp_daemon_msglog_amqp_vhost) config.bgp_daemon_msglog_amqp_vhost = default_amqp_vhost;
  if (!config.bgp_daemon_msglog_amqp_retry) config.bgp_daemon_msglog_amqp_retry = AMQP_DEFAULT_RETRY;

  p_amqp_set_user(&bgp_daemon_msglog_amqp_host, config.bgp_daemon_msglog_amqp_user);
  p_amqp_set_passwd(&bgp_daemon_msglog_amqp_host, config.bgp_daemon_msglog_amqp_passwd);
  p_amqp_set_exchange(&bgp_daemon_msglog_amqp_host, config.bgp_daemon_msglog_amqp_exchange);
  p_amqp_set_exchange_type(&bgp_daemon_msglog_amqp_host, config.bgp_daemon_msglog_amqp_exchange_type);
  p_amqp_set_host(&bgp_daemon_msglog_amqp_host, config.bgp_daemon_msglog_amqp_host);
  p_amqp_set_vhost(&bgp_daemon_msglog_amqp_host, config.bgp_daemon_msglog_amqp_vhost);
  p_amqp_set_persistent_msg(&bgp_daemon_msglog_amqp_host, config.bgp_daemon_msglog_amqp_persistent_msg);
  p_amqp_set_frame_max(&bgp_daemon_msglog_amqp_host, config.bgp_daemon_msglog_amqp_frame_max);
  p_amqp_set_content_type_json(&bgp_daemon_msglog_amqp_host);
  p_amqp_set_heartbeat_interval(&bgp_daemon_msglog_amqp_host, config.bgp_daemon_msglog_amqp_heartbeat_interval);
  P_broker_timers_set_retry_interval(&bgp_daemon_msglog_amqp_host.btimers, config.bgp_daemon_msglog_amqp_retry);
}
#else
void bgp_daemon_msglog_init_amqp_host()
{
}
#endif

#if defined WITH_RABBITMQ
void bgp_table_dump_init_amqp_host(void *btdah)
{
  struct p_amqp_host *bgp_table_dump_amqp_host = btdah;

  p_amqp_init_host(bgp_table_dump_amqp_host);

  if (!config.bgp_table_dump_amqp_user) config.bgp_table_dump_amqp_user = rabbitmq_user;
  if (!config.bgp_table_dump_amqp_passwd) config.bgp_table_dump_amqp_passwd = rabbitmq_pwd;
  if (!config.bgp_table_dump_amqp_exchange) config.bgp_table_dump_amqp_exchange = default_amqp_exchange;
  if (!config.bgp_table_dump_amqp_exchange_type) config.bgp_table_dump_amqp_exchange_type = default_amqp_exchange_type;
  if (!config.bgp_table_dump_amqp_host) config.bgp_table_dump_amqp_host = default_amqp_host;
  if (!config.bgp_table_dump_amqp_vhost) config.bgp_table_dump_amqp_vhost = default_amqp_vhost;

  p_amqp_set_user(bgp_table_dump_amqp_host, config.bgp_table_dump_amqp_user);
  p_amqp_set_passwd(bgp_table_dump_amqp_host, config.bgp_table_dump_amqp_passwd);
  p_amqp_set_exchange(bgp_table_dump_amqp_host, config.bgp_table_dump_amqp_exchange);
  p_amqp_set_exchange_type(bgp_table_dump_amqp_host, config.bgp_table_dump_amqp_exchange_type);
  p_amqp_set_host(bgp_table_dump_amqp_host, config.bgp_table_dump_amqp_host);
  p_amqp_set_vhost(bgp_table_dump_amqp_host, config.bgp_table_dump_amqp_vhost);
  p_amqp_set_persistent_msg(bgp_table_dump_amqp_host, config.bgp_table_dump_amqp_persistent_msg);
  p_amqp_set_frame_max(bgp_table_dump_amqp_host, config.bgp_table_dump_amqp_frame_max);
  p_amqp_set_content_type_json(bgp_table_dump_amqp_host);
  p_amqp_set_heartbeat_interval(bgp_table_dump_amqp_host, config.bgp_table_dump_amqp_heartbeat_interval);
}
#else
void bgp_table_dump_init_amqp_host(void *btdah)
{
}
#endif

#if defined WITH_KAFKA
int bgp_daemon_msglog_init_kafka_host()
{
  int ret;

  p_kafka_init_host(&bgp_daemon_msglog_kafka_host, config.bgp_daemon_msglog_kafka_config_file);
  ret = p_kafka_connect_to_produce(&bgp_daemon_msglog_kafka_host);

  if (!config.bgp_daemon_msglog_kafka_broker_host) config.bgp_daemon_msglog_kafka_broker_host = default_kafka_broker_host;
  if (!config.bgp_daemon_msglog_kafka_broker_port) config.bgp_daemon_msglog_kafka_broker_port = default_kafka_broker_port;
  if (!config.bgp_daemon_msglog_kafka_retry) config.bgp_daemon_msglog_kafka_retry = PM_KAFKA_DEFAULT_RETRY;

  p_kafka_set_broker(&bgp_daemon_msglog_kafka_host, config.bgp_daemon_msglog_kafka_broker_host, config.bgp_daemon_msglog_kafka_broker_port);
  p_kafka_set_topic(&bgp_daemon_msglog_kafka_host, config.bgp_daemon_msglog_kafka_topic);
  p_kafka_set_partition(&bgp_daemon_msglog_kafka_host, config.bgp_daemon_msglog_kafka_partition);
  p_kafka_set_key(&bgp_daemon_msglog_kafka_host, config.bgp_daemon_msglog_kafka_partition_key, config.bgp_daemon_msglog_kafka_partition_keylen);
  p_kafka_set_content_type(&bgp_daemon_msglog_kafka_host, PM_KAFKA_CNT_TYPE_STR);
  P_broker_timers_set_retry_interval(&bgp_daemon_msglog_kafka_host.btimers, config.bgp_daemon_msglog_kafka_retry);
#ifdef WITH_SERDES
  P_broker_timers_set_retry_interval(&bgp_daemon_msglog_kafka_host.sd_schema_timers, config.bgp_daemon_msglog_kafka_retry);
#endif

  return ret;
}
#else
int bgp_daemon_msglog_init_kafka_host()
{
  return ERR;
}
#endif

#if defined WITH_KAFKA
int bgp_table_dump_init_kafka_host(void *btdkh)
{
  struct p_kafka_host *bgp_table_dump_kafka_host = btdkh;
  int ret;

  p_kafka_init_host(bgp_table_dump_kafka_host, config.bgp_table_dump_kafka_config_file);
  ret = p_kafka_connect_to_produce(bgp_table_dump_kafka_host);

  if (!config.bgp_table_dump_kafka_broker_host) config.bgp_table_dump_kafka_broker_host = default_kafka_broker_host;
  if (!config.bgp_table_dump_kafka_broker_port) config.bgp_table_dump_kafka_broker_port = default_kafka_broker_port;

  p_kafka_set_broker(bgp_table_dump_kafka_host, config.bgp_table_dump_kafka_broker_host, config.bgp_table_dump_kafka_broker_port);
  p_kafka_set_topic(bgp_table_dump_kafka_host, config.bgp_table_dump_kafka_topic);
  p_kafka_set_partition(bgp_table_dump_kafka_host, config.bgp_table_dump_kafka_partition);
  p_kafka_set_key(bgp_table_dump_kafka_host, config.bgp_table_dump_kafka_partition_key, config.bgp_table_dump_kafka_partition_keylen);
  p_kafka_set_content_type(bgp_table_dump_kafka_host, PM_KAFKA_CNT_TYPE_STR);

  return ret;
}
#else
int bgp_table_dump_init_kafka_host(void *btdkh)
{
  return ERR;
}
#endif

#if defined WITH_AVRO
avro_schema_t p_avro_schema_build_bgp(int log_type, char *schema_name)
{
  avro_schema_t schema = NULL;
  avro_schema_t optlong_s = avro_schema_union();
  avro_schema_t optstr_s = avro_schema_union();
  avro_schema_t optint_s = avro_schema_union();

  if (log_type != BGP_LOGDUMP_ET_LOG && log_type != BGP_LOGDUMP_ET_DUMP) return NULL;

  p_avro_schema_init_bgp(&schema, &optlong_s, &optstr_s, &optint_s, FUNC_TYPE_BGP, schema_name);
  p_avro_schema_build_bgp_common(&schema, &optlong_s, &optstr_s, &optint_s, log_type); 

  avro_schema_record_field_append(schema, "peer_ip_src", avro_schema_string());
  avro_schema_record_field_append(schema, "peer_tcp_port", optint_s);

  if (config.tmp_bgp_lookup_compare_ports) {
    avro_schema_record_field_append(schema, "peer_id", avro_schema_string());
  }

  p_avro_schema_build_bgp_route(&schema, &optlong_s, &optstr_s, &optint_s);

  avro_schema_decref(optlong_s);
  avro_schema_decref(optstr_s);
  avro_schema_decref(optint_s);

  return schema;
}

avro_schema_t p_avro_schema_build_bgp_log_initclose(int log_type, char *schema_name)
{
  avro_schema_t schema = NULL;
  avro_schema_t optlong_s = avro_schema_union();
  avro_schema_t optstr_s = avro_schema_union();
  avro_schema_t optint_s = avro_schema_union();

  if (log_type != BGP_LOGDUMP_ET_LOG) return NULL;

  p_avro_schema_init_bgp(&schema, &optlong_s, &optstr_s, &optint_s, FUNC_TYPE_BGP, schema_name);

  /* prevent log_type from being added to Avro schema */
  log_type = BGP_LOGDUMP_ET_NONE;
  p_avro_schema_build_bgp_common(&schema, &optlong_s, &optstr_s, &optint_s, log_type); 
  log_type = BGP_LOGDUMP_ET_LOG;

  avro_schema_record_field_append(schema, "peer_ip_src", avro_schema_string());
  avro_schema_record_field_append(schema, "peer_tcp_port", optint_s);

  avro_schema_decref(optlong_s);
  avro_schema_decref(optstr_s);
  avro_schema_decref(optint_s);

  return schema;
}

avro_schema_t p_avro_schema_build_bgp_dump_init(int log_type, char *schema_name)
{
  avro_schema_t schema = NULL;
  avro_schema_t optlong_s = avro_schema_union();
  avro_schema_t optstr_s = avro_schema_union();
  avro_schema_t optint_s = avro_schema_union();

  if (log_type != BGP_LOGDUMP_ET_DUMP) return NULL;

  p_avro_schema_init_bgp(&schema, &optlong_s, &optstr_s, &optint_s, FUNC_TYPE_BGP, schema_name);
  p_avro_schema_build_bgp_common(&schema, &optlong_s, &optstr_s, &optint_s, log_type);

  avro_schema_record_field_append(schema, "peer_ip_src", avro_schema_string());
  avro_schema_record_field_append(schema, "peer_tcp_port", optint_s);
  avro_schema_record_field_append(schema, "dump_period", avro_schema_long());

  avro_schema_decref(optlong_s);
  avro_schema_decref(optstr_s);
  avro_schema_decref(optint_s);

  return schema;
}

avro_schema_t p_avro_schema_build_bgp_dump_close(int log_type, char *schema_name)
{
  avro_schema_t schema = NULL;
  avro_schema_t optlong_s = avro_schema_union();
  avro_schema_t optstr_s = avro_schema_union();
  avro_schema_t optint_s = avro_schema_union();

  if (log_type != BGP_LOGDUMP_ET_DUMP) return NULL;

  p_avro_schema_init_bgp(&schema, &optlong_s, &optstr_s, &optint_s, FUNC_TYPE_BGP, schema_name);
  p_avro_schema_build_bgp_common(&schema, &optlong_s, &optstr_s, &optint_s, log_type);

  avro_schema_record_field_append(schema, "peer_ip_src", avro_schema_string());
  avro_schema_record_field_append(schema, "peer_tcp_port", optint_s);
  avro_schema_record_field_append(schema, "entries", optlong_s);
  avro_schema_record_field_append(schema, "tables", optint_s);

  avro_schema_decref(optlong_s);
  avro_schema_decref(optstr_s);
  avro_schema_decref(optint_s);

  return schema;
}

void p_avro_schema_init_bgp(avro_schema_t *schema, avro_schema_t *optlong_s, avro_schema_t *optstr_s, avro_schema_t *optint_s, int type, char *schema_name)
{
  struct bgp_misc_structs *bms = bgp_select_misc_db(type);

  (*schema) = avro_schema_record(schema_name, NULL);
  Log(LOG_INFO, "INFO ( %s/%s ): p_avro_schema_init_bgp(): building %s schema.\n", config.name, bms->log_str, schema_name);

  avro_schema_union_append((*optlong_s), avro_schema_null());
  avro_schema_union_append((*optlong_s), avro_schema_long());

  avro_schema_union_append((*optstr_s), avro_schema_null());
  avro_schema_union_append((*optstr_s), avro_schema_string());

  avro_schema_union_append((*optint_s), avro_schema_null());
  avro_schema_union_append((*optint_s), avro_schema_int());
}

void p_avro_schema_build_bgp_common(avro_schema_t *schema, avro_schema_t *optlong_s, avro_schema_t *optstr_s, avro_schema_t *optint_s, int log_type)
{
  if (log_type == BGP_LOGDUMP_ET_LOG) {
    avro_schema_record_field_append((*schema), "log_type", avro_schema_string());
  }
  avro_schema_record_field_append((*schema), "seq", avro_schema_long());
  avro_schema_record_field_append((*schema), "timestamp", avro_schema_string());
  avro_schema_record_field_append((*schema), "event_type", avro_schema_string());
  avro_schema_record_field_append((*schema), "writer_id", avro_schema_string());
}

void p_avro_schema_build_bgp_route(avro_schema_t *schema, avro_schema_t *optlong_s, avro_schema_t *optstr_s, avro_schema_t *optint_s)
{
  avro_schema_record_field_append((*schema), "afi", avro_schema_int());
  avro_schema_record_field_append((*schema), "safi", avro_schema_int());
  avro_schema_record_field_append((*schema), "ip_prefix", (*optstr_s));
  avro_schema_record_field_append((*schema), "rd", (*optstr_s));
  avro_schema_record_field_append((*schema), "rd_origin", (*optstr_s));

  avro_schema_record_field_append((*schema), "bgp_nexthop", (*optstr_s));
  avro_schema_record_field_append((*schema), "as_path", (*optstr_s));
  avro_schema_record_field_append((*schema), "as_path_id", (*optlong_s));
  avro_schema_record_field_append((*schema), "comms", (*optstr_s));
  avro_schema_record_field_append((*schema), "ecomms", (*optstr_s));
  avro_schema_record_field_append((*schema), "lcomms", (*optstr_s));
  if (!config.tmp_bgp_daemon_origin_type_int) {
    avro_schema_record_field_append((*schema), "origin", (*optstr_s));
  }
  else {
    avro_schema_record_field_append((*schema), "origin", (*optlong_s));
  }
  avro_schema_record_field_append((*schema), "local_pref", (*optlong_s));
  avro_schema_record_field_append((*schema), "med", (*optlong_s));
  avro_schema_record_field_append((*schema), "aigp", (*optlong_s));
  avro_schema_record_field_append((*schema), "psid_li", (*optlong_s));
  avro_schema_record_field_append((*schema), "label", (*optstr_s));

  if (config.rpki_roas_file || config.rpki_rtr_cache) {
    avro_schema_record_field_append((*schema), "roa", avro_schema_string());
  }
}
#endif
