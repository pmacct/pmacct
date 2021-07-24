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
/* includes */
#include "pmacct.h"
#include "addr.h"
#include "bgp/bgp.h"
#include "bmp.h"
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

int bmp_log_msg(struct bgp_peer *peer, struct bmp_data *bdata, struct pm_list *tlvs, void *log_data, u_int64_t log_seq, char *event_type, int output, int log_type)
{
  struct bgp_misc_structs *bms = bgp_select_misc_db(FUNC_TYPE_BMP);
  int ret = 0, amqp_ret = 0, kafka_ret = 0, etype = BGP_LOGDUMP_ET_NONE;

#if defined (WITH_JANSSON) || defined (WITH_AVRO)
  pid_t writer_pid = getpid();
#endif

  if (!bms || !peer || !peer->log || !bdata || !event_type) return ERR;

  if (!strcmp(event_type, "dump")) etype = BGP_LOGDUMP_ET_DUMP;
  else if (!strcmp(event_type, "log")) etype = BGP_LOGDUMP_ET_LOG;

  if ((config.bmp_daemon_msglog_amqp_routing_key && etype == BGP_LOGDUMP_ET_LOG) ||
      (config.bmp_dump_amqp_routing_key && etype == BGP_LOGDUMP_ET_DUMP)) {
#ifdef WITH_RABBITMQ
    p_amqp_set_routing_key(peer->log->amqp_host, peer->log->filename);
#endif
  }

  if ((config.bmp_daemon_msglog_kafka_topic && etype == BGP_LOGDUMP_ET_LOG) ||
      (config.bmp_dump_kafka_topic && etype == BGP_LOGDUMP_ET_DUMP)) {
#ifdef WITH_KAFKA
    p_kafka_set_topic(peer->log->kafka_host, peer->log->filename);

    if (config.bmp_daemon_msglog_kafka_partition_key && etype == BGP_LOGDUMP_ET_LOG) {
      p_kafka_set_key(peer->log->kafka_host, peer->log->partition_key, strlen(peer->log->partition_key));
    }
#endif
  }

  if (output == PRINT_OUTPUT_JSON) {
#ifdef WITH_JANSSON
    json_t *obj = json_object();
    char tstamp_str[SRVBUFLEN];

    json_object_set_new_nocheck(obj, "event_type", json_string(event_type));

    if (etype == BGP_LOGDUMP_ET_LOG) {
      json_object_set_new_nocheck(obj, "seq", json_integer((json_int_t)log_seq));

      compose_timestamp(tstamp_str, SRVBUFLEN, &bdata->tstamp, TRUE,
			config.timestamps_since_epoch, config.timestamps_rfc3339,
			config.timestamps_utc);
      json_object_set_new_nocheck(obj, "timestamp", json_string(tstamp_str));

      compose_timestamp(tstamp_str, SRVBUFLEN, &bdata->tstamp_arrival, TRUE,
			config.timestamps_since_epoch, config.timestamps_rfc3339,
			config.timestamps_utc);
      json_object_set_new_nocheck(obj, "timestamp_arrival", json_string(tstamp_str));
    }
    else if (etype == BGP_LOGDUMP_ET_DUMP) {
      json_object_set_new_nocheck(obj, "seq", json_integer((json_int_t) bgp_peer_log_seq_get(&bms->log_seq))); 

      json_object_set_new_nocheck(obj, "timestamp", json_string(bms->dump.tstamp_str));

      compose_timestamp(tstamp_str, SRVBUFLEN, &bdata->tstamp, TRUE,
			config.timestamps_since_epoch, config.timestamps_rfc3339,
			config.timestamps_utc);
      json_object_set_new_nocheck(obj, "timestamp_event", json_string(tstamp_str));
    }

    json_object_set_new_nocheck(obj, "bmp_router", json_string(peer->addr_str));

    json_object_set_new_nocheck(obj, "bmp_router_port", json_integer((json_int_t)peer->tcp_port));

    switch (log_type) {
    case BMP_LOG_TYPE_STATS:
      ret = bmp_log_msg_stats(peer, bdata, tlvs, (struct bmp_log_stats *) log_data, event_type, output, obj);
      break;
    case BMP_LOG_TYPE_INIT:
      ret = bmp_log_msg_init(peer, bdata, tlvs, event_type, output, obj);
      break;
    case BMP_LOG_TYPE_TERM:
      ret = bmp_log_msg_term(peer, bdata, tlvs, event_type, output, obj);
      break;
    case BMP_LOG_TYPE_PEER_UP:
      ret = bmp_log_msg_peer_up(peer, bdata, tlvs, (struct bmp_log_peer_up *) log_data, event_type, output, obj);
      break;
    case BMP_LOG_TYPE_PEER_DOWN:
      ret = bmp_log_msg_peer_down(peer, bdata, tlvs, (struct bmp_log_peer_down *) log_data, event_type, output, obj);
      break;
    case BMP_LOG_TYPE_RPAT:
      ret = bmp_log_msg_rpat(peer, bdata, tlvs, (struct bmp_log_rpat *) log_data, event_type, output, obj);
      break;
    default:
      Log(LOG_INFO, "INFO ( %s/%s ): [%s] bmp_log_msg(): unknown message type (%u)\n", config.name, bms->log_str, peer->addr_str, log_type);
      break;
    }

    if ((config.bmp_daemon_msglog_file && etype == BGP_LOGDUMP_ET_LOG) ||
	(config.bmp_dump_file && etype == BGP_LOGDUMP_ET_DUMP))
      write_and_free_json(peer->log->fd, obj);

    if ((config.bmp_daemon_msglog_amqp_routing_key && etype == BGP_LOGDUMP_ET_LOG) ||
	(config.bmp_dump_amqp_routing_key && etype == BGP_LOGDUMP_ET_DUMP)) {
      add_writer_name_and_pid_json(obj, config.proc_name, writer_pid);
#ifdef WITH_RABBITMQ
      amqp_ret = write_and_free_json_amqp(peer->log->amqp_host, obj);
      p_amqp_unset_routing_key(peer->log->amqp_host);
#endif
    }

    if ((config.bmp_daemon_msglog_kafka_topic && etype == BGP_LOGDUMP_ET_LOG) ||
        (config.bmp_dump_kafka_topic && etype == BGP_LOGDUMP_ET_DUMP)) {
      add_writer_name_and_pid_json(obj, config.proc_name, writer_pid);
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
    void *p_avro_local_buf = NULL;

    char wid[SHORTSHORTBUFLEN], tstamp_str[SRVBUFLEN];

    p_avro_writer = avro_writer_memory(bms->avro_buf, LARGEBUFLEN);

    if (etype == BGP_LOGDUMP_ET_LOG) {
      p_avro_iface = avro_generic_class_from_schema(bms->msglog_avro_schema[log_type]);
    }
    else if (etype == BGP_LOGDUMP_ET_DUMP) {
      p_avro_iface = avro_generic_class_from_schema(bms->dump_avro_schema[log_type]);
    }

    pm_avro_check(avro_generic_value_new(p_avro_iface, &p_avro_obj));

    pm_avro_check(avro_value_get_by_name(&p_avro_obj, "event_type", &p_avro_field, NULL));
    pm_avro_check(avro_value_set_string(&p_avro_field, event_type));

    if (etype == BGP_LOGDUMP_ET_LOG) {
      pm_avro_check(avro_value_get_by_name(&p_avro_obj, "seq", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_long(&p_avro_field, log_seq));

      compose_timestamp(tstamp_str, SRVBUFLEN, &bdata->tstamp, TRUE,
                        config.timestamps_since_epoch, config.timestamps_rfc3339,
                        config.timestamps_utc);
      pm_avro_check(avro_value_get_by_name(&p_avro_obj, "timestamp", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_string(&p_avro_field, tstamp_str));

      compose_timestamp(tstamp_str, SRVBUFLEN, &bdata->tstamp_arrival, TRUE,
			config.timestamps_since_epoch, config.timestamps_rfc3339,
			config.timestamps_utc);
      pm_avro_check(avro_value_get_by_name(&p_avro_obj, "timestamp_arrival", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, TRUE, &p_avro_branch));
      pm_avro_check(avro_value_set_string(&p_avro_branch, tstamp_str));

      pm_avro_check(avro_value_get_by_name(&p_avro_obj, "timestamp_event", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, FALSE, &p_avro_branch));
    }
    else if (etype == BGP_LOGDUMP_ET_DUMP) {
      pm_avro_check(avro_value_get_by_name(&p_avro_obj, "seq", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_long(&p_avro_field, bgp_peer_log_seq_get(&bms->log_seq)));

      pm_avro_check(avro_value_get_by_name(&p_avro_obj, "timestamp", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_string(&p_avro_field, bms->dump.tstamp_str));

      pm_avro_check(avro_value_get_by_name(&p_avro_obj, "timestamp_arrival", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, FALSE, &p_avro_branch));

      compose_timestamp(tstamp_str, SRVBUFLEN, &bdata->tstamp, TRUE,
                        config.timestamps_since_epoch, config.timestamps_rfc3339,
                        config.timestamps_utc);
      pm_avro_check(avro_value_get_by_name(&p_avro_obj, "timestamp_event", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, TRUE, &p_avro_branch));
      pm_avro_check(avro_value_set_string(&p_avro_branch, tstamp_str));
    }

    pm_avro_check(avro_value_get_by_name(&p_avro_obj, "bmp_router", &p_avro_field, NULL));
    pm_avro_check(avro_value_set_string(&p_avro_field, peer->addr_str));

    if (bms->peer_port_str) {
      pm_avro_check(avro_value_get_by_name(&p_avro_obj, "bmp_router_port", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, TRUE, &p_avro_branch));
      pm_avro_check(avro_value_set_int(&p_avro_branch, peer->tcp_port));
    }
    else {
      pm_avro_check(avro_value_get_by_name(&p_avro_obj, "bmp_router_port", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, FALSE, &p_avro_branch));
    }

    switch (log_type) {
    case BMP_LOG_TYPE_STATS:
      ret = bmp_log_msg_stats(peer, bdata, tlvs, (struct bmp_log_stats *) log_data, event_type, output, &p_avro_obj);
      break;
    case BMP_LOG_TYPE_INIT:
      ret = bmp_log_msg_init(peer, bdata, tlvs, event_type, output, &p_avro_obj);
      break;
    case BMP_LOG_TYPE_TERM:
      ret = bmp_log_msg_term(peer, bdata, tlvs, event_type, output, &p_avro_obj);
      break;
    case BMP_LOG_TYPE_PEER_UP:
      ret = bmp_log_msg_peer_up(peer, bdata, tlvs, (struct bmp_log_peer_up *) log_data, event_type, output, &p_avro_obj);
      break;
    case BMP_LOG_TYPE_PEER_DOWN:
      ret = bmp_log_msg_peer_down(peer, bdata, tlvs, (struct bmp_log_peer_down *) log_data, event_type, output, &p_avro_obj);
      break;
    case BMP_LOG_TYPE_RPAT:
      ret = bmp_log_msg_rpat(peer, bdata, tlvs, (struct bmp_log_rpat *) log_data, event_type, output, &p_avro_obj);
      break;
    default:
      Log(LOG_INFO, "INFO ( %s/%s ): [%s] bmp_log_msg(): unknown message type (%u)\n", config.name, bms->log_str, peer->addr_str, log_type);
      break;
    }

    pm_avro_check(avro_value_get_by_name(&p_avro_obj, "writer_id", &p_avro_field, NULL));
    snprintf(wid, SHORTSHORTBUFLEN, "%s/%u", config.proc_name, writer_pid);
    pm_avro_check(avro_value_set_string(&p_avro_field, wid));

    if (((config.bmp_daemon_msglog_file && etype == BGP_LOGDUMP_ET_LOG) ||
         (config.bmp_dump_file && etype == BGP_LOGDUMP_ET_DUMP) ||
         (config.bmp_daemon_msglog_file && etype == BGP_LOGDUMP_ET_LOG) ||
         (config.bmp_dump_amqp_routing_key && etype == BGP_LOGDUMP_ET_DUMP) ||
         (config.bmp_daemon_msglog_kafka_topic && etype == BGP_LOGDUMP_ET_LOG && !bms->msglog_kafka_avro_schema_registry) ||
         (config.bmp_dump_kafka_topic && etype == BGP_LOGDUMP_ET_DUMP && !bms->dump_kafka_avro_schema_registry)) &&
	(output == PRINT_OUTPUT_AVRO_BIN)) {
      avro_value_sizeof(&p_avro_obj, &p_avro_obj_len);
      assert(p_avro_obj_len < LARGEBUFLEN);

      if (avro_value_write(p_avro_writer, &p_avro_obj)) {
        Log(LOG_ERR, "ERROR ( %s/%s ): bmp_log_msg(): avro_value_write() failed: %s\n", config.name, bms->log_str, avro_strerror());
        exit_gracefully(1);
      }

      p_avro_len = avro_writer_tell(p_avro_writer);
      p_avro_local_buf = bms->avro_buf;
    }

    if ((config.bmp_daemon_msglog_file && etype == BGP_LOGDUMP_ET_LOG) ||
        (config.bmp_dump_file && etype == BGP_LOGDUMP_ET_DUMP)) {
      if (output == PRINT_OUTPUT_AVRO_BIN) {
	write_file_binary(peer->log->fd, p_avro_local_buf, p_avro_len);
      }
      else if (output == PRINT_OUTPUT_AVRO_JSON) {
	write_avro_json_record_to_file(peer->log->fd, p_avro_obj);
      }
    }

    if ((config.bmp_daemon_msglog_amqp_routing_key && etype == BGP_LOGDUMP_ET_LOG) ||
        (config.bmp_dump_amqp_routing_key && etype == BGP_LOGDUMP_ET_DUMP)) {
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

    if ((config.bmp_daemon_msglog_kafka_topic && etype == BGP_LOGDUMP_ET_LOG) ||
        (config.bmp_dump_kafka_topic && etype == BGP_LOGDUMP_ET_DUMP)) {
#ifdef WITH_KAFKA
      if ((bms->msglog_kafka_avro_schema_registry && etype == BGP_LOGDUMP_ET_LOG) ||
          (bms->dump_kafka_avro_schema_registry && etype == BGP_LOGDUMP_ET_DUMP)) {
#ifdef WITH_SERDES
	struct p_kafka_host *kafka_host = (struct p_kafka_host *) peer->log->kafka_host;

	if (kafka_host->sd_schema[log_type]) {
	  if (serdes_schema_serialize_avro(kafka_host->sd_schema[log_type], &p_avro_obj, &p_avro_local_buf, &p_avro_len,
					 kafka_host->errstr, sizeof(kafka_host->errstr))) {
	    Log(LOG_ERR, "ERROR ( %s/%s ): bmp_log_msg(): serdes_schema_serialize_avro() failed for %s: %s\n",
	        config.name, bms->log_str, bmp_msg_types[log_type], kafka_host->errstr);
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

int bmp_log_msg_stats(struct bgp_peer *peer, struct bmp_data *bdata, struct pm_list *tlvs, struct bmp_log_stats *blstats, char *event_type, int output, void *vobj)
{
  int ret = 0;

  if (!peer || !bdata || !blstats || !vobj) return ERR;

  if (output == PRINT_OUTPUT_JSON) {
#ifdef WITH_JANSSON
    json_t *obj = (json_t *) vobj;
    char bmp_msg_type[] = "stats";
    char ip_address[INET6_ADDRSTRLEN];

    json_object_set_new_nocheck(obj, "bmp_msg_type", json_string(bmp_msg_type));

    addr_to_str(ip_address, &bdata->peer_ip);
    json_object_set_new_nocheck(obj, "peer_ip", json_string(ip_address));

    json_object_set_new_nocheck(obj, "peer_asn", json_integer((json_int_t)bdata->peer_asn));
    json_object_set_new_nocheck(obj, "peer_type", json_integer((json_int_t)bdata->chars.peer_type));

    if (!bdata->chars.is_loc && !bdata->chars.is_out) {
      json_object_set_new_nocheck(obj, "is_post", json_integer((json_int_t)bdata->chars.is_post));
      json_object_set_new_nocheck(obj, "is_in", json_integer(1));
    }
    else if (bdata->chars.is_loc) {
      json_object_set_new_nocheck(obj, "is_filtered", json_integer((json_int_t)bdata->chars.is_filtered));
      json_object_set_new_nocheck(obj, "is_loc", json_integer((json_int_t)bdata->chars.is_loc));
    }
    else if (bdata->chars.is_out) {
      json_object_set_new_nocheck(obj, "is_post", json_integer((json_int_t)bdata->chars.is_post));
      json_object_set_new_nocheck(obj, "is_out", json_integer((json_int_t)bdata->chars.is_out));
    }

    if (!is_empty_256b(&bdata->chars.rd, sizeof(bdata->chars.rd))) {
      char rd_str[SHORTSHORTBUFLEN];

      bgp_rd2str(rd_str, &bdata->chars.rd);
      json_object_set_new_nocheck(obj, "rd", json_string(rd_str));
      json_object_set_new_nocheck(obj, "rd_origin", json_string(bgp_rd_origin_print(bdata->chars.rd.type)));
    }

    json_object_set_new_nocheck(obj, "counter_type", json_integer((json_int_t)blstats->cnt_type));

    if (blstats->cnt_type <= BMP_STATS_MAX) {
      json_object_set_new_nocheck(obj, "counter_type_str", json_string(bmp_stats_cnt_types[blstats->cnt_type]));
    }
    else {
      json_object_set_new_nocheck(obj, "counter_type_str", json_string("Unknown"));
    }

    if (blstats->cnt_type == BMP_STATS_TYPE9 || blstats->cnt_type == BMP_STATS_TYPE10) {
      json_object_set_new_nocheck(obj, "afi", json_integer((json_int_t)blstats->cnt_afi));
      json_object_set_new_nocheck(obj, "safi", json_integer((json_int_t)blstats->cnt_safi));
    }

    if (!tlvs || !pm_listcount(tlvs)) {
      json_object_set_new_nocheck(obj, "counter_value", json_integer((json_int_t)blstats->cnt_data));
    }
    else {
      char *value = NULL;
      struct pm_listnode *node = NULL;
      struct bmp_log_tlv *tlv = NULL;

      for (PM_ALL_LIST_ELEMENTS_RO(tlvs, node, tlv)) {
	value = bmp_tlv_value_print(tlv, bmp_stats_info_types, BMP_STATS_INFO_MAX);

	if (value) {
	  json_object_set_new_nocheck(obj, "counter_value", json_string(value));
	  free(value);
	}
	else {
	  json_object_set_new_nocheck(obj, "counter_value", json_null());
	}
      }
    }
#endif
  }
  else if ((output == PRINT_OUTPUT_AVRO_BIN) || 
	   (output == PRINT_OUTPUT_AVRO_JSON)) {
#ifdef WITH_AVRO
    avro_value_t *obj = (avro_value_t *) vobj, p_avro_field, p_avro_branch;
    char bmp_msg_type[] = "stats";
    char ip_address[INET6_ADDRSTRLEN];

    pm_avro_check(avro_value_get_by_name(obj, "bmp_msg_type", &p_avro_field, NULL));
    pm_avro_check(avro_value_set_string(&p_avro_field, bmp_msg_type));

    addr_to_str(ip_address, &bdata->peer_ip);
    pm_avro_check(avro_value_get_by_name(obj, "peer_ip", &p_avro_field, NULL));
    pm_avro_check(avro_value_set_string(&p_avro_field, ip_address));

    pm_avro_check(avro_value_get_by_name(obj, "peer_asn", &p_avro_field, NULL));
    pm_avro_check(avro_value_set_long(&p_avro_field, bdata->peer_asn));

    pm_avro_check(avro_value_get_by_name(obj, "peer_type", &p_avro_field, NULL));
    pm_avro_check(avro_value_set_int(&p_avro_field, bdata->chars.peer_type));

    if (!bdata->chars.is_loc && !bdata->chars.is_out) {
      pm_avro_check(avro_value_get_by_name(obj, "is_in", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, TRUE, &p_avro_branch));
      pm_avro_check(avro_value_set_int(&p_avro_branch, 1));

      pm_avro_check(avro_value_get_by_name(obj, "is_post", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, TRUE, &p_avro_branch));
      pm_avro_check(avro_value_set_int(&p_avro_branch, bdata->chars.is_post));

      pm_avro_check(avro_value_get_by_name(obj, "is_filtered", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, FALSE, &p_avro_branch));

      pm_avro_check(avro_value_get_by_name(obj, "is_loc", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, FALSE, &p_avro_branch));

      pm_avro_check(avro_value_get_by_name(obj, "is_out", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, FALSE, &p_avro_branch));
    }
    else if (bdata->chars.is_loc) {
      pm_avro_check(avro_value_get_by_name(obj, "is_in", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, FALSE, &p_avro_branch));

      pm_avro_check(avro_value_get_by_name(obj, "is_filtered", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, TRUE, &p_avro_branch));
      pm_avro_check(avro_value_set_int(&p_avro_branch, bdata->chars.is_filtered));

      pm_avro_check(avro_value_get_by_name(obj, "is_loc", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, TRUE, &p_avro_branch));
      pm_avro_check(avro_value_set_int(&p_avro_branch, bdata->chars.is_loc));

      pm_avro_check(avro_value_get_by_name(obj, "is_post", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, FALSE, &p_avro_branch));

      pm_avro_check(avro_value_get_by_name(obj, "is_out", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, FALSE, &p_avro_branch));
    }
    else if (bdata->chars.is_out) {
      pm_avro_check(avro_value_get_by_name(obj, "is_in", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, FALSE, &p_avro_branch));

      pm_avro_check(avro_value_get_by_name(obj, "is_filtered", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, FALSE, &p_avro_branch));

      pm_avro_check(avro_value_get_by_name(obj, "is_loc", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, FALSE, &p_avro_branch));

      pm_avro_check(avro_value_get_by_name(obj, "is_post", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, TRUE, &p_avro_branch));
      pm_avro_check(avro_value_set_int(&p_avro_branch, bdata->chars.is_post));

      pm_avro_check(avro_value_get_by_name(obj, "is_out", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, TRUE, &p_avro_branch));
      pm_avro_check(avro_value_set_int(&p_avro_branch, bdata->chars.is_out));
    }

    if (!is_empty_256b(&bdata->chars.rd, sizeof(bdata->chars.rd))) {
      char rd_str[SHORTSHORTBUFLEN];

      bgp_rd2str(rd_str, &bdata->chars.rd);
      pm_avro_check(avro_value_get_by_name(obj, "rd", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, TRUE, &p_avro_branch));
      pm_avro_check(avro_value_set_string(&p_avro_branch, rd_str));

      pm_avro_check(avro_value_get_by_name(obj, "rd_origin", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, TRUE, &p_avro_branch));
      pm_avro_check(avro_value_set_string(&p_avro_branch, bgp_rd_origin_print(bdata->chars.rd.type)));
    }
    else {
      pm_avro_check(avro_value_get_by_name(obj, "rd", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, FALSE, &p_avro_branch));

      pm_avro_check(avro_value_get_by_name(obj, "rd_origin", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, FALSE, &p_avro_branch));
    }

    pm_avro_check(avro_value_get_by_name(obj, "counter_type", &p_avro_field, NULL));
    pm_avro_check(avro_value_set_int(&p_avro_field, blstats->cnt_type));

    if (blstats->cnt_type <= BMP_STATS_MAX) {
      pm_avro_check(avro_value_get_by_name(obj, "counter_type_str", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_string(&p_avro_field, bmp_stats_cnt_types[blstats->cnt_type]));
    }
    else {
      pm_avro_check(avro_value_get_by_name(obj, "counter_type_str", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_string(&p_avro_field, "Unknown"));
    }

    if (blstats->cnt_type == BMP_STATS_TYPE9 || blstats->cnt_type == BMP_STATS_TYPE10) {
      pm_avro_check(avro_value_get_by_name(obj, "afi", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, TRUE, &p_avro_branch));
      pm_avro_check(avro_value_set_int(&p_avro_branch, blstats->cnt_afi));

      pm_avro_check(avro_value_get_by_name(obj, "safi", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, TRUE, &p_avro_branch));
      pm_avro_check(avro_value_set_int(&p_avro_branch, blstats->cnt_safi));
    }
    else {
      pm_avro_check(avro_value_get_by_name(obj, "afi", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, FALSE, &p_avro_branch));

      pm_avro_check(avro_value_get_by_name(obj, "safi", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, FALSE, &p_avro_branch));
    }

    pm_avro_check(avro_value_get_by_name(obj, "counter_value", &p_avro_field, NULL));
    pm_avro_check(avro_value_set_long(&p_avro_field, blstats->cnt_data));
#endif
  }

  return ret;
}

int bmp_log_msg_init(struct bgp_peer *peer, struct bmp_data *bdata, struct pm_list *tlvs, char *event_type, int output, void *vobj)
{
  int ret = 0;

  if (!peer || !vobj) return ERR;

  if (output == PRINT_OUTPUT_JSON) {
#ifdef WITH_JANSSON
    char bmp_msg_type[] = "init";
    json_t *obj = (json_t *) vobj;

    json_object_set_new_nocheck(obj, "bmp_msg_type", json_string(bmp_msg_type));

    if (tlvs) {
      struct pm_listnode *node = NULL;
      struct bmp_log_tlv *tlv = NULL;
      
      for (PM_ALL_LIST_ELEMENTS_RO(tlvs, node, tlv)) {
	char *type = NULL, *value = NULL;

	switch (tlv->pen) {
	case BMP_TLV_PEN_STD:
	  type = bmp_tlv_type_print(tlv, "bmp_init_info", bmp_init_info_types, BMP_INIT_INFO_MAX);
	  value = bmp_tlv_value_print(tlv, bmp_init_info_types, BMP_INIT_INFO_MAX);
	  break;
	default:
	  type = bmp_tlv_type_print(tlv, "bmp_init_info", NULL, -1);
	  value = bmp_tlv_value_print(tlv, NULL, -1);
	  break;
	}

	if (type) {
	  if (value) {
	    json_object_set_new_nocheck(obj, type, json_string(value));
	    free(value);
	  }
  	  else {
	    json_object_set_new_nocheck(obj, type, json_null());
	  }

	  free(type);
	}
      }
    }
#endif
  }
  else if ((output == PRINT_OUTPUT_AVRO_BIN) || 
	   (output == PRINT_OUTPUT_AVRO_JSON)) {
#ifdef WITH_AVRO
    int idx = 0, bmp_init_tlvs[BMP_INIT_INFO_MAX + 1];
    avro_value_t *obj = (avro_value_t *) vobj, p_avro_field, p_avro_branch;
    char bmp_msg_type[] = "init";

    pm_avro_check(avro_value_get_by_name(obj, "bmp_msg_type", &p_avro_field, NULL));
    pm_avro_check(avro_value_set_string(&p_avro_field, bmp_msg_type));

    memset(&bmp_init_tlvs, 0, sizeof(bmp_init_tlvs));

    if (tlvs) {
      char *type = NULL, *value = NULL;
      struct pm_listnode *node = NULL;
      struct bmp_log_tlv *tlv = NULL;

      /* No PEN defined so far so we short-circuit to standard elements */
      for (PM_ALL_LIST_ELEMENTS_RO(tlvs, node, tlv)) {
	if (tlv->type <= BMP_INIT_INFO_MAX) {
	  type = bmp_tlv_type_print(tlv, "bmp_init_info", bmp_init_info_types, BMP_INIT_INFO_MAX);
	  value = bmp_tlv_value_print(tlv, bmp_init_info_types, BMP_INIT_INFO_MAX);

	  if (type) {
	    pm_avro_check(avro_value_get_by_name(obj, type, &p_avro_field, NULL));
	    pm_avro_check(avro_value_set_branch(&p_avro_field, TRUE, &p_avro_branch));

	    if (value) {
	      pm_avro_check(avro_value_set_string(&p_avro_branch, value));
	      free(value);
	    }
	    else {
	      pm_avro_check(avro_value_set_null(&p_avro_branch));
	    }

	    free(type);
	  }

	  bmp_init_tlvs[tlv->type] = TRUE;
	}
      }
    }

    for (idx = 0; idx <= BMP_INIT_INFO_MAX; idx++) {
      struct bmp_log_tlv dummy_tlv;
      char *type;

      memset(&dummy_tlv, 0, sizeof(dummy_tlv));
      dummy_tlv.type = idx;

      if (!bmp_init_tlvs[idx]) {
	type = bmp_tlv_type_print(&dummy_tlv, "bmp_init_info", bmp_init_info_types, BMP_INIT_INFO_MAX);
	pm_avro_check(avro_value_get_by_name(obj, type, &p_avro_field, NULL));
	pm_avro_check(avro_value_set_branch(&p_avro_field, FALSE, &p_avro_branch));
      }
    }
#endif
  }

  return ret;
}

int bmp_log_msg_term(struct bgp_peer *peer, struct bmp_data *bdata, struct pm_list *tlvs, char *event_type, int output, void *vobj)
{
  int ret = 0;

  if (!peer || !vobj) return ERR;

  if (output == PRINT_OUTPUT_JSON) {
#ifdef WITH_JANSSON
    char bmp_msg_type[] = "term";
    json_t *obj = (json_t *) vobj;

    json_object_set_new_nocheck(obj, "bmp_msg_type", json_string(bmp_msg_type));

    if (tlvs) {
      struct pm_listnode *node = NULL;
      struct bmp_log_tlv *tlv = NULL;

      for (PM_ALL_LIST_ELEMENTS_RO(tlvs, node, tlv)) {
        char *type = NULL, *value = NULL;

	switch (tlv->pen) {
	case BMP_TLV_PEN_STD:
	  type = bmp_tlv_type_print(tlv, "bmp_term_info", bmp_term_info_types, BMP_TERM_INFO_MAX);

	  if (tlv->type == BMP_TERM_INFO_REASON && tlv->len == 2) {
	    char *value_tmp = NULL;
	    u_int16_t reas_type = 0;

	    value_tmp = bmp_tlv_value_print(tlv, bmp_term_info_types, BMP_TERM_INFO_MAX);
	    if (value_tmp) {
	      reas_type = atoi(value_tmp);
	      free(value_tmp);
	    }

	    value = bmp_term_reason_print(reas_type);
	  }
	  else {
	    value = bmp_tlv_value_print(tlv, bmp_term_info_types, BMP_TERM_INFO_MAX);
	  }

	  break;
	default:
	  type = bmp_tlv_type_print(tlv, "bmp_term_info", NULL, -1);
	  value = bmp_tlv_value_print(tlv, NULL, -1);
	  break;
        }

	if (type) {
	  if (value) {
	    json_object_set_new_nocheck(obj, type, json_string(value));
	    free(value);
	  }
	  else {
	    json_object_set_new_nocheck(obj, type, json_null());
	  }

	  free(type);
	}
      }
    }
#endif
  }
  else if ((output == PRINT_OUTPUT_AVRO_BIN) || 
	   (output == PRINT_OUTPUT_AVRO_JSON)) {
#ifdef WITH_AVRO
    int idx = 0, bmp_term_tlvs[BMP_TERM_INFO_MAX + 1];
    avro_value_t *obj = (avro_value_t *) vobj, p_avro_field, p_avro_branch;
    char bmp_msg_type[] = "term";

    pm_avro_check(avro_value_get_by_name(obj, "bmp_msg_type", &p_avro_field, NULL));
    pm_avro_check(avro_value_set_string(&p_avro_field, bmp_msg_type));

    memset(&bmp_term_tlvs, 0, sizeof(bmp_term_tlvs));

    if (tlvs) {
      char *type = NULL, *value = NULL;
      struct pm_listnode *node = NULL;
      struct bmp_log_tlv *tlv = NULL;

      /* No PEN defined so far so we short-circuit to standard elements */
      for (PM_ALL_LIST_ELEMENTS_RO(tlvs, node, tlv)) {
	if (tlv->type <= BMP_TERM_INFO_MAX) {
	  type = bmp_tlv_type_print(tlv, "bmp_term_info", bmp_term_info_types, BMP_TERM_INFO_MAX);

	  if (tlv->type == BMP_TERM_INFO_REASON && tlv->len == 2) {
	    u_int16_t reas_type;

	    memcpy(&reas_type, tlv->val, 2);
	    reas_type = ntohs(reas_type);
	    value = bmp_term_reason_print(reas_type);
	  }
	  else {
	    value = null_terminate(tlv->val, tlv->len);
	  }

	  if (type) {
	    pm_avro_check(avro_value_get_by_name(obj, type, &p_avro_field, NULL));
	    pm_avro_check(avro_value_set_branch(&p_avro_field, TRUE, &p_avro_branch));

	    if (value) {
	      pm_avro_check(avro_value_set_string(&p_avro_branch, value));
	      free(value);
	    }
	    else {
	      pm_avro_check(avro_value_set_null(&p_avro_branch));
	    }

	    free(type);
	  }

	  bmp_term_tlvs[tlv->type] = TRUE;
        }
      }
    }

    for (idx = 0; idx <= BMP_TERM_INFO_MAX; idx++) {
      struct bmp_log_tlv dummy_tlv;
      char *type;

      memset(&dummy_tlv, 0, sizeof(dummy_tlv));
      dummy_tlv.type = idx;

      if (!bmp_term_tlvs[idx]) {
	type = bmp_tlv_type_print(&dummy_tlv, "bmp_term_info", bmp_term_info_types, BMP_TERM_INFO_MAX);
	pm_avro_check(avro_value_get_by_name(obj, type, &p_avro_field, NULL));
	pm_avro_check(avro_value_set_branch(&p_avro_field, FALSE, &p_avro_branch));
      }
    }
#endif
  }

  return ret;
}

int bmp_log_msg_peer_up(struct bgp_peer *peer, struct bmp_data *bdata, struct pm_list *tlvs, struct bmp_log_peer_up *blpu, char *event_type, int output, void *vobj)
{
  int ret = 0;

  if (!peer || !bdata || !blpu || !vobj) return ERR;

  if (output == PRINT_OUTPUT_JSON) {
#ifdef WITH_JANSSON
    char bmp_msg_type[] = "peer_up";
    char ip_address[INET6_ADDRSTRLEN];
    json_t *obj = (json_t *) vobj;

    json_object_set_new_nocheck(obj, "bmp_msg_type", json_string(bmp_msg_type));

    addr_to_str(ip_address, &bdata->peer_ip);
    json_object_set_new_nocheck(obj, "peer_ip", json_string(ip_address));

    json_object_set_new_nocheck(obj, "peer_asn", json_integer((json_int_t)bdata->peer_asn));
    json_object_set_new_nocheck(obj, "peer_type", json_integer((json_int_t)bdata->chars.peer_type));

    if (bdata->chars.peer_type <= BMP_PEER_TYPE_MAX) {
      json_object_set_new_nocheck(obj, "peer_type_str", json_string(bmp_peer_types[bdata->chars.peer_type]));
    }

    if (!bdata->chars.is_loc && !bdata->chars.is_out) {
      json_object_set_new_nocheck(obj, "is_post", json_integer((json_int_t)bdata->chars.is_post));
      json_object_set_new_nocheck(obj, "is_in", json_integer(1));
    }
    else if (bdata->chars.is_loc) {
      json_object_set_new_nocheck(obj, "is_filtered", json_integer((json_int_t)bdata->chars.is_filtered));
      json_object_set_new_nocheck(obj, "is_loc", json_integer((json_int_t)bdata->chars.is_loc));
    }
    else if (bdata->chars.is_out) {
      json_object_set_new_nocheck(obj, "is_post", json_integer((json_int_t)bdata->chars.is_post));
      json_object_set_new_nocheck(obj, "is_out", json_integer((json_int_t)bdata->chars.is_out));
    }

    json_object_set_new_nocheck(obj, "bgp_id", json_string(inet_ntoa(bdata->bgp_id.address.ipv4)));
    json_object_set_new_nocheck(obj, "local_port", json_integer((json_int_t)blpu->loc_port));
    json_object_set_new_nocheck(obj, "remote_port", json_integer((json_int_t)blpu->rem_port));

    addr_to_str(ip_address, &blpu->local_ip);
    json_object_set_new_nocheck(obj, "local_ip", json_string(ip_address));

    if (!is_empty_256b(&bdata->chars.rd, sizeof(bdata->chars.rd))) {
      char rd_str[SHORTSHORTBUFLEN];

      bgp_rd2str(rd_str, &bdata->chars.rd);
      json_object_set_new_nocheck(obj, "rd", json_string(rd_str));
      json_object_set_new_nocheck(obj, "rd_origin", json_string(bgp_rd_origin_print(bdata->chars.rd.type)));
    }

    if (tlvs) {
      struct pm_listnode *node = NULL;
      struct bmp_log_tlv *tlv = NULL;

      for (PM_ALL_LIST_ELEMENTS_RO(tlvs, node, tlv)) {
        char *type = NULL, *value = NULL;

	switch (tlv->pen) {
	case BMP_TLV_PEN_STD:
	  type = bmp_tlv_type_print(tlv, "bmp_peer_up_info", bmp_peer_up_info_types, BMP_PEER_UP_INFO_MAX);
	  value = bmp_tlv_value_print(tlv, bmp_peer_up_info_types, BMP_PEER_UP_INFO_MAX);
	  break;
	default:
	  type = bmp_tlv_type_print(tlv, "bmp_peer_up_info", NULL, -1);
	  value = bmp_tlv_value_print(tlv, NULL, -1);
	  break;
	}

	if (type) {
	  if (value) {
	    json_object_set_new_nocheck(obj, type, json_string(value));
	    free(value);
	  }
	  else {
	    json_object_set_new_nocheck(obj, type, json_null());
	  }

	  free(type);
	}
      }
    }
#endif
  }
  else if ((output == PRINT_OUTPUT_AVRO_BIN) ||
	   (output == PRINT_OUTPUT_AVRO_JSON)) {
#ifdef WITH_AVRO
    int idx = 0, bmp_peer_up_tlvs[BMP_PEER_UP_INFO_MAX + 1];
    avro_value_t *obj = (avro_value_t *) vobj, p_avro_field, p_avro_branch;
    char bmp_msg_type[] = "peer_up";
    char ip_address[INET6_ADDRSTRLEN];

    pm_avro_check(avro_value_get_by_name(obj, "bmp_msg_type", &p_avro_field, NULL));
    pm_avro_check(avro_value_set_string(&p_avro_field, bmp_msg_type));

    addr_to_str(ip_address, &bdata->peer_ip);
    pm_avro_check(avro_value_get_by_name(obj, "peer_ip", &p_avro_field, NULL));
    pm_avro_check(avro_value_set_string(&p_avro_field, ip_address));

    pm_avro_check(avro_value_get_by_name(obj, "peer_asn", &p_avro_field, NULL));
    pm_avro_check(avro_value_set_long(&p_avro_field, bdata->peer_asn));

    pm_avro_check(avro_value_get_by_name(obj, "peer_type", &p_avro_field, NULL));
    pm_avro_check(avro_value_set_int(&p_avro_field, bdata->chars.peer_type));

    if (bdata->chars.peer_type <= BMP_PEER_TYPE_MAX) {
      pm_avro_check(avro_value_get_by_name(obj, "peer_type_str", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, TRUE, &p_avro_branch));
      pm_avro_check(avro_value_set_string(&p_avro_branch, bmp_peer_types[bdata->chars.peer_type]));
    }
    else {
      pm_avro_check(avro_value_get_by_name(obj, "peer_type_str", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, FALSE, &p_avro_branch));
    }

    if (!bdata->chars.is_loc && !bdata->chars.is_out) {
      pm_avro_check(avro_value_get_by_name(obj, "is_in", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, TRUE, &p_avro_branch));
      pm_avro_check(avro_value_set_int(&p_avro_branch, 1));

      pm_avro_check(avro_value_get_by_name(obj, "is_post", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, TRUE, &p_avro_branch));
      pm_avro_check(avro_value_set_int(&p_avro_branch, bdata->chars.is_post));

      pm_avro_check(avro_value_get_by_name(obj, "is_filtered", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, FALSE, &p_avro_branch));

      pm_avro_check(avro_value_get_by_name(obj, "is_loc", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, FALSE, &p_avro_branch));

      pm_avro_check(avro_value_get_by_name(obj, "is_out", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, FALSE, &p_avro_branch));
    }
    else if (bdata->chars.is_loc) {
      pm_avro_check(avro_value_get_by_name(obj, "is_in", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, FALSE, &p_avro_branch));

      pm_avro_check(avro_value_get_by_name(obj, "is_filtered", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, TRUE, &p_avro_branch));
      pm_avro_check(avro_value_set_int(&p_avro_branch, bdata->chars.is_filtered));

      pm_avro_check(avro_value_get_by_name(obj, "is_loc", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, TRUE, &p_avro_branch));
      pm_avro_check(avro_value_set_int(&p_avro_branch, bdata->chars.is_loc));

      pm_avro_check(avro_value_get_by_name(obj, "is_post", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, FALSE, &p_avro_branch));

      pm_avro_check(avro_value_get_by_name(obj, "is_out", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, FALSE, &p_avro_branch));
    }
    else if (bdata->chars.is_out) {
      pm_avro_check(avro_value_get_by_name(obj, "is_in", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, FALSE, &p_avro_branch));

      pm_avro_check(avro_value_get_by_name(obj, "is_filtered", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, FALSE, &p_avro_branch));

      pm_avro_check(avro_value_get_by_name(obj, "is_loc", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, FALSE, &p_avro_branch));

      pm_avro_check(avro_value_get_by_name(obj, "is_post", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, TRUE, &p_avro_branch));
      pm_avro_check(avro_value_set_int(&p_avro_branch, bdata->chars.is_post));

      pm_avro_check(avro_value_get_by_name(obj, "is_out", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, TRUE, &p_avro_branch));
      pm_avro_check(avro_value_set_int(&p_avro_branch, bdata->chars.is_out));
    }

    pm_avro_check(avro_value_get_by_name(obj, "bgp_id", &p_avro_field, NULL));
    pm_avro_check(avro_value_set_string(&p_avro_field, inet_ntoa(bdata->bgp_id.address.ipv4)));

    pm_avro_check(avro_value_get_by_name(obj, "local_port", &p_avro_field, NULL));
    pm_avro_check(avro_value_set_int(&p_avro_field, blpu->loc_port));

    pm_avro_check(avro_value_get_by_name(obj, "remote_port", &p_avro_field, NULL));
    pm_avro_check(avro_value_set_int(&p_avro_field, blpu->rem_port));

    addr_to_str(ip_address, &blpu->local_ip);
    pm_avro_check(avro_value_get_by_name(obj, "local_ip", &p_avro_field, NULL));
    pm_avro_check(avro_value_set_string(&p_avro_field, ip_address));

    if (!is_empty_256b(&bdata->chars.rd, sizeof(bdata->chars.rd))) {
      char rd_str[SHORTSHORTBUFLEN];

      bgp_rd2str(rd_str, &bdata->chars.rd);
      pm_avro_check(avro_value_get_by_name(obj, "rd", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, TRUE, &p_avro_branch));
      pm_avro_check(avro_value_set_string(&p_avro_branch, rd_str));

      pm_avro_check(avro_value_get_by_name(obj, "rd_origin", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, TRUE, &p_avro_branch));
      pm_avro_check(avro_value_set_string(&p_avro_branch, bgp_rd_origin_print(bdata->chars.rd.type)));
    }
    else {
      pm_avro_check(avro_value_get_by_name(obj, "rd", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, FALSE, &p_avro_branch));

      pm_avro_check(avro_value_get_by_name(obj, "rd_origin", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, FALSE, &p_avro_branch));
    }

    memset(&bmp_peer_up_tlvs, 0, sizeof(bmp_peer_up_tlvs));

    if (tlvs) {
      char *type = NULL, *value = NULL;
      struct pm_listnode *node = NULL;
      struct bmp_log_tlv *tlv = NULL;

      /* No PEN defined so far so we short-circuit to standard elements */
      for (PM_ALL_LIST_ELEMENTS_RO(tlvs, node, tlv)) {
	if (tlv->type <= BMP_PEER_UP_INFO_MAX) {
	  type = bmp_tlv_type_print(tlv, "bmp_peer_up_info", bmp_peer_up_info_types, BMP_PEER_UP_INFO_MAX);
	  value = bmp_tlv_value_print(tlv, bmp_peer_up_info_types, BMP_PEER_UP_INFO_MAX);

	  if (type) {
	    pm_avro_check(avro_value_get_by_name(obj, type, &p_avro_field, NULL));
	    pm_avro_check(avro_value_set_branch(&p_avro_field, TRUE, &p_avro_branch));

	    if (value) {
	      pm_avro_check(avro_value_set_string(&p_avro_branch, value));
	      free(value);
	    }
	    else {
	      pm_avro_check(avro_value_set_null(&p_avro_branch));
	    }

	    free(type);
	  }

	  bmp_peer_up_tlvs[tlv->type] = TRUE;
        }
      }
    }

    /* mark missing tlv types */
    for (idx = 0; idx <= BMP_PEER_UP_INFO_MAX; idx++) {
      struct bmp_log_tlv dummy_tlv;
      char *type;

      memset(&dummy_tlv, 0, sizeof(dummy_tlv));
      dummy_tlv.type = idx;

      if (!bmp_peer_up_tlvs[idx]) {
        type = bmp_tlv_type_print(&dummy_tlv, "bmp_peer_up_info", bmp_peer_up_info_types, BMP_PEER_UP_INFO_MAX);
        pm_avro_check(avro_value_get_by_name(obj, type, &p_avro_field, NULL));
        pm_avro_check(avro_value_set_branch(&p_avro_field, FALSE, &p_avro_branch));
      }
    }
#endif
  }

  return ret;
}

int bmp_log_msg_peer_down(struct bgp_peer *peer, struct bmp_data *bdata, struct pm_list *tlvs, struct bmp_log_peer_down *blpd, char *event_type, int output, void *vobj)
{
  int ret = 0;

  if (!peer || !bdata || !blpd || !vobj) return ERR;

  if (output == PRINT_OUTPUT_JSON) {
#ifdef WITH_JANSSON
    char bmp_msg_type[] = "peer_down";
    char ip_address[INET6_ADDRSTRLEN];
    json_t *obj = (json_t *) vobj;

    json_object_set_new_nocheck(obj, "bmp_msg_type", json_string(bmp_msg_type));

    addr_to_str(ip_address, &bdata->peer_ip);
    json_object_set_new_nocheck(obj, "peer_ip", json_string(ip_address));

    json_object_set_new_nocheck(obj, "peer_asn", json_integer((json_int_t)bdata->peer_asn));
    json_object_set_new_nocheck(obj, "peer_type", json_integer((json_int_t)bdata->chars.peer_type));

    if (bdata->chars.peer_type <= BMP_PEER_TYPE_MAX) {
      json_object_set_new_nocheck(obj, "peer_type_str", json_string(bmp_peer_types[bdata->chars.peer_type]));
    }

    if (!is_empty_256b(&bdata->chars.rd, sizeof(bdata->chars.rd))) {
      char rd_str[SHORTSHORTBUFLEN];

      bgp_rd2str(rd_str, &bdata->chars.rd);
      json_object_set_new_nocheck(obj, "rd", json_string(rd_str));
      json_object_set_new_nocheck(obj, "rd_origin", json_string(bgp_rd_origin_print(bdata->chars.rd.type)));
    }

    json_object_set_new_nocheck(obj, "reason_type", json_integer((json_int_t)blpd->reason));

    if (blpd->reason <= BMP_PEER_DOWN_MAX) {
      json_object_set_new_nocheck(obj, "reason_str", json_string(bmp_peer_down_reason_types[blpd->reason]));
    }

    if (blpd->reason == BMP_PEER_DOWN_LOC_CODE) {
      json_object_set_new_nocheck(obj, "reason_loc_code", json_integer((json_int_t)blpd->loc_code));
    }

    if (tlvs) {
      struct pm_listnode *node = NULL;
      struct bmp_log_tlv *tlv = NULL;

      for (PM_ALL_LIST_ELEMENTS_RO(tlvs, node, tlv)) {
	char *type = NULL, *value = NULL;

	switch (tlv->pen) {
	case BMP_TLV_PEN_STD:
	  type = bmp_tlv_type_print(tlv, "bmp_peer_down_info", bmp_peer_down_info_types, BMP_PEER_DOWN_INFO_MAX);
	  value = bmp_tlv_value_print(tlv, bmp_peer_down_info_types, BMP_PEER_DOWN_INFO_MAX);
	  break;
	default:
	  type = bmp_tlv_type_print(tlv, "bmp_peer_down_info", NULL, -1);
	  value = bmp_tlv_value_print(tlv, NULL, -1);
	  break;
	}

	if (type) {
	  if (value) {
	    json_object_set_new_nocheck(obj, type, json_string(value));
	    free(value);
	  }
	  else {
	    json_object_set_new_nocheck(obj, type, json_null());
	  }

	  free(type);
	}
      }
    }
#endif
  }
  else if ((output == PRINT_OUTPUT_AVRO_BIN) ||
	   (output == PRINT_OUTPUT_AVRO_JSON)) {
#ifdef WITH_AVRO
    int idx = 0, bmp_peer_down_tlvs[BMP_PEER_DOWN_INFO_MAX + 1];
    avro_value_t *obj = (avro_value_t *) vobj, p_avro_field, p_avro_branch;
    char bmp_msg_type[] = "peer_down";
    char ip_address[INET6_ADDRSTRLEN];

    pm_avro_check(avro_value_get_by_name(obj, "bmp_msg_type", &p_avro_field, NULL));
    pm_avro_check(avro_value_set_string(&p_avro_field, bmp_msg_type));

    addr_to_str(ip_address, &bdata->peer_ip);
    pm_avro_check(avro_value_get_by_name(obj, "peer_ip", &p_avro_field, NULL));
    pm_avro_check(avro_value_set_string(&p_avro_field, ip_address));

    pm_avro_check(avro_value_get_by_name(obj, "peer_asn", &p_avro_field, NULL));
    pm_avro_check(avro_value_set_long(&p_avro_field, bdata->peer_asn));

    pm_avro_check(avro_value_get_by_name(obj, "peer_type", &p_avro_field, NULL));
    pm_avro_check(avro_value_set_int(&p_avro_field, bdata->chars.peer_type));

    if (bdata->chars.peer_type <= BMP_PEER_TYPE_MAX) {
      pm_avro_check(avro_value_get_by_name(obj, "peer_type_str", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, TRUE, &p_avro_branch));
      pm_avro_check(avro_value_set_string(&p_avro_branch, bmp_peer_types[bdata->chars.peer_type]));
    }
    else {
      pm_avro_check(avro_value_get_by_name(obj, "peer_type_str", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, FALSE, &p_avro_branch));
    }

    if (!is_empty_256b(&bdata->chars.rd, sizeof(bdata->chars.rd))) {
      char rd_str[SHORTSHORTBUFLEN];

      bgp_rd2str(rd_str, &bdata->chars.rd);
      pm_avro_check(avro_value_get_by_name(obj, "rd", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, TRUE, &p_avro_branch));
      pm_avro_check(avro_value_set_string(&p_avro_branch, rd_str));

      pm_avro_check(avro_value_get_by_name(obj, "rd_origin", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, TRUE, &p_avro_branch));
      pm_avro_check(avro_value_set_string(&p_avro_branch, bgp_rd_origin_print(bdata->chars.rd.type)));
    }
    else {
      pm_avro_check(avro_value_get_by_name(obj, "rd", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, FALSE, &p_avro_branch));

      pm_avro_check(avro_value_get_by_name(obj, "rd_origin", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, FALSE, &p_avro_branch));
    }

    pm_avro_check(avro_value_get_by_name(obj, "reason_type", &p_avro_field, NULL));
    pm_avro_check(avro_value_set_int(&p_avro_field, blpd->reason));

    if (blpd->reason <= BMP_PEER_DOWN_MAX) {
      pm_avro_check(avro_value_get_by_name(obj, "reason_str", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, TRUE, &p_avro_branch));
      pm_avro_check(avro_value_set_string(&p_avro_branch, bmp_peer_down_reason_types[blpd->reason]));
    }
    else {
      pm_avro_check(avro_value_get_by_name(obj, "reason_str", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, FALSE, &p_avro_branch));
    }

    if (blpd->reason == BMP_PEER_DOWN_LOC_CODE) {
      pm_avro_check(avro_value_get_by_name(obj, "reason_loc_code", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, TRUE, &p_avro_branch));
      pm_avro_check(avro_value_set_int(&p_avro_branch, blpd->loc_code));
    }
    else {
      pm_avro_check(avro_value_get_by_name(obj, "reason_loc_code", &p_avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&p_avro_field, FALSE, &p_avro_branch));
    }

    memset(&bmp_peer_down_tlvs, 0, sizeof(bmp_peer_down_tlvs));

    /* No Peer Down TLVs defined, BMP_PEER_DOWN_INFO_MAX is hence set to
       -1 and this requires converting to int to sanitize comparisons */
    if (tlvs) {
      char *type = NULL, *value = NULL;
      struct pm_listnode *node = NULL;
      struct bmp_log_tlv *tlv = NULL;

      /* No PEN defined so far so we short-circuit to standard elements */
      for (PM_ALL_LIST_ELEMENTS_RO(tlvs, node, tlv)) {
	if ((int)tlv->type <= (int)BMP_PEER_DOWN_INFO_MAX) {
	  type = bmp_tlv_type_print(tlv, "bmp_peer_down_info", bmp_peer_down_info_types, BMP_PEER_DOWN_INFO_MAX);
	  value = bmp_tlv_value_print(tlv, bmp_peer_down_info_types, BMP_PEER_DOWN_INFO_MAX);

	  if (type) {
	    pm_avro_check(avro_value_get_by_name(obj, type, &p_avro_field, NULL));
	    pm_avro_check(avro_value_set_branch(&p_avro_field, TRUE, &p_avro_branch));

	    if (value) {
	      pm_avro_check(avro_value_set_string(&p_avro_branch, value));
	      free(value);
	    }
	    else {
	      pm_avro_check(avro_value_set_null(&p_avro_branch));
	    }

	    free(type);
	  }

	  bmp_peer_down_tlvs[tlv->type] = TRUE;
	}
      }
    }

    /* mark missing tlv types */
    for (idx = 0; idx <= BMP_PEER_DOWN_INFO_MAX; idx++) {
      struct bmp_log_tlv dummy_tlv;
      char *type;

      memset(&dummy_tlv, 0, sizeof(dummy_tlv));
      dummy_tlv.type = idx;

      if (!bmp_peer_down_tlvs[idx]) {
	type = bmp_tlv_type_print(&dummy_tlv, "bmp_peer_down_info", bmp_peer_down_info_types, BMP_PEER_DOWN_INFO_MAX);
	pm_avro_check(avro_value_get_by_name(obj, type, &p_avro_field, NULL));
	pm_avro_check(avro_value_set_branch(&p_avro_field, FALSE, &p_avro_branch));
      }
    }
#endif
  }

  return ret;
}

int bmp_log_msg_route_monitor_tlv(struct pm_list *tlvs, int output, void *vobj)
{
  int ret = 0;

  if (!vobj) return ERR;

  if (output == PRINT_OUTPUT_JSON) {
#ifdef WITH_JANSSON
    json_t *obj = (json_t *) vobj;

    if (tlvs) {
      struct pm_listnode *node = NULL;
      struct bmp_log_tlv *tlv = NULL;

      for (PM_ALL_LIST_ELEMENTS_RO(tlvs, node, tlv)) {
	char *type = NULL, *value = NULL;

	switch (tlv->pen) {
	case BMP_TLV_PEN_STD:
	  switch (tlv->type) {
	  case BMP_ROUTE_MONITOR_INFO_MARKING:
	    (*bmp_rm_info_types[tlv->type].logdump_func)(NULL, NULL, tlv, NULL, FALSE, output, vobj);
	    break;
	  default:
	    type = bmp_tlv_type_print(tlv, "bmp_rm_info", bmp_rm_info_types, BMP_ROUTE_MONITOR_INFO_MAX);
	    value = bmp_tlv_value_print(tlv, bmp_rm_info_types, BMP_ROUTE_MONITOR_INFO_MAX);
	    break;
	  }
	  break;
	default:
	  type = bmp_tlv_type_print(tlv, "bmp_rm_info", NULL, -1);
	  value = bmp_tlv_value_print(tlv, NULL, -1);
	  break;
	}

	if (type) {
	  if (value) {
	    json_object_set_new_nocheck(obj, type, json_string(value));
	    free(value);
	  }
	  else {
	    json_object_set_new_nocheck(obj, type, json_null());
	  }

	  free(type);
	}
      }
    }
#endif
  }
  else if ((output == PRINT_OUTPUT_AVRO_BIN) || 
	   (output == PRINT_OUTPUT_AVRO_JSON)) {
#ifdef WITH_AVRO
    /* TBD: once IANA-governed TLVs are defined or E-bit is implemented */
#endif
  }

  return ret;
}

int bmp_log_rm_tlv_path_marking(struct bgp_peer *null1, struct bmp_data *null2, void *vtlv, void *null3, char *null4, int output, void *vobj)
{
  struct bmp_log_tlv *tlv = vtlv;
  int ret = 0;

  if (!tlv || !vobj) return ERR;

  if (output == PRINT_OUTPUT_JSON) {
#ifdef WITH_JANSSON
    json_t *obj = (json_t *) vobj;
    struct bmp_rm_pm_tlv *pm_tlv = NULL;
    char value_str[SUPERSHORTBUFLEN];
    unsigned char *value;

    pm_tlv = (struct bmp_rm_pm_tlv *) tlv->val;

    bmp_log_rm_tlv_pm_status(ntohl(pm_tlv->path_status), output, vobj);

    if (tlv->len == 8 /* index (2) + status (4) + reason code (2) */) {
      value = (unsigned char *) &pm_tlv->reason_code;
      snprintf(value_str, SUPERSHORTBUFLEN, "0x%02x%02x", value[0], value[1]);
      json_object_set_new_nocheck(obj, "reason_code", json_string(value_str));
    }
#endif
  }
  else if ((output == PRINT_OUTPUT_AVRO_BIN) ||
	   (output == PRINT_OUTPUT_AVRO_JSON)) {
#ifdef WITH_AVRO
    // XXX: to be worked out later
#endif
  }

  return ret;
}

int bmp_log_rm_tlv_pm_status(u_int32_t path_status, int output, void *vobj)
{
  int ret = 0;

  if (!vobj) return ERR;

  if (output == PRINT_OUTPUT_JSON) {
#ifdef WITH_JANSSON
    json_t *obj = (json_t *) vobj;
    json_t *ps_array = json_array();
    char *value = NULL, value_str[SUPERSHORTBUFLEN];

    if (!path_status) {
      json_array_append_new(ps_array, json_string("Unknown"));
    }
    else {
      if (path_status & BMP_RM_PM_PS_INVALID) {
	json_array_append_new(ps_array, json_string("Invalid"));
	path_status ^= BMP_RM_PM_PS_INVALID;
      }

      if (path_status & BMP_RM_PM_PS_BEST) {
	json_array_append_new(ps_array, json_string("Best"));
	path_status ^= BMP_RM_PM_PS_BEST;
      }

      if (path_status & BMP_RM_PM_PS_NO_SELECT) {
	json_array_append_new(ps_array, json_string("Non-selected"));
	path_status ^= BMP_RM_PM_PS_NO_SELECT;
      }

      if (path_status & BMP_RM_PM_PS_PRIMARY) {
	json_array_append_new(ps_array, json_string("Primary"));
	path_status ^= BMP_RM_PM_PS_PRIMARY;
      }

      if (path_status & BMP_RM_PM_PS_BACKUP) {
	json_array_append_new(ps_array, json_string("Backup"));
	path_status ^= BMP_RM_PM_PS_BACKUP;
      }

      if (path_status & BMP_RM_PM_PS_NO_INSTALL) {
	json_array_append_new(ps_array, json_string("Non-installed"));
	path_status ^= BMP_RM_PM_PS_NO_INSTALL;
      }

      if (path_status & BMP_RM_PM_PS_BEST_EXT) {
	json_array_append_new(ps_array, json_string("Best-external"));
	path_status ^= BMP_RM_PM_PS_BEST_EXT;
      }

      if (path_status & BMP_RM_PM_PS_ADD_PATH) {
	json_array_append_new(ps_array, json_string("Add-Path"));
	path_status ^= BMP_RM_PM_PS_ADD_PATH;
      }

      if (path_status) {
	value = (char *) &path_status;
	snprintf(value_str, SUPERSHORTBUFLEN, "0x%02x%02x%02x%02x", value[0], value[1], value[2], value[3]);
	json_array_append_new(ps_array, json_string(value_str));
	path_status = FALSE;
      }
    }

    json_object_set_new_nocheck(obj, "path_status", ps_array);
#endif
  }
  else if ((output == PRINT_OUTPUT_AVRO_BIN) ||
           (output == PRINT_OUTPUT_AVRO_JSON)) {
#ifdef WITH_AVRO
    // XXX: to be worked out later
#endif
  }

  return ret;
}

void bmp_dump_init_peer(struct bgp_peer *peer)
{
  struct bgp_misc_structs *bms;

  if (!peer) return;

  bms = bgp_select_misc_db(peer->type);

  if (!bms) return;

  assert(!peer->bmp_se);

  peer->bmp_se = malloc(sizeof(struct bmp_dump_se_ll));
  if (!peer->bmp_se) {
    Log(LOG_ERR, "ERROR ( %s/%s ): Unable to malloc() bmp_se structure. Terminating thread.\n", config.name, bms->log_str);
    exit_gracefully(1);
  }

  memset(peer->bmp_se, 0, sizeof(struct bmp_dump_se_ll));
}

void bmp_dump_close_peer(struct bgp_peer *peer)
{
  struct bmp_dump_se_ll *bdsell;

  if (!peer) return;

  bdsell = (struct bmp_dump_se_ll *) peer->bmp_se;

  if (bdsell && bdsell->start) bmp_dump_se_ll_destroy(bdsell);
 
  free(peer->bmp_se);
  peer->bmp_se = NULL;
}

void bmp_dump_se_ll_append(struct bgp_peer *peer, struct bmp_data *bdata, struct pm_list *tlvs, void *extra, int log_type)
{
  struct bgp_misc_structs *bms = bgp_select_misc_db(FUNC_TYPE_BMP);
  struct bmp_dump_se_ll *se_ll;
  struct bmp_dump_se_ll_elem *se_ll_elem;

  if (!peer) return;

  assert(peer->bmp_se);

  se_ll_elem = malloc(sizeof(struct bmp_dump_se_ll_elem));
  if (!se_ll_elem) {
    Log(LOG_ERR, "ERROR ( %s/%s ): Unable to malloc() se_ll_elem structure. Terminating thread.\n", config.name, bms->log_str);
    exit_gracefully(1);
  }

  memset(se_ll_elem, 0, sizeof(struct bmp_dump_se_ll_elem));

  if (bdata) memcpy(&se_ll_elem->rec.bdata, bdata, sizeof(struct bmp_data));

  if (extra && log_type) {
    switch (log_type) {
    case BMP_LOG_TYPE_STATS:
      memcpy(&se_ll_elem->rec.se.stats, extra, sizeof(struct bmp_log_stats));
      break;
    case BMP_LOG_TYPE_PEER_UP:
      memcpy(&se_ll_elem->rec.se.peer_up, extra, sizeof(struct bmp_log_peer_up));
      break;
    case BMP_LOG_TYPE_PEER_DOWN:
      memcpy(&se_ll_elem->rec.se.peer_down, extra, sizeof(struct bmp_log_peer_down));
      break;
    default:
      break;
    }
  }

  if (tlvs && pm_listcount(tlvs)) {
    se_ll_elem->rec.tlvs = tlvs;
  }
  se_ll_elem->rec.seq = bgp_peer_log_seq_get(&bms->log_seq);
  se_ll_elem->rec.se_type = log_type;
  se_ll_elem->next = NULL; /* pedantic */

  se_ll = (struct bmp_dump_se_ll *) peer->bmp_se;

  /* append to an empty ll */
  if (!se_ll->start) {
    assert(!se_ll->last);

    se_ll->start = se_ll_elem;
    se_ll->last = se_ll_elem;
  }
  /* append to an existing ll */
  else {
    assert(se_ll->last);

    se_ll->last->next = se_ll_elem;
    se_ll->last = se_ll_elem;
  }
}

void bmp_dump_se_ll_destroy(struct bmp_dump_se_ll *bdsell)
{
  struct bmp_dump_se_ll_elem *se_ll_elem, *se_ll_elem_next;

  if (!bdsell) return;

  if (!bdsell->start) return;

  assert(bdsell->last);
  for (se_ll_elem = bdsell->start; se_ll_elem; se_ll_elem = se_ll_elem_next) {
    if (se_ll_elem->rec.tlvs) {
      bmp_tlv_list_destroy(se_ll_elem->rec.tlvs);
    }

    se_ll_elem_next = se_ll_elem->next;
    free(se_ll_elem);
  }

  bdsell->start = NULL;
  bdsell->last = NULL;
}

void bmp_handle_dump_event(int max_peers_idx)
{
  struct bgp_misc_structs *bms = bgp_select_misc_db(FUNC_TYPE_BMP);
  thread_pool_t *bmp_dump_workers_pool;
  struct pm_dump_runner pdr[config.bmp_dump_workers];
  u_int64_t dump_seqno;
  int idx, ret;

  struct bgp_peer *peer;
  struct bmp_dump_se_ll *bdsell;

  /* pre-flight check */
  if (!bms->dump_backend_methods || !config.bmp_dump_refresh_time) {
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
    pm_setproctitle("%s %s [%s]", config.type, "Core Process -- BMP Dump Writer", config.name);
    config.is_forked = TRUE;

    /* setting ourselves as read-only */
    bms->is_readonly = TRUE;

    /* Arranging workers data */
    distribute_work(pdr, dump_seqno, config.bmp_dump_workers, max_peers_idx);

    /* creating the thread pool */
    bmp_dump_workers_pool = allocate_thread_pool(config.bmp_dump_workers);
    assert(bmp_dump_workers_pool);

    for (idx = 0; idx < config.bmp_dump_workers; idx++) {
      if (!pdr[idx].noop) {
        send_to_pool(bmp_dump_workers_pool, bmp_dump_event_runner, &pdr[idx]);
      }
    }

    deallocate_thread_pool(&bmp_dump_workers_pool);
    exit_gracefully(0);
  default: /* Parent */
    if (ret == -1) { /* Something went wrong */
      Log(LOG_WARNING, "WARN ( %s/%s ): Unable to fork BMP table dump writer: %s\n",
	  config.name, bms->log_str, strerror(errno));
    }

    /* destroy bmp_se linked-list content after dump event */
    for (peer = NULL, idx = 0; idx < max_peers_idx; idx++) {
      if (bmp_peers[idx].self.fd) {
	peer = &bmp_peers[idx].self;
	bdsell = peer->bmp_se;

	if (bdsell && bdsell->start) bmp_dump_se_ll_destroy(bdsell);
      }
    }
    break;
  }
}

int bmp_dump_event_runner(struct pm_dump_runner *pdr)
{
  struct bgp_misc_structs *bms = bgp_select_misc_db(FUNC_TYPE_BMP);
  char current_filename[SRVBUFLEN], last_filename[SRVBUFLEN], tmpbuf[SRVBUFLEN];
  char latest_filename[SRVBUFLEN], dump_partition_key[SRVBUFLEN];
  char event_type[] = "dump", *fd_buf = NULL;
  int peers_idx, duration, tables_num;
  struct bgp_rt_structs *inter_domain_routing_db;
  struct bgp_table *table;
  struct bgp_node *node;
  afi_t afi;
  safi_t safi;
  pid_t dumper_pid;
  time_t start;
  u_int64_t dump_elems = 0, dump_seqno = pdr->seq;

  struct bgp_peer *peer, *saved_peer;
  struct bmp_dump_se_ll *bdsell;
  struct bgp_peer_log peer_log;

#ifdef WITH_RABBITMQ
  struct p_amqp_host bmp_dump_amqp_host;
#endif

#ifdef WITH_KAFKA
  struct p_kafka_host bmp_dump_kafka_host;
#endif

  memset(last_filename, 0, sizeof(last_filename));
  memset(current_filename, 0, sizeof(current_filename));

  fd_buf = malloc(OUTPUT_FILE_BUFSZ);
  bgp_peer_log_seq_set(&bms->log_seq, dump_seqno);

#ifdef WITH_RABBITMQ
  if (config.bmp_dump_amqp_routing_key) {
    int ret;

    bmp_dump_init_amqp_host(&bmp_dump_amqp_host);
    ret = p_amqp_connect_to_publish(&bmp_dump_amqp_host);
    if (ret) exit_gracefully(ret);
  }
#endif

#ifdef WITH_KAFKA
  if (config.bmp_dump_kafka_topic) {
    int ret;

    ret = bmp_dump_init_kafka_host(&bmp_dump_kafka_host);
    if (ret) exit_gracefully(ret);
  }
#endif

  dumper_pid = getpid();
  Log(LOG_INFO, "INFO ( %s/%s ): *** Dumping BMP tables - START (PID: %u RID: %u) ***\n",
      config.name, bms->log_str, dumper_pid, pdr->id);
  start = time(NULL);
  tables_num = 0;

#ifdef WITH_SERDES
  if (config.bmp_dump_kafka_avro_schema_registry) {
    if (strchr(config.bmp_dump_kafka_topic, '$')) {
      Log(LOG_ERR, "ERROR ( %s/%s ): dynamic 'bmp_dump_kafka_topic' is not compatible with 'bmp_dump_kafka_avro_schema_registry'. Exiting.\n",
	  config.name, bms->log_str);
      exit_gracefully(1);
    }

    bmp_dump_kafka_host.sd_schema[BMP_MSG_ROUTE_MONITOR] = compose_avro_schema_registry_name_2(config.bmp_dump_kafka_topic, FALSE,
											     bmp_misc_db->dump_avro_schema[BMP_MSG_ROUTE_MONITOR],
											     "bmp", "dump_rm",
											     config.bmp_dump_kafka_avro_schema_registry);

    bmp_dump_kafka_host.sd_schema[BMP_MSG_STATS] = compose_avro_schema_registry_name_2(config.bmp_dump_kafka_topic, FALSE,
											     bmp_misc_db->dump_avro_schema[BMP_MSG_STATS],
											     "bmp", "stats",
											     config.bmp_dump_kafka_avro_schema_registry);

    bmp_dump_kafka_host.sd_schema[BMP_MSG_PEER_UP] = compose_avro_schema_registry_name_2(config.bmp_dump_kafka_topic, FALSE,
											     bmp_misc_db->dump_avro_schema[BMP_MSG_PEER_UP],
											     "bmp", "peer_up",
											     config.bmp_dump_kafka_avro_schema_registry);

    bmp_dump_kafka_host.sd_schema[BMP_MSG_PEER_DOWN] = compose_avro_schema_registry_name_2(config.bmp_dump_kafka_topic, FALSE,
											     bmp_misc_db->dump_avro_schema[BMP_MSG_PEER_DOWN],
											     "bmp", "peer_down",
											     config.bmp_dump_kafka_avro_schema_registry);

    bmp_dump_kafka_host.sd_schema[BMP_MSG_INIT] = compose_avro_schema_registry_name_2(config.bmp_dump_kafka_topic, FALSE,
											     bmp_misc_db->dump_avro_schema[BMP_MSG_INIT],
											     "bmp", "init",
											     config.bmp_dump_kafka_avro_schema_registry);

    bmp_dump_kafka_host.sd_schema[BMP_MSG_TERM] = compose_avro_schema_registry_name_2(config.bmp_dump_kafka_topic, FALSE,
											     bmp_misc_db->dump_avro_schema[BMP_MSG_TERM],
											     "bmp", "term",
											     config.bmp_dump_kafka_avro_schema_registry);

    bmp_dump_kafka_host.sd_schema[BMP_MSG_TMP_RPAT] = compose_avro_schema_registry_name_2(config.bmp_dump_kafka_topic, FALSE,
											     bmp_misc_db->dump_avro_schema[BMP_MSG_TMP_RPAT],
											     "bmp", "rpat",
											     config.bmp_dump_kafka_avro_schema_registry);

    bmp_dump_kafka_host.sd_schema[BMP_LOG_TYPE_DUMPINIT] = compose_avro_schema_registry_name_2(config.bmp_dump_kafka_topic, FALSE,
											     bmp_misc_db->dump_avro_schema[BMP_LOG_TYPE_DUMPINIT],
											     "bmp", "dumpinit",
											     config.bmp_dump_kafka_avro_schema_registry);

    bmp_dump_kafka_host.sd_schema[BMP_LOG_TYPE_DUMPCLOSE] = compose_avro_schema_registry_name_2(config.bmp_dump_kafka_topic, FALSE,
											     bmp_misc_db->dump_avro_schema[BMP_LOG_TYPE_DUMPCLOSE],
											     "bmp", "dumpclose",
											     config.bmp_dump_kafka_avro_schema_registry);
  }
#endif

  for (peer = NULL, saved_peer = NULL, peers_idx = pdr->first; peers_idx <= pdr->last; peers_idx++) {
    if (bmp_peers[peers_idx].self.fd) {
      peer = &bmp_peers[peers_idx].self;
      peer->log = &peer_log; /* abusing struct bgp_peer a bit, but we are in a child */
      bdsell = peer->bmp_se;

      if (config.bmp_dump_file) {
	bgp_peer_log_dynname(current_filename, SRVBUFLEN, config.bmp_dump_file, peer);
      }

      if (config.bmp_dump_amqp_routing_key) {
	bgp_peer_log_dynname(current_filename, SRVBUFLEN, config.bmp_dump_amqp_routing_key, peer);
      }

      if (config.bmp_dump_kafka_topic) {
	bgp_peer_log_dynname(current_filename, SRVBUFLEN, config.bmp_dump_kafka_topic, peer);
      }

      if (config.bmp_dump_kafka_partition_key) {
	bgp_peer_log_dynname(dump_partition_key, SRVBUFLEN, config.bmp_dump_kafka_partition_key, peer);
      }

      pm_strftime_same(current_filename, SRVBUFLEN, tmpbuf, &bms->dump.tstamp.tv_sec, config.timestamps_utc);

      /*
	we close last_filename and open current_filename in case they differ;
	we are safe with this approach until time and BMP peer (IP, port) are
	the only variables supported as part of bmp_dump_file.
      */
      if (config.bmp_dump_file) {
        if (strcmp(last_filename, current_filename)) {
	  if (saved_peer && saved_peer->log && strlen(last_filename)) {
	    close_output_file(saved_peer->log->fd);

	    if (config.bmp_dump_latest_file) {
	      bgp_peer_log_dynname(latest_filename, SRVBUFLEN, config.bmp_dump_latest_file, saved_peer);
	      link_latest_output_file(latest_filename, last_filename);
	    }
	  }

          peer->log->fd = open_output_file(current_filename, "w", TRUE);

          if (fd_buf) {
            if (setvbuf(peer->log->fd, fd_buf, _IOFBF, OUTPUT_FILE_BUFSZ)) {
	      Log(LOG_WARNING, "WARN ( %s/%s ): [%s] setvbuf() failed: %s\n", config.name, bms->log_str, current_filename, strerror(errno));
	    }
            else {
	      memset(fd_buf, 0, OUTPUT_FILE_BUFSZ);
	    }
          }
        }
      }

      /*
        a bit pedantic maybe but should come at little cost and emulating
        bmp_dump_file behaviour will work
      */
#ifdef WITH_RABBITMQ
      if (config.bmp_dump_amqp_routing_key) {
        peer->log->amqp_host = &bmp_dump_amqp_host;
        strcpy(peer->log->filename, current_filename);
      }
#endif

#ifdef WITH_KAFKA
      if (config.bmp_dump_kafka_topic) {
        peer->log->kafka_host = &bmp_dump_kafka_host;
        strcpy(peer->log->filename, current_filename);

	if (config.bmp_dump_kafka_partition_key) {
	  p_kafka_set_key(peer->log->kafka_host, dump_partition_key, strlen(dump_partition_key));
	}
      }
#endif

      bgp_peer_dump_init(peer, config.bmp_dump_output, FUNC_TYPE_BMP);
      inter_domain_routing_db = bgp_select_routing_db(FUNC_TYPE_BMP);

      if (!inter_domain_routing_db) return ERR;

      for (afi = AFI_IP; afi < AFI_MAX; afi++) {
        for (safi = SAFI_UNICAST; safi < SAFI_MAX; safi++) {
          table = inter_domain_routing_db->rib[afi][safi];
          node = bgp_table_top(peer, table);

          while (node) {
            u_int32_t modulo = bms->route_info_modulo(peer, NULL, bms->table_per_peer_buckets);
            u_int32_t peer_buckets;
            struct bgp_info *ri;

            for (peer_buckets = 0; peer_buckets < config.bmp_table_per_peer_buckets; peer_buckets++) {
              for (ri = node->info[modulo+peer_buckets]; ri; ri = ri->next) {
		struct bmp_peer *local_bmpp = ri->peer->bmp_se;

                if (local_bmpp && (&local_bmpp->self == peer)) {
		  ri->peer->log = peer->log;
                  bgp_peer_log_msg(node, ri, afi, safi, event_type, config.bmp_dump_output, NULL, BGP_LOG_TYPE_MISC);
                  dump_elems++;
                }
              }
            }

            node = bgp_route_next(peer, node);
	  }
	}
      }

      if (bdsell && bdsell->start) {
	struct bmp_dump_se_ll_elem *se_ll_elem;
	char event_type[] = "dump";

	for (se_ll_elem = bdsell->start; se_ll_elem; se_ll_elem = se_ll_elem->next) {
	  switch (se_ll_elem->rec.se_type) {
	  case BMP_LOG_TYPE_STATS:
	    bmp_log_msg(peer, &se_ll_elem->rec.bdata, NULL, &se_ll_elem->rec.se.stats,
			se_ll_elem->rec.seq, event_type, config.bmp_dump_output, BMP_LOG_TYPE_STATS);
	    break;
	  case BMP_LOG_TYPE_INIT:
	    bmp_log_msg(peer, &se_ll_elem->rec.bdata, se_ll_elem->rec.tlvs, NULL,
			se_ll_elem->rec.seq, event_type, config.bmp_dump_output, BMP_LOG_TYPE_INIT);
	    break;
	  case BMP_LOG_TYPE_TERM:
	    bmp_log_msg(peer, &se_ll_elem->rec.bdata, se_ll_elem->rec.tlvs, NULL,
			se_ll_elem->rec.seq, event_type, config.bmp_dump_output, BMP_LOG_TYPE_TERM);
	    break;
	  case BMP_LOG_TYPE_PEER_UP:
	    bmp_log_msg(peer, &se_ll_elem->rec.bdata, se_ll_elem->rec.tlvs, &se_ll_elem->rec.se.peer_up,
			se_ll_elem->rec.seq, event_type, config.bmp_dump_output, BMP_LOG_TYPE_PEER_UP);
	    break;
	  case BMP_LOG_TYPE_PEER_DOWN:
	    bmp_log_msg(peer, &se_ll_elem->rec.bdata, se_ll_elem->rec.tlvs, &se_ll_elem->rec.se.peer_down,
			se_ll_elem->rec.seq, event_type, config.bmp_dump_output, BMP_LOG_TYPE_PEER_DOWN);
	    break;
	  default:
	    break;
	  }
	}
      }
 
      saved_peer = peer;
      strlcpy(last_filename, current_filename, SRVBUFLEN);
      bgp_peer_dump_close(peer, NULL, config.bmp_dump_output, FUNC_TYPE_BMP);
      tables_num++;
    }
  }

#ifdef WITH_RABBITMQ
  if (config.bmp_dump_amqp_routing_key) {
    p_amqp_close(&bmp_dump_amqp_host, FALSE);
  }
#endif

#ifdef WITH_KAFKA
  if (config.bmp_dump_kafka_topic) {
    p_kafka_close(&bmp_dump_kafka_host, FALSE);
  }
#endif

  if (config.bmp_dump_file && peer) {
    close_output_file(peer->log->fd);
  }

  if (config.bmp_dump_latest_file && peer) {
    bgp_peer_log_dynname(latest_filename, SRVBUFLEN, config.bmp_dump_latest_file, peer);
    link_latest_output_file(latest_filename, last_filename);
  }

  duration = time(NULL)-start;
  Log(LOG_INFO, "INFO ( %s/%s ): *** Dumping BMP tables - END (PID: %u RID: %u TABLES: %u ENTRIES: %" PRIu64 " ET: %u) ***\n",
      config.name, bms->log_str, dumper_pid, pdr->id, tables_num, dump_elems, duration);

  return FALSE;
}

#if defined WITH_RABBITMQ
void bmp_daemon_msglog_init_amqp_host()
{
  p_amqp_init_host(&bmp_daemon_msglog_amqp_host);

  if (!config.bmp_daemon_msglog_amqp_user) config.bmp_daemon_msglog_amqp_user = rabbitmq_user;
  if (!config.bmp_daemon_msglog_amqp_passwd) config.bmp_daemon_msglog_amqp_passwd = rabbitmq_pwd;
  if (!config.bmp_daemon_msglog_amqp_exchange) config.bmp_daemon_msglog_amqp_exchange = default_amqp_exchange;
  if (!config.bmp_daemon_msglog_amqp_exchange_type) config.bmp_daemon_msglog_amqp_exchange_type = default_amqp_exchange_type;
  if (!config.bmp_daemon_msglog_amqp_host) config.bmp_daemon_msglog_amqp_host = default_amqp_host;
  if (!config.bmp_daemon_msglog_amqp_vhost) config.bmp_daemon_msglog_amqp_vhost = default_amqp_vhost;
  if (!config.bmp_daemon_msglog_amqp_retry) config.bmp_daemon_msglog_amqp_retry = AMQP_DEFAULT_RETRY;

  p_amqp_set_user(&bmp_daemon_msglog_amqp_host, config.bmp_daemon_msglog_amqp_user);
  p_amqp_set_passwd(&bmp_daemon_msglog_amqp_host, config.bmp_daemon_msglog_amqp_passwd);
  p_amqp_set_exchange(&bmp_daemon_msglog_amqp_host, config.bmp_daemon_msglog_amqp_exchange);
  p_amqp_set_exchange_type(&bmp_daemon_msglog_amqp_host, config.bmp_daemon_msglog_amqp_exchange_type);
  p_amqp_set_host(&bmp_daemon_msglog_amqp_host, config.bmp_daemon_msglog_amqp_host);
  p_amqp_set_vhost(&bmp_daemon_msglog_amqp_host, config.bmp_daemon_msglog_amqp_vhost);
  p_amqp_set_persistent_msg(&bmp_daemon_msglog_amqp_host, config.bmp_daemon_msglog_amqp_persistent_msg);
  p_amqp_set_frame_max(&bmp_daemon_msglog_amqp_host, config.bmp_daemon_msglog_amqp_frame_max);
  p_amqp_set_content_type_json(&bmp_daemon_msglog_amqp_host);
  p_amqp_set_heartbeat_interval(&bmp_daemon_msglog_amqp_host, config.bmp_daemon_msglog_amqp_heartbeat_interval);
  P_broker_timers_set_retry_interval(&bmp_daemon_msglog_amqp_host.btimers, config.bmp_daemon_msglog_amqp_retry);
}
#else
void bmp_daemon_msglog_init_amqp_host()
{
}
#endif

#if defined WITH_RABBITMQ
void bmp_dump_init_amqp_host(void *bdah)
{
  struct p_amqp_host *bmp_dump_amqp_host = bdah;

  p_amqp_init_host(bmp_dump_amqp_host);

  if (!config.bmp_dump_amqp_user) config.bmp_dump_amqp_user = rabbitmq_user;
  if (!config.bmp_dump_amqp_passwd) config.bmp_dump_amqp_passwd = rabbitmq_pwd;
  if (!config.bmp_dump_amqp_exchange) config.bmp_dump_amqp_exchange = default_amqp_exchange;
  if (!config.bmp_dump_amqp_exchange_type) config.bmp_dump_amqp_exchange_type = default_amqp_exchange_type;
  if (!config.bmp_dump_amqp_host) config.bmp_dump_amqp_host = default_amqp_host;
  if (!config.bmp_dump_amqp_vhost) config.bmp_dump_amqp_vhost = default_amqp_vhost;

  p_amqp_set_user(bmp_dump_amqp_host, config.bmp_dump_amqp_user);
  p_amqp_set_passwd(bmp_dump_amqp_host, config.bmp_dump_amqp_passwd);
  p_amqp_set_exchange(bmp_dump_amqp_host, config.bmp_dump_amqp_exchange);
  p_amqp_set_exchange_type(bmp_dump_amqp_host, config.bmp_dump_amqp_exchange_type);
  p_amqp_set_host(bmp_dump_amqp_host, config.bmp_dump_amqp_host);
  p_amqp_set_vhost(bmp_dump_amqp_host, config.bmp_dump_amqp_vhost);
  p_amqp_set_persistent_msg(bmp_dump_amqp_host, config.bmp_dump_amqp_persistent_msg);
  p_amqp_set_frame_max(bmp_dump_amqp_host, config.bmp_dump_amqp_frame_max);
  p_amqp_set_content_type_json(bmp_dump_amqp_host);
  p_amqp_set_heartbeat_interval(bmp_dump_amqp_host, config.bmp_dump_amqp_heartbeat_interval);
}
#else
void bmp_dump_init_amqp_host(void *bdah)
{
}
#endif

#if defined WITH_KAFKA
int bmp_daemon_msglog_init_kafka_host()
{
  int ret;

  p_kafka_init_host(&bmp_daemon_msglog_kafka_host, config.bmp_daemon_msglog_kafka_config_file);
  ret = p_kafka_connect_to_produce(&bmp_daemon_msglog_kafka_host);

  if (!config.bmp_daemon_msglog_kafka_broker_host) config.bmp_daemon_msglog_kafka_broker_host = default_kafka_broker_host;
  if (!config.bmp_daemon_msglog_kafka_broker_port) config.bmp_daemon_msglog_kafka_broker_port = default_kafka_broker_port;
  if (!config.bmp_daemon_msglog_kafka_retry) config.bmp_daemon_msglog_kafka_retry = PM_KAFKA_DEFAULT_RETRY;

  p_kafka_set_broker(&bmp_daemon_msglog_kafka_host, config.bmp_daemon_msglog_kafka_broker_host, config.bmp_daemon_msglog_kafka_broker_port);
  p_kafka_set_topic(&bmp_daemon_msglog_kafka_host, config.bmp_daemon_msglog_kafka_topic);
  p_kafka_set_partition(&bmp_daemon_msglog_kafka_host, config.bmp_daemon_msglog_kafka_partition);
  p_kafka_set_key(&bmp_daemon_msglog_kafka_host, config.bmp_daemon_msglog_kafka_partition_key, config.bmp_daemon_msglog_kafka_partition_keylen);
  p_kafka_set_content_type(&bmp_daemon_msglog_kafka_host, PM_KAFKA_CNT_TYPE_STR);
  P_broker_timers_set_retry_interval(&bmp_daemon_msglog_kafka_host.btimers, config.bmp_daemon_msglog_kafka_retry);
#ifdef WITH_SERDES
  P_broker_timers_set_retry_interval(&bmp_daemon_msglog_kafka_host.sd_schema_timers, config.bmp_daemon_msglog_kafka_retry);
#endif

  return ret;
}
#else
int bmp_daemon_msglog_init_kafka_host()
{
  return ERR;
}
#endif

#if defined WITH_KAFKA
int bmp_dump_init_kafka_host(void *bmkh)
{
  struct p_kafka_host *bmp_dump_kafka_host = bmkh;
  int ret;

  p_kafka_init_host(bmp_dump_kafka_host, config.bmp_dump_kafka_config_file);
  ret = p_kafka_connect_to_produce(bmp_dump_kafka_host);

  if (!config.bmp_dump_kafka_broker_host) config.bmp_dump_kafka_broker_host = default_kafka_broker_host;
  if (!config.bmp_dump_kafka_broker_port) config.bmp_dump_kafka_broker_port = default_kafka_broker_port;

  p_kafka_set_broker(bmp_dump_kafka_host, config.bmp_dump_kafka_broker_host, config.bmp_dump_kafka_broker_port);
  p_kafka_set_topic(bmp_dump_kafka_host, config.bmp_dump_kafka_topic);
  p_kafka_set_partition(bmp_dump_kafka_host, config.bmp_dump_kafka_partition);
  p_kafka_set_key(bmp_dump_kafka_host, config.bmp_dump_kafka_partition_key, config.bmp_dump_kafka_partition_keylen);
  p_kafka_set_content_type(bmp_dump_kafka_host, PM_KAFKA_CNT_TYPE_STR);

  return ret;
}
#else
int bmp_dump_init_kafka_host(void *bmkh)
{
  return ERR;
}
#endif

#if defined WITH_AVRO
avro_schema_t p_avro_schema_build_bmp_rm(int log_type, char *schema_name)
{
  avro_schema_t schema = NULL;
  avro_schema_t optlong_s = avro_schema_union();
  avro_schema_t optstr_s = avro_schema_union();
  avro_schema_t optint_s = avro_schema_union();

  if (log_type != BGP_LOGDUMP_ET_LOG && log_type != BGP_LOGDUMP_ET_DUMP) return NULL;

  p_avro_schema_init_bgp(&schema, &optlong_s, &optstr_s, &optint_s, FUNC_TYPE_BMP, schema_name);
  p_avro_schema_build_bgp_common(&schema, &optlong_s, &optstr_s, &optint_s, log_type);
  p_avro_schema_build_bgp_route(&schema, &optlong_s, &optstr_s, &optint_s);

  /* also cherry-picking from avro_schema_build_bmp_common() */ 
  avro_schema_record_field_append(schema, "peer_ip", avro_schema_string());
  avro_schema_record_field_append(schema, "peer_tcp_port", optint_s);
  avro_schema_record_field_append(schema, "timestamp_arrival", optstr_s);

  avro_schema_record_field_append(schema, "bmp_router", avro_schema_string());
  avro_schema_record_field_append(schema, "bmp_router_port", optint_s);
  avro_schema_record_field_append(schema, "bmp_msg_type", avro_schema_string());

  avro_schema_record_field_append(schema, "is_in", optint_s);
  avro_schema_record_field_append(schema, "is_filtered", optint_s);
  avro_schema_record_field_append(schema, "is_loc", optint_s);
  avro_schema_record_field_append(schema, "is_post", optint_s);
  avro_schema_record_field_append(schema, "is_out", optint_s);

  avro_schema_decref(optlong_s);
  avro_schema_decref(optstr_s);
  avro_schema_decref(optint_s);

  return schema;
}

avro_schema_t p_avro_schema_build_bmp_init(char *schema_name)
{
  char *type = NULL;
  struct bmp_log_tlv dummy_tlv;
  avro_schema_t schema = NULL;
  avro_schema_t optlong_s = avro_schema_union();
  avro_schema_t optstr_s = avro_schema_union();
  avro_schema_t optint_s = avro_schema_union();

  memset(&dummy_tlv, 0, sizeof(dummy_tlv));

  p_avro_schema_init_bgp(&schema, &optlong_s, &optstr_s, &optint_s, FUNC_TYPE_BMP, schema_name);
  p_avro_schema_build_bmp_common(&schema, &optlong_s, &optstr_s, &optint_s);

  dummy_tlv.type = BMP_INIT_INFO_STRING;
  type = bmp_tlv_type_print(&dummy_tlv, "bmp_init_info", bmp_init_info_types, BMP_INIT_INFO_MAX);
  avro_schema_record_field_append(schema, type, optstr_s);
  free(type);

  dummy_tlv.type = BMP_INIT_INFO_SYSDESCR;
  type = bmp_tlv_type_print(&dummy_tlv, "bmp_init_info", bmp_init_info_types, BMP_INIT_INFO_MAX);
  avro_schema_record_field_append(schema, type, optstr_s);
  free(type);

  dummy_tlv.type = BMP_INIT_INFO_SYSNAME;
  type = bmp_tlv_type_print(&dummy_tlv, "bmp_init_info", bmp_init_info_types, BMP_INIT_INFO_MAX);
  avro_schema_record_field_append(schema, type, optstr_s);
  free(type);

  avro_schema_decref(optlong_s);
  avro_schema_decref(optstr_s);
  avro_schema_decref(optint_s);

  return schema;
}

avro_schema_t p_avro_schema_build_bmp_term(char *schema_name)
{
  char *type = NULL;
  struct bmp_log_tlv dummy_tlv;
  avro_schema_t schema = NULL;
  avro_schema_t optlong_s = avro_schema_union();
  avro_schema_t optstr_s = avro_schema_union();
  avro_schema_t optint_s = avro_schema_union();

  memset(&dummy_tlv, 0, sizeof(dummy_tlv));

  p_avro_schema_init_bgp(&schema, &optlong_s, &optstr_s, &optint_s, FUNC_TYPE_BMP, schema_name);
  p_avro_schema_build_bmp_common(&schema, &optlong_s, &optstr_s, &optint_s);

  dummy_tlv.type = BMP_TERM_INFO_STRING;
  type = bmp_tlv_type_print(&dummy_tlv, "bmp_term_info", bmp_term_info_types, BMP_TERM_INFO_MAX);
  avro_schema_record_field_append(schema, type, optstr_s);
  free(type);

  dummy_tlv.type = BMP_TERM_INFO_REASON;
  type = bmp_tlv_type_print(&dummy_tlv, "bmp_term_info", bmp_term_info_types, BMP_TERM_INFO_MAX);
  avro_schema_record_field_append(schema, type, optstr_s);
  free(type);

  avro_schema_decref(optlong_s);
  avro_schema_decref(optstr_s);
  avro_schema_decref(optint_s);

  return schema;
}

avro_schema_t p_avro_schema_build_bmp_peer_up(char *schema_name)
{
  char *type = NULL;
  struct bmp_log_tlv dummy_tlv;
  avro_schema_t schema = NULL;
  avro_schema_t optlong_s = avro_schema_union();
  avro_schema_t optstr_s = avro_schema_union();
  avro_schema_t optint_s = avro_schema_union();

  memset(&dummy_tlv, 0, sizeof(dummy_tlv));

  p_avro_schema_init_bgp(&schema, &optlong_s, &optstr_s, &optint_s, FUNC_TYPE_BMP, schema_name);
  p_avro_schema_build_bmp_common(&schema, &optlong_s, &optstr_s, &optint_s);

  avro_schema_record_field_append(schema, "peer_ip", avro_schema_string());
  avro_schema_record_field_append(schema, "peer_asn", avro_schema_long());
  avro_schema_record_field_append(schema, "peer_type", avro_schema_int());
  avro_schema_record_field_append(schema, "peer_type_str", optstr_s);

  avro_schema_record_field_append(schema, "is_in", optint_s);
  avro_schema_record_field_append(schema, "is_filtered", optint_s);
  avro_schema_record_field_append(schema, "is_loc", optint_s);
  avro_schema_record_field_append(schema, "is_post", optint_s);
  avro_schema_record_field_append(schema, "is_out", optint_s);

  avro_schema_record_field_append(schema, "rd", optstr_s);
  avro_schema_record_field_append(schema, "rd_origin", optstr_s);

  avro_schema_record_field_append(schema, "bgp_id", avro_schema_string());
  avro_schema_record_field_append(schema, "local_port", avro_schema_int());
  avro_schema_record_field_append(schema, "remote_port", avro_schema_int());
  avro_schema_record_field_append(schema, "local_ip", avro_schema_string());

  dummy_tlv.type = BMP_PEER_UP_INFO_STRING;
  type = bmp_tlv_type_print(&dummy_tlv, "bmp_peer_up_info", bmp_peer_up_info_types, BMP_PEER_UP_INFO_MAX);
  avro_schema_record_field_append(schema, type, optstr_s);
  free(type);

  avro_schema_decref(optlong_s);
  avro_schema_decref(optstr_s);
  avro_schema_decref(optint_s);

  return schema;
}

avro_schema_t p_avro_schema_build_bmp_peer_down(char *schema_name)
{
  avro_schema_t schema = NULL;
  avro_schema_t optlong_s = avro_schema_union();
  avro_schema_t optstr_s = avro_schema_union();
  avro_schema_t optint_s = avro_schema_union();

  p_avro_schema_init_bgp(&schema, &optlong_s, &optstr_s, &optint_s, FUNC_TYPE_BMP, schema_name);
  p_avro_schema_build_bmp_common(&schema, &optlong_s, &optstr_s, &optint_s);

  avro_schema_record_field_append(schema, "peer_ip", avro_schema_string());
  avro_schema_record_field_append(schema, "peer_asn", avro_schema_long());
  avro_schema_record_field_append(schema, "peer_type", avro_schema_int());
  avro_schema_record_field_append(schema, "peer_type_str", optstr_s);

  avro_schema_record_field_append(schema, "rd", optstr_s);
  avro_schema_record_field_append(schema, "rd_origin", optstr_s);

  avro_schema_record_field_append(schema, "reason_type", avro_schema_int());
  avro_schema_record_field_append(schema, "reason_str", optstr_s);
  avro_schema_record_field_append(schema, "reason_loc_code", optint_s);

  avro_schema_decref(optlong_s);
  avro_schema_decref(optstr_s);
  avro_schema_decref(optint_s);

  return schema;
}

avro_schema_t p_avro_schema_build_bmp_stats(char *schema_name)
{
  avro_schema_t schema = NULL;
  avro_schema_t optlong_s = avro_schema_union();
  avro_schema_t optstr_s = avro_schema_union();
  avro_schema_t optint_s = avro_schema_union();

  p_avro_schema_init_bgp(&schema, &optlong_s, &optstr_s, &optint_s, FUNC_TYPE_BMP, schema_name);
  p_avro_schema_build_bmp_common(&schema, &optlong_s, &optstr_s, &optint_s);

  avro_schema_record_field_append(schema, "peer_ip", avro_schema_string());
  avro_schema_record_field_append(schema, "peer_asn", avro_schema_long());
  avro_schema_record_field_append(schema, "peer_type", avro_schema_int());
  avro_schema_record_field_append(schema, "peer_type_str", avro_schema_string());

  avro_schema_record_field_append(schema, "is_in", optint_s);
  avro_schema_record_field_append(schema, "is_filtered", optint_s);
  avro_schema_record_field_append(schema, "is_loc", optint_s);
  avro_schema_record_field_append(schema, "is_post", optint_s);
  avro_schema_record_field_append(schema, "is_out", optint_s);

  avro_schema_record_field_append(schema, "rd", optstr_s);
  avro_schema_record_field_append(schema, "rd_origin", optstr_s);

  avro_schema_record_field_append(schema, "counter_type", avro_schema_int());
  avro_schema_record_field_append(schema, "counter_type_str", avro_schema_string());
  avro_schema_record_field_append(schema, "counter_value", avro_schema_long());

  avro_schema_record_field_append(schema, "afi", optint_s);
  avro_schema_record_field_append(schema, "safi", optint_s);

  avro_schema_decref(optlong_s);
  avro_schema_decref(optstr_s);
  avro_schema_decref(optint_s);

  return schema;
}

avro_schema_t p_avro_schema_build_bmp_log_initclose(int log_type, char *schema_name)
{
  avro_schema_t schema = NULL;
  avro_schema_t optlong_s = avro_schema_union();
  avro_schema_t optstr_s = avro_schema_union();
  avro_schema_t optint_s = avro_schema_union();

  if (log_type != BGP_LOGDUMP_ET_LOG) return NULL;

  p_avro_schema_init_bgp(&schema, &optlong_s, &optstr_s, &optint_s, FUNC_TYPE_BMP, schema_name);

  /* prevent log_type from being added to Avro schema */
  log_type = BGP_LOGDUMP_ET_NONE;
  p_avro_schema_build_bgp_common(&schema, &optlong_s, &optstr_s, &optint_s, log_type);
  log_type = BGP_LOGDUMP_ET_LOG;

  avro_schema_record_field_append(schema, "bmp_router", avro_schema_string());
  avro_schema_record_field_append(schema, "bmp_router_port", optint_s);

  avro_schema_decref(optlong_s);
  avro_schema_decref(optstr_s);
  avro_schema_decref(optint_s);

  return schema;
}

avro_schema_t p_avro_schema_build_bmp_dump_init(int log_type, char *schema_name)
{
  avro_schema_t schema = NULL;
  avro_schema_t optlong_s = avro_schema_union();
  avro_schema_t optstr_s = avro_schema_union();
  avro_schema_t optint_s = avro_schema_union();

  if (log_type != BGP_LOGDUMP_ET_DUMP) return NULL;

  p_avro_schema_init_bgp(&schema, &optlong_s, &optstr_s, &optint_s, FUNC_TYPE_BMP, schema_name);
  p_avro_schema_build_bgp_common(&schema, &optlong_s, &optstr_s, &optint_s, log_type);

  avro_schema_record_field_append(schema, "bmp_router", avro_schema_string());
  avro_schema_record_field_append(schema, "bmp_router_port", optint_s);
  avro_schema_record_field_append(schema, "dump_period", avro_schema_long());

  avro_schema_decref(optlong_s);
  avro_schema_decref(optstr_s);
  avro_schema_decref(optint_s);

  return schema;
}

avro_schema_t p_avro_schema_build_bmp_dump_close(int log_type, char *schema_name)
{
  avro_schema_t schema = NULL;
  avro_schema_t optlong_s = avro_schema_union();
  avro_schema_t optstr_s = avro_schema_union();
  avro_schema_t optint_s = avro_schema_union();

  if (log_type != BGP_LOGDUMP_ET_DUMP) return NULL;

  p_avro_schema_init_bgp(&schema, &optlong_s, &optstr_s, &optint_s, FUNC_TYPE_BMP, schema_name);
  p_avro_schema_build_bgp_common(&schema, &optlong_s, &optstr_s, &optint_s, log_type);

  avro_schema_record_field_append(schema, "bmp_router", avro_schema_string());
  avro_schema_record_field_append(schema, "bmp_router_port", optint_s);
  avro_schema_record_field_append(schema, "entries", optlong_s);
  avro_schema_record_field_append(schema, "tables", optint_s);

  avro_schema_decref(optlong_s);
  avro_schema_decref(optstr_s);
  avro_schema_decref(optint_s);

  return schema;
}

void p_avro_schema_build_bmp_common(avro_schema_t *schema, avro_schema_t *optlong_s, avro_schema_t *optstr_s, avro_schema_t *optint_s)
{
  avro_schema_record_field_append((*schema), "seq", avro_schema_long());
  avro_schema_record_field_append((*schema), "timestamp", avro_schema_string());
  avro_schema_record_field_append((*schema), "timestamp_event", (*optstr_s));
  avro_schema_record_field_append((*schema), "timestamp_arrival", (*optstr_s));
  avro_schema_record_field_append((*schema), "event_type", avro_schema_string());
  avro_schema_record_field_append((*schema), "bmp_router", avro_schema_string());
  avro_schema_record_field_append((*schema), "bmp_router_port", (*optint_s));
  avro_schema_record_field_append((*schema), "bmp_msg_type", avro_schema_string());
  avro_schema_record_field_append((*schema), "writer_id", avro_schema_string());
}
#endif
