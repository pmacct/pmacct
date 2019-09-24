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
/* includes */
#include "pmacct.h"
#include "addr.h"
#include "bgp/bgp.h"
#include "bmp.h"
#if defined WITH_RABBITMQ
#include "amqp_common.h"
#endif
#ifdef WITH_KAFKA
#include "kafka_common.h"
#endif
#ifdef WITH_AVRO
#include "plugin_cmn_avro.h"
#endif

int bmp_log_msg(struct bgp_peer *peer, struct bmp_data *bdata, void *log_data, u_int64_t log_seq, char *event_type, int output, int log_type)
{
  struct bgp_misc_structs *bms = bgp_select_misc_db(FUNC_TYPE_BMP);
  int ret = 0, amqp_ret = 0, kafka_ret = 0, etype = BGP_LOGDUMP_ET_NONE;

#if defined (WITH_JANSSON) || defined (WITH_AVRO)
  pid_t writer_pid = getpid();
#endif

  if (!bms || !peer || !peer->log || !bdata || !event_type) return ERR;

  if (!strcmp(event_type, "dump")) etype = BGP_LOGDUMP_ET_DUMP;
  else if (!strcmp(event_type, "log")) etype = BGP_LOGDUMP_ET_LOG;

  if ((config.nfacctd_bmp_msglog_amqp_routing_key && etype == BGP_LOGDUMP_ET_LOG) ||
      (config.bmp_dump_amqp_routing_key && etype == BGP_LOGDUMP_ET_DUMP)) {
#ifdef WITH_RABBITMQ
    p_amqp_set_routing_key(peer->log->amqp_host, peer->log->filename);
#endif
  }

  if ((config.nfacctd_bmp_msglog_kafka_topic && etype == BGP_LOGDUMP_ET_LOG) ||
      (config.bmp_dump_kafka_topic && etype == BGP_LOGDUMP_ET_DUMP)) {
#ifdef WITH_KAFKA
    p_kafka_set_topic(peer->log->kafka_host, peer->log->filename);
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
    }
    else if (etype == BGP_LOGDUMP_ET_DUMP) {
      json_object_set_new_nocheck(obj, "seq", json_integer((json_int_t) bgp_peer_log_seq_get(&bms->log_seq))); 

      json_object_set_new_nocheck(obj, "timestamp", json_string(bms->dump.tstamp_str));

      compose_timestamp(tstamp_str, SRVBUFLEN, &bdata->tstamp, TRUE,
			config.timestamps_since_epoch, config.timestamps_rfc3339,
			config.timestamps_utc);
      json_object_set_new_nocheck(obj, "event_timestamp", json_string(tstamp_str));
    }

    json_object_set_new_nocheck(obj, "bmp_router", json_string(peer->addr_str));

    json_object_set_new_nocheck(obj, "bmp_router_port", json_integer((json_int_t)peer->tcp_port));

    switch (log_type) {
    case BMP_LOG_TYPE_STATS:
      ret = bmp_log_msg_stats(peer, bdata, (struct bmp_log_stats *) log_data, event_type, output, obj);
      break;
    case BMP_LOG_TYPE_INIT:
      ret = bmp_log_msg_init(peer, bdata, (struct bmp_log_init_array *) log_data, event_type, output, obj);
      break;
    case BMP_LOG_TYPE_TERM:
      ret = bmp_log_msg_term(peer, bdata, (struct bmp_log_term_array *) log_data, event_type, output, obj);
      break;
    case BMP_LOG_TYPE_PEER_UP:
      ret = bmp_log_msg_peer_up(peer, bdata, (struct bmp_log_peer_up *) log_data, event_type, output, obj);
      break;
    case BMP_LOG_TYPE_PEER_DOWN:
      ret = bmp_log_msg_peer_down(peer, bdata, (struct bmp_log_peer_down *) log_data, event_type, output, obj);
      break;
    default:
      break;
    }

    if ((config.nfacctd_bmp_msglog_file && etype == BGP_LOGDUMP_ET_LOG) ||
	(config.bmp_dump_file && etype == BGP_LOGDUMP_ET_DUMP))
      write_and_free_json(peer->log->fd, obj);

    if ((config.nfacctd_bmp_msglog_amqp_routing_key && etype == BGP_LOGDUMP_ET_LOG) ||
	(config.bmp_dump_amqp_routing_key && etype == BGP_LOGDUMP_ET_DUMP)) {
      add_writer_name_and_pid_json(obj, config.proc_name, writer_pid);
#ifdef WITH_RABBITMQ
      amqp_ret = write_and_free_json_amqp(peer->log->amqp_host, obj);
      p_amqp_unset_routing_key(peer->log->amqp_host);
#endif
    }

    if ((config.nfacctd_bmp_msglog_kafka_topic && etype == BGP_LOGDUMP_ET_LOG) ||
        (config.bmp_dump_kafka_topic && etype == BGP_LOGDUMP_ET_DUMP)) {
      add_writer_name_and_pid_json(obj, config.proc_name, writer_pid);
#ifdef WITH_KAFKA
      kafka_ret = write_and_free_json_kafka(peer->log->kafka_host, obj);
      p_kafka_unset_topic(peer->log->kafka_host);
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
    void *avro_local_buf = NULL;

    char wid[SHORTSHORTBUFLEN], tstamp_str[SRVBUFLEN];

    avro_writer = avro_writer_memory(bms->avro_buf, LARGEBUFLEN);

    if (etype == BGP_LOGDUMP_ET_LOG) {
      avro_iface = avro_generic_class_from_schema(bms->msglog_avro_schema[log_type]);
    }
    else if (etype == BGP_LOGDUMP_ET_DUMP) {
      avro_iface = avro_generic_class_from_schema(bms->dump_avro_schema[log_type]);
    }

    pm_avro_check(avro_generic_value_new(avro_iface, &avro_obj));

    pm_avro_check(avro_value_get_by_name(&avro_obj, "event_type", &avro_field, NULL));
    pm_avro_check(avro_value_set_string(&avro_field, event_type));

    if (etype == BGP_LOGDUMP_ET_LOG) {
      pm_avro_check(avro_value_get_by_name(&avro_obj, "seq", &avro_field, NULL));
      pm_avro_check(avro_value_set_long(&avro_field, log_seq));

      compose_timestamp(tstamp_str, SRVBUFLEN, &bdata->tstamp, TRUE,
                        config.timestamps_since_epoch, config.timestamps_rfc3339,
                        config.timestamps_utc);
      pm_avro_check(avro_value_get_by_name(&avro_obj, "timestamp", &avro_field, NULL));
      pm_avro_check(avro_value_set_string(&avro_field, tstamp_str));

      pm_avro_check(avro_value_get_by_name(&avro_obj, "event_timestamp", &avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&avro_field, FALSE, &avro_branch));
    }
    else if (etype == BGP_LOGDUMP_ET_DUMP) {
      pm_avro_check(avro_value_get_by_name(&avro_obj, "seq", &avro_field, NULL));
      pm_avro_check(avro_value_set_long(&avro_field, bgp_peer_log_seq_get(&bms->log_seq)));

      pm_avro_check(avro_value_get_by_name(&avro_obj, "timestamp", &avro_field, NULL));
      pm_avro_check(avro_value_set_string(&avro_field, bms->dump.tstamp_str));

      compose_timestamp(tstamp_str, SRVBUFLEN, &bdata->tstamp, TRUE,
                        config.timestamps_since_epoch, config.timestamps_rfc3339,
                        config.timestamps_utc);
      pm_avro_check(avro_value_get_by_name(&avro_obj, "event_timestamp", &avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&avro_field, TRUE, &avro_branch));
      pm_avro_check(avro_value_set_string(&avro_branch, tstamp_str));
    }

    pm_avro_check(avro_value_get_by_name(&avro_obj, "bmp_router", &avro_field, NULL));
    pm_avro_check(avro_value_set_string(&avro_field, peer->addr_str));

    pm_avro_check(avro_value_get_by_name(&avro_obj, "bmp_router_port", &avro_field, NULL));
    pm_avro_check(avro_value_set_int(&avro_field, peer->tcp_port));

    switch (log_type) {
    case BMP_LOG_TYPE_STATS:
      ret = bmp_log_msg_stats(peer, bdata, (struct bmp_log_stats *) log_data, event_type, output, &avro_obj);
      break;
    case BMP_LOG_TYPE_INIT:
      ret = bmp_log_msg_init(peer, bdata, (struct bmp_log_init_array *) log_data, event_type, output, &avro_obj);
      break;
    case BMP_LOG_TYPE_TERM:
      ret = bmp_log_msg_term(peer, bdata, (struct bmp_log_term_array *) log_data, event_type, output, &avro_obj);
      break;
    case BMP_LOG_TYPE_PEER_UP:
      ret = bmp_log_msg_peer_up(peer, bdata, (struct bmp_log_peer_up *) log_data, event_type, output, &avro_obj);
      break;
    case BMP_LOG_TYPE_PEER_DOWN:
      ret = bmp_log_msg_peer_down(peer, bdata, (struct bmp_log_peer_down *) log_data, event_type, output, &avro_obj);
      break;
    default:
      break;
    }

    pm_avro_check(avro_value_get_by_name(&avro_obj, "writer_id", &avro_field, NULL));
    snprintf(wid, SHORTSHORTBUFLEN, "%s/%u", config.proc_name, writer_pid);
    pm_avro_check(avro_value_set_string(&avro_field, wid));

    if ((config.nfacctd_bmp_msglog_file && etype == BGP_LOGDUMP_ET_LOG) ||
        (config.bmp_dump_file && etype == BGP_LOGDUMP_ET_DUMP) ||
        (config.nfacctd_bmp_msglog_file && etype == BGP_LOGDUMP_ET_LOG) ||
        (config.bmp_dump_amqp_routing_key && etype == BGP_LOGDUMP_ET_DUMP) ||
        (config.nfacctd_bmp_msglog_kafka_topic && etype == BGP_LOGDUMP_ET_LOG && !bms->msglog_kafka_avro_schema_registry) ||
        (config.bmp_dump_kafka_topic && etype == BGP_LOGDUMP_ET_DUMP && !bms->dump_kafka_avro_schema_registry)) {
      avro_value_sizeof(&avro_obj, &avro_obj_len);
      assert(avro_obj_len < LARGEBUFLEN);

      if (avro_value_write(avro_writer, &avro_obj)) {
        Log(LOG_ERR, "ERROR ( %s/%s ): AVRO: unable to write value: %s\n", config.name, bms->log_str, avro_strerror());
        exit_gracefully(1);
      }

      avro_len = avro_writer_tell(avro_writer);
      avro_local_buf = bms->avro_buf;
    }

    if ((config.nfacctd_bmp_msglog_file && etype == BGP_LOGDUMP_ET_LOG) ||
        (config.bmp_dump_file && etype == BGP_LOGDUMP_ET_DUMP)) {
      write_file_binary(peer->log->fd, avro_local_buf, avro_len);
    }

    if ((config.nfacctd_bmp_msglog_amqp_routing_key && etype == BGP_LOGDUMP_ET_LOG) ||
        (config.bmp_dump_amqp_routing_key && etype == BGP_LOGDUMP_ET_DUMP)) {
#ifdef WITH_RABBITMQ
      amqp_ret = write_binary_amqp(peer->log->amqp_host, avro_local_buf, avro_len);
      p_amqp_unset_routing_key(peer->log->amqp_host);
#endif
    }

    if ((config.nfacctd_bmp_msglog_kafka_topic && etype == BGP_LOGDUMP_ET_LOG) ||
        (config.bmp_dump_kafka_topic && etype == BGP_LOGDUMP_ET_DUMP)) {
#ifdef WITH_KAFKA
      if ((bms->msglog_kafka_avro_schema_registry && etype == BGP_LOGDUMP_ET_LOG) ||
          (bms->dump_kafka_avro_schema_registry && etype == BGP_LOGDUMP_ET_DUMP)) {
#ifdef WITH_SERDES
	struct p_kafka_host *kafka_host = (struct p_kafka_host *) peer->log->kafka_host;

	if (serdes_schema_serialize_avro(kafka_host->sd_schema[log_type], &avro_obj, &avro_local_buf, &avro_len,
					 kafka_host->errstr, sizeof(kafka_host->errstr))) {
	  Log(LOG_ERR, "ERROR ( %s/%s ): AVRO: serdes_schema_serialize_avro() failed: %s\n", config.name, bms->log_str, kafka_host->errstr);
	  exit_gracefully(1);
	}
#endif
      }

      kafka_ret = write_binary_kafka(peer->log->kafka_host, avro_local_buf, avro_len);
      p_kafka_unset_topic(peer->log->kafka_host);
#endif
    }

    avro_value_decref(&avro_obj);
    avro_value_iface_decref(avro_iface);
    avro_writer_reset(avro_writer);
#endif
  }

  return (ret | amqp_ret | kafka_ret);
}

int bmp_log_msg_stats(struct bgp_peer *peer, struct bmp_data *bdata, struct bmp_log_stats *blstats, char *event_type, int output, void *vobj)
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

    if (bdata->chars.is_loc) {
      json_object_set_new_nocheck(obj, "is_filtered", json_integer((json_int_t)bdata->chars.is_filtered));
      json_object_set_new_nocheck(obj, "is_loc", json_integer((json_int_t)bdata->chars.is_loc));
    }
    else if (bdata->chars.is_out) {
      json_object_set_new_nocheck(obj, "is_post", json_integer((json_int_t)bdata->chars.is_post));
      json_object_set_new_nocheck(obj, "is_out", json_integer((json_int_t)bdata->chars.is_out));
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

    if (blstats->got_data) json_object_set_new_nocheck(obj, "counter_value", json_integer((json_int_t)blstats->cnt_data));
#endif
  }
  else if (output == PRINT_OUTPUT_AVRO) {
#ifdef WITH_AVRO
    avro_value_t *obj = (avro_value_t *) vobj, avro_field, avro_branch;
    char bmp_msg_type[] = "stats";
    char ip_address[INET6_ADDRSTRLEN];

    pm_avro_check(avro_value_get_by_name(obj, "bmp_msg_type", &avro_field, NULL));
    pm_avro_check(avro_value_set_string(&avro_field, bmp_msg_type));

    addr_to_str(ip_address, &bdata->peer_ip);
    pm_avro_check(avro_value_get_by_name(obj, "peer_ip", &avro_field, NULL));
    pm_avro_check(avro_value_set_string(&avro_field, ip_address));

    pm_avro_check(avro_value_get_by_name(obj, "peer_asn", &avro_field, NULL));
    pm_avro_check(avro_value_set_long(&avro_field, bdata->peer_asn));

    pm_avro_check(avro_value_get_by_name(obj, "peer_type", &avro_field, NULL));
    pm_avro_check(avro_value_set_int(&avro_field, bdata->chars.peer_type));

    if (bdata->chars.is_loc) {
      pm_avro_check(avro_value_get_by_name(obj, "is_filtered", &avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&avro_field, TRUE, &avro_branch));
      pm_avro_check(avro_value_set_int(&avro_branch, bdata->chars.is_filtered));

      pm_avro_check(avro_value_get_by_name(obj, "is_loc", &avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&avro_field, TRUE, &avro_branch));
      pm_avro_check(avro_value_set_int(&avro_branch, bdata->chars.is_loc));

      pm_avro_check(avro_value_get_by_name(obj, "is_post", &avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&avro_field, FALSE, &avro_branch));

      pm_avro_check(avro_value_get_by_name(obj, "is_out", &avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&avro_field, FALSE, &avro_branch));
    }
    else if (bdata->chars.is_out) {
      pm_avro_check(avro_value_get_by_name(obj, "is_filtered", &avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&avro_field, FALSE, &avro_branch));

      pm_avro_check(avro_value_get_by_name(obj, "is_loc", &avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&avro_field, FALSE, &avro_branch));

      pm_avro_check(avro_value_get_by_name(obj, "is_post", &avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&avro_field, TRUE, &avro_branch));
      pm_avro_check(avro_value_set_int(&avro_branch, bdata->chars.is_post));

      pm_avro_check(avro_value_get_by_name(obj, "is_out", &avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&avro_field, TRUE, &avro_branch));
      pm_avro_check(avro_value_set_int(&avro_branch, bdata->chars.is_out));
    }
    else {
      pm_avro_check(avro_value_get_by_name(obj, "is_filtered", &avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&avro_field, FALSE, &avro_branch));

      pm_avro_check(avro_value_get_by_name(obj, "is_loc", &avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&avro_field, FALSE, &avro_branch));

      pm_avro_check(avro_value_get_by_name(obj, "is_post", &avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&avro_field, FALSE, &avro_branch));

      pm_avro_check(avro_value_get_by_name(obj, "is_out", &avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&avro_field, FALSE, &avro_branch));
    }

    pm_avro_check(avro_value_get_by_name(obj, "counter_type", &avro_field, NULL));
    pm_avro_check(avro_value_set_int(&avro_field, blstats->cnt_type));

    if (blstats->cnt_type <= BMP_STATS_MAX) {
      pm_avro_check(avro_value_get_by_name(obj, "counter_type_str", &avro_field, NULL));
      pm_avro_check(avro_value_set_string(&avro_field, bmp_stats_cnt_types[blstats->cnt_type]));
    }
    else {
      pm_avro_check(avro_value_get_by_name(obj, "counter_type_str", &avro_field, NULL));
      pm_avro_check(avro_value_set_string(&avro_field, "Unknown"));
    }

    if (blstats->cnt_type == BMP_STATS_TYPE9 || blstats->cnt_type == BMP_STATS_TYPE10) {
      pm_avro_check(avro_value_get_by_name(obj, "afi", &avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&avro_field, TRUE, &avro_branch));
      pm_avro_check(avro_value_set_int(&avro_branch, blstats->cnt_afi));

      pm_avro_check(avro_value_get_by_name(obj, "safi", &avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&avro_field, TRUE, &avro_branch));
      pm_avro_check(avro_value_set_int(&avro_branch, blstats->cnt_safi));
    }
    else {
      pm_avro_check(avro_value_get_by_name(obj, "afi", &avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&avro_field, FALSE, &avro_branch));

      pm_avro_check(avro_value_get_by_name(obj, "safi", &avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&avro_field, FALSE, &avro_branch));
    }

    pm_avro_check(avro_value_get_by_name(obj, "counter_value", &avro_field, NULL));
    pm_avro_check(avro_value_set_long(&avro_field, blstats->cnt_data));
#endif
  }

  return ret;
}

int bmp_log_msg_init(struct bgp_peer *peer, struct bmp_data *bdata, struct bmp_log_init_array *blinit, char *event_type, int output, void *vobj)
{
  int ret = 0;

  if (!peer || !vobj) return ERR;

  if (output == PRINT_OUTPUT_JSON) {
#ifdef WITH_JANSSON
    int idx = 0;
    char bmp_msg_type[] = "init";
    json_t *obj = (json_t *) vobj;

    json_object_set_new_nocheck(obj, "bmp_msg_type", json_string(bmp_msg_type));

    if (blinit) {
      while (idx < blinit->entries) { 
	char *type = NULL, *value = NULL;

	type = bmp_tlv_type_print(blinit->e[idx].type, "bmp_init_info", bmp_init_info_types, BMP_INIT_INFO_ENTRIES);
	value = null_terminate(blinit->e[idx].val, blinit->e[idx].len);
	json_object_set_new_nocheck(obj, type, json_string(value));
	free(type);
	free(value);

	idx++;
      }
    }
#endif
  }
  else if (output == PRINT_OUTPUT_AVRO) {
#ifdef WITH_AVRO
    int idx = 0, bmp_init_tlvs[BMP_INIT_INFO_MAX + 1];
    avro_value_t *obj = (avro_value_t *) vobj, avro_field, avro_branch;
    char bmp_msg_type[] = "init";

    pm_avro_check(avro_value_get_by_name(obj, "bmp_msg_type", &avro_field, NULL));
    pm_avro_check(avro_value_set_string(&avro_field, bmp_msg_type));

    memset(&bmp_init_tlvs, 0, sizeof(bmp_init_tlvs));

    if (blinit) {
      while (idx < blinit->entries) {
	char *type = NULL, *value = NULL;

	if (blinit->e[idx].type <= BMP_INIT_INFO_MAX) {
	  type = bmp_tlv_type_print(blinit->e[idx].type, "bmp_init_info", bmp_init_info_types, BMP_INIT_INFO_ENTRIES);
	  value = null_terminate(blinit->e[idx].val, blinit->e[idx].len);

	  pm_avro_check(avro_value_get_by_name(obj, type, &avro_field, NULL));
	  pm_avro_check(avro_value_set_branch(&avro_field, TRUE, &avro_branch));
	  pm_avro_check(avro_value_set_string(&avro_branch, value));

	  free(type);
	  free(value);

	  bmp_init_tlvs[blinit->e[idx].type] = TRUE;
	}

	idx++;
      }
    }

    /* mark missing tlv types */
    for (idx = 0; idx <= BMP_INIT_INFO_MAX; idx++) {
      char *type;

      if (!bmp_init_tlvs[idx]) {
	type = bmp_tlv_type_print(idx, "bmp_init_info", bmp_init_info_types, BMP_INIT_INFO_ENTRIES);
	pm_avro_check(avro_value_get_by_name(obj, type, &avro_field, NULL));
	pm_avro_check(avro_value_set_branch(&avro_field, FALSE, &avro_branch));
      }
    }
#endif
  }

  return ret;
}

int bmp_log_msg_term(struct bgp_peer *peer, struct bmp_data *bdata, struct bmp_log_term_array *blterm, char *event_type, int output, void *vobj)
{
  int ret = 0;

  if (!peer || !vobj) return ERR;

  if (output == PRINT_OUTPUT_JSON) {
#ifdef WITH_JANSSON
    char bmp_msg_type[] = "term";
    int idx = 0;
    json_t *obj = (json_t *) vobj;

    json_object_set_new_nocheck(obj, "bmp_msg_type", json_string(bmp_msg_type));

    if (blterm) {
      while (idx < blterm->entries) {
	char *type = NULL, *value = NULL;

	type = bmp_tlv_type_print(blterm->e[idx].type, "bmp_term_info", bmp_term_info_types, BMP_TERM_INFO_ENTRIES);

	if (blterm->e[idx].type == BMP_TERM_INFO_REASON) {
	  value = bmp_term_reason_print(blterm->e[idx].reas_type);
	}
	else {
	  value = null_terminate(blterm->e[idx].val, blterm->e[idx].len);
	}

        json_object_set_new_nocheck(obj, type, json_string(value));
        free(type);
        free(value);

        idx++;
      }
    }
#endif
  }
  else if (output == PRINT_OUTPUT_AVRO) {
#ifdef WITH_AVRO
    int idx = 0, bmp_term_tlvs[BMP_TERM_INFO_MAX + 1];
    avro_value_t *obj = (avro_value_t *) vobj, avro_field, avro_branch;
    char bmp_msg_type[] = "term";

    pm_avro_check(avro_value_get_by_name(obj, "bmp_msg_type", &avro_field, NULL));
    pm_avro_check(avro_value_set_string(&avro_field, bmp_msg_type));

    memset(&bmp_term_tlvs, 0, sizeof(bmp_term_tlvs));

    if (blterm) {
      while (idx < blterm->entries) {
	char *type = NULL, *value = NULL;

	if (blterm->e[idx].type <= BMP_TERM_INFO_MAX) {
	  type = bmp_tlv_type_print(blterm->e[idx].type, "bmp_term_info", bmp_term_info_types, BMP_TERM_INFO_ENTRIES);

	  if (blterm->e[idx].type == BMP_TERM_INFO_REASON) {
	    value = bmp_term_reason_print(blterm->e[idx].reas_type);
	  }
	  else {
	    value = null_terminate(blterm->e[idx].val, blterm->e[idx].len);
	  }

	  pm_avro_check(avro_value_get_by_name(obj, type, &avro_field, NULL));
	  pm_avro_check(avro_value_set_branch(&avro_field, TRUE, &avro_branch));
	  pm_avro_check(avro_value_set_string(&avro_branch, value));

	  free(type);
	  free(value);

	  bmp_term_tlvs[blterm->e[idx].type] = TRUE;
	}

	idx++;
      }
    }

    /* mark missing tlv types */
    for (idx = 0; idx <= BMP_TERM_INFO_MAX; idx++) {
      char *type;

      if (!bmp_term_tlvs[idx]) {
        type = bmp_tlv_type_print(idx, "bmp_term_info", bmp_term_info_types, BMP_TERM_INFO_ENTRIES);
        pm_avro_check(avro_value_get_by_name(obj, type, &avro_field, NULL));
        pm_avro_check(avro_value_set_branch(&avro_field, FALSE, &avro_branch));
      }
    }
#endif
  }

  return ret;
}

int bmp_log_msg_peer_up(struct bgp_peer *peer, struct bmp_data *bdata, struct bmp_log_peer_up *blpu, char *event_type, int output, void *vobj)
{
  int ret = 0;

  if (!peer || !bdata || !blpu || !vobj) return ERR;

  if (output == PRINT_OUTPUT_JSON) {
#ifdef WITH_JANSSON
    char bmp_msg_type[] = "peer_up";
    char ip_address[INET6_ADDRSTRLEN];
    int idx = 0;
    json_t *obj = (json_t *) vobj;

    json_object_set_new_nocheck(obj, "bmp_msg_type", json_string(bmp_msg_type));

    addr_to_str(ip_address, &bdata->peer_ip);
    json_object_set_new_nocheck(obj, "peer_ip", json_string(ip_address));

    json_object_set_new_nocheck(obj, "peer_asn", json_integer((json_int_t)bdata->peer_asn));
    json_object_set_new_nocheck(obj, "peer_type", json_integer((json_int_t)bdata->chars.peer_type));

    if (bdata->chars.peer_type <= BMP_PEER_TYPE_MAX) {
      json_object_set_new_nocheck(obj, "peer_type_str", json_string(bmp_peer_types[bdata->chars.peer_type]));
    }

    if (bdata->chars.is_loc) {
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

    while (idx < blpu->tlv.entries) {
      char *type = NULL, *value = NULL;

      type = bmp_tlv_type_print(blpu->tlv.e[idx].type, "bmp_peer_up_info", bmp_peer_up_info_types, BMP_PEER_UP_INFO_ENTRIES);
      value = null_terminate(blpu->tlv.e[idx].val, blpu->tlv.e[idx].len);
      json_object_set_new_nocheck(obj, type, json_string(value));
      free(type);
      free(value);

      idx++;
    }
#endif
  }
  else if (output == PRINT_OUTPUT_AVRO) {
#ifdef WITH_AVRO
    int idx = 0, bmp_peer_up_tlvs[BMP_PEER_UP_INFO_MAX + 1];
    avro_value_t *obj = (avro_value_t *) vobj, avro_field, avro_branch;
    char bmp_msg_type[] = "peer_up";
    char ip_address[INET6_ADDRSTRLEN];

    pm_avro_check(avro_value_get_by_name(obj, "bmp_msg_type", &avro_field, NULL));
    pm_avro_check(avro_value_set_string(&avro_field, bmp_msg_type));

    addr_to_str(ip_address, &bdata->peer_ip);
    pm_avro_check(avro_value_get_by_name(obj, "peer_ip", &avro_field, NULL));
    pm_avro_check(avro_value_set_string(&avro_field, ip_address));

    pm_avro_check(avro_value_get_by_name(obj, "peer_asn", &avro_field, NULL));
    pm_avro_check(avro_value_set_long(&avro_field, bdata->peer_asn));

    pm_avro_check(avro_value_get_by_name(obj, "peer_type", &avro_field, NULL));
    pm_avro_check(avro_value_set_int(&avro_field, bdata->chars.peer_type));

    if (bdata->chars.peer_type <= BMP_PEER_TYPE_MAX) {
      pm_avro_check(avro_value_get_by_name(obj, "peer_type_str", &avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&avro_field, TRUE, &avro_branch));
      pm_avro_check(avro_value_set_string(&avro_branch, bmp_peer_types[bdata->chars.peer_type]));
    }
    else {
      pm_avro_check(avro_value_get_by_name(obj, "peer_type_str", &avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&avro_field, FALSE, &avro_branch));
    }

    if (bdata->chars.is_loc) {
      pm_avro_check(avro_value_get_by_name(obj, "is_filtered", &avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&avro_field, TRUE, &avro_branch));
      pm_avro_check(avro_value_set_int(&avro_branch, bdata->chars.is_filtered));

      pm_avro_check(avro_value_get_by_name(obj, "is_loc", &avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&avro_field, TRUE, &avro_branch));
      pm_avro_check(avro_value_set_int(&avro_branch, bdata->chars.is_loc));

      pm_avro_check(avro_value_get_by_name(obj, "is_post", &avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&avro_field, FALSE, &avro_branch));

      pm_avro_check(avro_value_get_by_name(obj, "is_out", &avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&avro_field, FALSE, &avro_branch));
    }
    else if (bdata->chars.is_out) {
      pm_avro_check(avro_value_get_by_name(obj, "is_filtered", &avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&avro_field, FALSE, &avro_branch));

      pm_avro_check(avro_value_get_by_name(obj, "is_loc", &avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&avro_field, FALSE, &avro_branch));

      pm_avro_check(avro_value_get_by_name(obj, "is_post", &avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&avro_field, TRUE, &avro_branch));
      pm_avro_check(avro_value_set_int(&avro_branch, bdata->chars.is_post));

      pm_avro_check(avro_value_get_by_name(obj, "is_out", &avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&avro_field, TRUE, &avro_branch));
      pm_avro_check(avro_value_set_int(&avro_branch, bdata->chars.is_out));
    }
    else {
      pm_avro_check(avro_value_get_by_name(obj, "is_filtered", &avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&avro_field, FALSE, &avro_branch));

      pm_avro_check(avro_value_get_by_name(obj, "is_loc", &avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&avro_field, FALSE, &avro_branch));

      pm_avro_check(avro_value_get_by_name(obj, "is_post", &avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&avro_field, FALSE, &avro_branch));

      pm_avro_check(avro_value_get_by_name(obj, "is_out", &avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&avro_field, FALSE, &avro_branch));
    }

    pm_avro_check(avro_value_get_by_name(obj, "bgp_id", &avro_field, NULL));
    pm_avro_check(avro_value_set_string(&avro_field, inet_ntoa(bdata->bgp_id.address.ipv4)));

    pm_avro_check(avro_value_get_by_name(obj, "local_port", &avro_field, NULL));
    pm_avro_check(avro_value_set_int(&avro_field, blpu->loc_port));

    pm_avro_check(avro_value_get_by_name(obj, "remote_port", &avro_field, NULL));
    pm_avro_check(avro_value_set_int(&avro_field, blpu->rem_port));

    addr_to_str(ip_address, &blpu->local_ip);
    pm_avro_check(avro_value_get_by_name(obj, "local_ip", &avro_field, NULL));
    pm_avro_check(avro_value_set_string(&avro_field, ip_address));

    memset(&bmp_peer_up_tlvs, 0, sizeof(bmp_peer_up_tlvs));

    while (idx < blpu->tlv.entries) {
      char *type = NULL, *value = NULL;

      if (blpu->tlv.e[idx].type <= BMP_PEER_UP_INFO_MAX) {
	type = bmp_tlv_type_print(blpu->tlv.e[idx].type, "bmp_peer_up_info", bmp_peer_up_info_types, BMP_PEER_UP_INFO_ENTRIES);
	value = null_terminate(blpu->tlv.e[idx].val, blpu->tlv.e[idx].len);

	pm_avro_check(avro_value_get_by_name(obj, type, &avro_field, NULL));
	pm_avro_check(avro_value_set_branch(&avro_field, TRUE, &avro_branch));
	pm_avro_check(avro_value_set_string(&avro_branch, value));

	free(type);
	free(value);

	bmp_peer_up_tlvs[blpu->tlv.e[idx].type] = TRUE;
      }

      idx++;
    }

    /* mark missing tlv types */
    for (idx = 0; idx <= BMP_PEER_UP_INFO_MAX; idx++) {
      char *type;

      if (!bmp_peer_up_tlvs[idx]) {
        type = bmp_tlv_type_print(idx, "bmp_peer_up_info", bmp_peer_up_info_types, BMP_PEER_UP_INFO_ENTRIES);
        pm_avro_check(avro_value_get_by_name(obj, type, &avro_field, NULL));
        pm_avro_check(avro_value_set_branch(&avro_field, FALSE, &avro_branch));
      }
    }
#endif
  }

  return ret;
}

int bmp_log_msg_peer_down(struct bgp_peer *peer, struct bmp_data *bdata, struct bmp_log_peer_down *blpd, char *event_type, int output, void *vobj)
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

    json_object_set_new_nocheck(obj, "reason_type", json_integer((json_int_t)blpd->reason));

    if (blpd->reason <= BMP_PEER_DOWN_MAX) {
      json_object_set_new_nocheck(obj, "reason_str", json_string(bmp_peer_down_reason_types[blpd->reason]));
    }

    if (blpd->reason == BMP_PEER_DOWN_LOC_CODE) {
      json_object_set_new_nocheck(obj, "reason_loc_code", json_integer((json_int_t)blpd->loc_code));
    }
#endif
  }
  else if (output == PRINT_OUTPUT_AVRO) {
#ifdef WITH_AVRO
    avro_value_t *obj = (avro_value_t *) vobj, avro_field, avro_branch;
    char bmp_msg_type[] = "peer_down";
    char ip_address[INET6_ADDRSTRLEN];

    pm_avro_check(avro_value_get_by_name(obj, "bmp_msg_type", &avro_field, NULL));
    pm_avro_check(avro_value_set_string(&avro_field, bmp_msg_type));

    addr_to_str(ip_address, &bdata->peer_ip);
    pm_avro_check(avro_value_get_by_name(obj, "peer_ip", &avro_field, NULL));
    pm_avro_check(avro_value_set_string(&avro_field, ip_address));

    pm_avro_check(avro_value_get_by_name(obj, "peer_asn", &avro_field, NULL));
    pm_avro_check(avro_value_set_long(&avro_field, bdata->peer_asn));

    pm_avro_check(avro_value_get_by_name(obj, "peer_type", &avro_field, NULL));
    pm_avro_check(avro_value_set_int(&avro_field, bdata->chars.peer_type));

    if (bdata->chars.peer_type <= BMP_PEER_TYPE_MAX) {
      pm_avro_check(avro_value_get_by_name(obj, "peer_type_str", &avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&avro_field, TRUE, &avro_branch));
      pm_avro_check(avro_value_set_string(&avro_branch, bmp_peer_types[bdata->chars.peer_type]));
    }
    else {
      pm_avro_check(avro_value_get_by_name(obj, "peer_type_str", &avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&avro_field, FALSE, &avro_branch));
    }

    pm_avro_check(avro_value_get_by_name(obj, "reason_type", &avro_field, NULL));
    pm_avro_check(avro_value_set_int(&avro_field, blpd->reason));

    if (blpd->reason <= BMP_PEER_DOWN_MAX) {
      pm_avro_check(avro_value_get_by_name(obj, "reason_str", &avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&avro_field, TRUE, &avro_branch));
      pm_avro_check(avro_value_set_string(&avro_branch, bmp_peer_down_reason_types[blpd->reason]));
    }
    else {
      pm_avro_check(avro_value_get_by_name(obj, "reason_str", &avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&avro_field, FALSE, &avro_branch));
    }

    if (blpd->reason == BMP_PEER_DOWN_LOC_CODE) {
      pm_avro_check(avro_value_get_by_name(obj, "reason_loc_code", &avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&avro_field, TRUE, &avro_branch));
      pm_avro_check(avro_value_set_int(&avro_branch, blpd->loc_code));
    }
    else {
      pm_avro_check(avro_value_get_by_name(obj, "reason_loc_code", &avro_field, NULL));
      pm_avro_check(avro_value_set_branch(&avro_field, FALSE, &avro_branch));
    }
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

void bmp_dump_se_ll_append(struct bgp_peer *peer, struct bmp_data *bdata, void *extra, int log_type)
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
    case BMP_LOG_TYPE_INIT:
      memcpy(&se_ll_elem->rec.se.init, extra, sizeof(struct bmp_log_init_array));
      break;
    case BMP_LOG_TYPE_TERM:
      memcpy(&se_ll_elem->rec.se.term, extra, sizeof(struct bmp_log_term_array));
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
    se_ll_elem_next = se_ll_elem->next;
    free(se_ll_elem);
  }

  bdsell->start = NULL;
  bdsell->last = NULL;
}

void bmp_handle_dump_event()
{
  struct bgp_misc_structs *bms = bgp_select_misc_db(FUNC_TYPE_BMP);
  char current_filename[SRVBUFLEN], last_filename[SRVBUFLEN], tmpbuf[SRVBUFLEN];
  char latest_filename[SRVBUFLEN], event_type[] = "dump", *fd_buf = NULL;
  int ret, peers_idx, duration, tables_num;
  struct bgp_rt_structs *inter_domain_routing_db;
  struct bgp_table *table;
  struct bgp_node *node;
  afi_t afi;
  safi_t safi;
  pid_t dumper_pid;
  time_t start;
  u_int64_t dump_elems = 0, dump_seqno;

  struct bgp_peer *peer, *saved_peer;
  struct bmp_dump_se_ll *bdsell;
  struct bgp_peer_log peer_log;      

  /* pre-flight check */
  if (!bms->dump_backend_methods || !config.bmp_dump_refresh_time)
    return;

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

    memset(last_filename, 0, sizeof(last_filename));
    memset(current_filename, 0, sizeof(current_filename));

    fd_buf = malloc(OUTPUT_FILE_BUFSZ);
    bgp_peer_log_seq_set(&bms->log_seq, dump_seqno);

#ifdef WITH_RABBITMQ
    if (config.bmp_dump_amqp_routing_key) {
      bmp_dump_init_amqp_host();
      ret = p_amqp_connect_to_publish(&bmp_dump_amqp_host);
      if (ret) exit_gracefully(ret);
    }
#endif

#ifdef WITH_KAFKA
    if (config.bmp_dump_kafka_topic) {
      ret = bmp_dump_init_kafka_host();
      if (ret) exit_gracefully(ret);
    }
#endif

    dumper_pid = getpid();
    Log(LOG_INFO, "INFO ( %s/%s ): *** Dumping BMP tables - START (PID: %u) ***\n", config.name, bms->log_str, dumper_pid);
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

    for (peer = NULL, saved_peer = NULL, peers_idx = 0; peers_idx < config.nfacctd_bmp_max_peers; peers_idx++) {
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
              if (setvbuf(peer->log->fd, fd_buf, _IOFBF, OUTPUT_FILE_BUFSZ))
		Log(LOG_WARNING, "WARN ( %s/%s ): [%s] setvbuf() failed: %s\n", config.name, bms->log_str, current_filename, strerror(errno));
              else memset(fd_buf, 0, OUTPUT_FILE_BUFSZ);
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
        }
#endif

	bgp_peer_dump_init(peer, config.bmp_dump_output, FUNC_TYPE_BMP);
	inter_domain_routing_db = bgp_select_routing_db(FUNC_TYPE_BMP);
        dump_elems = 0;

        if (!inter_domain_routing_db) return;

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
		    char peer_str[] = "peer_ip", *saved_peer_str = bms->peer_str;
		    char peer_port_str[] = "peer_tcp_port", *saved_peer_port_str = bms->peer_port_str;

		    ri->peer->log = peer->log;
		    bms->peer_str = peer_str;
		    bms->peer_port_str = peer_port_str;
                    bgp_peer_log_msg(node, ri, afi, safi, event_type, config.bmp_dump_output, NULL, BGP_LOG_TYPE_MISC);
		    bms->peer_str = saved_peer_str;
		    bms->peer_port_str = saved_peer_port_str;
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
	      bmp_log_msg(peer, &se_ll_elem->rec.bdata, &se_ll_elem->rec.se.stats, se_ll_elem->rec.seq, event_type, config.bmp_dump_output, BMP_LOG_TYPE_STATS);
	      break;
	    case BMP_LOG_TYPE_INIT:
	      bmp_log_msg(peer, &se_ll_elem->rec.bdata, &se_ll_elem->rec.se.init, se_ll_elem->rec.seq, event_type, config.bmp_dump_output, BMP_LOG_TYPE_INIT);
	      break;
	    case BMP_LOG_TYPE_TERM:
	      bmp_log_msg(peer, &se_ll_elem->rec.bdata, &se_ll_elem->rec.se.term, se_ll_elem->rec.seq, event_type, config.bmp_dump_output, BMP_LOG_TYPE_TERM);
	      break;
	    case BMP_LOG_TYPE_PEER_UP:
	      bmp_log_msg(peer, &se_ll_elem->rec.bdata, &se_ll_elem->rec.se.peer_up, se_ll_elem->rec.seq, event_type, config.bmp_dump_output, BMP_LOG_TYPE_PEER_UP);
	      break;
	    case BMP_LOG_TYPE_PEER_DOWN:
	      bmp_log_msg(peer, &se_ll_elem->rec.bdata, &se_ll_elem->rec.se.peer_down, se_ll_elem->rec.seq, event_type, config.bmp_dump_output, BMP_LOG_TYPE_PEER_DOWN);
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
    if (config.bmp_dump_amqp_routing_key)
      p_amqp_close(&bmp_dump_amqp_host, FALSE);
#endif

#ifdef WITH_KAFKA
    if (config.bmp_dump_kafka_topic)
      p_kafka_close(&bmp_dump_kafka_host, FALSE);
#endif

    if (config.bmp_dump_latest_file && peer) {
      bgp_peer_log_dynname(latest_filename, SRVBUFLEN, config.bmp_dump_latest_file, peer);
      link_latest_output_file(latest_filename, last_filename);
    }

    duration = time(NULL)-start;
    Log(LOG_INFO, "INFO ( %s/%s ): *** Dumping BMP tables - END (PID: %u TABLES: %u ENTRIES: %" PRIu64 " ET: %u) ***\n",
                config.name, bms->log_str, dumper_pid, tables_num, dump_elems, duration);

    exit_gracefully(0);
  default: /* Parent */
    if (ret == -1) { /* Something went wrong */
      Log(LOG_WARNING, "WARN ( %s/%s ): Unable to fork BMP table dump writer: %s\n",
		config.name, bms->log_str, strerror(errno));
    }

    /* destroy bmp_se linked-list content after dump event */
    for (peer = NULL, peers_idx = 0; peers_idx < config.nfacctd_bmp_max_peers; peers_idx++) {
      if (bmp_peers[peers_idx].self.fd) {
        peer = &bmp_peers[peers_idx].self;
        bdsell = peer->bmp_se;

	if (bdsell && bdsell->start) bmp_dump_se_ll_destroy(bdsell);
      }
    }

    break;
  }
}

#if defined WITH_RABBITMQ
void bmp_daemon_msglog_init_amqp_host()
{
  p_amqp_init_host(&bmp_daemon_msglog_amqp_host);

  if (!config.nfacctd_bmp_msglog_amqp_user) config.nfacctd_bmp_msglog_amqp_user = rabbitmq_user;
  if (!config.nfacctd_bmp_msglog_amqp_passwd) config.nfacctd_bmp_msglog_amqp_passwd = rabbitmq_pwd;
  if (!config.nfacctd_bmp_msglog_amqp_exchange) config.nfacctd_bmp_msglog_amqp_exchange = default_amqp_exchange;
  if (!config.nfacctd_bmp_msglog_amqp_exchange_type) config.nfacctd_bmp_msglog_amqp_exchange_type = default_amqp_exchange_type;
  if (!config.nfacctd_bmp_msglog_amqp_host) config.nfacctd_bmp_msglog_amqp_host = default_amqp_host;
  if (!config.nfacctd_bmp_msglog_amqp_vhost) config.nfacctd_bmp_msglog_amqp_vhost = default_amqp_vhost;
  if (!config.nfacctd_bmp_msglog_amqp_retry) config.nfacctd_bmp_msglog_amqp_retry = AMQP_DEFAULT_RETRY;

  p_amqp_set_user(&bmp_daemon_msglog_amqp_host, config.nfacctd_bmp_msglog_amqp_user);
  p_amqp_set_passwd(&bmp_daemon_msglog_amqp_host, config.nfacctd_bmp_msglog_amqp_passwd);
  p_amqp_set_exchange(&bmp_daemon_msglog_amqp_host, config.nfacctd_bmp_msglog_amqp_exchange);
  p_amqp_set_exchange_type(&bmp_daemon_msglog_amqp_host, config.nfacctd_bmp_msglog_amqp_exchange_type);
  p_amqp_set_host(&bmp_daemon_msglog_amqp_host, config.nfacctd_bmp_msglog_amqp_host);
  p_amqp_set_vhost(&bmp_daemon_msglog_amqp_host, config.nfacctd_bmp_msglog_amqp_vhost);
  p_amqp_set_persistent_msg(&bmp_daemon_msglog_amqp_host, config.nfacctd_bmp_msglog_amqp_persistent_msg);
  p_amqp_set_frame_max(&bmp_daemon_msglog_amqp_host, config.nfacctd_bmp_msglog_amqp_frame_max);
  p_amqp_set_content_type_json(&bmp_daemon_msglog_amqp_host);
  p_amqp_set_heartbeat_interval(&bmp_daemon_msglog_amqp_host, config.nfacctd_bmp_msglog_amqp_heartbeat_interval);
  P_broker_timers_set_retry_interval(&bmp_daemon_msglog_amqp_host.btimers, config.nfacctd_bmp_msglog_amqp_retry);
}
#else
void bmp_daemon_msglog_init_amqp_host()
{
}
#endif

#if defined WITH_RABBITMQ
void bmp_dump_init_amqp_host()
{
  p_amqp_init_host(&bmp_dump_amqp_host);

  if (!config.bmp_dump_amqp_user) config.bmp_dump_amqp_user = rabbitmq_user;
  if (!config.bmp_dump_amqp_passwd) config.bmp_dump_amqp_passwd = rabbitmq_pwd;
  if (!config.bmp_dump_amqp_exchange) config.bmp_dump_amqp_exchange = default_amqp_exchange;
  if (!config.bmp_dump_amqp_exchange_type) config.bmp_dump_amqp_exchange_type = default_amqp_exchange_type;
  if (!config.bmp_dump_amqp_host) config.bmp_dump_amqp_host = default_amqp_host;
  if (!config.bmp_dump_amqp_vhost) config.bmp_dump_amqp_vhost = default_amqp_vhost;

  p_amqp_set_user(&bmp_dump_amqp_host, config.bmp_dump_amqp_user);
  p_amqp_set_passwd(&bmp_dump_amqp_host, config.bmp_dump_amqp_passwd);
  p_amqp_set_exchange(&bmp_dump_amqp_host, config.bmp_dump_amqp_exchange);
  p_amqp_set_exchange_type(&bmp_dump_amqp_host, config.bmp_dump_amqp_exchange_type);
  p_amqp_set_host(&bmp_dump_amqp_host, config.bmp_dump_amqp_host);
  p_amqp_set_vhost(&bmp_dump_amqp_host, config.bmp_dump_amqp_vhost);
  p_amqp_set_persistent_msg(&bmp_dump_amqp_host, config.bmp_dump_amqp_persistent_msg);
  p_amqp_set_frame_max(&bmp_dump_amqp_host, config.bmp_dump_amqp_frame_max);
  p_amqp_set_content_type_json(&bmp_dump_amqp_host);
  p_amqp_set_heartbeat_interval(&bmp_dump_amqp_host, config.bmp_dump_amqp_heartbeat_interval);
}
#else
void bmp_dump_init_amqp_host()
{
}
#endif

#if defined WITH_KAFKA
int bmp_daemon_msglog_init_kafka_host()
{
  int ret;

  p_kafka_init_host(&bmp_daemon_msglog_kafka_host, config.nfacctd_bmp_msglog_kafka_config_file);
  ret = p_kafka_connect_to_produce(&bmp_daemon_msglog_kafka_host);

  if (!config.nfacctd_bmp_msglog_kafka_broker_host) config.nfacctd_bmp_msglog_kafka_broker_host = default_kafka_broker_host;
  if (!config.nfacctd_bmp_msglog_kafka_broker_port) config.nfacctd_bmp_msglog_kafka_broker_port = default_kafka_broker_port;
  if (!config.nfacctd_bmp_msglog_kafka_retry) config.nfacctd_bmp_msglog_kafka_retry = PM_KAFKA_DEFAULT_RETRY;

  p_kafka_set_broker(&bmp_daemon_msglog_kafka_host, config.nfacctd_bmp_msglog_kafka_broker_host, config.nfacctd_bmp_msglog_kafka_broker_port);
  p_kafka_set_topic(&bmp_daemon_msglog_kafka_host, config.nfacctd_bmp_msglog_kafka_topic);
  p_kafka_set_partition(&bmp_daemon_msglog_kafka_host, config.nfacctd_bmp_msglog_kafka_partition);
  p_kafka_set_key(&bmp_daemon_msglog_kafka_host, config.nfacctd_bmp_msglog_kafka_partition_key, config.nfacctd_bmp_msglog_kafka_partition_keylen);
  p_kafka_set_content_type(&bmp_daemon_msglog_kafka_host, PM_KAFKA_CNT_TYPE_STR);
  P_broker_timers_set_retry_interval(&bmp_daemon_msglog_kafka_host.btimers, config.nfacctd_bmp_msglog_kafka_retry);

  return ret;
}
#else
int bmp_daemon_msglog_init_kafka_host()
{
  return ERR;
}
#endif

#if defined WITH_KAFKA
int bmp_dump_init_kafka_host()
{
  int ret;

  p_kafka_init_host(&bmp_dump_kafka_host, config.bmp_dump_kafka_config_file);
  ret = p_kafka_connect_to_produce(&bmp_dump_kafka_host);

  if (!config.bmp_dump_kafka_broker_host) config.bmp_dump_kafka_broker_host = default_kafka_broker_host;
  if (!config.bmp_dump_kafka_broker_port) config.bmp_dump_kafka_broker_port = default_kafka_broker_port;

  p_kafka_set_broker(&bmp_dump_kafka_host, config.bmp_dump_kafka_broker_host, config.bmp_dump_kafka_broker_port);
  p_kafka_set_topic(&bmp_dump_kafka_host, config.bmp_dump_kafka_topic);
  p_kafka_set_partition(&bmp_dump_kafka_host, config.bmp_dump_kafka_partition);
  p_kafka_set_key(&bmp_dump_kafka_host, config.bmp_dump_kafka_partition_key, config.bmp_dump_kafka_partition_keylen);
  p_kafka_set_content_type(&bmp_dump_kafka_host, PM_KAFKA_CNT_TYPE_STR);

  return ret;
}
#else
int bmp_dump_init_kafka_host()
{
  return ERR;
}
#endif

#if defined WITH_AVRO
avro_schema_t avro_schema_build_bmp_rm(int log_type, char *schema_name)
{
  avro_schema_t schema = NULL;
  avro_schema_t optlong_s = avro_schema_union();
  avro_schema_t optstr_s = avro_schema_union();
  avro_schema_t optint_s = avro_schema_union();

  if (log_type != BGP_LOGDUMP_ET_LOG && log_type != BGP_LOGDUMP_ET_DUMP) return NULL;

  avro_schema_init_bgp(&schema, &optlong_s, &optstr_s, &optint_s, FUNC_TYPE_BMP, schema_name);
  avro_schema_build_bgp_common(&schema, &optlong_s, &optstr_s, &optint_s, log_type, FUNC_TYPE_BMP);
  avro_schema_build_bgp_route(&schema, &optlong_s, &optstr_s, &optint_s);

  /* also cherry-picking from avro_schema_build_bmp_common() */ 
  avro_schema_record_field_append(schema, "peer_ip", avro_schema_string());
  avro_schema_record_field_append(schema, "peer_tcp_port", optint_s);

  avro_schema_record_field_append(schema, "bmp_router", avro_schema_string());
  avro_schema_record_field_append(schema, "bmp_router_port", avro_schema_int());
  avro_schema_record_field_append(schema, "bmp_msg_type", avro_schema_string());

  avro_schema_record_field_append(schema, "is_filtered", optint_s);
  avro_schema_record_field_append(schema, "is_loc", optint_s);
  avro_schema_record_field_append(schema, "is_post", optint_s);
  avro_schema_record_field_append(schema, "is_out", optint_s);

  avro_schema_decref(optlong_s);
  avro_schema_decref(optstr_s);
  avro_schema_decref(optint_s);

  return schema;
}

avro_schema_t avro_schema_build_bmp_init(char *schema_name)
{
  char *type = NULL;
  avro_schema_t schema = NULL;
  avro_schema_t optlong_s = avro_schema_union();
  avro_schema_t optstr_s = avro_schema_union();
  avro_schema_t optint_s = avro_schema_union();

  avro_schema_init_bgp(&schema, &optlong_s, &optstr_s, &optint_s, FUNC_TYPE_BMP, schema_name);
  avro_schema_build_bmp_common(&schema, &optlong_s, &optstr_s, &optint_s);

  type = bmp_tlv_type_print(BMP_INIT_INFO_STRING, "bmp_init_info", bmp_init_info_types, BMP_INIT_INFO_ENTRIES);
  avro_schema_record_field_append(schema, type, optstr_s);
  free(type);

  type = bmp_tlv_type_print(BMP_INIT_INFO_SYSDESCR, "bmp_init_info", bmp_init_info_types, BMP_INIT_INFO_ENTRIES);
  avro_schema_record_field_append(schema, type, optstr_s);
  free(type);

  type = bmp_tlv_type_print(BMP_INIT_INFO_SYSNAME, "bmp_init_info", bmp_init_info_types, BMP_INIT_INFO_ENTRIES);
  avro_schema_record_field_append(schema, type, optstr_s);
  free(type);

  avro_schema_decref(optlong_s);
  avro_schema_decref(optstr_s);
  avro_schema_decref(optint_s);

  return schema;
}

avro_schema_t avro_schema_build_bmp_term(char *schema_name)
{
  char *type = NULL;
  avro_schema_t schema = NULL;
  avro_schema_t optlong_s = avro_schema_union();
  avro_schema_t optstr_s = avro_schema_union();
  avro_schema_t optint_s = avro_schema_union();

  avro_schema_init_bgp(&schema, &optlong_s, &optstr_s, &optint_s, FUNC_TYPE_BMP, schema_name);
  avro_schema_build_bmp_common(&schema, &optlong_s, &optstr_s, &optint_s);

  type = bmp_tlv_type_print(BMP_TERM_INFO_STRING, "bmp_term_info", bmp_term_info_types, BMP_TERM_INFO_ENTRIES);
  avro_schema_record_field_append(schema, type, optstr_s);
  free(type);

  type = bmp_tlv_type_print(BMP_TERM_INFO_REASON, "bmp_term_info", bmp_term_info_types, BMP_TERM_INFO_ENTRIES);
  avro_schema_record_field_append(schema, type, optstr_s);
  free(type);

  avro_schema_decref(optlong_s);
  avro_schema_decref(optstr_s);
  avro_schema_decref(optint_s);

  return schema;
}

avro_schema_t avro_schema_build_bmp_peer_up(char *schema_name)
{
  char *type = NULL;
  avro_schema_t schema = NULL;
  avro_schema_t optlong_s = avro_schema_union();
  avro_schema_t optstr_s = avro_schema_union();
  avro_schema_t optint_s = avro_schema_union();

  avro_schema_init_bgp(&schema, &optlong_s, &optstr_s, &optint_s, FUNC_TYPE_BMP, schema_name);
  avro_schema_build_bmp_common(&schema, &optlong_s, &optstr_s, &optint_s);

  avro_schema_record_field_append(schema, "peer_ip", avro_schema_string());
  avro_schema_record_field_append(schema, "peer_asn", avro_schema_long());
  avro_schema_record_field_append(schema, "peer_type", avro_schema_int());
  avro_schema_record_field_append(schema, "peer_type_str", optstr_s);

  avro_schema_record_field_append(schema, "is_filtered", optint_s);
  avro_schema_record_field_append(schema, "is_loc", optint_s);
  avro_schema_record_field_append(schema, "is_post", optint_s);
  avro_schema_record_field_append(schema, "is_out", optint_s);

  avro_schema_record_field_append(schema, "bgp_id", avro_schema_string());
  avro_schema_record_field_append(schema, "local_port", avro_schema_int());
  avro_schema_record_field_append(schema, "remote_port", avro_schema_int());
  avro_schema_record_field_append(schema, "local_ip", avro_schema_string());

  type = bmp_tlv_type_print(BMP_PEER_UP_INFO_STRING, "bmp_peer_up_info", bmp_peer_up_info_types, BMP_PEER_UP_INFO_ENTRIES);
  avro_schema_record_field_append(schema, type, optstr_s);
  free(type);

  avro_schema_decref(optlong_s);
  avro_schema_decref(optstr_s);
  avro_schema_decref(optint_s);

  return schema;
}

avro_schema_t avro_schema_build_bmp_peer_down(char *schema_name)
{
  avro_schema_t schema = NULL;
  avro_schema_t optlong_s = avro_schema_union();
  avro_schema_t optstr_s = avro_schema_union();
  avro_schema_t optint_s = avro_schema_union();

  avro_schema_init_bgp(&schema, &optlong_s, &optstr_s, &optint_s, FUNC_TYPE_BMP, schema_name);
  avro_schema_build_bmp_common(&schema, &optlong_s, &optstr_s, &optint_s);

  avro_schema_record_field_append(schema, "peer_ip", avro_schema_string());
  avro_schema_record_field_append(schema, "peer_asn", avro_schema_long());
  avro_schema_record_field_append(schema, "peer_type", avro_schema_int());
  avro_schema_record_field_append(schema, "peer_type_str", optstr_s);

  avro_schema_record_field_append(schema, "reason_type", avro_schema_int());
  avro_schema_record_field_append(schema, "reason_str", optstr_s);
  avro_schema_record_field_append(schema, "reason_loc_code", optint_s);

  avro_schema_decref(optlong_s);
  avro_schema_decref(optstr_s);
  avro_schema_decref(optint_s);

  return schema;
}

avro_schema_t avro_schema_build_bmp_stats(char *schema_name)
{
  avro_schema_t schema = NULL;
  avro_schema_t optlong_s = avro_schema_union();
  avro_schema_t optstr_s = avro_schema_union();
  avro_schema_t optint_s = avro_schema_union();

  avro_schema_init_bgp(&schema, &optlong_s, &optstr_s, &optint_s, FUNC_TYPE_BMP, schema_name);
  avro_schema_build_bmp_common(&schema, &optlong_s, &optstr_s, &optint_s);

  avro_schema_record_field_append(schema, "peer_ip", avro_schema_string());
  avro_schema_record_field_append(schema, "peer_asn", avro_schema_long());
  avro_schema_record_field_append(schema, "peer_type", avro_schema_int());
  avro_schema_record_field_append(schema, "peer_type_str", avro_schema_string());

  avro_schema_record_field_append(schema, "is_filtered", optint_s);
  avro_schema_record_field_append(schema, "is_loc", optint_s);
  avro_schema_record_field_append(schema, "is_post", optint_s);
  avro_schema_record_field_append(schema, "is_out", optint_s);

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

avro_schema_t avro_schema_build_bmp_log_initclose(int log_type, char *schema_name)
{
  avro_schema_t schema = NULL;
  avro_schema_t optlong_s = avro_schema_union();
  avro_schema_t optstr_s = avro_schema_union();
  avro_schema_t optint_s = avro_schema_union();

  if (log_type != BGP_LOGDUMP_ET_LOG) return NULL;

  avro_schema_init_bgp(&schema, &optlong_s, &optstr_s, &optint_s, FUNC_TYPE_BMP, schema_name);

  /* prevent log_type from being added to Avro schema */
  log_type = BGP_LOGDUMP_ET_NONE;
  avro_schema_build_bgp_common(&schema, &optlong_s, &optstr_s, &optint_s, log_type, FUNC_TYPE_BMP);
  log_type = BGP_LOGDUMP_ET_LOG;

  avro_schema_record_field_append(schema, "bmp_router", avro_schema_string());
  avro_schema_record_field_append(schema, "bmp_router_port", optint_s);

  avro_schema_decref(optlong_s);
  avro_schema_decref(optstr_s);
  avro_schema_decref(optint_s);

  return schema;
}

avro_schema_t avro_schema_build_bmp_dump_init(int log_type, char *schema_name)
{
  avro_schema_t schema = NULL;
  avro_schema_t optlong_s = avro_schema_union();
  avro_schema_t optstr_s = avro_schema_union();
  avro_schema_t optint_s = avro_schema_union();

  if (log_type != BGP_LOGDUMP_ET_DUMP) return NULL;

  avro_schema_init_bgp(&schema, &optlong_s, &optstr_s, &optint_s, FUNC_TYPE_BMP, schema_name);
  avro_schema_build_bgp_common(&schema, &optlong_s, &optstr_s, &optint_s, log_type, FUNC_TYPE_BMP);

  avro_schema_record_field_append(schema, "bmp_router", avro_schema_string());
  avro_schema_record_field_append(schema, "bmp_router_port", optint_s);
  avro_schema_record_field_append(schema, "dump_period", avro_schema_int());

  avro_schema_decref(optlong_s);
  avro_schema_decref(optstr_s);
  avro_schema_decref(optint_s);

  return schema;
}

avro_schema_t avro_schema_build_bmp_dump_close(int log_type, char *schema_name)
{
  avro_schema_t schema = NULL;
  avro_schema_t optlong_s = avro_schema_union();
  avro_schema_t optstr_s = avro_schema_union();
  avro_schema_t optint_s = avro_schema_union();

  if (log_type != BGP_LOGDUMP_ET_DUMP) return NULL;

  avro_schema_init_bgp(&schema, &optlong_s, &optstr_s, &optint_s, FUNC_TYPE_BMP, schema_name);
  avro_schema_build_bgp_common(&schema, &optlong_s, &optstr_s, &optint_s, log_type, FUNC_TYPE_BMP);

  avro_schema_record_field_append(schema, "bmp_router", avro_schema_string());
  avro_schema_record_field_append(schema, "bmp_router_port", optint_s);
  avro_schema_record_field_append(schema, "entries", optint_s);
  avro_schema_record_field_append(schema, "tables", optint_s);

  avro_schema_decref(optlong_s);
  avro_schema_decref(optstr_s);
  avro_schema_decref(optint_s);

  return schema;
}

void avro_schema_build_bmp_common(avro_schema_t *schema, avro_schema_t *optlong_s, avro_schema_t *optstr_s, avro_schema_t *optint_s)
{
  avro_schema_record_field_append((*schema), "seq", avro_schema_long());
  avro_schema_record_field_append((*schema), "timestamp", avro_schema_string());
  avro_schema_record_field_append((*schema), "event_type", avro_schema_string());
  avro_schema_record_field_append((*schema), "event_timestamp", (*optstr_s));
  avro_schema_record_field_append((*schema), "bmp_router", avro_schema_string());
  avro_schema_record_field_append((*schema), "bmp_router_port", avro_schema_int());
  avro_schema_record_field_append((*schema), "bmp_msg_type", avro_schema_string());
  avro_schema_record_field_append((*schema), "writer_id", avro_schema_string());
}
#endif
