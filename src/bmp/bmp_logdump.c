/*  
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2015 by Paolo Lucente
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
#define __BMP_LOGDUMP_C

/* includes */
/* includes */
#include "pmacct.h"
#include "../bgp/bgp.h"
#include "bmp.h"
#if defined WITH_RABBITMQ
#include "amqp_common.h"
#endif
#ifdef WITH_JANSSON
#include <jansson.h>
#endif

int bmp_log_msg_stats(struct bgp_peer *peer, struct bmp_data *bdata, u_int16_t cnt_type, u_int64_t cnt_data64, u_int8_t got_data, char *event_type, int output)
{
  int ret = 0, amqp_ret = 0;

#ifdef WITH_RABBITMQ
  if (config.nfacctd_bmp_msglog_amqp_routing_key || config.bmp_dump_amqp_routing_key)
    p_amqp_set_routing_key(peer->log->amqp_host, peer->log->filename);
#endif

  if (output == PRINT_OUTPUT_JSON) {
#ifdef WITH_JANSSON
    char tstamp_str[SRVBUFLEN], peer_ip[INET6_ADDRSTRLEN];
    json_t *obj = json_object(), *kv;

    addr_to_str(peer_ip, bdata->peer_ip);

    /* no need for seq for "dump" event_type */
    if (strcmp(event_type, "dump")) {
      kv = json_pack("{sI}", "seq", bmp_log_seq);
      json_object_update_missing(obj, kv);
      json_decref(kv);
      bgp_peer_log_seq_increment(&bmp_log_seq);
    }

    compose_timestamp(tstamp_str, SRVBUFLEN, &bdata->tstamp, TRUE);
    kv = json_pack("{ss}", "timestamp", tstamp_str);
    json_object_update_missing(obj, kv);
    json_decref(kv);

    kv = json_pack("{ss}", "bmp_router", peer->addr_str);
    json_object_update_missing(obj, kv);
    json_decref(kv);

    addr_to_str(peer_ip, bdata->peer_ip);
    kv = json_pack("{ss}", "peer_ip", peer_ip);
    json_object_update_missing(obj, kv);
    json_decref(kv);

    kv = json_pack("{sI}", "counter_type", cnt_type);
    json_object_update_missing(obj, kv);
    json_decref(kv);

    if (cnt_type <= BMP_STATS_MAX) {
      kv = json_pack("{ss}", "counter_type_str", bmp_stats_cnt_types[cnt_type]);
      json_object_update_missing(obj, kv);
      json_decref(kv);
    }
    else {
      kv = json_pack("{ss}", "counter_type_str", "Unknown");
      json_object_update_missing(obj, kv);
      json_decref(kv);
    }

    if (got_data) {
      kv = json_pack("{sI}", "counter_value", cnt_data64);
      json_object_update_missing(obj, kv);
      json_decref(kv);
    }

    if (config.nfacctd_bmp_msglog_file || config.bmp_dump_file)
      write_and_free_json(peer->log->fd, obj);

#ifdef WITH_RABBITMQ
    if (config.nfacctd_bmp_msglog_amqp_routing_key || config.bmp_dump_amqp_routing_key) {
      amqp_ret = write_and_free_json_amqp(peer->log->amqp_host, obj);
      p_amqp_unset_routing_key(peer->log->amqp_host);
    }
#endif
#endif
  }

  return (ret | amqp_ret);
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

  p_amqp_set_user(&bmp_daemon_msglog_amqp_host, config.nfacctd_bmp_msglog_amqp_user);
  p_amqp_set_passwd(&bmp_daemon_msglog_amqp_host, config.nfacctd_bmp_msglog_amqp_passwd);
  p_amqp_set_exchange(&bmp_daemon_msglog_amqp_host, config.nfacctd_bmp_msglog_amqp_exchange);
  p_amqp_set_exchange_type(&bmp_daemon_msglog_amqp_host, config.nfacctd_bmp_msglog_amqp_exchange_type);
  p_amqp_set_host(&bmp_daemon_msglog_amqp_host, config.nfacctd_bmp_msglog_amqp_host);
  p_amqp_set_vhost(&bmp_daemon_msglog_amqp_host, config.nfacctd_bmp_msglog_amqp_vhost);
  p_amqp_set_persistent_msg(&bmp_daemon_msglog_amqp_host, config.nfacctd_bmp_msglog_amqp_persistent_msg);
  p_amqp_set_frame_max(&bmp_daemon_msglog_amqp_host, config.nfacctd_bmp_msglog_amqp_frame_max);
  p_amqp_set_heartbeat_interval(&bmp_daemon_msglog_amqp_host, config.nfacctd_bmp_msglog_amqp_heartbeat_interval);
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
  p_amqp_set_heartbeat_interval(&bmp_dump_amqp_host, config.bmp_dump_amqp_heartbeat_interval);
}
#else
void bmp_dump_init_amqp_host()
{
}
#endif
