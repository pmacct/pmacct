/*  
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2017 by Paolo Lucente
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
#define __TELEMETRY_UTIL_C

/* includes */
#include "pmacct.h"
#include "../bgp/bgp.h"
#include "telemetry.h"
#if defined WITH_RABBITMQ
#include "amqp_common.h"
#endif
#ifdef WITH_KAFKA
#include "kafka_common.h"
#endif

/* Functions */
int telemetry_peer_init(telemetry_peer *peer, int type)
{
  return bgp_peer_init(peer, type);
}

int telemetry_peer_z_init(telemetry_peer_z *peer_z)
{
#if defined (HAVE_ZLIB)
  peer_z->stm.zalloc = Z_NULL;
  peer_z->stm.zfree = Z_NULL;
  peer_z->stm.opaque = Z_NULL;
  peer_z->stm.avail_in = 0;
  peer_z->stm.next_in = Z_NULL;

  if (inflateInit(&peer_z->stm) != Z_OK) return ERR;
#endif

  return FALSE;
}

void telemetry_peer_close(telemetry_peer *peer, int type)
{
  telemetry_dump_se_ll *tdsell;
  telemetry_misc_structs *tms;

  if (!peer) return;

  tms = bgp_select_misc_db(peer->type);

  if (!tms) return;
 
  if (tms->dump_file || tms->dump_amqp_routing_key || tms->dump_kafka_topic) {
    tdsell = (telemetry_dump_se_ll *) peer->bmp_se;

    if (tdsell && tdsell->start) telemetry_dump_se_ll_destroy(tdsell);

    free(peer->bmp_se);
    peer->bmp_se = NULL;
  }

  if (config.telemetry_port_udp) {
    telemetry_peer_udp_cache tpuc;

    memcpy(&tpuc.addr, &peer->addr, sizeof(struct host_addr));
    pm_tdelete(&tpuc, &telemetry_peers_udp_cache, telemetry_tpuc_addr_cmp);

    peer->fd = ERR; /* dirty trick to prevent close() a valid fd in bgp_peer_close() */
  }

  bgp_peer_close(peer, type, FALSE, FALSE, FALSE, FALSE, NULL);
}

void telemetry_peer_z_close(telemetry_peer_z *peer_z)
{
#if defined (HAVE_ZLIB)
  inflateEnd(&peer_z->stm);
#endif
}

u_int32_t telemetry_cisco_hdr_get_len(telemetry_peer *peer)
{
  u_int32_t len;

  memcpy(&len, (peer->buf.base + 8), 4);
  len = ntohl(len);

  return len;
}

u_int32_t telemetry_cisco_hdr_get_type(telemetry_peer *peer)
{
  u_int32_t type;

  memcpy(&type, peer->buf.base, 4);
  type = ntohl(type);

  return type;
}

int telemetry_is_zjson(int decoder)
{
  if (decoder == TELEMETRY_DECODER_ZJSON || decoder == TELEMETRY_DECODER_CISCO_ZJSON) return TRUE;
  else return FALSE;
}

int telemetry_tpuc_addr_cmp(const void *a, const void *b)
{
  return memcmp(&((telemetry_peer_udp_cache *)a)->addr, &((telemetry_peer_udp_cache *)b)->addr, sizeof(struct host_addr));
}

void telemetry_link_misc_structs(telemetry_misc_structs *tms)
{
#if defined WITH_RABBITMQ
  tms->msglog_amqp_host = &telemetry_daemon_msglog_amqp_host;
#endif
#if defined WITH_KAFKA
  tms->msglog_kafka_host = &telemetry_daemon_msglog_kafka_host;
#endif
  tms->max_peers = config.telemetry_max_peers;
  tms->dump_file = config.telemetry_dump_file;
  tms->dump_amqp_routing_key = config.telemetry_dump_amqp_routing_key;
  tms->dump_amqp_routing_key_rr = config.telemetry_dump_amqp_routing_key_rr;
  tms->dump_kafka_topic = config.telemetry_dump_kafka_topic;
  tms->dump_kafka_topic_rr = config.telemetry_dump_kafka_topic_rr;
  tms->msglog_file = config.telemetry_msglog_file;
  tms->msglog_output = config.telemetry_msglog_output;
  tms->msglog_amqp_routing_key = config.telemetry_msglog_amqp_routing_key;
  tms->msglog_amqp_routing_key_rr = config.telemetry_msglog_amqp_routing_key_rr;
  tms->msglog_kafka_topic = config.telemetry_msglog_kafka_topic;
  tms->msglog_kafka_topic_rr = config.telemetry_msglog_kafka_topic_rr;
  tms->peer_str = malloc(strlen("telemetry_node") + 1);
  strcpy(tms->peer_str, "telemetry_node");
}

int telemetry_validate_input_output_decoders(int input, int output)
{
  if (input == TELEMETRY_DATA_DECODER_GPB) {
    if (output == PRINT_OUTPUT_JSON) return FALSE;
    /* else if (output == PRINT_OUTPUT_GPB) return FALSE; */
  }
  else if (input == TELEMETRY_DATA_DECODER_JSON) {
    if (output == PRINT_OUTPUT_JSON) return FALSE;
    /* else if (output == PRINT_OUTPUT_GPB) return ERR; */
  }
}

void telemetry_log_peer_stats(telemetry_peer *peer, struct telemetry_data *t_data)
{
  Log(LOG_INFO, "INFO ( %s/%s ): [%s:%u] Packets: %u Packet_Bytes: %u Msg_Bytes: %u Msg_Errors: %u\n",
	config.name, t_data->log_str, peer->addr_str, peer->tcp_port, peer->stats.packets,
	peer->stats.packet_bytes, peer->stats.msg_bytes, peer->stats.msg_errors);

  t_data->global_stats.packets += peer->stats.packets;
  t_data->global_stats.packet_bytes += peer->stats.packet_bytes;
  t_data->global_stats.msg_bytes += peer->stats.msg_bytes;
  t_data->global_stats.msg_errors += peer->stats.msg_errors;

  peer->stats.packets = 0;
  peer->stats.packet_bytes = 0;
  peer->stats.msg_bytes = 0;
  peer->stats.msg_errors = 0;
}

void telemetry_log_global_stats(struct telemetry_data *t_data)
{
  Log(LOG_INFO, "INFO ( %s/%s ): Packets: %u Packet_Bytes: %u Msg_Bytes: %u Msg_Errors: %u\n",
        config.name, t_data->log_str, t_data->global_stats.packets, t_data->global_stats.packet_bytes,
	t_data->global_stats.msg_bytes, t_data->global_stats.msg_errors);

  t_data->global_stats.packets = 0;
  t_data->global_stats.packet_bytes = 0;
  t_data->global_stats.msg_bytes = 0;
  t_data->global_stats.msg_errors = 0;
}
