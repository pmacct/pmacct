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
#define __BMP_UTIL_C

/* includes */
#include "pmacct.h"
#include "addr.h"
#include "../bgp/bgp.h"
#include "bmp.h"
#if defined WITH_RABBITMQ
#include "amqp_common.h"
#endif
#ifdef WITH_KAFKA
#include "kafka_common.h"
#endif

char *bmp_get_and_check_length(char **bmp_packet_ptr, u_int32_t *pkt_size, u_int32_t len)
{
  char *current_ptr = NULL;
  
  if (bmp_packet_ptr && (*bmp_packet_ptr) && pkt_size) {
    if ((*pkt_size) >= len) {
      current_ptr = (*bmp_packet_ptr);
      (*pkt_size) -= len;
      (*bmp_packet_ptr) += len;
    }
  }

  return current_ptr;
}

void bmp_jump_offset(char **bmp_packet_ptr, u_int32_t *len, u_int32_t offset)
{
  if (bmp_packet_ptr && (*bmp_packet_ptr) && len) {
    if (offset <= (*len)) {
      (*bmp_packet_ptr) += offset;
      (*len) -= offset;
    }
  }
}

u_int32_t bmp_packet_adj_offset(char *bmp_packet, u_int32_t buf_len, u_int32_t recv_len, u_int32_t remaining_len, char *addr_str)
{
  char tmp_packet[BGP_BUFFER_SIZE];
  
  if (!bmp_packet || recv_len > buf_len || remaining_len >= buf_len || remaining_len > recv_len) {
    if (addr_str)
      Log(LOG_INFO, "INFO ( %s/core/BMP ): [%s] packet discarded: failed bmp_packet_adj_offset()\n", config.name, addr_str);

    return FALSE;
  }

  memcpy(tmp_packet, &bmp_packet[recv_len - remaining_len], remaining_len);
  memcpy(bmp_packet, tmp_packet, remaining_len);

  return remaining_len;
}

void bgp_peer_log_msg_extras_bmp(struct bgp_peer *peer, int output, void *void_obj)
{
  char bmp_msg_type[] = "route_monitor";
  struct bgp_misc_structs *bms;
  struct bmp_peer *bmpp;

  if (!peer || !void_obj) return;

  bms = bgp_select_misc_db(peer->type);
  bmpp = peer->bmp_se;
  if (!bms || !bmpp) return;

  if (output == PRINT_OUTPUT_JSON) {
#ifdef WITH_JANSSON
    char ip_address[INET6_ADDRSTRLEN];
    json_t *obj = void_obj, *kv;

    addr_to_str(ip_address, &bmpp->self.addr);
    kv = json_pack("{ss}", "bmp_router", ip_address);
    json_object_update_missing(obj, kv);
    json_decref(kv);

    kv = json_pack("{ss}", "bmp_msg_type", bmp_msg_type);
    json_object_update_missing(obj, kv);
    json_decref(kv);
#endif
  }
}

void bmp_link_misc_structs(struct bgp_misc_structs *bms)
{
#if defined WITH_RABBITMQ
  bms->msglog_amqp_host = &bmp_daemon_msglog_amqp_host;
#endif
#if defined WITH_KAFKA
  bms->msglog_kafka_host = &bmp_daemon_msglog_kafka_host;
#endif
  bms->max_peers = config.nfacctd_bmp_max_peers;
  bms->dump_file = config.bmp_dump_file;
  bms->dump_amqp_routing_key = config.bmp_dump_amqp_routing_key;
  bms->dump_amqp_routing_key_rr = config.bmp_dump_amqp_routing_key_rr;
  bms->dump_kafka_topic = config.bmp_dump_kafka_topic;
  bms->dump_kafka_topic_rr = config.bmp_dump_kafka_topic_rr;
  bms->msglog_file = config.nfacctd_bmp_msglog_file;
  bms->msglog_output = config.nfacctd_bmp_msglog_output;
  bms->msglog_amqp_routing_key = config.nfacctd_bmp_msglog_amqp_routing_key;
  bms->msglog_amqp_routing_key_rr = config.nfacctd_bmp_msglog_amqp_routing_key_rr;
  bms->msglog_kafka_topic = config.nfacctd_bmp_msglog_kafka_topic;
  bms->msglog_kafka_topic_rr = config.nfacctd_bmp_msglog_kafka_topic_rr;
  bms->peer_str = malloc(strlen("bmp_router") + 1);
  strcpy(bms->peer_str, "bmp_router");
  bms->bgp_peer_log_msg_extras = bgp_peer_log_msg_extras_bmp;

  bms->table_peer_buckets = config.bmp_table_peer_buckets;
  bms->table_per_peer_buckets = config.bmp_table_per_peer_buckets;
  bms->table_attr_hash_buckets = config.bmp_table_attr_hash_buckets;
  bms->table_per_peer_hash = config.bmp_table_per_peer_hash;
  bms->route_info_modulo = bmp_route_info_modulo;
  bms->bgp_lookup_find_peer = bgp_lookup_find_bmp_peer;
  bms->bgp_lookup_node_match_cmp = bgp_lookup_node_match_cmp_bmp;
}

struct bgp_peer *bmp_sync_loc_rem_peers(struct bgp_peer *bgp_peer_loc, struct bgp_peer *bgp_peer_rem)
{
  if (!bgp_peer_loc || !bgp_peer_rem) return NULL;

  if (!bgp_peer_loc->cap_4as || !bgp_peer_rem->cap_4as) bgp_peer_rem->cap_4as = FALSE;
  if (!bgp_peer_loc->cap_add_paths || !bgp_peer_rem->cap_add_paths) bgp_peer_rem->cap_add_paths = FALSE;

  bgp_peer_rem->type = FUNC_TYPE_BMP;
  memcpy(&bgp_peer_rem->id, &bgp_peer_rem->addr, sizeof(struct host_addr));

  return bgp_peer_rem;
}

int bmp_peer_init(struct bmp_peer *bmpp, int type)
{
  int ret;

  if (!bmpp) return ERR;

  ret = bgp_peer_init(&bmpp->self, type);
  log_notification_init(&bmpp->missing_peer_up);

  return ret;
}

void bmp_peer_close(struct bmp_peer *bmpp, int type)
{
  struct bgp_misc_structs *bms;
  struct bgp_peer *peer;

  if (!bmpp) return;

  peer = &bmpp->self;
  bms = bgp_select_misc_db(peer->type);

  if (!bms) return;

  pm_twalk(bmpp->bgp_peers, bmp_bmpp_bgp_peers_walk_delete);

  pm_tdestroy(&bmpp->bgp_peers, bmp_bmpp_bgp_peers_free);

  if (bms->dump_file || bms->dump_amqp_routing_key || bms->dump_kafka_topic)
    bmp_dump_close_peer(peer);

  bgp_peer_close(peer, type);
}

int bmp_bmpp_bgp_peers_cmp(const void *a, const void *b)
{
  return memcmp(&((struct bgp_peer *)a)->addr, &((struct bgp_peer *)b)->addr, sizeof(struct host_addr));
}

int bmp_bmpp_bgp_peer_host_addr_cmp(const void *a, const void *b)
{
  return memcmp(a, &((struct bgp_peer *)b)->addr, sizeof(struct host_addr));
}

void bmp_bmpp_bgp_peers_free(void *a)
{
}

void bmp_bmpp_bgp_peers_walk_print(const void *nodep, const VISIT which, const int depth)
{
  struct bgp_misc_structs *bms;
  struct bgp_peer *peer;
  char peer_str[INET6_ADDRSTRLEN];

  peer = (*(struct bgp_peer **) nodep);
  bms = bgp_select_misc_db(peer->type);

  if (!bms) return;

  if (!peer) Log(LOG_INFO, "INFO ( %s/%s ): bmp_bmpp_bgp_peers_walk_print(): null\n", config.name, bms->log_str);
  else {
    addr_to_str(peer_str, &peer->addr);
    Log(LOG_INFO, "INFO ( %s/%s ): bmp_bmpp_bgp_peers_walk_print(): %s\n", config.name, bms->log_str, peer_str);
  }
}

void bmp_bmpp_bgp_peers_walk_delete(const void *nodep, const VISIT which, const int depth)
{
  struct bgp_misc_structs *bms;
  char peer_str[] = "peer_ip", *saved_peer_str;
  struct bgp_peer *peer;

  peer = (*(struct bgp_peer **) nodep);

  if (!peer) return;

  bms = bgp_select_misc_db(peer->type);

  if (!bms) return;

  saved_peer_str = bms->peer_str;
  bms->peer_str = peer_str;
  bgp_peer_info_delete(peer);
  bms->peer_str = saved_peer_str;

  // XXX: count tree elements to index and free() later
}
