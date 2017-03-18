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
#define __BMP_MSG_C

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

u_int32_t bmp_process_packet(char *bmp_packet, u_int32_t len, struct bmp_peer *bmpp)
{
  struct bgp_misc_structs *bms;
  struct bgp_peer *peer;
  char *bmp_packet_ptr = bmp_packet;
  u_int32_t pkt_remaining_len, msg_len, msg_start_len;

  struct bmp_common_hdr *bch = NULL;

  if (!bmpp) return FALSE;

  peer = &bmpp->self;
  bms = bgp_select_misc_db(peer->type);

  if (!bms) return FALSE;

  if (len < sizeof(struct bmp_common_hdr)) {
    Log(LOG_INFO, "INFO ( %s/%s ): [%s] packet discarded: failed bmp_get_and_check_length() BMP common hdr\n",
	config.name, bms->log_str, peer->addr_str);
    return FALSE;
  }

  for (msg_start_len = pkt_remaining_len = len; pkt_remaining_len; msg_start_len = pkt_remaining_len) {
    if (!(bch = (struct bmp_common_hdr *) bmp_get_and_check_length(&bmp_packet_ptr, &pkt_remaining_len, sizeof(struct bmp_common_hdr))))
      return msg_start_len;

    if (bch->version != BMP_V3) {
      Log(LOG_INFO, "INFO ( %s/%s ): [%s] packet discarded: BMP version != %u\n",
	  config.name, bms->log_str, peer->addr_str, BMP_V3);
      return FALSE;
    }

    bmp_common_hdr_get_len(bch, &msg_len);
    if (pkt_remaining_len < msg_len) return msg_start_len;

    if (bch->type <= BMP_MSG_TYPE_MAX) {
      Log(LOG_DEBUG, "DEBUG ( %s/%s ): [%s] [common] type: %s (%u)\n",
	  config.name, bms->log_str, peer->addr_str, bmp_msg_types[bch->type], bch->type);
    }

    switch (bch->type) {
    case BMP_MSG_ROUTE_MONITOR:
      bmp_process_msg_route_monitor(&bmp_packet_ptr, &pkt_remaining_len, bmpp);
      break;
    case BMP_MSG_STATS:
      bmp_process_msg_stats(&bmp_packet_ptr, &pkt_remaining_len, bmpp);
      break;
    case BMP_MSG_PEER_DOWN:
      bmp_process_msg_peer_down(&bmp_packet_ptr, &pkt_remaining_len, bmpp);
      break;
    case BMP_MSG_PEER_UP:
      bmp_process_msg_peer_up(&bmp_packet_ptr, &pkt_remaining_len, bmpp); 
      break;
    case BMP_MSG_INIT:
      bmp_process_msg_init(&bmp_packet_ptr, &pkt_remaining_len, msg_len, bmpp); 
      break;
    case BMP_MSG_TERM:
      bmp_process_msg_term(&bmp_packet_ptr, &pkt_remaining_len, msg_len, bmpp); 
      break;
    case BMP_MSG_ROUTE_MIRROR:
      bmp_process_msg_route_mirror(&bmp_packet_ptr, &pkt_remaining_len, bmpp);
      break;
    default:
      Log(LOG_INFO, "INFO ( %s/%s ): [%s] packet discarded: unknown message type (%u)\n",
	  config.name, bms->log_str, peer->addr_str, bch->type);
      break;
    }

    if ((msg_start_len - pkt_remaining_len) < msg_len) {
      /* let's jump forward: we may have been unable to parse some (sub-)element */
      bmp_jump_offset(&bmp_packet_ptr, &pkt_remaining_len, (msg_len - (msg_start_len - pkt_remaining_len)));
    }
  }

  return FALSE;
}

void bmp_process_msg_init(char **bmp_packet, u_int32_t *len, u_int32_t bmp_hdr_len, struct bmp_peer *bmpp)
{
  struct bgp_misc_structs *bms;
  struct bgp_peer *peer;
  struct bmp_data bdata;
  struct bmp_init_hdr *bih;
  u_int16_t bmp_init_len;
  char *bmp_init_info;

  if (!bmpp) return;

  peer = &bmpp->self;
  bms = bgp_select_misc_db(peer->type);

  if (!bms) return;

  memset(&bdata, 0, sizeof(bdata));
  gettimeofday(&bdata.tstamp, NULL);
  bmp_hdr_len -= sizeof(struct bmp_common_hdr);

  if (bms->msglog_backend_methods) {
    char event_type[] = "log";

    bmp_log_msg(peer, &bdata, NULL, bms->log_seq, event_type, config.nfacctd_bmp_msglog_output, BMP_LOG_TYPE_INIT);
  }

  if (bms->dump_backend_methods)
    bmp_dump_se_ll_append(peer, &bdata, NULL, BMP_LOG_TYPE_INIT);

  if (bms->msglog_backend_methods || bms->dump_backend_methods)
    bgp_peer_log_seq_increment(&bms->log_seq);

  while (bmp_hdr_len) {
    if (!(bih = (struct bmp_init_hdr *) bmp_get_and_check_length(bmp_packet, len, sizeof(struct bmp_init_hdr)))) {
      Log(LOG_INFO, "INFO ( %s/%s ): [%s] [init] packet discarded: failed bmp_get_and_check_length() BMP init hdr\n",
		config.name, bms->log_str, peer->addr_str);
      return;
    }

    bmp_init_hdr_get_len(bih, &bmp_init_len);

    if (!(bmp_init_info = bmp_get_and_check_length(bmp_packet, len, bmp_init_len))) {
      Log(LOG_INFO, "INFO ( %s/%s ): [%s] [init] packet discarded: failed bmp_get_and_check_length() BMP init info\n",
		config.name, bms->log_str, peer->addr_str);
      return;
    }

    {
      struct bmp_log_init blinit;

      blinit.type = bih->type;
      blinit.len = bmp_init_len;
      blinit.val = bmp_init_info;

      if (bms->msglog_backend_methods) {
        char event_type[] = "log";

        bmp_log_msg(peer, &bdata, &blinit, bms->log_seq, event_type, config.nfacctd_bmp_msglog_output, BMP_LOG_TYPE_INIT);
      }

      if (bms->dump_backend_methods)
        bmp_dump_se_ll_append(peer, &bdata, &blinit, BMP_LOG_TYPE_INIT);

      if (bms->msglog_backend_methods || bms->dump_backend_methods)
        bgp_peer_log_seq_increment(&bms->log_seq);
    }

    bmp_hdr_len -= (bmp_init_len + sizeof(struct bmp_init_hdr));
  }
}

void bmp_process_msg_term(char **bmp_packet, u_int32_t *len, u_int32_t bmp_hdr_len, struct bmp_peer *bmpp)
{
  struct bgp_misc_structs *bms;
  struct bgp_peer *peer;
  struct bmp_data bdata;
  struct bmp_term_hdr *bth;
  u_int16_t bmp_term_len, reason_type = 0;
  char *bmp_term_info;

  if (!bmpp) return;

  peer = &bmpp->self;
  bms = bgp_select_misc_db(peer->type);

  if (!bms) return;

  memset(&bdata, 0, sizeof(bdata));
  gettimeofday(&bdata.tstamp, NULL);
  bmp_hdr_len -= sizeof(struct bmp_common_hdr);

  if (bms->msglog_backend_methods) {
    char event_type[] = "log";

    bmp_log_msg(peer, &bdata, NULL, bms->log_seq, event_type, config.nfacctd_bmp_msglog_output, BMP_LOG_TYPE_TERM);
  }

  if (bms->dump_backend_methods)
    bmp_dump_se_ll_append(peer, &bdata, NULL, BMP_LOG_TYPE_TERM);

  if (bms->msglog_backend_methods || bms->dump_backend_methods)
    bgp_peer_log_seq_increment(&bms->log_seq);

  while (bmp_hdr_len) {
    if (!(bth = (struct bmp_term_hdr *) bmp_get_and_check_length(bmp_packet, len, sizeof(struct bmp_term_hdr)))) {
      Log(LOG_INFO, "INFO ( %s/%s ): [%s] [term] packet discarded: failed bmp_get_and_check_length() BMP term hdr\n",
		config.name, bms->log_str, peer->addr_str);
       return;
    }

    bmp_term_hdr_get_len(bth, &bmp_term_len);

    if (!(bmp_term_info = bmp_get_and_check_length(bmp_packet, len, bmp_term_len))) {
      Log(LOG_INFO, "INFO ( %s/%s ): [%s] [term] packet discarded: failed bmp_get_and_check_length() BMP term info\n",
		config.name, bms->log_str, peer->addr_str);
      return;
    }

    if (bth->type == BMP_TERM_INFO_REASON && bmp_term_len == 2) bmp_term_hdr_get_reason_type(bmp_packet, len, &reason_type);

    {
      struct bmp_log_term blterm;

      blterm.type = bth->type;
      blterm.len = bmp_term_len;
      blterm.val = bmp_term_info;
      blterm.reas_type = reason_type;

      if (bms->msglog_backend_methods) {
        char event_type[] = "log";

        bmp_log_msg(peer, &bdata, &blterm, bms->log_seq, event_type, config.nfacctd_bmp_msglog_output, BMP_LOG_TYPE_TERM);
      }

      if (bms->dump_backend_methods)
        bmp_dump_se_ll_append(peer, &bdata, &blterm, BMP_LOG_TYPE_TERM);

      if (bms->msglog_backend_methods || bms->dump_backend_methods)
        bgp_peer_log_seq_increment(&bms->log_seq);
    }

    bmp_hdr_len -= (bmp_term_len + sizeof(struct bmp_term_hdr));
  }

  /* BGP peers are deleted as part of bmp_peer_close() */
}

void bmp_process_msg_peer_up(char **bmp_packet, u_int32_t *len, struct bmp_peer *bmpp)
{
  struct bgp_misc_structs *bms;
  struct bgp_peer *peer;
  struct bmp_data bdata;
  struct bmp_peer_hdr *bph;
  struct bmp_peer_up_hdr *bpuh;

  if (!bmpp) return;

  peer = &bmpp->self;
  bms = bgp_select_misc_db(peer->type);

  if (!bms) return;

  memset(&bdata, 0, sizeof(bdata));

  if (!(bph = (struct bmp_peer_hdr *) bmp_get_and_check_length(bmp_packet, len, sizeof(struct bmp_peer_hdr)))) {
    Log(LOG_INFO, "INFO ( %s/%s ): [%s] [peer up] packet discarded: failed bmp_get_and_check_length() BMP peer hdr\n",
	config.name, bms->log_str, peer->addr_str);
    return;
  }

  if (!(bpuh = (struct bmp_peer_up_hdr *) bmp_get_and_check_length(bmp_packet, len, sizeof(struct bmp_peer_up_hdr)))) {
    Log(LOG_INFO, "INFO ( %s/%s ): [%s] [peer up] packet discarded: failed bmp_get_and_check_length() BMP peer up hdr\n",
	config.name, bms->log_str, peer->addr_str);
    return;
  }

  bmp_peer_hdr_get_v_flag(bph, &bdata.family);
  bmp_peer_hdr_get_peer_ip(bph, &bdata.peer_ip, bdata.family);
  bmp_peer_hdr_get_l_flag(bph, &bdata.is_post);
  bmp_peer_hdr_get_a_flag(bph, &bdata.is_2b_asn);
  bmp_peer_hdr_get_bgp_id(bph, &bdata.bgp_id);
  bmp_peer_hdr_get_tstamp(bph, &bdata.tstamp);
  bmp_peer_hdr_get_peer_asn(bph, &bdata.peer_asn);
  bmp_peer_hdr_get_peer_type(bph, &bdata.peer_type);

  if (bdata.family) {
    /* If no timestamp in BMP then let's generate one */
    if (!bdata.tstamp.tv_sec) gettimeofday(&bdata.tstamp, NULL);

    {
      struct bmp_log_peer_up blpu;
      struct bgp_peer bgp_peer_loc, bgp_peer_rem, *bmpp_bgp_peer;
      struct bgp_msg_extra_data_bmp bmed_bmp;
      struct bgp_msg_data bmd;
      int bgp_open_len;
      void *ret, *alloc_key;

      memset(&bgp_peer_loc, 0, sizeof(bgp_peer_loc));
      memset(&bgp_peer_rem, 0, sizeof(bgp_peer_rem));
      memset(&bmd, 0, sizeof(bmd));
      memset(&bmed_bmp, 0, sizeof(bmed_bmp));
      bmp_peer_up_hdr_get_loc_port(bpuh, &blpu.loc_port);
      bmp_peer_up_hdr_get_rem_port(bpuh, &blpu.rem_port);
      bmp_peer_up_hdr_get_local_ip(bpuh, &blpu.local_ip, bdata.family);

      bmd.peer = &bgp_peer_loc;
      bmd.extra.id = BGP_MSG_EXTRA_DATA_BMP;
      bmd.extra.len = sizeof(bmed_bmp);
      bmd.extra.data = &bmed_bmp;
      bgp_msg_data_set_data_bmp(&bmed_bmp, &bdata);

      /* XXX: checks, ie. marker, message length, etc., bypassed */
      bgp_open_len = bgp_parse_open_msg(&bmd, (*bmp_packet), FALSE, FALSE);
      bmp_get_and_check_length(bmp_packet, len, bgp_open_len);
      memcpy(&bgp_peer_loc.addr, &blpu.local_ip, sizeof(struct host_addr));

      bmd.peer = &bgp_peer_rem;
      bgp_open_len = bgp_parse_open_msg(&bmd, (*bmp_packet), FALSE, FALSE);
      bmp_get_and_check_length(bmp_packet, len, bgp_open_len);
      memcpy(&bgp_peer_rem.addr, &bdata.peer_ip, sizeof(struct host_addr));

      bmpp_bgp_peer = bmp_sync_loc_rem_peers(&bgp_peer_loc, &bgp_peer_rem);
      bmpp_bgp_peer->log = bmpp->self.log; 
      bmpp_bgp_peer->bmp_se = bmpp; /* using bmp_se field to back-point a BGP peer to its parent BMP peer */  
      ret = pm_tsearch(bmpp_bgp_peer, &bmpp->bgp_peers, bgp_peer_cmp, sizeof(struct bgp_peer));
      if (!ret) Log(LOG_WARNING, "WARN ( %s/%s ): [%s] [peer up] tsearch() unable to insert.\n", config.name, bms->log_str, peer->addr_str);

      if (bms->msglog_backend_methods) {
        char event_type[] = "log";

        bmp_log_msg(peer, &bdata, &blpu, bms->log_seq, event_type, config.nfacctd_bmp_msglog_output, BMP_LOG_TYPE_PEER_UP);
      }

      if (bms->dump_backend_methods)
        bmp_dump_se_ll_append(peer, &bdata, &blpu, BMP_LOG_TYPE_PEER_UP);

      if (bms->msglog_backend_methods || bms->dump_backend_methods)
        bgp_peer_log_seq_increment(&bms->log_seq);
    }
  }
}

void bmp_process_msg_peer_down(char **bmp_packet, u_int32_t *len, struct bmp_peer *bmpp)
{
  struct bgp_misc_structs *bms;
  struct bgp_peer *peer, *bmpp_bgp_peer;
  struct bmp_data bdata;
  struct bmp_peer_hdr *bph;
  struct bmp_peer_down_hdr *bpdh;
  void *ret;

  if (!bmpp) return;

  peer = &bmpp->self;
  bms = bgp_select_misc_db(peer->type);

  if (!bms) return;

  memset(&bdata, 0, sizeof(bdata));

  if (!(bph = (struct bmp_peer_hdr *) bmp_get_and_check_length(bmp_packet, len, sizeof(struct bmp_peer_hdr)))) {
    Log(LOG_INFO, "INFO ( %s/%s ): [%s] [peer down] packet discarded: failed bmp_get_and_check_length() BMP peer hdr\n",
        config.name, bms->log_str, peer->addr_str);
    return;
  }

  if (!(bpdh = (struct bmp_peer_down_hdr *) bmp_get_and_check_length(bmp_packet, len, sizeof(struct bmp_peer_down_hdr)))) {
    Log(LOG_INFO, "INFO ( %s/%s ): [%s] [peer down] packet discarded: failed bmp_get_and_check_length() BMP peer down hdr\n",
        config.name, bms->log_str, peer->addr_str);
    return;
  }

  bmp_peer_hdr_get_v_flag(bph, &bdata.family);
  bmp_peer_hdr_get_peer_ip(bph, &bdata.peer_ip, bdata.family);
  bmp_peer_hdr_get_l_flag(bph, &bdata.is_post);
  bmp_peer_hdr_get_bgp_id(bph, &bdata.bgp_id);
  bmp_peer_hdr_get_tstamp(bph, &bdata.tstamp);
  bmp_peer_hdr_get_peer_asn(bph, &bdata.peer_asn);
  bmp_peer_hdr_get_peer_type(bph, &bdata.peer_type);

  if (bdata.family) {
    /* If no timestamp in BMP then let's generate one */
    if (!bdata.tstamp.tv_sec) gettimeofday(&bdata.tstamp, NULL);

    {
      struct bmp_log_peer_down blpd;

      bmp_peer_down_hdr_get_reason(bpdh, &blpd.reason);
      if (blpd.reason == BMP_PEER_DOWN_LOC_CODE) bmp_peer_down_hdr_get_loc_code(bmp_packet, len, &blpd.loc_code);

      if (bms->msglog_backend_methods) {
        char event_type[] = "log";

        bmp_log_msg(peer, &bdata, &blpd, bms->log_seq, event_type, config.nfacctd_bmp_msglog_output, BMP_LOG_TYPE_PEER_DOWN);
      }

      if (bms->dump_backend_methods)
        bmp_dump_se_ll_append(peer, &bdata, &blpd, BMP_LOG_TYPE_PEER_DOWN);

      if (bms->msglog_backend_methods || bms->dump_backend_methods)
        bgp_peer_log_seq_increment(&bms->log_seq);
    }

    ret = pm_tfind(&bdata.peer_ip, &bmpp->bgp_peers, bgp_peer_host_addr_cmp);

    if (ret) {
      char peer_str[] = "peer_ip", *saved_peer_str = bms->peer_str;

      bmpp_bgp_peer = (*(struct bgp_peer **) ret);
    
      bms->peer_str = peer_str;
      bgp_peer_info_delete(bmpp_bgp_peer);
      bms->peer_str = saved_peer_str;

      pm_tdelete(&bdata.peer_ip, &bmpp->bgp_peers, bgp_peer_host_addr_cmp);
    } 
    /* missing BMP peer up message, ie. case of replay/replication of BMP messages */
    else {
      char peer_ip[INET6_ADDRSTRLEN];

      addr_to_str(peer_ip, &bdata.peer_ip);

      if (!log_notification_isset(&bmpp->missing_peer_up, bdata.tstamp.tv_sec)) {
        log_notification_set(&bmpp->missing_peer_up, bdata.tstamp.tv_sec, BMP_MISSING_PEER_UP_LOG_TOUT);
        Log(LOG_INFO, "INFO ( %s/%s ): [%s] [peer down] packet discarded: missing peer up BMP message for peer %s\n",
                config.name, bms->log_str, peer->addr_str, peer_ip);
      }
    }
  }
}

void bmp_process_msg_route_monitor(char **bmp_packet, u_int32_t *len, struct bmp_peer *bmpp)
{
  struct bgp_misc_structs *bms;
  struct bgp_peer *peer, *bmpp_bgp_peer;
  struct bmp_data bdata;
  struct bmp_peer_hdr *bph;
  char tstamp_str[SRVBUFLEN], peer_ip[INET6_ADDRSTRLEN];
  int bgp_update_len;
  void *ret;

  if (!bmpp) return;

  peer = &bmpp->self;
  bms = bgp_select_misc_db(peer->type);

  if (!bms) return;

  if (!(bph = (struct bmp_peer_hdr *) bmp_get_and_check_length(bmp_packet, len, sizeof(struct bmp_peer_hdr)))) {
    Log(LOG_INFO, "INFO ( %s/%s ): [%s] [route] packet discarded: failed bmp_get_and_check_length() BMP peer hdr\n",
        config.name, bms->log_str, peer->addr_str);
    return;
  }

  bmp_peer_hdr_get_v_flag(bph, &bdata.family);
  bmp_peer_hdr_get_peer_ip(bph, &bdata.peer_ip, bdata.family);
  bmp_peer_hdr_get_l_flag(bph, &bdata.is_post);
  bmp_peer_hdr_get_a_flag(bph, &bdata.is_2b_asn);
  bmp_peer_hdr_get_bgp_id(bph, &bdata.bgp_id);
  bmp_peer_hdr_get_tstamp(bph, &bdata.tstamp);
  bmp_peer_hdr_get_peer_asn(bph, &bdata.peer_asn);
  bmp_peer_hdr_get_peer_type(bph, &bdata.peer_type);

  if (bdata.family) {
    /* If no timestamp in BMP then let's generate one */
    if (!bdata.tstamp.tv_sec) gettimeofday(&bdata.tstamp, NULL);

    compose_timestamp(tstamp_str, SRVBUFLEN, &bdata.tstamp, TRUE, config.timestamps_since_epoch);
    addr_to_str(peer_ip, &bdata.peer_ip);

    ret = pm_tfind(&bdata.peer_ip, &bmpp->bgp_peers, bgp_peer_host_addr_cmp);

    if (ret) {
      char peer_str[] = "peer_ip", *saved_peer_str = bms->peer_str;
      struct bgp_msg_extra_data_bmp bmed_bmp;
      struct bgp_msg_data bmd;

      bmpp_bgp_peer = (*(struct bgp_peer **) ret);
      memset(&bmd, 0, sizeof(bmd));
      memset(&bmed_bmp, 0, sizeof(bmed_bmp));

      bms->peer_str = peer_str;
      bmd.peer = bmpp_bgp_peer;
      bmd.extra.id = BGP_MSG_EXTRA_DATA_BMP;
      bmd.extra.len = sizeof(bmed_bmp);
      bmd.extra.data = &bmed_bmp;
      bgp_msg_data_set_data_bmp(&bmed_bmp, &bdata);
      /* XXX: checks, ie. marker, message length, etc., bypassed */
      bgp_update_len = bgp_parse_update_msg(&bmd, (*bmp_packet)); 
      bms->peer_str = saved_peer_str;

      bmp_get_and_check_length(bmp_packet, len, bgp_update_len);
    }
    /* missing BMP peer up message, ie. case of replay/replication of BMP messages */
    else {
      if (!log_notification_isset(&bmpp->missing_peer_up, bdata.tstamp.tv_sec)) {
	log_notification_set(&bmpp->missing_peer_up, bdata.tstamp.tv_sec, BMP_MISSING_PEER_UP_LOG_TOUT);
	Log(LOG_INFO, "INFO ( %s/%s ): [%s] [route] packet discarded: missing peer up BMP message for peer %s\n",
		config.name, bms->log_str, peer->addr_str, peer_ip);
      }
    }
  }
}

void bmp_process_msg_route_mirror(char **bmp_packet, u_int32_t *len, struct bmp_peer *bmpp)
{
  // XXX: maybe support route mirroring
}

void bmp_process_msg_stats(char **bmp_packet, u_int32_t *len, struct bmp_peer *bmpp)
{
  struct bgp_misc_structs *bms;
  struct bgp_peer *peer;
  struct bmp_data bdata;
  struct bmp_peer_hdr *bph;
  struct bmp_stats_hdr *bsh;
  struct bmp_stats_cnt_hdr *bsch;
  u_int64_t cnt_data64;
  u_int32_t index, count = 0, cnt_data32;
  u_int16_t cnt_type, cnt_len;
  u_int8_t got_data;

  if (!bmpp) return;

  peer = &bmpp->self;
  bms = bgp_select_misc_db(peer->type);

  if (!bms) return;

  memset(&bdata, 0, sizeof(bdata));

  if (!(bph = (struct bmp_peer_hdr *) bmp_get_and_check_length(bmp_packet, len, sizeof(struct bmp_peer_hdr)))) {
    Log(LOG_INFO, "INFO ( %s/%s ): [%s] [stats] packet discarded: failed bmp_get_and_check_length() BMP peer hdr\n",
        config.name, bms->log_str, peer->addr_str);
    return;
  }

  if (!(bsh = (struct bmp_stats_hdr *) bmp_get_and_check_length(bmp_packet, len, sizeof(struct bmp_stats_hdr)))) {
    Log(LOG_INFO, "INFO ( %s/%s ): [%s] [stats] packet discarded: failed bmp_get_and_check_length() BMP stats hdr\n",
        config.name, bms->log_str, peer->addr_str);
    return;
  }

  bmp_peer_hdr_get_v_flag(bph, &bdata.family);
  bmp_peer_hdr_get_peer_ip(bph, &bdata.peer_ip, bdata.family);
  bmp_peer_hdr_get_bgp_id(bph, &bdata.bgp_id);
  bmp_peer_hdr_get_l_flag(bph, &bdata.is_post);
  bmp_peer_hdr_get_tstamp(bph, &bdata.tstamp);
  bmp_peer_hdr_get_peer_asn(bph, &bdata.peer_asn);
  bmp_peer_hdr_get_peer_type(bph, &bdata.peer_type);
  bmp_stats_hdr_get_count(bsh, &count);

  if (bdata.family) {
    /* If no timestamp in BMP then let's generate one */
    if (!bdata.tstamp.tv_sec) gettimeofday(&bdata.tstamp, NULL);

    for (index = 0; index < count; index++) {
      if (!(bsch = (struct bmp_stats_cnt_hdr *) bmp_get_and_check_length(bmp_packet, len, sizeof(struct bmp_stats_cnt_hdr)))) {
        Log(LOG_INFO, "INFO ( %s/%s ): [%s] [stats] packet discarded: failed bmp_get_and_check_length() BMP stats cnt hdr #%u\n",
		config.name, bms->log_str, peer->addr_str, index);
        return;
      }

      bmp_stats_cnt_hdr_get_type(bsch, &cnt_type);
      bmp_stats_cnt_hdr_get_len(bsch, &cnt_len);
      cnt_data32 = 0; cnt_data64 = 0, got_data = TRUE;

      switch (cnt_type) {
      case BMP_STATS_TYPE0:
        if (cnt_len == 4) bmp_stats_cnt_get_data32(bmp_packet, len, &cnt_data32);
        break;
      case BMP_STATS_TYPE1:
        if (cnt_len == 4) bmp_stats_cnt_get_data32(bmp_packet, len, &cnt_data32);
        break;
      case BMP_STATS_TYPE2:
        if (cnt_len == 4) bmp_stats_cnt_get_data32(bmp_packet, len, &cnt_data32);
        break;
      case BMP_STATS_TYPE3:
        if (cnt_len == 4) bmp_stats_cnt_get_data32(bmp_packet, len, &cnt_data32);
        break;
      case BMP_STATS_TYPE4:
        if (cnt_len == 4) bmp_stats_cnt_get_data32(bmp_packet, len, &cnt_data32);
        break;
      case BMP_STATS_TYPE5:
        if (cnt_len == 4) bmp_stats_cnt_get_data32(bmp_packet, len, &cnt_data32);
        break;
      case BMP_STATS_TYPE6:
        if (cnt_len == 4) bmp_stats_cnt_get_data32(bmp_packet, len, &cnt_data32);
        break;
      case BMP_STATS_TYPE7:
        if (cnt_len == 8) bmp_stats_cnt_get_data64(bmp_packet, len, &cnt_data64);
        break;
      case BMP_STATS_TYPE8:
        if (cnt_len == 8) bmp_stats_cnt_get_data64(bmp_packet, len, &cnt_data64);
        break;
      default:
        if (cnt_len == 4) bmp_stats_cnt_get_data32(bmp_packet, len, &cnt_data32);
        else if (cnt_len == 8) bmp_stats_cnt_get_data64(bmp_packet, len, &cnt_data64);
        else {
          bmp_get_and_check_length(bmp_packet, len, cnt_len);
          got_data = FALSE;
        }
        break;
      }

      if (cnt_data32 && !cnt_data64) cnt_data64 = cnt_data32; 

      { 
        struct bmp_log_stats blstats;

        blstats.cnt_type = cnt_type;
        blstats.cnt_data = cnt_data64;
        blstats.got_data = got_data;

        if (bms->msglog_backend_methods) {
          char event_type[] = "log";

          bmp_log_msg(peer, &bdata, &blstats, bms->log_seq, event_type, config.nfacctd_bmp_msglog_output, BMP_LOG_TYPE_STATS);
        } 

        if (bms->dump_backend_methods)
          bmp_dump_se_ll_append(peer, &bdata, &blstats, BMP_LOG_TYPE_STATS);

        if (bms->msglog_backend_methods || bms->dump_backend_methods)
          bgp_peer_log_seq_increment(&bms->log_seq);
      }
    }
  }
}

void bmp_common_hdr_get_len(struct bmp_common_hdr *bch, u_int32_t *len)
{
  if (bch && len) (*len) = ntohl(bch->len);
}

void bmp_init_hdr_get_len(struct bmp_init_hdr *bih, u_int16_t *len)
{
  if (bih && len) (*len) = ntohs(bih->len);
}

void bmp_term_hdr_get_len(struct bmp_term_hdr *bth, u_int16_t *len)
{
  if (bth && len) (*len) = ntohs(bth->len);
}

void bmp_term_hdr_get_reason_type(char **bmp_packet, u_int32_t *pkt_size, u_int16_t *type)
{
  char *ptr;

  if (bmp_packet && (*bmp_packet) && pkt_size && type) {
    ptr = bmp_get_and_check_length(bmp_packet, pkt_size, 2);
    memcpy(type, ptr, 2);
    (*type) = ntohs((*type));
  }
}

void bmp_peer_hdr_get_v_flag(struct bmp_peer_hdr *bph, u_int8_t *family)
{
  u_int8_t version;

  if (bph && family) {
    version = (bph->flags & 0x80);
    (*family) = FALSE;

    if (version == 0) (*family) = AF_INET;
#if defined ENABLE_IPV6
    else if (version == 1) (*family) = AF_INET6;
#endif
  }
}

void bmp_peer_hdr_get_l_flag(struct bmp_peer_hdr *bph, u_int8_t *is_post)
{
  if (bph && is_post) (*is_post) = (bph->flags & 0x40);
}

void bmp_peer_hdr_get_a_flag(struct bmp_peer_hdr *bph, u_int8_t *is_2b_asn)
{
  if (bph && is_2b_asn) (*is_2b_asn) = (bph->flags & 0x20);
}

void bmp_peer_hdr_get_peer_ip(struct bmp_peer_hdr *bph, struct host_addr *a, u_int8_t family)
{
  if (bph && a) {
    a->family = family;

    if (family == AF_INET) a->address.ipv4.s_addr = bph->addr[3]; 
#if defined ENABLE_IPV6
    else if (family == AF_INET6) memcpy(&a->address.ipv6, &bph->addr, 16); 
#endif
    else memset(a, 0, sizeof(struct host_addr));
  }
}

void bmp_peer_hdr_get_bgp_id(struct bmp_peer_hdr *bph, struct host_addr *a)
{
  if (bph && a) {
    a->family = AF_INET;
    a->address.ipv4.s_addr = bph->bgp_id;
  }
}

void bmp_peer_hdr_get_tstamp(struct bmp_peer_hdr *bph, struct timeval *tv)
{
  u_int32_t sec, usec;

  if (bph && tv) {
    if (bph->tstamp_sec) {
      sec = ntohl(bph->tstamp_sec);
      usec = ntohl(bph->tstamp_usec);

      tv->tv_sec = sec;
      tv->tv_usec = usec;
    }
  }
}

void bmp_peer_hdr_get_peer_asn(struct bmp_peer_hdr *bph, u_int32_t *asn)
{
  if (bph && asn) (*asn) = ntohl(bph->asn);
}

void bmp_peer_hdr_get_peer_type(struct bmp_peer_hdr *bph, u_int8_t *type)
{
  if (bph && type) (*type) = bph->type;
}

void bmp_peer_up_hdr_get_local_ip(struct bmp_peer_up_hdr *bpuh, struct host_addr *a, u_int8_t family)
{
  if (bpuh && a && family) {
    a->family = family;

    if (family == AF_INET) a->address.ipv4.s_addr = bpuh->loc_addr[3];
#if defined ENABLE_IPV6
    else if (family == AF_INET6) memcpy(&a->address.ipv6, &bpuh->loc_addr, 16);
#endif
  }
}

void bmp_peer_up_hdr_get_loc_port(struct bmp_peer_up_hdr *bpuh, u_int16_t *port)
{
  if (bpuh && port) (*port) = ntohs(bpuh->loc_port);
}

void bmp_peer_up_hdr_get_rem_port(struct bmp_peer_up_hdr *bpuh, u_int16_t *port)
{
  if (bpuh && port) (*port) = ntohs(bpuh->rem_port);
}

void bmp_peer_down_hdr_get_reason(struct bmp_peer_down_hdr *bpdh, u_char *reason)
{
  if (bpdh && reason) (*reason) = bpdh->reason;
}

void bmp_peer_down_hdr_get_loc_code(char **bmp_packet, u_int32_t *pkt_size, u_int16_t *code)
{
  char *ptr;
 
  if (bmp_packet && (*bmp_packet) && pkt_size && code) {
    ptr = bmp_get_and_check_length(bmp_packet, pkt_size, 2); 
    memcpy(code, ptr, 2);
    (*code) = ntohs((*code));
  }
}

void bmp_stats_hdr_get_count(struct bmp_stats_hdr *bsh, u_int32_t *count)
{
  if (bsh && count) (*count) = ntohl(bsh->count);
}

void bmp_stats_cnt_hdr_get_type(struct bmp_stats_cnt_hdr *bsch, u_int16_t *type)
{
  if (bsch && type) (*type) = ntohs(bsch->type);
}

void bmp_stats_cnt_hdr_get_len(struct bmp_stats_cnt_hdr *bsch, u_int16_t *len)
{
  if (bsch && len) (*len) = ntohs(bsch->len);
}

void bmp_stats_cnt_get_data32(char **bmp_packet, u_int32_t *pkt_size, u_int32_t *data)
{
  char *ptr;

  if (bmp_packet && (*bmp_packet) && pkt_size && data) {
    ptr = bmp_get_and_check_length(bmp_packet, pkt_size, 4);
    memcpy(data, ptr, 4);
    (*data) = ntohl((*data));
  }
}

void bmp_stats_cnt_get_data64(char **bmp_packet, u_int32_t *pkt_size, u_int64_t *data)
{
  char *ptr;

  if (bmp_packet && (*bmp_packet) && pkt_size && data) {
    ptr = bmp_get_and_check_length(bmp_packet, pkt_size, 8);
    memcpy(data, ptr, 8);
    (*data) = pm_ntohll((*data));
  }
}
