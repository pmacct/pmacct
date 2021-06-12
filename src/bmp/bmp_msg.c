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
#include "addr.h"
#include "bgp/bgp.h"
#include "bmp.h"
#if defined WITH_RABBITMQ
#include "amqp_common.h"
#endif
#ifdef WITH_KAFKA
#include "kafka_common.h"
#endif

u_int32_t bmp_process_packet(char *bmp_packet, u_int32_t len, struct bmp_peer *bmpp, int *do_term)
{
  struct bgp_misc_structs *bms;
  struct bgp_peer *peer;
  char *bmp_packet_ptr = bmp_packet;
  u_int32_t pkt_remaining_len, orig_msg_len, msg_len, msg_start_len;

  struct bmp_common_hdr *bch = NULL;

  if (do_term) (*do_term) = FALSE;
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
    if (!(bch = (struct bmp_common_hdr *) bmp_get_and_check_length(&bmp_packet_ptr, &pkt_remaining_len, sizeof(struct bmp_common_hdr)))) { 
      return msg_start_len;
    }

    if (bch->version != BMP_V3 && bch->version != BMP_V4) {
      Log(LOG_INFO, "INFO ( %s/%s ): [%s] packet discarded: unknown BMP version: %u (2)\n",
	  config.name, bms->log_str, peer->addr_str, bch->version);
      return FALSE;
    }

    peer->version = bch->version;
    bmp_common_hdr_get_len(bch, &msg_len);
    msg_len -= sizeof(struct bmp_common_hdr);
    orig_msg_len = msg_len;

    if (pkt_remaining_len < msg_len) return msg_start_len;

    if (bch->type <= BMP_MSG_TYPE_MAX) {
      Log(LOG_DEBUG, "DEBUG ( %s/%s ): [%s] [common] type: %s (%u)\n",
	  config.name, bms->log_str, peer->addr_str, bmp_msg_types[bch->type], bch->type);
    }

    switch (bch->type) {
    case BMP_MSG_ROUTE_MONITOR:
      bmp_process_msg_route_monitor(&bmp_packet_ptr, &msg_len, bmpp);
      break;
    case BMP_MSG_STATS:
      bmp_process_msg_stats(&bmp_packet_ptr, &msg_len, bmpp);
      break;
    case BMP_MSG_PEER_DOWN:
      bmp_process_msg_peer_down(&bmp_packet_ptr, &msg_len, bmpp);
      break;
    case BMP_MSG_PEER_UP:
      bmp_process_msg_peer_up(&bmp_packet_ptr, &msg_len, bmpp); 
      break;
    case BMP_MSG_INIT:
      bmp_process_msg_init(&bmp_packet_ptr, &msg_len, bmpp); 
      break;
    case BMP_MSG_TERM:
      bmp_process_msg_term(&bmp_packet_ptr, &msg_len, bmpp); 
      if (do_term) (*do_term) = TRUE;
      break;
    case BMP_MSG_ROUTE_MIRROR:
      bmp_process_msg_route_mirror(&bmp_packet_ptr, &msg_len, bmpp);
      break;
    case BMP_MSG_TMP_RPAT:
      bmp_process_msg_rpat(&bmp_packet_ptr, &msg_len, bmpp);
      break;
    default:
      Log(LOG_INFO, "INFO ( %s/%s ): [%s] packet discarded: unknown message type (%u)\n",
	  config.name, bms->log_str, peer->addr_str, bch->type);
      break;
    }

    /* sync-up status of pkt_remaining_len to bmp_packet_ptr */
    pkt_remaining_len -= (orig_msg_len - msg_len);
 
    if (msg_len) {
      /* let's jump forward: we may have been unable to parse some (sub-)element */
      bmp_jump_offset(&bmp_packet_ptr, &pkt_remaining_len, msg_len);
    }
  }

  return FALSE;
}

void bmp_process_msg_init(char **bmp_packet, u_int32_t *len, struct bmp_peer *bmpp)
{
  struct bgp_misc_structs *bms;
  struct bgp_peer *peer;
  struct bmp_data bdata;
  int ret;

  /* TLV vars */
  struct bmp_tlv_hdr *bth;
  u_int16_t bmp_tlv_type, bmp_tlv_len;
  char *bmp_tlv_value;
  struct pm_list *tlvs = NULL;

  if (!bmpp) return;

  peer = &bmpp->self;
  bms = bgp_select_misc_db(peer->type);

  if (!bms) return;

  memset(&bdata, 0, sizeof(bdata));

  tlvs = bmp_tlv_list_new(NULL, bmp_tlv_list_node_del);
  if (!tlvs) return;

  /* Init message does not contain a timestamp */
  gettimeofday(&bdata.tstamp_arrival, NULL);
  memset(&bdata.tstamp, 0, sizeof(struct timeval));

  while ((*len)) {
    u_int32_t pen = 0;

    if (!(bth = (struct bmp_tlv_hdr *) bmp_get_and_check_length(bmp_packet, len, sizeof(struct bmp_tlv_hdr)))) {
      Log(LOG_INFO, "INFO ( %s/%s ): [%s] [init] packet discarded: failed bmp_get_and_check_length() BMP TLV hdr\n",
	  config.name, bms->log_str, peer->addr_str);
      bmp_tlv_list_destroy(tlvs);
      return;
    }

    bmp_tlv_hdr_get_type(bth, &bmp_tlv_type);
    bmp_tlv_hdr_get_len(bth, &bmp_tlv_len);
    if (bmp_tlv_handle_ebit(&bmp_tlv_type)) {
      if (!(bmp_tlv_get_pen(bmp_packet, len, &bmp_tlv_len, &pen))) {
	Log(LOG_INFO, "INFO ( %s/%s ): [%s] [init] packet discarded: failed bmp_tlv_get_pen()\n",
	    config.name, bms->log_str, peer->addr_str);
	bmp_tlv_list_destroy(tlvs);
	return;
      }
    }

    if (!(bmp_tlv_value = bmp_get_and_check_length(bmp_packet, len, bmp_tlv_len))) {
      Log(LOG_INFO, "INFO ( %s/%s ): [%s] [init] packet discarded: failed bmp_get_and_check_length() BMP TLV info\n",
	  config.name, bms->log_str, peer->addr_str);
      bmp_tlv_list_destroy(tlvs);
      return;
    }

    ret = bmp_tlv_list_add(tlvs, pen, bmp_tlv_type, bmp_tlv_len, bmp_tlv_value);
    if (ret == ERR) {
      Log(LOG_ERR, "ERROR ( %s/%s ): [%s] [init] bmp_tlv_list_add() failed.\n", config.name, bms->log_str, peer->addr_str); 
      exit_gracefully(1);
    }
  }

  if (bms->msglog_backend_methods) {
    char event_type[] = "log";

    bmp_log_msg(peer, &bdata, tlvs, NULL, bgp_peer_log_seq_get(&bms->log_seq), event_type, config.bmp_daemon_msglog_output, BMP_LOG_TYPE_INIT);
  }

  if (bms->dump_backend_methods) bmp_dump_se_ll_append(peer, &bdata, tlvs, NULL, BMP_LOG_TYPE_INIT);

  if (bms->msglog_backend_methods || bms->dump_backend_methods) bgp_peer_log_seq_increment(&bms->log_seq);

  if (!pm_listcount(tlvs) || !bms->dump_backend_methods) bmp_tlv_list_destroy(tlvs);
}

void bmp_process_msg_term(char **bmp_packet, u_int32_t *len, struct bmp_peer *bmpp)
{
  struct bgp_misc_structs *bms;
  struct bgp_peer *peer;
  struct bmp_data bdata;
  int ret = 0;

  /* TLV vars */
  struct bmp_tlv_hdr *bth;
  u_int16_t bmp_tlv_type, bmp_tlv_len;
  char *bmp_tlv_value;
  struct pm_list *tlvs = NULL;

  if (!bmpp) return;

  peer = &bmpp->self;
  bms = bgp_select_misc_db(peer->type);

  if (!bms) return;

  memset(&bdata, 0, sizeof(bdata));

  tlvs = bmp_tlv_list_new(NULL, bmp_tlv_list_node_del);
  if (!tlvs) return;

  /* Term message does not contain a timestamp */
  gettimeofday(&bdata.tstamp_arrival, NULL);
  memset(&bdata.tstamp, 0, sizeof(struct timeval));

  while ((*len)) {
    u_int32_t pen = 0;

    if (!(bth = (struct bmp_tlv_hdr *) bmp_get_and_check_length(bmp_packet, len, sizeof(struct bmp_tlv_hdr)))) {
      Log(LOG_INFO, "INFO ( %s/%s ): [%s] [term] packet discarded: failed bmp_get_and_check_length() BMP TLV hdr\n",
	  config.name, bms->log_str, peer->addr_str);
      bmp_tlv_list_destroy(tlvs);
      return;
    }

    bmp_tlv_hdr_get_type(bth, &bmp_tlv_type);
    bmp_tlv_hdr_get_len(bth, &bmp_tlv_len);
    if (bmp_tlv_handle_ebit(&bmp_tlv_type)) {
      if (!(bmp_tlv_get_pen(bmp_packet, len, &bmp_tlv_len, &pen))) {
	Log(LOG_INFO, "INFO ( %s/%s ): [%s] [term] packet discarded: failed bmp_tlv_get_pen()\n",
	    config.name, bms->log_str, peer->addr_str);
	bmp_tlv_list_destroy(tlvs);
	return;
      }
    }

    if (!(bmp_tlv_value = bmp_get_and_check_length(bmp_packet, len, bmp_tlv_len))) {
      Log(LOG_INFO, "INFO ( %s/%s ): [%s] [term] packet discarded: failed bmp_get_and_check_length() BMP TLV info\n",
	  config.name, bms->log_str, peer->addr_str);
      bmp_tlv_list_destroy(tlvs);
      return;
    }

    ret = bmp_tlv_list_add(tlvs, pen, bmp_tlv_type, bmp_tlv_len, bmp_tlv_value);
    if (ret == ERR) {
      Log(LOG_ERR, "ERROR ( %s/%s ): [%s] [term] bmp_tlv_list_add() failed.\n", config.name, bms->log_str, peer->addr_str);
      exit_gracefully(1);
    }
  }

  if (bms->msglog_backend_methods) {
    char event_type[] = "log";

    bmp_log_msg(peer, &bdata, tlvs, NULL, bgp_peer_log_seq_get(&bms->log_seq), event_type, config.bmp_daemon_msglog_output, BMP_LOG_TYPE_TERM);
  }

  if (bms->dump_backend_methods) bmp_dump_se_ll_append(peer, &bdata, tlvs, NULL, BMP_LOG_TYPE_TERM);

  if (bms->msglog_backend_methods || bms->dump_backend_methods) bgp_peer_log_seq_increment(&bms->log_seq);

  if (!pm_listcount(tlvs) || !bms->dump_backend_methods) bmp_tlv_list_destroy(tlvs);

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

  bmp_peer_hdr_get_peer_type(bph, &bdata.chars.peer_type);
  if (bdata.chars.peer_type == BMP_PEER_TYPE_LOC_RIB) {
    bmp_peer_hdr_get_f_flag(bph, &bdata.chars.is_filtered);
    bdata.chars.is_loc = TRUE;
  }
  else {
    bmp_peer_hdr_get_v_flag(bph, &bdata.family);
    bmp_peer_hdr_get_l_flag(bph, &bdata.chars.is_post);
    bmp_peer_hdr_get_a_flag(bph, &bdata.chars.is_2b_asn);
    bmp_peer_hdr_get_o_flag(bph, &bdata.chars.is_out);
  }

  bmp_peer_hdr_get_peer_ip(bph, &bdata.peer_ip, &bdata.family);
  bmp_peer_hdr_get_bgp_id(bph, &bdata.bgp_id);
  bmp_peer_hdr_get_rd(bph, &bdata.chars.rd);
  bmp_peer_hdr_get_tstamp(bph, &bdata.tstamp);
  bmp_peer_hdr_get_peer_asn(bph, &bdata.peer_asn);

  if (bdata.family) {
    gettimeofday(&bdata.tstamp_arrival, NULL);

    {
      struct bmp_log_peer_up blpu;
      struct bgp_peer bgp_peer_loc, bgp_peer_rem, *bmpp_bgp_peer;
      struct bmp_chars bmed_bmp;
      struct bgp_msg_data bmd;
      int bgp_open_len, ret2 = 0;
      u_int8_t bgp_msg_type = 0;
      void *ret = NULL;

      /* TLV vars */
      struct bmp_tlv_hdr *bth; 
      u_int16_t bmp_tlv_type, bmp_tlv_len;
      char *bmp_tlv_value;
      struct pm_list *tlvs = NULL;

      memset(&bgp_peer_loc, 0, sizeof(bgp_peer_loc));
      memset(&bgp_peer_rem, 0, sizeof(bgp_peer_rem));
      memset(&bmd, 0, sizeof(bmd));
      memset(&bmed_bmp, 0, sizeof(bmed_bmp));

      tlvs = bmp_tlv_list_new(NULL, bmp_tlv_list_node_del);
      if (!tlvs) return;

      bmp_peer_up_hdr_get_loc_port(bpuh, &blpu.loc_port);
      bmp_peer_up_hdr_get_rem_port(bpuh, &blpu.rem_port);
      bmp_peer_up_hdr_get_local_ip(bpuh, &blpu.local_ip, bdata.family);

      bgp_peer_loc.type = FUNC_TYPE_BMP;
      bmd.peer = &bgp_peer_loc;

      bmd.extra.id = BGP_MSG_EXTRA_DATA_BMP;
      bmd.extra.len = sizeof(bmed_bmp);
      bmd.extra.data = &bmed_bmp;
      bgp_msg_data_set_data_bmp(&bmed_bmp, &bdata);

      /* length checks */
      if ((*len) >= sizeof(struct bgp_header)) {
	bgp_open_len = bgp_get_packet_len((*bmp_packet));
	if (bgp_open_len <= 0 || bgp_open_len > (*len)) {
	  Log(LOG_INFO, "INFO ( %s/%s ): [%s] [peer up] packet discarded: failed bgp_get_packet_len()\n",
	      config.name, bms->log_str, peer->addr_str);
	  bmp_tlv_list_destroy(tlvs);
	  return;
	}
      }
      else {
        Log(LOG_INFO, "INFO ( %s/%s ): [%s] [peer_up] packet discarded: incomplete BGP header\n",
            config.name, bms->log_str, peer->addr_str);
	bmp_tlv_list_destroy(tlvs);
        return;
      }

      if ((bgp_msg_type = bgp_get_packet_type((*bmp_packet))) == BGP_OPEN) {
	bgp_open_len = bgp_parse_open_msg(&bmd, (*bmp_packet), FALSE, FALSE);
	if (bgp_open_len == ERR) {
	  Log(LOG_INFO, "INFO ( %s/%s ): [%s] [peer up] packet discarded: failed bgp_parse_open_msg()\n",
	      config.name, bms->log_str, peer->addr_str);
	  bmp_tlv_list_destroy(tlvs);
	  return;
        }
      }
      else {
	Log(LOG_INFO, "INFO ( %s/%s ): [%s] [peer up] packet discarded: wrong BGP message type: %s (%u)\n",
	    config.name, bms->log_str, peer->addr_str,
	    (bgp_msg_type <= BGP_MSG_TYPE_MAX ? bgp_msg_types[bgp_msg_type] : bgp_msg_types[0]),
	    bgp_msg_type);
	bmp_tlv_list_destroy(tlvs);
	return;
      }

      bmp_get_and_check_length(bmp_packet, len, bgp_open_len);
      memcpy(&bmpp->self.id, &bgp_peer_loc.id, sizeof(struct host_addr));
      memcpy(&bgp_peer_loc.addr, &blpu.local_ip, sizeof(struct host_addr));

      bgp_peer_rem.type = FUNC_TYPE_BMP;
      bmd.peer = &bgp_peer_rem;

      /* length checks */
      if ((*len) >= sizeof(struct bgp_header)) {
	bgp_open_len = bgp_get_packet_len((*bmp_packet));
	if (bgp_open_len <= 0 || bgp_open_len > (*len)) {
	  Log(LOG_INFO, "INFO ( %s/%s ): [%s] [peer up] packet discarded: failed bgp_get_packet_len() (2)\n",
	      config.name, bms->log_str, peer->addr_str);
	  bmp_tlv_list_destroy(tlvs);
	  return;
        }
      }
      else {
	Log(LOG_INFO, "INFO ( %s/%s ): [%s] [peer_up] packet discarded: incomplete BGP header (2)\n",
	    config.name, bms->log_str, peer->addr_str);
	bmp_tlv_list_destroy(tlvs);
	return;
      }

      if ((bgp_msg_type = bgp_get_packet_type((*bmp_packet))) == BGP_OPEN) {
	bgp_open_len = bgp_parse_open_msg(&bmd, (*bmp_packet), FALSE, FALSE);
	if (bgp_open_len == ERR) {
	  Log(LOG_INFO, "INFO ( %s/%s ): [%s] [peer up] packet discarded: failed bgp_parse_open_msg() (2)\n",
	      config.name, bms->log_str, peer->addr_str);
	  bmp_tlv_list_destroy(tlvs);
	  return;
	}
      }
      else {
	Log(LOG_INFO, "INFO ( %s/%s ): [%s] [peer up] packet discarded: wrong BGP message type: %u (2)\n",
	    config.name, bms->log_str, peer->addr_str, bgp_msg_type);
	bmp_tlv_list_destroy(tlvs);
	return;
      }

      bmp_get_and_check_length(bmp_packet, len, bgp_open_len);
      memcpy(&bgp_peer_rem.addr, &bdata.peer_ip, sizeof(struct host_addr));

      bmpp_bgp_peer = bmp_sync_loc_rem_peers(&bgp_peer_loc, &bgp_peer_rem);
      bmpp_bgp_peer->log = bmpp->self.log; 
      bmpp_bgp_peer->bmp_se = bmpp; /* using bmp_se field to back-point a BGP peer to its parent BMP peer */  

      if (bdata.family == AF_INET) {
	ret = pm_tsearch(bmpp_bgp_peer, &bmpp->bgp_peers_v4, bgp_peer_cmp, sizeof(struct bgp_peer));
      }
      else if (bdata.family == AF_INET6) {
	ret = pm_tsearch(bmpp_bgp_peer, &bmpp->bgp_peers_v6, bgp_peer_cmp, sizeof(struct bgp_peer));
      }

      if (!ret) Log(LOG_WARNING, "WARN ( %s/%s ): [%s] [peer up] tsearch() unable to insert.\n", config.name, bms->log_str, peer->addr_str);

      while ((*len)) {
	u_int32_t pen = 0;

	if (!(bth = (struct bmp_tlv_hdr *) bmp_get_and_check_length(bmp_packet, len, sizeof(struct bmp_tlv_hdr)))) {
	  Log(LOG_INFO, "INFO ( %s/%s ): [%s] [peer up] packet discarded: failed bmp_get_and_check_length() BMP TLV hdr\n",
	      config.name, bms->log_str, peer->addr_str);
	  bmp_tlv_list_destroy(tlvs);
	  return;
	}

	bmp_tlv_hdr_get_type(bth, &bmp_tlv_type);
	bmp_tlv_hdr_get_len(bth, &bmp_tlv_len);
	if (bmp_tlv_handle_ebit(&bmp_tlv_type)) {
	  if (!(bmp_tlv_get_pen(bmp_packet, len, &bmp_tlv_len, &pen))) {
	    Log(LOG_INFO, "INFO ( %s/%s ): [%s] [peer up] packet discarded: failed bmp_tlv_get_pen()\n",
		config.name, bms->log_str, peer->addr_str);
	    bmp_tlv_list_destroy(tlvs);
	    return;
	  }
	}

	if (!(bmp_tlv_value = bmp_get_and_check_length(bmp_packet, len, bmp_tlv_len))) {
	  Log(LOG_INFO, "INFO ( %s/%s ): [%s] [peer up] packet discarded: failed bmp_get_and_check_length() BMP TLV info\n",
	      config.name, bms->log_str, peer->addr_str);
	  bmp_tlv_list_destroy(tlvs);
	  return;
	}

	ret2 = bmp_tlv_list_add(tlvs, pen, bmp_tlv_type, bmp_tlv_len, bmp_tlv_value);
	if (ret2 == ERR) {
	  Log(LOG_ERR, "ERROR ( %s/%s ): [%s] [peer up] bmp_tlv_list_add() failed.\n", config.name, bms->log_str, peer->addr_str);
	  exit_gracefully(1);
	}
      }

      if (bms->msglog_backend_methods) {
        char event_type[] = "log";

        bmp_log_msg(peer, &bdata, tlvs, &blpu, bgp_peer_log_seq_get(&bms->log_seq), event_type, config.bmp_daemon_msglog_output, BMP_LOG_TYPE_PEER_UP);
      }

      if (bms->dump_backend_methods) bmp_dump_se_ll_append(peer, &bdata, tlvs, &blpu, BMP_LOG_TYPE_PEER_UP);

      if (bms->msglog_backend_methods || bms->dump_backend_methods) bgp_peer_log_seq_increment(&bms->log_seq);

      if (!pm_listcount(tlvs) || !bms->dump_backend_methods) bmp_tlv_list_destroy(tlvs);
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
  void *ret = NULL;

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

  bmp_peer_hdr_get_peer_type(bph, &bdata.chars.peer_type);
  if (bdata.chars.peer_type == BMP_PEER_TYPE_LOC_RIB) {
    bdata.chars.is_loc = TRUE;
  }
  else {
    bmp_peer_hdr_get_v_flag(bph, &bdata.family);
    bmp_peer_hdr_get_l_flag(bph, &bdata.chars.is_post);
    bmp_peer_hdr_get_o_flag(bph, &bdata.chars.is_out);
  }

  bmp_peer_hdr_get_peer_ip(bph, &bdata.peer_ip, &bdata.family);
  bmp_peer_hdr_get_bgp_id(bph, &bdata.bgp_id);
  bmp_peer_hdr_get_rd(bph, &bdata.chars.rd);
  bmp_peer_hdr_get_tstamp(bph, &bdata.tstamp);
  bmp_peer_hdr_get_peer_asn(bph, &bdata.peer_asn);

  if (bdata.family) {
    gettimeofday(&bdata.tstamp_arrival, NULL);

    {
      struct bmp_log_peer_down blpd;
      int ret2 = 0;

      /* TLV vars */
      struct bmp_tlv_hdr *bth; 
      u_int16_t bmp_tlv_type, bmp_tlv_len;
      char *bmp_tlv_value;
      struct pm_list *tlvs = NULL;

      tlvs = bmp_tlv_list_new(NULL, bmp_tlv_list_node_del);
      if (!tlvs) return;

      bmp_peer_down_hdr_get_reason(bpdh, &blpd.reason);
      if (blpd.reason == BMP_PEER_DOWN_LOC_CODE) bmp_peer_down_hdr_get_loc_code(bmp_packet, len, &blpd.loc_code);

      /* draft-ietf-grow-bmp-tlv */
      if (peer->version == BMP_V4) {
	/* let's skip intermediate data in order to get to TLVs */
	if (blpd.reason == BMP_PEER_DOWN_LOC_NOT_MSG || blpd.reason == BMP_PEER_DOWN_REM_NOT_MSG) {
	  int bgp_notification_len = 0;

	  bgp_notification_len = bgp_get_packet_len((*bmp_packet));
	  if (bgp_notification_len <= 0 || bgp_notification_len > (*len)) {
	    Log(LOG_INFO, "INFO ( %s/%s ): [%s] [peer down] packet discarded: failed bgp_get_packet_len() reason=%u\n",
		config.name, bms->log_str, peer->addr_str, blpd.reason);
	    bmp_tlv_list_destroy(tlvs);
	    return;
	  }

	  bmp_jump_offset(bmp_packet, len, bgp_notification_len);
	}
	else if (blpd.reason == BMP_PEER_DOWN_LOC_CODE) {
	  ret2 = bmp_jump_offset(bmp_packet, len, 2);
	  if (ret2 == ERR) {
	    Log(LOG_INFO, "INFO ( %s/%s ): [%s] [peer down] packet discarded: failed bmp_jump_offset() reason=%u\n",
		config.name, bms->log_str, peer->addr_str, blpd.reason);
	    bmp_tlv_list_destroy(tlvs);
	    return;
	  }
	}

        while ((*len)) {
	  u_int32_t pen = 0;

	  if (!(bth = (struct bmp_tlv_hdr *) bmp_get_and_check_length(bmp_packet, len, sizeof(struct bmp_tlv_hdr)))) {
	    Log(LOG_INFO, "INFO ( %s/%s ): [%s] [peer down] packet discarded: failed bmp_get_and_check_length() BMP TLV hdr\n",
		config.name, bms->log_str, peer->addr_str);
	    bmp_tlv_list_destroy(tlvs);
	    return;
	  }

	  bmp_tlv_hdr_get_type(bth, &bmp_tlv_type);
	  bmp_tlv_hdr_get_len(bth, &bmp_tlv_len);
	  if (bmp_tlv_handle_ebit(&bmp_tlv_type)) {
	    if (!(bmp_tlv_get_pen(bmp_packet, len, &bmp_tlv_len, &pen))) {
	      Log(LOG_INFO, "INFO ( %s/%s ): [%s] [peer down] packet discarded: failed bmp_tlv_get_pen()\n",
		  config.name, bms->log_str, peer->addr_str);
	      bmp_tlv_list_destroy(tlvs);
	      return;
	    }
	  }

	  if (!(bmp_tlv_value = bmp_get_and_check_length(bmp_packet, len, bmp_tlv_len))) {
	    Log(LOG_INFO, "INFO ( %s/%s ): [%s] [peer down] packet discarded: failed bmp_get_and_check_length() BMP TLV info\n",
		config.name, bms->log_str, peer->addr_str);
	    bmp_tlv_list_destroy(tlvs);
	    return;
	  }

	  ret2 = bmp_tlv_list_add(tlvs, pen, bmp_tlv_type, bmp_tlv_len, bmp_tlv_value);
	  if (ret2 == ERR) {
	    Log(LOG_ERR, "ERROR ( %s/%s ): [%s] [peer down] bmp_tlv_list_add() failed.\n", config.name, bms->log_str, peer->addr_str);
	    exit_gracefully(1);
	  }
	}
      }

      if (bms->msglog_backend_methods) {
        char event_type[] = "log";

        bmp_log_msg(peer, &bdata, tlvs, &blpd, bgp_peer_log_seq_get(&bms->log_seq), event_type, config.bmp_daemon_msglog_output, BMP_LOG_TYPE_PEER_DOWN);
      }

      if (bms->dump_backend_methods) bmp_dump_se_ll_append(peer, &bdata, tlvs, &blpd, BMP_LOG_TYPE_PEER_DOWN);

      if (bms->msglog_backend_methods || bms->dump_backend_methods) bgp_peer_log_seq_increment(&bms->log_seq);

      if (!pm_listcount(tlvs) || !bms->dump_backend_methods) bmp_tlv_list_destroy(tlvs);
    }

    if (bdata.family == AF_INET) {
      ret = pm_tfind(&bdata.peer_ip, &bmpp->bgp_peers_v4, bgp_peer_host_addr_cmp);
    }
    else if (bdata.family == AF_INET6) {
      ret = pm_tfind(&bdata.peer_ip, &bmpp->bgp_peers_v6, bgp_peer_host_addr_cmp);
    }

    if (ret) {
      bmpp_bgp_peer = (*(struct bgp_peer **) ret);
    
      bgp_peer_info_delete(bmpp_bgp_peer);

      if (bdata.family == AF_INET) {
	pm_tdelete(&bdata.peer_ip, &bmpp->bgp_peers_v4, bgp_peer_host_addr_cmp);
      }
      else if (bdata.family == AF_INET6) {
	pm_tdelete(&bdata.peer_ip, &bmpp->bgp_peers_v6, bgp_peer_host_addr_cmp);
      }
    } 
    /* missing BMP peer up message, ie. case of replay/replication of BMP messages */
    else {
      char peer_ip[INET6_ADDRSTRLEN];

      addr_to_str(peer_ip, &bdata.peer_ip);

      if (!log_notification_isset(&bmpp->missing_peer_up, bdata.tstamp_arrival.tv_sec)) {
        log_notification_set(&bmpp->missing_peer_up, bdata.tstamp_arrival.tv_sec, BMP_MISSING_PEER_UP_LOG_TOUT);
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
  int bgp_update_len, ret2 = 0;
  u_int8_t bgp_msg_type = 0;
  void *ret = NULL;

  if (!bmpp) return;

  peer = &bmpp->self;
  bms = bgp_select_misc_db(peer->type);

  if (!bms) return;

  memset(&bdata, 0, sizeof(bdata));

  if (!(bph = (struct bmp_peer_hdr *) bmp_get_and_check_length(bmp_packet, len, sizeof(struct bmp_peer_hdr)))) {
    Log(LOG_INFO, "INFO ( %s/%s ): [%s] [route monitor] packet discarded: failed bmp_get_and_check_length() BMP peer hdr\n",
        config.name, bms->log_str, peer->addr_str);
    return;
  }

  bmp_peer_hdr_get_peer_type(bph, &bdata.chars.peer_type);
  if (bdata.chars.peer_type == BMP_PEER_TYPE_LOC_RIB) {
    bmp_peer_hdr_get_f_flag(bph, &bdata.chars.is_filtered);
    bdata.chars.is_loc = TRUE;
  }
  else {
    bmp_peer_hdr_get_v_flag(bph, &bdata.family);
    bmp_peer_hdr_get_l_flag(bph, &bdata.chars.is_post);
    bmp_peer_hdr_get_a_flag(bph, &bdata.chars.is_2b_asn);
    bmp_peer_hdr_get_o_flag(bph, &bdata.chars.is_out);
  }

  bmp_peer_hdr_get_peer_ip(bph, &bdata.peer_ip, &bdata.family);
  bmp_peer_hdr_get_bgp_id(bph, &bdata.bgp_id);
  bmp_peer_hdr_get_rd(bph, &bdata.chars.rd);
  bmp_peer_hdr_get_tstamp(bph, &bdata.tstamp);
  bmp_peer_hdr_get_peer_asn(bph, &bdata.peer_asn);

  if (bdata.family) {
    gettimeofday(&bdata.tstamp_arrival, NULL);

    if (bdata.family == AF_INET) {
      ret = pm_tfind(&bdata.peer_ip, &bmpp->bgp_peers_v4, bgp_peer_host_addr_cmp);
    }
    else if (bdata.family == AF_INET6) {
      ret = pm_tfind(&bdata.peer_ip, &bmpp->bgp_peers_v6, bgp_peer_host_addr_cmp);
    }

    if (ret) {
      struct bmp_chars bmed_bmp;
      struct bgp_msg_data bmd;

      bmpp_bgp_peer = (*(struct bgp_peer **) ret);
      memset(&bmd, 0, sizeof(bmd));
      memset(&bmed_bmp, 0, sizeof(bmed_bmp));

      bmd.peer = bmpp_bgp_peer;
      bmd.extra.id = BGP_MSG_EXTRA_DATA_BMP;
      bmd.extra.len = sizeof(bmed_bmp);
      bmd.extra.data = &bmed_bmp;
      bgp_msg_data_set_data_bmp(&bmed_bmp, &bdata);

      compose_timestamp(bms->log_tstamp_str, SRVBUFLEN, &bdata.tstamp, TRUE,
			config.timestamps_since_epoch, config.timestamps_rfc3339,
			config.timestamps_utc);

      encode_tstamp_arrival(bms->log_tstamp_str, SRVBUFLEN, &bdata.tstamp_arrival, TRUE);

      /* length checks & draft-ietf-grow-bmp-tlv preps */
      if ((*len) >= sizeof(struct bgp_header)) {
        bgp_update_len = bgp_get_packet_len((*bmp_packet));
        if (bgp_update_len <= 0 || bgp_update_len > (*len)) {
	  Log(LOG_INFO, "INFO ( %s/%s ): [%s] [route monitor] packet discarded: bgp_get_packet_len() failed\n",
	      config.name, bms->log_str, peer->addr_str);
	  return;
	}
      }
      else {
	Log(LOG_INFO, "INFO ( %s/%s ): [%s] [route monitor] packet discarded: incomplete BGP header\n",
	    config.name, bms->log_str, peer->addr_str);
	return;
      }

      if (peer->version == BMP_V4 && bgp_update_len && bgp_update_len < (*len)) {
	struct bmp_tlv_hdr *bth;
	u_int16_t bmp_tlv_type, bmp_tlv_len;
	char *bmp_tlv_value;
	struct pm_list *tlvs = NULL;

	tlvs = bmp_tlv_list_new(NULL, bmp_tlv_list_node_del);
	if (!tlvs) return;

	u_int32_t loc_len = (*len);
	char *loc_ptr = (*bmp_packet);

	bmp_jump_offset(&loc_ptr, &loc_len, bgp_update_len);

	while (loc_len) {
	  u_int32_t pen = 0;

	  if (!(bth = (struct bmp_tlv_hdr *) bmp_get_and_check_length(&loc_ptr, &loc_len, sizeof(struct bmp_tlv_hdr)))) {
	    Log(LOG_INFO, "INFO ( %s/%s ): [%s] [route monitor] packet discarded: failed bmp_get_and_check_length() BMP TLV hdr\n",
		config.name, bms->log_str, peer->addr_str);
	    bmp_tlv_list_destroy(tlvs);
	    return;
	  }

	  bmp_tlv_hdr_get_type(bth, &bmp_tlv_type);
	  bmp_tlv_hdr_get_len(bth, &bmp_tlv_len);
	  if (bmp_tlv_handle_ebit(&bmp_tlv_type)) {
	    if (!(bmp_tlv_get_pen(&loc_ptr, &loc_len, &bmp_tlv_len, &pen))) {
	      Log(LOG_INFO, "INFO ( %s/%s ): [%s] [route monitor] packet discarded: failed bmp_tlv_get_pen()\n",
		  config.name, bms->log_str, peer->addr_str);
	      bmp_tlv_list_destroy(tlvs);
	      return;
	    }
	  }

	  if (!(bmp_tlv_value = bmp_get_and_check_length(&loc_ptr, &loc_len, bmp_tlv_len))) {
	    Log(LOG_INFO, "INFO ( %s/%s ): [%s] [route monitor] packet discarded: failed bmp_get_and_check_length() BMP TLV info\n",
		config.name, bms->log_str, peer->addr_str);
	    bmp_tlv_list_destroy(tlvs);
	    return;
	  }

	  ret2 = bmp_tlv_list_add(tlvs, pen, bmp_tlv_type, bmp_tlv_len, bmp_tlv_value);
	  if (ret2 == ERR) {
	    Log(LOG_ERR, "ERROR ( %s/%s ): [%s] [route monitor] bmp_tlv_list_add() failed.\n", config.name, bms->log_str, peer->addr_str);
	    exit_gracefully(1);
	  }
        }

        bmed_bmp.tlvs = tlvs;
      }

      if ((bgp_msg_type = bgp_get_packet_type((*bmp_packet))) == BGP_UPDATE) {
	bgp_update_len = bgp_parse_update_msg(&bmd, (*bmp_packet));
	if (bgp_update_len <= 0) {
	  Log(LOG_INFO, "INFO ( %s/%s ): [%s] [route monitor] packet discarded: bgp_parse_update_msg() failed\n",
	      config.name, bms->log_str, peer->addr_str);
	  bmp_tlv_list_destroy(bmed_bmp.tlvs);
	  return;
	}
      }
      else {
	Log(LOG_DEBUG, "DEBUG ( %s/%s ): [%s] [route monitor] packet discarded: unsupported BGP message type: %s (%u)\n",
	    config.name, bms->log_str, peer->addr_str,
	    (bgp_msg_type <= BGP_MSG_TYPE_MAX ? bgp_msg_types[bgp_msg_type] : bgp_msg_types[0]),
	    bgp_msg_type);
      }

      bmp_get_and_check_length(bmp_packet, len, bgp_update_len);

      bmp_tlv_list_destroy(bmed_bmp.tlvs);
    }
    /* missing BMP peer up message, ie. case of replay/replication of BMP messages */
    else {
      if (!log_notification_isset(&bmpp->missing_peer_up, bdata.tstamp_arrival.tv_sec)) {
	char peer_ip[INET6_ADDRSTRLEN];

	addr_to_str(peer_ip, &bdata.peer_ip);

	log_notification_set(&bmpp->missing_peer_up, bdata.tstamp_arrival.tv_sec, BMP_MISSING_PEER_UP_LOG_TOUT);
	Log(LOG_INFO, "INFO ( %s/%s ): [%s] [route monitor] packet discarded: missing peer up BMP message for peer %s\n",
	    config.name, bms->log_str, peer->addr_str, peer_ip);
      }
    }
  }
}

void bmp_process_msg_route_mirror(char **bmp_packet, u_int32_t *len, struct bmp_peer *bmpp)
{
  struct bgp_misc_structs *bms;
  struct bgp_peer *peer;

  if (!bmpp) return;

  peer = &bmpp->self;
  bms = bgp_select_misc_db(peer->type);

  if (!bms) return;

  Log(LOG_INFO, "INFO ( %s/%s ): [%s] [route mirror] packet discarded: Unicorn! Message type currently not supported.\n",
      config.name, bms->log_str, peer->addr_str);

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
  afi_t afi;
  safi_t safi;
  int ret;

  /* unknown stats TLVs */
  char *cnt_value;
  struct pm_list *tlvs = NULL;

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

  bmp_peer_hdr_get_peer_type(bph, &bdata.chars.peer_type);
  if (bdata.chars.peer_type == BMP_PEER_TYPE_LOC_RIB) {
    bmp_peer_hdr_get_f_flag(bph, &bdata.chars.is_filtered);
    bdata.chars.is_loc = TRUE;
  }
  else {
    bmp_peer_hdr_get_v_flag(bph, &bdata.family);
    bmp_peer_hdr_get_l_flag(bph, &bdata.chars.is_post);
    bmp_peer_hdr_get_o_flag(bph, &bdata.chars.is_out);
  }

  bmp_peer_hdr_get_peer_ip(bph, &bdata.peer_ip, &bdata.family);
  bmp_peer_hdr_get_bgp_id(bph, &bdata.bgp_id);
  bmp_peer_hdr_get_rd(bph, &bdata.chars.rd);
  bmp_peer_hdr_get_tstamp(bph, &bdata.tstamp);
  bmp_peer_hdr_get_peer_asn(bph, &bdata.peer_asn);
  bmp_stats_hdr_get_count(bsh, &count);

  if (bdata.family) {
    gettimeofday(&bdata.tstamp_arrival, NULL);

    for (index = 0; index < count; index++) {
      if (!(bsch = (struct bmp_stats_cnt_hdr *) bmp_get_and_check_length(bmp_packet, len, sizeof(struct bmp_stats_cnt_hdr)))) {
        Log(LOG_INFO, "INFO ( %s/%s ): [%s] [stats] packet discarded: failed bmp_get_and_check_length() BMP stats cnt hdr #%u\n",
	    config.name, bms->log_str, peer->addr_str, index);
        return;
      }

      cnt_value = 0;
      tlvs = bmp_tlv_list_new(NULL, bmp_tlv_list_node_del);
      if (!tlvs) return;

      bmp_stats_cnt_hdr_get_type(bsch, &cnt_type);
      bmp_stats_cnt_hdr_get_len(bsch, &cnt_len);
      cnt_data32 = 0, cnt_data64 = 0, afi = 0, safi = 0;

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
      case BMP_STATS_TYPE9:
	if (cnt_len == 11) bmp_stats_cnt_get_afi_safi_data64(bmp_packet, len, &afi, &safi, &cnt_data64);
	break;
      case BMP_STATS_TYPE10:
	if (cnt_len == 11) bmp_stats_cnt_get_afi_safi_data64(bmp_packet, len, &afi, &safi, &cnt_data64);
	break;
      case BMP_STATS_TYPE11:
        if (cnt_len == 4) bmp_stats_cnt_get_data32(bmp_packet, len, &cnt_data32);
        break;
      case BMP_STATS_TYPE12:
        if (cnt_len == 4) bmp_stats_cnt_get_data32(bmp_packet, len, &cnt_data32);
        break;
      case BMP_STATS_TYPE13:
        if (cnt_len == 4) bmp_stats_cnt_get_data32(bmp_packet, len, &cnt_data32);
        break;
      case BMP_STATS_TYPE14:
	if (cnt_len == 8) bmp_stats_cnt_get_data64(bmp_packet, len, &cnt_data64);
	break;
      case BMP_STATS_TYPE15:
	if (cnt_len == 8) bmp_stats_cnt_get_data64(bmp_packet, len, &cnt_data64);
	break;
      case BMP_STATS_TYPE16:
	if (cnt_len == 11) bmp_stats_cnt_get_afi_safi_data64(bmp_packet, len, &afi, &safi, &cnt_data64);
	break;
      case BMP_STATS_TYPE17:
	if (cnt_len == 11) bmp_stats_cnt_get_afi_safi_data64(bmp_packet, len, &afi, &safi, &cnt_data64);
	break;
      default:
	if (!(cnt_value = bmp_get_and_check_length(bmp_packet, len, cnt_len))) {
	  Log(LOG_INFO, "INFO ( %s/%s ): [%s] [stats] packet discarded: failed bmp_get_and_check_length() BMP TLV info\n",
	      config.name, bms->log_str, peer->addr_str);
	  bmp_tlv_list_destroy(tlvs);
	  return;
	}

	ret = bmp_tlv_list_add(tlvs, 0, cnt_type, cnt_len, cnt_value);
	if (ret == ERR) {
	  Log(LOG_ERR, "ERROR ( %s/%s ): [%s] [stats] bmp_tlv_list_add() failed.\n", config.name, bms->log_str, peer->addr_str);
	  exit_gracefully(1);
	}

        break;
      }

      if (cnt_data32 && !cnt_data64) cnt_data64 = cnt_data32; 

      { 
        struct bmp_log_stats blstats;

	memset(&blstats, 0, sizeof(blstats));
        blstats.cnt_type = cnt_type;
	blstats.cnt_afi = afi;
	blstats.cnt_safi = safi;
        blstats.cnt_data = cnt_data64;

        if (bms->msglog_backend_methods) {
          char event_type[] = "log";

          bmp_log_msg(peer, &bdata, tlvs, &blstats, bgp_peer_log_seq_get(&bms->log_seq), event_type, config.bmp_daemon_msglog_output, BMP_LOG_TYPE_STATS);
        } 

        if (bms->dump_backend_methods) bmp_dump_se_ll_append(peer, &bdata, tlvs, &blstats, BMP_LOG_TYPE_STATS);

        if (bms->msglog_backend_methods || bms->dump_backend_methods) bgp_peer_log_seq_increment(&bms->log_seq);

	if (!pm_listcount(tlvs) || !bms->dump_backend_methods) bmp_tlv_list_destroy(tlvs);
      }
    }
  }
}

void bmp_common_hdr_get_len(struct bmp_common_hdr *bch, u_int32_t *len)
{
  if (bch && len) (*len) = ntohl(bch->len);
}

void bmp_tlv_hdr_get_type(struct bmp_tlv_hdr *bth, u_int16_t *type)
{
  if (bth && type) (*type) = ntohs(bth->type);
}

void bmp_tlv_hdr_get_len(struct bmp_tlv_hdr *bth, u_int16_t *len)
{
  if (bth && len) (*len) = ntohs(bth->len);
}

void bmp_term_hdr_get_reason_type(char **bmp_packet, u_int32_t *pkt_size, u_int16_t *type)
{
  char *ptr;

  if (bmp_packet && (*bmp_packet) && pkt_size && type) {
    ptr = bmp_get_and_check_length(bmp_packet, pkt_size, 2);
    
    if (ptr) { 
      memcpy(type, ptr, 2);
      (*type) = ntohs((*type));
    }
  }
}

void bmp_peer_hdr_get_v_flag(struct bmp_peer_hdr *bph, u_int8_t *family)
{
  u_int8_t version;

  if (bph && family) {
    version = (bph->flags & BMP_PEER_FLAGS_ARI_V);
    (*family) = FALSE;

    if (version == 0) (*family) = AF_INET;
    else (*family) = AF_INET6;
  }
}

void bmp_peer_hdr_get_l_flag(struct bmp_peer_hdr *bph, u_int8_t *is_post)
{
  if (bph && is_post) {
    if (bph->flags & BMP_PEER_FLAGS_ARI_L) (*is_post) = TRUE;
    else (*is_post) = FALSE;
  }
}

void bmp_peer_hdr_get_a_flag(struct bmp_peer_hdr *bph, u_int8_t *is_2b_asn)
{
  if (bph && is_2b_asn) {
    if (bph->flags & BMP_PEER_FLAGS_ARI_A) (*is_2b_asn) = TRUE;
    else (*is_2b_asn) = FALSE;
  }
}

void bmp_peer_hdr_get_f_flag(struct bmp_peer_hdr *bph, u_int8_t *is_filtered)
{
  if (bph && is_filtered) {
    if (bph->flags & BMP_PEER_FLAGS_LR_F) (*is_filtered) = TRUE;
    else (*is_filtered) = FALSE;
  }
}

void bmp_peer_hdr_get_o_flag(struct bmp_peer_hdr *bph, u_int8_t *is_out)
{
  if (bph && is_out) {
    if (bph->flags & BMP_PEER_FLAGS_ARO_O)  (*is_out) = TRUE;
    else (*is_out) = FALSE;
  }
}

void bmp_peer_hdr_get_peer_ip(struct bmp_peer_hdr *bph, struct host_addr *a, u_int8_t *family)
{
  if (bph && a) {
    if ((*family) == AF_INET) a->address.ipv4.s_addr = bph->addr[3];
    else if ((*family) == AF_INET6) memcpy(&a->address.ipv6, &bph->addr, 16);
    else {
      memset(a, 0, sizeof(struct host_addr));
      if (!bph->addr[0] && !bph->addr[1] && !bph->addr[2] && !bph->addr[3]) {
	(*family) = AF_INET; /* we just set this up to something non-zero */
      }
    }

    a->family = (*family);
  }
}

void bmp_peer_hdr_get_bgp_id(struct bmp_peer_hdr *bph, struct host_addr *a)
{
  if (bph && a) {
    a->family = AF_INET;
    a->address.ipv4.s_addr = bph->bgp_id;
  }
}

void bmp_peer_hdr_get_rd(struct bmp_peer_hdr *bph, rd_t *rd)
{
  if (bph && rd) {
    if (bph->type == BMP_PEER_TYPE_L3VPN || bph->type == BMP_PEER_TYPE_LOC_RIB) {
      memcpy(rd, bph->rd, RD_LEN);
      bgp_rd_ntoh(rd);

      if (!is_empty_256b(rd, RD_LEN)) {
        bgp_rd_origin_set(rd, RD_ORIGIN_BMP);
      }
    }
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
    else if (family == AF_INET6) memcpy(&a->address.ipv6, &bpuh->loc_addr, 16);
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

void bmp_stats_cnt_get_afi_safi_data64(char **bmp_packet, u_int32_t *pkt_size, afi_t *afi, safi_t *safi, u_int64_t *data)
{
  char *ptr;

  if (bmp_packet && (*bmp_packet) && pkt_size && afi && safi && data) {
    ptr = bmp_get_and_check_length(bmp_packet, pkt_size, 2);
    memcpy(afi, ptr, 2);
    (*afi) = ntohs((*afi));

    ptr = bmp_get_and_check_length(bmp_packet, pkt_size, 1);
    memcpy(safi, ptr, 1);

    ptr = bmp_get_and_check_length(bmp_packet, pkt_size, 8);
    memcpy(data, ptr, 8);
    (*data) = pm_ntohll((*data));
  }
}
