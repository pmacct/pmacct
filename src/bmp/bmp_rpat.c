/*  
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2020 by Paolo Lucente
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

/* functions */
void bmp_process_msg_rpat(char **bmp_packet, u_int32_t *len, struct bmp_peer *bmpp)
{
  struct bgp_misc_structs *bms;
  struct bgp_peer *peer;
  struct bmp_data bdata;
  struct bmp_rpat_common_hdr *brch;
  struct bmp_rpat_event_hdr *breh; 
  struct bmp_log_rpat blrpat;
  int idx, tecount, telen;

  if (!bmpp) return;

  peer = &bmpp->self;
  bms = bgp_select_misc_db(peer->type);

  if (!bms) return;

  memset(&bdata, 0, sizeof(bdata));
  memset(&blrpat, 0, sizeof(blrpat));

  if (!(brch = (struct bmp_rpat_common_hdr *) bmp_get_and_check_length(bmp_packet, len, sizeof(struct bmp_rpat_common_hdr)))) {
    Log(LOG_INFO, "INFO ( %s/%s ): [%s] [rpat] packet discarded: failed bmp_get_and_check_length() BMP rpat common hdr\n",
	config.name, bms->log_str, peer->addr_str);
    return;
  }

  bmp_rpat_common_hdr_get_v_flag(brch, &bdata.family);
  bmp_rpat_common_hdr_get_bgp_id(brch, &bdata.bgp_id);
  bmp_rpat_common_hdr_get_rd(brch, &bdata.rd);
  bmp_rpat_common_hdr_get_prefix(brch, &blrpat.prefix, &bdata.family);
  bmp_rpat_common_hdr_get_prefix_len(brch, &blrpat.prefix_len);

  tecount = brch->events_count;
  telen = ntohs(brch->events_length);

  for (idx = 0; (idx < tecount) && (telen > 0); idx++) {
    u_int32_t orig_loc_len, rmn_loc_len;
    int ret, elen;

    /* TLV vars */
    struct bmp_tlv_hdr *bth;
    u_int16_t bmp_tlv_type, bmp_tlv_len;
    char *bmp_tlv_value;
    struct pm_list *tlvs = NULL;

    tlvs = bmp_tlv_list_new(NULL, bmp_tlv_list_node_del);
    if (!tlvs) return;

    if (!(breh = (struct bmp_rpat_event_hdr *) bmp_get_and_check_length(bmp_packet, len, sizeof(struct bmp_rpat_event_hdr)))) {
      Log(LOG_INFO, "INFO ( %s/%s ): [%s] [rpat] packet discarded: failed bmp_get_and_check_length() BMP rpat event hdr\n",
	  config.name, bms->log_str, peer->addr_str);
      bmp_tlv_list_destroy(tlvs);
      return;
    }

    elen = rmn_loc_len = ntohs(breh->len);
    orig_loc_len = rmn_loc_len = (rmn_loc_len - sizeof(struct bmp_rpat_event_hdr));
    
    bmp_rpat_event_hdr_get_index(breh, &blrpat.event_idx);
    bmp_rpat_event_hdr_get_tstamp(breh, &blrpat.tstamp);
    bmp_rpat_event_hdr_get_path_id(breh, &blrpat.path_id);
    bmp_rpat_event_hdr_get_afi_safi(breh, &blrpat.afi, &blrpat.safi);

    while (rmn_loc_len) {
      if (!(bth = (struct bmp_tlv_hdr *) bmp_get_and_check_length(bmp_packet, &rmn_loc_len, sizeof(struct bmp_tlv_hdr)))) {
	Log(LOG_INFO, "INFO ( %s/%s ): [%s] [rpat] packet discarded: failed bmp_get_and_check_length() BMP TLV hdr\n",
	    config.name, bms->log_str, peer->addr_str);
	(*len) -= (orig_loc_len - rmn_loc_len);
        bmp_tlv_list_destroy(tlvs);
        return;
      }

      bmp_tlv_hdr_get_type(bth, &bmp_tlv_type);
      bmp_tlv_hdr_get_len(bth, &bmp_tlv_len);

      if (!(bmp_tlv_value = bmp_get_and_check_length(bmp_packet, &rmn_loc_len, bmp_tlv_len))) {
	Log(LOG_INFO, "INFO ( %s/%s ): [%s] [rpat] packet discarded: failed bmp_get_and_check_length() BMP TLV info\n",
	    config.name, bms->log_str, peer->addr_str);
	(*len) -= (orig_loc_len - rmn_loc_len);
	bmp_tlv_list_destroy(tlvs);
	return;
      }

      ret = bmp_tlv_list_add(tlvs, 0, bmp_tlv_type, bmp_tlv_len, bmp_tlv_value);
      if (ret == ERR) {
	Log(LOG_ERR, "ERROR ( %s/%s ): [%s] [rpat] bmp_tlv_list_add() failed.\n", config.name, bms->log_str, peer->addr_str);
	exit_gracefully(1);
      }
    }

    // XXX: log
    bmp_tlv_list_destroy(tlvs);

    (*len) -= orig_loc_len;
    telen -= elen;
  }
}

void bmp_rpat_common_hdr_get_v_flag(struct bmp_rpat_common_hdr *brch, u_int8_t *family)
{
  u_int8_t version;

  if (brch && family) {
    version = (brch->flags & BMP_PEER_FLAGS_ARI_V);
    (*family) = FALSE;

    if (version == 0) (*family) = AF_INET;
    else (*family) = AF_INET6;
  }
}

void bmp_rpat_common_hdr_get_bgp_id(struct bmp_rpat_common_hdr *brch, struct host_addr *a)
{
  if (brch && a) {
    a->family = AF_INET;
    a->address.ipv4.s_addr = brch->bgp_id;
  }
}

void bmp_rpat_common_hdr_get_rd(struct bmp_rpat_common_hdr *brch, rd_t *rd)
{
  if (brch && rd) {
    memcpy(rd, brch->rd, RD_LEN);
  }
}

void bmp_rpat_common_hdr_get_prefix(struct bmp_rpat_common_hdr *brch, struct host_addr *a, u_int8_t *family)
{
  if (brch && a) {
    if ((*family) == AF_INET) a->address.ipv4.s_addr = brch->prefix[3];
    else if ((*family) == AF_INET6) memcpy(&a->address.ipv6, &brch->prefix, 16);
    else {
      memset(a, 0, sizeof(struct host_addr));
      if (!brch->prefix[0] && !brch->prefix[1] && !brch->prefix[2] && !brch->prefix[3]) {
        (*family) = AF_INET; /* we just set this up to something non-zero */
      }
    }

    a->family = (*family);
  }
}

void bmp_rpat_common_hdr_get_prefix_len(struct bmp_rpat_common_hdr *brch, u_int8_t *plen)
{
  if (brch && plen) (*plen) = brch->prefix_len;
}

void bmp_rpat_event_hdr_get_index(struct bmp_rpat_event_hdr *breh, u_int8_t *idx)
{
  if (breh && idx) (*idx) = breh->idx;
}

void bmp_rpat_event_hdr_get_tstamp(struct bmp_rpat_event_hdr *breh, struct timeval *tv)
{
  u_int32_t sec, usec;

  if (breh && tv) {
    if (breh->tstamp_sec) {
      sec = ntohl(breh->tstamp_sec);
      usec = ntohl(breh->tstamp_usec);

      tv->tv_sec = sec;
      tv->tv_usec = usec;
    }
  }
}

void bmp_rpat_event_hdr_get_path_id(struct bmp_rpat_event_hdr *breh, u_int32_t *path_id)
{
  if (breh && path_id) (*path_id) = ntohl(breh->path_id);
}

void bmp_rpat_event_hdr_get_afi_safi(struct bmp_rpat_event_hdr *breh, afi_t *afi, safi_t *safi)
{
  if (breh) {
    if (afi && safi) {
      (*afi) = ntohs(breh->afi);
      (*safi) = breh->safi;
    }
  }
}
