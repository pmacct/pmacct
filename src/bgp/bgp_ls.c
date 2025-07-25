/*  
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2025 by Paolo Lucente
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
#include "bgp.h"
#include "bgp_ls.h"
#include "bgp_ls-data.h"

#if defined WITH_RABBITMQ
#include "amqp_common.h"
#endif
#ifdef WITH_KAFKA
#include "kafka_common.h"
#endif
#ifdef WITH_AVRO
#include "plugin_cmn_avro.h"
#endif

void bgp_ls_init()
{
  int ret, idx;

  bgp_ls_nlri_tlv_map = cdada_map_create(u_int16_t); /* sizeof type */
  if (!bgp_ls_nlri_tlv_map) {
    Log(LOG_ERR, "ERROR ( %s/core/BGP ): Unable to allocate bgp_ls_nlri_tlv_map. Exiting.\n", config.name);
    exit_gracefully(1);
  }

  for (idx = 0; bgp_ls_nlri_tlv_list[idx].hdlr; idx++) {
    ret = cdada_map_insert(bgp_ls_nlri_tlv_map, &bgp_ls_nlri_tlv_list[idx].type, (void *) &bgp_ls_nlri_tlv_list[idx].hdlr);
    if (ret != CDADA_SUCCESS) {
      Log(LOG_ERR, "ERROR ( %s/core/BGP ): Unable to insert in bgp_ls_nlri_tlv_map. Exiting.\n", config.name);
      exit_gracefully(1);
    }
  }

  bgp_ls_nd_tlv_map = cdada_map_create(u_int16_t); /* sizeof type */
  if (!bgp_ls_nd_tlv_map) {
    Log(LOG_ERR, "ERROR ( %s/core/BGP ): Unable to allocate bgp_ls_nd_tlv_map. Exiting.\n", config.name);
    exit_gracefully(1);
  }

  for (idx = 0; bgp_ls_nd_tlv_list[idx].hdlr; idx++) {
    ret = cdada_map_insert(bgp_ls_nd_tlv_map, &bgp_ls_nd_tlv_list[idx].type, (void *) &bgp_ls_nd_tlv_list[idx].hdlr);
    if (ret != CDADA_SUCCESS) {
      Log(LOG_ERR, "ERROR ( %s/core/BGP ): Unable to insert in bgp_ls_nd_tlv_map. Exiting.\n", config.name);
      exit_gracefully(1);
    } 
  }

  bgp_ls_attr_tlv_print_map = cdada_map_create(u_int16_t); /* sizeof type */
  if (!bgp_ls_attr_tlv_print_map) {
    Log(LOG_ERR, "ERROR ( %s/core/BGP ): Unable to allocate bgp_ls_attr_tlv_print_map. Exiting.\n", config.name);
    exit_gracefully(1);
  }

  for (idx = 0; bgp_ls_attr_tlv_print_list[idx].hdlr; idx++) {
    ret = cdada_map_insert(bgp_ls_attr_tlv_print_map, &bgp_ls_attr_tlv_print_list[idx].type, (void *) &bgp_ls_attr_tlv_print_list[idx]);
    if (ret != CDADA_SUCCESS) {
      Log(LOG_ERR, "ERROR ( %s/core/BGP ): Unable to insert in bgp_ls_attr_tlv_print_map. Exiting.\n", config.name);
      exit_gracefully(1);
    }
  }

  bgp_ls_nlri_map = cdada_map_create(struct bgp_ls_nlri);
  if (!bgp_ls_nlri_map) {
    Log(LOG_ERR, "ERROR ( %s/core/BGP ): Unable to allocate bgp_ls_nlri_map. Exiting.\n", config.name);
    exit_gracefully(1);
  }
}

int bgp_ls_nlri_parse(struct bgp_msg_data *bmd, struct bgp_attr *attr, struct bgp_attr_extra *attr_extra, struct bgp_nlri *info, int type)
{
  struct bgp_misc_structs *bms;
  struct bgp_peer *peer = bmd->peer;
  struct bgp_ls_nlri blsn;

  char bgp_peer_str[INET6_ADDRSTRLEN];
  u_char *pnt;
  int rem_len, rem_nlri_len, ret, idx, log_type = 0;
  u_int16_t tmp16, nlri_len, tlv_type, tlv_len;

  if (!peer) goto exit_fail_lane;

  bms = bgp_select_misc_db(peer->type);

  if (!bms) goto exit_fail_lane;

  pnt = info->nlri;
  rem_len = info->length;
  memset(&blsn, 0, sizeof(blsn));
  blsn.safi = info->safi;
  blsn.peer = peer;

  /* parse NLRIs, make sure can read Type and Length */
  for (idx = 0; rem_len > 4; rem_len -= nlri_len, idx++) {
    memcpy(&tmp16, pnt, 2);
    blsn.type = ntohs(tmp16);
    pnt += 2; rem_len -= 2;

    memcpy(&tmp16, pnt, 2);
    nlri_len = rem_nlri_len = ntohs(tmp16);
    pnt += 2; rem_len -= 2;

    if (nlri_len >= 9) {
      blsn.proto = (*pnt); pnt++; rem_nlri_len--;

      /* skip identifier */
      pnt += 8; rem_nlri_len -= 8;
    }

    for (; rem_nlri_len >= 4; rem_nlri_len -= tlv_len, pnt += tlv_len) {
      bgp_ls_nlri_tlv_hdlr *tlv_hdlr = NULL;

      memcpy(&tmp16, pnt, 2);
      tlv_type = ntohs(tmp16);
      pnt += 2; rem_nlri_len -= 2;

      memcpy(&tmp16, pnt, 2);
      tlv_len = ntohs(tmp16);
      pnt += 2; rem_nlri_len -= 2;

      ret = cdada_map_find(bgp_ls_nlri_tlv_map, &tlv_type, (void **) &tlv_hdlr);
      if (ret == CDADA_SUCCESS && tlv_hdlr) {
	ret = (*tlv_hdlr)(pnt, tlv_len, &blsn);
      }
      else {
	bgp_peer_print(peer, bgp_peer_str, INET6_ADDRSTRLEN);
        Log(LOG_DEBUG, "DEBUG ( %s/%s/BGP ): [%s] BGP-LS Unknown TLV %u\n", config.name, config.type, bgp_peer_str, tlv_type);
      }
    }
  }

  if (type == BGP_NLRI_UPDATE) {
    void *attr_aux = NULL;
    struct bgp_attr_ls *attr_hdr = NULL, *attr_hdr_prev = NULL;

    if (!bms->skip_rib) {
      if (attr_extra && attr_extra->ls.ptr) {
        attr_hdr = malloc(sizeof(struct bgp_attr_ls));
        attr_aux = malloc(attr_extra->ls.len);
        if (attr_hdr && attr_aux) {
	  memcpy(attr_aux, attr_extra->ls.ptr, attr_extra->ls.len);
	  attr_hdr->ptr = attr_aux;
	  attr_hdr->len = attr_extra->ls.len;

	  ret = cdada_map_insert_replace(bgp_ls_nlri_map, &blsn, attr_hdr, (void **) &attr_hdr_prev);
	  if (ret != CDADA_SUCCESS) {
	    bgp_peer_print(peer, bgp_peer_str, INET6_ADDRSTRLEN);
	    Log(LOG_WARNING, "WARN ( %s/%s/BGP ): [%s] BGP-LS failed NLRI Insert/Replace\n", config.name, config.type, bgp_peer_str);
	  }
	  else {
	    if (attr_hdr_prev) {
	      free(attr_hdr_prev->ptr);
	      free(attr_hdr_prev);
	    }
	  }
	}
      }
    }

    log_type = BGP_LOG_TYPE_UPDATE;
  }
  else if (type == BGP_NLRI_WITHDRAW) {
    struct bgp_attr_ls *blsa = NULL;

    if (!bms->skip_rib) {
      ret = cdada_map_find(bgp_ls_nlri_map, &blsn, (void **) &blsa);
      if (ret == CDADA_SUCCESS && blsa) {
        cdada_map_erase(bgp_ls_nlri_map, &blsn);
        free(blsa->ptr);
	free(blsa);
      }
      else {
	bgp_peer_print(peer, bgp_peer_str, INET6_ADDRSTRLEN);
        Log(LOG_WARNING, "WARN ( %s/%s/BGP ): [%s] BGP-LS failed NLRI Withdraw\n", config.name, config.type, bgp_peer_str);
      }
    }

    log_type = BGP_LOG_TYPE_WITHDRAW;
  }

  if (bms->msglog_backend_methods) {
    char event_type[] = "log";

    bgp_ls_log_msg(&blsn, &attr_extra->ls, AFI_BGP_LS, blsn.safi, bms->tag, event_type, bms->msglog_output, NULL, log_type);
  }

  return SUCCESS;

exit_fail_lane:
  bmd->nlri_count = ERR;
  return ERR;
}

void bgp_ls_peer_info_print(const cdada_map_t *m, const void *k, void *v, void *o)
{
  struct bgp_ls_nlri_map_trav_print *blsnmtp = o;
  struct bgp_ls_nlri *blsn = (void *) k;
  struct bgp_attr_ls *blsa = (void *) v;
  struct bgp_misc_structs *bms = bgp_select_misc_db(blsnmtp->peer->type);

  if (!host_addr_cmp(&blsnmtp->peer->addr, &blsn->peer->addr)) {
    char event_type[] = "dump";

    bgp_ls_log_msg(blsn, blsa, AFI_BGP_LS, blsn->safi, bms->tag, event_type, config.bgp_table_dump_output, NULL, BGP_LOG_TYPE_MISC);
    (*blsnmtp->num_entries)++;
  }
}

void bgp_ls_peer_info_delete(const cdada_map_t *m, const void *k, void *v, void *o)
{
  struct bgp_ls_nlri_map_trav_del *blsnmtd = o;
  struct bgp_ls_nlri *blsn = (void *) k;

  if (!host_addr_cmp(&blsnmtd->peer->addr, &blsn->peer->addr)) {
    cdada_list_push_back(blsnmtd->list_del, &blsn);
  }
}

void bgp_ls_info_print(struct bgp_peer *peer, u_int64_t *num_entries)
{
  if (peer) {
    if (!cdada_map_empty(bgp_ls_nlri_map)) {
      struct bgp_ls_nlri_map_trav_print blsnmtp;

      blsnmtp.peer = peer;
      blsnmtp.num_entries = num_entries;
      cdada_map_traverse(bgp_ls_nlri_map, bgp_ls_peer_info_print, &blsnmtp);
    }
  }
}

void bgp_ls_info_delete(struct bgp_peer *peer)
{
  int ret;

  if (peer) {
    struct bgp_misc_structs *bms = bgp_select_misc_db(peer->type);

    if (!cdada_map_empty(bgp_ls_nlri_map)) {
      struct bgp_ls_nlri_map_trav_del blsnmtd;
      struct bgp_ls_nlri *blsn = NULL;
      
      blsnmtd.peer = peer;
      blsnmtd.list_del = cdada_list_create(struct bgp_ls_nlri *);

      cdada_map_traverse(bgp_ls_nlri_map, bgp_ls_peer_info_delete, &blsnmtd);

      while (cdada_list_first(blsnmtd.list_del, &blsn) == CDADA_SUCCESS) {
	struct bgp_attr_ls *blsa = NULL;

	ret = cdada_map_find(bgp_ls_nlri_map, blsn, (void **) &blsa);
	if (ret == CDADA_SUCCESS && blsa) {
	  if (bms->msglog_backend_methods) {
	    char event_type[] = "log";

	    bgp_ls_log_msg(blsn, blsa, AFI_BGP_LS, blsn->safi, bms->tag, event_type, bms->msglog_output, NULL, BGP_LOG_TYPE_DELETE);
          }

	  cdada_map_erase(bgp_ls_nlri_map, blsn); 
	  free(blsa->ptr);
	  free(blsa);

	  cdada_list_pop_front(blsnmtd.list_del);
        }
	else {
	  char bgp_peer_str[INET6_ADDRSTRLEN];

	  bgp_peer_print(peer, bgp_peer_str, INET6_ADDRSTRLEN);
	  Log(LOG_WARNING, "WARN ( %s/%s/BGP ): [%s] BGP-LS failed NLRI delete\n", config.name, config.type, bgp_peer_str);
	}
      }

      cdada_list_destroy(blsnmtd.list_del);
    }
  }
}

int bgp_ls_nlri_tlv_local_nd_handler(u_char *pnt, int len, struct bgp_ls_nlri *blsn)
{
  char bgp_peer_str[INET6_ADDRSTRLEN];
  u_int16_t tlv_type, tlv_len, tmp16;
  struct bgp_ls_node_desc *blnd = NULL;
  int ret = SUCCESS;

  if (!pnt || !len || !blsn) {
    return ERR;
  }

  switch (blsn->type) {
  case BGP_LS_NLRI_NODE:
    blnd = &blsn->nlri.node.n.ndesc;
    break;
  case BGP_LS_NLRI_LINK:
    blnd = &blsn->nlri.link.l.loc_ndesc;
    break;
  case BGP_LS_NLRI_V4_TOPO_PFX:
  case BGP_LS_NLRI_V6_TOPO_PFX:
    blnd = &blsn->nlri.topo_pfx.p.ndesc;
    break;
  default:
    return ERR;
  };

  for (; len >= 4; len -= tlv_len, pnt += tlv_len) {
    bgp_ls_nd_tlv_hdlr *tlv_hdlr = NULL;

    memcpy(&tmp16, pnt, 2);
    tlv_type = ntohs(tmp16);
    pnt += 2; len -= 2;

    memcpy(&tmp16, pnt, 2);
    tlv_len = ntohs(tmp16);
    pnt += 2; len -= 2;

    ret = cdada_map_find(bgp_ls_nd_tlv_map, &tlv_type, (void **) &tlv_hdlr);
    if (ret == CDADA_SUCCESS && tlv_hdlr) {
      ret = (*tlv_hdlr)(pnt, tlv_len, blnd);
      if (ret == ERR) {
	bgp_peer_print(blsn->peer, bgp_peer_str, INET6_ADDRSTRLEN);
	Log(LOG_WARNING, "WARN ( %s/%s/BGP ): [%s] BGP-LS Issue parsing ND Sub-TLV %u\n", config.name, config.type, bgp_peer_str, tlv_type);
      }
    }
    else {
      bgp_peer_print(blsn->peer, bgp_peer_str, INET6_ADDRSTRLEN);
      Log(LOG_DEBUG, "DEBUG ( %s/%s/BGP ): [%s] BGP-LS Unknown ND Sub-TLV %u\n", config.name, config.type, bgp_peer_str, tlv_type);
      ret = SUCCESS;
    }
  }

  return ret;
}

int bgp_ls_nlri_tlv_remote_nd_handler(u_char *pnt, int len, struct bgp_ls_nlri *blsn)
{
  char bgp_peer_str[INET6_ADDRSTRLEN];
  u_int16_t tlv_type, tlv_len, tmp16;
  struct bgp_ls_node_desc *blnd = NULL;
  int ret = SUCCESS;

  if (!pnt || !len || !blsn) {
    return ERR;
  }

  blnd = &blsn->nlri.link.l.rem_ndesc;

  for (; len >= 4; len -= tlv_len, pnt += tlv_len) {
    bgp_ls_nd_tlv_hdlr *tlv_hdlr = NULL;

    memcpy(&tmp16, pnt, 2);
    tlv_type = ntohs(tmp16);
    pnt += 2; len -= 2;

    memcpy(&tmp16, pnt, 2);
    tlv_len = ntohs(tmp16);
    pnt += 2; len -= 2;

    ret = cdada_map_find(bgp_ls_nd_tlv_map, &tlv_type, (void **) &tlv_hdlr);
    if (ret == CDADA_SUCCESS && tlv_hdlr) {
      ret = (*tlv_hdlr)(pnt, tlv_len, blnd);
      if (ret == ERR) {
        bgp_peer_print(blsn->peer, bgp_peer_str, INET6_ADDRSTRLEN);
        Log(LOG_WARNING, "WARN ( %s/%s/BGP ): [%s] BGP-LS Issue parsing Remote ND Sub-TLV %u\n", config.name, config.type, bgp_peer_str, tlv_type);
      }
    }
    else {
      bgp_peer_print(blsn->peer, bgp_peer_str, INET6_ADDRSTRLEN);
      Log(LOG_DEBUG, "DEBUG ( %s/%s/BGP ): [%s] BGP-LS Unknown Remote ND Sub-TLV %u\n", config.name, config.type, bgp_peer_str, tlv_type);

      ret = SUCCESS;
    }
  }

  return ret;
}

int bgp_ls_nlri_tlv_v4_addr_if_handler(u_char *pnt, int len, struct bgp_ls_nlri *blsn)
{
  int ret = SUCCESS;

  if (!pnt || !len || !blsn) {
    return ERR;
  }

  if (len == 4) {
    blsn->nlri.link.l.ldesc.local_addr.family = AF_INET;
    memcpy(&blsn->nlri.link.l.ldesc.local_addr.address.ipv4, pnt, 4);
  }
  else {
    char bgp_peer_str[INET6_ADDRSTRLEN];

    bgp_peer_print(blsn->peer, bgp_peer_str, INET6_ADDRSTRLEN);
    Log(LOG_WARNING, "WARN ( %s/%s/BGP ): [%s] BGP-LS Wrong Length TLV %u\n", config.name, config.type, bgp_peer_str, BGP_LS_V4_ADDR_IF);

    ret = ERR;
  }

  return ret;
}

int bgp_ls_nlri_tlv_v4_addr_neigh_handler(u_char *pnt, int len, struct bgp_ls_nlri *blsn)
{
  int ret = SUCCESS;

  if (!pnt || !len || !blsn) {
    return ERR;
  }

  if (len == 4) {
    blsn->nlri.link.l.ldesc.neigh_addr.family = AF_INET;
    memcpy(&blsn->nlri.link.l.ldesc.neigh_addr.address.ipv4, pnt, 4);
  }
  else {
    char bgp_peer_str[INET6_ADDRSTRLEN];

    bgp_peer_print(blsn->peer, bgp_peer_str, INET6_ADDRSTRLEN);
    Log(LOG_WARNING, "WARN ( %s/%s/BGP ): [%s] BGP-LS Wrong Length TLV %u\n", config.name, config.type, bgp_peer_str, BGP_LS_V4_ADDR_NEIGHBOR);

    ret = ERR;
  }

  return ret;
}

int bgp_ls_nlri_tlv_v6_addr_if_handler(u_char *pnt, int len, struct bgp_ls_nlri *blsn)
{
  int ret = SUCCESS;

  if (!pnt || !len || !blsn) {
    return ERR;
  }

  if (len == 16) {
    blsn->nlri.link.l.ldesc.local_addr.family = AF_INET6;
    memcpy(&blsn->nlri.link.l.ldesc.local_addr.address.ipv6, pnt, 16);
  }
  else {
    char bgp_peer_str[INET6_ADDRSTRLEN];

    bgp_peer_print(blsn->peer, bgp_peer_str, INET6_ADDRSTRLEN);
    Log(LOG_WARNING, "WARN ( %s/%s/BGP ): [%s] BGP-LS Wrong Length TLV %u\n", config.name, config.type, bgp_peer_str, BGP_LS_V6_ADDR_IF);

    ret = ERR;
  }

  return ret;
}

int bgp_ls_nlri_tlv_v6_addr_neigh_handler(u_char *pnt, int len, struct bgp_ls_nlri *blsn)
{
  int ret = SUCCESS;

  if (!pnt || !len || !blsn) {
    return ERR;
  }

  if (len == 16) {
    blsn->nlri.link.l.ldesc.neigh_addr.family = AF_INET6;
    memcpy(&blsn->nlri.link.l.ldesc.neigh_addr.address.ipv6, pnt, 16);
  }
  else {
    char bgp_peer_str[INET6_ADDRSTRLEN];

    bgp_peer_print(blsn->peer, bgp_peer_str, INET6_ADDRSTRLEN);
    Log(LOG_WARNING, "WARN ( %s/%s/BGP ): [%s] BGP-LS Wrong Length TLV %u\n", config.name, config.type, bgp_peer_str, BGP_LS_V6_ADDR_NEIGHBOR);

    ret = ERR;
  }

  return ret;
}

int bgp_ls_nlri_tlv_ip_reach_handler(u_char *pnt, int len, struct bgp_ls_nlri *blsn)
{
  int ret = SUCCESS, pfx_size;
  u_int8_t pfx_len;

  if (!pnt || !len || !blsn) {
    return ERR;
  }

  memcpy(&pfx_len, pnt, 1);
  pnt++; len--;

  pfx_size = ((pfx_len + 7) / 8);
  if (pfx_size > len) {
    char bgp_peer_str[INET6_ADDRSTRLEN];

    bgp_peer_print(blsn->peer, bgp_peer_str, INET6_ADDRSTRLEN);
    Log(LOG_WARNING, "WARN ( %s/%s/BGP ): [%s] BGP-LS Wrong Length TLV %u\n", config.name, config.type, bgp_peer_str, BGP_LS_IP_REACH);

    ret = ERR;
  }

  if (!ret) {
    /* IPv4 */
    if (blsn->type == 3 && pfx_size <= 4) {
      blsn->nlri.topo_pfx.p.pdesc.addr.family = AF_INET;
      memcpy(&blsn->nlri.topo_pfx.p.pdesc.addr.address.ipv4, pnt, pfx_size);

      blsn->nlri.topo_pfx.p.pdesc.mask.family = AF_INET;
      blsn->nlri.topo_pfx.p.pdesc.mask.len = pfx_len;
    }
    /* IPv6 */
    else if (blsn->type == 4 && pfx_size <= 16) {
      blsn->nlri.topo_pfx.p.pdesc.addr.family = AF_INET6;
      memcpy(&blsn->nlri.topo_pfx.p.pdesc.addr.address.ipv6, pnt, pfx_size);

      blsn->nlri.topo_pfx.p.pdesc.mask.family = AF_INET6;
      blsn->nlri.topo_pfx.p.pdesc.mask.len = pfx_len;
    }
    else {
      char bgp_peer_str[INET6_ADDRSTRLEN];

      bgp_peer_print(blsn->peer, bgp_peer_str, INET6_ADDRSTRLEN);
      Log(LOG_WARNING, "WARN ( %s/%s/BGP ): [%s] BGP-LS Wrong Length (pfx_size) TLV %u\n", config.name, config.type, bgp_peer_str, BGP_LS_IP_REACH);

      ret = ERR;
    }
  }

  return ret;
}

int bgp_ls_nd_tlv_as_handler(u_char *pnt, int len, struct bgp_ls_node_desc *blnd)
{
  int ret = SUCCESS;
  u_int32_t tmp32;

  if (!pnt || !len || !blnd) {
    return ERR;
  }

  if (len == 4) {
    memcpy(&tmp32, pnt, 4);
    blnd->asn = ntohl(tmp32);
  }
  else {
    ret = ERR;
  }

  return ret;
}

int bgp_ls_nd_tlv_id_handler(u_char *pnt, int len, struct bgp_ls_node_desc *blnd)
{
  int ret = SUCCESS;
  u_int32_t tmp32;

  if (!pnt || !len || !blnd) {
    return ERR;
  }

  if (len == 4) {
    memcpy(&tmp32, pnt, 4);
    blnd->bgp_ls_id = ntohl(tmp32);
  }
  else {
    ret = ERR;
  }

  return ret;
}

int bgp_ls_nd_tlv_router_id_handler(u_char *pnt, int len, struct bgp_ls_node_desc *blnd)
{
  int ret = SUCCESS;

  if (!pnt || !len || !blnd) {
    return ERR;
  }

  if (len <= 8) {
    memcpy(blnd->igp_rtr_id.id, pnt, len);
    blnd->igp_rtr_id.len = len;
  }
  else {
    ret = ERR;
  }

  return ret;
}

int bgp_ls_nd_tlv_confed_member_handler(u_char *pnt, int len, struct bgp_ls_node_desc *blnd)
{
  int ret = SUCCESS;
  u_int32_t tmp32;

  if (!pnt || !len || !blnd) {
    return ERR;
  }

  if (len == 4) {
    memcpy(&tmp32, pnt, 4);
    blnd->confed_asn = ntohl(tmp32);
  }
  else {
    ret = ERR;
  }

  return ret;
}

int bgp_ls_attr_tlv_unknown_handler(u_char *pnt, u_int16_t len, u_int16_t type, int output, void *void_obj)
{
  if (!pnt || !len || !type || !void_obj) {
    return ERR;
  }
 
  if (output == PRINT_OUTPUT_JSON) {
#ifdef WITH_JANSSON
    json_t *obj = void_obj;
    char key[32], *value = NULL;

    value = malloc(len * 3);    
    if (value) {
      memset(key, 0, sizeof(key));
      memset(value, 0, len * 3);

      snprintf(key, sizeof(key), "attr_%d", type);
      serialize_hex((u_char *)pnt, (u_char *)value, len);
      json_object_set_new_nocheck(obj, key, json_string(value));

      free(value);
    } 
#endif
  }

  return SUCCESS;
}

int bgp_ls_log_msg(struct bgp_ls_nlri *blsn, struct bgp_attr_ls *blsa,
		afi_t afi, safi_t safi, bgp_tag_t *tag, char *event_type,
		int output, char **output_data, int log_type)
{
  struct bgp_misc_structs *bms;
  struct bgp_peer *peer;
  int ret = 0, amqp_ret = 0, kafka_ret = 0, etype = BGP_LOGDUMP_ET_NONE;

  if (!blsn->peer || !event_type) return ERR; /* missing required parameters */
  if (!blsn->peer->log && !output_data) return ERR; /* missing any output method */

  peer = blsn->peer;

  bms = bgp_select_misc_db(peer->type);
  if (!bms) return ERR;

  if (!strcmp(event_type, "dump")) etype = BGP_LOGDUMP_ET_DUMP;
  else if (!strcmp(event_type, "log")) etype = BGP_LOGDUMP_ET_LOG;

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

  // XXX: tag handling

  if (output == PRINT_OUTPUT_JSON) {
#ifdef WITH_JANSSON
    char ip_address[INET6_ADDRSTRLEN], ip_addr_mask[INET6_ADDRSTRLEN + 1 + 3], log_type_str[SUPERSHORTBUFLEN];
    char bgp_peer_str[INET6_ADDRSTRLEN];
    json_t *obj = json_object();

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

    if (etype == BGP_LOGDUMP_ET_LOG) {
      json_object_set_new_nocheck(obj, "timestamp", json_string(bms->log_tstamp_str));
    }
    else if (etype == BGP_LOGDUMP_ET_DUMP) {
      json_object_set_new_nocheck(obj, "timestamp", json_string(bms->dump.tstamp_str));
    }

    json_object_set_new_nocheck(obj, "event_type", json_string(event_type));
    json_object_set_new_nocheck(obj, "afi", json_integer((json_int_t)afi));
    json_object_set_new_nocheck(obj, "safi", json_integer((json_int_t)safi));

    addr_to_str(ip_address, &peer->addr);
    json_object_set_new_nocheck(obj, bms->peer_str, json_string(ip_address));

    if (blsn->type <= BGP_LS_NLRI_MAX) {
      json_object_set_new_nocheck(obj, "nlri_type", json_string(bgp_ls_nlri_type[blsn->type]));
    } 
    else {
      json_object_set_new_nocheck(obj, "nlri_type", json_integer(blsn->type));
    }

    if (blsn->proto <= BGP_LS_PROTO_MAX) {
      json_object_set_new_nocheck(obj, "proto", json_string(bgp_ls_protocol_id[blsn->proto]));
    }
    else {
      json_object_set_new_nocheck(obj, "proto", json_integer(blsn->proto));
    }

    if (safi == SAFI_LS_VPN) {
      char rd_str[SHORTSHORTBUFLEN];

      bgp_rd2str(rd_str, &blsn->rd);
      json_object_set_new_nocheck(obj, "rd", json_string(rd_str));
    }

    switch (blsn->type) {
    case BGP_LS_NLRI_NODE:
      bgp_ls_log_node_desc(obj, &blsn->nlri.node.n.ndesc, blsn->proto, "local", output);
      break;
    case BGP_LS_NLRI_LINK:
      bgp_ls_log_node_desc(obj, &blsn->nlri.link.l.loc_ndesc, blsn->proto, "local", output);
      bgp_ls_log_node_desc(obj, &blsn->nlri.link.l.rem_ndesc, blsn->proto, "remote", output);

      addr_to_str(ip_address, &blsn->nlri.link.l.ldesc.local_addr);
      json_object_set_new_nocheck(obj, "local_addr", json_string(ip_address));

      addr_to_str(ip_address, &blsn->nlri.link.l.ldesc.neigh_addr);
      json_object_set_new_nocheck(obj, "neigh_addr", json_string(ip_address));

      break;
    case BGP_LS_NLRI_V4_TOPO_PFX:
    case BGP_LS_NLRI_V6_TOPO_PFX:
      bgp_ls_log_node_desc(obj, &blsn->nlri.topo_pfx.p.ndesc, blsn->proto, "local", output);

      addr_mask_to_str(ip_addr_mask, sizeof(ip_addr_mask), &blsn->nlri.topo_pfx.p.pdesc.addr, &blsn->nlri.topo_pfx.p.pdesc.mask); 
      json_object_set_new_nocheck(obj, "ip_reach", json_string(ip_addr_mask));

      break;
    }

    if (blsa && blsa->ptr && blsa->len) {
      u_char *pnt = blsa->ptr;
      u_int16_t rem_len = blsa->len, tlv_type, tlv_len, tmp16;

      for (; rem_len >= 4; rem_len -= tlv_len, pnt += tlv_len) {
	struct bgp_ls_attr_tlv_print_list_entry *blsatple = NULL;

	memcpy(&tmp16, pnt, 2);
	tlv_type = ntohs(tmp16);
	pnt += 2; rem_len -= 2;

	memcpy(&tmp16, pnt, 2);
	tlv_len = ntohs(tmp16);
	pnt += 2; rem_len -= 2;

	ret = cdada_map_find(bgp_ls_attr_tlv_print_map, &tlv_type, (void **) &blsatple);
	if (ret == CDADA_SUCCESS && blsatple && blsatple->hdlr) {
	  ret = (*blsatple->hdlr)(pnt, tlv_len, blsatple->keystr, blsatple->flags, output, obj);
	  if (ret == ERR) { 
	    bgp_peer_print(peer, bgp_peer_str, INET6_ADDRSTRLEN);
	    Log(LOG_WARNING, "WARN ( %s/%s/BGP ): [%s] BGP-LS Issue parsing Attribute TLV %u\n", config.name, config.type, bgp_peer_str, tlv_type);
	  }
	}
	else {
	  bgp_peer_print(peer, bgp_peer_str, INET6_ADDRSTRLEN);
	  Log(LOG_DEBUG, "DEBUG ( %s/%s/BGP ): [%s] BGP-LS Unknown Attribute TLV %u\n", config.name, config.type, bgp_peer_str, tlv_type);
	  ret = bgp_ls_attr_tlv_unknown_handler(pnt, tlv_len, tlv_type, output, obj);
	}
      }
    }

    if ((bms->msglog_file && etype == BGP_LOGDUMP_ET_LOG) ||
	(bms->dump_file && etype == BGP_LOGDUMP_ET_DUMP)) {
      write_and_free_json(peer->log->fd, obj);
    }

    if (output_data && etype == BGP_LOGDUMP_ET_LG) {
      (*output_data) = compose_json_str(obj);
    }

    if ((bms->msglog_amqp_routing_key && etype == BGP_LOGDUMP_ET_LOG) ||
	(bms->dump_amqp_routing_key && etype == BGP_LOGDUMP_ET_DUMP)) {
      add_writer_name_and_pid_json(obj, &bms->writer_id_tokens);
#ifdef WITH_RABBITMQ
      amqp_ret = write_and_free_json_amqp(peer->log->amqp_host, obj);
      p_amqp_unset_routing_key(peer->log->amqp_host);
#endif
    }

    if ((bms->msglog_kafka_topic && etype == BGP_LOGDUMP_ET_LOG) ||
	(bms->dump_kafka_topic && etype == BGP_LOGDUMP_ET_DUMP)) {
      add_writer_name_and_pid_json(obj, &bms->writer_id_tokens);
#ifdef WITH_KAFKA
      kafka_ret = write_and_free_json_kafka(peer->log->kafka_host, obj);
      p_kafka_unset_topic(peer->log->kafka_host);
#endif
    }
#endif
  }
  // XXX: Apache Avro handling

  return (ret | amqp_ret | kafka_ret);
}

void bgp_ls_log_node_desc(void *void_obj, struct bgp_ls_node_desc *blsnd, u_int8_t proto, char *in_prefix, int output)
{
  if (output == PRINT_OUTPUT_JSON) {
#ifdef WITH_JANSSON
    json_t *obj = void_obj;
    char key_str[32];
    char empty_prefix[] = "", *prefix;

    if (!in_prefix) {
      prefix = empty_prefix;
    }
    else {
      prefix = in_prefix;
    }

    strcpy(key_str, prefix); strcat(key_str, "_asn");
    json_object_set_new_nocheck(obj, key_str, json_integer(blsnd->asn));

    if (blsnd->confed_asn) {
      strcpy(key_str, prefix); strcat(key_str, "_confed_asn");
      json_object_set_new_nocheck(obj, key_str, json_integer(blsnd->confed_asn));
    }

    strcpy(key_str, prefix); strcat(key_str, "_bgp_ls_id");
    json_object_set_new_nocheck(obj, key_str, json_integer(blsnd->bgp_ls_id));

    if (proto == BGP_LS_PROTO_ISIS_L1 || proto == BGP_LS_PROTO_ISIS_L2) {
      char sys_id[BGP_LS_ISIS_SYS_ID_LEN * 3 + 4 /* pseudonode */];

      memset(sys_id, 0, sizeof(sys_id));
      bgp_ls_isis_sysid_print(sys_id, blsnd->igp_rtr_id.id);
      if (blsnd->igp_rtr_id.len == 7) {
	sprintf(&sys_id[strlen(sys_id)], "-%02x", blsnd->igp_rtr_id.id[6]);
        json_object_set_new_nocheck(obj, "pseudonode", json_string("true"));
      }
 
      strcpy(key_str, prefix); strcat(key_str, "_igp_rtr_id");
      json_object_set_new_nocheck(obj, key_str, json_string(sys_id));
    }
#endif
  }
}

void bgp_ls_isis_sysid_print(char *to, char *from)
{
  int i = 0;

  if (!from || !to) return;

  while (i < BGP_LS_ISIS_SYS_ID_LEN - 1) {
    if (i & 1) {
      sprintf (to, "%02x.", *(from + i));
      to += 3;
    }
    else {
      sprintf (to, "%02x", *(from + i));
      to += 2;
    }

    i++;
  }

  sprintf (to, "%02x", *(from + (BGP_LS_ISIS_SYS_ID_LEN - 1)));
  to += 2;
  *(to) = '\0';
}

void bgp_ls_isis_areaid_print(char *to, char *from, int len)
{
  int i;

  for (i = 0, to[0] = '\0'; i < len; ++i) {
    char tmp[4];

    snprintf(tmp, sizeof(tmp), "%02x", from[i]);
    strcat(to, tmp);
  }
}

int bgp_ls_attr_tlv_string_print(u_char *pnt, u_int16_t len, char *key, u_int8_t flags, int output, void *void_obj)
{
  if (!pnt || !key || !output || !void_obj) {
    return ERR;
  };

  if (len) {
    if (output == PRINT_OUTPUT_JSON) { 
#ifdef WITH_JANSSON
      json_t *obj = void_obj;
      char *null_term_str = NULL;

      null_term_str = malloc(len + 1);
      if (null_term_str) {
	memcpy(null_term_str, pnt, len);
	null_term_str[len] = '\0';

	json_object_set_new_nocheck(obj, key, json_string(null_term_str));
	free(null_term_str);
      }
      else {
	return ERR;
      }
#endif
    }
  }

  return SUCCESS;
}

int bgp_ls_attr_tlv_ip_print(u_char *pnt, u_int16_t len, char *key, u_int8_t flags, int output, void *void_obj)
{
  if (!pnt || !key || !output || !void_obj) {
    return ERR;
  };

  if (output == PRINT_OUTPUT_JSON) {
#ifdef WITH_JANSSON
    json_t *obj = void_obj;
    char ip_str[INET6_ADDRSTRLEN];
    struct host_addr ip;

    if (len == 4) {
      ip.family = AF_INET;
      memcpy(&ip.address.ipv4, pnt, 4);
    }
    else if (len == 16) {
      ip.family = AF_INET6;
      memcpy(&ip.address.ipv6, pnt, 16);
    }
    else {
      return ERR;
    }

    addr_to_str(ip_str, &ip);
    json_object_set_new_nocheck(obj, key, json_string(ip_str));
#endif
  }

  return SUCCESS;
}

int bgp_ls_attr_tlv_int32_print(u_char *pnt, u_int16_t len, char *key, u_int8_t flags, int output, void *void_obj)
{
  if (!pnt || !key || !output || !void_obj) {
    return ERR;
  }; 

  if (len % 4) {
    return ERR;
  }

  if (output == PRINT_OUTPUT_JSON) {
#ifdef WITH_JANSSON
    json_t *obj = void_obj;
    json_t *l1 = NULL, *tmp64_json = NULL;
    u_int32_t tmp32 = 0;
    u_int64_t tmp64 = 0;

    if (flags & BGP_LS_PRINT_ARRAY) {
      l1 = json_object_get(obj, key);
      if (!l1) {
        l1 = json_array();
        json_object_set_new_nocheck(obj, key, l1);
      }
    }

    for (; len; pnt += 4, len -=4) {
      memcpy(&tmp32, pnt, 4);
      tmp32 = ntohl(tmp32);

      if (flags & BGP_LS_PRINT_IEEE_TO_BITS) {
	tmp64 = convertIEEEFloatToUnsignedInt(tmp32);
	tmp64 *= 8;
      }
      else {
	tmp64 = tmp32;
      }

      if (!(flags & BGP_LS_PRINT_HEX)) {
	tmp64_json = json_integer(tmp64);
      }
      else {
	char hex[16];

	snprintf(hex, sizeof(hex), "%lx", tmp64);
	tmp64_json = json_string(hex);
      }

      if (flags & BGP_LS_PRINT_ARRAY) {
	json_array_append(l1, tmp64_json);
      }
      else {
	json_object_set_new_nocheck(obj, key, tmp64_json);
      }
    }
#endif
  }

  return SUCCESS;
}

int bgp_ls_attr_tlv_int8_print(u_char *pnt, u_int16_t len, char *key, u_int8_t flags, int output, void *void_obj)
{
  if (!pnt || !key || !output || !void_obj) {
    return ERR;
  }; 

  if (output == PRINT_OUTPUT_JSON) {
#ifdef WITH_JANSSON
    json_t *obj = void_obj;
    json_t *l1 = NULL, *tmp8_json = NULL;
    u_int8_t tmp8 = 0;

    if (flags & BGP_LS_PRINT_ARRAY) {
      l1 = json_object_get(obj, key);
      if (!l1) {
        l1 = json_array();
        json_object_set_new_nocheck(obj, key, l1);
      }
    }

    for (; len; pnt++, len--) {
      memcpy(&tmp8, pnt, 1);

      if (!(flags & BGP_LS_PRINT_HEX)) {
	tmp8_json = json_integer(tmp8);
      }
      else {
	char hex[10];

	sprintf(hex, "%x", tmp8);
	tmp8_json = json_string(hex);
      }

      if (flags & BGP_LS_PRINT_ARRAY) {
	json_array_append(l1, tmp8_json);
      }
      else {
        json_object_set_new_nocheck(obj, key, tmp8_json);
      }
    }
#endif
  }

  return SUCCESS;
}

int bgp_ls_attr_tlv_isis_areaid_print(u_char *pnt, u_int16_t len, char *key, u_int8_t flags, int output, void *void_obj)
{
  if (!pnt || !key || !output || !void_obj) {
    return ERR;
  };  
        
  if (output == PRINT_OUTPUT_JSON) {
#ifdef WITH_JANSSON
    json_t *obj = void_obj;
    json_t *l1 = NULL;
    char area_id[3 * len];

    l1 = json_object_get(obj, key);
    if (!l1) {
      l1 = json_array();
      json_object_set_new_nocheck(obj, key, l1); 
    }

    bgp_ls_isis_areaid_print(area_id, (char *)pnt, len);
    json_array_append(l1, json_string(area_id));
#endif
  }

  return SUCCESS;
}

int bgp_ls_attr_tlv_igp_metric_print(u_char *pnt, u_int16_t len, char *key, u_int8_t flags, int output, void *void_obj)
{
  if (!pnt || !key || !output || !void_obj) {
    return ERR;
  };  
        
  if (output == PRINT_OUTPUT_JSON) {
#ifdef WITH_JANSSON
    json_t *obj = void_obj;
    u_int32_t tmp32 = 0;

    switch (len) {
    case 1:
      tmp32 = (u_int8_t) pnt[0] & 0x3F;
      break;
    case 2:
      tmp32 = (u_int8_t) (pnt[0] << 8) | (u_int8_t) pnt[1];
      break;
    case 3:
      tmp32 = ((u_int8_t) pnt[0] << 16) | ((u_int8_t) pnt[1] << 8) | (u_int8_t) pnt[2];
      break;
    default:
      return ERR;
    }

    json_object_set_new_nocheck(obj, key, json_integer(tmp32));
#endif
  }

  return SUCCESS;
}
