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
#include "bgp.h"
#include "bgp_ls.h"
#include "bgp_ls-data.h"

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
  }

  bgp_ls_nd_tlv_map = cdada_map_create(u_int16_t); /* sizeof type */
  if (!bgp_ls_nd_tlv_map) {
    Log(LOG_ERR, "ERROR ( %s/core/BGP ): Unable to allocate bgp_ls_nd_tlv_map. Exiting.\n", config.name);
    exit_gracefully(1);
  }

  for (idx = 0; bgp_ls_nd_tlv_list[idx].hdlr; idx++) {
    ret = cdada_map_insert(bgp_ls_nd_tlv_map, &bgp_ls_nd_tlv_list[idx].type, (void *) &bgp_ls_nd_tlv_list[idx].hdlr);
  }
}

int bgp_ls_nlri_parse(struct bgp_msg_data *bmd, void *attr, struct bgp_attr_extra *attr_extra, struct bgp_nlri *info, int type)
{
  struct bgp_misc_structs *bms;
  struct bgp_peer *peer = bmd->peer;
  struct bgp_ls_nlri blsn;

  char bgp_peer_str[INET6_ADDRSTRLEN];
  u_char *pnt;
  int rem_len, rem_nlri_len, ret, idx;
  u_int16_t tmp16, nlri_type, nlri_len, tlv_type, tlv_len;

  if (!peer) goto exit_fail_lane;

  bms = bgp_select_misc_db(peer->type);

  if (!bms) goto exit_fail_lane;

  pnt = info->nlri;
  rem_len = info->length;
  memset(&blsn, 0, sizeof(blsn));

  /* parse NLRIs, make sure can read Type and Length */
  for (idx = 0; rem_len > 4; rem_len -= nlri_len, idx++) {
    memcpy(&tmp16, pnt, 2);
    nlri_type = blsn.type = ntohs(tmp16);
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
        Log(LOG_DEBUG, "DEBUG ( %s/%s/BGP ): BGP-LS Unknown TLV %u\n", config.name, config.type, tlv_type);
      }
    }
  }

  return SUCCESS;

exit_fail_lane:
  bmd->nlri_count = ERR;
  return ERR;
}

int bgp_ls_nlri_tlv_local_nd_handler(char *pnt, int len, struct bgp_ls_nlri *blsn)
{
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
    }
    else {
      Log(LOG_DEBUG, "DEBUG ( %s/%s/BGP ): BGP-LS Unknown ND Sub-TLV %u\n", config.name, config.type, tlv_type);
      ret = SUCCESS;
    }
  }

  return ret;
}

int bgp_ls_nlri_tlv_remote_nd_handler(char *pnt, int len, struct bgp_ls_nlri *blsn)
{
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
    }
    else {
      Log(LOG_DEBUG, "DEBUG ( %s/%s/BGP ): BGP-LS Unknown Remote ND Sub-TLV %u\n", config.name, config.type, tlv_type);
      ret = SUCCESS;
    }
  }

  return ret;
}

int bgp_ls_nlri_tlv_v4_addr_if_handler(char *pnt, int len, struct bgp_ls_nlri *blsn)
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
    Log(LOG_DEBUG, "DEBUG ( %s/%s/BGP ): BGP-LS Wrong Length TLV %u\n", config.name, config.type, BGP_LS_V4_ADDR_IF);
    ret = ERR;
  }

  return ret;
}

int bgp_ls_nlri_tlv_v4_addr_neigh_handler(char *pnt, int len, struct bgp_ls_nlri *blsn)
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
    Log(LOG_DEBUG, "DEBUG ( %s/%s/BGP ): BGP-LS Wrong Length TLV %u\n", config.name, config.type, BGP_LS_V4_ADDR_NEIGHBOR);
    ret = ERR;
  }

  return ret;
}

int bgp_ls_nlri_tlv_v6_addr_if_handler(char *pnt, int len, struct bgp_ls_nlri *blsn)
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
    Log(LOG_DEBUG, "DEBUG ( %s/%s/BGP ): BGP-LS Wrong Length TLV %u\n", config.name, config.type, BGP_LS_V6_ADDR_IF);
    ret = ERR;
  }

  return ret;
}

int bgp_ls_nlri_tlv_v6_addr_neigh_handler(char *pnt, int len, struct bgp_ls_nlri *blsn)
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
    Log(LOG_DEBUG, "DEBUG ( %s/%s/BGP ): BGP-LS Wrong Length TLV %u\n", config.name, config.type, BGP_LS_V6_ADDR_NEIGHBOR);
    ret = ERR;
  }

  return ret;
}

int bgp_ls_nlri_tlv_ip_reach_handler(char *pnt, int len, struct bgp_ls_nlri *blsn)
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
    Log(LOG_DEBUG, "DEBUG ( %s/%s/BGP ): BGP-LS Wrong Length TLV %u\n", config.name, config.type, BGP_LS_IP_REACH);
    ret = ERR;
  }

  if (!ret) {
    /* IPv4 */
    if (blsn->type == 3 && pfx_size <= 4) {
      blsn->nlri.topo_pfx.p.pdesc.addr.family = AF_INET;
      memcpy(&blsn->nlri.topo_pfx.p.pdesc.addr.address.ipv4, pnt, pfx_size);

      blsn->nlri.topo_pfx.p.pdesc.mask.family = AF_INET;
      blsn->nlri.topo_pfx.p.pdesc.mask.len = pfx_size;
    }
    /* IPv6 */
    else if (blsn->type == 4 && pfx_size <= 16) {
      blsn->nlri.topo_pfx.p.pdesc.addr.family = AF_INET6;
      memcpy(&blsn->nlri.topo_pfx.p.pdesc.addr.address.ipv6, pnt, pfx_size);

      blsn->nlri.topo_pfx.p.pdesc.mask.family = AF_INET6;
      blsn->nlri.topo_pfx.p.pdesc.mask.len = pfx_size;
    }
    else {
      Log(LOG_DEBUG, "DEBUG ( %s/%s/BGP ): BGP-LS Wrong Length (pfx_size) TLV %u\n", config.name, config.type, BGP_LS_IP_REACH);
      ret = ERR;
    }
  }

  return ret;
}

int bgp_ls_nd_tlv_as_handler(char *pnt, int len, struct bgp_ls_node_desc *blnd)
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
    Log(LOG_DEBUG, "DEBUG ( %s/%s/BGP ): BGP-LS Wrong Length TLV %u\n", config.name, config.type, BGP_LS_ND_AS);
    ret = ERR;
  }

  return ret;
}

int bgp_ls_nd_tlv_router_id_handler(char *pnt, int len, struct bgp_ls_node_desc *blnd)
{
  int ret = SUCCESS;

  if (!pnt || !len || !blnd) {
    return ERR;
  }

  if (len == 6) {
    memcpy(blnd->igp_id.isis.rtr_id, pnt, 6);
  }
  else {
    Log(LOG_DEBUG, "DEBUG ( %s/%s/BGP ): BGP-LS Wrong Length TLV %u\n", config.name, config.type, BGP_LS_ND_IGP_ROUTER_ID);
    ret = ERR;
  }

  return ret;
}
