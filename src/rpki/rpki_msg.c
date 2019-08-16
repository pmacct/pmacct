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
#include "pmacct.h"
#include "pmacct-data.h"
#include "bgp/bgp.h"
#include "rpki.h"

/* functions */
int rpki_roas_file_load(char *file, struct bgp_table *rib_v4, struct bgp_table *rib_v6)
{
  struct bgp_misc_structs *m_data = rpki_misc_db;

  Log(LOG_INFO, "INFO ( %s/%s ): [%s] (re)loading map.\n", config.name, m_data->log_str, file);

#if defined WITH_JANSSON
  json_t *roas_obj, *roa_json, *roas_json;
  json_error_t file_err;
  int roas_idx;

  roas_obj = json_load_file(file, 0, &file_err);

  if (roas_obj) {
    if (!json_is_object(roas_obj)) {
      Log(LOG_ERR, "ERROR ( %s/%s ): [%s] json_is_object() failed for results: %s\n", config.name, m_data->log_str, file, file_err.text);
      return ERR;
    }
    else {
      roas_json = json_object_get(roas_obj, "roas");
      if (roas_json == NULL || !json_is_array(roas_json)) {
        Log(LOG_ERR, "ERROR ( %s/%s ): [%s] no 'roas' element or not an array.\n", config.name, m_data->log_str, file);
	json_decref(roas_obj);
        return ERR;
      }
      else {
	for (roas_idx = 0; (roa_json = json_array_get(roas_json, roas_idx)); roas_idx++) {
	  json_t *prefix_json, *maxlen_json, *asn_json;
	  struct prefix p;
	  u_int8_t maxlen;
	  as_t asn;
	  int ret;

	  memset(&p, 0, sizeof(p));
	    
	  prefix_json = json_object_get(roa_json, "prefix");
	  if (prefix_json == NULL || !json_is_string(prefix_json)) {
	    Log(LOG_WARNING, "WARN ( %s/%s ): [%s] no 'prefix' element in ROA #%u.\n", config.name, m_data->log_str, file, (roas_idx + 1));
	    goto exit_lane;
	  }
	  else {
	    ret = str2prefix(json_string_value(prefix_json), &p);

	    if (!ret) {
	      Log(LOG_WARNING, "WARN ( %s/%s ): [%s] invalid 'prefix' element in ROA #%u.\n", config.name, m_data->log_str, file, (roas_idx + 1));
	      goto exit_lane;
	    }
	  }

	  asn_json = json_object_get(roa_json, "asn");
	  if (asn_json == NULL || !json_is_string(asn_json)) {
	    Log(LOG_WARNING, "WARN ( %s/%s ): [%s] no 'asn' element in ROA #%u.\n", config.name, m_data->log_str, file, (roas_idx + 1));
	    goto exit_lane;
	  }
	  else {
	    ret = bgp_str2asn((char *)json_string_value(asn_json), &asn);

	    if (ret) {
	      Log(LOG_WARNING, "WARN ( %s/%s ): [%s] invalid 'asn' element in ROA #%u.\n", config.name, m_data->log_str, file, (roas_idx + 1));
	      goto exit_lane;
	    }
	  }

	  maxlen_json = json_object_get(roa_json, "maxLength");
	  if (maxlen_json == NULL || !json_is_integer(maxlen_json)) {
	    Log(LOG_WARNING, "WARN ( %s/%s ): [%s] no 'maxLength' element in ROA #%u.\n", config.name, m_data->log_str, file, (roas_idx + 1));
	    goto exit_lane;
	  }
	  else maxlen = json_integer_value(maxlen_json);

	  if (maxlen < p.prefixlen) {
	    char prefix_str[PREFIX_STRLEN];

	    prefix2str(&p, prefix_str, PREFIX_STRLEN);
	    Log(LOG_WARNING, "WARN ( %s/%s ): [%s] 'maxLength' < prefixLength: prefix=%s maxLength=%u asn=%u\n",
		config.name, m_data->log_str, file, prefix_str, maxlen, asn);
	  }

	  ret = rpki_info_add(&rpki_peer, &p, asn, maxlen, rib_v4, rib_v6);

	  exit_lane:
	  continue;
	}
      }

      json_decref(roas_obj);
    }

    Log(LOG_INFO, "INFO ( %s/%s ): [%s] map successfully (re)loaded.\n", config.name, m_data->log_str, file);
  }
  else {
    Log(LOG_ERR, "ERROR ( %s/%s ): [%s] json_loads() failed: %s.\n", config.name, m_data->log_str, file, file_err.text);
    return ERR;
  }
#else
  Log(LOG_WARNING, "WARN ( %s/%s ): rpki_roas_file will not load (missing --enable-jansson).\n", config.name, m_data->log_str);
#endif

  return SUCCESS;
}

int rpki_info_add(struct bgp_peer *peer, struct prefix *p, as_t asn, u_int8_t maxlen, struct bgp_table *rib_v4, struct bgp_table *rib_v6)
{
  struct bgp_misc_structs *m_data = rpki_misc_db;
  struct bgp_node *route = NULL;
  struct bgp_info *new = NULL;
  struct bgp_attr attr, *attr_new = NULL;
  struct bgp_table *rib = NULL;
  afi_t afi;
  u_int32_t modulo;

  if (!m_data || !peer || !p || !rib_v4 || !rib_v6) return ERR;

  afi = family2afi(p->family); 
  modulo = 0;

  if (afi == AFI_IP) rib = rib_v4;
  else if (afi == AFI_IP6) rib = rib_v6; 
  else return ERR;

  route = bgp_node_get(peer, rib, p);

  memset(&attr, 0, sizeof(attr));
  attr.flag = maxlen; /* abusing flag for maxlen */
  attr.aspath = aspath_parse_ast(peer, asn);
  attr_new = bgp_attr_intern(peer, &attr);
  if (attr.aspath) aspath_unintern(peer, attr.aspath);

  /* Make new BGP info. */
  new = bgp_info_new(peer);
  if (new) {
    new->peer = peer;
    new->attr = attr_new;
  }
  else return ERR;

  /* Register new BGP information. */
  bgp_info_add(peer, route, new, modulo);

  /* route_node_get lock */
  bgp_unlock_node(peer, route);

  return SUCCESS;
}

int rpki_info_delete(struct bgp_peer *peer, struct prefix *p, as_t asn, u_int8_t maxlen, struct bgp_table *rib_v4, struct bgp_table *rib_v6)
{
  struct bgp_misc_structs *m_data = rpki_misc_db;
  struct bgp_node *route = NULL;
  struct bgp_info *ri = NULL;
  struct bgp_attr attr, *attr_new = NULL;
  struct bgp_table *rib = NULL;
  afi_t afi;
  u_int32_t modulo;
  u_int8_t end;

  if (!m_data || !peer || !p || !rib_v4 || !rib_v6) return ERR;

  afi = family2afi(p->family); 
  modulo = 0;

  if (afi == AFI_IP) rib = rib_v4;
  else if (afi == AFI_IP6) rib = rib_v6; 
  else return ERR;

  for (end = MAX(p->prefixlen, maxlen); p->prefixlen <= end; p->prefixlen++) {
    route = bgp_node_get(peer, rib, p);

    memset(&attr, 0, sizeof(attr));
    attr.aspath = aspath_parse_ast(peer, asn);
    attr_new = bgp_attr_intern(peer, &attr);
    if (attr.aspath) aspath_unintern(peer, attr.aspath);

    /* Check previously received route. */
    for (ri = route->info[modulo]; ri; ri = ri->next) {
      if (ri->peer == peer && rpki_attrhash_cmp(ri->attr, attr_new)) {
	bgp_info_delete(peer, route, ri, modulo);
	break;
      }
    }

    bgp_attr_unintern(peer, attr_new);

    /* route_node_get lock */
    bgp_unlock_node(peer, route);
  }

  return SUCCESS;
}

void rpki_rtr_parse_msg(struct rpki_rtr_handle *cache)
{
  struct rpki_rtr_serial peek;
  ssize_t msglen;

  if (cache->fd > 0) {
    memset(&peek, 0, sizeof(peek));

    msglen = recv(cache->fd, &peek, 2, MSG_PEEK);
    if (msglen == 2) {
      if (peek.version != config.rpki_rtr_cache_version) {
	Log(LOG_WARNING, "WARN ( %s/core/RPKI ): rpki_rtr_parse_msg(): RPKI version mismatch (me=%u cache=%u)\n",
	    config.name, config.rpki_rtr_cache_version, peek.version);
	rpki_rtr_close(cache);
	rpki_rtr_set_dont_reconnect(cache);
	return;
      }

      switch(peek.pdu_type) {
      case RPKI_RTR_PDU_SERIAL_NOTIFY:
	rpki_rtr_recv_serial_notify(cache);
	break;
      case RPKI_RTR_PDU_CACHE_RESPONSE:
	rpki_rtr_recv_cache_response(cache);
	break;
      case RPKI_RTR_PDU_IPV4_PREFIX:
	rpki_rtr_recv_ipv4_pref(cache);
	break;
      case RPKI_RTR_PDU_IPV6_PREFIX:
	rpki_rtr_recv_ipv6_pref(cache);
	break;
      case RPKI_RTR_PDU_END_OF_DATA:
	rpki_rtr_recv_eod(cache, peek.version);
	break;
      case RPKI_RTR_PDU_CACHE_RESET:
	rpki_rtr_recv_cache_reset(cache);
	break;
      case RPKI_RTR_PDU_ROUTER_KEY:
	rpki_rtr_recv_router_key(cache);
	break;
      case RPKI_RTR_PDU_ERROR_REPORT:
	rpki_rtr_recv_error_report(cache);
	break;
      default:
	Log(LOG_WARNING, "WARN ( %s/core/RPKI ): rpki_rtr_parse_msg(): unknown PDU type (%u)\n", config.name, peek.pdu_type);
	rpki_rtr_close(cache);
	break;
      }
    }
    else {
      Log(LOG_WARNING, "WARN ( %s/core/RPKI ): rpki_rtr_parse_msg(): recv() peek failed\n", config.name);
      rpki_rtr_close(cache);
    }
  }
}

void rpki_rtr_parse_ipv4_prefix(struct rpki_rtr_handle *cache, struct rpki_rtr_ipv4_pref *p4m)
{
  struct bgp_misc_structs *m_data = rpki_misc_db;
  struct prefix_ipv4 p;
  as_t asn;

  memset(&p, 0, sizeof(p));
  p.family = AF_INET;
  p.prefix.s_addr = p4m->prefix;
  p.prefixlen = p4m->pref_len;

  asn = ntohl(p4m->asn);

  if (p4m->max_len < p.prefixlen) {
    char prefix_str[PREFIX_STRLEN];

    prefix2str((struct prefix *) &p, prefix_str, PREFIX_STRLEN);
    Log(LOG_WARNING, "WARN ( %s/%s ): 'maxLength' < prefixLength: prefix=%s maxLength=%u asn=%u\n",
	config.name, m_data->log_str, prefix_str, p4m->max_len, asn);
  }

  switch(p4m->flags) {
  case RPKI_RTR_PREFIX_FLAGS_WITHDRAW:
    rpki_info_delete(&rpki_peer, (struct prefix *) &p, asn, p4m->max_len,
			rpki_roa_db->rib[AFI_IP][SAFI_UNICAST],
			rpki_roa_db->rib[AFI_IP6][SAFI_UNICAST]);
    break;
  case RPKI_RTR_PREFIX_FLAGS_ANNOUNCE:
    rpki_info_add(&rpki_peer, (struct prefix *) &p, asn, p4m->max_len,
			rpki_roa_db->rib[AFI_IP][SAFI_UNICAST],
			rpki_roa_db->rib[AFI_IP6][SAFI_UNICAST]);
    break;
  default:
    Log(LOG_WARNING, "WARN ( %s/core/RPKI ): rpki_rtr_parse_ipv4_prefix(): unknown flag (%u)\n", config.name, p4m->flags);
    break;
  }
}

void rpki_rtr_parse_ipv6_prefix(struct rpki_rtr_handle *cache, struct rpki_rtr_ipv6_pref *p6m)
{
  struct bgp_misc_structs *m_data = rpki_misc_db;
  struct prefix_ipv6 p;
  as_t asn;

  memset(&p, 0, sizeof(p));
  p.family = AF_INET6;
  memcpy(&p.prefix.s6_addr, p6m->prefix, 16);
  p.prefixlen = p6m->pref_len;

  asn = ntohl(p6m->asn);

  if (p6m->max_len < p.prefixlen) {
    char prefix_str[PREFIX_STRLEN];

    prefix2str((struct prefix *) &p, prefix_str, PREFIX_STRLEN);
    Log(LOG_WARNING, "WARN ( %s/%s ): 'maxLength' < prefixLength: prefix=%s maxLength=%u asn=%u\n",
	config.name, m_data->log_str, prefix_str, p6m->max_len, asn);
  }

  switch(p6m->flags) {
  case RPKI_RTR_PREFIX_FLAGS_WITHDRAW:
    rpki_info_delete(&rpki_peer, (struct prefix *) &p, asn, p6m->max_len,
			rpki_roa_db->rib[AFI_IP][SAFI_UNICAST],
			rpki_roa_db->rib[AFI_IP6][SAFI_UNICAST]);
    break;
  case RPKI_RTR_PREFIX_FLAGS_ANNOUNCE:
    rpki_info_add(&rpki_peer, (struct prefix *) &p, asn, p6m->max_len,
			rpki_roa_db->rib[AFI_IP][SAFI_UNICAST],
			rpki_roa_db->rib[AFI_IP6][SAFI_UNICAST]);
    break;
  default:
    Log(LOG_WARNING, "WARN ( %s/core/RPKI ): rpki_rtr_parse_ipv6_prefix(): unknown flag (%u)\n", config.name, p6m->flags);
    break;
  }
}

void rpki_rtr_connect(struct rpki_rtr_handle *cache)
{
  int rc;

  if (cache->now >= (cache->retry.tstamp + cache->retry.ivl)) {
    cache->retry.tstamp = cache->now;
  }
  else return;

  if ((cache->fd = socket(cache->sock.ss_family, SOCK_STREAM, 0)) == -1) {
    Log(LOG_ERR, "ERROR ( %s/core/RPKI ): rpki_rtr_connect(): socket() failed: %s\n", config.name, strerror(errno));
    exit_gracefully(1);
  }

  if (config.rpki_rtr_cache_ipprec) {
    int opt = config.rpki_rtr_cache_ipprec << 5;

    rc = setsockopt(cache->fd, IPPROTO_IP, IP_TOS, &opt, (socklen_t) sizeof(opt));
    if (rc < 0) Log(LOG_WARNING, "WARN ( %s/core/RPKI ): rpki_rtr_connect(): setsockopt() failed for IP_TOS (errno: %d).\n", config.name, errno);
  }

  if (config.rpki_rtr_cache_pipe_size) {
    socklen_t l = sizeof(config.rpki_rtr_cache_pipe_size);
    int saved = 0, obtained = 0;

    getsockopt(cache->fd, SOL_SOCKET, SO_RCVBUF, &saved, &l);
    Setsocksize(cache->fd, SOL_SOCKET, SO_RCVBUF, &config.rpki_rtr_cache_pipe_size, (socklen_t) sizeof(config.rpki_rtr_cache_pipe_size));
    getsockopt(cache->fd, SOL_SOCKET, SO_RCVBUF, &obtained, &l);

    Setsocksize(cache->fd, SOL_SOCKET, SO_RCVBUF, &saved, l);
    getsockopt(cache->fd, SOL_SOCKET, SO_RCVBUF, &obtained, &l);
    Log(LOG_INFO, "INFO ( %s/core/RPKI ): rpki_rtr_connect(): rpki_rtr_srv_pipe_size: obtained=%d target=%d.\n",
	config.name, obtained, config.rpki_rtr_cache_pipe_size);
  }

  rc = connect(cache->fd, (struct sockaddr *) &cache->sock, cache->socklen);
  if (rc < 0) {
    Log(LOG_WARNING, "WARN ( %s/core/RPKI ): rpki_rtr_connect(): connect() failed: %s\n", config.name, strerror(errno));
    rpki_rtr_close(cache);
  }
  else {
    Log(LOG_INFO, "INFO ( %s/core/RPKI ): Connected to RTR Cache: %s\n", config.name, config.rpki_rtr_cache);
    cache->session_id = 0;
    cache->serial = 0;
  }
}

void rpki_rtr_close(struct rpki_rtr_handle *cache)
{
  if (config.debug) Log(LOG_DEBUG, "DEBUG ( %s/core/RPKI ): rpki_rtr_close()\n", config.name);

  close(cache->fd);
  cache->fd = ERR;

  cache->session_id = 0;
  cache->serial = 0;

  rpki_ribs_reset(&rpki_peer, &rpki_roa_db->rib[AFI_IP][SAFI_UNICAST], &rpki_roa_db->rib[AFI_IP6][SAFI_UNICAST]);
}

void rpki_rtr_send_reset_query(struct rpki_rtr_handle *cache)
{
  struct rpki_rtr_reset rqm;
  ssize_t msglen;

  if (cache->fd > 0) {
    if (cache->now >= (cache->refresh.tstamp + cache->refresh.ivl)) {
      cache->refresh.tstamp = cache->now;
    }
    else return;

    if (config.debug) Log(LOG_DEBUG, "DEBUG ( %s/core/RPKI ): rpki_rtr_send_reset_query()\n", config.name);

    memset(&rqm, 0, sizeof(rqm));

    rqm.version = config.rpki_rtr_cache_version;
    rqm.pdu_type = RPKI_RTR_PDU_RESET_QUERY;
    rqm.len = htonl(RPKI_RTR_PDU_RESET_QUERY_LEN);

    msglen = send(cache->fd, &rqm, sizeof(rqm), 0);
    if (msglen != RPKI_RTR_PDU_RESET_QUERY_LEN) {
      Log(LOG_WARNING, "WARN ( %s/core/RPKI ): rpki_rtr_send_reset_query(): send() failed\n", config.name);
      rpki_rtr_close(cache);
    }
  }
}

void rpki_rtr_send_serial_query(struct rpki_rtr_handle *cache)
{
  struct rpki_rtr_serial snm;
  ssize_t msglen;

  if (cache->fd > 0) {
    if (cache->now >= (cache->refresh.tstamp + cache->refresh.ivl)) {
      cache->refresh.tstamp = cache->now;
    }
    else return;

    if (config.debug) Log(LOG_DEBUG, "DEBUG ( %s/core/RPKI ): rpki_rtr_send_serial_query()\n", config.name);

    memset(&snm, 0, sizeof(snm));

    snm.version = config.rpki_rtr_cache_version;
    snm.pdu_type = RPKI_RTR_PDU_SERIAL_QUERY;
    snm.len = htonl(RPKI_RTR_PDU_SERIAL_QUERY_LEN);
    snm.session_id = htons(cache->session_id);
    snm.serial = htonl(cache->serial);

    msglen = send(cache->fd, &snm, sizeof(snm), 0);
    if (msglen != RPKI_RTR_PDU_SERIAL_QUERY_LEN) {
      Log(LOG_WARNING, "WARN ( %s/core/RPKI ): rpki_rtr_send_serial_query(): send() failed\n", config.name);
      rpki_rtr_close(cache);
    }
  }
}

void rpki_rtr_recv_cache_response(struct rpki_rtr_handle *cache)
{
  struct rpki_rtr_cache_response crm;
  ssize_t msglen;

  if (cache->fd > 0) {
    if (config.debug) Log(LOG_DEBUG, "DEBUG ( %s/core/RPKI ): rpki_rtr_recv_cache_response()\n", config.name);

    memset(&crm, 0, sizeof(crm));

    msglen = recv(cache->fd, &crm, sizeof(crm), MSG_WAITALL);
    if (msglen == RPKI_RTR_PDU_CACHE_RESPONSE_LEN) {
      cache->session_id = ntohs(crm.session_id);
    }
    else {
      Log(LOG_WARNING, "WARN ( %s/core/RPKI ): rpki_rtr_recv_cache_response(): recv() failed\n", config.name);
      rpki_rtr_close(cache);
    }
  }
}

void rpki_rtr_recv_serial_notify(struct rpki_rtr_handle *cache)
{
  struct rpki_rtr_serial snm;
  ssize_t msglen;

  if (cache->fd > 0) {
    if (config.debug) Log(LOG_DEBUG, "DEBUG ( %s/core/RPKI ): rpki_rtr_recv_serial_notify()\n", config.name);

    memset(&snm, 0, sizeof(snm));

    msglen = recv(cache->fd, &snm, sizeof(snm), MSG_WAITALL);
    if (msglen != RPKI_RTR_PDU_SERIAL_NOTIFY_LEN) {
      Log(LOG_WARNING, "WARN ( %s/core/RPKI ): rpki_rtr_recv_serial_notify(): recv() failed\n", config.name);
      rpki_rtr_close(cache);
    }
  }
}

void rpki_rtr_recv_ipv4_pref(struct rpki_rtr_handle *cache)
{
  struct rpki_rtr_ipv4_pref p4m;
  ssize_t msglen;

  if (cache->fd > 0) {
    if (config.debug) Log(LOG_DEBUG, "DEBUG ( %s/core/RPKI ): rpki_rtr_recv_ipv4_pref()\n", config.name);

    memset(&p4m, 0, sizeof(p4m));

    msglen = recv(cache->fd, &p4m, sizeof(p4m), MSG_WAITALL);
    if (msglen == RPKI_RTR_PDU_IPV4_PREFIX_LEN) {
      rpki_rtr_parse_ipv4_prefix(cache, &p4m);
    }
    else {
      Log(LOG_WARNING, "WARN ( %s/core/RPKI ): rpki_rtr_recv_ipv4_pref(): recv() failed\n", config.name);
      rpki_rtr_close(cache);
    }
  }
}

void rpki_rtr_recv_ipv6_pref(struct rpki_rtr_handle *cache)
{
  struct rpki_rtr_ipv6_pref p6m;
  ssize_t msglen;

  if (cache->fd > 0) {
    if (config.debug) Log(LOG_DEBUG, "DEBUG ( %s/core/RPKI ): rpki_rtr_recv_ipv6_pref()\n", config.name);

    memset(&p6m, 0, sizeof(p6m));
  
    msglen = recv(cache->fd, &p6m, sizeof(p6m), MSG_WAITALL);
    if (msglen == RPKI_RTR_PDU_IPV6_PREFIX_LEN) {
      rpki_rtr_parse_ipv6_prefix(cache, &p6m);
    }
    else {
      Log(LOG_WARNING, "WARN ( %s/core/RPKI ): rpki_rtr_recv_ipv6_pref(): recv() failed\n", config.name);
      rpki_rtr_close(cache);
    }
  }
}

void rpki_rtr_recv_eod(struct rpki_rtr_handle *cache, u_int8_t version)
{
  struct rpki_rtr_eod_v0 eodm_v0, *eodm_cmn = NULL;
  struct rpki_rtr_eod_v1 eodm_v1;
  char *eodm = NULL;

  ssize_t msglen = 0;
  u_int8_t eodm_len = 0;

  if (cache->fd > 0) {
    if (config.debug) Log(LOG_DEBUG, "DEBUG ( %s/core/RPKI ): rpki_rtr_recv_eod()\n", config.name);

    if (version == RPKI_RTR_V0) {
      memset(&eodm_v0, 0, sizeof(eodm_v0));

      eodm = (char *) &eodm_v0;
      eodm_cmn = (struct rpki_rtr_eod_v0 *) &eodm_v0;
      eodm_len = RPKI_RTR_PDU_END_OF_DATA_V0_LEN;
    }
    else {
      memset(&eodm_v1, 0, sizeof(eodm_v1));

      eodm = (char *) &eodm_v1;
      eodm_cmn = (struct rpki_rtr_eod_v0 *) &eodm_v1;
      eodm_len = RPKI_RTR_PDU_END_OF_DATA_V1_LEN;
    }

    msglen = recv(cache->fd, eodm, eodm_len, MSG_WAITALL);
    if (msglen == eodm_len) {
      if (cache->session_id != ntohs(eodm_cmn->session_id)) {
	Log(LOG_WARNING, "WARN ( %s/core/RPKI ): rpki_rtr_recv_eod(): unexpected session_id: %u\n", config.name, eodm_cmn->session_id);
	rpki_rtr_close(cache);
      }

      cache->serial = ntohl(eodm_cmn->serial);

      cache->refresh.tstamp = cache->now;
      cache->expire.tstamp = cache->now;

      if (version == RPKI_RTR_V1) {
	if (eodm_v1.retry_ivl) cache->retry.ivl = ntohl(eodm_v1.retry_ivl);
	if (eodm_v1.refresh_ivl) cache->refresh.ivl = ntohl(eodm_v1.refresh_ivl);
	if (eodm_v1.expire_ivl) cache->expire.ivl = ntohl(eodm_v1.expire_ivl);

	if (cache->expire.tstamp <= cache->retry.ivl || cache->expire.tstamp <= cache->refresh.ivl) {
	  Log(LOG_WARNING, "WARN ( %s/core/RPKI ): rpki_rtr_recv_eod(): invalid expire interval (refresh_ivl=%u retry_ivl=%u expire_ivl=%u)\n",
	      config.name, cache->refresh.ivl, cache->retry.ivl, cache->expire.ivl);
	  rpki_rtr_close(cache);
	}
      }

      if (config.debug) {
	Log(LOG_DEBUG, "DEBUG ( %s/core/RPKI ): rpki_rtr_recv_eod(): refresh_ivl=%u retry_ivl=%u expire_ivl=%u\n",
	    config.name, cache->refresh.ivl, cache->retry.ivl, cache->expire.ivl);
      }
    }
    else {
      Log(LOG_WARNING, "WARN ( %s/core/RPKI ): rpki_rtr_recv_eod(): recv() failed\n", config.name);
      rpki_rtr_close(cache);
    }
  }
}

void rpki_rtr_recv_cache_reset(struct rpki_rtr_handle *cache)
{
  struct rpki_rtr_reset crm;
  ssize_t msglen;

  if (cache-> fd > 0) {
    if (config.debug) Log(LOG_DEBUG, "DEBUG ( %s/core/RPKI ): rpki_rtr_recv_cache_reset()\n", config.name);

    memset(&crm, 0, sizeof(crm));

    msglen = recv(cache->fd, &crm, sizeof(crm), MSG_WAITALL);
    if (msglen != RPKI_RTR_PDU_CACHE_RESET_LEN) {
      Log(LOG_WARNING, "WARN ( %s/core/RPKI ): rpki_rtr_recv_cache_reset(): recv() failed\n", config.name);
      rpki_rtr_close(cache);
    }

    /* this will trigger a reset query */
    cache->session_id = 0;
    cache->serial = 0;

    rpki_ribs_reset(&rpki_peer, &rpki_roa_db->rib[AFI_IP][SAFI_UNICAST], &rpki_roa_db->rib[AFI_IP6][SAFI_UNICAST]); 
  }
}

void rpki_rtr_recv_router_key(struct rpki_rtr_handle *cache)
{
  struct rpki_rtr_router_key rkm;
  ssize_t msglen;
  char *rkmbuf = NULL;

  if (cache-> fd > 0) {
    if (config.debug) Log(LOG_DEBUG, "DEBUG ( %s/core/RPKI ): rpki_rtr_recv_router_key()\n", config.name);

    memset(&rkm, 0, sizeof(rkm));

    msglen = recv(cache->fd, &rkm, sizeof(rkm), MSG_WAITALL);
    if (msglen != sizeof(rkm)) {
      Log(LOG_WARNING, "WARN ( %s/core/RPKI ): rpki_rtr_recv_router_key(): recv() failed (1)\n", config.name);
      rpki_rtr_close(cache);
      goto exit_lane;
    }

    if (rkm.version == RPKI_RTR_V0) {
      Log(LOG_WARNING, "WARN ( %s/core/RPKI ): rpki_rtr_recv_router_key(): Router Key not supported in RTRv0\n", config.name);
      rpki_rtr_close(cache);
      goto exit_lane;
    }

    if (rkm.len > msglen) {
      u_int32_t rem_len = (rkm.len - msglen);

      rkmbuf = malloc(rem_len);
      msglen = recv(cache->fd, rkmbuf, rem_len, MSG_WAITALL);
      if (msglen != rem_len) {
	Log(LOG_WARNING, "WARN ( %s/core/RPKI ): rpki_rtr_recv_router_key(): recv() failed (2)\n", config.name);
	rpki_rtr_close(cache);
	goto exit_lane;
      }

      // XXX

      exit_lane:
      if (rkmbuf) free(rkmbuf);
    }
  }
}

void rpki_rtr_recv_error_report(struct rpki_rtr_handle *cache)
{
  struct rpki_rtr_err_report erm;
  ssize_t msglen;
  char *ermbuf = NULL, *errmsg_ptr;
  u_int32_t *encpdu_len;

  if (cache->fd > 0) {
    if (config.debug) Log(LOG_DEBUG, "DEBUG ( %s/core/RPKI ): rpki_rtr_recv_error_report()\n", config.name);

    memset(&erm, 0, sizeof(erm));

    msglen = recv(cache->fd, &erm, sizeof(erm), MSG_WAITALL);
    if (msglen != sizeof(erm)) {
      Log(LOG_WARNING, "WARN ( %s/core/RPKI ): rpki_rtr_recv_error_report(): recv() failed (1)\n", config.name);
      rpki_rtr_close(cache);
      goto exit_lane;
    }

    if (erm.tot_len > msglen) {
      u_int32_t rem_len = (erm.tot_len - msglen);

      ermbuf = malloc(rem_len + 1);
      msglen = recv(cache->fd, ermbuf, rem_len, MSG_WAITALL);
      if (msglen != rem_len) {
	Log(LOG_WARNING, "WARN ( %s/core/RPKI ): rpki_rtr_recv_error_report(): recv() failed (2)\n", config.name);
	rpki_rtr_close(cache);
	goto exit_lane;
      }

      ermbuf[rem_len] = '\0';

      encpdu_len = (u_int32_t *) ermbuf;
      errmsg_ptr = (char *) (ermbuf + (*encpdu_len) + 4 + 4);

      Log(LOG_WARNING, "WARN ( %s/core/RPKI ): rpki_rtr_recv_error_report(): %s\n", config.name, errmsg_ptr);

      exit_lane:
      if (ermbuf) free(ermbuf);
    }
  }
}
