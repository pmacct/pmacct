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

/* defines */
#define __RPKI_MSG_C

/* includes */
#include "pmacct.h"
#include "pmacct-data.h"
#include "bgp/bgp.h"
#include "rpki.h"

/* functions */
int rpki_roas_file_load(char *file, struct bgp_table *rib_v4, struct bgp_table *rib_v6)
{
  struct bgp_misc_structs *r_data = rpki_misc_db;

  Log(LOG_INFO, "INFO ( %s/%s ): [%s] (re)loading map.\n", config.name, r_data->log_str, file);

#if defined WITH_JANSSON
  json_t *roas_obj, *roa_json, *roas_json;
  json_error_t file_err;
  int roas_idx;

  rpki_init_dummy_peer(&rpki_peer);

  roas_obj = json_load_file(file, 0, &file_err);

  if (roas_obj) {
    if (!json_is_object(roas_obj)) {
      Log(LOG_ERR, "ERROR ( %s/%s ): [%s] json_is_object() failed for results: %s\n", config.name, r_data->log_str, file, file_err.text);
      return ERR;
    }
    else {
      roas_json = json_object_get(roas_obj, "roas");
      if (roas_json == NULL || !json_is_array(roas_json)) {
        Log(LOG_ERR, "ERROR ( %s/%s ): [%s] no 'roas' element or not an array.\n", config.name, r_data->log_str, file);
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
	    Log(LOG_WARNING, "WARN ( %s/%s ): [%s] no 'prefix' element in ROA #%u.\n", config.name, r_data->log_str, file, (roas_idx + 1));
	    goto exit_lane;
	  }
	  else {
	    ret = str2prefix(json_string_value(prefix_json), &p);

	    if (!ret) {
	      Log(LOG_WARNING, "WARN ( %s/%s ): [%s] invalid 'prefix' element in ROA #%u.\n", config.name, r_data->log_str, file, (roas_idx + 1));
	      goto exit_lane;
	    }
	  }

	  asn_json = json_object_get(roa_json, "asn");
	  if (asn_json == NULL || !json_is_string(asn_json)) {
	    Log(LOG_WARNING, "WARN ( %s/%s ): [%s] no 'asn' element in ROA #%u.\n", config.name, r_data->log_str, file, (roas_idx + 1));
	    goto exit_lane;
	  }
	  else {
	    ret = bgp_str2asn((char *)json_string_value(asn_json), &asn);

	    if (ret) {
	      Log(LOG_WARNING, "WARN ( %s/%s ): [%s] invalid 'asn' element in ROA #%u.\n", config.name, r_data->log_str, file, (roas_idx + 1));
	      goto exit_lane;
	    }
	  }

	  maxlen_json = json_object_get(roa_json, "maxLength");
	  if (maxlen_json == NULL || !json_is_integer(maxlen_json)) {
	    Log(LOG_WARNING, "WARN ( %s/%s ): [%s] no 'maxLength' element in ROA #%u.\n", config.name, r_data->log_str, file, (roas_idx + 1));
	    goto exit_lane;
	  }
	  else maxlen = json_integer_value(maxlen_json);

	  if (maxlen < p.prefixlen) {
	    char prefix_str[INET6_ADDRSTRLEN];

	    prefix2str(&p, prefix_str, INET6_ADDRSTRLEN);
	    Log(LOG_WARNING, "WARN ( %s/%s ): [%s] 'maxLength' < prefixLength: prefix=%s maxLength=%u asn=%u\n",
		config.name, r_data->log_str, file, prefix_str, maxlen, asn);
	  }

	  ret = rpki_info_add(&rpki_peer, &p, asn, maxlen, rib_v4, rib_v6);

	  exit_lane:
	  continue;
	}
      }

      json_decref(roas_obj);
    }

    Log(LOG_INFO, "INFO ( %s/%s ): [%s] map successfully (re)loaded.\n", config.name, r_data->log_str, file);
  }
  else {
    Log(LOG_ERR, "ERROR ( %s/%s ): [%s] json_loads() failed: %s.\n", config.name, r_data->log_str, file, file_err.text);
    return ERR;
  }
#else
  Log(LOG_WARNING, "WARN ( %s/%s ): rpki_roas_file will not load (missing --enable-jansson).\n", config.name, r_data->log_str);
#endif

  return SUCCESS;
}

int rpki_info_add(struct bgp_peer *peer, struct prefix *p, as_t asn, u_int8_t maxlen, struct bgp_table *rib_v4, struct bgp_table *rib_v6)
{
  struct bgp_misc_structs *r_data = rpki_misc_db;
  struct bgp_node *route = NULL;
  struct bgp_info *new = NULL;
  struct bgp_attr attr, *attr_new = NULL;
  struct bgp_table *rib = NULL;
  afi_t afi;
  u_int32_t modulo;
  u_int8_t end;

  if (!r_data || !peer || !p || !rib_v4 || !rib_v6) return ERR;

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

    exit_lane:  
    continue;
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
	rpki_rtr_recv_eod(cache);
	break;
      case RPKI_RTR_PDU_CACHE_RESET:
	rpki_rtr_recv_cache_reset(cache);
	break;
      case RPKI_RTR_PDU_ERROR_REPORT:
	rpki_rtr_recv_error_report(cache);
	break;
      default:
	Log(LOG_ERR, "WARN ( %s/core/RPKI ): rpki_rtr_parse_msg(): unknown PDU type (%u)\n", config.name, peek.pdu_type);
	rpki_rtr_close(cache);
	break;
      }
    }
  }
}

void rpki_rtr_connect(struct rpki_rtr_handle *cache)
{
  int rc;

  if ((cache->fd = socket(cache->sock.ss_family, SOCK_DGRAM, 0)) == -1) {
    Log(LOG_ERR, "ERROR ( %s/core/RPKI ): rpki_rtr_connect(): socket() failed: %s\n", config.name, strerror(errno));
    exit_gracefully(1);
  }

  if (config.rpki_rtr_server_ipprec) {
    int opt = config.rpki_rtr_server_ipprec << 5;

    rc = setsockopt(cache->fd, IPPROTO_IP, IP_TOS, &opt, (socklen_t) sizeof(opt));
    if (rc < 0) Log(LOG_ERR, "WARN ( %s/core/RPKI ): rpki_rtr_connect(): setsockopt() failed for IP_TOS (errno: %d).\n", config.name, errno);
  }

  if (config.rpki_rtr_server_pipe_size) {
    socklen_t l = sizeof(config.rpki_rtr_server_pipe_size);
    int saved = 0, obtained = 0;

    getsockopt(cache->fd, SOL_SOCKET, SO_RCVBUF, &saved, &l);
    Setsocksize(cache->fd, SOL_SOCKET, SO_RCVBUF, &config.rpki_rtr_server_pipe_size, (socklen_t) sizeof(config.rpki_rtr_server_pipe_size));
    getsockopt(cache->fd, SOL_SOCKET, SO_RCVBUF, &obtained, &l);

    Setsocksize(cache->fd, SOL_SOCKET, SO_RCVBUF, &saved, l);
    getsockopt(cache->fd, SOL_SOCKET, SO_RCVBUF, &obtained, &l);
    Log(LOG_INFO, "INFO ( %s/core/RPKI ): rpki_rtr_connect(): rpki_rtr_srv_pipe_size: obtained=%d target=%d.\n",
	config.name, obtained, config.rpki_rtr_server_pipe_size);
  }

  rc = connect(cache->fd, (struct sockaddr *) &cache->sock, cache->socklen);
  if (rc < 0) {
    Log(LOG_ERR, "WARN ( %s/core/RPKI ): rpki_rtr_connect(): connect() failed: %s\n", config.name, strerror(errno));
    rpki_rtr_close(cache);
  }
  else {
    Log(LOG_INFO, "INFO ( %s/core/RPKI ): Connected to RTR Cache: %s\n", config.name, config.rpki_rtr_server);
    cache->session_id = 0;
    cache->serial = 0;
  }
}

void rpki_rtr_close(struct rpki_rtr_handle *cache)
{
  close(cache->fd);
  cache->fd = ERR;

  cache->session_id = 0;
  cache->serial = 0;
}

void rpki_rtr_send_reset(struct rpki_rtr_handle *cache)
{
  struct rpki_rtr_reset rqm;
  ssize_t msglen;

  if (cache->fd > 0) {
    memset(&rqm, 0, sizeof(rqm));

    rqm.version = config.rpki_rtr_server_version;
    rqm.pdu_type = RPKI_RTR_PDU_RESET_QUERY;
    rqm.len = htonl(RPKI_RTR_PDU_RESET_QUERY_LEN);

    msglen = send(cache->fd, &rqm, sizeof(rqm), 0);
    if (msglen != RPKI_RTR_PDU_RESET_QUERY_LEN) {
      Log(LOG_ERR, "WARN ( %s/core/RPKI ): rpki_rtr_send_reset(): send() failed\n", config.name);
      rpki_rtr_close(cache);
    }
  }
}

void rpki_rtr_send_serial_query(struct rpki_rtr_handle *cache)
{
  struct rpki_rtr_serial snm;
  ssize_t msglen;

  if (cache->fd > 0) {
    // XXX
  }
}

void rpki_rtr_recv_cache_response(struct rpki_rtr_handle *cache)
{
  struct rpki_rtr_cache_response crm;
  ssize_t msglen;

  if (cache->fd > 0) {
    memset(&crm, 0, sizeof(crm));

    msglen = recv(cache->fd, &crm, sizeof(crm), 0);
    if (msglen == RPKI_RTR_PDU_CACHE_RESPONSE_LEN) {
      cache->session_id = crm.session_id;
    }
    else {
      Log(LOG_ERR, "WARN ( %s/core/RPKI ): rpki_rtr_recv_cache_response(): recv() failed\n", config.name);
      rpki_rtr_close(cache);
    }
  }
}

void rpki_rtr_recv_serial_notify(struct rpki_rtr_handle *cache)
{
  struct rpki_rtr_serial snm;
  ssize_t msglen;

  if (cache->fd > 0) {
    memset(&snm, 0, sizeof(snm));

    msglen = recv(cache->fd, &snm, sizeof(snm), 0);
    if (msglen != RPKI_RTR_PDU_SERIAL_NOTIFY_LEN) {
      Log(LOG_ERR, "WARN ( %s/core/RPKI ): rpki_rtr_recv_serial_notify(): recv() failed\n", config.name);
      rpki_rtr_close(cache);
    }
  }
}

void rpki_rtr_recv_ipv4_pref(struct rpki_rtr_handle *cache)
{
  struct rpki_rtr_ipv4_pref p4m;
  ssize_t msglen;

  if (cache->fd > 0) {
    memset(&p4m, 0, sizeof(p4m));

    msglen = recv(cache->fd, &p4m, sizeof(p4m), 0);
    if (msglen == RPKI_RTR_PDU_IPV4_PREFIX) {
      // XXX: parse
    }
    else {
      Log(LOG_ERR, "WARN ( %s/core/RPKI ): rpki_rtr_recv_ipv4_pref(): recv() failed\n", config.name);
      rpki_rtr_close(cache);
    }
  }
}

void rpki_rtr_recv_ipv6_pref(struct rpki_rtr_handle *cache)
{
  struct rpki_rtr_ipv6_pref p6m;
  ssize_t msglen;

  if (cache->fd > 0) {
    memset(&p6m, 0, sizeof(p6m));
  
    msglen = recv(cache->fd, &p6m, sizeof(p6m), 0);
    if (msglen == RPKI_RTR_PDU_IPV6_PREFIX) {
      // XXX: parse
    }
    else {
      Log(LOG_ERR, "WARN ( %s/core/RPKI ): rpki_rtr_recv_ipv6_pref(): recv() failed\n", config.name);
      rpki_rtr_close(cache);
    }
  }
}

void rpki_rtr_recv_eod(struct rpki_rtr_handle *cache)
{
  struct rpki_rtr_eod_v0 eodm;
  ssize_t msglen;

  if (cache->fd > 0) {
    memset(&eodm, 0, sizeof(eodm));

    msglen = recv(cache->fd, &eodm, sizeof(eodm), 0);
    if (msglen == RPKI_RTR_PDU_END_OF_DATA_LEN) {
      if (cache->session_id != eodm.session_id) {
	Log(LOG_ERR, "WARN ( %s/core/RPKI ): rpki_rtr_recv_eod(): unexpected session_id: %u\n", config.name, eodm.session_id);
	rpki_rtr_close(cache);
      }
    }
    else {
      Log(LOG_ERR, "WARN ( %s/core/RPKI ): rpki_rtr_recv_eod(): recv() failed\n", config.name);
      rpki_rtr_close(cache);
    }
  }
}

void rpki_rtr_recv_cache_reset(struct rpki_rtr_handle *cache)
{
  struct rpki_rtr_reset crm;
  ssize_t msglen;

  if (cache-> fd > 0) {
    // XXX
  }
}

void rpki_rtr_recv_error_report(struct rpki_rtr_handle *cache)
{
  struct rpki_rtr_err_report erm;
  ssize_t msglen;
  char *ermbuf = NULL;

  if (cache->fd > 0) {
    memset(&erm, 0, sizeof(erm));

    msglen = recv(cache->fd, &erm, sizeof(erm), 0);
    if (msglen != sizeof(erm)) {
      Log(LOG_ERR, "WARN ( %s/core/RPKI ): rpki_rtr_recv_error_report(): recv() failed (1)\n", config.name);
      rpki_rtr_close(cache);
      goto exit_lane;
    }

    if (erm.tot_len > msglen) {
      u_int32_t rem_len = (erm.tot_len - msglen);

      ermbuf = malloc(rem_len);
      msglen = recv(cache->fd, ermbuf, rem_len, 0);
      if (msglen != rem_len) {
	Log(LOG_ERR, "WARN ( %s/core/RPKI ): rpki_rtr_recv_error_report(): recv() failed (2)\n", config.name);
	rpki_rtr_close(cache);
	goto exit_lane;
      }

      // XXX

      exit_lane:
      if (ermbuf) free(ermbuf);
    }
  }
}
