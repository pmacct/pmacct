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
#if defined WITH_ZMQ
#include "zmq_common.h"
#endif
#include "bgp.h"
#include "bgp_lg.h"
#include "pmacct-data.h"
#include "thread_pool.h"

/* global var */
thread_pool_t *bgp_lg_pool;
char bgp_lg_default_ip[] = "127.0.0.1";

#if defined WITH_ZMQ
void bgp_lg_wrapper()
{
  /* initialize variables */
  if (!config.bgp_lg_ip) config.bgp_lg_ip = bgp_lg_default_ip;
  if (!config.bgp_lg_port) config.bgp_lg_port = BGP_LG_DEFAULT_TCP_PORT;
  if (!config.bgp_lg_threads) config.bgp_lg_threads = BGP_LG_DEFAULT_THREADS;

  /* initialize threads pool */
  bgp_lg_pool = allocate_thread_pool(1);
  assert(bgp_lg_pool);
  Log(LOG_DEBUG, "DEBUG ( %s/core/lg ): Looking Glass thread initialized\n", config.name);

  /* giving a kick to the BGP thread */
  send_to_pool(bgp_lg_pool, bgp_lg_daemon, NULL);
}

int bgp_lg_daemon()
{
  char inproc_str[] = "inproc://lg_host_backend", log_id[SHORTBUFLEN];
  struct p_zmq_host lg_host;

  memset(&lg_host, 0, sizeof(lg_host));

  snprintf(log_id, sizeof(log_id), "%s/core/lg", config.name);
  p_zmq_set_log_id(&lg_host, log_id);

  p_zmq_set_address(&lg_host, inproc_str);
  if (config.bgp_lg_user) p_zmq_set_username(&lg_host, config.bgp_lg_user);
  if (config.bgp_lg_passwd) p_zmq_set_password(&lg_host, config.bgp_lg_passwd);

  p_zmq_router_setup(&lg_host, config.bgp_lg_ip, config.bgp_lg_port);
  Log(LOG_INFO, "INFO ( %s/core/lg ): Looking Glass listening on %s:%u\n", config.name, config.bgp_lg_ip, config.bgp_lg_port);

  // XXX: more encodings supported in future?
#ifdef WITH_JANSSON
  lg_host.router_worker.func = &bgp_lg_daemon_worker_json;
#else
  lg_host.router_worker.func = NULL;
  Log(LOG_WARNING, "WARN ( %s/core/lg ): Looking Glass depends on missing --enable-jansson.\n", config.name);
  exit_gracefully(1);
#endif

  p_zmq_router_backend_setup(&lg_host, config.bgp_lg_threads);

  return SUCCESS;
}

#ifdef WITH_JANSSON
void bgp_lg_daemon_worker_json(void *zh, void *zs)
{
  struct p_zmq_host *lg_host = (struct p_zmq_host *) zh;
  struct p_zmq_sock *sock = zs;
  struct bgp_lg_req req;
  struct bgp_lg_rep ipl_rep, gp_rep;
  int ret;

  if (!lg_host || !sock) {
    Log(LOG_ERR, "ERROR ( %s/core/lg ): bgp_lg_daemon_worker no lg_host or sock\nExiting.\n", config.name);
    exit_gracefully(1);
  }

  memset(&ipl_rep, 0, sizeof(ipl_rep));
  memset(&gp_rep, 0, sizeof(gp_rep));

  for (;;) {
    memset(&req, 0, sizeof(req));
    ret = bgp_lg_daemon_decode_query_header_json(sock, &req);

    switch(req.type) {
    case BGP_LG_QT_IP_LOOKUP:
      {
        struct bgp_lg_req_ipl_data query_data;

        req.data = &query_data;
	memset(req.data, 0, sizeof(struct bgp_lg_req_ipl_data));
        ret = bgp_lg_daemon_decode_query_ip_lookup_json(sock, req.data);

        bgp_lg_rep_init(&ipl_rep);
        if (!ret) ret = bgp_lg_daemon_ip_lookup(req.data, &ipl_rep, FUNC_TYPE_BGP); 

        bgp_lg_daemon_encode_reply_ip_lookup_json(sock, &ipl_rep, ret);
      }
      break;
    case BGP_LG_QT_GET_PEERS:
      bgp_lg_rep_init(&gp_rep);
      ret = bgp_lg_daemon_get_peers(&gp_rep, FUNC_TYPE_BGP);
      bgp_lg_daemon_encode_reply_get_peers_json(sock, &gp_rep, ret);

      break;
    case BGP_LG_QT_UNKNOWN:
    default:
      bgp_lg_daemon_encode_reply_unknown_json(sock);
      break;
    }
  }
}

int bgp_lg_daemon_decode_query_header_json(struct p_zmq_sock *sock, struct bgp_lg_req *req) 
{
  json_t *req_obj, *query_type_json, *queries_num_json;
  json_error_t req_err;
  char *req_str;
  int ret = SUCCESS;

  if (!sock || !req) return ERR;

  req_str = p_zmq_recv_str(sock);
  if (req_str) {
    req_obj = json_loads(req_str, 0, &req_err);
    free(req_str);
  }
  else {
    req_obj = NULL;
    ret = ERR;
  }

  if (req_obj) {
    if (!json_is_object(req_obj)) {
      Log(LOG_WARNING, "WARN ( %s/core/lg ): bgp_lg_daemon_decode_query_header_json(): json_is_object() failed.\n", config.name);
      ret = ERR;
      goto exit_lane;
    }
    else {
      query_type_json = json_object_get(req_obj, "query_type");
      if (query_type_json == NULL) {
        Log(LOG_WARNING, "WARN ( %s/core/lg ): bgp_lg_daemon_decode_query_header_json(): no 'query_type' element.\n", config.name);
        ret = ERR;
        goto exit_lane;
      }
      else req->type = json_integer_value(query_type_json);

      queries_num_json = json_object_get(req_obj, "queries");
      if (queries_num_json == NULL) {
        Log(LOG_WARNING, "WARN ( %s/core/lg ): bgp_lg_daemon_decode_query_header_json(): no 'queries' element.\n", config.name);
        ret = ERR;
        goto exit_lane;
      }
      else req->num = json_integer_value(queries_num_json);

      /* XXX: only one query per query message currently supported */
      if (req->num != 1) {
        Log(LOG_WARNING, "WARN ( %s/core/lg ): bgp_lg_daemon_decode_query_header_json(): 'queries' element != 1.\n", config.name);
        ret = ERR;
        goto exit_lane;
      }
    }

    exit_lane:
    json_decref(req_obj);
  }
  else {
    Log(LOG_WARNING, "WARN ( %s/core/lg ): bgp_lg_daemon_decode_query_header_json(): invalid request received: %s.\n", config.name, req_err.text);
    ret = ERR;
  }

  return ret;
}

int bgp_lg_daemon_decode_query_ip_lookup_json(struct p_zmq_sock *sock, struct bgp_lg_req_ipl_data *req) 
{
  json_error_t req_err;
  json_t *req_obj, *peer_ip_src_json, *bgp_port_json, *ip_prefix_json, *rd_json;
  const char *peer_ip_src_str, *ip_prefix_str, *rd_str;
  char *req_str;
  int ret = SUCCESS;
  struct rd_as4 *rd_as4_ptr; 
  u_int16_t bgp_port = 0;

  if (!sock || !req) return ERR;

  req_str = p_zmq_recv_str(sock);

  if (req_str) {
    req_obj = json_loads(req_str, 0, &req_err);
    free(req_str);
  }
  else {
    req_obj = NULL;
    ret = ERR;
  }

  if (req_obj) {
    if (!json_is_object(req_obj)) {
      Log(LOG_WARNING, "WARN ( %s/core/lg ): bgp_lg_daemon_decode_query_ip_lookup_json(): json_is_object() failed.\n", config.name);
      ret = ERR;
      goto exit_lane;
    }
    else {
      bgp_port_json = json_object_get(req_obj, "peer_tcp_port");
      if (bgp_port_json) {
        int bgp_port_int;

        bgp_port_int = json_integer_value(bgp_port_json);
        if (bgp_port_int >= 0 && bgp_port_int <= 65535) bgp_port = bgp_port_int;
        else {
          Log(LOG_WARNING, "WARN ( %s/core/lg ): bgp_lg_daemon_decode_query_ip_lookup_json(): bogus 'peer_tcp_port' element.\n", config.name);
          ret = ERR;
          goto exit_lane;
        }
      }

      peer_ip_src_json = json_object_get(req_obj, "peer_ip_src");
      if (peer_ip_src_json == NULL) {
	Log(LOG_WARNING, "WARN ( %s/core/lg ): bgp_lg_daemon_decode_query_ip_lookup_json(): no 'peer_ip_src' element.\n", config.name);
	ret = ERR;
	goto exit_lane;
      }
      else {
	struct host_addr peer_ip_src_ha;

	peer_ip_src_str = json_string_value(peer_ip_src_json);
	str_to_addr(peer_ip_src_str, &peer_ip_src_ha);
	addr_to_sa(&req->peer, &peer_ip_src_ha, bgp_port);
	if (!req->peer.sa_family) {
	  Log(LOG_WARNING, "WARN ( %s/core/lg ): bgp_lg_daemon_decode_query_ip_lookup_json(): bogus 'peer_ip_src' element.\n", config.name);
	  ret = ERR;
	  goto exit_lane;
	}
      }

      ip_prefix_json = json_object_get(req_obj, "ip_prefix");
      if (ip_prefix_json == NULL) {
	Log(LOG_WARNING, "WARN ( %s/core/lg ): bgp_lg_daemon_decode_query_ip_lookup_json(): no 'ip_prefix' element.\n", config.name);
	ret = ERR;
	goto exit_lane;
      }
      else {
	ip_prefix_str = json_string_value(ip_prefix_json);
	str2prefix(ip_prefix_str, &req->pref);
	if (!req->pref.family) {
	  Log(LOG_WARNING, "WARN ( %s/core/lg ): bgp_lg_daemon_decode_query_ip_lookup_json(): bogus 'ip_prefix' element.\n", config.name);
	  ret = ERR;
	  goto exit_lane;
	}
      }

      rd_json = json_object_get(req_obj, "rd");
      if (rd_json) {
        rd_str = json_string_value(rd_json);
        bgp_str2rd(&req->rd, (char *) rd_str);
	rd_as4_ptr = (struct rd_as4 *) &req->rd;
        if (!rd_as4_ptr->as) {
          Log(LOG_WARNING, "WARN ( %s/core/lg ): bgp_lg_daemon_decode_query_ip_lookup_json(): bogus 'rd' element.\n", config.name);
          ret = ERR;
          goto exit_lane;
        }
      }
    }

    exit_lane:
    json_decref(req_obj);
  }
  else {
    Log(LOG_WARNING, "WARN ( %s/core/lg ): bgp_lg_daemon_decode_query_ip_lookup_json(): invalid request received: %s.\n", config.name, req_err.text);
    ret = ERR;
  }

  return ret;
}

void bgp_lg_daemon_encode_reply_results_json(struct p_zmq_sock *sock, struct bgp_lg_rep *rep, int res, int query_type)
{
  json_t *rep_results_obj;
  char *rep_results_str;

  rep_results_obj = json_object();
  json_object_set_new_nocheck(rep_results_obj, "results", json_integer(rep->results));
  json_object_set_new_nocheck(rep_results_obj, "query_type", json_integer(query_type));

  if (!rep->results && res) {
    switch (res) {
    case BGP_LOOKUP_ERR:
      json_object_set_new_nocheck(rep_results_obj, "text", json_string("lookup error"));
      break;
    case BGP_LOOKUP_NOPREFIX:
      json_object_set_new_nocheck(rep_results_obj, "text", json_string("prefix not found"));
      break;
    case BGP_LOOKUP_NOPEER:
      json_object_set_new_nocheck(rep_results_obj, "text", json_string("peer not found"));
      break;
    default:
      json_object_set_new_nocheck(rep_results_obj, "text", json_string("unknown lookup error"));
      break;
    }
  }

  rep_results_str = json_dumps(rep_results_obj, JSON_PRESERVE_ORDER);
  json_decref(rep_results_obj);

  if (rep_results_str) {
    if (!rep->results) p_zmq_send_str(sock, rep_results_str);
    else p_zmq_sendmore_str(sock, rep_results_str);

    free(rep_results_str);
  }
}

void bgp_lg_daemon_encode_reply_ip_lookup_json(struct p_zmq_sock *sock, struct bgp_lg_rep *rep, int res) 
{
  if (!sock || !rep) return;

  bgp_lg_daemon_encode_reply_results_json(sock, rep, res, BGP_LG_QT_IP_LOOKUP);  

  if (rep->results) {
    struct bgp_lg_rep_data *data;
    struct bgp_lg_rep_ipl_data *ipl_data;
    char *rep_data_str;
    u_int32_t idx;

    for (idx = 0, data = rep->data; idx < rep->results; idx++) {
      ipl_data = data->ptr;

      rep_data_str = bgp_lg_daemon_encode_reply_ip_lookup_data_json(ipl_data);

      if (rep_data_str) {
	if (idx == (rep->results - 1)) p_zmq_send_str(sock, rep_data_str); 
        else p_zmq_sendmore_str(sock, rep_data_str);

	free(rep_data_str);
      }

      data = data->next;
    }
  }
}

char *bgp_lg_daemon_encode_reply_ip_lookup_data_json(struct bgp_lg_rep_ipl_data *rep_data)
{
  struct bgp_node dummy_node;
  char event_type[] = "lglass", *data_str = NULL;

  if (rep_data && rep_data->pref) {
    memset(&dummy_node, 0, sizeof(dummy_node));
    memcpy(&dummy_node.p, rep_data->pref, sizeof(struct prefix)); 

    bgp_peer_log_msg(&dummy_node, rep_data->info, rep_data->afi, rep_data->safi, event_type,
		     PRINT_OUTPUT_JSON, &data_str, BGP_LOG_TYPE_MISC);
  }

  return data_str;
}

void bgp_lg_daemon_encode_reply_get_peers_json(struct p_zmq_sock *sock, struct bgp_lg_rep *rep, int res) 
{
  if (!sock || !rep) return;

  bgp_lg_daemon_encode_reply_results_json(sock, rep, res, BGP_LG_QT_GET_PEERS);

  if (rep->results) {
    struct bgp_lg_rep_data *data;
    struct bgp_lg_rep_gp_data *gp_data;
    char *rep_data_str;
    u_int32_t idx;

    for (idx = 0, data = rep->data; idx < rep->results; idx++) {
      gp_data = data->ptr;

      rep_data_str = bgp_lg_daemon_encode_reply_get_peers_data_json(gp_data);

      if (rep_data_str) {
        if (idx == (rep->results - 1)) p_zmq_send_str(sock, rep_data_str);
        else p_zmq_sendmore_str(sock, rep_data_str);

        free(rep_data_str);
      }

      data = data->next;
    }
  }
}

char *bgp_lg_daemon_encode_reply_get_peers_data_json(struct bgp_lg_rep_gp_data *rep_data)
{
  struct bgp_misc_structs *bms;
  char ip_address[INET6_ADDRSTRLEN], *data_str = NULL;
  json_t *obj = json_object();

  if (rep_data) {
    struct bgp_peer *peer = rep_data->peer;

    bms = bgp_select_misc_db(peer->type);
    if (!bms) return NULL;

    addr_to_str(ip_address, &peer->addr);
    json_object_set_new_nocheck(obj, bms->peer_str, json_string(ip_address));

    addr_to_str(ip_address, &peer->id);
    json_object_set_new_nocheck(obj, "peer_id", json_string(ip_address));

    json_object_set_new_nocheck(obj, "peer_tcp_port", json_integer((json_int_t)peer->tcp_port));
    json_object_set_new_nocheck(obj, "peer_as", json_integer((json_int_t)peer->as));

    data_str = compose_json_str(obj); 
  }

  return data_str;
}

void bgp_lg_daemon_encode_reply_unknown_json(struct p_zmq_sock *sock)
{
  json_t *rep_results_obj;
  char *rep_results_str;

  if (!sock) return;

  rep_results_obj = json_object();
  json_object_set_new_nocheck(rep_results_obj, "results", json_integer(FALSE));
  json_object_set_new_nocheck(rep_results_obj, "query_type", json_integer(BGP_LG_QT_UNKNOWN));
  json_object_set_new_nocheck(rep_results_obj, "text", json_string("unsupported query_type"));

  rep_results_str = json_dumps(rep_results_obj, JSON_PRESERVE_ORDER);
  json_decref(rep_results_obj);

  p_zmq_send_str(sock, rep_results_str);
}
#endif
#endif /* WITH_ZMQ */ 
