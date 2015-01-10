/*  
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2015 by Paolo Lucente
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
#define __BGP_LOGDUMP_C

/* includes */
#include "pmacct.h"
#include "bgp.h"
#if defined WITH_RABBITMQ
#include "amqp_common.h"
#endif
#ifdef WITH_JANSSON
#include <jansson.h>
#endif

int bgp_peer_log_msg(struct bgp_node *route, struct bgp_info *ri, safi_t safi, char *event_type, int output)
{
  char log_rk[SRVBUFLEN];
  struct bgp_peer *peer = ri->peer;
  struct bgp_attr *attr = ri->attr;
  int ret = 0, amqp_ret = 0;

#ifdef WITH_RABBITMQ
  if (config.nfacctd_bgp_msglog_amqp_routing_key ||
      config.bgp_table_dump_amqp_routing_key)
    p_amqp_set_routing_key(peer->log->amqp_host, peer->log->filename);
#endif

  if (output == PRINT_OUTPUT_JSON) {
#ifdef WITH_JANSSON
    char ip_address[INET6_ADDRSTRLEN];
    json_t *obj = json_object(), *kv;

    char empty[] = "";
    char prefix_str[INET6_ADDRSTRLEN], nexthop_str[INET6_ADDRSTRLEN];
    char *aspath;

    /* no need for seq and timestamp for "dump" event_type */
    if (strcmp(event_type, "dump")) {
      kv = json_pack("{sI}", "seq", log_seq);
      json_object_update_missing(obj, kv);
      json_decref(kv);
      bgp_peer_log_seq_increment();

      kv = json_pack("{ss}", "timestamp", log_tstamp_str);
      json_object_update_missing(obj, kv);
      json_decref(kv);
    }

    addr_to_str(ip_address, &peer->addr);
    kv = json_pack("{ss}", "peer_ip_src", ip_address);
    json_object_update_missing(obj, kv);
    json_decref(kv);

    kv = json_pack("{ss}", "event_type", event_type);
    json_object_update_missing(obj, kv);
    json_decref(kv);

    memset(prefix_str, 0, INET6_ADDRSTRLEN);
    prefix2str(&route->p, prefix_str, INET6_ADDRSTRLEN);
    kv = json_pack("{ss}", "ip_prefix", prefix_str);
    json_object_update_missing(obj, kv);
    json_decref(kv);

    memset(nexthop_str, 0, INET6_ADDRSTRLEN);
    if (attr->mp_nexthop.family) addr_to_str(nexthop_str, &attr->mp_nexthop);
    else inet_ntop(AF_INET, &attr->nexthop, nexthop_str, INET6_ADDRSTRLEN);
    kv = json_pack("{ss}", "bgp_nexthop", nexthop_str);
    json_object_update_missing(obj, kv);
    json_decref(kv);

    if (ri && ri->extra && ri->extra->path_id) {
      kv = json_pack("{sI}", "as_path_id", ri->extra->path_id);
      json_object_update_missing(obj, kv);
      json_decref(kv);
    }

    aspath = attr->aspath ? attr->aspath->str : empty;
    kv = json_pack("{ss}", "as_path", aspath);
    json_object_update_missing(obj, kv);
    json_decref(kv);

    if (attr->community) {
      kv = json_pack("{ss}", "comms", attr->community->str);
      json_object_update_missing(obj, kv);
      json_decref(kv);
    }

    if (attr->ecommunity) {
      kv = json_pack("{ss}", "ecomms", attr->ecommunity->str);
      json_object_update_missing(obj, kv);
      json_decref(kv);
    }

    kv = json_pack("{sI}", "origin", attr->origin);
    json_object_update_missing(obj, kv);
    json_decref(kv);

    kv = json_pack("{sI}", "local_pref", attr->local_pref);
    json_object_update_missing(obj, kv);
    json_decref(kv);

    if (attr->med) {
      kv = json_pack("{sI}", "med", attr->med);
      json_object_update_missing(obj, kv);
      json_decref(kv);
    }

    if (safi == SAFI_MPLS_VPN) {
      u_char rd_str[SRVBUFLEN];

      bgp_rd2str(rd_str, &ri->extra->rd);
      kv = json_pack("{ss}", "rd", rd_str);
      json_object_update_missing(obj, kv);
      json_decref(kv);
    }

    if (config.nfacctd_bgp_msglog_file || config.bgp_table_dump_file)
      write_and_free_json(peer->log->fd, obj);

#ifdef WITH_RABBITMQ
    if (config.nfacctd_bgp_msglog_amqp_routing_key ||
	config.bgp_table_dump_amqp_routing_key) {
      amqp_ret = write_and_free_json_amqp(peer->log->amqp_host, obj);
      p_amqp_unset_routing_key(peer->log->amqp_host);
    }
#endif
#endif
  }

  return (ret | amqp_ret);
}

int bgp_peer_log_init(struct bgp_peer *peer, int output)
{
  int peer_idx, have_it, ret = 0, amqp_ret = 0;
  char log_filename[SRVBUFLEN], event_type[] = "log_init";

  if (!peers_log || !peer || peer->log) return;

  if (config.nfacctd_bgp_msglog_file)
    bgp_peer_log_dynname(log_filename, SRVBUFLEN, config.nfacctd_bgp_msglog_file, peer); 

  if (config.nfacctd_bgp_msglog_amqp_routing_key) {
    bgp_peer_log_dynname(log_filename, SRVBUFLEN, config.nfacctd_bgp_msglog_amqp_routing_key, peer); 
  }

  for (peer_idx = 0, have_it = 0; peer_idx < config.nfacctd_bgp_max_peers; peer_idx++) {
    if (!peers_log[peer_idx].refcnt) {
      if (config.nfacctd_bgp_msglog_file)
	peers_log[peer_idx].fd = open_logfile(log_filename, "a");

#ifdef WITH_RABBITMQ
      if (config.nfacctd_bgp_msglog_amqp_routing_key)
        peers_log[peer_idx].amqp_host = &bgp_daemon_msglog_amqp_host;
#endif
      
      strcpy(peers_log[peer_idx].filename, log_filename);
      have_it = TRUE;
      break;
    }
    else if (!strcmp(log_filename, peers_log[peer_idx].filename)) {
      have_it = TRUE;
      break;
    }
  }

  if (have_it) {
    peer->log = &peers_log[peer_idx];
    peers_log[peer_idx].refcnt++;

#ifdef WITH_RABBITMQ
    if (config.nfacctd_bgp_msglog_amqp_routing_key)
      p_amqp_set_routing_key(peer->log->amqp_host, peer->log->filename);

    if (config.nfacctd_bgp_msglog_amqp_routing_key_rr && !p_amqp_get_routing_key_rr(peer->log->amqp_host)) {
      p_amqp_init_routing_key_rr(peer->log->amqp_host);
      p_amqp_set_routing_key_rr(peer->log->amqp_host, config.nfacctd_bgp_msglog_amqp_routing_key_rr);
    }
#endif

    if (output == PRINT_OUTPUT_JSON) {
#ifdef WITH_JANSSON
      char ip_address[INET6_ADDRSTRLEN];
      json_t *obj = json_object(), *kv;

      kv = json_pack("{sI}", "seq", log_seq);
      json_object_update_missing(obj, kv);
      json_decref(kv);
      bgp_peer_log_seq_increment();

      kv = json_pack("{ss}", "timestamp", log_tstamp_str);
      json_object_update_missing(obj, kv);
      json_decref(kv);

      addr_to_str(ip_address, &peer->addr);
      kv = json_pack("{ss}", "peer_ip_src", ip_address);
      json_object_update_missing(obj, kv);
      json_decref(kv);

      kv = json_pack("{ss}", "event_type", event_type);
      json_object_update_missing(obj, kv);
      json_decref(kv);

      if (config.nfacctd_bgp_msglog_file)
	write_and_free_json(peer->log->fd, obj);

#ifdef WITH_RABBITMQ
      if (config.nfacctd_bgp_msglog_amqp_routing_key) {
	amqp_ret = write_and_free_json_amqp(peer->log->amqp_host, obj); 
	p_amqp_unset_routing_key(peer->log->amqp_host);
      }
#endif
#endif
    }
  }

  return (ret | amqp_ret);
}

int bgp_peer_log_close(struct bgp_peer *peer, int output)
{
  char event_type[] = "log_close";
  struct bgp_peer_log *log_ptr;
  void *amqp_log_ptr;
  int ret = 0, amqp_ret = 0;;

  if (!peers_log || !peer || !peer->log) return;

#ifdef WITH_RABBITMQ
  if (config.nfacctd_bgp_msglog_amqp_routing_key)
    p_amqp_set_routing_key(peer->log->amqp_host, peer->log->filename);
#endif

  log_ptr = peer->log;
  amqp_log_ptr = peer->log->amqp_host;

  assert(peer->log->refcnt);
  peer->log->refcnt--;
  peer->log = NULL;

  if (output == PRINT_OUTPUT_JSON) {
#ifdef WITH_JANSSON
    char ip_address[INET6_ADDRSTRLEN];
    json_t *obj = json_object(), *kv;

    kv = json_pack("{sI}", "seq", log_seq);
    json_object_update_missing(obj, kv);
    json_decref(kv);
    bgp_peer_log_seq_increment();

    kv = json_pack("{ss}", "timestamp", log_tstamp_str);
    json_object_update_missing(obj, kv);
    json_decref(kv);

    addr_to_str(ip_address, &peer->addr);
    kv = json_pack("{ss}", "peer_ip_src", ip_address);
    json_object_update_missing(obj, kv);
    json_decref(kv);

    kv = json_pack("{ss}", "event_type", event_type);
    json_object_update_missing(obj, kv);
    json_decref(kv);

    if (config.nfacctd_bgp_msglog_file)
      write_and_free_json(log_ptr->fd, obj);

#ifdef WITH_RABBITMQ
    if (config.nfacctd_bgp_msglog_amqp_routing_key) {
      amqp_ret = write_and_free_json_amqp(amqp_log_ptr, obj);
      p_amqp_unset_routing_key(amqp_log_ptr);
    }
#endif
#endif
  }

  if (!log_ptr->refcnt) {
    if (config.nfacctd_bgp_msglog_file && !log_ptr->refcnt) {
      fclose(log_ptr->fd);
      memset(log_ptr, 0, sizeof(struct bgp_peer_log));
    }
  }

  return (ret | amqp_ret);
}

void bgp_peer_log_seq_init()
{
  log_seq = 0;
}

void bgp_peer_log_seq_increment()
{
  /* Jansson does not support unsigned 64 bit integers, let's wrap at 2^63-1 */
  if (log_seq == INT64T_THRESHOLD) log_seq = 0;
  else log_seq++;
}

void bgp_peer_log_dynname(char *new, int newlen, char *old, struct bgp_peer *peer)
{
  int oldlen;
  char psi_string[] = "$peer_src_ip";
  char *ptr_start, *ptr_end;

  if (!new || !old || !peer) return;

  oldlen = strlen(old);
  if (oldlen <= newlen) strcpy(new, old);

  ptr_start = strstr(new, psi_string);
  if (ptr_start) {
    char empty_peer_src_ip[] = "null";
    char peer_src_ip[SRVBUFLEN];
    char buf[newlen];
    int len, howmany;

    len = strlen(ptr_start);
    ptr_end = ptr_start;
    ptr_end += strlen(psi_string);
    len -= strlen(psi_string);

    if (peer->addr.family) addr_to_str(peer_src_ip, &peer->addr);
    else strlcpy(peer_src_ip, empty_peer_src_ip, strlen(empty_peer_src_ip));

    escape_ip_uscores(peer_src_ip);
    snprintf(buf, newlen, "%s", peer_src_ip);
    strncat(buf, ptr_end, len);

    len = strlen(buf);
    *ptr_start = '\0';
    strncat(new, buf, len);
  }
}

int bgp_peer_dump_init(struct bgp_peer *peer, int output)
{
  char event_type[] = "dump_init";
  int ret = 0, amqp_ret = 0;

  if (!peer || !peer->log) return;

#ifdef WITH_RABBITMQ
  if (config.bgp_table_dump_amqp_routing_key)
    p_amqp_set_routing_key(peer->log->amqp_host, peer->log->filename);

  if (config.bgp_table_dump_amqp_routing_key_rr && !p_amqp_get_routing_key_rr(peer->log->amqp_host)) {
    p_amqp_init_routing_key_rr(peer->log->amqp_host);
    p_amqp_set_routing_key_rr(peer->log->amqp_host, config.bgp_table_dump_amqp_routing_key_rr);
  }
#endif

  if (output == PRINT_OUTPUT_JSON) {
#ifdef WITH_JANSSON
    char ip_address[INET6_ADDRSTRLEN];
    json_t *obj = json_object(), *kv;

    kv = json_pack("{ss}", "timestamp", log_tstamp_str);
    json_object_update_missing(obj, kv);
    json_decref(kv);

    addr_to_str(ip_address, &peer->addr);
    kv = json_pack("{ss}", "peer_ip_src", ip_address);
    json_object_update_missing(obj, kv);
    json_decref(kv);

    kv = json_pack("{ss}", "event_type", event_type);
    json_object_update_missing(obj, kv);
    json_decref(kv);

    if (config.bgp_table_dump_file)
      write_and_free_json(peer->log->fd, obj);

#ifdef WITH_RABBITMQ
    if (config.bgp_table_dump_amqp_routing_key) {
      amqp_ret = write_and_free_json_amqp(peer->log->amqp_host, obj);
      p_amqp_unset_routing_key(peer->log->amqp_host);
    }
#endif
#endif
  }

  return (ret | amqp_ret);
}

int bgp_peer_dump_close(struct bgp_peer *peer, int output)
{
  char event_type[] = "dump_close";
  int ret = 0, amqp_ret = 0;

  if (!peer || !peer->log) return;

#ifdef WITH_RABBITMQ
  if (config.bgp_table_dump_amqp_routing_key)
    p_amqp_set_routing_key(peer->log->amqp_host, peer->log->filename);
#endif

  if (output == PRINT_OUTPUT_JSON) {
#ifdef WITH_JANSSON
    char ip_address[INET6_ADDRSTRLEN];
    json_t *obj = json_object(), *kv;

    kv = json_pack("{ss}", "timestamp", log_tstamp_str);
    json_object_update_missing(obj, kv);
    json_decref(kv);

    addr_to_str(ip_address, &peer->addr);
    kv = json_pack("{ss}", "peer_ip_src", ip_address);
    json_object_update_missing(obj, kv);
    json_decref(kv);

    kv = json_pack("{ss}", "event_type", event_type);
    json_object_update_missing(obj, kv);
    json_decref(kv);

    if (config.bgp_table_dump_file)
      write_and_free_json(peer->log->fd, obj);

#ifdef WITH_RABBITMQ
    if (config.bgp_table_dump_amqp_routing_key) {
      amqp_ret = write_and_free_json_amqp(peer->log->amqp_host, obj);
      p_amqp_unset_routing_key(peer->log->amqp_host);
    }
#endif
#endif
  }

  return (ret | amqp_ret);
}

void bgp_handle_dump_event()
{
  char current_filename[SRVBUFLEN], last_filename[SRVBUFLEN], tmpbuf[SRVBUFLEN];
  char event_type[] = "dump";
  int ret, peers_idx, duration, tables_num;
  struct bgp_peer *peer, *saved_peer;
  struct bgp_table *table;
  struct bgp_node *node;
  struct bgp_peer_log peer_log;
  afi_t afi;
  safi_t safi;
  pid_t dumper_pid;
  time_t start;

  /* pre-flight check */
  if ((!config.bgp_table_dump_file && !config.bgp_table_dump_amqp_routing_key) ||
      !config.bgp_table_dump_refresh_time)
    return;

  switch (ret = fork()) {
  case 0: /* Child */
    /* we have to ignore signals to avoid loops: because we are already forked */
    signal(SIGINT, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    pm_setproctitle("%s %s [%s]", config.type, "Core Process -- BGP Dump Writer", config.name);
    memset(last_filename, 0, sizeof(last_filename));
    memset(current_filename, 0, sizeof(current_filename));
    memset(&peer_log, 0, sizeof(struct bgp_peer_log));

#ifdef WITH_RABBITMQ
    if (config.bgp_table_dump_amqp_routing_key) {
      bgp_table_dump_init_amqp_host();
      ret = p_amqp_connect(&bgp_table_dump_amqp_host);
      if (ret) exit(ret);
    }
#endif

    dumper_pid = getpid();
    Log(LOG_INFO, "INFO ( %s/core/BGP ): *** Dumping BGP tables - START (PID: %u) ***\n", config.name, dumper_pid);
    start = time(NULL);
    tables_num = 0;

    for (peer = NULL, saved_peer = NULL, peers_idx = 0; peers_idx < config.nfacctd_bgp_max_peers; peers_idx++) {
      if (peers[peers_idx].fd) {
        peer = &peers[peers_idx];
	peer->log = &peer_log; /* abusing struct bgp_peer a bit, but we are in a child */

	if (config.bgp_table_dump_file)
	  bgp_peer_log_dynname(current_filename, SRVBUFLEN, config.bgp_table_dump_file, peer);

	if (config.bgp_table_dump_amqp_routing_key)
	  bgp_peer_log_dynname(current_filename, SRVBUFLEN, config.bgp_table_dump_amqp_routing_key, peer);

	strftime_same(current_filename, SRVBUFLEN, tmpbuf, &log_tstamp.tv_sec);

	/*
	   we close last_filename and open current_filename in case they differ;
	   we are safe with this approach until $peer_src_ip is the only variable
	   supported as part of bgp_table_dump_file configuration directive.
        */
	if (config.bgp_table_dump_file) {
	  if (strcmp(last_filename, current_filename)) {
	    if (saved_peer && saved_peer->log && strlen(last_filename)) fclose(saved_peer->log->fd);
	    peer->log->fd = open_logfile(current_filename, "w");
	  }
	}

#ifdef WITH_RABBITMQ
	/*
	   a bit pedantic maybe but should come at little cost and emulating
	   bgp_table_dump_file behaviour will work
	*/ 
	if (config.bgp_table_dump_amqp_routing_key) {
	  peer->log->amqp_host = &bgp_table_dump_amqp_host;
	  strcpy(peer->log->filename, current_filename);
	}
#endif

	bgp_peer_dump_init(peer, config.bgp_table_dump_output);

	for (afi = AFI_IP; afi < AFI_MAX; afi++) {
	  for (safi = SAFI_UNICAST; safi < SAFI_MAX; safi++) {
	    table = rib[afi][safi];
	    node = bgp_table_top(table);

	    while (node) {
	      u_int32_t modulo = bgp_route_info_modulo(peer, NULL);
	      u_int32_t peer_buckets;
	      struct bgp_info *ri;

	      for (peer_buckets = 0; peer_buckets < config.bgp_table_per_peer_buckets; peer_buckets++) {
	        for (ri = node->info[modulo+peer_buckets]; ri; ri = ri->next) {
		  if (ri->peer == peer) {
	            bgp_peer_log_msg(node, ri, safi, event_type, config.bgp_table_dump_output);
		  }
		}
	      }

	      node = bgp_route_next(node);
	    }
	  }
	}

        saved_peer = peer;
        strlcpy(last_filename, current_filename, SRVBUFLEN);
        bgp_peer_dump_close(peer, config.bgp_table_dump_output);
	tables_num++;
      }
    }

#ifdef WITH_RABBITMQ
    if (config.bgp_table_dump_amqp_routing_key)
      p_amqp_close(&bgp_table_dump_amqp_host, FALSE);
#endif

    duration = time(NULL)-start;
    Log(LOG_INFO, "INFO ( %s/core/BGP ): *** Dumping BGP tables - END (PID: %u, TABLES: %u ET: %u) ***\n",
		config.name, dumper_pid, tables_num, duration);

    exit(0);
  default: /* Parent */
    if (ret == -1) { /* Something went wrong */
      Log(LOG_WARNING, "WARN ( %s/core/BGP ): Unable to fork BGP table dump writer: %s\n", config.name, strerror(errno));
    }

    break;
  }
}

#if defined WITH_RABBITMQ
void bgp_daemon_msglog_init_amqp_host()
{
  p_amqp_init_host(&bgp_daemon_msglog_amqp_host);

  if (!config.nfacctd_bgp_msglog_amqp_user) config.nfacctd_bgp_msglog_amqp_user = rabbitmq_user;
  if (!config.nfacctd_bgp_msglog_amqp_passwd) config.nfacctd_bgp_msglog_amqp_passwd = rabbitmq_pwd;
  if (!config.nfacctd_bgp_msglog_amqp_exchange) config.nfacctd_bgp_msglog_amqp_exchange = default_amqp_exchange;
  if (!config.nfacctd_bgp_msglog_amqp_exchange_type) config.nfacctd_bgp_msglog_amqp_exchange_type = default_amqp_exchange_type;
  if (!config.nfacctd_bgp_msglog_amqp_host) config.nfacctd_bgp_msglog_amqp_host = default_amqp_host;
  if (!config.nfacctd_bgp_msglog_amqp_vhost) config.nfacctd_bgp_msglog_amqp_vhost = default_amqp_vhost;

  p_amqp_set_user(&bgp_daemon_msglog_amqp_host, config.nfacctd_bgp_msglog_amqp_user);
  p_amqp_set_passwd(&bgp_daemon_msglog_amqp_host, config.nfacctd_bgp_msglog_amqp_passwd);
  p_amqp_set_exchange(&bgp_daemon_msglog_amqp_host, config.nfacctd_bgp_msglog_amqp_exchange);
  p_amqp_set_exchange_type(&bgp_daemon_msglog_amqp_host, config.nfacctd_bgp_msglog_amqp_exchange_type);
  p_amqp_set_host(&bgp_daemon_msglog_amqp_host, config.nfacctd_bgp_msglog_amqp_host);
  p_amqp_set_vhost(&bgp_daemon_msglog_amqp_host, config.nfacctd_bgp_msglog_amqp_vhost);
  p_amqp_set_persistent_msg(&bgp_daemon_msglog_amqp_host, config.nfacctd_bgp_msglog_amqp_persistent_msg);
  p_amqp_set_frame_max(&bgp_daemon_msglog_amqp_host, config.nfacctd_bgp_msglog_amqp_frame_max);
  p_amqp_set_heartbeat_interval(&bgp_daemon_msglog_amqp_host, config.nfacctd_bgp_msglog_amqp_heartbeat_interval);
}
#else
void bgp_daemon_msglog_init_amqp_host()
{
}
#endif

#if defined WITH_RABBITMQ
void bgp_table_dump_init_amqp_host()
{
  p_amqp_init_host(&bgp_table_dump_amqp_host);

  if (!config.bgp_table_dump_amqp_user) config.bgp_table_dump_amqp_user = rabbitmq_user;
  if (!config.bgp_table_dump_amqp_passwd) config.bgp_table_dump_amqp_passwd = rabbitmq_pwd;
  if (!config.bgp_table_dump_amqp_exchange) config.bgp_table_dump_amqp_exchange = default_amqp_exchange;
  if (!config.bgp_table_dump_amqp_exchange_type) config.bgp_table_dump_amqp_exchange_type = default_amqp_exchange_type;
  if (!config.bgp_table_dump_amqp_host) config.bgp_table_dump_amqp_host = default_amqp_host;
  if (!config.bgp_table_dump_amqp_vhost) config.bgp_table_dump_amqp_vhost = default_amqp_vhost;

  p_amqp_set_user(&bgp_table_dump_amqp_host, config.bgp_table_dump_amqp_user);
  p_amqp_set_passwd(&bgp_table_dump_amqp_host, config.bgp_table_dump_amqp_passwd);
  p_amqp_set_exchange(&bgp_table_dump_amqp_host, config.bgp_table_dump_amqp_exchange);
  p_amqp_set_exchange_type(&bgp_table_dump_amqp_host, config.bgp_table_dump_amqp_exchange_type);
  p_amqp_set_host(&bgp_table_dump_amqp_host, config.bgp_table_dump_amqp_host);
  p_amqp_set_vhost(&bgp_table_dump_amqp_host, config.bgp_table_dump_amqp_vhost);
  p_amqp_set_persistent_msg(&bgp_table_dump_amqp_host, config.bgp_table_dump_amqp_persistent_msg);
  p_amqp_set_frame_max(&bgp_table_dump_amqp_host, config.bgp_table_dump_amqp_frame_max);
  p_amqp_set_heartbeat_interval(&bgp_table_dump_amqp_host, config.bgp_table_dump_amqp_heartbeat_interval);
}
#else
void bgp_table_dump_init_amqp_host()
{
}
#endif
