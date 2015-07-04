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
#define __BMP_LOGDUMP_C

/* includes */
/* includes */
#include "pmacct.h"
#include "../bgp/bgp.h"
#include "bmp.h"
#if defined WITH_RABBITMQ
#include "amqp_common.h"
#endif
#ifdef WITH_JANSSON
#include <jansson.h>
#endif

int bmp_log_msg(struct bgp_peer *peer, struct bmp_data *bdata, void *log_data, char *event_type, int output, int log_type)
{
  int ret = 0, amqp_ret = 0, etype = BGP_LOGDUMP_ET_NONE;

  if (!peer || !bdata || !event_type) return ret;

  if (!strcmp(event_type, "dump")) etype = BGP_LOGDUMP_ET_DUMP;
  else if (!strcmp(event_type, "log")) etype = BGP_LOGDUMP_ET_LOG;

#ifdef WITH_RABBITMQ
  if ((config.nfacctd_bmp_msglog_amqp_routing_key && etype == BGP_LOGDUMP_ET_LOG) ||
      (config.bmp_dump_amqp_routing_key && etype == BGP_LOGDUMP_ET_DUMP))
    p_amqp_set_routing_key(peer->log->amqp_host, peer->log->filename);
#endif

  if (output == PRINT_OUTPUT_JSON) {
#ifdef WITH_JANSSON
    json_t *obj = json_object(), *kv;
    char tstamp_str[SRVBUFLEN];

    kv = json_pack("{ss}", "event_type", event_type);
    json_object_update_missing(obj, kv);
    json_decref(kv);

    /* no need for seq for "dump" event_type */
    if (etype == BGP_LOGDUMP_ET_LOG) {
      kv = json_pack("{sI}", "seq", bmp_log_seq);
      json_object_update_missing(obj, kv);
      json_decref(kv);
      bgp_peer_log_seq_increment(&bmp_log_seq);
    }

    compose_timestamp(tstamp_str, SRVBUFLEN, &bdata->tstamp, TRUE, config.sql_history_since_epoch);
    kv = json_pack("{ss}", "timestamp", tstamp_str);
    json_object_update_missing(obj, kv);
    json_decref(kv);

    kv = json_pack("{ss}", "bmp_router", peer->addr_str);
    json_object_update_missing(obj, kv);
    json_decref(kv);

    switch (log_type) {
    case BMP_LOG_TYPE_STATS:
      ret = bmp_log_msg_stats(peer, bdata, (struct bmp_log_stats *) log_data, event_type, output, obj);
      break;
    case BMP_LOG_TYPE_INIT:
      ret = bmp_log_msg_init(peer, bdata, (struct bmp_log_init *) log_data, event_type, output, obj);
      break;
    case BMP_LOG_TYPE_TERM:
      ret = bmp_log_msg_term(peer, bdata, (struct bmp_log_term *) log_data, event_type, output, obj);
      break;
    case BMP_LOG_TYPE_PEER_UP:
      ret = bmp_log_msg_peer_up(peer, bdata, (struct bmp_log_peer_up *) log_data, event_type, output, obj);
      break;
    case BMP_LOG_TYPE_PEER_DOWN:
      ret = bmp_log_msg_peer_down(peer, bdata, (struct bmp_log_peer_down *) log_data, event_type, output, obj);
      break;
    default:
      break;
    }

    if ((config.nfacctd_bmp_msglog_file && etype == BGP_LOGDUMP_ET_LOG) ||
	(config.bmp_dump_file && etype == BGP_LOGDUMP_ET_DUMP))
      write_and_free_json(peer->log->fd, obj);

#ifdef WITH_RABBITMQ
    if ((config.nfacctd_bmp_msglog_amqp_routing_key && etype == BGP_LOGDUMP_ET_LOG) ||
	(config.bmp_dump_amqp_routing_key && etype == BGP_LOGDUMP_ET_DUMP)) {
      amqp_ret = write_and_free_json_amqp(peer->log->amqp_host, obj);
      p_amqp_unset_routing_key(peer->log->amqp_host);
    }
#endif
#endif
  }

  return ret;
}

int bmp_log_msg_stats(struct bgp_peer *peer, struct bmp_data *bdata, struct bmp_log_stats *blstats, char *event_type, int output, void *vobj)
{
  char bmp_msg_type[] = "stats";
  int ret = 0;
#ifdef WITH_JANSSON
  char ip_address[INET6_ADDRSTRLEN];
  json_t *obj = (json_t *) vobj, *kv;

  if (!peer || !bdata || !blstats || !vobj) return ret;

  kv = json_pack("{ss}", "bmp_msg_type", bmp_msg_type);
  json_object_update_missing(obj, kv);
  json_decref(kv);

  addr_to_str(ip_address, &bdata->peer_ip);
  kv = json_pack("{ss}", "peer_ip", ip_address);
  json_object_update_missing(obj, kv);
  json_decref(kv);

  kv = json_pack("{sI}", "peer_asn", bdata->peer_asn);
  json_object_update_missing(obj, kv);
  json_decref(kv);

  kv = json_pack("{sI}", "peer_type", bdata->peer_type);
  json_object_update_missing(obj, kv);
  json_decref(kv);

  kv = json_pack("{sI}", "counter_type", blstats->cnt_type);
  json_object_update_missing(obj, kv);
  json_decref(kv);

  if (blstats->cnt_type <= BMP_STATS_MAX) {
    kv = json_pack("{ss}", "counter_type_str", bmp_stats_cnt_types[blstats->cnt_type]);
    json_object_update_missing(obj, kv);
    json_decref(kv);
  }
  else {
    kv = json_pack("{ss}", "counter_type_str", "Unknown");
    json_object_update_missing(obj, kv);
    json_decref(kv);
  }

  if (blstats->got_data) {
    kv = json_pack("{sI}", "counter_value", blstats->cnt_data);
    json_object_update_missing(obj, kv);
    json_decref(kv);
  }
#endif

  return ret;
}

int bmp_log_msg_init(struct bgp_peer *peer, struct bmp_data *bdata, struct bmp_log_init *blinit, char *event_type, int output, void *vobj)
{
  char bmp_msg_type[] = "init";
  int ret = 0;
#ifdef WITH_JANSSON
  json_t *obj = (json_t *) vobj, *kv;

  if (!peer || !vobj) return ret;

  kv = json_pack("{ss}", "bmp_msg_type", bmp_msg_type);
  json_object_update_missing(obj, kv);
  json_decref(kv);

  if (blinit) {
    kv = json_pack("{sI}", "bmp_init_data_type", blinit->type);
    json_object_update_missing(obj, kv);
    json_decref(kv);

    kv = json_pack("{sI}", "bmp_init_data_len", blinit->len);
    json_object_update_missing(obj, kv);
    json_decref(kv);

    if (blinit->type == BMP_INIT_INFO_STRING || blinit->type == BMP_INIT_INFO_SYSDESCR || blinit->type == BMP_INIT_INFO_SYSNAME) {
      kv = json_pack("{ss}", "bmp_init_data_val", blinit->val);
      json_object_update_missing(obj, kv);
      json_decref(kv);
    }
  }
#endif

  return ret;
}

int bmp_log_msg_term(struct bgp_peer *peer, struct bmp_data *bdata, struct bmp_log_term *blterm, char *event_type, int output, void *vobj)
{
  char bmp_msg_type[] = "term";
  int ret = 0;
#ifdef WITH_JANSSON
  json_t *obj = (json_t *) vobj, *kv;

  if (!peer || !vobj) return ret;

  kv = json_pack("{ss}", "bmp_msg_type", bmp_msg_type);
  json_object_update_missing(obj, kv);
  json_decref(kv);

  if (blterm) {
    kv = json_pack("{sI}", "bmp_term_data_type", blterm->type);
    json_object_update_missing(obj, kv);
    json_decref(kv);

    kv = json_pack("{sI}", "bmp_term_data_len", blterm->len);
    json_object_update_missing(obj, kv);
    json_decref(kv);

    if (blterm->type == BMP_TERM_INFO_STRING) {
      kv = json_pack("{ss}", "bmp_term_data_val_str", blterm->val);
      json_object_update_missing(obj, kv);
      json_decref(kv);
    }
    else if (blterm->type == BMP_TERM_INFO_REASON) {
      kv = json_pack("{sI}", "bmp_term_data_val_reas_type", blterm->reas_type);
      json_object_update_missing(obj, kv);
      json_decref(kv);

      if (blterm->reas_type <= BMP_TERM_REASON_MAX) {
        kv = json_pack("{ss}", "bmp_term_data_val_reas_str", bmp_term_reason_types[blterm->reas_type]);
        json_object_update_missing(obj, kv);
        json_decref(kv);
      }
    }
  }
#endif

  return ret;
}

int bmp_log_msg_peer_up(struct bgp_peer *peer, struct bmp_data *bdata, struct bmp_log_peer_up *blpu, char *event_type, int output, void *vobj)
{
  char bmp_msg_type[] = "peer_up";
  int ret = 0;
#ifdef WITH_JANSSON
  char ip_address[INET6_ADDRSTRLEN];
  json_t *obj = (json_t *) vobj, *kv;

  if (!peer || !bdata || !blpu || !vobj) return ret;

  kv = json_pack("{ss}", "bmp_msg_type", bmp_msg_type);
  json_object_update_missing(obj, kv);
  json_decref(kv);

  addr_to_str(ip_address, &bdata->peer_ip);
  kv = json_pack("{ss}", "peer_ip", ip_address);
  json_object_update_missing(obj, kv);
  json_decref(kv);

  kv = json_pack("{sI}", "peer_asn", bdata->peer_asn);
  json_object_update_missing(obj, kv);
  json_decref(kv);

  kv = json_pack("{sI}", "peer_type", bdata->peer_type);
  json_object_update_missing(obj, kv);
  json_decref(kv);

  kv = json_pack("{ss}", "bgp_id", inet_ntoa(bdata->bgp_id.address.ipv4));
  json_object_update_missing(obj, kv);
  json_decref(kv);

  kv = json_pack("{sI}", "local_port", blpu->loc_port);
  json_object_update_missing(obj, kv);
  json_decref(kv);

  kv = json_pack("{sI}", "remote_port", blpu->rem_port);
  json_object_update_missing(obj, kv);
  json_decref(kv);

  addr_to_str(ip_address, &blpu->local_ip);
  kv = json_pack("{ss}", "local_ip", ip_address);
  json_object_update_missing(obj, kv);
  json_decref(kv);
#endif

  return ret;
}

int bmp_log_msg_peer_down(struct bgp_peer *peer, struct bmp_data *bdata, struct bmp_log_peer_down *blpd, char *event_type, int output, void *vobj)
{
  char bmp_msg_type[] = "peer_down";
  int ret = 0;
#ifdef WITH_JANSSON
  char ip_address[INET6_ADDRSTRLEN];
  json_t *obj = (json_t *) vobj, *kv;

  if (!peer || !bdata || !blpd || !vobj) return ret;

  kv = json_pack("{ss}", "bmp_msg_type", bmp_msg_type);
  json_object_update_missing(obj, kv);
  json_decref(kv);

  addr_to_str(ip_address, &bdata->peer_ip);
  kv = json_pack("{ss}", "peer_ip", ip_address);
  json_object_update_missing(obj, kv);
  json_decref(kv);

  kv = json_pack("{sI}", "peer_asn", bdata->peer_asn);
  json_object_update_missing(obj, kv);
  json_decref(kv);

  kv = json_pack("{sI}", "peer_type", bdata->peer_type);
  json_object_update_missing(obj, kv);
  json_decref(kv);

  kv = json_pack("{sI}", "reason_type", blpd->reason);
  json_object_update_missing(obj, kv);
  json_decref(kv);

  if (blpd->reason == BMP_PEER_DOWN_LOC_CODE) {
    kv = json_pack("{sI}", "reason_loc_code", blpd->loc_code);
    json_object_update_missing(obj, kv);
    json_decref(kv);
  }
#endif

  return ret;
}

void bmp_dump_init_peer(struct bgp_peer *peer)
{
  if (!peer) return;

  assert(!peer->bmp_se);

  peer->bmp_se = malloc(sizeof(struct bmp_dump_se_ll));
  if (!peer->bmp_se) {
    Log(LOG_ERR, "ERROR ( %s/core/BMP ): Unable to malloc() bmp_se structure. Terminating thread.\n", config.name);
    exit_all(1);
  }

  memset(peer->bmp_se, 0, sizeof(struct bmp_dump_se_ll));
}

void bmp_dump_close_peer(struct bgp_peer *peer)
{
  struct bmp_dump_se_ll *bdsell;

  if (!peer) return;

  bdsell = (struct bmp_dump_se_ll *) peer->bmp_se;

  if (bdsell && bdsell->start) bmp_dump_se_ll_destroy(bdsell);
 
  free(peer->bmp_se);
  peer->bmp_se = NULL;
}

void bmp_dump_se_ll_append(struct bgp_peer *peer, struct bmp_data *bdata, void *extra, int log_type)
{
  struct bmp_dump_se_ll *se_ll;
  struct bmp_dump_se_ll_elem *se_ll_elem;

  if (!peer) return;

  assert(peer->bmp_se);

  se_ll_elem = malloc(sizeof(struct bmp_dump_se_ll_elem));
  if (!se_ll_elem) {
    Log(LOG_ERR, "ERROR ( %s/core/BMP ): Unable to malloc() se_ll_elem structure. Terminating thread.\n", config.name);
    exit_all(1);
  }

  memset(se_ll_elem, 0, sizeof(struct bmp_dump_se_ll_elem));

  if (bdata) memcpy(&se_ll_elem->rec.bdata, bdata, sizeof(struct bmp_data));
  if (extra && log_type) {
    switch (log_type) {
    case BMP_LOG_TYPE_STATS:
      memcpy(&se_ll_elem->rec.se.stats, extra, sizeof(struct bmp_log_stats));
      break;
    case BMP_LOG_TYPE_INIT:
      memcpy(&se_ll_elem->rec.se.init, extra, sizeof(struct bmp_log_init));
      break;
    case BMP_LOG_TYPE_TERM:
      memcpy(&se_ll_elem->rec.se.term, extra, sizeof(struct bmp_log_term));
      break;
    case BMP_LOG_TYPE_PEER_UP:
      memcpy(&se_ll_elem->rec.se.peer_up, extra, sizeof(struct bmp_log_peer_up));
      break;
    case BMP_LOG_TYPE_PEER_DOWN:
      memcpy(&se_ll_elem->rec.se.peer_down, extra, sizeof(struct bmp_log_peer_down));
      break;
    default:
      break;
    }
  }

  se_ll_elem->rec.se_type = log_type;
  se_ll_elem->next = NULL; /* pedantic */

  se_ll = (struct bmp_dump_se_ll *) peer->bmp_se;

  /* append to an empty ll */
  if (!se_ll->start) {
    assert(!se_ll->last);

    se_ll->start = se_ll_elem;
    se_ll->last = se_ll_elem;
  }
  /* append to an existing ll */
  else {
    assert(se_ll->last);

    se_ll->last->next = se_ll_elem;
    se_ll->last = se_ll_elem;
  }
}

void bmp_dump_se_ll_destroy(struct bmp_dump_se_ll *bdsell)
{
  struct bmp_dump_se_ll_elem *se_ll_elem, *se_ll_elem_next;

  if (!bdsell) return;

  if (!bdsell->start) return;

  assert(bdsell->last);
  for (se_ll_elem = bdsell->start; se_ll_elem; se_ll_elem = se_ll_elem_next) {
    se_ll_elem_next = se_ll_elem->next;
    free(se_ll_elem);
  }

  bdsell->start = NULL;
  bdsell->last = NULL;
}

void bmp_handle_dump_event()
{
  char current_filename[SRVBUFLEN], last_filename[SRVBUFLEN], tmpbuf[SRVBUFLEN];
  char event_type[] = "dump";
  int ret, peers_idx, duration, tables_num;
  pid_t dumper_pid;
  time_t start;

  struct bgp_peer *peer, *saved_peer;
  struct bmp_dump_se_ll *bdsell;
  struct bgp_peer_log peer_log;      

  /* pre-flight check */
  if ((!config.bmp_dump_file && !config.bmp_dump_amqp_routing_key) || !config.bmp_dump_refresh_time)
    return;

  switch (ret = fork()) {
  case 0: /* Child */
    /* we have to ignore signals to avoid loops: because we are already forked */
    signal(SIGINT, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    pm_setproctitle("%s %s [%s]", config.type, "Core Process -- BMP Dump Writer", config.name);

    memset(last_filename, 0, sizeof(last_filename));
    memset(current_filename, 0, sizeof(current_filename));

#ifdef WITH_RABBITMQ
    if (config.bmp_dump_amqp_routing_key) {
      bmp_dump_init_amqp_host();
      ret = p_amqp_connect_to_publish(&bmp_dump_amqp_host);
      if (ret) exit(ret);
    }
#endif

    dumper_pid = getpid();
    Log(LOG_INFO, "INFO ( %s/core/BMP ): *** Dumping BMP tables - START (PID: %u) ***\n", config.name, dumper_pid);
    start = time(NULL);
    tables_num = 0;

    for (peer = NULL, saved_peer = NULL, peers_idx = 0; peers_idx < config.nfacctd_bmp_max_peers; peers_idx++) {
      if (bmp_peers[peers_idx].fd) {
        peer = &bmp_peers[peers_idx];
        peer->log = &peer_log; /* abusing struct bgp_peer a bit, but we are in a child */
	bdsell = peer->bmp_se;

        if (config.bmp_dump_file) bgp_peer_log_dynname(current_filename, SRVBUFLEN, config.bmp_dump_file, peer);
        if (config.bmp_dump_amqp_routing_key) bgp_peer_log_dynname(current_filename, SRVBUFLEN, config.bmp_dump_amqp_routing_key, peer);

        strftime_same(current_filename, SRVBUFLEN, tmpbuf, &bmp_log_tstamp.tv_sec);

        /*
	  we close last_filename and open current_filename in case they differ;
	  we are safe with this approach until $peer_src_ip is the only variable
	  supported as part of bgp_table_dump_file configuration directive.
	*/
        if (config.bmp_dump_file) {
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
        if (config.bmp_dump_amqp_routing_key) {
          peer->log->amqp_host = &bgp_table_dump_amqp_host;
          strcpy(peer->log->filename, current_filename);
        }
#endif

	bgp_peer_dump_init(peer, config.bmp_dump_output, FUNC_TYPE_BMP);

	if (bdsell && bdsell->start) {
	  struct bmp_dump_se_ll_elem *se_ll_elem;
	  char event_type[] = "dump";

	  for (se_ll_elem = bdsell->start; se_ll_elem; se_ll_elem = se_ll_elem->next) {
	    switch (se_ll_elem->rec.se_type) {
	    case BMP_LOG_TYPE_STATS:
	      bmp_log_msg(peer, &se_ll_elem->rec.bdata, &se_ll_elem->rec.se.stats, event_type, config.bmp_dump_output, BMP_LOG_TYPE_STATS);
	      break;
	    case BMP_LOG_TYPE_INIT:
	      bmp_log_msg(peer, &se_ll_elem->rec.bdata, &se_ll_elem->rec.se.init, event_type, config.bmp_dump_output, BMP_LOG_TYPE_INIT);
	      break;
	    case BMP_LOG_TYPE_TERM:
	      bmp_log_msg(peer, &se_ll_elem->rec.bdata, &se_ll_elem->rec.se.term, event_type, config.bmp_dump_output, BMP_LOG_TYPE_TERM);
	      break;
	    case BMP_LOG_TYPE_PEER_UP:
	      bmp_log_msg(peer, &se_ll_elem->rec.bdata, &se_ll_elem->rec.se.peer_up, event_type, config.bmp_dump_output, BMP_LOG_TYPE_PEER_UP);
	      break;
	    case BMP_LOG_TYPE_PEER_DOWN:
	      bmp_log_msg(peer, &se_ll_elem->rec.bdata, &se_ll_elem->rec.se.peer_down, event_type, config.bmp_dump_output, BMP_LOG_TYPE_PEER_DOWN);
	      break;
	    default:
	      break;
	    }
	  }
	}
 
	saved_peer = peer;
        strlcpy(last_filename, current_filename, SRVBUFLEN);
        bgp_peer_dump_close(peer, NULL, config.bmp_dump_output, FUNC_TYPE_BMP);
        tables_num++;
      }
    }

#ifdef WITH_RABBITMQ
    if (config.bmp_dump_amqp_routing_key)
      p_amqp_close(&bmp_dump_amqp_host, FALSE);
#endif

    duration = time(NULL)-start;
    Log(LOG_INFO, "INFO ( %s/core/BMP ): *** Dumping BMP tables - END (PID: %u, TABLES: %u ET: %u) ***\n",
                config.name, dumper_pid, tables_num, duration);

    exit(0);
  default: /* Parent */
    if (ret == -1) { /* Something went wrong */
      Log(LOG_WARNING, "WARN ( %s/core/BMP ): Unable to fork BMP table dump writer: %s\n", config.name, strerror(errno));
    }

    /* destroy bmp_se linked-list content after dump event */
    for (peer = NULL, peers_idx = 0; peers_idx < config.nfacctd_bmp_max_peers; peers_idx++) {
      if (bmp_peers[peers_idx].fd) {
        peer = &bmp_peers[peers_idx];
        bdsell = peer->bmp_se;

	if (bdsell && bdsell->start) bmp_dump_se_ll_destroy(bdsell);
      }
    }

    break;
  }
}

#if defined WITH_RABBITMQ
void bmp_daemon_msglog_init_amqp_host()
{
  p_amqp_init_host(&bmp_daemon_msglog_amqp_host);

  if (!config.nfacctd_bmp_msglog_amqp_user) config.nfacctd_bmp_msglog_amqp_user = rabbitmq_user;
  if (!config.nfacctd_bmp_msglog_amqp_passwd) config.nfacctd_bmp_msglog_amqp_passwd = rabbitmq_pwd;
  if (!config.nfacctd_bmp_msglog_amqp_exchange) config.nfacctd_bmp_msglog_amqp_exchange = default_amqp_exchange;
  if (!config.nfacctd_bmp_msglog_amqp_exchange_type) config.nfacctd_bmp_msglog_amqp_exchange_type = default_amqp_exchange_type;
  if (!config.nfacctd_bmp_msglog_amqp_host) config.nfacctd_bmp_msglog_amqp_host = default_amqp_host;
  if (!config.nfacctd_bmp_msglog_amqp_vhost) config.nfacctd_bmp_msglog_amqp_vhost = default_amqp_vhost;
  if (!config.nfacctd_bmp_msglog_amqp_retry) config.nfacctd_bmp_msglog_amqp_retry = AMQP_DEFAULT_RETRY;

  p_amqp_set_user(&bmp_daemon_msglog_amqp_host, config.nfacctd_bmp_msglog_amqp_user);
  p_amqp_set_passwd(&bmp_daemon_msglog_amqp_host, config.nfacctd_bmp_msglog_amqp_passwd);
  p_amqp_set_exchange(&bmp_daemon_msglog_amqp_host, config.nfacctd_bmp_msglog_amqp_exchange);
  p_amqp_set_exchange_type(&bmp_daemon_msglog_amqp_host, config.nfacctd_bmp_msglog_amqp_exchange_type);
  p_amqp_set_host(&bmp_daemon_msglog_amqp_host, config.nfacctd_bmp_msglog_amqp_host);
  p_amqp_set_vhost(&bmp_daemon_msglog_amqp_host, config.nfacctd_bmp_msglog_amqp_vhost);
  p_amqp_set_persistent_msg(&bmp_daemon_msglog_amqp_host, config.nfacctd_bmp_msglog_amqp_persistent_msg);
  p_amqp_set_frame_max(&bmp_daemon_msglog_amqp_host, config.nfacctd_bmp_msglog_amqp_frame_max);
  p_amqp_set_content_type_json(&bmp_daemon_msglog_amqp_host);
  p_amqp_set_heartbeat_interval(&bmp_daemon_msglog_amqp_host, config.nfacctd_bmp_msglog_amqp_heartbeat_interval);
  p_amqp_set_retry_interval(&bmp_daemon_msglog_amqp_host, config.nfacctd_bmp_msglog_amqp_retry);
}
#else
void bmp_daemon_msglog_init_amqp_host()
{
}
#endif

#if defined WITH_RABBITMQ
void bmp_dump_init_amqp_host()
{
  p_amqp_init_host(&bmp_dump_amqp_host);

  if (!config.bmp_dump_amqp_user) config.bmp_dump_amqp_user = rabbitmq_user;
  if (!config.bmp_dump_amqp_passwd) config.bmp_dump_amqp_passwd = rabbitmq_pwd;
  if (!config.bmp_dump_amqp_exchange) config.bmp_dump_amqp_exchange = default_amqp_exchange;
  if (!config.bmp_dump_amqp_exchange_type) config.bmp_dump_amqp_exchange_type = default_amqp_exchange_type;
  if (!config.bmp_dump_amqp_host) config.bmp_dump_amqp_host = default_amqp_host;
  if (!config.bmp_dump_amqp_vhost) config.bmp_dump_amqp_vhost = default_amqp_vhost;

  p_amqp_set_user(&bmp_dump_amqp_host, config.bmp_dump_amqp_user);
  p_amqp_set_passwd(&bmp_dump_amqp_host, config.bmp_dump_amqp_passwd);
  p_amqp_set_exchange(&bmp_dump_amqp_host, config.bmp_dump_amqp_exchange);
  p_amqp_set_exchange_type(&bmp_dump_amqp_host, config.bmp_dump_amqp_exchange_type);
  p_amqp_set_host(&bmp_dump_amqp_host, config.bmp_dump_amqp_host);
  p_amqp_set_vhost(&bmp_dump_amqp_host, config.bmp_dump_amqp_vhost);
  p_amqp_set_persistent_msg(&bmp_dump_amqp_host, config.bmp_dump_amqp_persistent_msg);
  p_amqp_set_frame_max(&bmp_dump_amqp_host, config.bmp_dump_amqp_frame_max);
  p_amqp_set_content_type_json(&bmp_dump_amqp_host);
  p_amqp_set_heartbeat_interval(&bmp_dump_amqp_host, config.bmp_dump_amqp_heartbeat_interval);
}
#else
void bmp_dump_init_amqp_host()
{
}
#endif
