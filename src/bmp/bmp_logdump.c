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
#define __BMP_LOGDUMP_C

/* includes */
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

int bmp_log_msg(struct bgp_peer *peer, struct bmp_data *bdata, void *log_data, u_int64_t log_seq, char *event_type, int output, int log_type)
{
  struct bgp_misc_structs *bms = bgp_select_misc_db(FUNC_TYPE_BMP);
  int ret = 0, amqp_ret = 0, kafka_ret = 0, etype = BGP_LOGDUMP_ET_NONE;
  pid_t writer_pid = getpid();

  if (!bms || !peer || !peer->log || !bdata || !event_type) return ERR;

  if (!strcmp(event_type, "dump")) etype = BGP_LOGDUMP_ET_DUMP;
  else if (!strcmp(event_type, "log")) etype = BGP_LOGDUMP_ET_LOG;

#ifdef WITH_RABBITMQ
  if ((config.nfacctd_bmp_msglog_amqp_routing_key && etype == BGP_LOGDUMP_ET_LOG) ||
      (config.bmp_dump_amqp_routing_key && etype == BGP_LOGDUMP_ET_DUMP))
    p_amqp_set_routing_key(peer->log->amqp_host, peer->log->filename);
#endif

#ifdef WITH_KAFKA
  if ((config.nfacctd_bmp_msglog_kafka_topic && etype == BGP_LOGDUMP_ET_LOG) ||
      (config.bmp_dump_kafka_topic && etype == BGP_LOGDUMP_ET_DUMP))
    p_kafka_set_topic(peer->log->kafka_host, peer->log->filename);
#endif

  if (output == PRINT_OUTPUT_JSON) {
#ifdef WITH_JANSSON
    json_t *obj = json_object();
    char tstamp_str[SRVBUFLEN];

    json_object_set_new_nocheck(obj, "event_type", json_string(event_type));

    json_object_set_new_nocheck(obj, "seq", json_integer((json_int_t)log_seq));

    if (etype == BGP_LOGDUMP_ET_LOG) {
      compose_timestamp(tstamp_str, SRVBUFLEN, &bdata->tstamp, TRUE, config.timestamps_since_epoch);
      json_object_set_new_nocheck(obj, "timestamp", json_string(tstamp_str));
    }
    else if (etype == BGP_LOGDUMP_ET_DUMP) {
      json_object_set_new_nocheck(obj, "timestamp", json_string(bms->dump.tstamp_str));

      compose_timestamp(tstamp_str, SRVBUFLEN, &bdata->tstamp, TRUE, config.timestamps_since_epoch);
      json_object_set_new_nocheck(obj, "event_timestamp", json_string(tstamp_str));
    }

    json_object_set_new_nocheck(obj, "bmp_router", json_string(peer->addr_str));

    json_object_set_new_nocheck(obj, "bmp_router_port", json_integer((json_int_t)peer->tcp_port));

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
      add_writer_name_and_pid_json(obj, config.proc_name, writer_pid);
      amqp_ret = write_and_free_json_amqp(peer->log->amqp_host, obj);
      p_amqp_unset_routing_key(peer->log->amqp_host);
    }
#endif

#ifdef WITH_KAFKA
    if ((config.nfacctd_bmp_msglog_kafka_topic && etype == BGP_LOGDUMP_ET_LOG) ||
        (config.bmp_dump_kafka_topic && etype == BGP_LOGDUMP_ET_DUMP)) {
      add_writer_name_and_pid_json(obj, config.proc_name, writer_pid);
      kafka_ret = write_and_free_json_kafka(peer->log->kafka_host, obj);
      p_kafka_unset_topic(peer->log->kafka_host);
    }
#endif
#endif
  }

  return (ret | amqp_ret | kafka_ret);
}

int bmp_log_msg_stats(struct bgp_peer *peer, struct bmp_data *bdata, struct bmp_log_stats *blstats, char *event_type, int output, void *vobj)
{
  char bmp_msg_type[] = "stats";
  int ret = 0;
#ifdef WITH_JANSSON
  char ip_address[INET6_ADDRSTRLEN];
  json_t *obj = (json_t *) vobj;

  if (!peer || !bdata || !blstats || !vobj) return ERR;

  json_object_set_new_nocheck(obj, "bmp_msg_type", json_string(bmp_msg_type));

  addr_to_str(ip_address, &bdata->peer_ip);
  json_object_set_new_nocheck(obj, "peer_ip", json_string(ip_address));

  json_object_set_new_nocheck(obj, "peer_asn", json_integer((json_int_t)bdata->peer_asn));

  json_object_set_new_nocheck(obj, "peer_type", json_integer((json_int_t)bdata->peer_type));

  json_object_set_new_nocheck(obj, "is_post", json_integer((json_int_t)bdata->is_post));

  json_object_set_new_nocheck(obj, "counter_type", json_integer((json_int_t)blstats->cnt_type));

  if (blstats->cnt_type <= BMP_STATS_MAX)
    json_object_set_new_nocheck(obj, "counter_type_str", json_string(bmp_stats_cnt_types[blstats->cnt_type]));
  else
    json_object_set_new_nocheck(obj, "counter_type_str", json_string("Unknown"));

  if (blstats->got_data) json_object_set_new_nocheck(obj, "counter_value", json_integer((json_int_t)blstats->cnt_data));
#endif

  return ret;
}

int bmp_log_msg_init(struct bgp_peer *peer, struct bmp_data *bdata, struct bmp_log_init *blinit, char *event_type, int output, void *vobj)
{
  char bmp_msg_type[] = "init";
  int ret = 0;
#ifdef WITH_JANSSON
  json_t *obj = (json_t *) vobj;

  if (!peer || !vobj) return ERR;

  json_object_set_new_nocheck(obj, "bmp_msg_type", json_string(bmp_msg_type));

  if (blinit) {
    json_object_set_new_nocheck(obj, "bmp_init_data_type", json_integer((json_int_t)blinit->type));

    json_object_set_new_nocheck(obj, "bmp_init_data_len", json_integer((json_int_t)blinit->len));

    if (blinit->type == BMP_INIT_INFO_STRING || blinit->type == BMP_INIT_INFO_SYSDESCR || blinit->type == BMP_INIT_INFO_SYSNAME)
      json_object_set_new_nocheck(obj, "bmp_init_data_val", json_string(blinit->val));
  }
#endif

  return ret;
}

int bmp_log_msg_term(struct bgp_peer *peer, struct bmp_data *bdata, struct bmp_log_term *blterm, char *event_type, int output, void *vobj)
{
  char bmp_msg_type[] = "term";
  int ret = 0;
#ifdef WITH_JANSSON
  json_t *obj = (json_t *) vobj;

  if (!peer || !vobj) return ERR;

  json_object_set_new_nocheck(obj, "bmp_msg_type", json_string(bmp_msg_type));

  if (blterm) {
    json_object_set_new_nocheck(obj, "bmp_term_data_type", json_integer((json_int_t)blterm->type));

    json_object_set_new_nocheck(obj, "bmp_term_data_len", json_integer((json_int_t)blterm->len));

    if (blterm->type == BMP_TERM_INFO_STRING)
      json_object_set_new_nocheck(obj, "bmp_term_data_val_str", json_string(blterm->val));
    else if (blterm->type == BMP_TERM_INFO_REASON) {
      json_object_set_new_nocheck(obj, "bmp_term_data_val_reas_type", json_integer((json_int_t)blterm->reas_type));

      if (blterm->reas_type <= BMP_TERM_REASON_MAX)
	json_object_set_new_nocheck(obj, "bmp_term_data_val_reas_str", json_string(bmp_term_reason_types[blterm->reas_type]));
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
  json_t *obj = (json_t *) vobj;

  if (!peer || !bdata || !blpu || !vobj) return ERR;

  json_object_set_new_nocheck(obj, "bmp_msg_type", json_string(bmp_msg_type));

  addr_to_str(ip_address, &bdata->peer_ip);
  json_object_set_new_nocheck(obj, "peer_ip", json_string(ip_address));

  json_object_set_new_nocheck(obj, "peer_asn", json_integer((json_int_t)bdata->peer_asn));

  json_object_set_new_nocheck(obj, "peer_type", json_integer((json_int_t)bdata->peer_type));

  json_object_set_new_nocheck(obj, "is_post", json_integer((json_int_t)bdata->is_post));

  json_object_set_new_nocheck(obj, "bgp_id", json_string(inet_ntoa(bdata->bgp_id.address.ipv4)));

  json_object_set_new_nocheck(obj, "local_port", json_integer((json_int_t)blpu->loc_port));

  json_object_set_new_nocheck(obj, "remote_port", json_integer((json_int_t)blpu->rem_port));

  addr_to_str(ip_address, &blpu->local_ip);
  json_object_set_new_nocheck(obj, "local_ip", json_string(ip_address));
#endif

  return ret;
}

int bmp_log_msg_peer_down(struct bgp_peer *peer, struct bmp_data *bdata, struct bmp_log_peer_down *blpd, char *event_type, int output, void *vobj)
{
  char bmp_msg_type[] = "peer_down";
  int ret = 0;
#ifdef WITH_JANSSON
  char ip_address[INET6_ADDRSTRLEN];
  json_t *obj = (json_t *) vobj;

  if (!peer || !bdata || !blpd || !vobj) return ERR;

  json_object_set_new_nocheck(obj, "bmp_msg_type", json_string(bmp_msg_type));

  addr_to_str(ip_address, &bdata->peer_ip);
  json_object_set_new_nocheck(obj, "peer_ip", json_string(ip_address));

  json_object_set_new_nocheck(obj, "peer_asn", json_integer((json_int_t)bdata->peer_asn));

  json_object_set_new_nocheck(obj, "peer_type", json_integer((json_int_t)bdata->peer_type));

  json_object_set_new_nocheck(obj, "is_post", json_integer((json_int_t)bdata->is_post));

  json_object_set_new_nocheck(obj, "reason_type", json_integer((json_int_t)blpd->reason));

  if (blpd->reason == BMP_PEER_DOWN_LOC_CODE)
    json_object_set_new_nocheck(obj, "reason_loc_code", json_integer((json_int_t)blpd->loc_code));
#endif

  return ret;
}

void bmp_dump_init_peer(struct bgp_peer *peer)
{
  struct bgp_misc_structs *bms;

  if (!peer) return;

  bms = bgp_select_misc_db(peer->type);

  if (!bms) return;

  assert(!peer->bmp_se);

  peer->bmp_se = malloc(sizeof(struct bmp_dump_se_ll));
  if (!peer->bmp_se) {
    Log(LOG_ERR, "ERROR ( %s/%s ): Unable to malloc() bmp_se structure. Terminating thread.\n", config.name, bms->log_str);
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
  struct bgp_misc_structs *bms = bgp_select_misc_db(FUNC_TYPE_BMP);
  struct bmp_dump_se_ll *se_ll;
  struct bmp_dump_se_ll_elem *se_ll_elem;

  if (!peer) return;

  assert(peer->bmp_se);

  se_ll_elem = malloc(sizeof(struct bmp_dump_se_ll_elem));
  if (!se_ll_elem) {
    Log(LOG_ERR, "ERROR ( %s/%s ): Unable to malloc() se_ll_elem structure. Terminating thread.\n", config.name, bms->log_str);
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

  se_ll_elem->rec.seq = bms->log_seq;;
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
  struct bgp_misc_structs *bms = bgp_select_misc_db(FUNC_TYPE_BMP);
  char current_filename[SRVBUFLEN], last_filename[SRVBUFLEN], tmpbuf[SRVBUFLEN];
  char latest_filename[SRVBUFLEN], event_type[] = "dump", *fd_buf = NULL;
  int ret, peers_idx, duration, tables_num;
  struct bgp_rt_structs *inter_domain_routing_db;
  struct bgp_table *table;
  struct bgp_node *node;
  afi_t afi;
  safi_t safi;
  pid_t dumper_pid;
  time_t start;
  u_int64_t dump_elems;

  struct bgp_peer *peer, *saved_peer;
  struct bmp_peer *bmpp, *saved_bmpp;
  struct bmp_dump_se_ll *bdsell;
  struct bgp_peer_log peer_log;      

  /* pre-flight check */
  if (!bms->dump_backend_methods || !config.bmp_dump_refresh_time)
    return;

  switch (ret = fork()) {
  case 0: /* Child */
    /* we have to ignore signals to avoid loops: because we are already forked */
    signal(SIGINT, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    pm_setproctitle("%s %s [%s]", config.type, "Core Process -- BMP Dump Writer", config.name);

    memset(last_filename, 0, sizeof(last_filename));
    memset(current_filename, 0, sizeof(current_filename));
    fd_buf = malloc(OUTPUT_FILE_BUFSZ);

#ifdef WITH_RABBITMQ
    if (config.bmp_dump_amqp_routing_key) {
      bmp_dump_init_amqp_host();
      ret = p_amqp_connect_to_publish(&bmp_dump_amqp_host);
      if (ret) exit(ret);
    }
#endif

#ifdef WITH_KAFKA
    if (config.bmp_dump_kafka_topic) {
      ret = bmp_dump_init_kafka_host();
      if (ret) exit(ret);
    }
#endif

    dumper_pid = getpid();
    Log(LOG_INFO, "INFO ( %s/%s ): *** Dumping BMP tables - START (PID: %u) ***\n", config.name, bms->log_str, dumper_pid);
    start = time(NULL);
    tables_num = 0;

    for (peer = NULL, saved_peer = NULL, peers_idx = 0; peers_idx < config.nfacctd_bmp_max_peers; peers_idx++) {
      if (bmp_peers[peers_idx].self.fd) {
        peer = &bmp_peers[peers_idx].self;
        bmpp = &bmp_peers[peers_idx];
        peer->log = &peer_log; /* abusing struct bgp_peer a bit, but we are in a child */
	bdsell = peer->bmp_se;

        if (config.bmp_dump_file) bgp_peer_log_dynname(current_filename, SRVBUFLEN, config.bmp_dump_file, peer);
        if (config.bmp_dump_amqp_routing_key) bgp_peer_log_dynname(current_filename, SRVBUFLEN, config.bmp_dump_amqp_routing_key, peer);
        if (config.bmp_dump_kafka_topic) bgp_peer_log_dynname(current_filename, SRVBUFLEN, config.bmp_dump_kafka_topic, peer);

        strftime_same(current_filename, SRVBUFLEN, tmpbuf, &bms->dump.tstamp.tv_sec);

        /*
	  we close last_filename and open current_filename in case they differ;
	  we are safe with this approach until $peer_src_ip is the only variable
	  supported as part of bmp_dump_file configuration directive.
	*/
        if (config.bmp_dump_file) {
          if (strcmp(last_filename, current_filename)) {
	    if (saved_peer && saved_peer->log && strlen(last_filename)) {
	      close_output_file(saved_peer->log->fd);

	      if (config.bmp_dump_latest_file) {
	        bgp_peer_log_dynname(latest_filename, SRVBUFLEN, config.bmp_dump_latest_file, saved_peer);
	        link_latest_output_file(latest_filename, last_filename);
	      }
	    }
            peer->log->fd = open_output_file(current_filename, "w", TRUE);
            if (fd_buf) {
              if (setvbuf(peer->log->fd, fd_buf, _IOFBF, OUTPUT_FILE_BUFSZ))
		Log(LOG_WARNING, "WARN ( %s/%s ): [%s] setvbuf() failed: %s\n", config.name, bms->log_str, current_filename, errno);
              else memset(fd_buf, 0, OUTPUT_FILE_BUFSZ);
            }
          }
        }

        /*
          a bit pedantic maybe but should come at little cost and emulating
          bmp_dump_file behaviour will work
        */
#ifdef WITH_RABBITMQ
        if (config.bmp_dump_amqp_routing_key) {
          peer->log->amqp_host = &bmp_dump_amqp_host;
          strcpy(peer->log->filename, current_filename);
        }
#endif

#ifdef WITH_KAFKA
        if (config.bmp_dump_kafka_topic) {
          peer->log->kafka_host = &bmp_dump_kafka_host;
          strcpy(peer->log->filename, current_filename);
        }
#endif

	bgp_peer_dump_init(peer, config.bmp_dump_output, FUNC_TYPE_BMP);
	inter_domain_routing_db = bgp_select_routing_db(FUNC_TYPE_BMP);
        dump_elems = 0;

        if (!inter_domain_routing_db) return;

        for (afi = AFI_IP; afi < AFI_MAX; afi++) {
          for (safi = SAFI_UNICAST; safi < SAFI_MAX; safi++) {
            table = inter_domain_routing_db->rib[afi][safi];
            node = bgp_table_top(peer, table);

            while (node) {
              u_int32_t modulo = bms->route_info_modulo(peer, NULL, bms->table_per_peer_buckets);
              u_int32_t peer_buckets;
              struct bgp_info *ri;

              for (peer_buckets = 0; peer_buckets < config.bmp_table_per_peer_buckets; peer_buckets++) {
                for (ri = node->info[modulo+peer_buckets]; ri; ri = ri->next) {
		  struct bmp_peer *local_bmpp = ri->peer->bmp_se;

                  if (local_bmpp && (&local_bmpp->self == peer)) {
		    char peer_str[] = "peer_ip", *saved_peer_str = bms->peer_str;

		    ri->peer->log = peer->log;
		    bms->peer_str = peer_str;
                    bgp_peer_log_msg(node, ri, afi, safi, event_type, config.bmp_dump_output, BGP_LOG_TYPE_MISC);
		    bms->peer_str = saved_peer_str;
                    dump_elems++;
                  }
                }
              }

              node = bgp_route_next(peer, node);
	    }
	  }
	}

	if (bdsell && bdsell->start) {
	  struct bmp_dump_se_ll_elem *se_ll_elem;
	  char event_type[] = "dump";

	  for (se_ll_elem = bdsell->start; se_ll_elem; se_ll_elem = se_ll_elem->next) {
	    switch (se_ll_elem->rec.se_type) {
	    case BMP_LOG_TYPE_STATS:
	      bmp_log_msg(peer, &se_ll_elem->rec.bdata, &se_ll_elem->rec.se.stats, se_ll_elem->rec.seq, event_type, config.bmp_dump_output, BMP_LOG_TYPE_STATS);
	      break;
	    case BMP_LOG_TYPE_INIT:
	      bmp_log_msg(peer, &se_ll_elem->rec.bdata, &se_ll_elem->rec.se.init, se_ll_elem->rec.seq, event_type, config.bmp_dump_output, BMP_LOG_TYPE_INIT);
	      break;
	    case BMP_LOG_TYPE_TERM:
	      bmp_log_msg(peer, &se_ll_elem->rec.bdata, &se_ll_elem->rec.se.term, se_ll_elem->rec.seq, event_type, config.bmp_dump_output, BMP_LOG_TYPE_TERM);
	      break;
	    case BMP_LOG_TYPE_PEER_UP:
	      bmp_log_msg(peer, &se_ll_elem->rec.bdata, &se_ll_elem->rec.se.peer_up, se_ll_elem->rec.seq, event_type, config.bmp_dump_output, BMP_LOG_TYPE_PEER_UP);
	      break;
	    case BMP_LOG_TYPE_PEER_DOWN:
	      bmp_log_msg(peer, &se_ll_elem->rec.bdata, &se_ll_elem->rec.se.peer_down, se_ll_elem->rec.seq, event_type, config.bmp_dump_output, BMP_LOG_TYPE_PEER_DOWN);
	      break;
	    default:
	      break;
	    }
	  }
	}
 
	saved_peer = peer;
	saved_bmpp = bmpp;
        strlcpy(last_filename, current_filename, SRVBUFLEN);
        bgp_peer_dump_close(peer, NULL, config.bmp_dump_output, FUNC_TYPE_BMP);
        tables_num++;
      }
    }

#ifdef WITH_RABBITMQ
    if (config.bmp_dump_amqp_routing_key)
      p_amqp_close(&bmp_dump_amqp_host, FALSE);
#endif

#ifdef WITH_KAFKA
    if (config.bmp_dump_kafka_topic)
      p_kafka_close(&bmp_dump_kafka_host, FALSE);
#endif

    if (config.bmp_dump_latest_file && peer) {
      bgp_peer_log_dynname(latest_filename, SRVBUFLEN, config.bmp_dump_latest_file, peer);
      link_latest_output_file(latest_filename, last_filename);
    }

    duration = time(NULL)-start;
    Log(LOG_INFO, "INFO ( %s/%s ): *** Dumping BMP tables - END (PID: %u, TABLES: %u ET: %u) ***\n",
                config.name, bms->log_str, dumper_pid, tables_num, duration);

    exit(0);
  default: /* Parent */
    if (ret == -1) { /* Something went wrong */
      Log(LOG_WARNING, "WARN ( %s/%s ): Unable to fork BMP table dump writer: %s\n",
		config.name, bms->log_str, strerror(errno));
    }

    /* destroy bmp_se linked-list content after dump event */
    for (peer = NULL, peers_idx = 0; peers_idx < config.nfacctd_bmp_max_peers; peers_idx++) {
      if (bmp_peers[peers_idx].self.fd) {
        peer = &bmp_peers[peers_idx].self;
        bmpp = &bmp_peers[peers_idx];
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
  P_broker_timers_set_retry_interval(&bmp_daemon_msglog_amqp_host.btimers, config.nfacctd_bmp_msglog_amqp_retry);
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

#if defined WITH_KAFKA
int bmp_daemon_msglog_init_kafka_host()
{
  int ret;

  p_kafka_init_host(&bmp_daemon_msglog_kafka_host, config.nfacctd_bmp_msglog_kafka_config_file);
  ret = p_kafka_connect_to_produce(&bmp_daemon_msglog_kafka_host);

  if (!config.nfacctd_bmp_msglog_kafka_broker_host) config.nfacctd_bmp_msglog_kafka_broker_host = default_kafka_broker_host;
  if (!config.nfacctd_bmp_msglog_kafka_broker_port) config.nfacctd_bmp_msglog_kafka_broker_port = default_kafka_broker_port;
  if (!config.nfacctd_bmp_msglog_kafka_retry) config.nfacctd_bmp_msglog_kafka_retry = PM_KAFKA_DEFAULT_RETRY;

  p_kafka_set_broker(&bmp_daemon_msglog_kafka_host, config.nfacctd_bmp_msglog_kafka_broker_host, config.nfacctd_bmp_msglog_kafka_broker_port);
  p_kafka_set_topic(&bmp_daemon_msglog_kafka_host, config.nfacctd_bmp_msglog_kafka_topic);
  p_kafka_set_partition(&bmp_daemon_msglog_kafka_host, config.nfacctd_bmp_msglog_kafka_partition);
  p_kafka_set_key(&bmp_daemon_msglog_kafka_host, config.nfacctd_bmp_msglog_kafka_partition_key, config.nfacctd_bmp_msglog_kafka_partition_keylen);
  p_kafka_set_content_type(&bmp_daemon_msglog_kafka_host, PM_KAFKA_CNT_TYPE_STR);
  P_broker_timers_set_retry_interval(&bmp_daemon_msglog_kafka_host.btimers, config.nfacctd_bmp_msglog_kafka_retry);

  return ret;
}
#else
int bmp_daemon_msglog_init_kafka_host()
{
  return ERR;
}
#endif

#if defined WITH_KAFKA
int bmp_dump_init_kafka_host()
{
  int ret;

  p_kafka_init_host(&bmp_dump_kafka_host, config.bmp_dump_kafka_config_file);
  ret = p_kafka_connect_to_produce(&bmp_dump_kafka_host);

  if (!config.bmp_dump_kafka_broker_host) config.bmp_dump_kafka_broker_host = default_kafka_broker_host;
  if (!config.bmp_dump_kafka_broker_port) config.bmp_dump_kafka_broker_port = default_kafka_broker_port;

  p_kafka_set_broker(&bmp_dump_kafka_host, config.bmp_dump_kafka_broker_host, config.bmp_dump_kafka_broker_port);
  p_kafka_set_topic(&bmp_dump_kafka_host, config.bmp_dump_kafka_topic);
  p_kafka_set_partition(&bmp_dump_kafka_host, config.bmp_dump_kafka_partition);
  p_kafka_set_key(&bmp_dump_kafka_host, config.bmp_dump_kafka_partition_key, config.bmp_dump_kafka_partition_keylen);
  p_kafka_set_content_type(&bmp_dump_kafka_host, PM_KAFKA_CNT_TYPE_STR);

  return ret;
}
#else
int bmp_dump_init_kafka_host()
{
  return ERR;
}
#endif
