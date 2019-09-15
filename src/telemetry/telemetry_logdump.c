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
#include "bgp/bgp.h"
#include "bmp/bmp.h"
#include "telemetry.h"
#if defined WITH_RABBITMQ
#include "amqp_common.h"
#endif
#ifdef WITH_KAFKA
#include "kafka_common.h"
#endif

/* Functions */
int telemetry_log_msg(telemetry_peer *peer, struct telemetry_data *t_data, void *log_data, u_int32_t log_data_len,
			int data_decoder, u_int64_t log_seq, char *event_type, int output)
{
  telemetry_misc_structs *tms;
  int ret = 0, amqp_ret = 0, kafka_ret = 0, etype = TELEMETRY_LOGDUMP_ET_NONE;

#if defined (WITH_JANSSON) || defined (WITH_AVRO)
  pid_t writer_pid = getpid();
#endif

  if (!peer || !peer->log || !log_data || !log_data_len || !t_data || !event_type) return ERR;

  tms = bgp_select_misc_db(FUNC_TYPE_TELEMETRY);

  if (!tms) return ERR;

  if (!strcmp(event_type, "dump")) etype = TELEMETRY_LOGDUMP_ET_DUMP;
  else if (!strcmp(event_type, "log")) etype = TELEMETRY_LOGDUMP_ET_LOG;

  if ((config.telemetry_msglog_amqp_routing_key && etype == TELEMETRY_LOGDUMP_ET_LOG) ||
      (config.telemetry_dump_amqp_routing_key && etype == TELEMETRY_LOGDUMP_ET_DUMP)) {
#ifdef WITH_RABBITMQ
    p_amqp_set_routing_key(peer->log->amqp_host, peer->log->filename);
#endif
  }

  if ((config.telemetry_msglog_kafka_topic && etype == TELEMETRY_LOGDUMP_ET_LOG) ||
      (config.telemetry_dump_kafka_topic && etype == TELEMETRY_LOGDUMP_ET_DUMP)) {
#ifdef WITH_KAFKA
    p_kafka_set_topic(peer->log->kafka_host, peer->log->filename);
#endif
  }

  if (output == PRINT_OUTPUT_JSON) {
#ifdef WITH_JANSSON
    u_char *base64_tdata = NULL;
    size_t base64_tdata_len = 0;
    json_t *obj = json_object();

    json_object_set_new_nocheck(obj, "event_type", json_string(event_type));

    if (etype == BGP_LOGDUMP_ET_LOG) {
      json_object_set_new_nocheck(obj, "seq", json_integer((json_int_t)log_seq));

      json_object_set_new_nocheck(obj, "timestamp", json_string(tms->log_tstamp_str));
    }
    else if (etype == BGP_LOGDUMP_ET_DUMP) {
      json_object_set_new_nocheck(obj, "seq", json_integer((json_int_t) telemetry_log_seq_get(&tms->log_seq)));

      json_object_set_new_nocheck(obj, "timestamp", json_string(tms->dump.tstamp_str));
    }

    json_object_set_new_nocheck(obj, "telemetry_node", json_string(peer->addr_str));

    json_object_set_new_nocheck(obj, "telemetry_port", json_integer((json_int_t)peer->tcp_port));

    if (data_decoder == TELEMETRY_DATA_DECODER_JSON) {
      json_object_set_new_nocheck(obj, "telemetry_data", json_string(log_data));

      json_object_set_new_nocheck(obj, "serialization", json_string("json"));
    }
    else if (data_decoder == TELEMETRY_DATA_DECODER_GPB) {
      base64_tdata = base64_encode(log_data, log_data_len, &base64_tdata_len);

      if (base64_tdata) {
        json_object_set_new_nocheck(obj, "telemetry_data", json_string((char *)base64_tdata));
	base64_freebuf(base64_tdata);
        base64_tdata_len = 0;
      }
      else json_object_set_new_nocheck(obj, "telemetry_data", json_null());
           // XXX: kv = json_pack("{sn}", "telemetry_data");

      json_object_set_new_nocheck(obj, "serialization", json_string("gpb"));
    }
    else if (data_decoder == TELEMETRY_DATA_DECODER_UNKNOWN) {
      json_object_set_new_nocheck(obj, "serialization", json_string("unknown"));
    }

    if ((config.telemetry_msglog_file && etype == TELEMETRY_LOGDUMP_ET_LOG) ||
        (config.telemetry_dump_file && etype == TELEMETRY_LOGDUMP_ET_DUMP))
      write_and_free_json(peer->log->fd, obj);

    if ((config.telemetry_msglog_amqp_routing_key && etype == TELEMETRY_LOGDUMP_ET_LOG) ||
        (config.telemetry_dump_amqp_routing_key && etype == TELEMETRY_LOGDUMP_ET_DUMP)) {
      add_writer_name_and_pid_json(obj, config.proc_name, writer_pid);
#ifdef WITH_RABBITMQ
      amqp_ret = write_and_free_json_amqp(peer->log->amqp_host, obj);
      p_amqp_unset_routing_key(peer->log->amqp_host);
#endif
    }

    if ((config.telemetry_msglog_kafka_topic && etype == TELEMETRY_LOGDUMP_ET_LOG) ||
        (config.telemetry_dump_kafka_topic && etype == TELEMETRY_LOGDUMP_ET_DUMP)) {
      add_writer_name_and_pid_json(obj, config.proc_name, writer_pid);
#ifdef WITH_KAFKA
      kafka_ret = write_and_free_json_kafka(peer->log->kafka_host, obj);
      p_kafka_unset_topic(peer->log->kafka_host);
#endif
    }
#endif
  }

  return (ret | amqp_ret | kafka_ret);
}

void telemetry_dump_se_ll_append(telemetry_peer *peer, struct telemetry_data *t_data, int data_decoder)
{
  telemetry_misc_structs *tms;
  telemetry_dump_se_ll *se_ll;
  telemetry_dump_se_ll_elem *se_ll_elem;

  if (!peer) return;

  tms = bgp_select_misc_db(FUNC_TYPE_TELEMETRY);

  if (!tms) return;

  assert(peer->bmp_se);

  se_ll_elem = malloc(sizeof(telemetry_dump_se_ll_elem));
  if (!se_ll_elem) {
    Log(LOG_ERR, "ERROR ( %s/%s ): Unable to malloc() se_ll_elem structure. Terminating.\n", config.name, t_data->log_str);
    exit_gracefully(1);
  }

  memset(se_ll_elem, 0, sizeof(telemetry_dump_se_ll_elem));

  se_ll_elem->rec.data = malloc(peer->msglen);
  if (!se_ll_elem->rec.data) {
    Log(LOG_ERR, "ERROR ( %s/%s ): Unable to malloc() se_ll_elem->rec.data structure. Terminating.\n", config.name, t_data->log_str);
    exit_gracefully(1);
  }
  memcpy(se_ll_elem->rec.data, peer->buf.base, peer->msglen); 
  se_ll_elem->rec.len = peer->msglen;
  se_ll_elem->rec.decoder = data_decoder;
  se_ll_elem->rec.seq = telemetry_log_seq_get(&tms->log_seq);

  se_ll = (telemetry_dump_se_ll *) peer->bmp_se;

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

void telemetry_log_seq_init(u_int64_t *seq)
{
  bgp_peer_log_seq_init(seq);
}

void telemetry_log_seq_increment(u_int64_t *seq)
{
  bgp_peer_log_seq_increment(seq);
}

u_int64_t telemetry_log_seq_get(u_int64_t *seq)
{
  return bgp_peer_log_seq_get(seq);
}

void telemetry_log_seq_set(u_int64_t *seq, u_int64_t value)
{
  bgp_peer_log_seq_set(seq, value);
}

int telemetry_log_seq_has_ro_bit(u_int64_t *seq)
{
  return bgp_peer_log_seq_has_ro_bit(seq);
}

int telemetry_peer_log_init(telemetry_peer *peer, int output, int type)
{
  return bgp_peer_log_init(peer, output, type);
}

void telemetry_peer_log_dynname(char *new, int newlen, char *old, telemetry_peer *peer)
{
  bgp_peer_log_dynname(new, newlen, old, peer);
}

int telemetry_peer_dump_init(telemetry_peer *peer, int output, int type)
{
  return bgp_peer_dump_init(peer, output, type);
}

int telemetry_peer_dump_close(telemetry_peer *peer, int output, int type)
{
  return bgp_peer_dump_close(peer, NULL, output, type);
}

void telemetry_dump_init_peer(telemetry_peer *peer)
{
  bmp_dump_init_peer(peer);
}

void telemetry_dump_se_ll_destroy(telemetry_dump_se_ll *tdsell)
{
  telemetry_dump_se_ll_elem *se_ll_elem, *se_ll_elem_next;

  if (!tdsell) return;

  if (!tdsell->start) return;

  assert(tdsell->last);
  for (se_ll_elem = tdsell->start; se_ll_elem; se_ll_elem = se_ll_elem_next) {
    se_ll_elem_next = se_ll_elem->next;
    free(se_ll_elem->rec.data);
    free(se_ll_elem);
  }

  tdsell->start = NULL;
  tdsell->last = NULL;
}

void telemetry_handle_dump_event(struct telemetry_data *t_data)
{
  telemetry_misc_structs *tms = bgp_select_misc_db(FUNC_TYPE_TELEMETRY);
  char current_filename[SRVBUFLEN], last_filename[SRVBUFLEN], tmpbuf[SRVBUFLEN];
  char latest_filename[SRVBUFLEN], event_type[] = "dump", *fd_buf = NULL;
  (void)event_type;
  int ret, peers_idx, duration, tables_num;
  pid_t dumper_pid;
  time_t start;
  u_int64_t dump_elems = 0, dump_seqno;

  telemetry_peer *peer, *saved_peer;
  telemetry_dump_se_ll *tdsell;
  telemetry_peer_log peer_log;

  if (!tms) return;

  /* pre-flight check */
  if (!tms->dump_backend_methods || !config.telemetry_dump_refresh_time)
    return;

  /* Sequencing the dump event */
  dump_seqno = telemetry_log_seq_get(&tms->log_seq);
  telemetry_log_seq_increment(&tms->log_seq);

  switch (ret = fork()) {
  case 0: /* Child */
    /* we have to ignore signals to avoid loops: because we are already forked */
    signal(SIGINT, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    pm_setproctitle("%s %s [%s]", config.type, "Core Process -- Telemetry Dump Writer", config.name);
    config.is_forked = TRUE;

    memset(last_filename, 0, sizeof(last_filename));
    memset(current_filename, 0, sizeof(current_filename));

    fd_buf = malloc(OUTPUT_FILE_BUFSZ);
    telemetry_log_seq_set(&tms->log_seq, dump_seqno);

#ifdef WITH_RABBITMQ
    if (config.telemetry_dump_amqp_routing_key) {
      telemetry_dump_init_amqp_host();
      ret = p_amqp_connect_to_publish(&telemetry_dump_amqp_host);
      if (ret) exit_gracefully(ret);
    }
#endif

#ifdef WITH_KAFKA
    if (config.telemetry_dump_kafka_topic) {
      ret = telemetry_dump_init_kafka_host();
      if (ret) exit_gracefully(ret);
    }
#endif

    dumper_pid = getpid();
    Log(LOG_INFO, "INFO ( %s/%s ): *** Dumping telemetry data - START (PID: %u) ***\n", config.name, t_data->log_str, dumper_pid);
    start = time(NULL);
    tables_num = 0;

    for (peer = NULL, saved_peer = NULL, peers_idx = 0; peers_idx < config.telemetry_max_peers; peers_idx++) {
      if (telemetry_peers[peers_idx].fd) {
        peer = &telemetry_peers[peers_idx];
        peer->log = &peer_log; /* abusing telemetry_peer a bit, but we are in a child */
        tdsell = peer->bmp_se;

        if (config.telemetry_dump_file) telemetry_peer_log_dynname(current_filename, SRVBUFLEN, config.telemetry_dump_file, peer);
        if (config.telemetry_dump_amqp_routing_key) telemetry_peer_log_dynname(current_filename, SRVBUFLEN, config.telemetry_dump_amqp_routing_key, peer);
        if (config.telemetry_dump_kafka_topic) telemetry_peer_log_dynname(current_filename, SRVBUFLEN, config.telemetry_dump_kafka_topic, peer);

        pm_strftime_same(current_filename, SRVBUFLEN, tmpbuf, &tms->dump.tstamp.tv_sec, config.timestamps_utc);

        /*
	   we close last_filename and open current_filename in case they differ;
	   we are safe with this approach until time and Streaming Telemetry node
	   (IP, port) are the only variables supported as part of telemetry_dump_file.
        */
        if (config.telemetry_dump_file) {
          if (strcmp(last_filename, current_filename)) {
            if (saved_peer && saved_peer->log && strlen(last_filename)) {
              close_output_file(saved_peer->log->fd);

              if (config.telemetry_dump_latest_file) {
                telemetry_peer_log_dynname(latest_filename, SRVBUFLEN, config.telemetry_dump_latest_file, saved_peer);
                link_latest_output_file(latest_filename, last_filename);
              }
            }
            peer->log->fd = open_output_file(current_filename, "w", TRUE);
            if (fd_buf) {
              if (setvbuf(peer->log->fd, fd_buf, _IOFBF, OUTPUT_FILE_BUFSZ))
                Log(LOG_WARNING, "WARN ( %s/%s ): [%s] setvbuf() failed: %s\n", config.name, t_data->log_str, current_filename, strerror(errno));
              else memset(fd_buf, 0, OUTPUT_FILE_BUFSZ);
            }
          }
        }

        /*
          a bit pedantic maybe but should come at little cost and emulating
          telemetry_dump_file behaviour will work
        */
#ifdef WITH_RABBITMQ
        if (config.telemetry_dump_amqp_routing_key) {
          peer->log->amqp_host = &telemetry_dump_amqp_host;
          strcpy(peer->log->filename, current_filename);
        }
#endif

#ifdef WITH_KAFKA
        if (config.telemetry_dump_kafka_topic) {
          peer->log->kafka_host = &telemetry_dump_kafka_host;
          strcpy(peer->log->filename, current_filename);
        }
#endif

        telemetry_peer_dump_init(peer, config.telemetry_dump_output, FUNC_TYPE_TELEMETRY);
        dump_elems = 0;

	if (tdsell && tdsell->start) {
          telemetry_dump_se_ll_elem *se_ll_elem;
          char event_type[] = "dump";

	  for (se_ll_elem = tdsell->start; se_ll_elem; se_ll_elem = se_ll_elem->next) {
	    telemetry_log_msg(peer, t_data, se_ll_elem->rec.data, se_ll_elem->rec.len, se_ll_elem->rec.decoder,
				se_ll_elem->rec.seq, event_type, config.telemetry_dump_output);
	  }
	}

        saved_peer = peer;
        strlcpy(last_filename, current_filename, SRVBUFLEN);
        telemetry_peer_dump_close(peer, config.telemetry_dump_output, FUNC_TYPE_TELEMETRY);
        tables_num++;
      }
    }

#ifdef WITH_RABBITMQ
    if (config.telemetry_dump_amqp_routing_key)
      p_amqp_close(&telemetry_dump_amqp_host, FALSE);
#endif

#ifdef WITH_KAFKA
    if (config.telemetry_dump_kafka_topic)
      p_kafka_close(&telemetry_dump_kafka_host, FALSE);
#endif

    if (config.telemetry_dump_latest_file && peer) {
      telemetry_peer_log_dynname(latest_filename, SRVBUFLEN, config.telemetry_dump_latest_file, peer);
      link_latest_output_file(latest_filename, last_filename);
    }

    duration = time(NULL)-start;

    Log(LOG_INFO, "INFO ( %s/%s ): *** Dumping telemetry data - END (PID: %u, PEERS: %u ENTRIES: %" PRIu64 " ET: %u) ***\n",
                config.name, t_data->log_str, dumper_pid, tables_num, dump_elems, duration);

    exit_gracefully(0);
  default: /* Parent */
    if (ret == -1) { /* Something went wrong */
      Log(LOG_WARNING, "WARN ( %s/%s ): Unable to fork telemetry dump writer: %s\n", config.name, t_data->log_str, strerror(errno));
    }

    /* destroy bmp_se linked-list content after dump event */
    for (peer = NULL, peers_idx = 0; peers_idx < config.telemetry_max_peers; peers_idx++) {
      if (telemetry_peers[peers_idx].fd) {
        peer = &telemetry_peers[peers_idx];
        tdsell = peer->bmp_se;

        if (tdsell && tdsell->start) telemetry_dump_se_ll_destroy(tdsell);
      }
    }

    break;
  }
}

#if defined WITH_RABBITMQ
void telemetry_daemon_msglog_init_amqp_host()
{
  p_amqp_init_host(&telemetry_daemon_msglog_amqp_host);

  if (!config.telemetry_msglog_amqp_user) config.telemetry_msglog_amqp_user = rabbitmq_user;
  if (!config.telemetry_msglog_amqp_passwd) config.telemetry_msglog_amqp_passwd = rabbitmq_pwd;
  if (!config.telemetry_msglog_amqp_exchange) config.telemetry_msglog_amqp_exchange = default_amqp_exchange;
  if (!config.telemetry_msglog_amqp_exchange_type) config.telemetry_msglog_amqp_exchange_type = default_amqp_exchange_type;
  if (!config.telemetry_msglog_amqp_host) config.telemetry_msglog_amqp_host = default_amqp_host;
  if (!config.telemetry_msglog_amqp_vhost) config.telemetry_msglog_amqp_vhost = default_amqp_vhost;
  if (!config.telemetry_msglog_amqp_retry) config.telemetry_msglog_amqp_retry = AMQP_DEFAULT_RETRY;

  p_amqp_set_user(&telemetry_daemon_msglog_amqp_host, config.telemetry_msglog_amqp_user);
  p_amqp_set_passwd(&telemetry_daemon_msglog_amqp_host, config.telemetry_msglog_amqp_passwd);
  p_amqp_set_exchange(&telemetry_daemon_msglog_amqp_host, config.telemetry_msglog_amqp_exchange);
  p_amqp_set_exchange_type(&telemetry_daemon_msglog_amqp_host, config.telemetry_msglog_amqp_exchange_type);
  p_amqp_set_host(&telemetry_daemon_msglog_amqp_host, config.telemetry_msglog_amqp_host);
  p_amqp_set_vhost(&telemetry_daemon_msglog_amqp_host, config.telemetry_msglog_amqp_vhost);
  p_amqp_set_persistent_msg(&telemetry_daemon_msglog_amqp_host, config.telemetry_msglog_amqp_persistent_msg);
  p_amqp_set_frame_max(&telemetry_daemon_msglog_amqp_host, config.telemetry_msglog_amqp_frame_max);
  p_amqp_set_content_type_json(&telemetry_daemon_msglog_amqp_host);
  p_amqp_set_heartbeat_interval(&telemetry_daemon_msglog_amqp_host, config.telemetry_msglog_amqp_heartbeat_interval);
  P_broker_timers_set_retry_interval(&telemetry_daemon_msglog_amqp_host.btimers, config.telemetry_msglog_amqp_retry);
}
#else
void telemetry_daemon_msglog_init_amqp_host()
{
}
#endif

#if defined WITH_RABBITMQ
void telemetry_dump_init_amqp_host()
{
  p_amqp_init_host(&telemetry_dump_amqp_host);

  if (!config.telemetry_dump_amqp_user) config.telemetry_dump_amqp_user = rabbitmq_user;
  if (!config.telemetry_dump_amqp_passwd) config.telemetry_dump_amqp_passwd = rabbitmq_pwd;
  if (!config.telemetry_dump_amqp_exchange) config.telemetry_dump_amqp_exchange = default_amqp_exchange;
  if (!config.telemetry_dump_amqp_exchange_type) config.telemetry_dump_amqp_exchange_type = default_amqp_exchange_type;
  if (!config.telemetry_dump_amqp_host) config.telemetry_dump_amqp_host = default_amqp_host;
  if (!config.telemetry_dump_amqp_vhost) config.telemetry_dump_amqp_vhost = default_amqp_vhost;

  p_amqp_set_user(&telemetry_dump_amqp_host, config.telemetry_dump_amqp_user);
  p_amqp_set_passwd(&telemetry_dump_amqp_host, config.telemetry_dump_amqp_passwd);
  p_amqp_set_exchange(&telemetry_dump_amqp_host, config.telemetry_dump_amqp_exchange);
  p_amqp_set_exchange_type(&telemetry_dump_amqp_host, config.telemetry_dump_amqp_exchange_type);
  p_amqp_set_host(&telemetry_dump_amqp_host, config.telemetry_dump_amqp_host);
  p_amqp_set_vhost(&telemetry_dump_amqp_host, config.telemetry_dump_amqp_vhost);
  p_amqp_set_persistent_msg(&telemetry_dump_amqp_host, config.telemetry_dump_amqp_persistent_msg);
  p_amqp_set_frame_max(&telemetry_dump_amqp_host, config.telemetry_dump_amqp_frame_max);
  p_amqp_set_content_type_json(&telemetry_dump_amqp_host);
  p_amqp_set_heartbeat_interval(&telemetry_dump_amqp_host, config.telemetry_dump_amqp_heartbeat_interval);
}
#else
void telemetry_dump_init_amqp_host()
{
}
#endif

#if defined WITH_KAFKA
int telemetry_daemon_msglog_init_kafka_host()
{
  int ret;

  p_kafka_init_host(&telemetry_daemon_msglog_kafka_host, config.telemetry_msglog_kafka_config_file);
  ret = p_kafka_connect_to_produce(&telemetry_daemon_msglog_kafka_host);

  if (!config.telemetry_msglog_kafka_broker_host) config.telemetry_msglog_kafka_broker_host = default_kafka_broker_host;
  if (!config.telemetry_msglog_kafka_broker_port) config.telemetry_msglog_kafka_broker_port = default_kafka_broker_port;
  if (!config.telemetry_msglog_kafka_retry) config.telemetry_msglog_kafka_retry = PM_KAFKA_DEFAULT_RETRY;

  p_kafka_set_broker(&telemetry_daemon_msglog_kafka_host, config.telemetry_msglog_kafka_broker_host, config.telemetry_msglog_kafka_broker_port);
  p_kafka_set_topic(&telemetry_daemon_msglog_kafka_host, config.telemetry_msglog_kafka_topic);
  p_kafka_set_partition(&telemetry_daemon_msglog_kafka_host, config.telemetry_msglog_kafka_partition);
  p_kafka_set_key(&telemetry_daemon_msglog_kafka_host, config.telemetry_msglog_kafka_partition_key, config.telemetry_msglog_kafka_partition_keylen);
  p_kafka_set_content_type(&telemetry_daemon_msglog_kafka_host, PM_KAFKA_CNT_TYPE_STR);
  P_broker_timers_set_retry_interval(&telemetry_daemon_msglog_kafka_host.btimers, config.telemetry_msglog_kafka_retry);

  return ret;
}
#else
int telemetry_daemon_msglog_init_kafka_host()
{
  return ERR;
}
#endif

#if defined WITH_KAFKA
int telemetry_dump_init_kafka_host()
{
  int ret;

  p_kafka_init_host(&telemetry_dump_kafka_host, config.telemetry_dump_kafka_config_file);
  ret = p_kafka_connect_to_produce(&telemetry_dump_kafka_host);

  if (!config.telemetry_dump_kafka_broker_host) config.telemetry_dump_kafka_broker_host = default_kafka_broker_host;
  if (!config.telemetry_dump_kafka_broker_port) config.telemetry_dump_kafka_broker_port = default_kafka_broker_port;

  p_kafka_set_broker(&telemetry_dump_kafka_host, config.telemetry_dump_kafka_broker_host, config.telemetry_dump_kafka_broker_port);
  p_kafka_set_topic(&telemetry_dump_kafka_host, config.telemetry_dump_kafka_topic);
  p_kafka_set_partition(&telemetry_dump_kafka_host, config.telemetry_dump_kafka_partition);
  p_kafka_set_key(&telemetry_dump_kafka_host, config.telemetry_dump_kafka_partition_key, config.telemetry_dump_kafka_partition_keylen);
  p_kafka_set_content_type(&telemetry_dump_kafka_host, PM_KAFKA_CNT_TYPE_STR);

  return ret;
}
#else
int telemetry_dump_init_kafka_host()
{
  return ERR;
}
#endif
