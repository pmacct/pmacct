/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2021 by Paolo Lucente
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
#include "thread_pool.h"
#include "bgp/bgp.h"
#include "telemetry.h"
#if defined WITH_RABBITMQ
#include "amqp_common.h"
#endif
#ifdef WITH_KAFKA
#include "kafka_common.h"
#endif
#if defined WITH_ZMQ
#include "zmq_common.h"
#endif

/* Global variables */
thread_pool_t *telemetry_pool;
telemetry_misc_structs *telemetry_misc_db;
telemetry_peer *telemetry_peers;
void *telemetry_peers_cache;
telemetry_peer_timeout *telemetry_peers_timeout;
int zmq_input = 0, kafka_input = 0, unyte_udp_notif_input = 0;

/* Functions */
void telemetry_wrapper()
{
  struct telemetry_data *t_data;

  /* initialize threads pool */
  telemetry_pool = allocate_thread_pool(1);
  assert(telemetry_pool);
  Log(LOG_DEBUG, "DEBUG ( %s/core/TELE ): %d thread(s) initialized\n", config.name, 1);

  t_data = malloc(sizeof(struct telemetry_data));
  if (!t_data) {
    Log(LOG_ERR, "ERROR ( %s/core/TELE ): malloc() struct telemetry_data failed. Terminating.\n", config.name);
    exit_gracefully(1);
  }
  telemetry_prepare_thread(t_data);

  /* giving a kick to the telemetry thread */
  send_to_pool(telemetry_pool, telemetry_daemon, t_data);
}

int telemetry_daemon(void *t_data_void)
{
  struct telemetry_data *t_data = t_data_void;
  telemetry_peer_cache tpc;

  int ret, rc, peers_idx, allowed, yes=1;
  int peers_idx_rr = 0, max_peers_idx = 0, peers_num = 0;
  int data_decoder = 0, recv_flags = 0;
  int capture_methods = 0;
  u_int16_t port = 0;
  char *srv_proto = NULL;
  time_t last_peers_timeout_check;
  socklen_t slen = {0}, clen;

  telemetry_peer *peer = NULL;

  struct sockaddr_storage server, client;
  struct hosts_table allow;
  struct host_addr addr;

  sigset_t signal_set;

  /* select() stuff */
  fd_set read_descs, bkp_read_descs;
  int fd, select_fd, bkp_select_fd, recalc_fds, select_num = 0;

  /* logdump time management */
  time_t dump_refresh_deadline = {0};
  struct timeval dump_refresh_timeout, *drt_ptr;

  /* ZeroMQ and Kafka stuff */
  char *saved_peer_buf = NULL;
  u_char consumer_buf[LARGEBUFLEN];

#if defined WITH_UNYTE_UDP_NOTIF
  unyte_udp_collector_t *uun_collector = NULL;
  void *seg_ptr = NULL;
#endif

  if (!t_data) {
    Log(LOG_ERR, "ERROR ( %s/%s ): telemetry_daemon(): missing telemetry data. Terminating.\n", config.name, t_data->log_str);
    exit_gracefully(1);
  }

  /* initial cleanups */
  reload_map_telemetry_thread = FALSE;
  reload_log_telemetry_thread = FALSE;
  memset(&server, 0, sizeof(server));
  memset(&client, 0, sizeof(client));
  memset(&allow, 0, sizeof(struct hosts_table));
  clen = sizeof(client);
  telemetry_peers_cache = NULL;
  last_peers_timeout_check = FALSE;

  telemetry_misc_db = &inter_domain_misc_dbs[FUNC_TYPE_TELEMETRY];
  memset(telemetry_misc_db, 0, sizeof(telemetry_misc_structs));

  /* initialize variables */
  if (config.telemetry_ip || config.telemetry_port_tcp || config.telemetry_port_udp) {
    capture_methods++;
  }

  if (config.telemetry_udp_notif_ip || config.telemetry_udp_notif_port) {
#if defined WITH_UNYTE_UDP_NOTIF
    capture_methods++;
    unyte_udp_notif_input = TRUE;
#endif
  }

  if (config.telemetry_zmq_address) {
#if defined WITH_ZMQ
    capture_methods++;
    zmq_input = TRUE;
#else 
    Log(LOG_ERR, "ERROR ( %s/%s ): telemetry_daemon_zmq_* require --enable-zmq. Terminating.\n", config.name, t_data->log_str);
    exit_gracefully(1);
#endif
  }
  if (config.telemetry_kafka_broker_host || config.telemetry_kafka_topic) {
#if defined WITH_KAFKA
    capture_methods++;
    kafka_input = TRUE;

    if ((config.telemetry_kafka_broker_host && !config.telemetry_kafka_topic) || (config.telemetry_kafka_topic && !config.telemetry_kafka_broker_host)) {
      Log(LOG_ERR, "ERROR ( %s/%s ): Kafka collection requires both broker host and topic to be specified. Terminating.\n\n", config.name, t_data->log_str);
      exit_gracefully(1);
    }
#else
    Log(LOG_ERR, "ERROR ( %s/%s ): telemetry_daemon_kafka_* require --enable-kafka. Terminating.\n", config.name, t_data->log_str);
    exit_gracefully(1);
#endif
  }

  if (capture_methods > 1) {
    Log(LOG_ERR, "ERROR ( %s/%s ): telemetry_daemon_ip, telemetry_daemon_zmq_* and telemetry_kafka_* are mutually exclusive. Exiting...\n",
	config.name, t_data->log_str);
    exit_gracefully(1);
  }

  memset(consumer_buf, 0, sizeof(consumer_buf));

  if (!zmq_input && !kafka_input && !unyte_udp_notif_input) {
    if (config.telemetry_port_tcp && config.telemetry_port_udp) {
      Log(LOG_ERR, "ERROR ( %s/%s ): telemetry_daemon_port_tcp and telemetry_daemon_port_udp are mutually exclusive. Terminating.\n", config.name, t_data->log_str);
      exit_gracefully(1);
    }
    else if (!config.telemetry_port_tcp && !config.telemetry_port_udp) {
      /* defaulting to TCP */
      port = config.telemetry_port_tcp = TELEMETRY_TCP_PORT;
      srv_proto = malloc(strlen("tcp") + 1);
      strcpy(srv_proto, "tcp");
    }
    else {
      if (config.telemetry_port_tcp) {
	port = config.telemetry_port_tcp;
	srv_proto = malloc(strlen("tcp") + 1);
	strcpy(srv_proto, "tcp");
      }

      if (config.telemetry_port_udp) {
	port = config.telemetry_port_udp;
	srv_proto = malloc(strlen("udp") + 1);
	strcpy(srv_proto, "udp");
      }
    }

    /* socket creation for telemetry server: IPv4 only */
    if (!config.telemetry_ip) {
      struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&server;

      sa6->sin6_family = AF_INET6;
      sa6->sin6_port = htons(port);
      slen = sizeof(struct sockaddr_in6);
    }
    else {
      trim_spaces(config.telemetry_ip);
      ret = str_to_addr(config.telemetry_ip, &addr);
      if (!ret) {
	Log(LOG_ERR, "ERROR ( %s/%s ): telemetry_daemon_ip value is not a valid IPv4/IPv6 address. Terminating.\n", config.name, t_data->log_str);
	exit_gracefully(1);
      }
      slen = addr_to_sa((struct sockaddr *)&server, &addr, port);
    }
  }

  if (!config.telemetry_decoder) {
    Log(LOG_ERR, "ERROR ( %s/%s ): telemetry_daemon_decoder is not specified. Terminating.\n", config.name, t_data->log_str);
    exit_gracefully(1);
  }
  else {
    if (!strcmp(config.telemetry_decoder, "json")) config.telemetry_decoder_id = TELEMETRY_DECODER_JSON;
    else if (!strcmp(config.telemetry_decoder, "gpb")) config.telemetry_decoder_id = TELEMETRY_DECODER_GPB;
    else if (!strcmp(config.telemetry_decoder, "cisco_v0")) config.telemetry_decoder_id = TELEMETRY_DECODER_CISCO_V0;
    else if (!strcmp(config.telemetry_decoder, "cisco_v1")) config.telemetry_decoder_id = TELEMETRY_DECODER_CISCO_V1;
    else {
      Log(LOG_ERR, "ERROR ( %s/%s ): telemetry_daemon_decoder set to unknown value. Terminating.\n", config.name, t_data->log_str);
      exit_gracefully(1);
    }

    if (config.telemetry_decoder_id != TELEMETRY_DECODER_JSON) {
      if (zmq_input) {
	Log(LOG_ERR, "ERROR ( %s/%s ): ZeroMQ collection supports only 'json' decoder (telemetry_daemon_decoder). Terminating.\n", config.name, t_data->log_str);
	exit_gracefully(1);
      }

      if (kafka_input) {
	Log(LOG_ERR, "ERROR ( %s/%s ): Kafka collection supports only 'json' decoder (telemetry_daemon_decoder). Terminating.\n", config.name, t_data->log_str);
	exit_gracefully(1);
      }

      if (unyte_udp_notif_input) {
	Log(LOG_ERR, "ERROR ( %s/%s ): Unyte UDP Notif collection supports only 'json' decoder (telemetry_daemon_decoder). Terminating.\n", config.name, t_data->log_str);
	exit_gracefully(1);
      }
    }
  }

  if (!config.telemetry_max_peers) config.telemetry_max_peers = TELEMETRY_MAX_PEERS_DEFAULT;
  Log(LOG_INFO, "INFO ( %s/%s ): maximum telemetry peers allowed: %d\n", config.name, t_data->log_str, config.telemetry_max_peers);

  if (config.telemetry_port_udp || zmq_input || kafka_input || unyte_udp_notif_input) {
    if (!config.telemetry_peer_timeout) config.telemetry_peer_timeout = TELEMETRY_PEER_TIMEOUT_DEFAULT;
    Log(LOG_INFO, "INFO ( %s/%s ): telemetry peers timeout: %u\n", config.name, t_data->log_str, config.telemetry_peer_timeout);
  }

  telemetry_peers = malloc(config.telemetry_max_peers*sizeof(telemetry_peer));
  if (!telemetry_peers) {
    Log(LOG_ERR, "ERROR ( %s/%s ): Unable to malloc() telemetry_peers structure. Terminating.\n", config.name, t_data->log_str);
    exit_gracefully(1);
  }
  memset(telemetry_peers, 0, config.telemetry_max_peers*sizeof(telemetry_peer));

  if (config.telemetry_port_udp || zmq_input || kafka_input || unyte_udp_notif_input) {
    telemetry_peers_timeout = malloc(config.telemetry_max_peers*sizeof(telemetry_peer_timeout));
    if (!telemetry_peers_timeout) {
      Log(LOG_ERR, "ERROR ( %s/%s ): Unable to malloc() telemetry_peers_timeout structure. Terminating.\n", config.name, t_data->log_str);
      exit_gracefully(1);
    }
    memset(telemetry_peers_timeout, 0, config.telemetry_max_peers*sizeof(telemetry_peer_timeout));
  }

  if (config.telemetry_msglog_file || config.telemetry_msglog_amqp_routing_key || config.telemetry_msglog_kafka_topic) {
    if (config.telemetry_msglog_file) telemetry_misc_db->msglog_backend_methods++;
    if (config.telemetry_msglog_amqp_routing_key) telemetry_misc_db->msglog_backend_methods++;
    if (config.telemetry_msglog_kafka_topic) telemetry_misc_db->msglog_backend_methods++;

    if (telemetry_misc_db->msglog_backend_methods > 1) {
      Log(LOG_ERR, "ERROR ( %s/%s ): telemetry_daemon_msglog_file, telemetry_daemon_msglog_amqp_routing_key and telemetry_daemon_msglog_kafka_topic are mutually exclusive. Terminating.\n", config.name, t_data->log_str);
      exit_gracefully(1);
    }
  }

  if (config.telemetry_dump_file || config.telemetry_dump_amqp_routing_key || config.telemetry_dump_kafka_topic) {
    if (config.telemetry_dump_file) telemetry_misc_db->dump_backend_methods++;
    if (config.telemetry_dump_amqp_routing_key) telemetry_misc_db->dump_backend_methods++;
    if (config.telemetry_dump_kafka_topic) telemetry_misc_db->dump_backend_methods++;

    if (telemetry_misc_db->dump_backend_methods > 1) {
      Log(LOG_ERR, "ERROR ( %s/%s ): telemetry_dump_file, telemetry_dump_amqp_routing_key and telemetry_dump_kafka_topic are mutually exclusive. Terminating.\n", config.name, t_data->log_str);
      exit_gracefully(1);
    }
  }

  if (telemetry_misc_db->msglog_backend_methods || telemetry_misc_db->dump_backend_methods)
    telemetry_log_seq_init(&telemetry_misc_db->log_seq);

  if (telemetry_misc_db->msglog_backend_methods) {
    telemetry_misc_db->peers_log = malloc(config.telemetry_max_peers*sizeof(telemetry_peer_log));
    if (!telemetry_misc_db->peers_log) {
      Log(LOG_ERR, "ERROR ( %s/%s ): Unable to malloc() telemetry peers_log structure. Terminating.\n", config.name, t_data->log_str);
      exit_gracefully(1);
    }
    memset(telemetry_misc_db->peers_log, 0, config.telemetry_max_peers*sizeof(telemetry_peer_log));

    if (config.telemetry_msglog_amqp_routing_key) {
#ifdef WITH_RABBITMQ
      telemetry_daemon_msglog_init_amqp_host();
      p_amqp_connect_to_publish(&telemetry_daemon_msglog_amqp_host);

      if (!config.telemetry_msglog_amqp_retry)
        config.telemetry_msglog_amqp_retry = AMQP_DEFAULT_RETRY;
#else
      Log(LOG_WARNING, "WARN ( %s/%s ): p_amqp_connect_to_publish() not possible due to missing --enable-rabbitmq\n", config.name, t_data->log_str);
#endif
    }

    if (config.telemetry_msglog_kafka_topic) {
#ifdef WITH_KAFKA
      telemetry_daemon_msglog_init_kafka_host();
#else
      Log(LOG_WARNING, "WARN ( %s/%s ): p_kafka_connect_to_produce() not possible due to missing --enable-kafka\n", config.name, t_data->log_str);
#endif
    }
  }

  if (!zmq_input && !kafka_input && !unyte_udp_notif_input) {
    if (config.telemetry_port_tcp) config.telemetry_sock = socket(((struct sockaddr *)&server)->sa_family, SOCK_STREAM, 0);
    else if (config.telemetry_port_udp) config.telemetry_sock = socket(((struct sockaddr *)&server)->sa_family, SOCK_DGRAM, 0);

    if (config.telemetry_sock < 0) {
      /* retry with IPv4 */
      if (!config.telemetry_ip) {
	struct sockaddr_in *sa4 = (struct sockaddr_in *)&server;

	sa4->sin_family = AF_INET;
	sa4->sin_addr.s_addr = htonl(0);
	sa4->sin_port = htons(port);
	slen = sizeof(struct sockaddr_in);

	if (config.telemetry_port_tcp) config.telemetry_sock = socket(((struct sockaddr *)&server)->sa_family, SOCK_STREAM, 0);
	else if (config.telemetry_port_udp) config.telemetry_sock = socket(((struct sockaddr *)&server)->sa_family, SOCK_DGRAM, 0);
      }

      if (config.telemetry_sock < 0) {
	Log(LOG_ERR, "ERROR ( %s/%s ): socket() failed. Terminating.\n", config.name, t_data->log_str);
	exit_gracefully(1);
      }

      if (config.telemetry_port_tcp) setsockopt(config.telemetry_sock, SOL_SOCKET, SO_KEEPALIVE, (void *)&yes, sizeof(yes));
    }

    if (config.telemetry_ipprec) {
      int opt = config.telemetry_ipprec << 5;

      rc = setsockopt(config.telemetry_sock, IPPROTO_IP, IP_TOS, &opt, (socklen_t) sizeof(opt));
      if (rc < 0) Log(LOG_ERR, "WARN ( %s/%s ): setsockopt() failed for IP_TOS (errno: %d).\n", config.name, t_data->log_str, errno);
    }

#if (defined HAVE_SO_REUSEPORT)
    rc = setsockopt(config.telemetry_sock, SOL_SOCKET, SO_REUSEPORT, (char *) &yes, (socklen_t) sizeof(yes));
    if (rc < 0) Log(LOG_ERR, "WARN ( %s/%s ): setsockopt() failed for SO_REUSEPORT (errno: %d).\n", config.name, t_data->log_str, errno);
#endif

    rc = setsockopt(config.telemetry_sock, SOL_SOCKET, SO_REUSEADDR, (char *) &yes, (socklen_t) sizeof(yes));
    if (rc < 0) Log(LOG_ERR, "WARN ( %s/%s ): setsockopt() failed for SO_REUSEADDR (errno: %d).\n", config.name, t_data->log_str, errno);

    if (config.telemetry_ipv6_only) {
      int yes=1;

      rc = setsockopt(config.telemetry_sock, IPPROTO_IPV6, IPV6_V6ONLY, (char *) &yes, (socklen_t) sizeof(yes));
      if (rc < 0) Log(LOG_ERR, "WARN ( %s/%s ): setsockopt() failed for IPV6_V6ONLY (errno: %d).\n", config.name, t_data->log_str, errno);
    }

    if (config.telemetry_pipe_size) {
      socklen_t l = sizeof(config.telemetry_pipe_size);
      int saved = 0, obtained = 0;

      getsockopt(config.telemetry_sock, SOL_SOCKET, SO_RCVBUF, &saved, &l);
      Setsocksize(config.telemetry_sock, SOL_SOCKET, SO_RCVBUF, &config.telemetry_pipe_size, (socklen_t) sizeof(config.telemetry_pipe_size));
      getsockopt(config.telemetry_sock, SOL_SOCKET, SO_RCVBUF, &obtained, &l);

      Setsocksize(config.telemetry_sock, SOL_SOCKET, SO_RCVBUF, &saved, l);
      getsockopt(config.telemetry_sock, SOL_SOCKET, SO_RCVBUF, &obtained, &l);
      Log(LOG_INFO, "INFO ( %s/%s ): telemetry_daemon_pipe_size: obtained=%d target=%d.\n",
	  config.name, t_data->log_str, obtained, config.telemetry_pipe_size);
    }

    rc = bind(config.telemetry_sock, (struct sockaddr *) &server, slen);
    if (rc < 0) {
      char null_ip_address[] = "0.0.0.0";
      char *ip_address;

      ip_address = config.telemetry_ip ? config.telemetry_ip : null_ip_address;
      Log(LOG_ERR, "ERROR ( %s/%s ): bind() to ip=%s port=%u/%s failed (errno: %d).\n",
	  config.name, t_data->log_str, ip_address, port, srv_proto, errno);
      exit_gracefully(1);
    }

    if (config.telemetry_port_tcp) {
      rc = listen(config.telemetry_sock, 1);
      if (rc < 0) {
	Log(LOG_ERR, "ERROR ( %s/%s ): listen() failed (errno: %d).\n", config.name, t_data->log_str, errno);
	exit_gracefully(1);
      }
    }
  }

  if (!zmq_input && !kafka_input && !unyte_udp_notif_input) {
    char srv_string[INET6_ADDRSTRLEN];
    struct host_addr srv_addr;
    u_int16_t srv_port;

    sa_to_addr((struct sockaddr *)&server, &srv_addr, &srv_port);
    addr_to_str(srv_string, &srv_addr);
    Log(LOG_INFO, "INFO ( %s/%s ): waiting for telemetry data on %s:%u/%s\n", config.name, t_data->log_str, srv_string, srv_port, srv_proto);
  }
#if defined WITH_ZMQ
  else if (zmq_input) {
    telemetry_init_zmq_host(&telemetry_zmq_host, &config.telemetry_sock);
    Log(LOG_INFO, "INFO ( %s/%s ): reading telemetry data from ZeroMQ %s\n", config.name, t_data->log_str, p_zmq_get_address(&telemetry_zmq_host));
  }
#endif
#if defined WITH_KAFKA
  else if (kafka_input) {
    telemetry_init_kafka_host(&telemetry_kafka_host);
    Log(LOG_INFO, "INFO ( %s/%s ): reading telemetry data from Kafka %s:%s\n", config.name, t_data->log_str,
	p_kafka_get_broker(&telemetry_kafka_host), p_kafka_get_topic(&telemetry_kafka_host));
  }
#endif
#if defined WITH_UNYTE_UDP_NOTIF
  else if (unyte_udp_notif_input) {
    char null_ip_address[] = "0.0.0.0";
    unyte_udp_options_t options = {0};

    if (config.telemetry_udp_notif_ip) {
      options.address = config.telemetry_udp_notif_ip;
    }
    else {
      options.address = null_ip_address;
    }

    if (config.telemetry_udp_notif_port) {
      options.port = config.telemetry_udp_notif_port;
    }
    else {
      Log(LOG_ERR, "ERROR ( %s/core/TELE ): Unyte UDP Notif specified but no telemetry_daemon_udp_notif_port supplied. Terminating.\n", config.name);
      exit_gracefully(1);
    }

    if (config.telemetry_udp_notif_nmsgs) {
      options.recvmmsg_vlen = config.telemetry_udp_notif_nmsgs;
    }
    else {
      options.recvmmsg_vlen = TELEMETRY_DEFAULT_UNYTE_UDP_NOTIF_NMSGS;
    }

    uun_collector = unyte_udp_start_collector(&options);

    Log(LOG_INFO, "INFO ( %s/%s ): reading telemetry data from Unyte UDP Notif on %s:%d\n",
	config.name, t_data->log_str, options.address, options.port);
  }
#endif

  /* Preparing for syncronous I/O multiplexing */
  select_fd = 0;
  FD_ZERO(&bkp_read_descs);
  FD_SET(config.telemetry_sock, &bkp_read_descs);

  /* Preparing ACL, if any */
  if (config.telemetry_allow_file) load_allow_file(config.telemetry_allow_file, &allow);

  if (telemetry_misc_db->msglog_backend_methods) {
#ifdef WITH_JANSSON
    if (!config.telemetry_msglog_output) config.telemetry_msglog_output = PRINT_OUTPUT_JSON;
#else
    Log(LOG_WARNING, "WARN ( %s/%s ): telemetry_daemon_msglog_output set to json but will produce no output (missing --enable-jansson).\n", config.name, t_data->log_str);
#endif
  }

  if (telemetry_misc_db->dump_backend_methods) {
    if (!config.telemetry_dump_workers) {
      config.telemetry_dump_workers = 1;
    }

#ifdef WITH_JANSSON
    if (!config.telemetry_dump_output) {
      config.telemetry_dump_output = PRINT_OUTPUT_JSON;
    }
#else
    Log(LOG_WARNING, "WARN ( %s/%s ): telemetry_table_dump_output set to json but will produce no output (missing --enable-jansson).\n", config.name, t_data->log_str);
#endif
  }

  if (telemetry_misc_db->dump_backend_methods) {
    char dump_roundoff[] = "m";
    time_t tmp_time;

    if (config.telemetry_dump_refresh_time) {
      gettimeofday(&telemetry_misc_db->log_tstamp, NULL);
      dump_refresh_deadline = telemetry_misc_db->log_tstamp.tv_sec;
      tmp_time = roundoff_time(dump_refresh_deadline, dump_roundoff);
      while ((tmp_time+config.telemetry_dump_refresh_time) < dump_refresh_deadline) {
        tmp_time += config.telemetry_dump_refresh_time;
      }
      dump_refresh_deadline = tmp_time;
      dump_refresh_deadline += config.telemetry_dump_refresh_time; /* it's a deadline not a basetime */
    }
    else {
      config.telemetry_dump_file = NULL;
      telemetry_misc_db->dump_backend_methods = FALSE;
      Log(LOG_WARNING, "WARN ( %s/%s ): Invalid 'telemetry_dump_refresh_time'.\n", config.name, t_data->log_str);
    }
  }

  select_fd = bkp_select_fd = (config.telemetry_sock + 1);
  recalc_fds = FALSE;

  telemetry_link_misc_structs(telemetry_misc_db);

  sigemptyset(&signal_set);
  sigaddset(&signal_set, SIGCHLD);
  sigaddset(&signal_set, SIGHUP);
  sigaddset(&signal_set, SIGUSR1);
  sigaddset(&signal_set, SIGUSR2);
  sigaddset(&signal_set, SIGTERM);
  if (config.daemon) {
    sigaddset(&signal_set, SIGINT);
  }

  for (;;) {
    select_again:

    if (!t_data->is_thread) {
      sigprocmask(SIG_UNBLOCK, &signal_set, NULL); 
      sigprocmask(SIG_BLOCK, &signal_set, NULL); 
    }

    if (recalc_fds) {
      select_fd = config.telemetry_sock;
      max_peers_idx = -1; /* .. since valid indexes include 0 */

      for (peers_idx = 0, peers_num = 0; peers_idx < config.telemetry_max_peers; peers_idx++) {
	if (select_fd < telemetry_peers[peers_idx].fd) select_fd = telemetry_peers[peers_idx].fd;
	if (telemetry_peers[peers_idx].fd > 0) {
	  max_peers_idx = peers_idx;
	  peers_num++;
	}
      }
      select_fd++;
      max_peers_idx++;

      bkp_select_fd = select_fd;
      recalc_fds = FALSE;
    }
    else select_fd = bkp_select_fd;

    memcpy(&read_descs, &bkp_read_descs, sizeof(bkp_read_descs));

    if (telemetry_misc_db->dump_backend_methods) {
      int delta;

      calc_refresh_timeout_sec(dump_refresh_deadline, telemetry_misc_db->log_tstamp.tv_sec, &delta);
      dump_refresh_timeout.tv_sec = delta;
      dump_refresh_timeout.tv_usec = 0;
      drt_ptr = &dump_refresh_timeout;
    }
    else drt_ptr = NULL;

    if (!zmq_input && !kafka_input && !unyte_udp_notif_input) {
      select_num = select(select_fd, &read_descs, NULL, NULL, drt_ptr);
      if (select_num < 0) goto select_again;
    }
#if defined WITH_ZMQ
    else if (zmq_input) {
      select_num = p_zmq_recv_poll(&telemetry_zmq_host.sock, drt_ptr ? (drt_ptr->tv_sec * 1000) : 1000);
      if (select_num < 0) goto select_again;
    }
#endif
#if defined WITH_KAFKA
    else if (kafka_input) {
      t_data->kafka_msg = NULL;

      select_num = p_kafka_consume_poller(&telemetry_kafka_host, &t_data->kafka_msg, drt_ptr ? (drt_ptr->tv_sec * 1000) : 1000);

      if (select_num < 0) {
	/* Close */
	p_kafka_manage_consumer(&nfacctd_kafka_host, FALSE);

	/* Re-open */
	telemetry_init_kafka_host(&telemetry_kafka_host);

	goto select_again;
      }
    }
#endif
#if defined WITH_UNYTE_UDP_NOTIF
    else if (unyte_udp_notif_input) {
      unyte_seg_met_t *seg = NULL;

      seg_ptr = unyte_udp_queue_read(uun_collector->queue);
      select_num = TRUE; /* anything but zero or negative */

      /* the library does pass src_addr / src_port that went through a ntoh*() func;
	 to align the workflow to the rest of collection methods, let's temporarily
	 revert this */
      seg = (unyte_seg_met_t *)seg_ptr;
      seg->metadata->src_addr = htonl(seg->metadata->src_addr);
      seg->metadata->src_port = htons(seg->metadata->src_port);
    }
#endif

    t_data->now = time(NULL);

    /* Logging stats */
    if (!t_data->global_stats.last_check || ((t_data->global_stats.last_check + TELEMETRY_LOG_STATS_INTERVAL) <= t_data->now)) {
      if (t_data->global_stats.last_check) {
	telemetry_peer *stats_peer;
	int peers_idx;

	for (stats_peer = NULL, peers_idx = 0; peers_idx < config.telemetry_max_peers; peers_idx++) {
	  if (telemetry_peers[peers_idx].fd) {
	    stats_peer = &telemetry_peers[peers_idx];
	    telemetry_log_peer_stats(stats_peer, t_data);
	    stats_peer->stats.last_check = t_data->now;
	  }
	}

	telemetry_log_global_stats(t_data);
      }

      t_data->global_stats.last_check = t_data->now;
    }

    /* XXX: ZeroMQ / Kafka cases: timeout handling (to be tested) */
    if (config.telemetry_port_udp || zmq_input || kafka_input || unyte_udp_notif_input) {
      if (t_data->now > (last_peers_timeout_check + TELEMETRY_PEER_TIMEOUT_INTERVAL)) {
	for (peers_idx = 0; peers_idx < config.telemetry_max_peers; peers_idx++) {
	  telemetry_peer_timeout *peer_timeout;

	  peer = &telemetry_peers[peers_idx];
	  peer_timeout = &telemetry_peers_timeout[peers_idx];

	  if (peer->fd) {
	    if (t_data->now > (peer_timeout->last_msg + config.telemetry_peer_timeout)) {
	      Log(LOG_INFO, "INFO ( %s/%s ): [%s] telemetry peer removed (timeout).\n", config.name, t_data->log_str, peer->addr_str);
	      telemetry_peer_close(peer, FUNC_TYPE_TELEMETRY);
	      peers_num--;
	      recalc_fds = TRUE;
	    }
	  }
	}

	last_peers_timeout_check = t_data->now;
      }
    }

    if (reload_map_telemetry_thread) {
      if (config.telemetry_allow_file) load_allow_file(config.telemetry_allow_file, &allow);

      reload_map_telemetry_thread = FALSE;
    }

    if (reload_log_telemetry_thread) {
      for (peers_idx = 0; peers_idx < config.telemetry_max_peers; peers_idx++) {
        if (telemetry_misc_db->peers_log[peers_idx].fd) {
          fclose(telemetry_misc_db->peers_log[peers_idx].fd);
          telemetry_misc_db->peers_log[peers_idx].fd = open_output_file(telemetry_misc_db->peers_log[peers_idx].filename, "a", FALSE);
          setlinebuf(telemetry_misc_db->peers_log[peers_idx].fd);
        }
        else break;
      }

      reload_log_telemetry_thread = FALSE;
    }

    if (reload_log && !telemetry_misc_db->is_thread) {
      reload_logs();
      reload_log = FALSE;
    }

    if (telemetry_misc_db->msglog_backend_methods || telemetry_misc_db->dump_backend_methods) {
      gettimeofday(&telemetry_misc_db->log_tstamp, NULL);
      compose_timestamp(telemetry_misc_db->log_tstamp_str, SRVBUFLEN, &telemetry_misc_db->log_tstamp, TRUE,
			config.timestamps_since_epoch, config.timestamps_rfc3339, config.timestamps_utc);

      /* let's reset log sequence here as we do not sequence dump_init/dump_close events */
      if (telemetry_log_seq_has_ro_bit(&telemetry_misc_db->log_seq))
	telemetry_log_seq_init(&telemetry_misc_db->log_seq);

      if (telemetry_misc_db->dump_backend_methods) {
        while (telemetry_misc_db->log_tstamp.tv_sec > dump_refresh_deadline) {
          telemetry_misc_db->dump.tstamp.tv_sec = dump_refresh_deadline;
          telemetry_misc_db->dump.tstamp.tv_usec = 0;
          compose_timestamp(telemetry_misc_db->dump.tstamp_str, SRVBUFLEN, &telemetry_misc_db->dump.tstamp, FALSE,
			    config.timestamps_since_epoch, config.timestamps_rfc3339, config.timestamps_utc);
	  telemetry_misc_db->dump.period = config.telemetry_dump_refresh_time;

          telemetry_handle_dump_event(t_data, max_peers_idx);

          dump_refresh_deadline += config.telemetry_dump_refresh_time;
        }
      }

#ifdef WITH_RABBITMQ
      if (config.telemetry_msglog_amqp_routing_key) {
        time_t last_fail = P_broker_timers_get_last_fail(&telemetry_daemon_msglog_amqp_host.btimers);

        if (last_fail && ((last_fail + P_broker_timers_get_retry_interval(&telemetry_daemon_msglog_amqp_host.btimers)) <= telemetry_misc_db->log_tstamp.tv_sec)) {
          telemetry_daemon_msglog_init_amqp_host();
          p_amqp_connect_to_publish(&telemetry_daemon_msglog_amqp_host);
        }
      }
#endif

#ifdef WITH_KAFKA
      if (config.telemetry_msglog_kafka_topic) {
        time_t last_fail = P_broker_timers_get_last_fail(&telemetry_daemon_msglog_kafka_host.btimers);

        if (last_fail && ((last_fail + P_broker_timers_get_retry_interval(&telemetry_daemon_msglog_kafka_host.btimers)) <= telemetry_misc_db->log_tstamp.tv_sec))
          telemetry_daemon_msglog_init_kafka_host();
      }
#endif
    }

    /*
       If select_num == 0 then we got out of polling due to a timeout
       rather than because we had a message from a peer to handle. By
       now we did all routine checks and can return to polling again.
    */
    if (!select_num) goto select_again;

    /* New connection is coming in */
    if (FD_ISSET(config.telemetry_sock, &read_descs) || kafka_input || unyte_udp_notif_input) {
      if (config.telemetry_port_tcp) {
        fd = accept(config.telemetry_sock, (struct sockaddr *) &client, &clen);
        if (fd == ERR) goto read_data;
      }
      else if (config.telemetry_port_udp) {
	char dummy_local_buf[TRUE];

	ret = recvfrom(config.telemetry_sock, dummy_local_buf, TRUE, MSG_PEEK, (struct sockaddr *) &client, &clen);
	if (ret <= 0) goto select_again;
	else fd = config.telemetry_sock;
      }
#if defined WITH_ZMQ
      else if (zmq_input) {
	ret = telemetry_decode_producer_peer(t_data, &telemetry_zmq_host, consumer_buf, sizeof(consumer_buf), (struct sockaddr *) &client, &clen);
	if (ret < 0) goto select_again; 
	else fd = config.telemetry_sock;
      }
#endif
#if defined WITH_KAFKA
      else if (kafka_input) {
	ret = telemetry_decode_producer_peer(t_data, &telemetry_kafka_host, consumer_buf, sizeof(consumer_buf), (struct sockaddr *) &client, &clen);
	if (ret < 0) goto select_again;
        else fd = TELEMETRY_KAFKA_FD;
      }
#endif
#if defined WITH_UNYTE_UDP_NOTIF
      else if (unyte_udp_notif_input) {
	if (seg_ptr) {
	  unyte_seg_met_t *seg = NULL;
          int payload_len = 0;

	  seg = (unyte_seg_met_t *)seg_ptr;

	  if (seg->header->encoding_type == TELEMETRY_UDP_NOTIF_ENC_JSON && config.telemetry_decoder_id == TELEMETRY_DECODER_JSON) {
	    raw_to_sa((struct sockaddr *)&client, (u_char *)&seg->metadata->src_addr, seg->metadata->src_port, AF_INET);

	    payload_len = strlen(seg->payload);
	    if (payload_len < sizeof(consumer_buf)) {
	      strlcpy((char *)consumer_buf, seg->payload, sizeof(consumer_buf));
	      fd = TELEMETRY_UDP_NOTIF_FD;
	    }
	    else {
	      goto select_again;
	    }
	  }
	  else {
	    goto select_again;
	  }
	}
      }
#endif

      ipv4_mapped_to_ipv4(&client);

      /* If an ACL is defined, here we check against and enforce it */
      if (allow.num) allowed = check_allow(&allow, (struct sockaddr *)&client);
      else allowed = TRUE;

      if (!allowed) {
        if (config.telemetry_port_tcp) close(fd);
        goto read_data;
      }

      /* XXX: UDP, ZeroMQ and Kafka cases may be optimized further */
      if (config.telemetry_port_udp || zmq_input || kafka_input || unyte_udp_notif_input) {
	telemetry_peer_cache *tpc_ret;
	u_int16_t client_port;

        sa_to_addr((struct sockaddr *)&client, &tpc.addr, &client_port);
	tpc_ret = pm_tfind(&tpc, &telemetry_peers_cache, telemetry_tpc_addr_cmp);

	if (tpc_ret) {
	  telemetry_peer_cache *tpc_peer = (*(telemetry_peer_cache **) tpc_ret);

	  peer = &telemetry_peers[tpc_peer->index];
	  telemetry_peers_timeout[tpc_peer->index].last_msg = t_data->now;

	  goto read_data;
	}
      }

      for (peer = NULL, peers_idx = 0; peers_idx < config.telemetry_max_peers; peers_idx++) {
        if (!telemetry_peers[peers_idx].fd) {
	  peer = &telemetry_peers[peers_idx];

	  if (telemetry_peer_init(peer, FUNC_TYPE_TELEMETRY)) peer = NULL;

	  if (peer) {
	    recalc_fds = TRUE; // XXX: do we need this for ZeroMQ / Kafka cases?

	    if (config.telemetry_port_udp || zmq_input || kafka_input || unyte_udp_notif_input) {
	      tpc.index = peers_idx;
	      telemetry_peers_timeout[peers_idx].last_msg = t_data->now;

	      if (!pm_tsearch(&tpc, &telemetry_peers_cache, telemetry_tpc_addr_cmp, sizeof(telemetry_peer_cache)))
		Log(LOG_WARNING, "WARN ( %s/%s ): tsearch() unable to insert in peers cache.\n", config.name, t_data->log_str);
	    }
	  }

	  break;
	}
      }

      if (!peer) {
        /* We briefly accept the new connection to be able to drop it */
        Log(LOG_WARNING, "WARN ( %s/%s ): Insufficient number of telemetry peers has been configured by telemetry_max_peers (%d).\n",
                        config.name, t_data->log_str, config.telemetry_max_peers);
        if (config.telemetry_port_tcp) close(fd);
        goto read_data;
      }

#if defined WITH_KAFKA
      if (kafka_input) {
	peer->buf.kafka_msg = t_data->kafka_msg;
        t_data->kafka_msg = NULL;
      }
#endif

      peer->fd = fd;
      if (config.telemetry_port_tcp) FD_SET(peer->fd, &bkp_read_descs);
      peer->addr.family = ((struct sockaddr *)&client)->sa_family;
      if (peer->addr.family == AF_INET) {
        peer->addr.address.ipv4.s_addr = ((struct sockaddr_in *)&client)->sin_addr.s_addr;
        peer->tcp_port = ntohs(((struct sockaddr_in *)&client)->sin_port);
      }
      else if (peer->addr.family == AF_INET6) {
        memcpy(&peer->addr.address.ipv6, &((struct sockaddr_in6 *)&client)->sin6_addr, 16);
        peer->tcp_port = ntohs(((struct sockaddr_in6 *)&client)->sin6_port);
      }
      addr_to_str(peer->addr_str, &peer->addr);

      if (telemetry_misc_db->msglog_backend_methods)
        telemetry_peer_log_init(peer, config.telemetry_msglog_output, FUNC_TYPE_TELEMETRY);

      if (telemetry_misc_db->dump_backend_methods)
        telemetry_dump_init_peer(peer);

      peers_num++;
      Log(LOG_INFO, "INFO ( %s/%s ): [%s] telemetry peers usage: %u/%u\n",
	  config.name, t_data->log_str, peer->addr_str, peers_num, config.telemetry_max_peers);
    }

    read_data:

    /*
       We have something coming in: let's lookup which peer is that.
       FvD: To avoid starvation of the "later established" peers, we
       offset the start of the search in a round-robin style.
    */
    if (config.telemetry_port_tcp) {
      for (peer = NULL, peers_idx = 0; peers_idx < max_peers_idx; peers_idx++) {
        int loc_idx = (peers_idx + peers_idx_rr) % max_peers_idx;

        if (telemetry_peers[loc_idx].fd && FD_ISSET(telemetry_peers[loc_idx].fd, &read_descs)) {
          peer = &telemetry_peers[loc_idx];
          peers_idx_rr = (peers_idx_rr + 1) % max_peers_idx;
          break;
        }
      }
    }

    if (!peer) goto select_again;

    recv_flags = 0;

    switch (config.telemetry_decoder_id) {
    case TELEMETRY_DECODER_JSON:
      if (!zmq_input && !kafka_input && !unyte_udp_notif_input) {
	ret = telemetry_recv_json(peer, 0, &recv_flags);
      }
      else {
	ret = (strlen((char *) consumer_buf) + 1);

	if (ret > 0) {
	  saved_peer_buf = peer->buf.base;
	  peer->buf.base = (char *) consumer_buf;
	  peer->msglen = peer->buf.tot_len = ret;

	  if (unyte_udp_notif_input) {
	    peer->stats.packet_bytes += ret;
	  }
	}
      }
      data_decoder = TELEMETRY_DATA_DECODER_JSON;
      break;
    case TELEMETRY_DECODER_GPB:
      ret = telemetry_recv_gpb(peer, 0);
      data_decoder = TELEMETRY_DATA_DECODER_GPB;
      break;
    case TELEMETRY_DECODER_CISCO_V0:
      ret = telemetry_recv_cisco_v0(peer, &recv_flags, &data_decoder);
      break;
    case TELEMETRY_DECODER_CISCO_V1:
      ret = telemetry_recv_cisco_v1(peer, &recv_flags, &data_decoder);
      break;
    default:
      ret = TRUE; recv_flags = ERR;
      data_decoder = TELEMETRY_DATA_DECODER_UNKNOWN;
      break;
    }

    if (ret <= 0) {
      Log(LOG_INFO, "INFO ( %s/%s ): [%s] connection reset by peer (%d).\n", config.name, t_data->log_str, peer->addr_str, errno);
      FD_CLR(peer->fd, &bkp_read_descs);
      telemetry_peer_close(peer, FUNC_TYPE_TELEMETRY);
      peers_num--;
      recalc_fds = TRUE;
    }
    else {
      peer->stats.packets++;
      if (recv_flags != ERR) {
        peer->stats.msg_bytes += ret;
        telemetry_process_data(peer, t_data, data_decoder);
      }

      if (zmq_input || kafka_input || unyte_udp_notif_input) {
	peer->buf.base = saved_peer_buf;
      }
    }
  }

  return SUCCESS;
}

void telemetry_prepare_thread(struct telemetry_data *t_data)
{
  if (!t_data) return;

  memset(t_data, 0, sizeof(struct telemetry_data));
  t_data->is_thread = TRUE;
  t_data->log_str = malloc(strlen("core/TELE") + 1);
  strcpy(t_data->log_str, "core/TELE");
}

void telemetry_prepare_daemon(struct telemetry_data *t_data)
{
  if (!t_data) return;

  memset(t_data, 0, sizeof(struct telemetry_data));
  t_data->is_thread = FALSE;
  t_data->log_str = malloc(strlen("core") + 1);
  strcpy(t_data->log_str, "core");
}
