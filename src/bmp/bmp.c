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
#include "bgp/bgp.h"
#include "bmp.h"
#include "rpki/rpki.h"
#include "thread_pool.h"
#include "ip_flow.h"
#include "ip_frag.h"
#if defined WITH_RABBITMQ
#include "amqp_common.h"
#endif
#ifdef WITH_KAFKA
#include "kafka_common.h"
#endif
#if defined WITH_AVRO
#include "plugin_cmn_avro.h"
#endif

/* variables to be exported away */
thread_pool_t *bmp_pool;

/* Functions */
void bmp_daemon_wrapper()
{
  /* initialize variables */
  if (!config.bmp_daemon_port) config.bmp_daemon_port = BMP_TCP_PORT;

  /* initialize threads pool */
  bmp_pool = allocate_thread_pool(1);
  assert(bmp_pool);
  Log(LOG_DEBUG, "DEBUG ( %s/core/BMP ): %d thread(s) initialized\n", config.name, 1);
  bmp_prepare_thread();

  /* giving a kick to the BMP thread */
  send_to_pool(bmp_pool, skinny_bmp_daemon, NULL);
}

int skinny_bmp_daemon()
{
  int ret, rc, peers_idx, allowed, yes=1, do_term;
  int peers_idx_rr = 0, max_peers_idx = 0;
  time_t now;
  afi_t afi;
  safi_t safi;
  socklen_t slen, clen;

  struct bmp_peer *bmpp = NULL;
  struct bgp_peer *peer = NULL;

  struct sockaddr_storage server, client;
  struct hosts_table allow;
  struct host_addr addr;
  struct bgp_peer_batch bp_batch;

  sigset_t signal_set;

  /* select() stuff */
  fd_set read_descs, bkp_read_descs;
  int fd, select_fd, bkp_select_fd, recalc_fds, select_num;

  /* logdump time management */
  time_t dump_refresh_deadline = {0};
  struct timeval dump_refresh_timeout, *drt_ptr;

  /* pcap_savefile stuff */
  struct packet_ptrs recv_pptrs;
  unsigned char *bmp_packet;
  int sf_ret, pcap_savefile_round = 1;

  /* initial cleanups */
  reload_map_bmp_thread = FALSE;
  reload_log_bmp_thread = FALSE;
  memset(&server, 0, sizeof(server));
  memset(&client, 0, sizeof(client));
  memset(&allow, 0, sizeof(struct hosts_table));
  clen = sizeof(client);

  memset(&recv_pptrs, 0, sizeof(recv_pptrs));
  memset(&device, 0, sizeof(device));
  bmp_packet = malloc(BGP_BUFFER_SIZE);

  bmp_routing_db = &inter_domain_routing_dbs[FUNC_TYPE_BMP];
  memset(bmp_routing_db, 0, sizeof(struct bgp_rt_structs));

  /* socket creation for BMP server: IPv4 only */
  if (!config.bmp_daemon_ip && !config.pcap_savefile) {
    struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&server;

    sa6->sin6_family = AF_INET6;
    sa6->sin6_port = htons(config.bmp_daemon_port);
    slen = sizeof(struct sockaddr_in6);
  }
  else if (config.bmp_daemon_ip) {
    trim_spaces(config.bmp_daemon_ip);
    ret = str_to_addr(config.bmp_daemon_ip, &addr);
    if (!ret) {
      Log(LOG_ERR, "ERROR ( %s/%s ): 'bmp_daemon_ip' value is not a valid IPv4/IPv6 address. Terminating thread.\n", config.name, bmp_misc_db->log_str);
      exit_gracefully(1);
    }
    slen = addr_to_sa((struct sockaddr *)&server, &addr, config.bmp_daemon_port);
  }

  if (config.bmp_daemon_ip && config.pcap_savefile) {
    Log(LOG_ERR, "ERROR ( %s/%s ): bmp_daemon_ip and pcap_savefile directives are mutually exclusive. Exiting.\n", config.name, bmp_misc_db->log_str);
    exit_gracefully(1);
  }

  if (config.pcap_savefile && bmp_misc_db->is_thread) {
    Log(LOG_ERR, "ERROR ( %s/%s ): pcap_savefile directive only applies to pmbmpd. Exiting.\n", config.name, bmp_misc_db->log_str);
    exit_gracefully(1);
  } 

  if (!config.bmp_daemon_max_peers) config.bmp_daemon_max_peers = BMP_MAX_PEERS_DEFAULT;
  Log(LOG_INFO, "INFO ( %s/%s ): maximum BMP peers allowed: %d\n", config.name, bmp_misc_db->log_str, config.bmp_daemon_max_peers);

  bmp_peers = malloc(config.bmp_daemon_max_peers*sizeof(struct bmp_peer));
  if (!bmp_peers) {
    Log(LOG_ERR, "ERROR ( %s/%s ): Unable to malloc() BMP peers structure. Terminating thread.\n", config.name, bmp_misc_db->log_str);
    exit_gracefully(1);
  }
  memset(bmp_peers, 0, config.bmp_daemon_max_peers*sizeof(struct bmp_peer));

  if (config.rpki_roas_file || config.rpki_rtr_cache) {
    rpki_daemon_wrapper();

    /* Let's give the RPKI thread some advantage to create its structures */
    sleep(DEFAULT_SLOTH_SLEEP_TIME);
  }

  if (config.bmp_daemon_msglog_file || config.bmp_daemon_msglog_amqp_routing_key || config.bmp_daemon_msglog_kafka_topic) {
    if (config.bmp_daemon_msglog_file) bmp_misc_db->msglog_backend_methods++;
    if (config.bmp_daemon_msglog_amqp_routing_key) bmp_misc_db->msglog_backend_methods++;
    if (config.bmp_daemon_msglog_kafka_topic) bmp_misc_db->msglog_backend_methods++;

    if (bmp_misc_db->msglog_backend_methods > 1) {
      Log(LOG_ERR, "ERROR ( %s/%s ): bmp_daemon_msglog_file, bmp_daemon_msglog_amqp_routing_key and bmp_daemon_msglog_kafka_topic are mutually exclusive. Terminating thread.\n", config.name, bmp_misc_db->log_str);
      exit_gracefully(1);
    }
  }

  if (config.bmp_dump_file || config.bmp_dump_amqp_routing_key || config.bmp_dump_kafka_topic) {
    if (config.bmp_dump_file) bmp_misc_db->dump_backend_methods++;
    if (config.bmp_dump_amqp_routing_key) bmp_misc_db->dump_backend_methods++;
    if (config.bmp_dump_kafka_topic) bmp_misc_db->dump_backend_methods++;

    if (bmp_misc_db->dump_backend_methods > 1) {
      Log(LOG_ERR, "ERROR ( %s/%s ): bmp_dump_file, bmp_dump_amqp_routing_key and bmp_dump_kafka_topic are mutually exclusive. Terminating thread.\n", config.name, bmp_misc_db->log_str);
      exit_gracefully(1);
    }
  }

  if (bmp_misc_db->msglog_backend_methods || bmp_misc_db->dump_backend_methods)
    bgp_peer_log_seq_init(&bmp_misc_db->log_seq);

  if (bmp_misc_db->msglog_backend_methods) {
    bmp_misc_db->peers_log = malloc(config.bmp_daemon_max_peers*sizeof(struct bgp_peer_log));
    if (!bmp_misc_db->peers_log) {
      Log(LOG_ERR, "ERROR ( %s/%s ): Unable to malloc() BMP peers log structure. Terminating thread.\n", config.name, bmp_misc_db->log_str);
      exit_gracefully(1);
    }
    memset(bmp_misc_db->peers_log, 0, config.bmp_daemon_max_peers*sizeof(struct bgp_peer_log));

    if (config.bmp_daemon_msglog_amqp_routing_key) {
#ifdef WITH_RABBITMQ
      bmp_daemon_msglog_init_amqp_host();
      p_amqp_connect_to_publish(&bmp_daemon_msglog_amqp_host);

      if (!config.bmp_daemon_msglog_amqp_retry)
        config.bmp_daemon_msglog_amqp_retry = AMQP_DEFAULT_RETRY;
#else
      Log(LOG_WARNING, "WARN ( %s/%s ): p_amqp_connect_to_publish() not possible due to missing --enable-rabbitmq\n", config.name, bmp_misc_db->log_str);
#endif
    }

    if (config.bmp_daemon_msglog_kafka_topic) {
#ifdef WITH_KAFKA
      bmp_daemon_msglog_init_kafka_host();
#else
      Log(LOG_WARNING, "WARN ( %s/%s ): p_kafka_connect_to_produce() not possible due to missing --enable-kafka\n", config.name, bmp_misc_db->log_str);
#endif
    }
  }

  if (!config.bmp_table_attr_hash_buckets) config.bmp_table_attr_hash_buckets = HASHTABSIZE;
  bgp_attr_init(config.bmp_table_attr_hash_buckets, bmp_routing_db);

  if (!config.bmp_table_peer_buckets) config.bmp_table_peer_buckets = DEFAULT_BGP_INFO_HASH;
  if (!config.bmp_table_per_peer_buckets) config.bmp_table_per_peer_buckets = DEFAULT_BGP_INFO_PER_PEER_HASH;

  if (config.bmp_table_per_peer_hash == BGP_ASPATH_HASH_PATHID)
    bmp_route_info_modulo = bmp_route_info_modulo_pathid;
  else {
    Log(LOG_ERR, "ERROR ( %s/%s ): Unknown 'bmp_table_per_peer_hash' value. Terminating thread.\n", config.name, bmp_misc_db->log_str);
    exit_gracefully(1);
  }

  if (!config.pcap_savefile) {
    config.bmp_sock = socket(((struct sockaddr *)&server)->sa_family, SOCK_STREAM, 0);
    if (config.bmp_sock < 0) {
      /* retry with IPv4 */
      if (!config.bmp_daemon_ip) {
	struct sockaddr_in *sa4 = (struct sockaddr_in *)&server;

	sa4->sin_family = AF_INET;
	sa4->sin_addr.s_addr = htonl(0);
	sa4->sin_port = htons(config.bmp_daemon_port);
	slen = sizeof(struct sockaddr_in);

	config.bmp_sock = socket(((struct sockaddr *)&server)->sa_family, SOCK_STREAM, 0);
      }

      if (config.bmp_sock < 0) {
	Log(LOG_ERR, "ERROR ( %s/%s ): thread socket() failed. Terminating thread.\n", config.name, bmp_misc_db->log_str);
	exit_gracefully(1);
      }
    }

    setnonblocking(config.bmp_sock);
    setsockopt(config.bmp_sock, SOL_SOCKET, SO_KEEPALIVE, (void *)&yes, sizeof(yes));

    if (config.bmp_daemon_ipprec) {
      int opt = config.bmp_daemon_ipprec << 5;

      rc = setsockopt(config.bmp_sock, IPPROTO_IP, IP_TOS, &opt, (socklen_t) sizeof(opt));
      if (rc < 0) Log(LOG_ERR, "WARN ( %s/%s ): setsockopt() failed for IP_TOS (errno: %d).\n", config.name, bmp_misc_db->log_str, errno);
    }

#if (defined HAVE_SO_REUSEPORT)
    rc = setsockopt(config.bmp_sock, SOL_SOCKET, SO_REUSEPORT, (char *)&yes, (socklen_t) sizeof(yes));
    if (rc < 0) Log(LOG_ERR, "WARN ( %s/%s ): setsockopt() failed for SO_REUSEPORT (errno: %d).\n", config.name, bmp_misc_db->log_str, errno);
#endif

    rc = setsockopt(config.bmp_sock, SOL_SOCKET, SO_REUSEADDR, (char *)&yes, (socklen_t) sizeof(yes));
    if (rc < 0) Log(LOG_ERR, "WARN ( %s/%s ): setsockopt() failed for SO_REUSEADDR (errno: %d).\n", config.name, bmp_misc_db->log_str, errno);

    if (config.bmp_daemon_ipv6_only) {
      int yes=1;

      rc = setsockopt(config.bmp_sock, IPPROTO_IPV6, IPV6_V6ONLY, (char *) &yes, (socklen_t) sizeof(yes));
      if (rc < 0) Log(LOG_ERR, "WARN ( %s/%s ): setsockopt() failed for IPV6_V6ONLY (errno: %d).\n", config.name, bmp_misc_db->log_str, errno);
    }

    if (config.bmp_daemon_pipe_size) {
      socklen_t l = sizeof(config.bmp_daemon_pipe_size);
      int saved = 0, obtained = 0;

      getsockopt(config.bmp_sock, SOL_SOCKET, SO_RCVBUF, &saved, &l);
      Setsocksize(config.bmp_sock, SOL_SOCKET, SO_RCVBUF, &config.bmp_daemon_pipe_size, (socklen_t) sizeof(config.bmp_daemon_pipe_size));
      getsockopt(config.bmp_sock, SOL_SOCKET, SO_RCVBUF, &obtained, &l);

      Setsocksize(config.bmp_sock, SOL_SOCKET, SO_RCVBUF, &saved, l);
      getsockopt(config.bmp_sock, SOL_SOCKET, SO_RCVBUF, &obtained, &l);
      Log(LOG_INFO, "INFO ( %s/%s ): bmp_daemon_pipe_size: obtained=%d target=%d.\n", config.name, bmp_misc_db->log_str, obtained, config.bmp_daemon_pipe_size);
    }

    rc = bind(config.bmp_sock, (struct sockaddr *) &server, slen);
    if (rc < 0) {
      char null_ip_address[] = "0.0.0.0";
      char *ip_address;

      ip_address = config.bmp_daemon_ip ? config.bmp_daemon_ip : null_ip_address;
      Log(LOG_ERR, "ERROR ( %s/%s ): bind() to ip=%s port=%d/tcp failed (errno: %d).\n", config.name, bmp_misc_db->log_str, ip_address, config.bmp_daemon_port, errno);
      exit_gracefully(1);
    }

    rc = listen(config.bmp_sock, 1);
    if (rc < 0) {
      Log(LOG_ERR, "ERROR ( %s/%s ): listen() failed (errno: %d).\n", config.name, bmp_misc_db->log_str, errno);
      exit_gracefully(1);
    }

    {
      char srv_string[INET6_ADDRSTRLEN];
      struct host_addr srv_addr;
      u_int16_t srv_port;

      sa_to_addr((struct sockaddr *)&server, &srv_addr, &srv_port);
      addr_to_str(srv_string, &srv_addr);
      Log(LOG_INFO, "INFO ( %s/%s ): waiting for BMP data on %s:%u\n", config.name, bmp_misc_db->log_str, srv_string, srv_port);
    }

    /* Preparing ACL, if any */
    if (config.bmp_daemon_allow_file) load_allow_file(config.bmp_daemon_allow_file, &allow);
  }
  else {
    open_pcap_savefile(&device, config.pcap_savefile);
    pm_pcap_add_filter(&device);
    config.bmp_sock = pcap_get_selectable_fd(device.dev_desc);

    enable_ip_fragment_handler();

    Log(LOG_INFO, "INFO ( %s/core ): reading BMP data from: %s\n", config.name, config.pcap_savefile);
    allowed = TRUE;

    sleep(2);
  }

  /* Preparing for syncronous I/O multiplexing */
  select_fd = 0;
  FD_ZERO(&bkp_read_descs);
  FD_SET(config.bmp_sock, &bkp_read_descs);

  /* Let's initialize clean shared RIB */
  for (afi = AFI_IP; afi < AFI_MAX; afi++) {
    for (safi = SAFI_UNICAST; safi < SAFI_MAX; safi++) {
      bmp_routing_db->rib[afi][safi] = bgp_table_init(afi, safi);
    }
  }

  /* BMP peers batching checks */
  if ((config.bmp_daemon_batch && !config.bmp_daemon_batch_interval) ||
      (config.bmp_daemon_batch_interval && !config.bmp_daemon_batch)) {
    Log(LOG_WARNING, "WARN ( %s/%s ): 'bmp_daemon_batch_interval' and 'bmp_daemon_batch' both set to zero.\n", config.name, bmp_misc_db->log_str);
    config.bmp_daemon_batch = 0;
    config.bmp_daemon_batch_interval = 0;
  }
  else bgp_batch_init(&bp_batch, config.bmp_daemon_batch, config.bmp_daemon_batch_interval);

  if (bmp_misc_db->msglog_backend_methods) {
#ifdef WITH_JANSSON
    if (!config.bmp_daemon_msglog_output) config.bmp_daemon_msglog_output = PRINT_OUTPUT_JSON;
#else
    Log(LOG_WARNING, "WARN ( %s/%s ): bmp_daemon_msglog_output set to json but will produce no output (missing --enable-jansson).\n", config.name, bmp_misc_db->log_str);
#endif

#ifdef WITH_AVRO
    if ((config.bmp_daemon_msglog_output == PRINT_OUTPUT_AVRO_BIN) ||
	(config.bmp_daemon_msglog_output == PRINT_OUTPUT_AVRO_JSON)) {
      assert(BMP_MSG_TYPE_MAX < BMP_LOG_TYPE_LOGINIT);
      assert(BMP_LOG_TYPE_MAX < MAX_AVRO_SCHEMA);

      bmp_misc_db->msglog_avro_schema[BMP_MSG_ROUTE_MONITOR] = p_avro_schema_build_bmp_rm(BGP_LOGDUMP_ET_LOG, "bmp_msglog_rm");
      bmp_misc_db->msglog_avro_schema[BMP_MSG_STATS] = p_avro_schema_build_bmp_stats("bmp_stats");
      bmp_misc_db->msglog_avro_schema[BMP_MSG_PEER_DOWN] = p_avro_schema_build_bmp_peer_down("bmp_peer_down");
      bmp_misc_db->msglog_avro_schema[BMP_MSG_PEER_UP] = p_avro_schema_build_bmp_peer_up("bmp_peer_up");
      bmp_misc_db->msglog_avro_schema[BMP_MSG_INIT] = p_avro_schema_build_bmp_init("bmp_init");
      bmp_misc_db->msglog_avro_schema[BMP_MSG_TERM] = p_avro_schema_build_bmp_term("bmp_term");
      bmp_misc_db->msglog_avro_schema[BMP_MSG_TMP_RPAT] = p_avro_schema_build_bmp_rpat("bmp_rpat");

      bmp_misc_db->msglog_avro_schema[BMP_LOG_TYPE_LOGINIT] = p_avro_schema_build_bmp_log_initclose(BGP_LOGDUMP_ET_LOG, "bmp_loginit");
      bmp_misc_db->msglog_avro_schema[BMP_LOG_TYPE_LOGCLOSE] = p_avro_schema_build_bmp_log_initclose(BGP_LOGDUMP_ET_LOG, "bmp_logclose");

      if (config.bmp_daemon_msglog_avro_schema_file) {
	char p_avro_schema_file[SRVBUFLEN];

	if (strlen(config.bmp_daemon_msglog_avro_schema_file) > (SRVBUFLEN - SUPERSHORTBUFLEN)) {
	  Log(LOG_ERR, "ERROR ( %s/%s ): 'bmp_daemon_msglog_avro_schema_file' too long. Exiting.\n", config.name, bmp_misc_db->log_str);
	  exit_gracefully(1);
	}

	write_avro_schema_to_file_with_suffix(config.bmp_daemon_msglog_avro_schema_file, "-bmp_msglog_rm",
					      p_avro_schema_file, bmp_misc_db->msglog_avro_schema[BMP_MSG_ROUTE_MONITOR]);

	write_avro_schema_to_file_with_suffix(config.bmp_daemon_msglog_avro_schema_file, "-bmp_stats",
					      p_avro_schema_file, bmp_misc_db->msglog_avro_schema[BMP_MSG_STATS]);

	write_avro_schema_to_file_with_suffix(config.bmp_daemon_msglog_avro_schema_file, "-bmp_peer_down",
					      p_avro_schema_file, bmp_misc_db->msglog_avro_schema[BMP_MSG_PEER_DOWN]);

	write_avro_schema_to_file_with_suffix(config.bmp_daemon_msglog_avro_schema_file, "-bmp_peer_up",
					      p_avro_schema_file, bmp_misc_db->msglog_avro_schema[BMP_MSG_PEER_UP]);

	write_avro_schema_to_file_with_suffix(config.bmp_daemon_msglog_avro_schema_file, "-bmp_init",
					      p_avro_schema_file, bmp_misc_db->msglog_avro_schema[BMP_MSG_INIT]);

	write_avro_schema_to_file_with_suffix(config.bmp_daemon_msglog_avro_schema_file, "-bmp_term",
					      p_avro_schema_file, bmp_misc_db->msglog_avro_schema[BMP_MSG_TERM]);

	write_avro_schema_to_file_with_suffix(config.bmp_daemon_msglog_avro_schema_file, "-bmp_rpat",
					      p_avro_schema_file, bmp_misc_db->msglog_avro_schema[BMP_MSG_TMP_RPAT]);

	write_avro_schema_to_file_with_suffix(config.bmp_daemon_msglog_avro_schema_file, "-bmp_loginit",
					      p_avro_schema_file, bmp_misc_db->msglog_avro_schema[BMP_LOG_TYPE_LOGINIT]);

	write_avro_schema_to_file_with_suffix(config.bmp_daemon_msglog_avro_schema_file, "-bmp_logclose",
					      p_avro_schema_file, bmp_misc_db->msglog_avro_schema[BMP_LOG_TYPE_LOGCLOSE]);
      }

      if (config.bmp_daemon_msglog_kafka_avro_schema_registry) {
#ifdef WITH_SERDES
        if (strchr(config.bmp_daemon_msglog_kafka_topic, '$')) {
	  Log(LOG_ERR, "ERROR ( %s/%s ): dynamic 'bmp_daemon_msglog_kafka_topic' is not compatible with 'bmp_daemon_msglog_kafka_avro_schema_registry'. Exiting.\n",
	      config.name, bmp_misc_db->log_str);
	  exit_gracefully(1);
	}

	if (config.bmp_daemon_msglog_output == PRINT_OUTPUT_AVRO_JSON) {
	  Log(LOG_ERR, "ERROR ( %s/%s ): 'avro_json' output is not compatible with 'bmp_daemon_msglog_kafka_avro_schema_registry'. Exiting.\n",
	      config.name, bmp_misc_db->log_str);
	  exit_gracefully(1);
        }
	
	bmp_daemon_msglog_prepare_sd_schemas();
#endif
      }
    }
#endif
  }

  if (bmp_misc_db->dump_backend_methods) {
    if (!config.bmp_dump_workers) {
      config.bmp_dump_workers = 1;
    }

#ifdef WITH_JANSSON
    if (!config.bmp_dump_output) {
      config.bmp_dump_output = PRINT_OUTPUT_JSON;
    }
#else
    Log(LOG_WARNING, "WARN ( %s/%s ): bmp_table_dump_output set to json but will produce no output (missing --enable-jansson).\n", config.name, bmp_misc_db->log_str);
#endif

#ifdef WITH_AVRO
    if ((config.bmp_dump_output == PRINT_OUTPUT_AVRO_BIN) || 
	(config.bmp_dump_output == PRINT_OUTPUT_AVRO_JSON)) {
      assert(BMP_MSG_TYPE_MAX < BMP_LOG_TYPE_LOGINIT);
      assert(BMP_LOG_TYPE_MAX < MAX_AVRO_SCHEMA);

      bmp_misc_db->dump_avro_schema[BMP_MSG_ROUTE_MONITOR] = p_avro_schema_build_bmp_rm(BGP_LOGDUMP_ET_DUMP, "bmp_dump_rm");
      bmp_misc_db->dump_avro_schema[BMP_MSG_STATS] = p_avro_schema_build_bmp_stats("bmp_stats");
      bmp_misc_db->dump_avro_schema[BMP_MSG_PEER_DOWN] = p_avro_schema_build_bmp_peer_down("bmp_peer_down");
      bmp_misc_db->dump_avro_schema[BMP_MSG_PEER_UP] = p_avro_schema_build_bmp_peer_up("bmp_peer_up");
      bmp_misc_db->dump_avro_schema[BMP_MSG_INIT] = p_avro_schema_build_bmp_init("bmp_init");
      bmp_misc_db->dump_avro_schema[BMP_MSG_TERM] = p_avro_schema_build_bmp_term("bmp_term");
      bmp_misc_db->dump_avro_schema[BMP_MSG_TMP_RPAT] = p_avro_schema_build_bmp_rpat("bmp_rpat");

      bmp_misc_db->dump_avro_schema[BMP_LOG_TYPE_DUMPINIT] = p_avro_schema_build_bmp_dump_init(BGP_LOGDUMP_ET_DUMP, "bmp_dumpinit");
      bmp_misc_db->dump_avro_schema[BMP_LOG_TYPE_DUMPCLOSE] = p_avro_schema_build_bmp_dump_close(BGP_LOGDUMP_ET_DUMP, "bmp_dumpclose");

      if (config.bmp_dump_avro_schema_file) {
	char p_avro_schema_file[SRVBUFLEN];

	if (strlen(config.bmp_dump_avro_schema_file) > (SRVBUFLEN - SUPERSHORTBUFLEN)) {
	  Log(LOG_ERR, "ERROR ( %s/%s ): 'bmp_table_dump_avro_schema_file' too long. Exiting ..\n", config.name, bmp_misc_db->log_str);
	  exit_gracefully(1);
	}

	write_avro_schema_to_file_with_suffix(config.bmp_dump_avro_schema_file, "-bmp_dump_rm",
					      p_avro_schema_file, bmp_misc_db->dump_avro_schema[BMP_MSG_ROUTE_MONITOR]);

	write_avro_schema_to_file_with_suffix(config.bmp_dump_avro_schema_file, "-bmp_stats",
					      p_avro_schema_file, bmp_misc_db->dump_avro_schema[BMP_MSG_STATS]);

	write_avro_schema_to_file_with_suffix(config.bmp_dump_avro_schema_file, "-bmp_peer_down",
					      p_avro_schema_file, bmp_misc_db->dump_avro_schema[BMP_MSG_PEER_DOWN]);

	write_avro_schema_to_file_with_suffix(config.bmp_dump_avro_schema_file, "-bmp_peer_up",
					      p_avro_schema_file, bmp_misc_db->dump_avro_schema[BMP_MSG_PEER_UP]);

	write_avro_schema_to_file_with_suffix(config.bmp_dump_avro_schema_file, "-bmp_init",
					      p_avro_schema_file, bmp_misc_db->dump_avro_schema[BMP_MSG_INIT]);

	write_avro_schema_to_file_with_suffix(config.bmp_dump_avro_schema_file, "-bmp_term",
					      p_avro_schema_file, bmp_misc_db->dump_avro_schema[BMP_MSG_TERM]);

	write_avro_schema_to_file_with_suffix(config.bmp_dump_avro_schema_file, "-bmp_rpat",
					      p_avro_schema_file, bmp_misc_db->dump_avro_schema[BMP_MSG_TMP_RPAT]);

	write_avro_schema_to_file_with_suffix(config.bmp_dump_avro_schema_file, "-bmp_dumpinit",
					      p_avro_schema_file, bmp_misc_db->dump_avro_schema[BMP_LOG_TYPE_DUMPINIT]);

	write_avro_schema_to_file_with_suffix(config.bmp_dump_avro_schema_file, "-bmp_dumpclose",
					      p_avro_schema_file, bmp_misc_db->dump_avro_schema[BMP_LOG_TYPE_DUMPCLOSE]);
      }
    }
#endif
  }

  if (bmp_misc_db->dump_backend_methods) {
    char dump_roundoff[] = "m";
    time_t tmp_time;

    if (config.bmp_dump_refresh_time) {
      gettimeofday(&bmp_misc_db->log_tstamp, NULL);
      dump_refresh_deadline = bmp_misc_db->log_tstamp.tv_sec;
      tmp_time = roundoff_time(dump_refresh_deadline, dump_roundoff);
      while ((tmp_time+config.bmp_dump_refresh_time) < dump_refresh_deadline) {
        tmp_time += config.bmp_dump_refresh_time;
      }
      dump_refresh_deadline = tmp_time;
      dump_refresh_deadline += config.bmp_dump_refresh_time; /* it's a deadline not a basetime */
    }
    else {
      config.bmp_dump_file = NULL;
      bmp_misc_db->dump_backend_methods = FALSE;
      Log(LOG_WARNING, "WARN ( %s/%s ): Invalid 'bmp_dump_refresh_time'.\n", config.name, bmp_misc_db->log_str);
    }
  }

#ifdef WITH_AVRO
  bmp_misc_db->avro_buf = malloc(LARGEBUFLEN);
  if (!bmp_misc_db->avro_buf) {
    Log(LOG_ERR, "ERROR ( %s/%s ): malloc() failed (avro_buf). Exiting ..\n", config.name, bmp_misc_db->log_str);
    exit_gracefully(1);
  }
  else memset(bmp_misc_db->avro_buf, 0, LARGEBUFLEN);
#endif

  if (config.bmp_daemon_msglog_kafka_avro_schema_registry || config.bmp_dump_kafka_avro_schema_registry) {
#ifndef WITH_SERDES
    Log(LOG_ERR, "ERROR ( %s/%s ): 'bmp_*_kafka_avro_schema_registry' require --enable-serdes. Exiting.\n", config.name, bmp_misc_db->log_str);
    exit_gracefully(1);
#endif
  }

  select_fd = bkp_select_fd = (config.bmp_sock + 1);
  recalc_fds = FALSE;

  bmp_link_misc_structs(bmp_misc_db);

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

    if (!bmp_misc_db->is_thread) {
      sigprocmask(SIG_UNBLOCK, &signal_set, NULL);
      sigprocmask(SIG_BLOCK, &signal_set, NULL);
    }

    if (recalc_fds) {
      select_fd = config.bmp_sock;
      max_peers_idx = -1; /* .. since valid indexes include 0 */

      for (peers_idx = 0; peers_idx < config.bmp_daemon_max_peers; peers_idx++) {
        if (select_fd < bmp_peers[peers_idx].self.fd) select_fd = bmp_peers[peers_idx].self.fd;
        if (bmp_peers[peers_idx].self.fd) max_peers_idx = peers_idx;
      }
      select_fd++;
      max_peers_idx++;

      bkp_select_fd = select_fd;
      recalc_fds = FALSE;
    }
    else select_fd = bkp_select_fd;

    memcpy(&read_descs, &bkp_read_descs, sizeof(bkp_read_descs));

    if (bmp_misc_db->dump_backend_methods) {
      int delta;

      calc_refresh_timeout_sec(dump_refresh_deadline, bmp_misc_db->log_tstamp.tv_sec, &delta);
      dump_refresh_timeout.tv_sec = delta;
      dump_refresh_timeout.tv_usec = 0;
      drt_ptr = &dump_refresh_timeout;
    }
    else drt_ptr = NULL;

    select_num = select(select_fd, &read_descs, NULL, NULL, drt_ptr);
    if (select_num < 0) goto select_again;

    if (reload_map_bmp_thread) {
      if (config.bmp_daemon_allow_file) load_allow_file(config.bmp_daemon_allow_file, &allow);

      reload_map_bmp_thread = FALSE;
    }

    if (reload_log_bmp_thread) {
      for (peers_idx = 0; peers_idx < config.bmp_daemon_max_peers; peers_idx++) {
        if (bmp_misc_db->peers_log[peers_idx].fd) {
          fclose(bmp_misc_db->peers_log[peers_idx].fd);
          bmp_misc_db->peers_log[peers_idx].fd = open_output_file(bmp_misc_db->peers_log[peers_idx].filename, "a", FALSE);
	  setlinebuf(bmp_misc_db->peers_log[peers_idx].fd);
        }
        else break;
      }

      reload_log_bmp_thread = FALSE;
    }

    if (reload_log && !bmp_misc_db->is_thread) {
      reload_logs();
      reload_log = FALSE;
    }

    if (bmp_misc_db->msglog_backend_methods || bmp_misc_db->dump_backend_methods) {
      gettimeofday(&bmp_misc_db->log_tstamp, NULL);
      compose_timestamp(bmp_misc_db->log_tstamp_str, SRVBUFLEN, &bmp_misc_db->log_tstamp, TRUE,
			config.timestamps_since_epoch, config.timestamps_rfc3339, config.timestamps_utc);

      /* if dumping, let's reset log sequence at the next dump event */
      if (!bmp_misc_db->dump_backend_methods) {
	if (bgp_peer_log_seq_has_ro_bit(&bmp_misc_db->log_seq))
	  bgp_peer_log_seq_init(&bmp_misc_db->log_seq);
      }

      if (bmp_misc_db->dump_backend_methods) {
        while (bmp_misc_db->log_tstamp.tv_sec > dump_refresh_deadline) {
          bmp_misc_db->dump.tstamp.tv_sec = dump_refresh_deadline;
          bmp_misc_db->dump.tstamp.tv_usec = 0;
          compose_timestamp(bmp_misc_db->dump.tstamp_str, SRVBUFLEN, &bmp_misc_db->dump.tstamp, FALSE,
			    config.timestamps_since_epoch, config.timestamps_rfc3339, config.timestamps_utc);
	  bmp_misc_db->dump.period = config.bmp_dump_refresh_time;

	  if (bgp_peer_log_seq_has_ro_bit(&bmp_misc_db->log_seq))
	    bgp_peer_log_seq_init(&bmp_misc_db->log_seq);

          bmp_handle_dump_event(max_peers_idx);

          dump_refresh_deadline += config.bmp_dump_refresh_time;
        }
      }

#ifdef WITH_RABBITMQ
      if (config.bmp_daemon_msglog_amqp_routing_key) {
        time_t last_fail = P_broker_timers_get_last_fail(&bmp_daemon_msglog_amqp_host.btimers);

        if (last_fail && ((last_fail + P_broker_timers_get_retry_interval(&bmp_daemon_msglog_amqp_host.btimers)) <= bmp_misc_db->log_tstamp.tv_sec)) {
          bmp_daemon_msglog_init_amqp_host();
          p_amqp_connect_to_publish(&bmp_daemon_msglog_amqp_host);
        }
      }
#endif

#ifdef WITH_KAFKA
      if (config.bmp_daemon_msglog_kafka_topic) {
        time_t last_fail = P_broker_timers_get_last_fail(&bmp_daemon_msglog_kafka_host.btimers);

        if (last_fail && ((last_fail + P_broker_timers_get_retry_interval(&bmp_daemon_msglog_kafka_host.btimers)) <= bmp_misc_db->log_tstamp.tv_sec))
          bmp_daemon_msglog_init_kafka_host();

	if (config.bmp_daemon_msglog_kafka_avro_schema_registry) {
#ifdef WITH_SERDES
	  bmp_daemon_msglog_prepare_sd_schemas();
#endif
	}
      }
#endif
    }

    /* 
       If select_num == 0 then we got out of select() due to a timeout rather
       than because we had a message from a peer to handle. By now we did all
       routine checks and can happily return to select() again.
    */
    if (!select_num) goto select_again;

    if (config.pcap_savefile) {
      struct bmp_peer pcap_savefile_peer;

      sf_ret = recvfrom_savefile(&device, (void **) &bmp_packet, (struct sockaddr *) &client, NULL, &pcap_savefile_round, &recv_pptrs);

      if (bmp_packet && (sf_ret >= BMP_CMN_HDRLEN)) {
	struct bmp_common_hdr *bch = (struct bmp_common_hdr *) bmp_packet;

	if (bch->version == BMP_V3 ||  bch->version == BMP_V4) {
          fd = config.bmp_sock;

	  memset(&pcap_savefile_peer, 0, sizeof(pcap_savefile_peer));
	  sa_to_addr((struct sockaddr *) &client, &pcap_savefile_peer.self.addr, &pcap_savefile_peer.self.tcp_port);

	  for (peer = NULL, peers_idx = 0; peers_idx < config.bmp_daemon_max_peers; peers_idx++) {
	    if (!sa_addr_cmp((struct sockaddr *) &client, &bmp_peers[peers_idx].self.addr) &&
		!sa_port_cmp((struct sockaddr *) &client, bmp_peers[peers_idx].self.tcp_port)) {
	      peer = &bmp_peers[peers_idx].self;
	      bmpp = &bmp_peers[peers_idx];
	      FD_CLR(config.bmp_sock, &read_descs);
	      break;
	    }
	  }
	}
        else {
	  goto select_again;
  	}
      }
      else {
	goto select_again;
      }
    }

    /* New connection is coming in */
    if (FD_ISSET(config.bmp_sock, &read_descs)) {
      int peers_check_idx, peers_num;

      if (!config.pcap_savefile) {
        fd = accept(config.bmp_sock, (struct sockaddr *) &client, &clen);
        if (fd == ERR) goto read_data;
      }

      ipv4_mapped_to_ipv4(&client);

      /* If an ACL is defined, here we check against and enforce it */
      if (allow.num) allowed = check_allow(&allow, (struct sockaddr *)&client);
      else allowed = TRUE;

      if (!allowed) {
	char disallowed_str[INET6_ADDRSTRLEN];

	sa_to_str(disallowed_str, sizeof(disallowed_str), (struct sockaddr *) &client);
	Log(LOG_INFO, "INFO ( %s/%s ): [%s] peer '%s' not allowed. close()\n", config.name, bmp_misc_db->log_str, config.bmp_daemon_allow_file, disallowed_str);

	close(fd);
	goto read_data;
      }

      for (peer = NULL, peers_idx = 0; peers_idx < config.bmp_daemon_max_peers; peers_idx++) {
        if (!bmp_peers[peers_idx].self.fd) {
          now = time(NULL);

          /*
             Admitted if:
             *  batching feature is disabled or
             *  we have room in the current batch or
             *  we can start a new batch 
          */
          if (bgp_batch_is_admitted(&bp_batch, now)) {
            peer = &bmp_peers[peers_idx].self;
	    bmpp = &bmp_peers[peers_idx];

            if (bmp_peer_init(bmpp, FUNC_TYPE_BMP)) {
	      peer = NULL;
	      bmpp = NULL;
	    }
            else recalc_fds = TRUE;

            log_notification_unset(&log_notifications.bgp_peers_throttling);

            if (bgp_batch_is_enabled(&bp_batch) && peer) {
              if (bgp_batch_is_expired(&bp_batch, now)) bgp_batch_reset(&bp_batch, now);
              if (bgp_batch_is_not_empty(&bp_batch)) bgp_batch_decrease_counter(&bp_batch);
            }

            break;
          }
          else { /* throttle */
            /* We briefly accept the new connection to be able to drop it */
            if (!log_notification_isset(&log_notifications.bmp_peers_throttling, now)) {
              Log(LOG_INFO, "INFO ( %s/%s ): throttling at BMP peer #%u\n", config.name, bmp_misc_db->log_str, peers_idx);
              log_notification_set(&log_notifications.bmp_peers_throttling, now, FALSE);
            }

            close(fd);
            goto read_data;
          }
        }
      }

      if (!peer) {
        /* We briefly accept the new connection to be able to drop it */
	if (!log_notification_isset(&log_notifications.bmp_peers_limit, now)) {
	  log_notification_set(&log_notifications.bmp_peers_limit, now, FALSE);
          Log(LOG_WARNING, "WARN ( %s/%s ): Insufficient number of BMP peers has been configured by 'bmp_daemon_max_peers' (%d).\n",
	      config.name, bmp_misc_db->log_str, config.bmp_daemon_max_peers);
	}

        close(fd);
        goto read_data;
      }

      peer->fd = fd;
      FD_SET(peer->fd, &bkp_read_descs);
      sa_to_addr((struct sockaddr *) &client, &peer->addr, &peer->tcp_port);
      addr_to_str(peer->addr_str, &peer->addr);
      memcpy(&peer->id, &peer->addr, sizeof(struct host_addr)); /* XXX: some inet_ntoa()'s could be around against peer->id */

      if (!config.bmp_daemon_parse_proxy_header) {
        if (bmp_misc_db->msglog_backend_methods) {
          bgp_peer_log_init(peer, config.bmp_daemon_msglog_output, FUNC_TYPE_BMP);
	}

        if (bmp_misc_db->dump_backend_methods) {
	  bmp_dump_init_peer(peer);
	}
      }

      /* Check: multiple TCP connections per peer */
      for (peers_check_idx = 0, peers_num = 0; peers_check_idx < config.bmp_daemon_max_peers; peers_check_idx++) {
        if (peers_idx != peers_check_idx && !memcmp(&bmp_peers[peers_check_idx].self.addr, &peer->addr, sizeof(bmp_peers[peers_check_idx].self.addr))) {
	  if (bmp_misc_db->is_thread && !config.bgp_daemon_to_xflow_agent_map) {
            Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Multiple connections from peer and no bgp_agent_map defined.\n",
		config.name, bmp_misc_db->log_str, bmp_peers[peers_check_idx].self.addr_str);
	  }
        }
        else {
          if (bmp_peers[peers_check_idx].self.fd) peers_num++;
        }
      }

      Log(LOG_INFO, "INFO ( %s/%s ): [%s] BMP peers usage: %u/%u\n", config.name, bmp_misc_db->log_str, peer->addr_str, peers_num, config.bmp_daemon_max_peers);
    }

    read_data:

    if (!config.pcap_savefile) {
      /*
	We have something coming in: let's lookup which peer is that.
	FvD: To avoid starvation of the "later established" peers, we
	offset the start of the search in a round-robin style.
      */
      for (peer = NULL, peers_idx = 0; peers_idx < max_peers_idx; peers_idx++) {
	int loc_idx = (peers_idx + peers_idx_rr) % max_peers_idx;

	if (bmp_peers[loc_idx].self.fd && FD_ISSET(bmp_peers[loc_idx].self.fd, &read_descs)) {
	  peer = &bmp_peers[loc_idx].self;
	  bmpp = &bmp_peers[loc_idx];
	  peers_idx_rr = (peers_idx_rr + 1) % max_peers_idx;
	  break;
	}
      }
    }

    if (!peer) goto select_again;

    /* If first message after connect, check for proxy protocol header */
    if (config.bmp_daemon_parse_proxy_header && !peer->parsed_proxy_header) {
      ret = parse_proxy_header(peer->fd, &peer->addr, &peer->tcp_port);
      if (ret < 0) {
        goto select_again; /* partial header */
      }
      addr_to_str(peer->addr_str, &peer->addr);

      if (bmp_misc_db->msglog_backend_methods) {
        bgp_peer_log_init(peer, config.bmp_daemon_msglog_output, FUNC_TYPE_BMP);
      }

      if (bmp_misc_db->dump_backend_methods) {
        bmp_dump_init_peer(peer);
      }
    }
    peer->parsed_proxy_header = TRUE;

    if (!config.pcap_savefile) {
      if (!peer->buf.exp_len) {
	ret = recv(peer->fd, &peer->buf.base[peer->buf.cur_len], (BMP_CMN_HDRLEN - peer->buf.cur_len), 0);

	if (ret > 0) {
	  peer->buf.cur_len += ret;

	  if (peer->buf.cur_len  == BMP_CMN_HDRLEN) {
	    struct bmp_common_hdr *bhdr = (struct bmp_common_hdr *) peer->buf.base;

	    if (bhdr->version != BMP_V3 && bhdr->version != BMP_V4) {
	      Log(LOG_INFO, "INFO ( %s/%s ): [%s] packet discarded: unknown BMP version: %u (1)\n",
		  config.name, bmp_misc_db->log_str, peer->addr_str, bhdr->version);

	      peer->msglen = 0;
	      peer->buf.cur_len = 0;
	      peer->buf.exp_len = 0;
	      ret = ERR;
	    }
	    else {
	      peer->buf.exp_len = ntohl(bhdr->len);

	      /* commit */
	      if (peer->buf.cur_len == peer->buf.exp_len) {
		peer->msglen = peer->buf.exp_len;
		peer->buf.cur_len = 0;
		peer->buf.exp_len = 0;
	      }
	    }
	  }
	  else {
	    goto select_again;
	  }
	}
      }

      if (peer->buf.exp_len) {
	int sink_mode = FALSE;

        if (peer->buf.exp_len <= peer->buf.tot_len) { 
	  ret = recv(peer->fd, &peer->buf.base[peer->buf.cur_len], (peer->buf.exp_len - peer->buf.cur_len), 0);
	}
	/* sink mode */
	else {
	  ret = recv(peer->fd, peer->buf.base, MIN(peer->buf.tot_len, (peer->buf.exp_len - peer->buf.cur_len)), 0);
	  sink_mode = TRUE;

	  Log(LOG_WARNING, "WARN ( %s/%s ): [%s] long BMP message received: len=%u buf=%u. Sinking.\n",
	      config.name, bmp_misc_db->log_str, peer->addr_str, peer->buf.exp_len, BGP_BUFFER_SIZE);
	}

	if (ret > 0) {
	  peer->buf.cur_len += ret;

	  /* commit */
	  if (peer->buf.cur_len == peer->buf.exp_len) {
	    peer->msglen = peer->buf.exp_len;
	    peer->buf.cur_len = 0;
	    peer->buf.exp_len = 0;
	  }
	  else {
	    goto select_again;
	  }
	}

        if (sink_mode) {
	  goto select_again;
	}
      }

      if (ret <= 0) {
        Log(LOG_INFO, "INFO ( %s/%s ): [%s] BMP connection reset by peer (%d).\n", config.name, bmp_misc_db->log_str, peer->addr_str, errno);
        FD_CLR(peer->fd, &bkp_read_descs);
        bmp_peer_close(bmpp, FUNC_TYPE_BMP);
        recalc_fds = TRUE;
        goto select_again;
      }
    }
    else {
      u_int32_t len = MIN(sf_ret, peer->buf.tot_len);

      /* recvfrom_savefile() already invoked before */
      memcpy(peer->buf.base, bmp_packet, len);
      peer->msglen = len;
    }

    do_term = FALSE;
    bmp_process_packet(peer->buf.base, peer->msglen, bmpp, &do_term);

    if (do_term) {
      Log(LOG_INFO, "INFO ( %s/%s ): [%s] BMP Term message received. Closing up.\n", config.name, bmp_misc_db->log_str, peer->addr_str);
      FD_CLR(peer->fd, &bkp_read_descs);
      bmp_peer_close(bmpp, FUNC_TYPE_BMP);
      recalc_fds = TRUE;
      goto select_again;
    }
  }

  return SUCCESS;
}

void bmp_prepare_thread()
{
  bmp_misc_db = &inter_domain_misc_dbs[FUNC_TYPE_BMP];
  memset(bmp_misc_db, 0, sizeof(struct bgp_misc_structs));

  bmp_misc_db->is_thread = TRUE;

  if (config.rpki_roas_file || config.rpki_rtr_cache) {
    bmp_misc_db->bnv = malloc(sizeof(struct bgp_node_vector));
    memset(bmp_misc_db->bnv, 0, sizeof(struct bgp_node_vector));
  }

  bmp_misc_db->log_str = malloc(strlen("core/BMP") + 1);
  strcpy(bmp_misc_db->log_str, "core/BMP");
}

void bmp_prepare_daemon()
{
  bmp_misc_db = &inter_domain_misc_dbs[FUNC_TYPE_BMP];
  memset(bmp_misc_db, 0, sizeof(struct bgp_misc_structs));

  bmp_misc_db->is_thread = FALSE;

  if (config.rpki_roas_file || config.rpki_rtr_cache) {
    bmp_misc_db->bnv = malloc(sizeof(struct bgp_node_vector));
    memset(bmp_misc_db->bnv, 0, sizeof(struct bgp_node_vector));
  }

  bmp_misc_db->log_str = malloc(strlen("core") + 1);
  strcpy(bmp_misc_db->log_str, "core");
}

void bmp_daemon_msglog_prepare_sd_schemas()
{
#ifdef WITH_SERDES
  time_t last_fail = P_broker_timers_get_last_fail(&bmp_daemon_msglog_kafka_host.sd_schema_timers);

  if ((last_fail + P_broker_timers_get_retry_interval(&bmp_daemon_msglog_kafka_host.sd_schema_timers)) <= bmp_misc_db->log_tstamp.tv_sec) {
    if (!bmp_daemon_msglog_kafka_host.sd_schema[BMP_MSG_ROUTE_MONITOR]) {
      bmp_daemon_msglog_kafka_host.sd_schema[BMP_MSG_ROUTE_MONITOR] = compose_avro_schema_registry_name_2(config.bmp_daemon_msglog_kafka_topic, FALSE,
												     bmp_misc_db->msglog_avro_schema[BMP_MSG_ROUTE_MONITOR],
												     "bmp", "msglog_rm",
												     config.bmp_daemon_msglog_kafka_avro_schema_registry);
      if (!bmp_daemon_msglog_kafka_host.sd_schema[BMP_MSG_ROUTE_MONITOR]) goto exit_lane;
    }

    if (!bmp_daemon_msglog_kafka_host.sd_schema[BMP_MSG_STATS]) {
      bmp_daemon_msglog_kafka_host.sd_schema[BMP_MSG_STATS] = compose_avro_schema_registry_name_2(config.bmp_daemon_msglog_kafka_topic, FALSE,
												     bmp_misc_db->msglog_avro_schema[BMP_MSG_STATS],
												     "bmp", "stats",
												     config.bmp_daemon_msglog_kafka_avro_schema_registry);
      if (!bmp_daemon_msglog_kafka_host.sd_schema[BMP_MSG_STATS]) goto exit_lane;
    }

    if (!bmp_daemon_msglog_kafka_host.sd_schema[BMP_MSG_PEER_UP]) {
      bmp_daemon_msglog_kafka_host.sd_schema[BMP_MSG_PEER_UP]= compose_avro_schema_registry_name_2(config.bmp_daemon_msglog_kafka_topic, FALSE,
												     bmp_misc_db->msglog_avro_schema[BMP_MSG_PEER_UP],
												     "bmp", "peer_up",
												     config.bmp_daemon_msglog_kafka_avro_schema_registry);
      if (!bmp_daemon_msglog_kafka_host.sd_schema[BMP_MSG_PEER_UP]) goto exit_lane;
    }

    if (!bmp_daemon_msglog_kafka_host.sd_schema[BMP_MSG_PEER_DOWN]) {
      bmp_daemon_msglog_kafka_host.sd_schema[BMP_MSG_PEER_DOWN] = compose_avro_schema_registry_name_2(config.bmp_daemon_msglog_kafka_topic, FALSE,
												     bmp_misc_db->msglog_avro_schema[BMP_MSG_PEER_DOWN],
												     "bmp", "peer_down",
												     config.bmp_daemon_msglog_kafka_avro_schema_registry);
      if (!bmp_daemon_msglog_kafka_host.sd_schema[BMP_MSG_PEER_DOWN]) goto exit_lane;
    }

    if (!bmp_daemon_msglog_kafka_host.sd_schema[BMP_MSG_INIT]) {
      bmp_daemon_msglog_kafka_host.sd_schema[BMP_MSG_INIT] = compose_avro_schema_registry_name_2(config.bmp_daemon_msglog_kafka_topic, FALSE,
												     bmp_misc_db->msglog_avro_schema[BMP_MSG_INIT],
												     "bmp", "init",
												     config.bmp_daemon_msglog_kafka_avro_schema_registry);
      if (!bmp_daemon_msglog_kafka_host.sd_schema[BMP_MSG_INIT]) goto exit_lane;
    }

    if (!bmp_daemon_msglog_kafka_host.sd_schema[BMP_MSG_TERM]) {
      bmp_daemon_msglog_kafka_host.sd_schema[BMP_MSG_TERM] = compose_avro_schema_registry_name_2(config.bmp_daemon_msglog_kafka_topic, FALSE,
												     bmp_misc_db->msglog_avro_schema[BMP_MSG_TERM],
												     "bmp", "term",
												     config.bmp_daemon_msglog_kafka_avro_schema_registry);
      if (!bmp_daemon_msglog_kafka_host.sd_schema[BMP_MSG_TERM]) goto exit_lane;
    }

    if (!bmp_daemon_msglog_kafka_host.sd_schema[BMP_MSG_TMP_RPAT]) {
      bmp_daemon_msglog_kafka_host.sd_schema[BMP_MSG_TMP_RPAT] = compose_avro_schema_registry_name_2(config.bmp_daemon_msglog_kafka_topic, FALSE,
												     bmp_misc_db->msglog_avro_schema[BMP_MSG_TMP_RPAT],
												     "bmp", "rpat",
												     config.bmp_daemon_msglog_kafka_avro_schema_registry);
      if (!bmp_daemon_msglog_kafka_host.sd_schema[BMP_MSG_TMP_RPAT]) goto exit_lane;
    }

    if (!bmp_daemon_msglog_kafka_host.sd_schema[BMP_LOG_TYPE_LOGINIT]) {
      bmp_daemon_msglog_kafka_host.sd_schema[BMP_LOG_TYPE_LOGINIT] = compose_avro_schema_registry_name_2(config.bmp_daemon_msglog_kafka_topic, FALSE,
												     bmp_misc_db->msglog_avro_schema[BMP_LOG_TYPE_LOGINIT],
												     "bmp", "loginit",
												     config.bmp_daemon_msglog_kafka_avro_schema_registry);
      if (!bmp_daemon_msglog_kafka_host.sd_schema[BMP_LOG_TYPE_LOGINIT]) goto exit_lane;
    }

    if (!bmp_daemon_msglog_kafka_host.sd_schema[BMP_LOG_TYPE_LOGCLOSE]) {
      bmp_daemon_msglog_kafka_host.sd_schema[BMP_LOG_TYPE_LOGCLOSE] = compose_avro_schema_registry_name_2(config.bmp_daemon_msglog_kafka_topic, FALSE,
												     bmp_misc_db->msglog_avro_schema[BMP_LOG_TYPE_LOGCLOSE],
												     "bmp", "logclose",
												     config.bmp_daemon_msglog_kafka_avro_schema_registry);
      if (!bmp_daemon_msglog_kafka_host.sd_schema[BMP_LOG_TYPE_LOGCLOSE]) goto exit_lane;
    }
  }

  return;

  exit_lane:
  P_broker_timers_set_last_fail(&bmp_daemon_msglog_kafka_host.sd_schema_timers, time(NULL));
#endif
}
