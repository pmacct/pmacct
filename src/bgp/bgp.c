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
#include "bgp.h"
#include "bgp_xcs.h"
#include "rpki/rpki.h"
#include "bgp_blackhole.h"
#include "thread_pool.h"
#if defined WITH_RABBITMQ
#include "amqp_common.h"
#endif
#ifdef WITH_KAFKA
#include "kafka_common.h"
#endif
#if defined WITH_ZMQ
#include "zmq_common.h"
#endif
#if defined WITH_AVRO
#include "plugin_cmn_avro.h"
#endif
#include "bgp_lg.h"

/* Global variables */
thread_pool_t *bgp_pool;
struct bgp_peer *peers;
struct bgp_peer_cache_bucket *peers_cache, *peers_port_cache;
char *std_comm_patterns[MAX_BGP_COMM_PATTERNS];
char *ext_comm_patterns[MAX_BGP_COMM_PATTERNS];
char *lrg_comm_patterns[MAX_BGP_COMM_PATTERNS];
char *std_comm_patterns_to_asn[MAX_BGP_COMM_PATTERNS];
char *lrg_comm_patterns_to_asn[MAX_BGP_COMM_PATTERNS];
struct bgp_comm_range peer_src_as_ifrange; 
struct bgp_comm_range peer_src_as_asrange; 
u_int32_t (*bgp_route_info_modulo)(struct bgp_peer *, path_id_t *, int);
struct bgp_rt_structs inter_domain_routing_dbs[FUNC_TYPE_MAX], *bgp_routing_db;
struct bgp_misc_structs inter_domain_misc_dbs[FUNC_TYPE_MAX], *bgp_misc_db;
struct bgp_xconnects bgp_xcs_map;

/* Functions */
void bgp_daemon_wrapper()
{
  /* initialize variables */
  if (!config.bgp_daemon_port) config.bgp_daemon_port = BGP_TCP_PORT;

#if defined WITH_ZMQ
  if (config.bgp_lg) bgp_lg_wrapper();
#else
  if (config.bgp_lg) {
    Log(LOG_ERR, "ERROR ( %s/core/lg ): 'bgp_daemon_lg' requires --enable-zmq. Exiting.\n", config.name);
    exit_gracefully(1);
  }
#endif

  /* initialize threads pool */
  bgp_pool = allocate_thread_pool(1);
  assert(bgp_pool);
  Log(LOG_DEBUG, "DEBUG ( %s/core/BGP ): %d thread(s) initialized\n", config.name, 1);
  bgp_prepare_thread();

  /* giving a kick to the BGP thread */
  send_to_pool(bgp_pool, skinny_bgp_daemon, NULL);
}

int skinny_bgp_daemon()
{
  skinny_bgp_daemon_online();

  return SUCCESS;
}

void skinny_bgp_daemon_online()
{
  int ret, rc, peers_idx, allowed, yes=1;
#if (defined IPV6_BINDV6ONLY)
  int no=0;
#endif
  int peers_idx_rr = 0, peers_xconnect_idx_rr = 0, max_peers_idx = 0;
  struct plugin_requests req;
  struct host_addr addr;
  struct bgp_peer *peer;
  struct bgp_peer_buf *peer_buf;
  char bgp_reply_pkt[BGP_BUFFER_SIZE], *bgp_reply_pkt_ptr;
  char bgp_peer_str[INET6_ADDRSTRLEN], bgp_xconnect_peer_str[BGP_XCONNECT_STRLEN];
  struct sockaddr_storage server, client;
  afi_t afi;
  safi_t safi;
  time_t now, dump_refresh_deadline = {0};
  struct hosts_table allow;
  struct bgp_md5_table bgp_md5;
  struct timeval dump_refresh_timeout, *drt_ptr;
  struct bgp_peer_batch bp_batch;
  socklen_t slen, clen = sizeof(client);

  sigset_t signal_set;

  /* select() stuff */
  fd_set read_descs, bkp_read_descs; 
  int fd, select_fd, bkp_select_fd, recalc_fds, select_num;
  int recv_fd, send_fd;

  /* initial cleanups */
  reload_map_bgp_thread = FALSE;
  reload_log_bgp_thread = FALSE;
  memset(&server, 0, sizeof(server));
  memset(&client, 0, sizeof(client));
  memset(&allow, 0, sizeof(struct hosts_table));

  bgp_routing_db = &inter_domain_routing_dbs[FUNC_TYPE_BGP];
  memset(bgp_routing_db, 0, sizeof(struct bgp_rt_structs));

  if (!config.bgp_table_attr_hash_buckets) config.bgp_table_attr_hash_buckets = HASHTABSIZE;
  bgp_attr_init(config.bgp_table_attr_hash_buckets, bgp_routing_db);

  /* socket creation for BGP server: IPv4 only */
  if (!config.bgp_daemon_ip) {
    struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&server;

    sa6->sin6_family = AF_INET6;
    sa6->sin6_port = htons(config.bgp_daemon_port);
    slen = sizeof(struct sockaddr_in6);
  }
  else {
    trim_spaces(config.bgp_daemon_ip);
    ret = str_to_addr(config.bgp_daemon_ip, &addr);
    if (!ret) {
      Log(LOG_ERR, "ERROR ( %s/%s ): 'bgp_daemon_ip' value is not a valid IPv4/IPv6 address. Terminating thread.\n", config.name, bgp_misc_db->log_str);
      exit_gracefully(1);
    }
    slen = addr_to_sa((struct sockaddr *)&server, &addr, config.bgp_daemon_port);
  }

  if (!config.bgp_daemon_max_peers) config.bgp_daemon_max_peers = MAX_BGP_PEERS_DEFAULT;
  Log(LOG_INFO, "INFO ( %s/%s ): maximum BGP peers allowed: %d\n", config.name, bgp_misc_db->log_str, config.bgp_daemon_max_peers);

  peers = malloc(config.bgp_daemon_max_peers*sizeof(struct bgp_peer));
  if (!peers) {
    Log(LOG_ERR, "ERROR ( %s/%s ): Unable to malloc() BGP peers structure. Terminating thread.\n", config.name, bgp_misc_db->log_str);
    exit_gracefully(1);
  }
  memset(peers, 0, config.bgp_daemon_max_peers*sizeof(struct bgp_peer));

  if (config.bgp_lg) {
    peers_cache = malloc(config.bgp_daemon_max_peers*sizeof(struct bgp_peer_cache_bucket));
    if (!peers_cache) {
      Log(LOG_ERR, "ERROR ( %s/%s ): Unable to malloc() BGP peers cache structure. Terminating thread.\n", config.name, bgp_misc_db->log_str);
      exit_gracefully(1);
    }

    bgp_peer_cache_init(peers_cache, config.bgp_daemon_max_peers);

    peers_port_cache = malloc(config.bgp_daemon_max_peers*sizeof(struct bgp_peer_cache_bucket));
    if (!peers_port_cache) {
      Log(LOG_ERR, "ERROR ( %s/%s ): Unable to malloc() BGP peers cache structure (2). Terminating thread.\n", config.name, bgp_misc_db->log_str);
      exit_gracefully(1);
    }

    bgp_peer_cache_init(peers_port_cache, config.bgp_daemon_max_peers);
  }
  else {
    peers_cache = NULL;
    peers_port_cache = NULL;
  }

  if (config.bgp_xconnect_map) {
    int bgp_xcs_allocated = FALSE;
    int bgp_xcs_size = config.maps_entries ? config.maps_entries : MAX_PRETAG_MAP_ENTRIES;

    if (config.acct_type != ACCT_PMBGP) {
      Log(LOG_ERR, "ERROR ( %s/%s ): bgp_daemon_xconnect_map feature not supported for this daemon. Exiting ...\n", config.name, config.type);
      exit_gracefully(1);
    }

    memset(&bgp_xcs_map, 0, sizeof(bgp_xcs_map));
    memset(&req, 0, sizeof(req));

    /* Setting up the pool */
    bgp_xcs_map.pool = malloc(bgp_xcs_size * sizeof(struct bgp_xconnect));
    if (!bgp_xcs_map.pool) {
      Log(LOG_ERR, "ERROR ( %s/%s ): unable to allocate BGP xconnect pool. Exiting ...\n", config.name, config.type);
      exit_gracefully(1);
    }
    else memset(bgp_xcs_map.pool, 0, bgp_xcs_size * sizeof(struct bgp_xconnect));

    req.key_value_table = (void *) &bgp_xcs_map;
    req.map_entries = bgp_xcs_size;
    load_id_file(MAP_BGP_XCS, config.bgp_xconnect_map, NULL, &req, &bgp_xcs_allocated);
  }
  else {
    bgp_xcs_map.pool = 0;
    bgp_xcs_map.num = 0;
  }

  if (config.rpki_roas_file || config.rpki_rtr_cache) {
    rpki_daemon_wrapper();

    /* Let's give the RPKI thread some advantage to create its structures */
    sleep(DEFAULT_SLOTH_SLEEP_TIME);
  }

  if (config.bgp_blackhole_stdcomm_list) {
#if defined WITH_ZMQ
    struct p_zmq_host *bgp_blackhole_zmq_host = NULL;
    char inproc_blackhole_str[] = "inproc://bgp_blackhole";
    (void)inproc_blackhole_str;

    bgp_blackhole_daemon_wrapper();

    /* Let's give the BGP blackhole thread some advantage to create its structures */
    sleep(DEFAULT_SLOTH_SLEEP_TIME);

    bgp_blackhole_zmq_host = bgp_blackhole_misc_db->bgp_blackhole_zmq_host;
    p_zmq_push_connect_setup(bgp_blackhole_zmq_host);
#else
    Log(LOG_ERR, "ERROR ( %s/%s ): 'bgp_blackhole_stdcomm_list' requires compiling with --enable-zmq. Exiting ..\n", config.name, bgp_misc_db->log_str);
    exit_gracefully(1);
#endif
  }

  if (config.bgp_daemon_msglog_file || config.bgp_daemon_msglog_amqp_routing_key || config.bgp_daemon_msglog_kafka_topic) {
    if (config.bgp_daemon_msglog_file) bgp_misc_db->msglog_backend_methods++;
    if (config.bgp_daemon_msglog_amqp_routing_key) bgp_misc_db->msglog_backend_methods++;
    if (config.bgp_daemon_msglog_kafka_topic) bgp_misc_db->msglog_backend_methods++;

    if (bgp_misc_db->msglog_backend_methods > 1) {
      Log(LOG_ERR, "ERROR ( %s/%s ): bgp_daemon_msglog_file, bgp_daemon_msglog_amqp_routing_key and bgp_daemon_msglog_kafka_topic are mutually exclusive. Terminating thread.\n", config.name, bgp_misc_db->log_str);
      exit_gracefully(1);
    }

    bgp_misc_db->peers_log = malloc(config.bgp_daemon_max_peers*sizeof(struct bgp_peer_log));
    if (!bgp_misc_db->peers_log) {
      Log(LOG_ERR, "ERROR ( %s/%s ): Unable to malloc() BGP peers log structure. Terminating thread.\n", config.name, bgp_misc_db->log_str);
      exit_gracefully(1);
    }
    memset(bgp_misc_db->peers_log, 0, config.bgp_daemon_max_peers*sizeof(struct bgp_peer_log));
    bgp_peer_log_seq_init(&bgp_misc_db->log_seq);

    if (config.bgp_daemon_msglog_amqp_routing_key) {
#ifdef WITH_RABBITMQ
      bgp_daemon_msglog_init_amqp_host();
      p_amqp_connect_to_publish(&bgp_daemon_msglog_amqp_host);
#else
      Log(LOG_WARNING, "WARN ( %s/%s ): p_amqp_connect_to_publish() not possible due to missing --enable-rabbitmq\n", config.name, bgp_misc_db->log_str);
#endif
    }

    if (config.bgp_daemon_msglog_kafka_topic) {
#ifdef WITH_KAFKA
      bgp_daemon_msglog_init_kafka_host();
#else
      Log(LOG_WARNING, "WARN ( %s/%s ): p_kafka_connect_to_produce() not possible due to missing --enable-kafka\n", config.name, bgp_misc_db->log_str);
#endif
    }
  }

  if (config.bgp_table_dump_file || config.bgp_table_dump_amqp_routing_key || config.bgp_table_dump_kafka_topic) {
    if (config.bgp_table_dump_file) bgp_misc_db->dump_backend_methods++;
    if (config.bgp_table_dump_amqp_routing_key) bgp_misc_db->dump_backend_methods++;
    if (config.bgp_table_dump_kafka_topic) bgp_misc_db->dump_backend_methods++;

    if (bgp_misc_db->dump_backend_methods > 1) {
      Log(LOG_ERR, "ERROR ( %s/%s ): bgp_table_dump_file, bgp_table_dump_amqp_routing_key and bgp_table_dump_kafka_topic are mutually exclusive. Terminating thread.\n", config.name, bgp_misc_db->log_str);
      exit_gracefully(1);
    }
  }

  if ((bgp_misc_db->msglog_backend_methods || bgp_misc_db->dump_backend_methods) && config.bgp_xconnect_map) {
    Log(LOG_ERR, "ERROR ( %s/%s ): bgp_daemon_xconnect_map is mutually exclusive with any BGP msglog and dump method. Terminating thread.\n", config.name, bgp_misc_db->log_str);
    exit_gracefully(1);
  }

  if (!config.bgp_table_peer_buckets) config.bgp_table_peer_buckets = DEFAULT_BGP_INFO_HASH;
  if (!config.bgp_table_per_peer_buckets) config.bgp_table_per_peer_buckets = DEFAULT_BGP_INFO_PER_PEER_HASH;

  if (config.bgp_table_per_peer_hash == BGP_ASPATH_HASH_PATHID)
    bgp_route_info_modulo = bgp_route_info_modulo_pathid; 
  else {
    Log(LOG_ERR, "ERROR ( %s/%s ): Unknown 'bgp_table_per_peer_hash' value. Terminating thread.\n", config.name, bgp_misc_db->log_str);
    exit_gracefully(1);
  }

  config.bgp_sock = socket(((struct sockaddr *)&server)->sa_family, SOCK_STREAM, 0);
  if (config.bgp_sock < 0) {
    /* retry with IPv4 */
    if (!config.bgp_daemon_ip) {
      struct sockaddr_in *sa4 = (struct sockaddr_in *)&server;

      sa4->sin_family = AF_INET;
      sa4->sin_addr.s_addr = htonl(0);
      sa4->sin_port = htons(config.bgp_daemon_port);
      slen = sizeof(struct sockaddr_in);

      config.bgp_sock = socket(((struct sockaddr *)&server)->sa_family, SOCK_STREAM, 0);
    }

    if (config.bgp_sock < 0) {
      Log(LOG_ERR, "ERROR ( %s/%s ): thread socket() failed. Terminating thread.\n", config.name, bgp_misc_db->log_str);
      exit_gracefully(1);
    }
  }

  setsockopt(config.bgp_sock, SOL_SOCKET, SO_KEEPALIVE, (void *)&yes, sizeof(yes));

  if (config.bgp_daemon_ipprec) {
    int opt = config.bgp_daemon_ipprec << 5;

    rc = setsockopt(config.bgp_sock, IPPROTO_IP, IP_TOS, &opt, (socklen_t) sizeof(opt));
    if (rc < 0) Log(LOG_ERR, "WARN ( %s/%s ): setsockopt() failed for IP_TOS (errno: %d).\n", config.name, bgp_misc_db->log_str, errno);
  }

#if (defined LINUX) && (defined HAVE_SO_REUSEPORT)
  rc = setsockopt(config.bgp_sock, SOL_SOCKET, SO_REUSEADDR|SO_REUSEPORT, (char *)&yes, (socklen_t) sizeof(yes));
  if (rc < 0) Log(LOG_ERR, "WARN ( %s/%s ): setsockopt() failed for SO_REUSEADDR|SO_REUSEPORT (errno: %d).\n", config.name, bgp_misc_db->log_str, errno);
#else
  rc = setsockopt(config.bgp_sock, SOL_SOCKET, SO_REUSEADDR, (char *)&yes, (socklen_t) sizeof(yes));
  if (rc < 0) Log(LOG_ERR, "WARN ( %s/%s ): setsockopt() failed for SO_REUSEADDR (errno: %d).\n", config.name, bgp_misc_db->log_str, errno);
#endif

#if (defined IPV6_BINDV6ONLY)
  rc = setsockopt(config.bgp_sock, IPPROTO_IPV6, IPV6_BINDV6ONLY, (char *) &no, (socklen_t) sizeof(no));
  if (rc < 0) Log(LOG_ERR, "WARN ( %s/%s ): setsockopt() failed for IPV6_BINDV6ONLY (errno: %d).\n", config.name, bgp_misc_db->log_str, errno);
#endif

  if (config.bgp_daemon_pipe_size) {
    socklen_t l = sizeof(config.bgp_daemon_pipe_size);
    int saved = 0, obtained = 0;

    getsockopt(config.bgp_sock, SOL_SOCKET, SO_RCVBUF, &saved, &l);
    Setsocksize(config.bgp_sock, SOL_SOCKET, SO_RCVBUF, &config.bgp_daemon_pipe_size, (socklen_t) sizeof(config.bgp_daemon_pipe_size));
    getsockopt(config.bgp_sock, SOL_SOCKET, SO_RCVBUF, &obtained, &l);

    Setsocksize(config.bgp_sock, SOL_SOCKET, SO_RCVBUF, &saved, l);
    getsockopt(config.bgp_sock, SOL_SOCKET, SO_RCVBUF, &obtained, &l);
    Log(LOG_INFO, "INFO ( %s/%s ): bgp_daemon_pipe_size: obtained=%d target=%d.\n", config.name, bgp_misc_db->log_str, obtained, config.bgp_daemon_pipe_size);
  }

  rc = bind(config.bgp_sock, (struct sockaddr *) &server, slen);
  if (rc < 0) {
    char null_ip_address[] = "0.0.0.0";
    char *ip_address;

    ip_address = config.bgp_daemon_ip ? config.bgp_daemon_ip : null_ip_address;
    Log(LOG_ERR, "ERROR ( %s/%s ): bind() to ip=%s port=%d/tcp failed (errno: %d).\n", config.name, bgp_misc_db->log_str, ip_address, config.bgp_daemon_port, errno);
    exit_gracefully(1);
  }

  rc = listen(config.bgp_sock, 1);
  if (rc < 0) {
    Log(LOG_ERR, "ERROR ( %s/%s ): listen() failed (errno: %d).\n", config.name, bgp_misc_db->log_str, errno);
    exit_gracefully(1);
  }

  /* Preparing for syncronous I/O multiplexing */
  select_fd = 0;
  FD_ZERO(&bkp_read_descs);
  FD_SET(config.bgp_sock, &bkp_read_descs);

  {
    char srv_string[INET6_ADDRSTRLEN];
    struct host_addr srv_addr;
    u_int16_t srv_port;

    sa_to_addr((struct sockaddr *)&server, &srv_addr, &srv_port);
    addr_to_str(srv_string, &srv_addr);
    Log(LOG_INFO, "INFO ( %s/%s ): waiting for BGP data on %s:%u\n", config.name, bgp_misc_db->log_str, srv_string, srv_port);
  }

  /* Preparing ACL, if any */
  if (config.bgp_daemon_allow_file) load_allow_file(config.bgp_daemon_allow_file, &allow);

  /* Preparing MD5 keys, if any */
  if (config.bgp_daemon_md5_file) {
    bgp_md5_file_init(&bgp_md5);
    bgp_md5_file_load(config.bgp_daemon_md5_file, &bgp_md5);
    if (bgp_md5.num) bgp_md5_file_process(config.bgp_sock, &bgp_md5);
  }

  /* Let's initialize clean shared RIB */
  for (afi = AFI_IP; afi < AFI_MAX; afi++) {
    for (safi = SAFI_UNICAST; safi < SAFI_MAX; safi++) {
      bgp_routing_db->rib[afi][safi] = bgp_table_init(afi, safi);
    }
  }

  /* BGP peers batching checks */
  if ((config.bgp_daemon_batch && !config.bgp_daemon_batch_interval) ||
      (config.bgp_daemon_batch_interval && !config.bgp_daemon_batch)) {
    Log(LOG_WARNING, "WARN ( %s/%s ): 'bgp_daemon_batch_interval' and 'bgp_daemon_batch' both set to zero.\n", config.name, bgp_misc_db->log_str);
    config.bgp_daemon_batch = 0;
    config.bgp_daemon_batch_interval = 0;
  }
  else bgp_batch_init(&bp_batch, config.bgp_daemon_batch, config.bgp_daemon_batch_interval);

  if (bgp_misc_db->msglog_backend_methods) {
#ifdef WITH_JANSSON
    if (!config.bgp_daemon_msglog_output) config.bgp_daemon_msglog_output = PRINT_OUTPUT_JSON;
#else
    Log(LOG_WARNING, "WARN ( %s/%s ): bgp_daemon_msglog_output set to json but will produce no output (missing --enable-jansson).\n", config.name, bgp_misc_db->log_str);
#endif

#ifdef WITH_AVRO
    if ((config.bgp_daemon_msglog_output == PRINT_OUTPUT_AVRO_BIN) ||
	(config.bgp_daemon_msglog_output == PRINT_OUTPUT_AVRO_JSON)) {
      assert(BGP_LOG_TYPE_MAX < MAX_AVRO_SCHEMA);

      bgp_misc_db->msglog_avro_schema[0] = p_avro_schema_build_bgp(BGP_LOGDUMP_ET_LOG, "bgp_msglog");
      bgp_misc_db->msglog_avro_schema[BGP_LOG_TYPE_LOGINIT] = p_avro_schema_build_bgp_log_initclose(BGP_LOGDUMP_ET_LOG, "bgp_loginit");
      bgp_misc_db->msglog_avro_schema[BGP_LOG_TYPE_LOGCLOSE] = p_avro_schema_build_bgp_log_initclose(BGP_LOGDUMP_ET_LOG, "bgp_logclose");

      if (config.bgp_daemon_msglog_avro_schema_file) {
	char p_avro_schema_file[SRVBUFLEN];

	if (strlen(config.bgp_daemon_msglog_avro_schema_file) > (SRVBUFLEN - SUPERSHORTBUFLEN)) {
	  Log(LOG_ERR, "ERROR ( %s/%s ): 'bgp_daemon_msglog_avro_schema_file' too long. Exiting.\n", config.name, bgp_misc_db->log_str);
	  exit_gracefully(1);
	}

	write_avro_schema_to_file_with_suffix(config.bgp_daemon_msglog_avro_schema_file, "-bgp_msglog",
					      p_avro_schema_file, bgp_misc_db->msglog_avro_schema[0]);

	write_avro_schema_to_file_with_suffix(config.bgp_daemon_msglog_avro_schema_file, "-bgp_loginit",
					      p_avro_schema_file, bgp_misc_db->msglog_avro_schema[BGP_LOG_TYPE_LOGINIT]);

	write_avro_schema_to_file_with_suffix(config.bgp_daemon_msglog_avro_schema_file, "-bgp_logclose",
					      p_avro_schema_file, bgp_misc_db->msglog_avro_schema[BGP_LOG_TYPE_LOGCLOSE]);
      }

      if (config.bgp_daemon_msglog_kafka_avro_schema_registry) {
#ifdef WITH_SERDES
        if (strchr(config.bgp_daemon_msglog_kafka_topic, '$')) {
          Log(LOG_ERR, "ERROR ( %s/%s ): dynamic 'bgp_daemon_msglog_kafka_topic' is not compatible with 'bgp_daemon_msglog_kafka_avro_schema_registry'. Exiting.\n",
	      config.name, bgp_misc_db->log_str);
	  exit_gracefully(1);
        }

	if (config.bgp_daemon_msglog_output == PRINT_OUTPUT_AVRO_JSON) {
          Log(LOG_ERR, "ERROR ( %s/%s ): 'avro_json' output is not compatible with 'bgp_daemon_msglog_kafka_avro_schema_registry'. Exiting.\n",
	      config.name, bgp_misc_db->log_str);
	  exit_gracefully(1);
	}

	bgp_daemon_msglog_kafka_host.sd_schema[0] = compose_avro_schema_registry_name_2(config.bgp_daemon_msglog_kafka_topic, FALSE,
										        bgp_misc_db->msglog_avro_schema[0], "bgp", "msglog",
										        config.bgp_daemon_msglog_kafka_avro_schema_registry);

	bgp_daemon_msglog_kafka_host.sd_schema[BGP_LOG_TYPE_LOGINIT] = compose_avro_schema_registry_name_2(config.bgp_daemon_msglog_kafka_topic, FALSE,
										        bgp_misc_db->msglog_avro_schema[BGP_LOG_TYPE_LOGINIT], "bgp", "loginit",
										        config.bgp_daemon_msglog_kafka_avro_schema_registry);

	bgp_daemon_msglog_kafka_host.sd_schema[BGP_LOG_TYPE_LOGCLOSE] = compose_avro_schema_registry_name_2(config.bgp_daemon_msglog_kafka_topic, FALSE,
										        bgp_misc_db->msglog_avro_schema[BGP_LOG_TYPE_LOGCLOSE], "bgp", "logclose",
										        config.bgp_daemon_msglog_kafka_avro_schema_registry);
#endif
      }
    }
#endif
  }

  if (bgp_misc_db->dump_backend_methods) {
#ifdef WITH_JANSSON
    if (!config.bgp_table_dump_output) config.bgp_table_dump_output = PRINT_OUTPUT_JSON;
#else
    Log(LOG_WARNING, "WARN ( %s/%s ): bgp_table_dump_output set to json but will produce no output (missing --enable-jansson).\n", config.name, bgp_misc_db->log_str);
#endif

#ifdef WITH_AVRO
    if ((config.bgp_table_dump_output == PRINT_OUTPUT_AVRO_BIN) ||
	(config.bgp_table_dump_output == PRINT_OUTPUT_AVRO_JSON)) {
      assert(BGP_LOG_TYPE_MAX < MAX_AVRO_SCHEMA);

      bgp_misc_db->dump_avro_schema[0] = p_avro_schema_build_bgp(BGP_LOGDUMP_ET_DUMP, "bgp_dump");
      bgp_misc_db->dump_avro_schema[BGP_LOG_TYPE_DUMPINIT] = p_avro_schema_build_bgp_dump_init(BGP_LOGDUMP_ET_DUMP, "bgp_dumpinit");
      bgp_misc_db->dump_avro_schema[BGP_LOG_TYPE_DUMPCLOSE] = p_avro_schema_build_bgp_dump_close(BGP_LOGDUMP_ET_DUMP, "bgp_dumpclose");

      if (config.bgp_table_dump_avro_schema_file) {
	char p_avro_schema_file[SRVBUFLEN];

	if (strlen(config.bgp_table_dump_avro_schema_file) > (SRVBUFLEN - SUPERSHORTBUFLEN)) {
	  Log(LOG_ERR, "ERROR ( %s/%s ): 'bgp_table_dump_avro_schema_file' too long. Exiting.\n", config.name, bgp_misc_db->log_str);
	  exit_gracefully(1);
	}

	write_avro_schema_to_file_with_suffix(config.bgp_table_dump_avro_schema_file, "-bgp_dump",
					      p_avro_schema_file, bgp_misc_db->dump_avro_schema[0]);

	write_avro_schema_to_file_with_suffix(config.bgp_table_dump_avro_schema_file, "-bgp_dumpinit",
					      p_avro_schema_file, bgp_misc_db->dump_avro_schema[BGP_LOG_TYPE_DUMPINIT]);

	write_avro_schema_to_file_with_suffix(config.bgp_table_dump_avro_schema_file, "-bgp_dumpclose",
					      p_avro_schema_file, bgp_misc_db->dump_avro_schema[BGP_LOG_TYPE_DUMPCLOSE]);
      }
    }
#endif
  }

  if (bgp_misc_db->dump_backend_methods) {
    char dump_roundoff[] = "m";
    time_t tmp_time;

    if (config.bgp_table_dump_refresh_time) {
      gettimeofday(&bgp_misc_db->log_tstamp, NULL);
      dump_refresh_deadline = bgp_misc_db->log_tstamp.tv_sec;
      tmp_time = roundoff_time(dump_refresh_deadline, dump_roundoff);
      while ((tmp_time+config.bgp_table_dump_refresh_time) < dump_refresh_deadline) {
        tmp_time += config.bgp_table_dump_refresh_time;
      }
      dump_refresh_deadline = tmp_time;
      dump_refresh_deadline += config.bgp_table_dump_refresh_time; /* it's a deadline not a basetime */
    }
    else {
      config.bgp_table_dump_file = NULL;
      bgp_misc_db->dump_backend_methods = FALSE;
      Log(LOG_WARNING, "WARN ( %s/%s ): Invalid 'bgp_table_dump_refresh_time'.\n", config.name, bgp_misc_db->log_str);
    }

    if (config.bgp_table_dump_amqp_routing_key) bgp_table_dump_init_amqp_host();
    if (config.bgp_table_dump_kafka_topic) bgp_table_dump_init_kafka_host();
  }

#ifdef WITH_AVRO
  bgp_misc_db->avro_buf = malloc(LARGEBUFLEN);
  if (!bgp_misc_db->avro_buf) {
    Log(LOG_ERR, "ERROR ( %s/%s ): malloc() failed (avro_buf). Exiting ..\n", config.name, bgp_misc_db->log_str);
    exit_gracefully(1);
  }
  else memset(bgp_misc_db->avro_buf, 0, LARGEBUFLEN);
#endif

  if (config.bgp_daemon_msglog_kafka_avro_schema_registry || config.bgp_table_dump_kafka_avro_schema_registry) {
#ifndef WITH_SERDES
    Log(LOG_ERR, "ERROR ( %s/%s ): 'bgp_*_kafka_avro_schema_registry' require --enable-serdes. Exiting.\n", config.name, bgp_misc_db->log_str);
    exit_gracefully(1);
#endif
  }

  select_fd = bkp_select_fd = (config.bgp_sock + 1);
  recalc_fds = FALSE;

  bgp_link_misc_structs(bgp_misc_db);

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

    if (!bgp_misc_db->is_thread) {
      sigprocmask(SIG_UNBLOCK, &signal_set, NULL);
      sigprocmask(SIG_BLOCK, &signal_set, NULL);
    }

    if (recalc_fds) { 
      select_fd = config.bgp_sock;
      max_peers_idx = -1; /* .. since valid indexes include 0 */

      for (peers_idx = 0; peers_idx < config.bgp_daemon_max_peers; peers_idx++) {
        if (select_fd < peers[peers_idx].fd) select_fd = peers[peers_idx].fd; 

        if (config.bgp_xconnect_map) {
	  if (select_fd < peers[peers_idx].xconnect_fd)
	    select_fd = peers[peers_idx].xconnect_fd; 
	}

	if (peers[peers_idx].fd) max_peers_idx = peers_idx;
      }
      select_fd++;
      max_peers_idx++;

      bkp_select_fd = select_fd;
      recalc_fds = FALSE;
    }
    else select_fd = bkp_select_fd;

    memcpy(&read_descs, &bkp_read_descs, sizeof(bkp_read_descs));

    if (bgp_misc_db->dump_backend_methods) {
      int delta;

      calc_refresh_timeout_sec(dump_refresh_deadline, bgp_misc_db->log_tstamp.tv_sec, &delta);
      dump_refresh_timeout.tv_sec = delta;
      dump_refresh_timeout.tv_usec = 0;
      drt_ptr = &dump_refresh_timeout;
    }
    else drt_ptr = NULL;

    select_num = select(select_fd, &read_descs, NULL, NULL, drt_ptr);
    if (select_num < 0) goto select_again;
    now = time(NULL);

    /* signals handling */
    if (reload_map_bgp_thread) {
      if (config.bgp_daemon_allow_file) load_allow_file(config.bgp_daemon_allow_file, &allow);

      if (config.bgp_daemon_md5_file) {
	bgp_md5_file_unload(&bgp_md5);
	if (bgp_md5.num) bgp_md5_file_process(config.bgp_sock, &bgp_md5); // process unload

	bgp_md5_file_load(config.bgp_daemon_md5_file, &bgp_md5);
	if (bgp_md5.num) bgp_md5_file_process(config.bgp_sock, &bgp_md5); // process load
      }

      if (config.bgp_xconnect_map) {
	int bgp_xcs_allocated = FALSE;

        bgp_xcs_map_destroy();

	memset(&req, 0, sizeof(req));
	req.key_value_table = (void *) &bgp_xcs_map;

	load_id_file(MAP_BGP_XCS, config.bgp_xconnect_map, NULL, &req, &bgp_xcs_allocated);
      }

      reload_map_bgp_thread = FALSE;
    }

    if (reload_log_bgp_thread) {
      for (peers_idx = 0; peers_idx < config.bgp_daemon_max_peers; peers_idx++) {
	if (bgp_misc_db->peers_log[peers_idx].fd) {
	  fclose(bgp_misc_db->peers_log[peers_idx].fd);
	  bgp_misc_db->peers_log[peers_idx].fd = open_output_file(bgp_misc_db->peers_log[peers_idx].filename, "a", FALSE);
	  setlinebuf(bgp_misc_db->peers_log[peers_idx].fd);
	}
	else break;
      }

      reload_log_bgp_thread = FALSE;
    }

    if (reload_log && !bgp_misc_db->is_thread) {
      reload_logs();
      reload_log = FALSE;
    }

    if (bgp_misc_db->msglog_backend_methods || bgp_misc_db->dump_backend_methods) {
      gettimeofday(&bgp_misc_db->log_tstamp, NULL);
      compose_timestamp(bgp_misc_db->log_tstamp_str, SRVBUFLEN, &bgp_misc_db->log_tstamp, TRUE,
			config.timestamps_since_epoch, config.timestamps_rfc3339, config.timestamps_utc);

      /* if dumping, let's reset log sequence at the next dump event */
      if (!bgp_misc_db->dump_backend_methods) {
        if (bgp_peer_log_seq_has_ro_bit(&bgp_misc_db->log_seq))
	  bgp_peer_log_seq_init(&bgp_misc_db->log_seq);
      }

      if (bgp_misc_db->dump_backend_methods) {
	while (bgp_misc_db->log_tstamp.tv_sec > dump_refresh_deadline) {
	  bgp_misc_db->dump.tstamp.tv_sec = dump_refresh_deadline;
	  bgp_misc_db->dump.tstamp.tv_usec = 0;
	  compose_timestamp(bgp_misc_db->dump.tstamp_str, SRVBUFLEN, &bgp_misc_db->dump.tstamp, FALSE,
			    config.timestamps_since_epoch, config.timestamps_rfc3339, config.timestamps_utc);
	  bgp_misc_db->dump.period = config.bgp_table_dump_refresh_time;

	  if (bgp_peer_log_seq_has_ro_bit(&bgp_misc_db->log_seq))
	    bgp_peer_log_seq_init(&bgp_misc_db->log_seq);

	  bgp_handle_dump_event();

	  dump_refresh_deadline += config.bgp_table_dump_refresh_time;
	}
      }

#ifdef WITH_RABBITMQ
      if (config.bgp_daemon_msglog_amqp_routing_key) { 
        time_t last_fail = P_broker_timers_get_last_fail(&bgp_daemon_msglog_amqp_host.btimers);

	if (last_fail && ((last_fail + P_broker_timers_get_retry_interval(&bgp_daemon_msglog_amqp_host.btimers)) <= bgp_misc_db->log_tstamp.tv_sec)) {
          bgp_daemon_msglog_init_amqp_host();
          p_amqp_connect_to_publish(&bgp_daemon_msglog_amqp_host);
	}
      }
#endif

#ifdef WITH_KAFKA
      if (config.bgp_daemon_msglog_kafka_topic) {
        time_t last_fail = P_broker_timers_get_last_fail(&bgp_daemon_msglog_kafka_host.btimers);

        if (last_fail && ((last_fail + P_broker_timers_get_retry_interval(&bgp_daemon_msglog_kafka_host.btimers)) <= bgp_misc_db->log_tstamp.tv_sec))
          bgp_daemon_msglog_init_kafka_host();
      }
#endif
    }

    /* 
       If select_num == 0 then we got out of select() due to a timeout rather
       than because we had a message from a peer to handle. By now we did all
       routine checks and can happily return to select() again.
    */ 
    if (!select_num) goto select_again;

    /* New connection is coming in */ 
    if (FD_ISSET(config.bgp_sock, &read_descs)) {
      int peers_check_idx, peers_num;

      fd = accept(config.bgp_sock, (struct sockaddr *) &client, &clen);
      if (fd == ERR) goto read_data;

      ipv4_mapped_to_ipv4(&client);

      /* If an ACL is defined, here we check against and enforce it */
      if (allow.num) allowed = check_allow(&allow, (struct sockaddr *)&client);
      else allowed = TRUE;

      if (!allowed) {
	char disallowed_str[INET6_ADDRSTRLEN];

	sa_to_str(disallowed_str, sizeof(disallowed_str), (struct sockaddr *) &client);
	Log(LOG_INFO, "INFO ( %s/%s ): [%s] peer '%s' not allowed. close()\n", config.name, bgp_misc_db->log_str, config.bgp_daemon_allow_file, disallowed_str);

        close(fd);
        goto read_data;
      }

      for (peer = NULL, peers_idx = 0; peers_idx < config.bgp_daemon_max_peers; peers_idx++) {
        if (!peers[peers_idx].fd) {
	  /*
	     Admitted if:
	     *  batching feature is disabled or
	     *  we have room in the current batch or
	     *  we can start a new batch 
	  */
          if (bgp_batch_is_admitted(&bp_batch, now)) {
            peer = &peers[peers_idx];
            if (bgp_peer_init(peer, FUNC_TYPE_BGP)) peer = NULL;
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
	    if (!log_notification_isset(&log_notifications.bgp_peers_throttling, now)) {
              Log(LOG_INFO, "INFO ( %s/%s ): throttling at BGP peer #%u\n", config.name, bgp_misc_db->log_str, peers_idx);
	      log_notification_set(&log_notifications.bgp_peers_throttling, now, FALSE);
	    }

            close(fd);
            goto read_data;
          }
        }
	/* XXX: replenish sessions with expired keepalives */
      }

      if (!peer) {
	/* We briefly accept the new connection to be able to drop it */
	if (!log_notification_isset(&log_notifications.bgp_peers_limit, now)) {
	  log_notification_set(&log_notifications.bgp_peers_limit, now, FALSE);
          Log(LOG_WARNING, "WARN ( %s/%s ): Insufficient number of BGP peers has been configured by 'bgp_daemon_max_peers' (%d).\n",
			config.name, bgp_misc_db->log_str, config.bgp_daemon_max_peers);
	}

	close(fd);
	goto read_data;
      }

      peer->fd = fd;
      peer->idx = peers_idx; 
      FD_SET(peer->fd, &bkp_read_descs);
      sa_to_addr((struct sockaddr *) &client, &peer->addr, &peer->tcp_port);

      if (peers_cache && peers_port_cache) {
	u_int32_t bucket;

	bucket = addr_hash(&peer->addr, config.bgp_daemon_max_peers);
	bgp_peer_cache_insert(peers_cache, bucket, peer);

	bucket = addr_port_hash(&peer->addr, peer->tcp_port, config.bgp_daemon_max_peers);
	bgp_peer_cache_insert(peers_port_cache, bucket, peer);
      }

      if (bgp_misc_db->msglog_backend_methods)
	bgp_peer_log_init(peer, config.bgp_daemon_msglog_output, FUNC_TYPE_BGP);

      /* Check: more than one TCP connection from a peer (IP address) */
      for (peers_check_idx = 0, peers_num = 0; peers_check_idx < config.bgp_daemon_max_peers; peers_check_idx++) { 
	if (peers_idx != peers_check_idx && !memcmp(&peers[peers_check_idx].addr, &peer->addr, sizeof(peers[peers_check_idx].addr))) {
	  int same_peer = FALSE;

	  bgp_peer_print(&peers[peers_check_idx], bgp_peer_str, INET6_ADDRSTRLEN);

          /* Check: if not x-connecting, let's see if we have to compare TCP ports
	     (ie. NAT traversal / non-transparent tee scenarios); then evaluate if
	     the new session is valid or has to be rejected */  
	  if (!config.bgp_xconnect_map) {
	    if (config.tmp_bgp_lookup_compare_ports) {
	      if (peers[peers_check_idx].tcp_port == peer->tcp_port) same_peer = TRUE;
	      else {
		same_peer = FALSE;
	        if (peers[peers_check_idx].fd) peers_num++;
	      }
	    }
	    else same_peer = TRUE;

	    if (same_peer) {
	      if ((now - peers[peers_check_idx].last_keepalive) > peers[peers_check_idx].ht) {
		bgp_peer_print(&peers[peers_check_idx], bgp_peer_str, INET6_ADDRSTRLEN);
              	Log(LOG_INFO, "INFO ( %s/%s ): [%s] Replenishing stale connection by peer.\n",
			config.name, bgp_misc_db->log_str, bgp_peer_str);
		FD_CLR(peers[peers_check_idx].fd, &bkp_read_descs);
		bgp_peer_close(&peers[peers_check_idx], FUNC_TYPE_BGP, FALSE, FALSE, FALSE, FALSE, NULL);
	      }
	      else {
		Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Refusing new connection from existing peer (residual holdtime: %ld).\n",
			config.name, bgp_misc_db->log_str, bgp_peer_str,
			(peers[peers_check_idx].ht - ((long)now - peers[peers_check_idx].last_keepalive)));
		FD_CLR(peer->fd, &bkp_read_descs);
		bgp_peer_close(peer, FUNC_TYPE_BGP, FALSE, FALSE, FALSE, FALSE, NULL);
		goto read_data;
	      }
	    }
	  }
	  /* XXX: if x-connecting we don't support NAT traversal / non-transparent tee
	     scenarios (yet?) */ 
	  else {
	    Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Refusing new incoming connection for existing BGP xconnect.\n",
			config.name, bgp_misc_db->log_str, bgp_peer_str);
	    FD_CLR(peer->fd, &bkp_read_descs);
	    bgp_peer_close(peer, FUNC_TYPE_BGP, FALSE, FALSE, FALSE, FALSE, NULL);
	    goto read_data;
	  }
        }
	else if (peers[peers_check_idx].fd) peers_num++;
      }

      if (config.bgp_xconnect_map) {
        bgp_peer_xconnect_init(peer, FUNC_TYPE_BGP);

        if (peer->xconnect_fd) FD_SET(peer->xconnect_fd, &bkp_read_descs);
        else {
          FD_CLR(peer->fd, &bkp_read_descs);
          bgp_peer_close(peer, FUNC_TYPE_BGP, FALSE, FALSE, FALSE, FALSE, NULL);
          goto read_data;
        }
      }

      if (!config.bgp_xconnect_map) {
        bgp_peer_print(peer, bgp_peer_str, INET6_ADDRSTRLEN);
        Log(LOG_INFO, "INFO ( %s/%s ): [%s] BGP peers usage: %u/%u\n", config.name, bgp_misc_db->log_str,
		bgp_peer_str, peers_num, config.bgp_daemon_max_peers);
      }
      else {
        bgp_peer_xconnect_print(peer, bgp_xconnect_peer_str, BGP_XCONNECT_STRLEN);
        Log(LOG_INFO, "INFO ( %s/%s ): [%s] BGP xconnects usage: %u/%u\n", config.name, bgp_misc_db->log_str,
		bgp_xconnect_peer_str, peers_num, config.bgp_daemon_max_peers);
      }

      if (config.bgp_daemon_neighbors_file) write_neighbors_file(config.bgp_daemon_neighbors_file, FUNC_TYPE_BGP);
    }

    read_data:

    /*
       We have something coming in: let's lookup which peer is that.
       FvD: To avoid starvation of the "later established" peers, we
       offset the start of the search in a round-robin style.
    */
    for (peer = NULL, peer_buf = NULL, peers_idx = 0; peers_idx < max_peers_idx; peers_idx++) {
      int loc_idx = (peers_idx + peers_idx_rr) % max_peers_idx;
      recv_fd = 0; send_fd = 0;

      if (peers[loc_idx].fd && FD_ISSET(peers[loc_idx].fd, &read_descs)) {
        peer = &peers[loc_idx];
	peer_buf = &peer->buf;
	recv_fd = peer->fd;
	if (config.bgp_xconnect_map) send_fd = peer->xconnect_fd;
        peers_idx_rr = (peers_idx_rr + 1) % max_peers_idx;
	break;
      }
      
      if (config.bgp_xconnect_map) {
        loc_idx = (peers_idx + peers_xconnect_idx_rr) % max_peers_idx;

	if (peers[loc_idx].xconnect_fd && FD_ISSET(peers[loc_idx].xconnect_fd, &read_descs)) {
	  peer = &peers[loc_idx];
	  peer_buf = &peer->xbuf;
	  recv_fd = peer->xconnect_fd;
	  send_fd = peer->fd;
	  peers_xconnect_idx_rr = (peers_xconnect_idx_rr + 1) % max_peers_idx;
	  break;
	}
      }
    }

    if (!peer) goto select_again;

    if (!peer_buf->exp_len) {
      ret = recv(recv_fd, &peer_buf->base[peer_buf->cur_len], (BGP_HEADER_SIZE - peer_buf->cur_len), 0);

      if (ret > 0) {
	peer_buf->cur_len += ret;

	if (peer_buf->cur_len == BGP_HEADER_SIZE) {
	  struct bgp_header *bhdr = (struct bgp_header *) peer_buf->base;

	  if (bgp_marker_check(bhdr, BGP_MARKER_SIZE) == ERR) {
	    bgp_peer_print(peer, bgp_peer_str, INET6_ADDRSTRLEN);
	    Log(LOG_INFO, "INFO ( %s/%s ): [%s] Received malformed BGP packet (marker check failed).\n",
		config.name, bgp_misc_db->log_str, bgp_peer_str);

	    peer->msglen = 0;
	    peer_buf->cur_len = 0;
	    peer_buf->exp_len = 0;
	    ret = ERR;
	  }
	  else {
	    peer_buf->exp_len = ntohs(bhdr->bgpo_len);

	    /* commit */
	    if (peer_buf->cur_len == peer_buf->exp_len) {
	      peer->msglen = peer_buf->exp_len;
	      peer_buf->cur_len = 0;
	      peer_buf->exp_len = 0;
	    }
	  }
	}
	else {
	  goto select_again;
	}
      }
    }

    if (peer_buf->exp_len) {
      ret = recv(recv_fd, &peer_buf->base[peer_buf->cur_len], (peer_buf->exp_len - peer_buf->cur_len), 0);

      if (ret > 0) {
	peer_buf->cur_len += ret;

	/* commit */
        if (peer_buf->cur_len == peer_buf->exp_len) {
	  peer->msglen = peer_buf->exp_len;
	  peer_buf->cur_len = 0;
	  peer_buf->exp_len = 0;
	}
	else {
	  goto select_again;
	}
      }
    }

    if (ret <= 0) {
      if (!config.bgp_xconnect_map) {
	bgp_peer_print(peer, bgp_peer_str, INET6_ADDRSTRLEN);
	Log(LOG_INFO, "INFO ( %s/%s ): [%s] BGP connection reset by peer (%d).\n", config.name, bgp_misc_db->log_str, bgp_peer_str, errno);
	FD_CLR(peer->fd, &bkp_read_descs);
      }
      else {
	bgp_peer_xconnect_print(peer, bgp_xconnect_peer_str, BGP_XCONNECT_STRLEN);

	if (recv_fd == peer->fd)
	  Log(LOG_INFO, "INFO ( %s/%s ): [%s] recv(): BGP xconnect reset by src peer (%d).\n",
		config.name, bgp_misc_db->log_str, bgp_xconnect_peer_str, errno);
	else if (recv_fd == peer->xconnect_fd)
	  Log(LOG_INFO, "INFO ( %s/%s ): [%s] recv(): BGP xconnect reset by dst peer (%d).\n",
		config.name, bgp_misc_db->log_str, bgp_xconnect_peer_str, errno);

	FD_CLR(peer->fd, &bkp_read_descs);
	FD_CLR(peer->xconnect_fd, &bkp_read_descs);
      }

      bgp_peer_close(peer, FUNC_TYPE_BGP, FALSE, FALSE, FALSE, FALSE, NULL);

      recalc_fds = TRUE;
      goto select_again;
    }
    else {
      if (!config.bgp_xconnect_map) {
	/* Appears a valid peer with a valid BGP message: before
	   continuing let's see if it's time to send a KEEPALIVE
	   back */
	if (peer->status == Established && ((now - peer->last_keepalive) > (peer->ht / 2))) {
	  bgp_reply_pkt_ptr = bgp_reply_pkt;
	  bgp_reply_pkt_ptr += bgp_write_keepalive_msg(bgp_reply_pkt_ptr);
	  ret = send(recv_fd, bgp_reply_pkt, bgp_reply_pkt_ptr - bgp_reply_pkt, 0);
	  peer->last_keepalive = now;
	} 

	ret = bgp_parse_msg(peer, now, TRUE);
	if (ret) {
	  FD_CLR(recv_fd, &bkp_read_descs);

	  if (ret < 0) bgp_peer_close(peer, FUNC_TYPE_BGP, FALSE, FALSE, FALSE, FALSE, NULL);
	  else bgp_peer_close(peer, FUNC_TYPE_BGP, FALSE, TRUE, ret, BGP_NOTIFY_SUBCODE_UNSPECIFIC, NULL);

	  recalc_fds = TRUE;
	  goto select_again;
	}
      }
      else {
	ret = send(send_fd, peer_buf->base, peer->msglen, 0);
	if (ret <= 0) {
	  bgp_peer_xconnect_print(peer, bgp_xconnect_peer_str, BGP_XCONNECT_STRLEN);

	  if (send_fd == peer->fd)
	    Log(LOG_INFO, "INFO ( %s/%s ): [%s] send(): BGP xconnect reset by src peer (%d).\n",
		config.name, bgp_misc_db->log_str, bgp_xconnect_peer_str, errno);
	  else if (send_fd == peer->xconnect_fd)
	    Log(LOG_INFO, "INFO ( %s/%s ): [%s] send(): BGP xconnect reset by dst peer (%d).\n",
		config.name, bgp_misc_db->log_str, bgp_xconnect_peer_str, errno);

	  FD_CLR(peer->fd, &bkp_read_descs);
	  FD_CLR(peer->xconnect_fd, &bkp_read_descs);

	  bgp_peer_close(peer, FUNC_TYPE_BGP, FALSE, FALSE, FALSE, FALSE, NULL);

	  recalc_fds = TRUE;
	  goto select_again;
	}
      }
    }
  }
}

void bgp_prepare_thread()
{
  bgp_misc_db = &inter_domain_misc_dbs[FUNC_TYPE_BGP];
  memset(bgp_misc_db, 0, sizeof(struct bgp_misc_structs));

  bgp_misc_db->is_thread = TRUE;
  if (config.bgp_lg) bgp_misc_db->has_lglass = TRUE;

  if (config.rpki_roas_file || config.rpki_rtr_cache) {
    bgp_misc_db->bnv = malloc(sizeof(struct bgp_node_vector));
    memset(bgp_misc_db->bnv, 0, sizeof(struct bgp_node_vector)); 
  }

  if (config.bgp_blackhole_stdcomm_list) bgp_misc_db->has_blackhole = TRUE;

  bgp_misc_db->log_str = malloc(strlen("core/BGP") + 1);
  strcpy(bgp_misc_db->log_str, "core/BGP");
}

void bgp_prepare_daemon()
{
  bgp_misc_db = &inter_domain_misc_dbs[FUNC_TYPE_BGP];
  memset(bgp_misc_db, 0, sizeof(struct bgp_misc_structs));

  bgp_misc_db->is_thread = FALSE;
  if (config.bgp_lg) bgp_misc_db->has_lglass = TRUE;

  if (config.rpki_roas_file || config.rpki_rtr_cache) {
    bgp_misc_db->bnv = malloc(sizeof(struct bgp_node_vector));
    memset(bgp_misc_db->bnv, 0, sizeof(struct bgp_node_vector));
  }

  if (config.bgp_blackhole_stdcomm_list) bgp_misc_db->has_blackhole = TRUE;

  bgp_misc_db->log_str = malloc(strlen("core") + 1);
  strcpy(bgp_misc_db->log_str, "core");
}
