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
#define __BMP_C

/* includes */
#include "pmacct.h"
#include "addr.h"
#include "../bgp/bgp.h"
#include "bmp.h"
#include "thread_pool.h"
#if defined WITH_RABBITMQ
#include "amqp_common.h"
#endif
#ifdef WITH_KAFKA
#include "kafka_common.h"
#endif

/* variables to be exported away */
thread_pool_t *bmp_pool;

/* Functions */
#if defined ENABLE_THREADS
void nfacctd_bmp_wrapper()
{
  /* initialize variables */
  if (!config.nfacctd_bmp_port) config.nfacctd_bmp_port = BMP_TCP_PORT;

  /* initialize threads pool */
  bmp_pool = allocate_thread_pool(1);
  assert(bmp_pool);
  Log(LOG_DEBUG, "DEBUG ( %s/core/BMP ): %d thread(s) initialized\n", config.name, 1);
  bmp_prepare_thread();

  /* giving a kick to the BMP thread */
  send_to_pool(bmp_pool, skinny_bmp_daemon, NULL);
}
#endif

void skinny_bmp_daemon()
{
  int slen, clen, ret, rc, peers_idx, allowed, yes=1, no=0;
  int peers_idx_rr = 0, max_peers_idx = 0;
  u_int32_t pkt_remaining_len=0;
  time_t now;
  afi_t afi;
  safi_t safi;

  struct bmp_peer *bmpp = NULL;
  struct bgp_peer *peer = NULL;

#if defined ENABLE_IPV6
  struct sockaddr_storage server, client;
#else
  struct sockaddr server, client;
#endif
  struct hosts_table allow;
  struct host_addr addr;
  struct bgp_peer_batch bp_batch;

  /* select() stuff */
  fd_set read_descs, bkp_read_descs;
  int fd, select_fd, bkp_select_fd, recalc_fds, select_num;

  /* logdump time management */
  time_t dump_refresh_deadline;
  struct timeval dump_refresh_timeout, *drt_ptr;


  /* initial cleanups */
  reload_log_bmp_thread = FALSE;
  memset(&server, 0, sizeof(server));
  memset(&client, 0, sizeof(client));
  memset(&allow, 0, sizeof(struct hosts_table));
  clen = sizeof(client);

  bmp_routing_db = &inter_domain_routing_dbs[FUNC_TYPE_BMP];
  memset(bmp_routing_db, 0, sizeof(struct bgp_rt_structs));

  /* socket creation for BMP server: IPv4 only */
#if (defined ENABLE_IPV6)
  if (!config.nfacctd_bmp_ip) {
    struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&server;

    sa6->sin6_family = AF_INET6;
    sa6->sin6_port = htons(config.nfacctd_bmp_port);
    slen = sizeof(struct sockaddr_in6);
  }
#else
  if (!config.nfacctd_bmp_ip) {
    struct sockaddr_in *sa4 = (struct sockaddr_in *)&server;

    sa4->sin_family = AF_INET;
    sa4->sin_addr.s_addr = htonl(0);
    sa4->sin_port = htons(config.nfacctd_bmp_port);
    slen = sizeof(struct sockaddr_in);
  }
#endif
  else {
    trim_spaces(config.nfacctd_bmp_ip);
    ret = str_to_addr(config.nfacctd_bmp_ip, &addr);
    if (!ret) {
      Log(LOG_ERR, "ERROR ( %s/%s ): 'bmp_daemon_ip' value is not a valid IPv4/IPv6 address. Terminating thread.\n", config.name, bmp_misc_db->log_str);
      exit_all(1);
    }
    slen = addr_to_sa((struct sockaddr *)&server, &addr, config.nfacctd_bmp_port);
  }

  if (!config.nfacctd_bmp_max_peers) config.nfacctd_bmp_max_peers = BMP_MAX_PEERS_DEFAULT;
  Log(LOG_INFO, "INFO ( %s/%s ): maximum BMP peers allowed: %d\n", config.name, bmp_misc_db->log_str, config.nfacctd_bmp_max_peers);

  bmp_peers = malloc(config.nfacctd_bmp_max_peers*sizeof(struct bmp_peer));
  if (!bmp_peers) {
    Log(LOG_ERR, "ERROR ( %s/%s ): Unable to malloc() BMP peers structure. Terminating thread.\n", config.name, bmp_misc_db->log_str);
    exit_all(1);
  }
  memset(bmp_peers, 0, config.nfacctd_bmp_max_peers*sizeof(struct bmp_peer));

  if (config.nfacctd_bmp_msglog_file || config.nfacctd_bmp_msglog_amqp_routing_key || config.nfacctd_bmp_msglog_kafka_topic) {
    if (config.nfacctd_bmp_msglog_file) bmp_misc_db->msglog_backend_methods++;
    if (config.nfacctd_bmp_msglog_amqp_routing_key) bmp_misc_db->msglog_backend_methods++;
    if (config.nfacctd_bmp_msglog_kafka_topic) bmp_misc_db->msglog_backend_methods++;

    if (bmp_misc_db->msglog_backend_methods > 1) {
      Log(LOG_ERR, "ERROR ( %s/%s ): bmp_daemon_msglog_file, bmp_daemon_msglog_amqp_routing_key and bmp_daemon_msglog_kafka_topic are mutually exclusive. Terminating thread.\n", config.name, bmp_misc_db->log_str);
      exit_all(1);
    }
  }

  if (config.bmp_dump_file || config.bmp_dump_amqp_routing_key || config.bmp_dump_kafka_topic) {
    if (config.bmp_dump_file) bmp_misc_db->dump_backend_methods++;
    if (config.bmp_dump_amqp_routing_key) bmp_misc_db->dump_backend_methods++;
    if (config.bmp_dump_kafka_topic) bmp_misc_db->dump_backend_methods++;

    if (bmp_misc_db->dump_backend_methods > 1) {
      Log(LOG_ERR, "ERROR ( %s/%s ): bmp_dump_file, bmp_dump_amqp_routing_key and bmp_dump_kafka_topic are mutually exclusive. Terminating thread.\n", config.name, bmp_misc_db->log_str);
      exit_all(1);
    }
  }

  if (bmp_misc_db->msglog_backend_methods || bmp_misc_db->dump_backend_methods)
    bgp_peer_log_seq_init(&bmp_misc_db->log_seq);

  if (bmp_misc_db->msglog_backend_methods) {
    bmp_misc_db->peers_log = malloc(config.nfacctd_bmp_max_peers*sizeof(struct bgp_peer_log));
    if (!bmp_misc_db->peers_log) {
      Log(LOG_ERR, "ERROR ( %s/%s ): Unable to malloc() BMP peers log structure. Terminating thread.\n", config.name, bmp_misc_db->log_str);
      exit_all(1);
    }
    memset(bmp_misc_db->peers_log, 0, config.nfacctd_bmp_max_peers*sizeof(struct bgp_peer_log));

    if (config.nfacctd_bmp_msglog_amqp_routing_key) {
#ifdef WITH_RABBITMQ
      bmp_daemon_msglog_init_amqp_host();
      p_amqp_connect_to_publish(&bmp_daemon_msglog_amqp_host);

      if (!config.nfacctd_bmp_msglog_amqp_retry)
        config.nfacctd_bmp_msglog_amqp_retry = AMQP_DEFAULT_RETRY;
#else
      Log(LOG_WARNING, "WARN ( %s/%s ): p_amqp_connect_to_publish() not possible due to missing --enable-rabbitmq\n", config.name, bmp_misc_db->log_str);
#endif
    }

    if (config.nfacctd_bmp_msglog_kafka_topic) {
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
    exit_all(1);
  }

  config.bmp_sock = socket(((struct sockaddr *)&server)->sa_family, SOCK_STREAM, 0);
  if (config.bmp_sock < 0) {
#if (defined ENABLE_IPV6)
    /* retry with IPv4 */
    if (!config.nfacctd_bmp_ip) {
      struct sockaddr_in *sa4 = (struct sockaddr_in *)&server;

      sa4->sin_family = AF_INET;
      sa4->sin_addr.s_addr = htonl(0);
      sa4->sin_port = htons(config.nfacctd_bmp_port);
      slen = sizeof(struct sockaddr_in);

      config.bmp_sock = socket(((struct sockaddr *)&server)->sa_family, SOCK_STREAM, 0);
    }
#endif

    if (config.bmp_sock < 0) {
      Log(LOG_ERR, "ERROR ( %s/%s ): thread socket() failed. Terminating thread.\n", config.name, bmp_misc_db->log_str);
      exit_all(1);
    }
  }
  if (config.nfacctd_bmp_ipprec) {
    int opt = config.nfacctd_bmp_ipprec << 5;

    rc = setsockopt(config.bmp_sock, IPPROTO_IP, IP_TOS, &opt, sizeof(opt));
    if (rc < 0) Log(LOG_ERR, "WARN ( %s/%s ): setsockopt() failed for IP_TOS (errno: %d).\n", config.name, bmp_misc_db->log_str, errno);
  }

  rc = setsockopt(config.bmp_sock, SOL_SOCKET, SO_REUSEADDR, (char *)&yes, sizeof(yes));
  if (rc < 0) Log(LOG_ERR, "WARN ( %s/%s ): setsockopt() failed for SO_REUSEADDR (errno: %d).\n", config.name, bmp_misc_db->log_str, errno);

#if (defined ENABLE_IPV6) && (defined IPV6_BINDV6ONLY)
  rc = setsockopt(config.bmp_sock, IPPROTO_IPV6, IPV6_BINDV6ONLY, (char *) &no, (socklen_t) sizeof(no));
  if (rc < 0) Log(LOG_ERR, "WARN ( %s/%s ): setsockopt() failed for IPV6_BINDV6ONLY (errno: %d).\n", config.name, bmp_misc_db->log_str, errno);
#endif

  if (config.nfacctd_bmp_pipe_size) {
    int l = sizeof(config.nfacctd_bmp_pipe_size);
    int saved = 0, obtained = 0;

    getsockopt(config.bmp_sock, SOL_SOCKET, SO_RCVBUF, &saved, &l);
    Setsocksize(config.bmp_sock, SOL_SOCKET, SO_RCVBUF, &config.nfacctd_bmp_pipe_size, sizeof(config.nfacctd_bmp_pipe_size));
    getsockopt(config.bmp_sock, SOL_SOCKET, SO_RCVBUF, &obtained, &l);

    Setsocksize(config.bmp_sock, SOL_SOCKET, SO_RCVBUF, &saved, l);
    getsockopt(config.bmp_sock, SOL_SOCKET, SO_RCVBUF, &obtained, &l);
    Log(LOG_INFO, "INFO ( %s/%s ): bmp_daemon_pipe_size: obtained=%d target=%d.\n", config.name, bmp_misc_db->log_str, obtained, config.nfacctd_bmp_pipe_size);
  }

  rc = bind(config.bmp_sock, (struct sockaddr *) &server, slen);
  if (rc < 0) {
    char null_ip_address[] = "0.0.0.0";
    char *ip_address;

    ip_address = config.nfacctd_bmp_ip ? config.nfacctd_bmp_ip : null_ip_address;
    Log(LOG_ERR, "ERROR ( %s/%s ): bind() to ip=%s port=%d/tcp failed (errno: %d).\n", config.name, bmp_misc_db->log_str, ip_address, config.nfacctd_bmp_port, errno);
    exit_all(1);
  }

  rc = listen(config.bmp_sock, 1);
  if (rc < 0) {
    Log(LOG_ERR, "ERROR ( %s/%s ): listen() failed (errno: %d).\n", config.name, bmp_misc_db->log_str, errno);
    exit_all(1);
  }

  /* Preparing for syncronous I/O multiplexing */
  select_fd = 0;
  FD_ZERO(&bkp_read_descs);
  FD_SET(config.bmp_sock, &bkp_read_descs);

  {
    char srv_string[INET6_ADDRSTRLEN];
    struct host_addr srv_addr;
    u_int16_t srv_port;

    sa_to_addr((struct sockaddr *)&server, &srv_addr, &srv_port);
    addr_to_str(srv_string, &srv_addr);
    Log(LOG_INFO, "INFO ( %s/%s ): waiting for BMP data on %s:%u\n", config.name, bmp_misc_db->log_str, srv_string, srv_port);
  }

  /* Preparing ACL, if any */
  if (config.nfacctd_bmp_allow_file) load_allow_file(config.nfacctd_bmp_allow_file, &allow);

  /* Let's initialize clean shared RIB */
  for (afi = AFI_IP; afi < AFI_MAX; afi++) {
    for (safi = SAFI_UNICAST; safi < SAFI_MAX; safi++) {
      bmp_routing_db->rib[afi][safi] = bgp_table_init(afi, safi);
    }
  }

  /* BMP peers batching checks */
  if ((config.nfacctd_bmp_batch && !config.nfacctd_bmp_batch_interval) ||
      (config.nfacctd_bmp_batch_interval && !config.nfacctd_bmp_batch)) {
    Log(LOG_WARNING, "WARN ( %s/%s ): 'bmp_daemon_batch_interval' and 'bmp_daemon_batch' both set to zero.\n", config.name, bmp_misc_db->log_str);
    config.nfacctd_bmp_batch = 0;
    config.nfacctd_bmp_batch_interval = 0;
  }
  else bgp_batch_init(&bp_batch, config.nfacctd_bmp_batch, config.nfacctd_bmp_batch_interval);

  if (bmp_misc_db->msglog_backend_methods) {
#ifdef WITH_JANSSON
    if (!config.nfacctd_bmp_msglog_output) config.nfacctd_bmp_msglog_output = PRINT_OUTPUT_JSON;
#else
    Log(LOG_WARNING, "WARN ( %s/%s ): bmp_daemon_msglog_output set to json but will produce no output (missing --enable-jansson).\n", config.name, bmp_misc_db->log_str);
#endif
  }

  if (bmp_misc_db->dump_backend_methods) {
#ifdef WITH_JANSSON
    if (!config.bmp_dump_output) config.bmp_dump_output = PRINT_OUTPUT_JSON;
#else
    Log(LOG_WARNING, "WARN ( %s/%s ): bmp_table_dump_output set to json but will produce no output (missing --enable-jansson).\n", config.name, bmp_misc_db->log_str);
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

    if (config.bmp_dump_amqp_routing_key) bmp_dump_init_amqp_host();
    if (config.bmp_dump_kafka_topic) bmp_dump_init_kafka_host();
  }

  select_fd = bkp_select_fd = (config.bmp_sock + 1);
  recalc_fds = FALSE;

  bmp_link_misc_structs(bmp_misc_db);

  for (;;) {
    select_again:

    if (recalc_fds) {
      select_fd = config.bmp_sock;
      max_peers_idx = -1; /* .. since valid indexes include 0 */

      for (peers_idx = 0; peers_idx < config.nfacctd_bmp_max_peers; peers_idx++) {
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

    if (reload_log_bmp_thread) {
      for (peers_idx = 0; peers_idx < config.nfacctd_bmp_max_peers; peers_idx++) {
        if (bmp_misc_db->peers_log[peers_idx].fd) {
          fclose(bmp_misc_db->peers_log[peers_idx].fd);
          bmp_misc_db->peers_log[peers_idx].fd = open_output_file(bmp_misc_db->peers_log[peers_idx].filename, "a", FALSE);
	  setlinebuf(bmp_misc_db->peers_log[peers_idx].fd);
        }
        else break;
      }

      reload_log_bmp_thread = FALSE;
    }

    if (bmp_misc_db->msglog_backend_methods || bmp_misc_db->dump_backend_methods) {
      gettimeofday(&bmp_misc_db->log_tstamp, NULL);
      compose_timestamp(bmp_misc_db->log_tstamp_str, SRVBUFLEN, &bmp_misc_db->log_tstamp, TRUE, config.timestamps_since_epoch);

      if (bmp_misc_db->dump_backend_methods) {
        while (bmp_misc_db->log_tstamp.tv_sec > dump_refresh_deadline) {
          bmp_misc_db->dump.tstamp.tv_sec = dump_refresh_deadline;
          bmp_misc_db->dump.tstamp.tv_usec = 0;
          compose_timestamp(bmp_misc_db->dump.tstamp_str, SRVBUFLEN, &bmp_misc_db->dump.tstamp, FALSE, config.timestamps_since_epoch);
	  bmp_misc_db->dump.period = config.bmp_dump_refresh_time;

          bmp_handle_dump_event();
          dump_refresh_deadline += config.bmp_dump_refresh_time;
        }
      }

#ifdef WITH_RABBITMQ
      if (config.nfacctd_bmp_msglog_amqp_routing_key) {
        time_t last_fail = P_broker_timers_get_last_fail(&bmp_daemon_msglog_amqp_host.btimers);

        if (last_fail && ((last_fail + P_broker_timers_get_retry_interval(&bmp_daemon_msglog_amqp_host.btimers)) <= bmp_misc_db->log_tstamp.tv_sec)) {
          bmp_daemon_msglog_init_amqp_host();
          p_amqp_connect_to_publish(&bmp_daemon_msglog_amqp_host);
        }
      }
#endif

#ifdef WITH_KAFKA
      if (config.nfacctd_bmp_msglog_kafka_topic) {
        time_t last_fail = P_broker_timers_get_last_fail(&bmp_daemon_msglog_kafka_host.btimers);

        if (last_fail && ((last_fail + P_broker_timers_get_retry_interval(&bmp_daemon_msglog_kafka_host.btimers)) <= bmp_misc_db->log_tstamp.tv_sec))
          bmp_daemon_msglog_init_kafka_host();
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
    if (FD_ISSET(config.bmp_sock, &read_descs)) {
      int peers_check_idx, peers_num;

      fd = accept(config.bmp_sock, (struct sockaddr *) &client, &clen);
      if (fd == ERR) goto read_data;

#if defined ENABLE_IPV6
      ipv4_mapped_to_ipv4(&client);
#endif

      /* If an ACL is defined, here we check against and enforce it */
      if (allow.num) allowed = check_allow(&allow, (struct sockaddr *)&client);
      else allowed = TRUE;

      if (!allowed) {
	close(fd);
	goto read_data;
      }

      for (peer = NULL, peers_idx = 0; peers_idx < config.nfacctd_bmp_max_peers; peers_idx++) {
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
        int fd;

        /* We briefly accept the new connection to be able to drop it */
        Log(LOG_ERR, "ERROR ( %s/%s ): Insufficient number of BMP peers has been configured by 'bmp_daemon_max_peers' (%d).\n",
                        config.name, bmp_misc_db->log_str, config.nfacctd_bmp_max_peers);
        close(fd);
        goto read_data;
      }

      peer->fd = fd;
      FD_SET(peer->fd, &bkp_read_descs);
      peer->addr.family = ((struct sockaddr *)&client)->sa_family;
      if (peer->addr.family == AF_INET) {
        peer->addr.address.ipv4.s_addr = ((struct sockaddr_in *)&client)->sin_addr.s_addr;
        peer->tcp_port = ntohs(((struct sockaddr_in *)&client)->sin_port);
      }
#if defined ENABLE_IPV6
      else if (peer->addr.family == AF_INET6) {
        memcpy(&peer->addr.address.ipv6, &((struct sockaddr_in6 *)&client)->sin6_addr, 16);
        peer->tcp_port = ntohs(((struct sockaddr_in6 *)&client)->sin6_port);
      }
#endif
      addr_to_str(peer->addr_str, &peer->addr);
      memcpy(&peer->id, &peer->addr, sizeof(struct host_addr)); /* XXX: some inet_ntoa()'s could be around against peer->id */

      if (bmp_misc_db->msglog_backend_methods)
        bgp_peer_log_init(peer, config.nfacctd_bmp_msglog_output, FUNC_TYPE_BMP);

      if (bmp_misc_db->dump_backend_methods)
	bmp_dump_init_peer(peer);

      /* Check: multiple TCP connections per peer */
      for (peers_check_idx = 0, peers_num = 0; peers_check_idx < config.nfacctd_bmp_max_peers; peers_check_idx++) {
        if (peers_idx != peers_check_idx && !memcmp(&bmp_peers[peers_check_idx].self.addr, &peer->addr, sizeof(bmp_peers[peers_check_idx].self.addr))) {
	  if (bmp_misc_db->is_thread && !config.nfacctd_bgp_to_agent_map) {
            Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Multiple connections from peer and no bgp_agent_map defined.\n",
                                config.name, bmp_misc_db->log_str, bmp_peers[peers_check_idx].self.addr_str);
	  }
        }
        else {
          if (bmp_peers[peers_check_idx].self.fd) peers_num++;
        }
      }

      Log(LOG_INFO, "INFO ( %s/%s ): [%s] BMP peers usage: %u/%u\n", config.name, bmp_misc_db->log_str, peer->addr_str, peers_num, config.nfacctd_bmp_max_peers);
    }

    read_data:

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

    if (!peer) goto select_again;

    ret = recv(peer->fd, &peer->buf.base[peer->buf.truncated_len], (peer->buf.len - peer->buf.truncated_len), 0);
    peer->msglen = (ret + peer->buf.truncated_len);

    if (ret <= 0) {
      Log(LOG_INFO, "INFO ( %s/%s ): [%s] BMP connection reset by peer (%d).\n", config.name, bmp_misc_db->log_str, peer->addr_str, errno);
      FD_CLR(peer->fd, &bkp_read_descs);
      bmp_peer_close(bmpp, FUNC_TYPE_BMP);
      recalc_fds = TRUE;
      goto select_again;
    }
    else {
      pkt_remaining_len = bmp_process_packet(peer->buf.base, peer->msglen, bmpp);

      /* handling offset for TCP segment reassembly */
      if (pkt_remaining_len) peer->buf.truncated_len = bmp_packet_adj_offset(peer->buf.base, peer->buf.len, peer->msglen,
									     pkt_remaining_len, peer->addr_str);
      else peer->buf.truncated_len = 0;
    }
  }
}

void bmp_prepare_thread()
{
  bmp_misc_db = &inter_domain_misc_dbs[FUNC_TYPE_BMP];
  memset(bmp_misc_db, 0, sizeof(struct bgp_misc_structs));

  bmp_misc_db->is_thread = TRUE;
  bmp_misc_db->log_str = malloc(strlen("core/BMP") + 1);
  strcpy(bmp_misc_db->log_str, "core/BMP");
}

void bmp_prepare_daemon()
{
  bmp_misc_db = &inter_domain_misc_dbs[FUNC_TYPE_BMP];
  memset(bmp_misc_db, 0, sizeof(struct bgp_misc_structs));

 bmp_misc_db->is_thread = FALSE;
 bmp_misc_db->log_str = malloc(strlen("core") + 1);
 strcpy(bmp_misc_db->log_str, "core");
}
