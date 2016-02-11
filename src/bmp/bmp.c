/*  
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2016 by Paolo Lucente
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
#include "../bgp/bgp.h"
#include "bmp.h"
#include "thread_pool.h"
#if defined WITH_RABBITMQ
#include "amqp_common.h"
#endif
#ifdef WITH_KAFKA
#include "kafka_common.h"
#endif
#ifdef WITH_JANSSON
#include <jansson.h>
#endif
#include <search.h>

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

  /* giving a kick to the BMP thread */
  send_to_pool(bmp_pool, skinny_bmp_daemon, NULL);
}
#endif

void skinny_bmp_daemon()
{
  int slen, clen, ret, rc, peers_idx, allowed, yes=1, no=0;
  int peers_idx_rr = 0, max_peers_idx = 0;
  char *bmp_packet_ptr;
  u_int32_t pkt_remaining_len=0;
  time_t now;
  afi_t afi;
  safi_t safi;

  struct bmp_peer *bmpp = NULL;
  struct bgp_peer *peer = NULL;

#if defined ENABLE_IPV6
  struct sockaddr_storage server, client;
  struct ipv6_mreq multi_req6;
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
  bmp_misc_db = &inter_domain_misc_dbs[FUNC_TYPE_BMP];
  memset(bmp_misc_db, 0, sizeof(struct bgp_misc_structs));

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
      Log(LOG_ERR, "ERROR ( %s/core/BMP ): 'bmp_daemon_ip' value is not a valid IPv4/IPv6 address. Terminating thread.\n", config.name);
      exit_all(1);
    }
    slen = addr_to_sa((struct sockaddr *)&server, &addr, config.nfacctd_bmp_port);
  }

  if (!config.nfacctd_bmp_max_peers) config.nfacctd_bmp_max_peers = BMP_MAX_PEERS_DEFAULT;
  Log(LOG_INFO, "INFO ( %s/core/BMP ): maximum BMP peers allowed: %d\n", config.name, config.nfacctd_bmp_max_peers);

  bmp_peers = malloc(config.nfacctd_bmp_max_peers*sizeof(struct bmp_peer));
  if (!bmp_peers) {
    Log(LOG_ERR, "ERROR ( %s/core/BMP ): Unable to malloc() BMP peers structure. Terminating thread.\n", config.name);
    exit_all(1);
  }
  memset(bmp_peers, 0, config.nfacctd_bmp_max_peers*sizeof(struct bmp_peer));

  if (config.nfacctd_bmp_msglog_file || config.nfacctd_bmp_msglog_amqp_routing_key || config.nfacctd_bmp_msglog_kafka_topic) {
    if (config.nfacctd_bmp_msglog_file) nfacctd_bmp_msglog_backend_methods++;
    if (config.nfacctd_bmp_msglog_amqp_routing_key) nfacctd_bmp_msglog_backend_methods++;
    if (config.nfacctd_bmp_msglog_kafka_topic) nfacctd_bmp_msglog_backend_methods++;

    if (nfacctd_bmp_msglog_backend_methods > 1) {
      Log(LOG_ERR, "ERROR ( %s/core/BMP ): bmp_daemon_msglog_file, bmp_daemon_msglog_amqp_routing_key and bmp_daemon_msglog_kafka_topic are mutually exclusive. Terminating thread.\n", config.name);
      exit_all(1);
    }
  }

  if (config.bmp_dump_file || config.bmp_dump_amqp_routing_key || config.bmp_dump_kafka_topic) {
    if (config.bmp_dump_file) bmp_dump_backend_methods++;
    if (config.bmp_dump_amqp_routing_key) bmp_dump_backend_methods++;
    if (config.bmp_dump_kafka_topic) bmp_dump_backend_methods++;

    if (bmp_dump_backend_methods > 1) {
      Log(LOG_ERR, "ERROR ( %s/core/BMP ): bmp_dump_file, bmp_dump_amqp_routing_key and bmp_dump_kafka_topic are mutually exclusive. Terminating thread.\n", config.name);
      exit_all(1);
    }
  }

  if (nfacctd_bmp_msglog_backend_methods) {
    bmp_misc_db->peers_log = malloc(config.nfacctd_bmp_max_peers*sizeof(struct bgp_peer_log));
    if (!bmp_misc_db->peers_log) {
      Log(LOG_ERR, "ERROR ( %s/core/BMP ): Unable to malloc() BMP peers log structure. Terminating thread.\n", config.name);
      exit_all(1);
    }
    memset(bmp_misc_db->peers_log, 0, config.nfacctd_bmp_max_peers*sizeof(struct bgp_peer_log));
    bgp_peer_log_seq_init(&bmp_misc_db->log_seq);

    if (config.nfacctd_bmp_msglog_amqp_routing_key) {
#ifdef WITH_RABBITMQ
      bmp_daemon_msglog_init_amqp_host();
      p_amqp_connect_to_publish(&bmp_daemon_msglog_amqp_host);

      if (!config.nfacctd_bmp_msglog_amqp_retry)
        config.nfacctd_bmp_msglog_amqp_retry = AMQP_DEFAULT_RETRY;
#else
      Log(LOG_WARNING, "WARN ( %s/core/BMP ): p_amqp_connect_to_publish() not possible due to missing --enable-rabbitmq\n", config.name);
#endif
    }

    if (config.nfacctd_bmp_msglog_kafka_topic) {
#ifdef WITH_KAFKA
      bmp_daemon_msglog_init_kafka_host();
#else
      Log(LOG_WARNING, "WARN ( %s/core/BMP ): p_kafka_connect_to_produce() not possible due to missing --enable-rabbitmq\n", config.name);
#endif
    }
  }

  if (!config.bmp_table_attr_hash_buckets) config.bmp_table_attr_hash_buckets = HASHTABSIZE;
  bgp_attr_init(config.bmp_table_attr_hash_buckets, bmp_routing_db);

  if (!config.bmp_table_peer_buckets) config.bmp_table_peer_buckets = DEFAULT_BGP_INFO_HASH;
  if (!config.bmp_table_per_peer_buckets) config.bmp_table_per_peer_buckets = DEFAULT_BGP_INFO_PER_PEER_HASH;

  if (config.bmp_table_per_peer_hash == BGP_ASPATH_HASH_PATHID)
    bmp_route_info_modulo = bgp_route_info_modulo_pathid;
  else {
    Log(LOG_ERR, "ERROR ( %s/core/BMP ): Unknown 'bmp_table_per_peer_hash' value. Terminating thread.\n", config.name);
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
      Log(LOG_ERR, "ERROR ( %s/core/BMP ): thread socket() failed. Terminating thread.\n", config.name);
      exit_all(1);
    }
  }
  if (config.nfacctd_bmp_ipprec) {
    int opt = config.nfacctd_bmp_ipprec << 5;

    rc = setsockopt(config.bmp_sock, IPPROTO_IP, IP_TOS, &opt, sizeof(opt));
    if (rc < 0) Log(LOG_ERR, "WARN ( %s/core/BMP ): setsockopt() failed for IP_TOS (errno: %d).\n", config.name, errno);
  }

  rc = setsockopt(config.bmp_sock, SOL_SOCKET, SO_REUSEADDR, (char *)&yes, sizeof(yes));
  if (rc < 0) Log(LOG_ERR, "WARN ( %s/core/BMP ): setsockopt() failed for SO_REUSEADDR (errno: %d).\n", config.name, errno);

#if (defined ENABLE_IPV6) && (defined IPV6_BINDV6ONLY)
  rc = setsockopt(config.bmp_sock, IPPROTO_IPV6, IPV6_BINDV6ONLY, (char *) &no, (socklen_t) sizeof(no));
  if (rc < 0) Log(LOG_ERR, "WARN ( %s/core ): setsockopt() failed for IPV6_BINDV6ONLY (errno: %d).\n", config.name, errno);
#endif

  if (config.nfacctd_bmp_pipe_size) {
    int l = sizeof(config.nfacctd_bmp_pipe_size);
    int saved = 0, obtained = 0;

    getsockopt(config.bmp_sock, SOL_SOCKET, SO_RCVBUF, &saved, &l);
    Setsocksize(config.bmp_sock, SOL_SOCKET, SO_RCVBUF, &config.nfacctd_bmp_pipe_size, sizeof(config.nfacctd_bmp_pipe_size));
    getsockopt(config.bmp_sock, SOL_SOCKET, SO_RCVBUF, &obtained, &l);

    Setsocksize(config.bmp_sock, SOL_SOCKET, SO_RCVBUF, &saved, l);
    getsockopt(config.bmp_sock, SOL_SOCKET, SO_RCVBUF, &obtained, &l);
    Log(LOG_INFO, "INFO ( %s/core/BMP ): bmp_daemon_pipe_size: obtained=%d target=%d.\n", config.name, obtained, config.nfacctd_bmp_pipe_size);
  }

  rc = bind(config.bmp_sock, (struct sockaddr *) &server, slen);
  if (rc < 0) {
    char null_ip_address[] = "0.0.0.0";
    char *ip_address;

    ip_address = config.nfacctd_bmp_ip ? config.nfacctd_bmp_ip : null_ip_address;
    Log(LOG_ERR, "ERROR ( %s/core/BMP ): bind() to ip=%s port=%d/tcp failed (errno: %d).\n", config.name, ip_address, config.nfacctd_bmp_port, errno);
    exit_all(1);
  }

  rc = listen(config.bmp_sock, 1);
  if (rc < 0) {
    Log(LOG_ERR, "ERROR ( %s/core/BMP ): listen() failed (errno: %d).\n", config.name, errno);
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

    sa_to_addr(&server, &srv_addr, &srv_port);
    addr_to_str(srv_string, &srv_addr);
    Log(LOG_INFO, "INFO ( %s/core/BMP ): waiting for BMP data on %s:%u\n", config.name, srv_string, srv_port);
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
    Log(LOG_WARNING, "WARN ( %s/core/BMP ): 'bmp_daemon_batch_interval' and 'bmp_daemon_batch' both set to zero.\n", config.name);
    config.nfacctd_bmp_batch = 0;
    config.nfacctd_bmp_batch_interval = 0;
  }
  else bgp_batch_init(&bp_batch, config.nfacctd_bmp_batch, config.nfacctd_bmp_batch_interval);

  if (nfacctd_bmp_msglog_backend_methods) {
#ifdef WITH_JANSSON
    if (!config.nfacctd_bmp_msglog_output) config.nfacctd_bmp_msglog_output = PRINT_OUTPUT_JSON;
#else
    Log(LOG_WARNING, "WARN ( %s/core/BMP ): bmp_daemon_msglog_output set to json but will produce no output (missing --enable-jansson).\n", config.name);
#endif
  }

  if (bmp_dump_backend_methods) {
#ifdef WITH_JANSSON
    if (!config.bmp_dump_output) config.bmp_dump_output = PRINT_OUTPUT_JSON;
#else
    Log(LOG_WARNING, "WARN ( %s/core/BMP ): bmp_table_dump_output set to json but will produce no output (missing --enable-jansson).\n", config.name);
#endif
  }

  if (bmp_dump_backend_methods) {
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
      Log(LOG_WARNING, "WARN ( %s/core/BMP ): Invalid 'bmp_dump_refresh_time'.\n", config.name);
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

    if (bmp_dump_backend_methods) {
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
    }

    if (nfacctd_bmp_msglog_backend_methods || bmp_dump_backend_methods) {
      gettimeofday(&bmp_misc_db->log_tstamp, NULL);
      compose_timestamp(bmp_misc_db->log_tstamp_str, SRVBUFLEN, &bmp_misc_db->log_tstamp, TRUE, config.sql_history_since_epoch);

      if (bmp_dump_backend_methods) {
        while (bmp_misc_db->log_tstamp.tv_sec > dump_refresh_deadline) {
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
       than because we had a message from a peeer to handle. By now we did all
       routine checks and can happily return to selet() again.
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
            if (!log_notification_isset(log_notifications.bmp_peers_throttling)) {
              Log(LOG_INFO, "INFO ( %s/core/BGP ): throttling at BMP peer #%u\n", config.name, peers_idx);
              log_notification_set(&log_notifications.bmp_peers_throttling);
            }

            close(fd);
            goto read_data;
          }
        }
      }

      if (!peer) {
        int fd;

        /* We briefly accept the new connection to be able to drop it */
        Log(LOG_ERR, "ERROR ( %s/core/BMP ): Insufficient number of BMP peers has been configured by 'bmp_daemon_max_peers' (%d).\n",
                        config.name, config.nfacctd_bmp_max_peers);
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

      if (nfacctd_bmp_msglog_backend_methods)
        bgp_peer_log_init(peer, config.nfacctd_bmp_msglog_output, FUNC_TYPE_BMP);

      if (bmp_dump_backend_methods)
	bmp_dump_init_peer(peer);

      /* Check: only one TCP connection is allowed per peer */
      for (peers_check_idx = 0, peers_num = 0; peers_check_idx < config.nfacctd_bmp_max_peers; peers_check_idx++) {
        if (peers_idx != peers_check_idx && !memcmp(&bmp_peers[peers_check_idx].self.addr, &peer->addr, sizeof(bmp_peers[peers_check_idx].self.addr))) {
          Log(LOG_ERR, "ERROR ( %s/core/BMP ): [%s] Refusing new connection from existing peer.\n",
                                config.name, bmp_peers[peers_check_idx].self.addr_str);
          FD_CLR(peer->fd, &bkp_read_descs);
          bmp_peer_close(bmpp, FUNC_TYPE_BMP);
	  recalc_fds = TRUE;
          goto read_data;
        }
        else {
          if (bmp_peers[peers_check_idx].self.fd) peers_num++;
        }
      }

      Log(LOG_INFO, "INFO ( %s/core/BMP ): [%s] BMP peers usage: %u/%u\n", config.name, peer->addr_str, peers_num, config.nfacctd_bmp_max_peers);

      if (config.nfacctd_bmp_neighbors_file) write_neighbors_file(config.nfacctd_bmp_neighbors_file);
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
      Log(LOG_INFO, "INFO ( %s/core/BMP ): [%s] BMP connection reset by peer (%d).\n", config.name, peer->addr_str, errno);
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

u_int32_t bmp_process_packet(char *bmp_packet, u_int32_t len, struct bmp_peer *bmpp)
{
  struct bgp_peer *peer;
  char *bmp_packet_ptr = bmp_packet;
  u_int32_t pkt_remaining_len, msg_len, msg_start_len;

  struct bmp_common_hdr *bch = NULL;

  if (!bmpp) return FALSE;
  peer = &bmpp->self;

  if (len < sizeof(struct bmp_common_hdr)) {
    Log(LOG_INFO, "INFO ( %s/core/BMP ): [%s] packet discarded: failed bmp_get_and_check_length() BMP common hdr\n", config.name, peer->addr_str);
    return FALSE;
  }

  for (msg_start_len = pkt_remaining_len = len; pkt_remaining_len; msg_start_len = pkt_remaining_len) {
    if (!(bch = (struct bmp_common_hdr *) bmp_get_and_check_length(&bmp_packet_ptr, &pkt_remaining_len, sizeof(struct bmp_common_hdr))))
      return msg_start_len;

    if (bch->version != BMP_V3) {
      Log(LOG_INFO, "INFO ( %s/core/BMP ): [%s] packet discarded: BMP version != %u\n", config.name, peer->addr_str, BMP_V3);
      return FALSE;
    }

    bmp_common_hdr_get_len(bch, &msg_len);
    if (pkt_remaining_len < msg_len) return msg_start_len;

    if (bch->type <= BMP_MSG_TYPE_MAX) {
      Log(LOG_DEBUG, "DEBUG ( %s/core/BMP ): [%s] [common] type: %s (%u)\n",
	  config.name, peer->addr_str, bmp_msg_types[bch->type], bch->type);
    }

    switch (bch->type) {
    case BMP_MSG_ROUTE_MONITOR:
      bmp_process_msg_route_monitor(&bmp_packet_ptr, &pkt_remaining_len, bmpp);
      break;
    case BMP_MSG_STATS:
      bmp_process_msg_stats(&bmp_packet_ptr, &pkt_remaining_len, bmpp);
      break;
    case BMP_MSG_PEER_DOWN:
      bmp_process_msg_peer_down(&bmp_packet_ptr, &pkt_remaining_len, bmpp);
      break;
    case BMP_MSG_PEER_UP:
      bmp_process_msg_peer_up(&bmp_packet_ptr, &pkt_remaining_len, bmpp); 
      break;
    case BMP_MSG_INIT:
      bmp_process_msg_init(&bmp_packet_ptr, &pkt_remaining_len, msg_len, bmpp); 
      break;
    case BMP_MSG_TERM:
      bmp_process_msg_term(&bmp_packet_ptr, &pkt_remaining_len, msg_len, bmpp); 
      break;
    case BMP_MSG_ROUTE_MIRROR:
      bmp_process_msg_route_mirror(&bmp_packet_ptr, &pkt_remaining_len, bmpp);
      break;
    default:
      Log(LOG_INFO, "INFO ( %s/core/BMP ): [%s] packet discarded: unknown message type (%u)\n", config.name, peer->addr_str, bch->type);
      break;
    }

    if ((msg_start_len - pkt_remaining_len) < msg_len) {
      /* let's jump forward: we may have been unable to parse some (sub-)element */
      bmp_jump_offset(&bmp_packet_ptr, &pkt_remaining_len, (msg_len - (msg_start_len - pkt_remaining_len)));
    }
  }

  return FALSE;
}

void bmp_process_msg_init(char **bmp_packet, u_int32_t *len, u_int32_t bmp_hdr_len, struct bmp_peer *bmpp)
{
  struct bgp_peer *peer;
  struct bmp_data bdata;
  struct bmp_init_hdr *bih;
  u_int16_t bmp_init_len;
  char *bmp_init_info;

  if (!bmpp) return;
  peer = &bmpp->self;

  memset(&bdata, 0, sizeof(bdata));
  gettimeofday(&bdata.tstamp, NULL);
  bmp_hdr_len -= sizeof(struct bmp_common_hdr);

  if (nfacctd_bmp_msglog_backend_methods) {
    char event_type[] = "log";

    bmp_log_msg(peer, &bdata, NULL, event_type, config.nfacctd_bmp_msglog_output, BMP_LOG_TYPE_INIT);
  }

  if (bmp_dump_backend_methods)
    bmp_dump_se_ll_append(peer, &bdata, NULL, BMP_LOG_TYPE_INIT);

  while (bmp_hdr_len) {
    if (!(bih = (struct bmp_init_hdr *) bmp_get_and_check_length(bmp_packet, len, sizeof(struct bmp_init_hdr)))) {
      Log(LOG_INFO, "INFO ( %s/core/BMP ): [%s] [init] packet discarded: failed bmp_get_and_check_length() BMP init hdr\n",
		config.name, peer->addr_str);
      return;
    }

    bmp_init_hdr_get_len(bih, &bmp_init_len);

    if (!(bmp_init_info = bmp_get_and_check_length(bmp_packet, len, bmp_init_len))) {
      Log(LOG_INFO, "INFO ( %s/core/BMP ): [%s] [init] packet discarded: failed bmp_get_and_check_length() BMP init info\n",
		config.name, peer->addr_str);
      return;
    }

    {
      struct bmp_log_init blinit;

      blinit.type = bih->type;
      blinit.len = bmp_init_len;
      blinit.val = bmp_init_info;

      if (nfacctd_bmp_msglog_backend_methods) {
        char event_type[] = "log";

        bmp_log_msg(peer, &bdata, &blinit, event_type, config.nfacctd_bmp_msglog_output, BMP_LOG_TYPE_INIT);
      }

      if (bmp_dump_backend_methods)
        bmp_dump_se_ll_append(peer, &bdata, &blinit, BMP_LOG_TYPE_INIT);
    }

    bmp_hdr_len -= (bmp_init_len + sizeof(struct bmp_init_hdr));
  }
}

void bmp_process_msg_term(char **bmp_packet, u_int32_t *len, u_int32_t bmp_hdr_len, struct bmp_peer *bmpp)
{
  struct bgp_peer *peer;
  struct bmp_data bdata;
  struct bmp_term_hdr *bth;
  u_int16_t bmp_term_len, reason_type = 0;
  char *bmp_term_info;

  if (!bmpp) return;
  peer = &bmpp->self;

  memset(&bdata, 0, sizeof(bdata));
  gettimeofday(&bdata.tstamp, NULL);
  bmp_hdr_len -= sizeof(struct bmp_common_hdr);

  if (nfacctd_bmp_msglog_backend_methods) {
    char event_type[] = "log";

    bmp_log_msg(peer, &bdata, NULL, event_type, config.nfacctd_bmp_msglog_output, BMP_LOG_TYPE_TERM);
  }

  if (bmp_dump_backend_methods)
    bmp_dump_se_ll_append(peer, &bdata, NULL, BMP_LOG_TYPE_TERM);

  while (bmp_hdr_len) {
    if (!(bth = (struct bmp_term_hdr *) bmp_get_and_check_length(bmp_packet, len, sizeof(struct bmp_term_hdr)))) {
      Log(LOG_INFO, "INFO ( %s/core/BMP ): [%s] [term] packet discarded: failed bmp_get_and_check_length() BMP term hdr\n",
		config.name, peer->addr_str);
       return;
    }

    bmp_term_hdr_get_len(bth, &bmp_term_len);

    if (!(bmp_term_info = bmp_get_and_check_length(bmp_packet, len, bmp_term_len))) {
      Log(LOG_INFO, "INFO ( %s/core/BMP ): [%s] [term] packet discarded: failed bmp_get_and_check_length() BMP term info\n",
		config.name, peer->addr_str);
      return;
    }

    if (bth->type == BMP_TERM_INFO_REASON && bmp_term_len == 2) bmp_term_hdr_get_reason_type(bmp_packet, len, &reason_type);

    {
      struct bmp_log_term blterm;

      blterm.type = bth->type;
      blterm.len = bmp_term_len;
      blterm.val = bmp_term_info;
      blterm.reas_type = reason_type;

      if (nfacctd_bmp_msglog_backend_methods) {
        char event_type[] = "log";

        bmp_log_msg(peer, &bdata, &blterm, event_type, config.nfacctd_bmp_msglog_output, BMP_LOG_TYPE_TERM);
      }

      if (bmp_dump_backend_methods)
        bmp_dump_se_ll_append(peer, &bdata, &blterm, BMP_LOG_TYPE_TERM);
    }

    bmp_hdr_len -= (bmp_term_len + sizeof(struct bmp_term_hdr));
  }
}

void bmp_process_msg_peer_up(char **bmp_packet, u_int32_t *len, struct bmp_peer *bmpp)
{
  struct bgp_peer *peer;
  struct bmp_data bdata;
  struct bmp_peer_hdr *bph;
  struct bmp_peer_up_hdr *bpuh;

  if (!bmpp) return;
  peer = &bmpp->self;

  memset(&bdata, 0, sizeof(bdata));

  if (!(bph = (struct bmp_peer_hdr *) bmp_get_and_check_length(bmp_packet, len, sizeof(struct bmp_peer_hdr)))) {
    Log(LOG_INFO, "INFO ( %s/core/BMP ): [%s] [peer up] packet discarded: failed bmp_get_and_check_length() BMP peer hdr\n",
	config.name, peer->addr_str);
    return;
  }

  if (!(bpuh = (struct bmp_peer_up_hdr *) bmp_get_and_check_length(bmp_packet, len, sizeof(struct bmp_peer_up_hdr)))) {
    Log(LOG_INFO, "INFO ( %s/core/BMP ): [%s] [peer up] packet discarded: failed bmp_get_and_check_length() BMP peer up hdr\n",
	config.name, peer->addr_str);
    return;
  }

  bmp_peer_hdr_get_family(bph, &bdata.family);
  bmp_peer_hdr_get_peer_ip(bph, &bdata.peer_ip, bdata.family);
  bmp_peer_hdr_get_bgp_id(bph, &bdata.bgp_id);
  bmp_peer_hdr_get_tstamp(bph, &bdata.tstamp);
  bmp_peer_hdr_get_peer_asn(bph, &bdata.peer_asn);
  bmp_peer_hdr_get_peer_type(bph, &bdata.peer_type);

  if (bdata.family) {
    /* If no timestamp in BMP then let's generate one */
    if (!bdata.tstamp.tv_sec) gettimeofday(&bdata.tstamp, NULL);

    {
      struct bmp_log_peer_up blpu;
      struct bgp_peer bgp_peer_loc, bgp_peer_rem, *bmpp_bgp_peer;
      int bgp_open_len;
      void *ret, *alloc_key;

      bmp_peer_up_hdr_get_loc_port(bpuh, &blpu.loc_port);
      bmp_peer_up_hdr_get_rem_port(bpuh, &blpu.rem_port);
      bmp_peer_up_hdr_get_local_ip(bpuh, &blpu.local_ip, bdata.family);

      bgp_open_len = bgp_parse_open_msg(&bgp_peer_loc, (*bmp_packet), FALSE, FALSE);
      bmp_get_and_check_length(bmp_packet, len, bgp_open_len);
      memcpy(&bgp_peer_loc.addr, &blpu.local_ip, sizeof(struct host_addr));
      bgp_open_len = bgp_parse_open_msg(&bgp_peer_rem, (*bmp_packet), FALSE, FALSE);
      bmp_get_and_check_length(bmp_packet, len, bgp_open_len);
      memcpy(&bgp_peer_rem.addr, &bdata.peer_ip, sizeof(struct host_addr));

      bmpp_bgp_peer = bmp_sync_loc_rem_peers(&bgp_peer_loc, &bgp_peer_rem);
      ret = pm_tsearch(bmpp_bgp_peer, &bmpp->bgp_peers, bmp_bmpp_bgp_peers_cmp, sizeof(struct bgp_peer));
      if (!ret) Log(LOG_WARNING, "WARN ( %s/core/BMP ): [%s] [peer up] tsearch() unable to insert.\n", config.name, peer->addr_str);

      if (nfacctd_bmp_msglog_backend_methods) {
        char event_type[] = "log";

        bmp_log_msg(peer, &bdata, &blpu, event_type, config.nfacctd_bmp_msglog_output, BMP_LOG_TYPE_PEER_UP);
      }

      if (bmp_dump_backend_methods)
        bmp_dump_se_ll_append(peer, &bdata, &blpu, BMP_LOG_TYPE_PEER_UP);
    }
  }
}

void bmp_process_msg_peer_down(char **bmp_packet, u_int32_t *len, struct bmp_peer *bmpp)
{
  struct bgp_peer *peer, bmpp_bgp_peer;
  struct bmp_data bdata;
  struct bmp_peer_hdr *bph;
  struct bmp_peer_down_hdr *bpdh;

  if (!bmpp) return;
  peer = &bmpp->self;

  memset(&bdata, 0, sizeof(bdata));

  if (!(bph = (struct bmp_peer_hdr *) bmp_get_and_check_length(bmp_packet, len, sizeof(struct bmp_peer_hdr)))) {
    Log(LOG_INFO, "INFO ( %s/core/BMP ): [%s] [peer down] packet discarded: failed bmp_get_and_check_length() BMP peer hdr\n",
        config.name, peer->addr_str);
    return;
  }

  if (!(bpdh = (struct bmp_peer_down_hdr *) bmp_get_and_check_length(bmp_packet, len, sizeof(struct bmp_peer_down_hdr)))) {
    Log(LOG_INFO, "INFO ( %s/core/BMP ): [%s] [peer down] packet discarded: failed bmp_get_and_check_length() BMP peer down hdr\n",
        config.name, peer->addr_str);
    return;
  }

  bmp_peer_hdr_get_family(bph, &bdata.family);
  bmp_peer_hdr_get_peer_ip(bph, &bdata.peer_ip, bdata.family);
  bmp_peer_hdr_get_bgp_id(bph, &bdata.bgp_id);
  bmp_peer_hdr_get_tstamp(bph, &bdata.tstamp);
  bmp_peer_hdr_get_peer_asn(bph, &bdata.peer_asn);
  bmp_peer_hdr_get_peer_type(bph, &bdata.peer_type);

  if (bdata.family) {
    /* If no timestamp in BMP then let's generate one */
    if (!bdata.tstamp.tv_sec) gettimeofday(&bdata.tstamp, NULL);

    {
      struct bmp_log_peer_down blpd;

      bmp_peer_down_hdr_get_reason(bpdh, &blpd.reason);
      if (blpd.reason == BMP_PEER_DOWN_LOC_CODE) bmp_peer_down_hdr_get_loc_code(bmp_packet, len, &blpd.loc_code);

      if (nfacctd_bmp_msglog_backend_methods) {
        char event_type[] = "log";

        bmp_log_msg(peer, &bdata, &blpd, event_type, config.nfacctd_bmp_msglog_output, BMP_LOG_TYPE_PEER_DOWN);
      }

      if (bmp_dump_backend_methods)
        bmp_dump_se_ll_append(peer, &bdata, &blpd, BMP_LOG_TYPE_PEER_DOWN);
    }

    // XXX: withdraw routes from peer

    pm_tdelete(&bdata.peer_ip, &bmpp->bgp_peers, bmp_bmpp_bgp_peer_host_addr_cmp);
  }
}

void bmp_process_msg_route_monitor(char **bmp_packet, u_int32_t *len, struct bmp_peer *bmpp)
{
  struct bgp_peer *peer, *bmpp_bgp_peer;
  struct bmp_data bdata;
  struct bmp_peer_hdr *bph;
  char tstamp_str[SRVBUFLEN], peer_ip[INET6_ADDRSTRLEN];
  int bgp_update_len;
  void *ret;

  if (!bmpp) return;
  peer = &bmpp->self;

  if (!(bph = (struct bmp_peer_hdr *) bmp_get_and_check_length(bmp_packet, len, sizeof(struct bmp_peer_hdr)))) {
    Log(LOG_INFO, "INFO ( %s/core/BMP ): [%s] [route] packet discarded: failed bmp_get_and_check_length() BMP peer hdr\n",
        config.name, peer->addr_str);
    return;
  }

  bmp_peer_hdr_get_family(bph, &bdata.family);
  bmp_peer_hdr_get_peer_ip(bph, &bdata.peer_ip, bdata.family);
  bmp_peer_hdr_get_bgp_id(bph, &bdata.bgp_id);
  bmp_peer_hdr_get_tstamp(bph, &bdata.tstamp);
  bmp_peer_hdr_get_peer_asn(bph, &bdata.peer_asn);
  bmp_peer_hdr_get_peer_type(bph, &bdata.peer_type);

  if (bdata.family) {
    /* If no timestamp in BMP then let's generate one */
    if (!bdata.tstamp.tv_sec) gettimeofday(&bdata.tstamp, NULL);

    compose_timestamp(tstamp_str, SRVBUFLEN, &bdata.tstamp, TRUE, config.sql_history_since_epoch);
    addr_to_str(peer_ip, &bdata.peer_ip);

    ret = pm_tfind(&bdata.peer_ip, &bmpp->bgp_peers, bmp_bmpp_bgp_peer_host_addr_cmp);

    if (ret) {
      bmpp_bgp_peer = (*(struct bgp_peer **) ret);
      /* XXX: parse BGP UPDATE(s)
      bgp_update_len = bgp_parse_update_msg(bmpp_bgp_peer, (*bmp_packet)); 
      bmp_get_and_check_length(bmp_packet, len, bgp_update_len);
      */
    }
  }
}

void bmp_process_msg_route_mirror(char **bmp_packet, u_int32_t *len, struct bmp_peer *bmpp)
{
  // XXX: support route mirroring
}

void bmp_process_msg_stats(char **bmp_packet, u_int32_t *len, struct bmp_peer *bmpp)
{
  struct bgp_peer *peer;
  struct bmp_data bdata;
  struct bmp_peer_hdr *bph;
  struct bmp_stats_hdr *bsh;
  struct bmp_stats_cnt_hdr *bsch;
  u_int64_t cnt_data64;
  u_int32_t index, count = 0, cnt_data32;
  u_int16_t cnt_type, cnt_len;
  u_int8_t got_data;

  if (!bmpp) return;
  peer = &bmpp->self;

  memset(&bdata, 0, sizeof(bdata));

  if (!(bph = (struct bmp_peer_hdr *) bmp_get_and_check_length(bmp_packet, len, sizeof(struct bmp_peer_hdr)))) {
    Log(LOG_INFO, "INFO ( %s/core/BMP ): [%s] [stats] packet discarded: failed bmp_get_and_check_length() BMP peer hdr\n",
        config.name, peer->addr_str);
    return;
  }

  if (!(bsh = (struct bmp_stats_hdr *) bmp_get_and_check_length(bmp_packet, len, sizeof(struct bmp_stats_hdr)))) {
    Log(LOG_INFO, "INFO ( %s/core/BMP ): [%s] [stats] packet discarded: failed bmp_get_and_check_length() BMP stats hdr\n",
        config.name, peer->addr_str);
    return;
  }

  bmp_peer_hdr_get_family(bph, &bdata.family);
  bmp_peer_hdr_get_peer_ip(bph, &bdata.peer_ip, bdata.family);
  bmp_peer_hdr_get_bgp_id(bph, &bdata.bgp_id);
  bmp_peer_hdr_get_tstamp(bph, &bdata.tstamp);
  bmp_peer_hdr_get_peer_asn(bph, &bdata.peer_asn);
  bmp_peer_hdr_get_peer_type(bph, &bdata.peer_type);
  bmp_stats_hdr_get_count(bsh, &count);

  if (bdata.family) {
    /* If no timestamp in BMP then let's generate one */
    if (!bdata.tstamp.tv_sec) gettimeofday(&bdata.tstamp, NULL);

    for (index = 0; index < count; index++) {
      if (!(bsch = (struct bmp_stats_cnt_hdr *) bmp_get_and_check_length(bmp_packet, len, sizeof(struct bmp_stats_cnt_hdr)))) {
        Log(LOG_INFO, "INFO ( %s/core/BMP ): [%s] [stats] packet discarded: failed bmp_get_and_check_length() BMP stats cnt hdr #%u\n",
		config.name, peer->addr_str, index);
        return;
      }

      bmp_stats_cnt_hdr_get_type(bsch, &cnt_type);
      bmp_stats_cnt_hdr_get_len(bsch, &cnt_len);
      cnt_data32 = 0; cnt_data64 = 0, got_data = TRUE;

      switch (cnt_type) {
      case BMP_STATS_TYPE0:
        if (cnt_len == 4) bmp_stats_cnt_get_data32(bmp_packet, len, &cnt_data32);
        break;
      case BMP_STATS_TYPE1:
        if (cnt_len == 4) bmp_stats_cnt_get_data32(bmp_packet, len, &cnt_data32);
        break;
      case BMP_STATS_TYPE2:
        if (cnt_len == 4) bmp_stats_cnt_get_data32(bmp_packet, len, &cnt_data32);
        break;
      case BMP_STATS_TYPE3:
        if (cnt_len == 4) bmp_stats_cnt_get_data32(bmp_packet, len, &cnt_data32);
        break;
      case BMP_STATS_TYPE4:
        if (cnt_len == 4) bmp_stats_cnt_get_data32(bmp_packet, len, &cnt_data32);
        break;
      case BMP_STATS_TYPE5:
        if (cnt_len == 4) bmp_stats_cnt_get_data32(bmp_packet, len, &cnt_data32);
        break;
      case BMP_STATS_TYPE6:
        if (cnt_len == 4) bmp_stats_cnt_get_data32(bmp_packet, len, &cnt_data32);
        break;
      case BMP_STATS_TYPE7:
        if (cnt_len == 8) bmp_stats_cnt_get_data64(bmp_packet, len, &cnt_data64);
        break;
      case BMP_STATS_TYPE8:
        if (cnt_len == 8) bmp_stats_cnt_get_data64(bmp_packet, len, &cnt_data64);
        break;
      default:
        if (cnt_len == 4) bmp_stats_cnt_get_data32(bmp_packet, len, &cnt_data32);
        else if (cnt_len == 8) bmp_stats_cnt_get_data64(bmp_packet, len, &cnt_data64);
        else {
          bmp_get_and_check_length(bmp_packet, len, cnt_len);
          got_data = FALSE;
        }
        break;
      }

      if (cnt_data32 && !cnt_data64) cnt_data64 = cnt_data32; 

      { 
        struct bmp_log_stats blstats;

        blstats.cnt_type = cnt_type;
        blstats.cnt_data = cnt_data64;
        blstats.got_data = got_data;

        if (nfacctd_bmp_msglog_backend_methods) {
          char event_type[] = "log";

          bmp_log_msg(peer, &bdata, &blstats, event_type, config.nfacctd_bmp_msglog_output, BMP_LOG_TYPE_STATS);
        } 

        if (bmp_dump_backend_methods)
          bmp_dump_se_ll_append(peer, &bdata, &blstats, BMP_LOG_TYPE_STATS);
      }
    }
  }
}

void bmp_common_hdr_get_len(struct bmp_common_hdr *bch, u_int32_t *len)
{
  if (bch && len) (*len) = ntohl(bch->len);
}

void bmp_init_hdr_get_len(struct bmp_init_hdr *bih, u_int16_t *len)
{
  if (bih && len) (*len) = ntohs(bih->len);
}

void bmp_term_hdr_get_len(struct bmp_term_hdr *bth, u_int16_t *len)
{
  if (bth && len) (*len) = ntohs(bth->len);
}

void bmp_term_hdr_get_reason_type(char **bmp_packet, u_int32_t *pkt_size, u_int16_t *type)
{
  char *ptr;

  if (bmp_packet && (*bmp_packet) && pkt_size && type) {
    ptr = bmp_get_and_check_length(bmp_packet, pkt_size, 2);
    memcpy(type, ptr, 2);
    (*type) = ntohs((*type));
  }
}

void bmp_peer_hdr_get_family(struct bmp_peer_hdr *bph, u_int8_t *family)
{
  u_int8_t version;

  if (bph && family) {
    version = (bph->flags >> 7);
    (*family) = FALSE;

    if (version == 0) (*family) = AF_INET;
#if defined ENABLE_IPV6
    else if (version == 1) (*family) = AF_INET6;
#endif
  }
}

void bmp_peer_hdr_get_peer_ip(struct bmp_peer_hdr *bph, struct host_addr *a, u_int8_t family)
{
  if (bph && a) {
    a->family = family;

    if (family == AF_INET) a->address.ipv4.s_addr = bph->addr[3]; 
#if defined ENABLE_IPV6
    else if (family == AF_INET6) memcpy(&a->address.ipv6, &bph->addr, 16); 
#endif
    else memset(a, 0, sizeof(struct host_addr));
  }
}

void bmp_peer_hdr_get_bgp_id(struct bmp_peer_hdr *bph, struct host_addr *a)
{
  if (bph && a) {
    a->family = AF_INET;
    a->address.ipv4.s_addr = bph->bgp_id;
  }
}

void bmp_peer_hdr_get_tstamp(struct bmp_peer_hdr *bph, struct timeval *tv)
{
  u_int32_t sec, usec;

  if (bph && tv) {
    if (bph->tstamp_sec) {
      sec = ntohl(bph->tstamp_sec);
      usec = ntohl(bph->tstamp_usec);

      tv->tv_sec = sec;
      tv->tv_usec = usec;
    }
  }
}

void bmp_peer_hdr_get_peer_asn(struct bmp_peer_hdr *bph, u_int32_t *asn)
{
  if (bph && asn) (*asn) = ntohl(bph->asn);
}

void bmp_peer_hdr_get_peer_type(struct bmp_peer_hdr *bph, u_int8_t *type)
{
  if (bph && type) (*type) = bph->type;
}

void bmp_peer_up_hdr_get_local_ip(struct bmp_peer_up_hdr *bpuh, struct host_addr *a, u_int8_t family)
{
  if (bpuh && a && family) {
    a->family = family;

    if (family == AF_INET) a->address.ipv4.s_addr = bpuh->loc_addr[3];
#if defined ENABLE_IPV6
    else if (family == AF_INET6) memcpy(&a->address.ipv6, &bpuh->loc_addr, 16);
#endif
  }
}

void bmp_peer_up_hdr_get_loc_port(struct bmp_peer_up_hdr *bpuh, u_int16_t *port)
{
  if (bpuh && port) (*port) = ntohs(bpuh->loc_port);
}

void bmp_peer_up_hdr_get_rem_port(struct bmp_peer_up_hdr *bpuh, u_int16_t *port)
{
  if (bpuh && port) (*port) = ntohs(bpuh->rem_port);
}

void bmp_peer_down_hdr_get_reason(struct bmp_peer_down_hdr *bpdh, u_char *reason)
{
  if (bpdh && reason) (*reason) = bpdh->reason;
}

void bmp_peer_down_hdr_get_loc_code(char **bmp_packet, u_int32_t *pkt_size, u_int16_t *code)
{
  char *ptr;
 
  if (bmp_packet && (*bmp_packet) && pkt_size && code) {
    ptr = bmp_get_and_check_length(bmp_packet, pkt_size, 2); 
    memcpy(code, ptr, 2);
    (*code) = ntohs((*code));
  }
}

void bmp_stats_hdr_get_count(struct bmp_stats_hdr *bsh, u_int32_t *count)
{
  if (bsh && count) (*count) = ntohl(bsh->count);
}

void bmp_stats_cnt_hdr_get_type(struct bmp_stats_cnt_hdr *bsch, u_int16_t *type)
{
  if (bsch && type) (*type) = ntohs(bsch->type);
}

void bmp_stats_cnt_hdr_get_len(struct bmp_stats_cnt_hdr *bsch, u_int16_t *len)
{
  if (bsch && len) (*len) = ntohs(bsch->len);
}

void bmp_stats_cnt_get_data32(char **bmp_packet, u_int32_t *pkt_size, u_int32_t *data)
{
  char *ptr;

  if (bmp_packet && (*bmp_packet) && pkt_size && data) {
    ptr = bmp_get_and_check_length(bmp_packet, pkt_size, 4);
    memcpy(data, ptr, 4);
    (*data) = ntohl((*data));
  }
}

void bmp_stats_cnt_get_data64(char **bmp_packet, u_int32_t *pkt_size, u_int64_t *data)
{
  char *ptr;

  if (bmp_packet && (*bmp_packet) && pkt_size && data) {
    ptr = bmp_get_and_check_length(bmp_packet, pkt_size, 8);
    memcpy(data, ptr, 8);
    (*data) = pm_ntohll((*data));
  }
}

char *bmp_get_and_check_length(char **bmp_packet_ptr, u_int32_t *pkt_size, u_int32_t len)
{
  char *current_ptr = NULL;
  
  if (bmp_packet_ptr && (*bmp_packet_ptr) && pkt_size) {
    if ((*pkt_size) >= len) {
      current_ptr = (*bmp_packet_ptr);
      (*pkt_size) -= len;
      (*bmp_packet_ptr) += len;
    }
  }

  return current_ptr;
}

void bmp_jump_offset(char **bmp_packet_ptr, u_int32_t *len, u_int32_t offset)
{
  if (bmp_packet_ptr && (*bmp_packet_ptr) && len) {
    if (offset <= (*len)) {
      (*bmp_packet_ptr) += offset;
      (*len) -= offset;
    }
  }
}

u_int32_t bmp_packet_adj_offset(char *bmp_packet, u_int32_t buf_len, u_int32_t recv_len, u_int32_t remaining_len, char *addr_str)
{
  char tmp_packet[BGP_BUFFER_SIZE];
  
  if (!bmp_packet || recv_len > buf_len || remaining_len >= buf_len || remaining_len > recv_len) {
    if (addr_str)
      Log(LOG_INFO, "INFO ( %s/core/BMP ): [%s] packet discarded: failed bmp_packet_adj_offset()\n", config.name, addr_str);

    return FALSE;
  }

  memcpy(tmp_packet, &bmp_packet[recv_len - remaining_len], remaining_len);
  memcpy(bmp_packet, tmp_packet, remaining_len);

  return remaining_len;
}

void bmp_link_misc_structs(struct bgp_misc_structs *bms)
{
#if defined WITH_RABBITMQ
  bms->msglog_amqp_host = &bmp_daemon_msglog_amqp_host;
#endif
#if defined WITH_KAFKA
  bms->msglog_kafka_host = &bmp_daemon_msglog_kafka_host;
#endif
  bms->max_peers = config.nfacctd_bmp_max_peers;
  bms->neighbors_file = config.nfacctd_bmp_neighbors_file;
  bms->dump_file = config.bmp_dump_file;
  bms->dump_amqp_routing_key = config.bmp_dump_amqp_routing_key;
  bms->dump_amqp_routing_key_rr = config.bmp_dump_amqp_routing_key_rr;
  bms->dump_kafka_topic = config.bmp_dump_kafka_topic;
  bms->dump_kafka_topic_rr = config.bmp_dump_kafka_topic_rr;
  bms->msglog_file = config.nfacctd_bmp_msglog_file;
  bms->msglog_amqp_routing_key = config.nfacctd_bmp_msglog_amqp_routing_key;
  bms->msglog_amqp_routing_key_rr = config.nfacctd_bmp_msglog_amqp_routing_key_rr;
  bms->msglog_kafka_topic = config.nfacctd_bmp_msglog_kafka_topic;
  bms->msglog_kafka_topic_rr = config.nfacctd_bmp_msglog_kafka_topic_rr;
  strcpy(bms->peer_str, "bmp_router");

  bms->table_peer_buckets = config.bmp_table_peer_buckets;
  bms->table_per_peer_buckets = config.bmp_table_per_peer_buckets;
  bms->table_attr_hash_buckets = config.bmp_table_attr_hash_buckets;
  bms->table_per_peer_hash = config.bmp_table_per_peer_hash;
  bms->route_info_modulo = bmp_route_info_modulo;
}

struct bgp_peer *bmp_sync_loc_rem_peers(struct bgp_peer *bgp_peer_loc, struct bgp_peer *bgp_peer_rem)
{
  if (!bgp_peer_loc || !bgp_peer_rem) return NULL;

  if (!bgp_peer_loc->cap_4as || !bgp_peer_rem->cap_4as) bgp_peer_rem->cap_4as = FALSE;
  if (!bgp_peer_loc->cap_add_paths || !bgp_peer_rem->cap_add_paths) bgp_peer_rem->cap_add_paths = FALSE;

  bgp_peer_rem->type = FUNC_TYPE_BMP;

  return bgp_peer_rem;
}

void bmp_peer_compose(struct bgp_peer *peer, struct bmp_data *bdata)
{
  if (!peer || !bdata) return;

  memset(peer, 0, sizeof(struct bgp_peer));
  
  memcpy(&peer->addr, &bdata->peer_ip, sizeof(struct host_addr));
/* XXX:
  memcpy(&peer->id, &bdata->bgp_id, sizeof(struct host_addr));
  addr_to_str(peer->addr_str, &peer->addr);
  peer->as = bdata->peer_asn;
  peer->status = Established;
  peer->type = FUNC_TYPE_BMP;
*/
} 

int bmp_peer_init(struct bmp_peer *bmpp, int type)
{
  return bgp_peer_init(&bmpp->self, type);
}

void bmp_peer_close(struct bmp_peer *bmpp, int type)
{
  if (!bmpp) return;

  tdestroy(&bmpp->bgp_peers, bmp_bmpp_bgp_peers_free);
  bgp_peer_close(&bmpp->self, type);
}

int bmp_bmpp_bgp_peers_cmp(const void *a, const void *b)
{
  return memcmp(&((struct bgp_peer *)a)->addr, &((struct bgp_peer *)b)->addr, sizeof(struct host_addr));
}

int bmp_bmpp_bgp_peer_host_addr_cmp(const void *a, const void *b)
{
  return memcmp(a, &((struct bgp_peer *)b)->addr, sizeof(struct host_addr));
}

void bmp_bmpp_bgp_peers_free(void *a)
{
}
