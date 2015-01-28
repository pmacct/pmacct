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
#define __BGP_C

/* includes */
#include "pmacct.h"
#include "bgp.h"
#include "thread_pool.h"
#if defined WITH_RABBITMQ
#include "amqp_common.h"
#endif
#ifdef WITH_JANSSON
#include <jansson.h>
#endif

/* variables to be exported away */
thread_pool_t *bgp_pool;

/* Functions */
#if defined ENABLE_THREADS
void nfacctd_bgp_wrapper()
{
  /* initialize variables */
  if (!config.nfacctd_bgp_port) config.nfacctd_bgp_port = BGP_TCP_PORT;

  /* initialize threads pool */
  bgp_pool = allocate_thread_pool(1);
  assert(bgp_pool);
  Log(LOG_DEBUG, "DEBUG ( %s/core/BGP ): %d thread(s) initialized\n", config.name, 1);

  /* giving a kick to the BGP thread */
  send_to_pool(bgp_pool, skinny_bgp_daemon, NULL);
}
#endif

void skinny_bgp_daemon()
{
  int slen, ret, rc, peers_idx, allowed;
  struct host_addr addr;
  struct bgp_header bhdr;
  struct bgp_peer *peer;
  struct bgp_open *bopen;
  char bgp_packet[BGP_MAX_PACKET_SIZE], *bgp_packet_ptr;
  char bgp_reply_pkt[BGP_MAX_PACKET_SIZE], *bgp_reply_pkt_ptr;
#if defined ENABLE_IPV6
  struct sockaddr_storage server, client;
  struct ipv6_mreq multi_req6;
#else
  struct sockaddr server, client;
#endif
  afi_t afi;
  safi_t safi;
  int clen = sizeof(client), yes=1;
  u_int16_t remote_as = 0;
  u_int32_t remote_as4 = 0;
  time_t now, dump_refresh_deadline;
  struct hosts_table allow;
  struct bgp_md5_table bgp_md5;
  struct timeval dump_refresh_timeout, *drt_ptr;

  /* BGP peer batching vars */
  int bgp_current_batch_elem = 0;
  time_t bgp_current_batch_stamp_base = 0;

  /* select() stuff */
  fd_set read_descs, bkp_read_descs; 
  int select_fd, select_num;

  /* initial cleanups */
  reload_map_bgp_thread = FALSE;
  reload_log_bgp_thread = FALSE;
  memset(&server, 0, sizeof(server));
  memset(&client, 0, sizeof(client));
  memset(bgp_packet, 0, BGP_MAX_PACKET_SIZE);
  memset(&allow, 0, sizeof(struct hosts_table));

  if (!config.bgp_table_attr_hash_buckets) config.bgp_table_attr_hash_buckets = HASHTABSIZE;
  bgp_attr_init();

  /* socket creation for BGP server: IPv4 only */
#if (defined ENABLE_IPV6 && defined V4_MAPPED)
  if (!config.nfacctd_bgp_ip) {
    struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&server;

    sa6->sin6_family = AF_INET6;
    sa6->sin6_port = htons(config.nfacctd_bgp_port);
    slen = sizeof(struct sockaddr_in6);
  }
#else
  if (!config.nfacctd_bgp_ip) {
    struct sockaddr_in *sa4 = (struct sockaddr_in *)&server;

    sa4->sin_family = AF_INET;
    sa4->sin_addr.s_addr = htonl(0);
    sa4->sin_port = htons(config.nfacctd_bgp_port);
    slen = sizeof(struct sockaddr_in);
  }
#endif
  else {
    trim_spaces(config.nfacctd_bgp_ip);
    ret = str_to_addr(config.nfacctd_bgp_ip, &addr);
    if (!ret) {
      Log(LOG_ERR, "ERROR ( %s/core/BGP ): 'bgp_daemon_ip' value is not a valid IPv4/IPv6 address. Terminating thread.\n", config.name);
      exit_all(1);
    }
    slen = addr_to_sa((struct sockaddr *)&server, &addr, config.nfacctd_bgp_port);
  }

  if (!config.nfacctd_bgp_max_peers) config.nfacctd_bgp_max_peers = MAX_BGP_PEERS_DEFAULT;
  Log(LOG_INFO, "INFO ( %s/core/BGP ): maximum BGP peers allowed: %d\n", config.name, config.nfacctd_bgp_max_peers);

  peers = malloc(config.nfacctd_bgp_max_peers*sizeof(struct bgp_peer));
  if (!peers) {
    Log(LOG_ERR, "ERROR ( %s/core/BGP ): Unable to malloc() BGP peers structure. Terminating thread.\n", config.name);
    exit_all(1);
  }
  memset(peers, 0, config.nfacctd_bgp_max_peers*sizeof(struct bgp_peer));

  if (config.nfacctd_bgp_msglog_file || config.nfacctd_bgp_msglog_amqp_routing_key) {
    if (config.nfacctd_bgp_msglog_file && config.nfacctd_bgp_msglog_amqp_routing_key) {
      Log(LOG_ERR, "ERROR ( %s/core/BGP ): bgp_daemon_msglog_file and bgp_daemon_msglog_amqp_routing_key are mutually exclusive. Terminating thread.\n", config.name);
      exit_all(1);
    }

    peers_log = malloc(config.nfacctd_bgp_max_peers*sizeof(struct bgp_peer_log));
    if (!peers_log) {
      Log(LOG_ERR, "ERROR ( %s/core/BGP ): Unable to malloc() BGP peers log structure. Terminating thread.\n", config.name);
      exit_all(1);
    }
    memset(peers_log, 0, config.nfacctd_bgp_max_peers*sizeof(struct bgp_peer_log));
    bgp_peer_log_seq_init();

    if (config.nfacctd_bgp_msglog_amqp_routing_key) {
#ifdef WITH_RABBITMQ
      bgp_daemon_msglog_init_amqp_host();
      p_amqp_connect(&bgp_daemon_msglog_amqp_host);

      if (!config.nfacctd_bgp_msglog_amqp_retry)
	config.nfacctd_bgp_msglog_amqp_retry = AMQP_DEFAULT_RETRY;
#else
      Log(LOG_WARNING, "WARN ( %s/core/BGP ): p_amqp_connect() not possible due to missing --enable-rabbitmq\n", config.name);
#endif
    }
  }

  if (config.bgp_table_dump_file && config.bgp_table_dump_amqp_routing_key) {
    Log(LOG_ERR, "ERROR ( %s/core/BGP ): bgp_table_dump_file and bgp_table_dump_amqp_routing_key are mutually exclusive. Terminating thread.\n", config.name);
    exit_all(1);
  }

  if (!config.bgp_table_peer_buckets) config.bgp_table_peer_buckets = DEFAULT_BGP_INFO_HASH;
  if (!config.bgp_table_per_peer_buckets) config.bgp_table_per_peer_buckets = DEFAULT_BGP_INFO_PER_PEER_HASH;

  if (config.bgp_table_per_peer_hash == BGP_ASPATH_HASH_PATHID)
    bgp_route_info_modulo = bgp_route_info_modulo_pathid; 
  else {
    Log(LOG_ERR, "ERROR ( %s/core/BGP ): Unknown 'bgp_table_per_peer_hash' value. Terminating thread.\n", config.name);
    exit_all(1);
  }

  config.bgp_sock = socket(((struct sockaddr *)&server)->sa_family, SOCK_STREAM, 0);
  if (config.bgp_sock < 0) {
#if (defined ENABLE_IPV6 && defined V4_MAPPED)
    /* retry with IPv4 */
    if (!config.nfacctd_bgp_ip) {
      struct sockaddr_in *sa4 = (struct sockaddr_in *)&server;

      sa4->sin_family = AF_INET;
      sa4->sin_addr.s_addr = htonl(0);
      sa4->sin_port = htons(config.nfacctd_bgp_port);
      slen = sizeof(struct sockaddr_in);

      config.bgp_sock = socket(((struct sockaddr *)&server)->sa_family, SOCK_STREAM, 0);
    }
#endif

    if (config.bgp_sock < 0) {
      Log(LOG_ERR, "ERROR ( %s/core/BGP ): thread socket() failed. Terminating thread.\n", config.name);
      exit_all(1);
    }
  }
  if (config.nfacctd_bgp_ipprec) {
    int opt = config.nfacctd_bgp_ipprec << 5;

    rc = setsockopt(config.bgp_sock, IPPROTO_IP, IP_TOS, &opt, sizeof(opt));
    if (rc < 0) Log(LOG_ERR, "WARN ( %s/core/BGP ): setsockopt() failed for IP_TOS (errno: %d).\n", config.name, errno);
  }

  rc = setsockopt(config.bgp_sock, SOL_SOCKET, SO_REUSEADDR, (char *)&yes, sizeof(yes));
  if (rc < 0) Log(LOG_ERR, "WARN ( %s/core/BGP ): setsockopt() failed for SO_REUSEADDR (errno: %d).\n", config.name, errno);

  if (config.nfacctd_bgp_pipe_size) {
    int l = sizeof(config.nfacctd_bgp_pipe_size);
    u_int64_t saved = 0, obtained = 0;

    getsockopt(config.bgp_sock, SOL_SOCKET, SO_RCVBUF, &saved, &l);
    Setsocksize(config.bgp_sock, SOL_SOCKET, SO_RCVBUF, &config.nfacctd_bgp_pipe_size, sizeof(config.nfacctd_bgp_pipe_size));
    getsockopt(config.bgp_sock, SOL_SOCKET, SO_RCVBUF, &obtained, &l);

    Setsocksize(config.bgp_sock, SOL_SOCKET, SO_RCVBUF, &saved, l);
    getsockopt(config.bgp_sock, SOL_SOCKET, SO_RCVBUF, &obtained, &l);
    Log(LOG_INFO, "INFO ( %s/core/BGP ): bgp_daemon_pipe_size: obtained=%u target=%u.\n", config.name, obtained, config.nfacctd_bgp_pipe_size);
  }

  rc = bind(config.bgp_sock, (struct sockaddr *) &server, slen);
  if (rc < 0) {
    char null_ip_address[] = "0.0.0.0";
    char *ip_address;

    ip_address = config.nfacctd_bgp_ip ? config.nfacctd_bgp_ip : null_ip_address;
    Log(LOG_ERR, "ERROR ( %s/core/BGP ): bind() to ip=%s port=%d/tcp failed (errno: %d).\n", config.name, ip_address, config.nfacctd_bgp_port, errno);
    exit_all(1);
  }

  rc = listen(config.bgp_sock, 1);
  if (rc < 0) {
    Log(LOG_ERR, "ERROR ( %s/core/BGP ): listen() failed (errno: %d).\n", config.name, errno);
    exit_all(1);
  }

  /* Preparing for syncronous I/O multiplexing */
  select_fd = 0;
  FD_ZERO(&bkp_read_descs);
  FD_SET(config.bgp_sock, &bkp_read_descs);

  {
    char srv_string[INET6_ADDRSTRLEN];
    struct host_addr srv_addr;
    u_int16_t srv_port;

    sa_to_addr(&server, &srv_addr, &srv_port);
    addr_to_str(srv_string, &srv_addr);
    Log(LOG_INFO, "INFO ( %s/core/BGP ): waiting for BGP data on %s:%u\n", config.name, srv_string, srv_port);
  }

  /* Preparing ACL, if any */
  if (config.nfacctd_bgp_allow_file) load_allow_file(config.nfacctd_bgp_allow_file, &allow);

  /* Preparing MD5 keys, if any */
  if (config.nfacctd_bgp_md5_file) {
    load_bgp_md5_file(config.nfacctd_bgp_md5_file, &bgp_md5);
    if (bgp_md5.num) process_bgp_md5_file(config.bgp_sock, &bgp_md5);
  }

  /* Let's initialize clean shared RIB */
  for (afi = AFI_IP; afi < AFI_MAX; afi++) {
    for (safi = SAFI_UNICAST; safi < SAFI_MAX; safi++) {
      rib[afi][safi] = bgp_table_init(afi, safi);
    }
  }

  /* BGP peers batching checks */
  if ((config.nfacctd_bgp_batch && !config.nfacctd_bgp_batch_interval) ||
      (config.nfacctd_bgp_batch_interval && !config.nfacctd_bgp_batch)) {
    Log(LOG_WARNING, "WARN ( %s/core/BGP ): 'bgp_daemon_batch_interval' and 'bgp_daemon_batch' both set to zero.\n", config.name);
    config.nfacctd_bgp_batch = 0;
    config.nfacctd_bgp_batch_interval = 0;
  }

  if (!config.nfacctd_bgp_msglog_output && (config.nfacctd_bgp_msglog_file ||
      config.nfacctd_bgp_msglog_amqp_routing_key))
#ifdef WITH_JANSSON
    config.nfacctd_bgp_msglog_output = PRINT_OUTPUT_JSON;
#else
    Log(LOG_WARNING, "WARN ( %s/core/BGP ): bgp_daemon_msglog_output set to json but will produce no output (missing --enable-jansson).\n", config.name);
#endif

  if (!config.bgp_table_dump_output && (config.bgp_table_dump_file ||
      config.bgp_table_dump_amqp_routing_key))
#ifdef WITH_JANSSON
    config.bgp_table_dump_output = PRINT_OUTPUT_JSON;
#else
    Log(LOG_WARNING, "WARN ( %s/core/BGP ): bgp_table_dump_output set to json but will produce no output (missing --enable-jansson).\n", config.name);
#endif

  if (config.bgp_table_dump_file || config.bgp_table_dump_amqp_routing_key) {
    char dump_roundoff[] = "m";
    time_t tmp_time;

    if (config.bgp_table_dump_refresh_time) {
      gettimeofday(&log_tstamp, NULL);
      dump_refresh_deadline = log_tstamp.tv_sec;
      tmp_time = roundoff_time(dump_refresh_deadline, dump_roundoff);
      while ((tmp_time+config.bgp_table_dump_refresh_time) < dump_refresh_deadline) {
        tmp_time += config.bgp_table_dump_refresh_time;
      }
      dump_refresh_deadline = tmp_time;
      dump_refresh_deadline += config.bgp_table_dump_refresh_time; /* it's a deadline not a basetime */
    }
    else {
      config.bgp_table_dump_file = NULL;
      Log(LOG_WARNING, "WARN ( %s/core/BGP ): Invalid 'bgp_table_dump_refresh_time'.\n", config.name);
    }

    bgp_table_dump_init_amqp_host();
  }

  for (;;) {
    select_again:

    select_fd = config.bgp_sock;
    for (peers_idx = 0; peers_idx < config.nfacctd_bgp_max_peers; peers_idx++)
      if (select_fd < peers[peers_idx].fd) select_fd = peers[peers_idx].fd; 
    select_fd++;
    memcpy(&read_descs, &bkp_read_descs, sizeof(bkp_read_descs));

    if (config.bgp_table_dump_file || config.bgp_table_dump_amqp_routing_key) {
      int delta;

      calc_refresh_timeout_sec(dump_refresh_deadline, log_tstamp.tv_sec, &delta);
      dump_refresh_timeout.tv_sec = delta;
      dump_refresh_timeout.tv_usec = 0;
      drt_ptr = &dump_refresh_timeout;
    }
    else drt_ptr = NULL;

    select_num = select(select_fd, &read_descs, NULL, NULL, drt_ptr);
    if (select_num < 0) goto select_again;

    /* signals handling */
    if (reload_map_bgp_thread) {
      if (config.nfacctd_bgp_md5_file) {
	unload_bgp_md5_file(&bgp_md5);
	if (bgp_md5.num) process_bgp_md5_file(config.bgp_sock, &bgp_md5); // process unload
	load_bgp_md5_file(config.nfacctd_bgp_md5_file, &bgp_md5);
	if (bgp_md5.num) process_bgp_md5_file(config.bgp_sock, &bgp_md5); // process load
      }
      reload_map_bgp_thread = FALSE;
    }

    if (reload_log_bgp_thread) {
      for (peers_idx = 0; peers_idx < config.nfacctd_bgp_max_peers; peers_idx++) {
	if (peers_log[peers_idx].fd) {
	  fclose(peers_log[peers_idx].fd);
	  peers_log[peers_idx].fd = open_logfile(peers_log[peers_idx].filename, "a");
	}
	else break;
      }
    }

    if (config.nfacctd_bgp_msglog_file || config.nfacctd_bgp_msglog_amqp_routing_key || 
	config.bgp_table_dump_file || config.bgp_table_dump_amqp_routing_key) {
      gettimeofday(&log_tstamp, NULL);
      compose_timestamp(log_tstamp_str, SRVBUFLEN, &log_tstamp, TRUE);

      if (config.bgp_table_dump_file || config.bgp_table_dump_amqp_routing_key) {
	while (log_tstamp.tv_sec > dump_refresh_deadline) {
	  bgp_handle_dump_event();
	  dump_refresh_deadline += config.bgp_table_dump_refresh_time;
	}
      }

#ifdef WITH_RABBITMQ
      if (config.nfacctd_bgp_msglog_amqp_routing_key) { 
        time_t last_fail = p_amqp_get_last_fail(&bgp_daemon_msglog_amqp_host);

	if (last_fail && (last_fail + config.nfacctd_bgp_msglog_amqp_retry < log_tstamp.tv_sec)) {
          bgp_daemon_msglog_init_amqp_host();
          p_amqp_connect(&bgp_daemon_msglog_amqp_host);
	}
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
    if (FD_ISSET(config.bgp_sock, &read_descs)) {
      int peers_check_idx, peers_num;

      for (peer = NULL, peers_idx = 0; peers_idx < config.nfacctd_bgp_max_peers; peers_idx++) {
        if (peers[peers_idx].fd == 0) {
          now = time(NULL);

          if (bgp_current_batch_elem > 0 || now > (bgp_current_batch_stamp_base + config.nfacctd_bgp_batch_interval)) {
            peer = &peers[peers_idx];
            if (bgp_peer_init(peer)) peer = NULL;

            log_notification_unset(&log_notifications.bgp_peers_throttling);

            if (config.nfacctd_bgp_batch && peer) {
              if (now > (bgp_current_batch_stamp_base + config.nfacctd_bgp_batch_interval)) {
                bgp_current_batch_elem = config.nfacctd_bgp_batch;
                bgp_current_batch_stamp_base = now;
              }

              if (bgp_current_batch_elem > 0) bgp_current_batch_elem--;
            }

            break;
	  }
          else { /* throttle */
            int fd = 0;

            /* We briefly accept the new connection to be able to drop it */
	    if (!log_notification_isset(log_notifications.bgp_peers_throttling)) {
              Log(LOG_INFO, "INFO ( %s/core/BGP ): throttling at BGP peer #%u\n", config.name, peers_idx);
	      log_notification_set(&log_notifications.bgp_peers_throttling);
	    }
            fd = accept(config.bgp_sock, (struct sockaddr *) &client, &clen);
            close(fd);
            goto select_again;
          }
        }
	/* XXX: replenish sessions with expired keepalives */
      }

      if (!peer) {
	int fd;

	/* We briefly accept the new connection to be able to drop it */
        Log(LOG_ERR, "ERROR ( %s/core/BGP ): Insufficient number of BGP peers has been configured by 'bgp_daemon_max_peers' (%d).\n",
			config.name, config.nfacctd_bgp_max_peers);
	fd = accept(config.bgp_sock, (struct sockaddr *) &client, &clen);
	close(fd);
	goto select_again;
      }
      peer->fd = accept(config.bgp_sock, (struct sockaddr *) &client, &clen);

#if defined ENABLE_IPV6
      ipv4_mapped_to_ipv4(&client);
#endif

      /* If an ACL is defined, here we check against and enforce it */
      if (allow.num) allowed = check_allow(&allow, (struct sockaddr *)&client);
      else allowed = TRUE;

      if (!allowed) {
	bgp_peer_close(peer);
	goto select_again;
      }

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

      if (config.nfacctd_bgp_msglog_file || config.nfacctd_bgp_msglog_amqp_routing_key)
	bgp_peer_log_init(peer, config.nfacctd_bgp_msglog_output);

      /* Check: only one TCP connection is allowed per peer */
      for (peers_check_idx = 0, peers_num = 0; peers_check_idx < config.nfacctd_bgp_max_peers; peers_check_idx++) { 
	if (peers_idx != peers_check_idx && !memcmp(&peers[peers_check_idx].addr, &peer->addr, sizeof(peers[peers_check_idx].addr))) { 
	  now = time(NULL);
	  if ((now - peers[peers_check_idx].last_keepalive) > peers[peers_check_idx].ht) {
            Log(LOG_INFO, "INFO ( %s/core/BGP ): [Id: %s] Replenishing stale connection by peer.\n",
				config.name, inet_ntoa(peers[peers_check_idx].id.address.ipv4));
            FD_CLR(peers[peers_check_idx].fd, &bkp_read_descs);
            bgp_peer_close(&peers[peers_check_idx]);
	  }
	  else {
	    Log(LOG_ERR, "ERROR ( %s/core/BGP ): [Id: %s] Refusing new connection from existing peer (residual holdtime: %u).\n",
				config.name, inet_ntoa(peers[peers_check_idx].id.address.ipv4),
				(peers[peers_check_idx].ht - (now - peers[peers_check_idx].last_keepalive)));
	    FD_CLR(peer->fd, &bkp_read_descs);
	    bgp_peer_close(peer);
	    goto select_again;
	  }
        }
	else {
	  if (peers[peers_check_idx].fd) peers_num++;
	}
      }

      Log(LOG_INFO, "INFO ( %s/core/BGP ): BGP peers usage: %u/%u\n", config.name, peers_num, config.nfacctd_bgp_max_peers);

      if (config.nfacctd_bgp_neighbors_file)
	write_neighbors_file(config.nfacctd_bgp_neighbors_file);

      goto select_again; 
    }

    /* We have something coming in: let's lookup which peer is thatl
       XXX: to be optimized */
    for (peer = NULL, peers_idx = 0; peers_idx < config.nfacctd_bgp_max_peers; peers_idx++) {
      if (peers[peers_idx].fd && FD_ISSET(peers[peers_idx].fd, &read_descs)) {
	peer = &peers[peers_idx];
	break;
      }
    } 

    if (!peer) {
      Log(LOG_ERR, "ERROR ( %s/core/BGP ): message delivered to an unknown peer (FD bits: %d; FD max: %d)\n", config.name, select_num, select_fd);
      goto select_again;
    }

    peer->msglen = ret = recv(peer->fd, bgp_packet, BGP_MAX_PACKET_SIZE, 0);

    if (ret <= 0) {
      Log(LOG_INFO, "INFO ( %s/core/BGP ): [Id: %s] Existing BGP connection was reset (%d).\n", config.name, inet_ntoa(peer->id.address.ipv4), errno);
      FD_CLR(peer->fd, &bkp_read_descs);
      bgp_peer_close(peer);
      goto select_again;
    }
    else {
      /* Appears a valid peer with a valid BGP message: before
	 continuing let's see if it's time to send a KEEPALIVE
	 back */
      now = time(NULL);
      if (peer->status == Established && ((now - peer->last_keepalive) > (peer->ht / 2))) {
        bgp_reply_pkt_ptr = bgp_reply_pkt;
        bgp_reply_pkt_ptr += bgp_keepalive_msg(bgp_reply_pkt_ptr);
        ret = send(peer->fd, bgp_reply_pkt, bgp_reply_pkt_ptr - bgp_reply_pkt, 0);
	peer->last_keepalive = now;
      } 

      /* BGP payload reassembly if required */
      if (peer->buf.truncated_len) {
	if (peer->buf.truncated_len+peer->msglen > peer->buf.len) {
	  char *newptr;

	  peer->buf.len += peer->buf.truncated_len+peer->msglen;
	  newptr = malloc(peer->buf.len);
	  if (newptr) {
	    memcpy(newptr, peer->buf.base, peer->buf.truncated_len);
	    free(peer->buf.base);
	    peer->buf.base = newptr;
	  }
          else {
            Log(LOG_ERR, "ERROR ( %s/core/BGP ): malloc() failed (newptr). Exiting ..\n", config.name);
            exit_all(1);
          }
	}
	memcpy(peer->buf.base+peer->buf.truncated_len, bgp_packet, peer->msglen);
	peer->msglen += peer->buf.truncated_len;
	peer->buf.truncated_len = 0;

	bgp_packet_ptr = peer->buf.base;
      }
      else {
	if (peer->buf.len > BGP_MAX_PACKET_SIZE) { 
	  peer->buf.base = realloc(peer->buf.base, BGP_MAX_PACKET_SIZE);
	  memset(peer->buf.base, 0, BGP_MAX_PACKET_SIZE);
	  peer->buf.len = BGP_MAX_PACKET_SIZE;
	}
	bgp_packet_ptr = bgp_packet;
      } 

      memset(&bhdr, 0, sizeof(bhdr));
      for ( ; peer->msglen > 0; peer->msglen -= ntohs(bhdr.bgpo_len), bgp_packet_ptr += ntohs(bhdr.bgpo_len)) { 
	memcpy(&bhdr, bgp_packet_ptr, sizeof(bhdr));

	/* BGP payload fragmentation check */
	if (peer->msglen < BGP_HEADER_SIZE || peer->msglen < ntohs(bhdr.bgpo_len)) {
	  peer->buf.truncated_len = peer->msglen;
	  if (bgp_packet_ptr != peer->buf.base) {
	    char *aux_buf;

	    aux_buf = malloc(peer->buf.truncated_len);
	    if (aux_buf) {
	      memcpy(aux_buf, bgp_packet_ptr, peer->buf.truncated_len);
	      memcpy(peer->buf.base, aux_buf, peer->buf.truncated_len);
	      free(aux_buf);
	    }
	    else {
              Log(LOG_ERR, "ERROR ( %s/core/BGP ): malloc() failed (aux_buf). Exiting ..\n", config.name);
	      exit_all(1);
	    } 
	  }

	  // goto bgp_recv;
	  goto select_again;
	  }

	  if (!bgp_marker_check(&bhdr, BGP_MARKER_SIZE)) {
            Log(LOG_INFO, "INFO ( %s/core/BGP ): [Id: %s] Received malformed BGP packet (marker check failed).\n",
				config.name, inet_ntoa(peer->id.address.ipv4));
	    FD_CLR(peer->fd, &bkp_read_descs);
	    bgp_peer_close(peer);
	    goto select_again;
          }

	  memset(bgp_reply_pkt, 0, BGP_MAX_PACKET_SIZE);

	  switch (bhdr.bgpo_type) {
	  case BGP_OPEN:
		  remote_as = remote_as4 = 0;

		  if (peer->status < OpenSent) {
		    peer->status = Active;
		    bopen = (struct bgp_open *) bgp_packet;  

		    if (bopen->bgpo_version == BGP_VERSION4) {
			  char bgp_open_cap_reply[BGP_MAX_PACKET_SIZE-BGP_MIN_OPEN_MSG_SIZE];
			  char *bgp_open_cap_reply_ptr = bgp_open_cap_reply, *bgp_open_cap_ptr;

			  remote_as = ntohs(bopen->bgpo_myas);
			  peer->ht = MAX(5, ntohs(bopen->bgpo_holdtime));
			  peer->id.family = AF_INET; 
			  peer->id.address.ipv4.s_addr = bopen->bgpo_id;

			  /* OPEN options parsing */
			  if (bopen->bgpo_optlen && bopen->bgpo_optlen >= 2) {
			    u_int8_t len, opt_type, opt_len, cap_type;
			    char *ptr;

			    ptr = bgp_packet + BGP_MIN_OPEN_MSG_SIZE;
			    memset(bgp_open_cap_reply, 0, sizeof(bgp_open_cap_reply));

			    for (len = bopen->bgpo_optlen; len > 0; len -= opt_len, ptr += opt_len) {
				  opt_type = (u_int8_t) ptr[0];
				  opt_len = (u_int8_t) ptr[1];

				  if (opt_len > bopen->bgpo_optlen) {
				    Log(LOG_INFO, "INFO ( %s/core/BGP ): [Id: %s] Received malformed BGP packet (option length).\n",
							config.name, inet_ntoa(peer->id.address.ipv4));
				    FD_CLR(peer->fd, &bkp_read_descs);
				    bgp_peer_close(peer);
				    goto select_again;
				  } 

				  /* 
 				   * If we stumble upon capabilities let's curse through them to find
 				   * some we are forced to support (ie. MP-BGP or 4-bytes AS support)
 				   */
				  if (opt_type == BGP_OPTION_CAPABILITY) {
				    char *optcap_ptr;
				    int optcap_len;

				    bgp_open_cap_ptr = ptr;
				    ptr += 2;
				    len -= 2;
				    optcap_ptr = ptr;
				    optcap_len = len;

				    while (optcap_len > 0) {
				      u_int8_t cap_len = optcap_ptr[1];
				      u_int8_t cap_type = optcap_ptr[0];

				      if (cap_len > optcap_len) {
                                        Log(LOG_INFO, "INFO ( %s/core/BGP ): [Id: %s] Received malformed BGP packet (malformed capability: %x).\n",
							config.name, inet_ntoa(peer->id.address.ipv4), cap_type);
                                        FD_CLR(peer->fd, &bkp_read_descs);
                                        bgp_peer_close(peer);
                                        goto select_again;
                                      }
				     
				      if (cap_type == BGP_CAPABILITY_MULTIPROTOCOL) {
				  	char *cap_ptr = optcap_ptr+2;
				  	struct capability_mp_data cap_data;

				  	memcpy(&cap_data, cap_ptr, sizeof(cap_data));
					  
				  	Log(LOG_INFO, "INFO ( %s/core/BGP ): Capability: MultiProtocol [%x] AFI [%x] SAFI [%x]\n",
							config.name, cap_type, ntohs(cap_data.afi), cap_data.safi);
				  	peer->cap_mp = TRUE;
				  	memcpy(bgp_open_cap_reply_ptr, bgp_open_cap_ptr, opt_len+2); 
				  	bgp_open_cap_reply_ptr += opt_len+2;
				      }
				      else if (cap_type == BGP_CAPABILITY_4_OCTET_AS_NUMBER) {
					char *cap_ptr = optcap_ptr+2;
					u_int32_t as4_ptr;

				   	if (cap_len == CAPABILITY_CODE_AS4_LEN) {
					  struct capability_as4 cap_data;

					  memcpy(&cap_data, cap_ptr, sizeof(cap_data));

					  Log(LOG_INFO, "INFO ( %s/core/BGP ): Capability: 4-bytes AS [%x] ASN [%u]\n",
					    		config.name, cap_type, ntohl(cap_data.as4));
					  memcpy(&as4_ptr, cap_ptr, 4);
					  remote_as4 = ntohl(as4_ptr);
					  memcpy(bgp_open_cap_reply_ptr, bgp_open_cap_ptr, opt_len+2); 
					  peer->cap_4as = bgp_open_cap_reply_ptr+4;
					  bgp_open_cap_reply_ptr += opt_len+2;
					}
					else {
					  Log(LOG_INFO, "INFO ( %s/core/BGP ): [Id: %s] Received malformed BGP packet (malformed AS4 option).\n",
							config.name, inet_ntoa(peer->id.address.ipv4));
					  FD_CLR(peer->fd, &bkp_read_descs);
					  bgp_peer_close(peer);
					  goto select_again;
					}
				      }
                                      else if (cap_type == BGP_CAPABILITY_ADD_PATHS) {
                                        char *cap_ptr = optcap_ptr+2;
					struct capability_add_paths cap_data;

                                        memcpy(&cap_data, cap_ptr, sizeof(cap_data));

                                        Log(LOG_INFO, "INFO ( %s/core/BGP ): Capability: ADD-PATHs [%x] AFI [%x] SAFI [%x] SEND_RECEIVE [%x]\n",
                                            		config.name, cap_type, ntohs(cap_data.afi), cap_data.safi, cap_data.sndrcv);

					if (cap_data.sndrcv == 2 /* send */) {
                                          peer->cap_add_paths = TRUE; 
                                          memcpy(bgp_open_cap_reply_ptr, bgp_open_cap_ptr, opt_len+2);
                                          *(bgp_open_cap_reply_ptr+((opt_len+2)-1)) = 1; /* receive */
                                          bgp_open_cap_reply_ptr += opt_len+2;
					}
                                      }

				      optcap_ptr += cap_len+2;
				      optcap_len -= cap_len+2;
				    }
				  }
				  else {
				    ptr += 2;
				    len -= 2;
				  }
			    } 
			  }

			  /* Let's grasp the remote ASN */
			  if (remote_as == BGP_AS_TRANS) {
				if (remote_as4 && remote_as4 != BGP_AS_TRANS)
				  peer->as = remote_as4;
				/* It is not valid to use the transitional ASN in the BGP OPEN and
 				   present an ASN == 0 or ASN == 23456 in the 4AS capability */
				else {
				  Log(LOG_INFO, "INFO ( %s/core/BGP ): [Id: %s] Received malformed BGP packet (invalid AS4 option).\n",
						config.name, inet_ntoa(peer->id.address.ipv4));
				  FD_CLR(peer->fd, &bkp_read_descs);
				  bgp_peer_close(peer);
				  goto select_again;
				}
			  }
			  else {
				if (remote_as4 == 0 || remote_as4 == remote_as)
				  peer->as = remote_as;
 				/* It is not valid to not use the transitional ASN in the BGP OPEN and
				   present an ASN != remote_as in the 4AS capability */
				else {
				  Log(LOG_INFO, "INFO ( %s/core/BGP ): [Id: %s] Received malformed BGP packet (mismatching AS4 option).\n",
						config.name, inet_ntoa(peer->id.address.ipv4));
				  FD_CLR(peer->fd, &bkp_read_descs);
				  bgp_peer_close(peer);
				  goto select_again;
				}
			  }

			  Log(LOG_INFO, "INFO ( %s/core/BGP ): [Id: %s] BGP_OPEN: Asn: %u HoldTime: %u\n", config.name,
					inet_ntoa(peer->id.address.ipv4), peer->as, peer->ht);

			  bgp_reply_pkt_ptr = bgp_reply_pkt;

			  /* Replying to OPEN message */
			  peer->myas = peer->as;
			  ret = bgp_open_msg(bgp_reply_pkt_ptr, bgp_open_cap_reply, bgp_open_cap_reply_ptr-bgp_open_cap_reply, peer);
			  if (ret > 0) bgp_reply_pkt_ptr += ret;
			  else {
				Log(LOG_INFO, "INFO ( %s/core/BGP ): [Id: %s] Local peer is 4AS while remote peer is 2AS: unsupported configuration.\n",
						config.name, inet_ntoa(peer->id.address.ipv4));
				FD_CLR(peer->fd, &bkp_read_descs);
				bgp_peer_close(peer);
				goto select_again;
			  }

			  /* sticking a KEEPALIVE to it */
			  bgp_reply_pkt_ptr += bgp_keepalive_msg(bgp_reply_pkt_ptr);
			  ret = send(peer->fd, bgp_reply_pkt, bgp_reply_pkt_ptr - bgp_reply_pkt, 0);
			  peer->last_keepalive = now;
		    }
		    else {
  			  Log(LOG_INFO, "INFO ( %s/core/BGP ): [Id: %s] Received malformed BGP packet (unsupported version).\n",
					config.name, inet_ntoa(peer->id.address.ipv4));
			  FD_CLR(peer->fd, &bkp_read_descs);
			  bgp_peer_close(peer);
			  goto select_again;
		    }

			// peer->status = OpenSent;
			peer->status = Established;
	      }
		  /* If we already passed successfully through an BGP OPEN exchange
  			 let's just ignore further BGP OPEN messages */
		  break;
	  case BGP_NOTIFICATION:
		  Log(LOG_INFO, "INFO ( %s/core/BGP ): [Id: %s] BGP_NOTIFICATION received\n", config.name, inet_ntoa(peer->id.address.ipv4));
		  FD_CLR(peer->fd, &bkp_read_descs);
		  bgp_peer_close(peer);
		  goto select_again;
		  break;
	  case BGP_KEEPALIVE:
		  Log(LOG_DEBUG, "DEBUG ( %s/core/BGP ): [Id: %s] BGP_KEEPALIVE received\n", config.name, inet_ntoa(peer->id.address.ipv4));
		  if (peer->status >= OpenSent) {
		    if (peer->status < Established) peer->status = Established;

		    bgp_reply_pkt_ptr = bgp_reply_pkt;
		    bgp_reply_pkt_ptr += bgp_keepalive_msg(bgp_reply_pkt_ptr);
		    ret = send(peer->fd, bgp_reply_pkt, bgp_reply_pkt_ptr - bgp_reply_pkt, 0);
		    peer->last_keepalive = now;

		    Log(LOG_DEBUG, "DEBUG ( %s/core/BGP ): [Id: %s] BGP_KEEPALIVE sent\n", config.name, inet_ntoa(peer->id.address.ipv4));
		  }
		  /* If we didn't pass through a successful BGP OPEN exchange just yet
  			 let's temporarily discard BGP KEEPALIVEs */
		  break;
	  case BGP_UPDATE:
		  if (peer->status < Established) {
		    Log(LOG_DEBUG, "DEBUG ( %s/core/BGP ): [Id: %s] BGP UPDATE received (no neighbor). Discarding.\n",
					config.name, inet_ntoa(peer->id.address.ipv4));
			FD_CLR(peer->fd, &bkp_read_descs);
			bgp_peer_close(peer);
			goto select_again;
		  }

		  ret = bgp_update_msg(peer, bgp_packet_ptr);
		  if (ret < 0) Log(LOG_WARNING, "WARN ( %s/core/BGP ): [Id: %s] BGP UPDATE: malformed (%d).\n",
						config.name, inet_ntoa(peer->id.address.ipv4), ret);
		  break;
	    default:
	      Log(LOG_INFO, "INFO ( %s/core/BGP ): [Id: %s] Received malformed BGP packet (unsupported message type).\n",
				config.name, inet_ntoa(peer->id.address.ipv4));
	      FD_CLR(peer->fd, &bkp_read_descs);
	      bgp_peer_close(peer);
	      goto select_again;
	    }
	  }
	}
  }
}

/* Marker check. */
int bgp_marker_check(struct bgp_header *bhdr, int length)
{
  int i;

  for (i = 0; i < length; i++)
    if (bhdr->bgpo_marker[i] != 0xff)
      return 0;

  return 1;
}

/* write BGP KEEPALIVE msg */
int bgp_keepalive_msg(char *msg)
{
  struct bgp_header bhdr;
	
  memset(&bhdr.bgpo_marker, 0xff, BGP_MARKER_SIZE);
  bhdr.bgpo_type = BGP_KEEPALIVE;
  bhdr.bgpo_len = htons(BGP_HEADER_SIZE);
  memcpy(msg, &bhdr, sizeof(bhdr));

  return BGP_HEADER_SIZE;
}

/* write BGP OPEN msg */
int bgp_open_msg(char *msg, char *cp_msg, int cp_msglen, struct bgp_peer *peer)
{
  struct bgp_open *bopen_reply = (struct bgp_open *) msg;
  char my_id_static[] = "1.2.3.4", *my_id = my_id_static;
  struct host_addr my_id_addr, bgp_ip, bgp_id;
  u_int16_t local_as;
  u_int32_t *local_as4;

  memset(bopen_reply->bgpo_marker, 0xff, BGP_MARKER_SIZE);
  bopen_reply->bgpo_type = BGP_OPEN;
  bopen_reply->bgpo_version = BGP_VERSION4;
  bopen_reply->bgpo_holdtime = htons(peer->ht);
  if (peer->myas > BGP_AS_MAX) {
    if (peer->cap_4as) {
      bopen_reply->bgpo_myas = htons(BGP_AS_TRANS);
      local_as4 = (u_int32_t *) peer->cap_4as;
      *local_as4 = htonl(peer->myas);
    }
    /* This is currently an unsupported configuration */
    else return -1;
  }
  else {
    local_as = peer->myas;
    bopen_reply->bgpo_myas = htons(local_as);
    if (peer->cap_4as) {
      local_as4 = (u_int32_t *) peer->cap_4as;
      *local_as4 = htonl(peer->myas);
    }
  }

  bopen_reply->bgpo_optlen = cp_msglen;
  bopen_reply->bgpo_len = htons(BGP_MIN_OPEN_MSG_SIZE + bopen_reply->bgpo_optlen);

  if (config.nfacctd_bgp_ip) str_to_addr(config.nfacctd_bgp_ip, &bgp_ip);
  else memset(&bgp_ip, 0, sizeof(bgp_ip));

  if (config.nfacctd_bgp_id) str_to_addr(config.nfacctd_bgp_id, &bgp_id);
  else memset(&bgp_id, 0, sizeof(bgp_id));

  /* set BGP router-ID trial #1 */
  memset(&my_id_addr, 0, sizeof(my_id_addr));

  if (config.nfacctd_bgp_id && !is_any(&bgp_id) && !my_id_addr.family) {
    my_id = config.nfacctd_bgp_id;
    str_to_addr(my_id, &my_id_addr);
    if (my_id_addr.family != AF_INET) memset(&my_id_addr, 0, sizeof(my_id_addr));
  }

  /* set BGP router-ID trial #2 */
  if (config.nfacctd_bgp_ip && !is_any(&bgp_ip) && !my_id_addr.family) {
    my_id = config.nfacctd_bgp_ip;
    str_to_addr(my_id, &my_id_addr);
    if (my_id_addr.family != AF_INET) memset(&my_id_addr, 0, sizeof(my_id_addr));
  }

  /* set BGP router-ID trial #3 */
  if (!my_id_addr.family) {
    my_id = my_id_static;
    str_to_addr(my_id, &my_id_addr);
  }

  bopen_reply->bgpo_id = my_id_addr.address.ipv4.s_addr;

  memcpy(msg+BGP_MIN_OPEN_MSG_SIZE, cp_msg, cp_msglen);

  return BGP_MIN_OPEN_MSG_SIZE + cp_msglen;
}

int bgp_update_msg(struct bgp_peer *peer, char *pkt)
{
  struct bgp_header bhdr;
  u_char *startp, *endp;
  struct bgp_attr attr;
  u_int16_t attribute_len;
  u_int16_t update_len;
  u_int16_t withdraw_len;
  u_int16_t end, tmp;
  struct bgp_nlri update;
  struct bgp_nlri withdraw;
  struct bgp_nlri mp_update;
  struct bgp_nlri mp_withdraw;
  int ret;

  /* Set initial values. */
  memset(&attr, 0, sizeof (struct bgp_attr));
  memset(&update, 0, sizeof (struct bgp_nlri));
  memset(&withdraw, 0, sizeof (struct bgp_nlri));
  memset(&mp_update, 0, sizeof (struct bgp_nlri));
  memset(&mp_withdraw, 0, sizeof (struct bgp_nlri));

  memcpy(&bhdr, pkt, sizeof(bhdr));
  end = ntohs(bhdr.bgpo_len);
  end -= BGP_HEADER_SIZE;
  pkt += BGP_HEADER_SIZE;

  /* handling Unfeasible routes */
  memcpy(&tmp, pkt, 2);
  withdraw_len = ntohs(tmp);
  if (withdraw_len > end) return -1;  
  else {
	end -= withdraw_len;
    pkt += 2; end -= 2;
  }

  if (withdraw_len > 0) {
	withdraw.afi = AFI_IP;
	withdraw.safi = SAFI_UNICAST;
	withdraw.nlri = pkt;
	withdraw.length = withdraw_len;
    pkt += withdraw_len;
  }

  /* handling Attributes */
  memcpy(&tmp, pkt, 2);
  attribute_len = ntohs(tmp);
  if (attribute_len > end) return -1;
  else {
	end -= attribute_len;
	pkt += 2; end -= 2;
  }

  if (attribute_len > 0) {
	ret = bgp_attr_parse(peer, &attr, pkt, attribute_len, &mp_update, &mp_withdraw);
	if (ret < 0) return ret;
    pkt += attribute_len;
  }

  update_len = end; end = 0;

  if (update_len > 0) {
	update.afi = AFI_IP;
	update.safi = SAFI_UNICAST;
	update.nlri = pkt;
	update.length = update_len;
  }

  if (withdraw.length) bgp_nlri_parse(peer, NULL, &withdraw);

  /* NLRI parsing */
  if (update.length) 
	bgp_nlri_parse(peer, &attr, &update);
	
  if (mp_update.length
	  && mp_update.afi == AFI_IP
	  && (mp_update.safi == SAFI_UNICAST || mp_update.safi == SAFI_MPLS_LABEL))
	bgp_nlri_parse(peer, &attr, &mp_update);

  if (mp_withdraw.length
	  && mp_withdraw.afi == AFI_IP
	  && (mp_withdraw.safi == SAFI_UNICAST || mp_withdraw.safi == SAFI_MPLS_LABEL))
	bgp_nlri_parse (peer, NULL, &mp_withdraw);

  if (mp_update.length
          && mp_update.afi == AFI_IP && mp_update.safi == SAFI_MPLS_VPN)
        bgp_nlri_parse(peer, &attr, &mp_update);

  if (mp_withdraw.length
          && mp_withdraw.afi == AFI_IP && mp_withdraw.safi == SAFI_MPLS_VPN)
        bgp_nlri_parse(peer, NULL, &mp_withdraw);

#if defined ENABLE_IPV6
  if (mp_update.length
	  && mp_update.afi == AFI_IP6
	  && (mp_update.safi == SAFI_UNICAST || mp_update.safi == SAFI_MPLS_LABEL))
	bgp_nlri_parse(peer, &attr, &mp_update);

  if (mp_withdraw.length
	  && mp_withdraw.afi == AFI_IP6
	  && (mp_withdraw.safi == SAFI_UNICAST || mp_withdraw.safi == SAFI_MPLS_LABEL))
	bgp_nlri_parse (peer, NULL, &mp_withdraw);
#endif

  /* Receipt of End-of-RIB can be processed here; being a silent
	 BGP receiver only, honestly it doesn't matter to us */

  /* Everything is done.  We unintern temporary structures which
	 interned in bgp_attr_parse(). */
  if (attr.aspath)
	aspath_unintern(attr.aspath);
  if (attr.community)
	community_unintern(attr.community);
  if (attr.ecommunity)
	ecommunity_unintern(attr.ecommunity);

  return 0;
}

/* BGP UPDATE Attribute parsing */
int bgp_attr_parse(struct bgp_peer *peer, struct bgp_attr *attr, char *ptr, int len, struct bgp_nlri *mp_update, struct bgp_nlri *mp_withdraw)
{
  int to_the_end = len, ret;
  u_int8_t flag, type, *tmp, mp_nlri = 0;
  u_int16_t tmp16, attr_len;
  struct aspath *as4_path = NULL;

  while (to_the_end > 0) {
	if (to_the_end < BGP_ATTR_MIN_LEN) return -1;

	tmp = (u_int8_t *) ptr++; to_the_end--; flag = *tmp;
	tmp = (u_int8_t *) ptr++; to_the_end--; type = *tmp;

    /* Attribute length */
	if (flag & BGP_ATTR_FLAG_EXTLEN) {
	  memcpy(&tmp16, ptr, 2); ptr += 2; to_the_end -= 2; attr_len = ntohs(tmp16);
	  if (attr_len > to_the_end) return -1;
	}
	else {
	  tmp = (u_int8_t *) ptr++; to_the_end--; attr_len = *tmp;
	  if (attr_len > to_the_end) return -1;
	}

	switch (type) {
	case BGP_ATTR_AS_PATH:
		ret = bgp_attr_parse_aspath(peer, attr_len, attr, ptr, flag);
		break;
	case BGP_ATTR_AS4_PATH:
		ret = bgp_attr_parse_as4path(peer, attr_len, attr, ptr, flag, &as4_path);
		break;
	case BGP_ATTR_NEXT_HOP:
		ret = bgp_attr_parse_nexthop(peer, attr_len, attr, ptr, flag);
		break;
	case BGP_ATTR_COMMUNITIES:
		ret = bgp_attr_parse_community(peer, attr_len, attr, ptr, flag);
		break;
	case BGP_ATTR_EXT_COMMUNITIES:
		ret = bgp_attr_parse_ecommunity(peer, attr_len, attr, ptr, flag);
		break;
	case BGP_ATTR_MULTI_EXIT_DISC:
		ret = bgp_attr_parse_med(peer, attr_len, attr, ptr, flag);
		break;
	case BGP_ATTR_LOCAL_PREF:
		ret = bgp_attr_parse_local_pref(peer, attr_len, attr, ptr, flag);
		break;
	case BGP_ATTR_ORIGIN:
		ret = bgp_attr_parse_origin(peer, attr_len, attr, ptr, flag);
		break;
	case BGP_ATTR_MP_REACH_NLRI:
		ret = bgp_attr_parse_mp_reach(peer, attr_len, attr, ptr, mp_update);
		mp_nlri = TRUE;
		break;
	case BGP_ATTR_MP_UNREACH_NLRI:
		ret = bgp_attr_parse_mp_unreach(peer, attr_len, attr, ptr, mp_withdraw);
		mp_nlri = TRUE;
		break;
	default:
		ret = 0;
		break;
	}

	if (ret < 0) return ret; 

	ptr += attr_len;
	to_the_end -= attr_len;
  }

  if (as4_path) {
	/* AS_PATH and AS4_PATH merge up */
    ret = bgp_attr_munge_as4path(peer, attr, as4_path);

  /* AS_PATH and AS4_PATH info are now fully merged;
	 hence we can free up temporary structures. */
    aspath_unintern(as4_path);
	
	if (ret < 0) return ret;
  }

  return 0;
}

int bgp_attr_parse_aspath(struct bgp_peer *peer, u_int16_t len, struct bgp_attr *attr, char *ptr, u_int8_t flag)
{
  u_int8_t cap_4as = peer->cap_4as ? 1 : 0;

  attr->aspath = aspath_parse(ptr, len, cap_4as);

  return 0;
}

int bgp_attr_parse_as4path(struct bgp_peer *peer, u_int16_t len, struct bgp_attr *attr, char *ptr, u_int8_t flag, struct aspath **aspath4)
{
  *aspath4 = aspath_parse(ptr, len, 1);

  return 0;
}

int bgp_attr_parse_nexthop(struct bgp_peer *peer, u_int16_t len, struct bgp_attr *attr, char *ptr, u_char flag)
{
  u_int32_t tmp;

  /* Length check. */
  if (len != 4) return -1;

  memcpy(&tmp, ptr, 4);
  attr->nexthop.s_addr = tmp;
  ptr += 4;

  return 0;
}

int bgp_attr_parse_community(struct bgp_peer *peer, u_int16_t len, struct bgp_attr *attr, char *ptr, u_int8_t flag)
{
  if (len == 0) attr->community = NULL;
  else attr->community = (struct community *) community_parse((u_int32_t *)ptr, len);

  return 0;
}

int bgp_attr_parse_ecommunity(struct bgp_peer *peer, u_int16_t len, struct bgp_attr *attr, char *ptr, u_int8_t flag)
{
  if (len == 0) attr->ecommunity = NULL;
  else attr->ecommunity = (struct ecommunity *) ecommunity_parse(ptr, len);

  return 0;
}

/* MED atrribute. */
int bgp_attr_parse_med(struct bgp_peer *peer, u_int16_t len, struct bgp_attr *attr, char *ptr, u_char flag)
{
  u_int32_t tmp;

  /* Length check. */
  if (len != 4) return -1;

  memcpy(&tmp, ptr, 4);
  attr->med = ntohl(tmp);
  ptr += 4;

  return 0;
}

/* Local preference attribute. */
int bgp_attr_parse_local_pref(struct bgp_peer *peer, u_int16_t len, struct bgp_attr *attr, char *ptr, u_char flag)
{
  u_int32_t tmp;

  if (len != 4) return -1;

  memcpy(&tmp, ptr, 4);
  attr->local_pref = ntohl(tmp);
  ptr += 4;

  return 0;
}

/* Origin attribute. */
int bgp_attr_parse_origin(struct bgp_peer *peer, u_int16_t len, struct bgp_attr *attr, char *ptr, u_char flag)
{
  if (len != 1) return -1;

  memcpy(&attr->local_pref, ptr, 1);
  ptr += 1;

  return 0;
}

int bgp_attr_parse_mp_reach(struct bgp_peer *peer, u_int16_t len, struct bgp_attr *attr, char *ptr, struct bgp_nlri *mp_update)
{
  u_int16_t afi, tmp16, mpreachlen, mpnhoplen;
  u_int16_t nlri_len;
  u_char safi;

  /* length check */
#define BGP_MP_REACH_MIN_SIZE 5
  if (len < BGP_MP_REACH_MIN_SIZE) return -1;

  mpreachlen = len;
  memcpy(&tmp16, ptr, 2); afi = ntohs(tmp16); ptr += 2;
  safi = *ptr; ptr++;
  mpnhoplen = *ptr; ptr++;
  mpreachlen -= 4; /* 2+1+1 above */ 
  
  /* IPv4 (4), RD+IPv4 (12), IPv6 (16), RD+IPv6 (24), IPv6 link-local+IPv6 global (32) */
  if (mpnhoplen == 4 || mpnhoplen == 12 || mpnhoplen == 16 || mpnhoplen == 24 || mpnhoplen == 32) {
	if (mpreachlen > mpnhoplen) {
	  switch (mpnhoplen) {
	  case 4:
	    attr->mp_nexthop.family = AF_INET;
	    memcpy(&attr->mp_nexthop.address.ipv4, ptr, 4); 
	    break;
	  case 12:
	    // XXX: make any use of RD ? 
	    attr->mp_nexthop.family = AF_INET;
	    memcpy(&attr->mp_nexthop.address.ipv4, ptr+8, 4);
	    break;
#if defined ENABLE_IPV6
	  case 16:
	  case 32:
	    attr->mp_nexthop.family = AF_INET6;
	    memcpy(&attr->mp_nexthop.address.ipv6, ptr, 16); 
	    break;
	  case 24:
            // XXX: make any use of RD ? 
            attr->mp_nexthop.family = AF_INET6;
            memcpy(&attr->mp_nexthop.address.ipv6, ptr+8, 16);
            break;
#endif
	  default:
	    memset(&attr->mp_nexthop, 0, sizeof(struct host_addr));
	    break;
	  }

	  mpreachlen -= mpnhoplen;
	  ptr += mpnhoplen;

	  /* Skipping SNPA info */
	  mpreachlen--; ptr++;
	}
	else return -1;
  }
  else return -1;

  nlri_len = mpreachlen;

  /* length check once again */
  if (!nlri_len || nlri_len > len) return -1;

  /* XXX: perhaps sanity check (applies to: mp_reach, mp_unreach, update, withdraw) */

  mp_update->afi = afi;
  mp_update->safi = safi;
  mp_update->nlri = ptr;
  mp_update->length = nlri_len;

  return 0;
}

int bgp_attr_parse_mp_unreach(struct bgp_peer *peer, u_int16_t len, struct bgp_attr *attr, char *ptr, struct bgp_nlri *mp_withdraw)
{
  u_int16_t afi, mpunreachlen, tmp16;
  u_int16_t withdraw_len;
  u_char safi;

  /* length check */
#define BGP_MP_UNREACH_MIN_SIZE 3
  if (len < BGP_MP_UNREACH_MIN_SIZE) return -1;

  mpunreachlen = len;
  memcpy(&tmp16, ptr, 2); afi = ntohs(tmp16); ptr += 2;
  safi = *ptr; ptr++;
  mpunreachlen -= 3; /* 2+1 above */

  withdraw_len = mpunreachlen;

  mp_withdraw->afi = afi;
  mp_withdraw->safi = safi;
  mp_withdraw->nlri = ptr;
  mp_withdraw->length = withdraw_len;

  return 0;
}


/* BGP UPDATE NLRI parsing */
int bgp_nlri_parse(struct bgp_peer *peer, void *attr, struct bgp_nlri *info)
{
  u_char *pnt;
  u_char *lim;
  u_char safi, label[3];
  struct prefix p;
  int psize, end;
  int ret;
  u_int32_t tmp32;
  u_int16_t tmp16;
  struct rd_ip  *rdi;
  struct rd_as  *rda;
  struct rd_as4 *rda4;
  rd_t rd;
  path_id_t path_id;

  memset (&p, 0, sizeof(struct prefix));
  memset (&rd, 0, sizeof(rd_t));
  memset (&path_id, 0, sizeof(path_id_t));

  pnt = info->nlri;
  lim = pnt + info->length;
  end = info->length;
  safi = info->safi;

  for (; pnt < lim; pnt += psize) {

	/* handle path identifier */
	if (peer->cap_add_paths) {
	  memcpy(&path_id, pnt, 4);
	  path_id = ntohl(path_id);
	  pnt += 4;
	}

	memset(&p, 0, sizeof(struct prefix));

	/* Fetch prefix length and cross-check */
	p.prefixlen = *pnt++; end--;
	p.family = bgp_afi2family (info->afi);

	if (info->safi == SAFI_UNICAST) { 
	  if ((info->afi == AFI_IP && p.prefixlen > 32) || (info->afi == AFI_IP6 && p.prefixlen > 128)) return -1;

	  psize = ((p.prefixlen+7)/8);
	  if (psize > end) return -1;

	  /* Fetch prefix from NLRI packet. */
	  memcpy(&p.u.prefix, pnt, psize);

	  // XXX: check address correctnesss now that we have it?
	}
	else if (info->safi == SAFI_MPLS_LABEL) { /* rfc3107 labeled unicast */
	  if ((info->afi == AFI_IP && p.prefixlen > 56) || (info->afi == AFI_IP6 && p.prefixlen > 152)) return -1;

          psize = ((p.prefixlen+7)/8);
          if (psize > end) return -1;

          /* Fetch prefix from NLRI packet, drop the 3 bytes label. */
          memcpy(&p.u.prefix, pnt+3, (psize-3));
	  p.prefixlen -= 24;

	  /* As we trash the label anyway, let's rewrite the SAFI as plain unicast */
	  safi = SAFI_UNICAST;
	}
	else if (info->safi == SAFI_MPLS_VPN) { /* rfc4364 BGP/MPLS IP Virtual Private Networks */
	  if (info->afi == AFI_IP && p.prefixlen > 120 || (info->afi == AFI_IP6 && p.prefixlen > 216)) return -1;

          psize = ((p.prefixlen+7)/8);
          if (psize > end) return -1;

          /* Fetch label (3), RD (8) and prefix (4) from NLRI packet */
	  memcpy(label, pnt, 3);

	  memcpy(&rd.type, pnt+3, 2);
	  rd.type = ntohs(rd.type);
	  switch(rd.type) {
	  case RD_TYPE_AS: 
	    rda = (struct rd_as *) &rd;
	    memcpy(&tmp16, pnt+5, 2);
	    memcpy(&tmp32, pnt+7, 4);
	    rda->as = ntohs(tmp16);
	    rda->val = ntohl(tmp32);
	    break;
	  case RD_TYPE_IP: 
            rdi = (struct rd_ip *) &rd;
            memcpy(&tmp32, pnt+5, 4);
            memcpy(&tmp16, pnt+9, 2);
            rdi->ip.s_addr = ntohl(tmp32);
            rdi->val = ntohs(tmp16);
            break;
	  case RD_TYPE_AS4: 
	    rda4 = (struct rd_as4 *) &rd;
	    memcpy(&tmp32, pnt+5, 4);
	    memcpy(&tmp16, pnt+9, 2);
	    rda4->as = ntohl(tmp32);
	    rda4->val = ntohs(tmp16);
	    break;
	  default:
	    return -1;
	    break;
	  }
	  
          memcpy(&p.u.prefix, pnt+11, (psize-11));
          p.prefixlen -= 88;
	}
	
    /* Let's do our job now! */
	if (attr)
	  ret = bgp_process_update(peer, &p, attr, info->afi, safi, &rd, &path_id, label);
	else
	  ret = bgp_process_withdraw(peer, &p, attr, info->afi, safi, &rd, &path_id, label);
  }

  return 0;
}

int bgp_process_update(struct bgp_peer *peer, struct prefix *p, void *attr, afi_t afi, safi_t safi,
		       rd_t *rd, path_id_t *path_id, char *label)
{
  struct bgp_node *route = NULL;
  struct bgp_info *ri = NULL, *new = NULL;
  struct bgp_attr *attr_new = NULL;
  u_int32_t modulo = bgp_route_info_modulo(peer, path_id);

  route = bgp_node_get(rib[afi][safi], p);

  /* Check previously received route. */
  for (ri = route->info[modulo]; ri; ri = ri->next) {
    if (ri->peer == peer) { 
      if (safi == SAFI_MPLS_VPN) {
	if (ri->extra && !memcmp(&ri->extra->rd, rd, sizeof(rd_t)));
	else continue;
      }

      if (peer->cap_add_paths) {
	if (path_id && *path_id) {
	  if (ri->extra && *path_id == ri->extra->path_id);
	  else continue;
	}
	else {
	  if (!ri->extra || (ri->extra && !ri->extra->path_id));
	  else continue;
	}
      }

      break;
    }
  }

  attr_new = bgp_attr_intern(attr);

  if (ri) {
	/* Received same information */
	if (attrhash_cmp(ri->attr, attr_new)) {
	  bgp_unlock_node (route);
	  bgp_attr_unintern(attr_new);

	  if (config.nfacctd_bgp_msglog_file || config.nfacctd_bgp_msglog_amqp_routing_key)
	    goto log_update;

	  return 0;
	}
	else {
	  struct bgp_info_extra *rie = NULL;

	  /* Update to new attribute.  */
	  bgp_attr_unintern(ri->attr);
	  ri->attr = attr_new;

	  /* Install/update MPLS stuff if required */
	  if (safi == SAFI_MPLS_VPN) {
	    if (!rie) rie = bgp_info_extra_get(ri);

	    if (rie) {
	      memcpy(&rie->rd, rd, sizeof(rd_t));
	      memcpy(&rie->label, label, 3);
	    }
	  }

          /* Install/update BGP ADD-PATHs stuff if required */
          if (peer->cap_add_paths && path_id && *path_id) {
            if (!rie) rie = bgp_info_extra_get(ri);

            if (rie) memcpy(&rie->path_id, path_id, sizeof(path_id_t));
          }

	  bgp_unlock_node (route);

	  if (config.nfacctd_bgp_msglog_file || config.nfacctd_bgp_msglog_amqp_routing_key)
	    goto log_update;

	  return 0;
	}
  }

  /* Make new BGP info. */
  new = bgp_info_new();
  if (new) {
    struct bgp_info_extra *rie = NULL;

    new->peer = peer;
    new->attr = attr_new;

    if (safi == SAFI_MPLS_VPN) {
      if (!rie) rie = bgp_info_extra_get(new);

      if (rie) {
        memcpy(&rie->rd, rd, sizeof(rd_t));
        memcpy(&rie->label, label, 3);
      }
    }

    if (peer->cap_add_paths && path_id && *path_id) {
      if (!rie) rie = bgp_info_extra_get(new);

      if (rie) memcpy(&rie->path_id, path_id, sizeof(path_id_t));
    }
  }
  else return -1;

  /* Register new BGP information. */
  bgp_info_add(route, new, modulo);

  /* route_node_get lock */
  bgp_unlock_node(route);

  if (config.nfacctd_bgp_msglog_file || config.nfacctd_bgp_msglog_amqp_routing_key) {
    ri = new;
    goto log_update;
  }

  /* XXX: Impose a maximum number of prefixes allowed */
  // if (bgp_maximum_prefix_overflow(peer, afi, safi, 0))
  // return -1;

  return 0;

log_update:
  {
    char event_type[] = "update";

    bgp_peer_log_msg(route, ri, safi, event_type, config.nfacctd_bgp_msglog_output);
  }

  return 0;
}

int bgp_process_withdraw(struct bgp_peer *peer, struct prefix *p, void *attr, afi_t afi, safi_t safi,
			 rd_t *rd, path_id_t *path_id, char *label)
{
  struct bgp_node *route = NULL;
  struct bgp_info *ri = NULL;
  u_int32_t modulo = bgp_route_info_modulo(peer, path_id);

  /* Lookup node. */
  route = bgp_node_get(rib[afi][safi], p);

  /* Check previously received route. */
  for (ri = route->info[modulo]; ri; ri = ri->next) {
    if (ri->peer == peer) {
      if (safi == SAFI_MPLS_VPN) {
        if (ri->extra && !memcmp(&ri->extra->rd, rd, sizeof(rd_t)));
        else continue;
      }

      if (peer->cap_add_paths) {
        if (path_id && *path_id) {
          if (ri->extra && *path_id == ri->extra->path_id);
          else continue;
        }
        else {
          if (!ri->extra || (ri->extra && !ri->extra->path_id));
          else continue;
        }
      }

      break;
    }
  }

  if (ri && config.nfacctd_bgp_msglog_file || config.nfacctd_bgp_msglog_amqp_routing_key) {
    char event_type[] = "withdraw";

    bgp_peer_log_msg(route, ri, safi, event_type, config.nfacctd_bgp_msglog_output);
  }

  /* Withdraw specified route from routing table. */
  if (ri) bgp_info_delete(route, ri, modulo); 

  /* Unlock bgp_node_get() lock. */
  bgp_unlock_node(route);

  return 0;
}

/* BGP Address Famiy Identifier to UNIX Address Family converter. */
int bgp_afi2family (int afi)
{
  if (afi == AFI_IP)
	return AF_INET;
#ifdef ENABLE_IPV6
  else if (afi == AFI_IP6)
	return AF_INET6;
#endif 
  return 0;
}

int bgp_rd2str(char *str, rd_t *rd)
{
  struct rd_ip  *rdi;
  struct rd_as  *rda;
  struct rd_as4 *rda4;
  struct host_addr a;
  u_char ip_address[INET6_ADDRSTRLEN];

  switch (rd->type) {
  case RD_TYPE_AS:
    rda = (struct rd_as *) rd;
    sprintf(str, "%u:%u:%u", rda->type, rda->as, rda->val); 
    break;
  case RD_TYPE_IP:
    rdi = (struct rd_ip *) rd;
    a.family = AF_INET;
    a.address.ipv4.s_addr = rdi->ip.s_addr;
    addr_to_str(ip_address, &a);
    sprintf(str, "%u:%s:%u", rdi->type, ip_address, rdi->val); 
    break;
  case RD_TYPE_AS4:
    rda4 = (struct rd_as4 *) rd;
    sprintf(str, "%u:%u:%u", rda4->type, rda4->as, rda4->val); 
    break;
  case RD_TYPE_VRFID:
    rda = (struct rd_as *) rd; 
    sprintf(str, "vrfid:%u", rda->val);
    break;
  default:
    sprintf(str, "unknown");
    break; 
  }
}

int bgp_str2rd(rd_t *output, char *value)
{
  struct host_addr a;
  char *endptr, *token;
  u_int32_t tmp32;
  u_int16_t tmp16;
  struct rd_ip  *rdi;
  struct rd_as  *rda;
  struct rd_as4 *rda4;
  int idx = 0;
  rd_t rd;

  memset(&a, 0, sizeof(a));
  memset(&rd, 0, sizeof(rd));

  /* type:RD_subfield1:RD_subfield2 */
  while ( (token = extract_token(&value, ':')) && idx < 3) {
    if (idx == 0) {
      tmp32 = strtoul(token, &endptr, 10);
      rd.type = tmp32;
      switch (rd.type) {
      case RD_TYPE_AS:
        rda = (struct rd_as *) &rd;
        break;
      case RD_TYPE_IP:
        rdi = (struct rd_ip *) &rd;
        break;
      case RD_TYPE_AS4:
        rda4 = (struct rd_as4 *) &rd;
        break;
      default:
        printf("ERROR: Invalid RD type specified\n");
        return FALSE;
      }
    }
    if (idx == 1) {
      switch (rd.type) {
      case RD_TYPE_AS:
        tmp32 = strtoul(token, &endptr, 10);
        rda->as = tmp32;
        break;
      case RD_TYPE_IP:
        memset(&a, 0, sizeof(a));
        str_to_addr(token, &a);
        if (a.family == AF_INET) rdi->ip.s_addr = a.address.ipv4.s_addr;
        break;
      case RD_TYPE_AS4:
        tmp32 = strtoul(token, &endptr, 10);
        rda4->as = tmp32;
        break;
      }
    }
    if (idx == 2) {
      switch (rd.type) {
      case RD_TYPE_AS:
        tmp32 = strtoul(token, &endptr, 10);
        rda->val = tmp32;
        break;
      case RD_TYPE_IP:
        tmp32 = strtoul(token, &endptr, 10);
        rdi->val = tmp32;
        break;
      case RD_TYPE_AS4:
        tmp32 = strtoul(token, &endptr, 10);
        rda4->val = tmp32;
        break;
      }
    }

    idx++;
  }

  memcpy(output, &rd, sizeof(rd));

  return TRUE;
}

/* Allocate bgp_info_extra */
struct bgp_info_extra *bgp_info_extra_new(void)
{
  struct bgp_info_extra *new;

  new = malloc(sizeof(struct bgp_info_extra));
  if (!new) {
    Log(LOG_ERR, "ERROR ( %s/core/BGP ): malloc() failed (bgp_info_extra_new). Exiting ..\n", config.name);
    exit_all(1);
  }
  else memset(new, 0, sizeof (struct bgp_info_extra));

  return new;
}

void bgp_info_extra_free(struct bgp_info_extra **extra)
{
  if (extra && *extra) {
    free(*extra);
    *extra = NULL;
  }
}

/* Get bgp_info extra information for the given bgp_info */
struct bgp_info_extra *bgp_info_extra_get(struct bgp_info *ri)
{
  if (!ri->extra)
    ri->extra = bgp_info_extra_new();

  return ri->extra;
}

/* Allocate new bgp info structure. */
struct bgp_info *bgp_info_new()
{
  struct bgp_info *new;

  new = malloc(sizeof(struct bgp_info));
  if (!new) {
    Log(LOG_ERR, "ERROR ( %s/core/BGP ): malloc() failed (bgp_info_new). Exiting ..\n", config.name);
    exit_all(1);
  }
  else memset(new, 0, sizeof (struct bgp_info));
  
  return new;
}

void bgp_info_add(struct bgp_node *rn, struct bgp_info *ri, u_int32_t modulo)
{
  struct bgp_info *top;

  top = rn->info[modulo];

  ri->next = rn->info[modulo];
  ri->prev = NULL;
  if (top)
	top->prev = ri;
  rn->info[modulo] = ri;

  // ri->lock++;
  bgp_lock_node(rn);
  ri->peer->lock++;
}

void bgp_info_delete(struct bgp_node *rn, struct bgp_info *ri, u_int32_t modulo)
{
  if (ri->next)
	ri->next->prev = ri->prev;
  if (ri->prev)
	ri->prev->next = ri->next;
  else
	rn->info[modulo] = ri->next;

  bgp_info_free(ri);

  bgp_unlock_node(rn);
}

/* Free bgp route information. */
void bgp_info_free(struct bgp_info *ri)
{
  if (ri->attr)
	bgp_attr_unintern(ri->attr);

  bgp_info_extra_free(&ri->extra);

  ri->peer->lock--;
  free(ri);
}

/* Initialization of attributes */
void bgp_attr_init()
{
  aspath_init(&ashash);
  attrhash_init(&attrhash);
  community_init(&comhash);
  ecommunity_init(&ecomhash);
}

unsigned int attrhash_key_make(void *p)
{
  struct bgp_attr *attr = (struct bgp_attr *) p;
  unsigned int key = 0;

  key += attr->origin;
  key += attr->nexthop.s_addr;
  key += attr->med;
  key += attr->local_pref;
  if (attr->pathlimit.as)
    {
      key += attr->pathlimit.ttl;
      key += attr->pathlimit.as;
    }

  if (attr->aspath)
    key += aspath_key_make(attr->aspath);
  if (attr->community)
    key += community_hash_make(attr->community);
  if (attr->ecommunity)
    key += ecommunity_hash_make(attr->ecommunity);

  return key;
}

int attrhash_cmp(const void *p1, const void *p2)
{
  const struct bgp_attr *attr1 = (const struct bgp_attr *)p1;
  const struct bgp_attr *attr2 = (const struct bgp_attr *)p2;

  if (attr1->flag == attr2->flag
      && attr1->origin == attr2->origin
      && attr1->nexthop.s_addr == attr2->nexthop.s_addr
      && attr1->aspath == attr2->aspath
      && attr1->community == attr2->community
      && attr1->ecommunity == attr2->ecommunity
      && attr1->med == attr2->med
      && attr1->local_pref == attr2->local_pref
      && attr1->pathlimit.ttl == attr2->pathlimit.ttl
      && attr1->pathlimit.as == attr2->pathlimit.as) {
    if (attr1->mp_nexthop.family == attr2->mp_nexthop.family) {
      if (attr1->mp_nexthop.family == AF_INET
	  && attr1->mp_nexthop.address.ipv4.s_addr == attr2->mp_nexthop.address.ipv4.s_addr) 
        return 1;
#if defined ENABLE_IPV6
      else if (attr1->mp_nexthop.family == AF_INET6
	  && !memcmp(&attr1->mp_nexthop.address.ipv6, &attr2->mp_nexthop.address.ipv6, 16))
        return 1;
#endif
      else return 1;
    }
  }

  return 0;
}

void attrhash_init(struct hash **loc_attrhash)
{
  (*loc_attrhash) = (struct hash *) hash_create(attrhash_key_make, attrhash_cmp);
}

/* Internet argument attribute. */
struct bgp_attr *bgp_attr_intern(struct bgp_attr *attr)
{
  struct bgp_attr *find;
 
  /* Intern referenced strucutre. */
  if (attr->aspath) {
    if (! attr->aspath->refcnt)
      attr->aspath = aspath_intern (attr->aspath);
  else
	  attr->aspath->refcnt++;
  }
  if (attr->community) {
	if (! attr->community->refcnt)
	  attr->community = community_intern (attr->community);
	else
	  attr->community->refcnt++;
  }
  if (attr->ecommunity) {
 	if (!attr->ecommunity->refcnt)
	  attr->ecommunity = ecommunity_intern (attr->ecommunity);
  else
	attr->ecommunity->refcnt++;
  }
 
  find = (struct bgp_attr *) hash_get(attrhash, attr, bgp_attr_hash_alloc);
  find->refcnt++;

  return find;
}

/* Free bgp attribute and aspath. */
void bgp_attr_unintern(struct bgp_attr *attr)
{
  struct bgp_attr *ret;
  struct aspath *aspath;
  struct community *community;
  struct ecommunity *ecommunity = NULL;
 
  /* Decrement attribute reference. */
  attr->refcnt--;
  aspath = attr->aspath;
  community = attr->community;
  ecommunity = attr->ecommunity;

  /* If reference becomes zero then free attribute object. */
  if (attr->refcnt == 0) {
	ret = (struct bgp_attr *) hash_release (attrhash, attr);
	// assert (ret != NULL);
	// if (ret) free(attr);
	if (!ret) Log(LOG_WARNING, "WARN ( %s/core/BGP ): bgp_attr_unintern() hash lookup failed.\n", config.name);
	free(attr);
  }

  /* aspath refcount shoud be decrement. */
  if (aspath)
	aspath_unintern (aspath);
  if (community)
	community_unintern (community);
  if (ecommunity)
	ecommunity_unintern (ecommunity);
}

void *bgp_attr_hash_alloc (void *p)
{
  struct bgp_attr *val = (struct bgp_attr *) p;
  struct bgp_attr *attr;

  attr = malloc(sizeof (struct bgp_attr));
  if (!attr) {
    Log(LOG_ERR, "ERROR ( %s/core/BGP ): malloc() failed (bgp_attr_hash_alloc). Exiting ..\n", config.name);
    exit_all(1);
  }
  else {
    memset(attr, 0, sizeof (struct bgp_attr));
    *attr = *val;
    attr->refcnt = 0;
  }

  return attr;
}

int bgp_peer_init(struct bgp_peer *peer)
{
  int ret = TRUE;
  afi_t afi;
  safi_t safi;

  memset(peer, 0, sizeof(struct bgp_peer));
  peer->status = Idle;
  peer->buf.len = BGP_MAX_PACKET_SIZE;
  peer->buf.base = malloc(peer->buf.len);
  if (!peer->buf.base) {
    Log(LOG_ERR, "ERROR ( %s/core/BGP ): malloc() failed (bgp_peer_init). Exiting ..\n", config.name);
    exit_all(1);
  }
  else {
    memset(peer->buf.base, 0, peer->buf.len);
    ret = FALSE;
  }

  return ret;
}

void bgp_peer_close(struct bgp_peer *peer)
{
  afi_t afi;
  safi_t safi;

  bgp_peer_info_delete(peer);

  if (config.nfacctd_bgp_msglog_file || config.nfacctd_bgp_msglog_amqp_routing_key)
    bgp_peer_log_close(peer, config.nfacctd_bgp_msglog_output); 

  close(peer->fd);
  peer->fd = 0;
  memset(&peer->id, 0, sizeof(peer->id));
  memset(&peer->addr, 0, sizeof(peer->addr));
  memset(&peer->addr_str, 0, sizeof(peer->addr_str));

  free(peer->buf.base);

  if (config.nfacctd_bgp_neighbors_file)
    write_neighbors_file(config.nfacctd_bgp_neighbors_file);
}

void bgp_peer_info_delete(struct bgp_peer *peer)
{
  struct bgp_table *table;
  struct bgp_node *node;
  afi_t afi;
  safi_t safi;

  for (afi = AFI_IP; afi < AFI_MAX; afi++) {
    for (safi = SAFI_UNICAST; safi < SAFI_MAX; safi++) {
      table = rib[afi][safi];
      node = bgp_table_top(table);

      while (node) {
        u_int32_t modulo = bgp_route_info_modulo(peer, NULL);
        u_int32_t peer_buckets;
        struct bgp_info *ri;
        struct bgp_info *ri_next;

        for (peer_buckets = 0; peer_buckets < config.bgp_table_per_peer_buckets; peer_buckets++) {
          for (ri = node->info[modulo+peer_buckets]; ri; ri = ri_next) {
            if (ri->peer == peer) {
	      if (config.nfacctd_bgp_msglog_file || config.nfacctd_bgp_msglog_amqp_routing_key) {
		char event_type[] = "delete";

		bgp_peer_log_msg(node, ri, safi, event_type, config.nfacctd_bgp_msglog_output);
	      }

	      ri_next = ri->next; /* let's save pointer to next before free up */
              bgp_info_delete(node, ri, modulo+peer_buckets);
            }
	    else ri_next = ri->next;
          }
        }

        node = bgp_route_next(node);
      }
    }
  }
}

int bgp_attr_munge_as4path(struct bgp_peer *peer, struct bgp_attr *attr, struct aspath *as4path)
{
  struct aspath *newpath;

  /* If the BGP peer supports 32bit AS_PATH then we are done */ 
  if (peer->cap_4as) return 0;

  /* pre-requisite for AS4_PATH is AS_PATH indeed */ 
  // XXX if (as4path && !attr->aspath) return -1;

  newpath = aspath_reconcile_as4(attr->aspath, as4path);
  aspath_unintern(attr->aspath);
  attr->aspath = aspath_intern(newpath);

  return 0;
}

void load_comm_patterns(char **stdcomm, char **extcomm, char **stdcomm_to_asn)
{
  int idx;
  char *token;

  memset(std_comm_patterns, 0, sizeof(std_comm_patterns));
  memset(ext_comm_patterns, 0, sizeof(ext_comm_patterns));
  memset(std_comm_patterns_to_asn, 0, sizeof(std_comm_patterns_to_asn));

  if (*stdcomm) {
    idx = 0;
    while ( (token = extract_token(stdcomm, ',')) && idx < MAX_BGP_COMM_PATTERNS ) {
      std_comm_patterns[idx] = token;
      trim_spaces(std_comm_patterns[idx]);
      idx++;
    }
  }
 
  if (*extcomm) {
    idx = 0;
    while ( (token = extract_token(extcomm, ',')) && idx < MAX_BGP_COMM_PATTERNS ) {
      ext_comm_patterns[idx] = token;
      trim_spaces(ext_comm_patterns[idx]);
      idx++;
    }
  }

  if (*stdcomm_to_asn) {
    idx = 0;
    while ( (token = extract_token(stdcomm_to_asn, ',')) && idx < MAX_BGP_COMM_PATTERNS ) {
      std_comm_patterns_to_asn[idx] = token;
      trim_spaces(std_comm_patterns_to_asn[idx]);
      idx++;
    }
  }
} 

void evaluate_comm_patterns(char *dst, char *src, char **patterns, int dstlen)
{
  char *ptr, *haystack, *delim_src, *delim_ptn;
  char local_ptr[MAX_BGP_STD_COMMS], *auxptr;
  int idx, i, j, srclen;

  srclen = strlen(src);

  for (idx = 0, j = 0; patterns[idx]; idx++) {
    haystack = src;

    find_again:
    delim_ptn = strchr(patterns[idx], '.');
    if (delim_ptn) *delim_ptn = '\0';
    ptr = strstr(haystack, patterns[idx]);

    if (ptr && delim_ptn) {
      delim_src = strchr(ptr, ' ');
      if (delim_src) {
	memcpy(local_ptr, ptr, delim_src-ptr);
        local_ptr[delim_src-ptr] = '\0';
      }
      else memcpy(local_ptr, ptr, strlen(ptr)+1);
      *delim_ptn = '.';

      if (strlen(local_ptr) != strlen(patterns[idx])) ptr = NULL;
      else {
	for (auxptr = strchr(patterns[idx], '.'); auxptr; auxptr = strchr(auxptr, '.')) {
	  local_ptr[auxptr-patterns[idx]] = '.';
	  auxptr++;
	} 
	if (strncmp(patterns[idx], local_ptr, strlen(patterns[idx]))) ptr = NULL;
      }
    } 
    else if (delim_ptn) *delim_ptn = '.';

    if (ptr) {
      /* If we have already something on the stack, let's insert a space */
      if (j && j < dstlen) {
	dst[j] = ' ';
	j++;
      }

      /* We should be able to trust this string */
      for (i = 0; ptr[i] != ' ' && ptr[i] != '\0'; i++, j++) {
	if (j < dstlen) dst[j] = ptr[i];
	else break;
      } 

      haystack = &ptr[i];
    }

    /* If we don't have space anymore, let's finish it here */
    if (j >= dstlen) {
      dst[dstlen-1] = '+';
      break;
    }

    /* Trick to find multiple occurrences */ 
    if (ptr) goto find_again;
  }
}

as_t evaluate_last_asn(struct aspath *as)
{
  if (!as) return 0;

  return as->last_as;
}

as_t evaluate_first_asn(char *src)
{
  int idx, is_space = FALSE, len = strlen(src), start, sub_as, iteration;
  char *endptr, *ptr, saved;
  as_t asn, real_first_asn;

  start = 0;
  iteration = 0;
  real_first_asn = 0;

  start_again:

  asn = 0;
  sub_as = FALSE;

  for (idx = start; idx < len && (src[idx] != ' ' && src[idx] != ')'); idx++);

  /* Mangling the AS_PATH string */
  if (src[idx] == ' ' || src[idx] == ')') {
    is_space = TRUE;  
    saved =  src[idx];
    src[idx] = '\0';
  }

  if (src[start] == '(') {
    ptr = &src[start+1];
    sub_as = TRUE;
  }
  else ptr = &src[start];

  asn = strtoul(ptr, &endptr, 10);

  /* Restoring mangled AS_PATH */
  if (is_space) {
    src[idx] = saved; 
    saved = '\0';
    is_space = FALSE;
  }

  if (config.nfacctd_bgp_peer_as_skip_subas && sub_as) {
    while (idx < len && (src[idx] == ' ' || src[idx] == ')')) idx++;

    if (idx != len-1) { 
      start = idx;
      if (iteration == 0) real_first_asn = asn;
      iteration++;
      goto start_again;
    }
  }

  /* skip sub-as kicks-in only when traffic is delivered to a different ASN */
  if (real_first_asn && (!asn || sub_as)) asn = real_first_asn;

  return asn;
}

void bgp_srcdst_lookup(struct packet_ptrs *pptrs)
{
  struct sockaddr *sa = (struct sockaddr *) pptrs->f_agent, sa_local;
  struct xflow_status_entry *xs_entry = (struct xflow_status_entry *) pptrs->f_status;
  struct bgp_peer *peer;
  struct bgp_node *default_node, *result;
  struct bgp_info *info;
  struct prefix default_prefix;
  int peers_idx, compare_bgp_port;
  int follow_default = config.nfacctd_bgp_follow_default;
  struct in_addr pref4;
#if defined ENABLE_IPV6
  struct in6_addr pref6;
#endif
  u_int32_t modulo, local_modulo, modulo_idx, modulo_max;
  u_int32_t peer_idx, *peer_idx_ptr;
  safi_t safi;
  rd_t rd;

  pptrs->bgp_src = NULL;
  pptrs->bgp_dst = NULL;
  pptrs->bgp_src_info = NULL;
  pptrs->bgp_dst_info = NULL;
  pptrs->bgp_peer = NULL;
  pptrs->bgp_nexthop_info = NULL;
  compare_bgp_port = FALSE;
  safi = SAFI_UNICAST;

  memset(&rd, 0, sizeof(rd));

  if (pptrs->bta) {
    sa = &sa_local;
    if (pptrs->bta_af == ETHERTYPE_IP) {
      sa->sa_family = AF_INET;
      ((struct sockaddr_in *)sa)->sin_addr.s_addr = pptrs->bta; 
      if (pptrs->lookup_bgp_port.set) {
	((struct sockaddr_in *)sa)->sin_port = pptrs->lookup_bgp_port.n; 
	compare_bgp_port = TRUE;
      }
    }
#if defined ENABLE_IPV6
    else if (pptrs->bta_af == ETHERTYPE_IPV6) {
      sa->sa_family = AF_INET6;
      ip6_addr_32bit_cpy(&((struct sockaddr_in6 *)sa)->sin6_addr, &pptrs->bta, 0, 0, 1);
      ip6_addr_32bit_cpy(&((struct sockaddr_in6 *)sa)->sin6_addr, &pptrs->bta2, 2, 0, 1);
      if (pptrs->lookup_bgp_port.set) {
        ((struct sockaddr_in6 *)sa)->sin6_port = pptrs->lookup_bgp_port.n; 
	compare_bgp_port = TRUE;
      }
    }
#endif
  }

  start_again:

  peer_idx = 0; peer_idx_ptr = NULL;
  if (xs_entry) {
    if (pptrs->l3_proto == ETHERTYPE_IP) {
      peer_idx = xs_entry->peer_v4_idx; 
      peer_idx_ptr = &xs_entry->peer_v4_idx;
    }
#if defined ENABLE_IPV6
    else if (pptrs->l3_proto == ETHERTYPE_IPV6) {
      peer_idx = xs_entry->peer_v6_idx; 
      peer_idx_ptr = &xs_entry->peer_v6_idx;
    }
#endif
  }

  if (xs_entry && peer_idx) {
    if ((!sa_addr_cmp(sa, &peers[peer_idx].addr) || !sa_addr_cmp(sa, &peers[peer_idx].id)) &&
        (!compare_bgp_port || !sa_port_cmp(sa, peers[peer_idx].tcp_port))) {
      peer = &peers[peer_idx];
      pptrs->bgp_peer = (char *) &peers[peer_idx];
    }
    /* If no match then let's invalidate the entry */
    else {
      *peer_idx_ptr = 0;
      peer = NULL;
    }
  }
  else {
    for (peer = NULL, peers_idx = 0; peers_idx < config.nfacctd_bgp_max_peers; peers_idx++) {
      if ((!sa_addr_cmp(sa, &peers[peers_idx].addr) || !sa_addr_cmp(sa, &peers[peers_idx].id)) && 
	  (!compare_bgp_port || !sa_port_cmp(sa, peers[peer_idx].tcp_port))) {
        peer = &peers[peers_idx];
        pptrs->bgp_peer = (char *) &peers[peers_idx];
        if (xs_entry && peer_idx_ptr) *peer_idx_ptr = peers_idx;
        break;
      }
    }
  }

  if (peer) {
    struct host_addr peer_dst_ip;

    modulo = bgp_route_info_modulo(peer, NULL);

    // XXX: to be optimized 
    if (config.bgp_table_per_peer_hash == BGP_ASPATH_HASH_PATHID) modulo_max = config.bgp_table_per_peer_buckets; 
    else modulo_max = 1;

    if (peer->cap_add_paths && (config.acct_type == ACCT_NF || config.acct_type == ACCT_SF)) {
      /* administrativia */
      struct pkt_bgp_primitives pbgp, *pbgp_ptr = &pbgp;
      memset(&pbgp, 0, sizeof(struct pkt_bgp_primitives));
      
      /* note: call to [NF|SF]_peer_dst_ip_handler for the purpose of
	 code re-use effectively is defeating the concept of libbgp */
      if (config.acct_type == ACCT_NF) NF_peer_dst_ip_handler(NULL, pptrs, &pbgp_ptr);
      else if (config.acct_type == ACCT_SF) SF_peer_dst_ip_handler(NULL, pptrs, &pbgp_ptr);

      memcpy(&peer_dst_ip, &pbgp.peer_dst_ip, sizeof(struct host_addr));
    }

    if (pptrs->bitr) {
      safi = SAFI_MPLS_VPN;
      memcpy(&rd, &pptrs->bitr, sizeof(rd));
    }

    if (pptrs->l3_proto == ETHERTYPE_IP) {
      if (!pptrs->bgp_src) {
        memcpy(&pref4, &((struct my_iphdr *)pptrs->iph_ptr)->ip_src, sizeof(struct in_addr));
	pptrs->bgp_src = (char *) bgp_node_match_ipv4(rib[AFI_IP][safi], &pref4, (struct bgp_peer *) pptrs->bgp_peer);
      }
      if (!pptrs->bgp_src_info && pptrs->bgp_src) {
	result = (struct bgp_node *) pptrs->bgp_src;	
        if (result->p.prefixlen >= pptrs->lm_mask_src) {
          pptrs->lm_mask_src = result->p.prefixlen;
          pptrs->lm_method_src = NF_NET_BGP;
        }

	for (info = result->info[modulo]; info; info = info->next) {
	  if (safi != SAFI_MPLS_VPN) {
	    if (info->peer == peer) {
	      pptrs->bgp_src_info = (char *) info;
	      break;
	    }
	  }
	  else {
	    if (info->peer == peer && info->extra && !memcmp(&info->extra->rd, &rd, sizeof(rd_t))) {
	      pptrs->bgp_src_info = (char *) info;
	      break;
	    }
	  }
	}
      }
      if (!pptrs->bgp_dst) {
	memcpy(&pref4, &((struct my_iphdr *)pptrs->iph_ptr)->ip_dst, sizeof(struct in_addr));
	pptrs->bgp_dst = (char *) bgp_node_match_ipv4(rib[AFI_IP][safi], &pref4, (struct bgp_peer *) pptrs->bgp_peer);
      }
      if (!pptrs->bgp_dst_info && pptrs->bgp_dst) {
	result = (struct bgp_node *) pptrs->bgp_dst;
        if (result->p.prefixlen >= pptrs->lm_mask_dst) {
          pptrs->lm_mask_dst = result->p.prefixlen;
          pptrs->lm_method_dst = NF_NET_BGP;
        }

        for (local_modulo = modulo, modulo_idx = 0; modulo_idx < modulo_max; local_modulo++, modulo_idx++) {
          for (info = result->info[local_modulo]; info; info = info->next) {
	    if (info->peer == peer) {
	      int no_match = FALSE;

	      /* flagging additional checks are required */
	      if (safi == SAFI_MPLS_VPN) no_match++;
	      if (peer->cap_add_paths) no_match++;
 
	      if (safi == SAFI_MPLS_VPN) {
	        if (info->extra && !memcmp(&info->extra->rd, &rd, sizeof(rd_t))) no_match--;
	      }

	      if (peer->cap_add_paths) {
	        if (info->attr) {
		  if (info->attr->mp_nexthop.family == peer_dst_ip.family) {
		    if (!memcmp(&info->attr->mp_nexthop, &peer_dst_ip, HostAddrSz)) no_match--;
		  }
		  else if (info->attr->nexthop.s_addr && peer_dst_ip.family == AF_INET) {
		    if (info->attr->nexthop.s_addr == peer_dst_ip.address.ipv4.s_addr) no_match--;
		  }
	        }
	      }

	      if (!no_match) {
	        pptrs->bgp_dst_info = (char *) info;
	        break;
	      }
	    }
	  }

	  /* if having results, let's not potentially look in other buckets */
	  if (pptrs->bgp_dst_info) break;
        }
      }
    }
#if defined ENABLE_IPV6
    else if (pptrs->l3_proto == ETHERTYPE_IPV6) {
      if (!pptrs->bgp_src) {
        memcpy(&pref6, &((struct ip6_hdr *)pptrs->iph_ptr)->ip6_src, sizeof(struct in6_addr));
	pptrs->bgp_src = (char *) bgp_node_match_ipv6(rib[AFI_IP6][safi], &pref6, (struct bgp_peer *) pptrs->bgp_peer);
      }
      if (!pptrs->bgp_src_info && pptrs->bgp_src) {
	result = (struct bgp_node *) pptrs->bgp_src;
        if (result->p.prefixlen >= pptrs->lm_mask_src) {
          pptrs->lm_mask_src = result->p.prefixlen;
          pptrs->lm_method_src = NF_NET_BGP;
        }

        for (info = result->info[modulo]; info; info = info->next) {
          if (safi != SAFI_MPLS_VPN) {
            if (info->peer == peer) {
              pptrs->bgp_src_info = (char *) info;
              break;
            }
          }
          else {
            if (info->peer == peer && info->extra && !memcmp(&info->extra->rd, &rd, sizeof(rd_t))) {
              pptrs->bgp_src_info = (char *) info;
              break;
            }
          }
        }
      }
      if (!pptrs->bgp_dst) {
        memcpy(&pref6, &((struct ip6_hdr *)pptrs->iph_ptr)->ip6_dst, sizeof(struct in6_addr));
	pptrs->bgp_dst = (char *) bgp_node_match_ipv6(rib[AFI_IP6][safi], &pref6, (struct bgp_peer *) pptrs->bgp_peer);
      }
      if (!pptrs->bgp_dst_info && pptrs->bgp_dst) {
	result = (struct bgp_node *) pptrs->bgp_dst; 
        if (result->p.prefixlen >= pptrs->lm_mask_dst) {
          pptrs->lm_mask_dst = result->p.prefixlen;
          pptrs->lm_method_dst = NF_NET_BGP;
        }

        for (local_modulo = modulo, modulo_idx = 0; modulo_idx < modulo_max; local_modulo++, modulo_idx++) {
          for (info = result->info[local_modulo]; info; info = info->next) {
            if (info->peer == peer) {
              int no_match = FALSE;

              /* flagging additional checks are required */
              if (safi == SAFI_MPLS_VPN) no_match++;
              if (peer->cap_add_paths) no_match++;

              if (safi == SAFI_MPLS_VPN) {
                if (info->extra && !memcmp(&info->extra->rd, &rd, sizeof(rd_t))) no_match--;
              } 

              if (peer->cap_add_paths) {
                if (info->attr) {
                  if (info->attr->mp_nexthop.family == peer_dst_ip.family) {
                    if (!memcmp(&info->attr->mp_nexthop, &peer_dst_ip, HostAddrSz)) no_match--;
                  }
                }
              }

              if (!no_match) {
	        pptrs->bgp_dst_info = (char *) info;
	        break;
	      }
	    }
          }

          /* if having results, let's not potentially look in other buckets */
          if (pptrs->bgp_dst_info) break;
        }
      }
    }
#endif

    if (follow_default && safi != SAFI_MPLS_VPN) {
      default_node = NULL;

      if (pptrs->l3_proto == ETHERTYPE_IP) {
        memset(&default_prefix, 0, sizeof(default_prefix));
        default_prefix.family = AF_INET;

        result = (struct bgp_node *) pptrs->bgp_src;
        if (result && prefix_match(&result->p, &default_prefix)) {
	  default_node = result;
	  pptrs->bgp_src = NULL;
	  pptrs->bgp_src_info = NULL;
        }

        result = (struct bgp_node *) pptrs->bgp_dst;
        if (result && prefix_match(&result->p, &default_prefix)) {
	  default_node = result;
	  pptrs->bgp_dst = NULL;
	  pptrs->bgp_dst_info = NULL;
        }
      }
#if defined ENABLE_IPV6
      else if (pptrs->l3_proto == ETHERTYPE_IPV6) {
        memset(&default_prefix, 0, sizeof(default_prefix));
        default_prefix.family = AF_INET6;

        result = (struct bgp_node *) pptrs->bgp_src;
        if (result && prefix_match(&result->p, &default_prefix)) {
          default_node = result;
          info = result->info[modulo];
          pptrs->bgp_src = NULL;
          pptrs->bgp_src_info = NULL;
        }

        result = (struct bgp_node *) pptrs->bgp_dst;
        if (result && prefix_match(&result->p, &default_prefix)) {
          default_node = result;
          info = result->info[local_modulo];
          pptrs->bgp_dst = NULL;
          pptrs->bgp_dst_info = NULL;
        }
      }
#endif
      
      if (!pptrs->bgp_src || !pptrs->bgp_dst) {
	follow_default--;
	compare_bgp_port = FALSE; // XXX: fixme: follow default in NAT traversal scenarios

        if (default_node) {
          if (info && info->attr) {
            if (info->attr->mp_nexthop.family == AF_INET) {
              sa = &sa_local;
              memset(sa, 0, sizeof(struct sockaddr));
              sa->sa_family = AF_INET;
              memcpy(&((struct sockaddr_in *)sa)->sin_addr, &info->attr->mp_nexthop.address.ipv4, 4);
	      goto start_again;
            }
#if defined ENABLE_IPV6
            else if (info->attr->mp_nexthop.family == AF_INET6) {
              sa = &sa_local;
              memset(sa, 0, sizeof(struct sockaddr));
              sa->sa_family = AF_INET6;
              ip6_addr_cpy(&((struct sockaddr_in6 *)sa)->sin6_addr, &info->attr->mp_nexthop.address.ipv6);
              goto start_again;
            }
#endif
            else {
              sa = &sa_local;
              memset(sa, 0, sizeof(struct sockaddr));
              sa->sa_family = AF_INET;
              memcpy(&((struct sockaddr_in *)sa)->sin_addr, &info->attr->nexthop, 4);
              goto start_again;
	    }
	  }
        }
      }
    }

    if (config.nfacctd_bgp_follow_nexthop[0].family && pptrs->bgp_dst && safi != SAFI_MPLS_VPN)
      bgp_follow_nexthop_lookup(pptrs);
  }
}

void bgp_follow_nexthop_lookup(struct packet_ptrs *pptrs)
{
  struct sockaddr *sa = (struct sockaddr *) pptrs->f_agent, sa_local;
  struct bgp_peer *nh_peer;
  struct bgp_node *result_node = NULL;
  struct bgp_info *info;
  char *result = NULL, *saved_info = NULL;
  int peers_idx, ttl = MAX_HOPS_FOLLOW_NH, self = MAX_NH_SELF_REFERENCES;
  int nh_idx, matched = 0;
  struct prefix nh, ch;
  struct in_addr pref4;
#if defined ENABLE_IPV6
  struct in6_addr pref6;
#endif
  char *saved_agent = pptrs->f_agent;
  pm_id_t bta;
  u_int32_t modulo, local_modulo, modulo_idx, modulo_max;

  start_again:

  if (config.nfacctd_bgp_to_agent_map && (*find_id_func)) {
    bta = 0;
    (*find_id_func)((struct id_table *)pptrs->bta_table, pptrs, &bta, NULL);
    if (bta) {
      sa = &sa_local;
      sa->sa_family = AF_INET;
      ((struct sockaddr_in *)sa)->sin_addr.s_addr = bta;
    }
  }

  for (nh_peer = NULL, peers_idx = 0; peers_idx < config.nfacctd_bgp_max_peers; peers_idx++) {
    if (!sa_addr_cmp(sa, &peers[peers_idx].addr) || !sa_addr_cmp(sa, &peers[peers_idx].id)) {
      nh_peer = &peers[peers_idx];
      break;
    }
  }

  if (nh_peer) {
    modulo = bgp_route_info_modulo(nh_peer, NULL);

    // XXX: to be optimized 
    if (config.bgp_table_per_peer_hash == BGP_ASPATH_HASH_PATHID) modulo_max = config.bgp_table_per_peer_buckets;
    else modulo_max = 1;

    memset(&ch, 0, sizeof(ch));
    ch.family = AF_INET;
    ch.prefixlen = 32;
    memcpy(&ch.u.prefix4, &nh_peer->addr.address.ipv4, 4);

    if (!result) {
      if (pptrs->l3_proto == ETHERTYPE_IP) {
        memcpy(&pref4, &((struct my_iphdr *)pptrs->iph_ptr)->ip_dst, sizeof(struct in_addr));
        result = (char *) bgp_node_match_ipv4(rib[AFI_IP][SAFI_UNICAST], &pref4, nh_peer);
      }
#if defined ENABLE_IPV6
      else if (pptrs->l3_proto == ETHERTYPE_IPV6) {
        memcpy(&pref6, &((struct ip6_hdr *)pptrs->iph_ptr)->ip6_dst, sizeof(struct in6_addr));
        result = (char *) bgp_node_match_ipv6(rib[AFI_IP6][SAFI_UNICAST], &pref6, nh_peer);
      }
#endif
    }

    memset(&nh, 0, sizeof(nh));
    result_node = (struct bgp_node *) result;

    if (result_node) {
      for (local_modulo = modulo, modulo_idx = 0; modulo_idx < modulo_max; local_modulo++, modulo_idx++) {
        for (info = result_node->info[modulo]; info; info = info->next) {
          if (info->peer == nh_peer) break;
	}
      }
    }
    else info = NULL;

    if (info && info->attr) {
      if (info->attr->mp_nexthop.family == AF_INET) {
	nh.family = AF_INET;
	nh.prefixlen = 32;
	memcpy(&nh.u.prefix4, &info->attr->mp_nexthop.address.ipv4, 4);

	for (nh_idx = 0; config.nfacctd_bgp_follow_nexthop[nh_idx].family && nh_idx < FOLLOW_BGP_NH_ENTRIES; nh_idx++) {
	  matched = prefix_match(&config.nfacctd_bgp_follow_nexthop[nh_idx], &nh);
	  if (matched) break;
	}

	if (matched && self > 0 && ttl > 0) { 
	  if (prefix_match(&ch, &nh)) self--;
          sa = &sa_local;
          pptrs->f_agent = (char *) &sa_local;
          memset(sa, 0, sizeof(struct sockaddr));
          sa->sa_family = AF_INET;
          memcpy(&((struct sockaddr_in *)sa)->sin_addr, &info->attr->mp_nexthop.address.ipv4, 4);
	  saved_info = (char *) info;
	  ttl--;
          goto start_again;
        }
	else goto end;
      }
#if defined ENABLE_IPV6
      else if (info->attr->mp_nexthop.family == AF_INET6) {
	nh.family = AF_INET6;
	nh.prefixlen = 128;
	memcpy(&nh.u.prefix6, &info->attr->mp_nexthop.address.ipv6, 16);

        for (nh_idx = 0; config.nfacctd_bgp_follow_nexthop[nh_idx].family && nh_idx < FOLLOW_BGP_NH_ENTRIES; nh_idx++) {
          matched = prefix_match(&config.nfacctd_bgp_follow_nexthop[nh_idx], &nh);
          if (matched) break;
        }

	if (matched && self > 0 && ttl > 0) {
	  if (prefix_match(&ch, &nh)) self--;
          sa = &sa_local;
          pptrs->f_agent = (char *) &sa_local;
          memset(sa, 0, sizeof(struct sockaddr));
          sa->sa_family = AF_INET6;
          ip6_addr_cpy(&((struct sockaddr_in6 *)sa)->sin6_addr, &info->attr->mp_nexthop.address.ipv6);
	  saved_info = (char *) info;
	  ttl--;
          goto start_again;
	}
	else goto end;
      }
#endif
      else {
	nh.family = AF_INET;
	nh.prefixlen = 32;
	memcpy(&nh.u.prefix4, &info->attr->nexthop, 4);

        for (nh_idx = 0; config.nfacctd_bgp_follow_nexthop[nh_idx].family && nh_idx < FOLLOW_BGP_NH_ENTRIES; nh_idx++) {
          matched = prefix_match(&config.nfacctd_bgp_follow_nexthop[nh_idx], &nh);
          if (matched) break;
        }

	if (matched && self > 0 && ttl > 0) {
	  if (prefix_match(&ch, &nh)) self--;
          sa = &sa_local;
          pptrs->f_agent = (char *) &sa_local;
          memset(sa, 0, sizeof(struct sockaddr));
          sa->sa_family = AF_INET;
          memcpy(&((struct sockaddr_in *)sa)->sin_addr, &info->attr->nexthop, 4);
	  saved_info = (char *) info;
	  ttl--;
          goto start_again;
	}
	else goto end;
      }
    }
  }

  end:

  if (saved_info) pptrs->bgp_nexthop_info = saved_info; 
  pptrs->f_agent = saved_agent;
}

void write_neighbors_file(char *filename)
{
  FILE *file;
  char neighbor[INET6_ADDRSTRLEN+1];
  int idx, len, ret;
  uid_t owner = -1;
  gid_t group = -1;

  unlink(filename);

  if (config.files_uid) owner = config.files_uid; 
  if (config.files_gid) group = config.files_gid; 

  file = fopen(filename,"w");
  if (file) {
    if ((ret = chown(filename, owner, group)) == -1)
      Log(LOG_WARNING, "WARN: Unable to chown() '%s': %s\n", filename, strerror(errno));

    if (file_lock(fileno(file))) {
      Log(LOG_ALERT, "ALERT: Unable to obtain lock for bgp_neighbors_file '%s'.\n", filename);
      return;
    }
    for (idx = 0; idx < config.nfacctd_bgp_max_peers; idx++) {
      if (peers[idx].fd) {
        if (peers[idx].addr.family == AF_INET) {
          inet_ntop(AF_INET, &peers[idx].addr.address.ipv4, neighbor, INET6_ADDRSTRLEN);
	  len = strlen(neighbor);
	  neighbor[len] = '\n'; len++;
	  neighbor[len] = '\0';
          fwrite(neighbor, len, 1, file);
        }
#if defined ENABLE_IPV6
	else if (peers[idx].addr.family == AF_INET6) {
          inet_ntop(AF_INET6, &peers[idx].addr.address.ipv6, neighbor, INET6_ADDRSTRLEN);
          len = strlen(neighbor);
          neighbor[len] = '\n'; len++;
          neighbor[len] = '\0';
          fwrite(neighbor, len, 1, file);
        }
#endif
      }
    }

    file_unlock(fileno(file));
    fclose(file);
  }
  else {
    Log(LOG_ERR, "ERROR: Unable to open bgp_neighbors_file '%s'\n", filename);
    return;
  }
}

void pkt_to_cache_bgp_primitives(struct cache_bgp_primitives *c, struct pkt_bgp_primitives *p, pm_cfgreg_t what_to_count)
{
  if (c && p) {
    c->peer_src_as = p->peer_src_as;
    c->peer_dst_as = p->peer_dst_as;
    memcpy(&c->peer_src_ip, &p->peer_src_ip, HostAddrSz);
    memcpy(&c->peer_dst_ip, &p->peer_dst_ip, HostAddrSz);
    if (what_to_count & COUNT_STD_COMM) {
      if (!c->std_comms) {
	c->std_comms = malloc(MAX_BGP_STD_COMMS);
	if (!c->std_comms) goto malloc_failed;
      }
      memcpy(c->std_comms, p->std_comms, MAX_BGP_STD_COMMS);
    }
    else {
      if (c->std_comms) {
	free(c->std_comms);
	c->std_comms = NULL;
      }
    }
    if (what_to_count & COUNT_EXT_COMM) {
      if (!c->ext_comms) {
	c->ext_comms = malloc(MAX_BGP_EXT_COMMS);
	if (!c->ext_comms) goto malloc_failed;
      }
      memcpy(c->ext_comms, p->ext_comms, MAX_BGP_EXT_COMMS);
    }
    else {
      if (c->ext_comms) {
	free(c->ext_comms);
	c->ext_comms = NULL;
      }
    }
    if (what_to_count & COUNT_AS_PATH) {
      if (!c->as_path) {
	c->as_path = malloc(MAX_BGP_ASPATH);
	if (!c->as_path) goto malloc_failed;
      }
      memcpy(c->as_path, p->as_path, MAX_BGP_ASPATH);
    }
    else {
      if (c->as_path) {
	free(c->as_path);
	c->as_path = NULL;
      }
    }
    c->local_pref = p->local_pref;
    c->med = p->med;
    if (what_to_count & COUNT_SRC_STD_COMM) {
      if (!c->src_std_comms) {
	c->src_std_comms = malloc(MAX_BGP_STD_COMMS);
	if (!c->src_std_comms) goto malloc_failed;
      }
      memcpy(c->src_std_comms, p->src_std_comms, MAX_BGP_STD_COMMS);
    }
    else {
      if (c->src_std_comms) {
	free(c->src_std_comms);
	c->src_std_comms = NULL;
      }
    }
    if (what_to_count & COUNT_SRC_EXT_COMM) {
      if (!c->src_ext_comms) {
	c->src_ext_comms = malloc(MAX_BGP_EXT_COMMS);
	if (!c->src_ext_comms) goto malloc_failed;
      }
      memcpy(c->src_ext_comms, p->src_ext_comms, MAX_BGP_EXT_COMMS);
    }
    else {
      if (c->src_ext_comms) {
	free(c->src_ext_comms);
	c->src_ext_comms = NULL;
      }
    }
    if (what_to_count & COUNT_SRC_AS_PATH) {
      if (!c->src_as_path) {
	c->src_as_path = malloc(MAX_BGP_ASPATH);
	if (!c->src_as_path) goto malloc_failed;
      }
      memcpy(c->src_as_path, p->src_as_path, MAX_BGP_ASPATH);
    }
    else {
      if (c->src_as_path) {
	free(c->src_as_path);
	c->src_as_path = NULL;
      }
    }
    c->src_local_pref = p->src_local_pref;
    c->src_med = p->src_med;
    memcpy(&c->mpls_vpn_rd, &p->mpls_vpn_rd, sizeof(rd_t));

    return;

    malloc_failed:
    Log(LOG_WARNING, "WARN ( %s/core/BGP ): malloc() failed (pkt_to_cache_bgp_primitives).\n", config.name);
  }
}

void cache_to_pkt_bgp_primitives(struct pkt_bgp_primitives *p, struct cache_bgp_primitives *c)
{
  if (c && p) {
    memset(p, 0, PbgpSz);

    p->peer_src_as = c->peer_src_as;
    p->peer_dst_as = c->peer_dst_as;
    memcpy(&p->peer_src_ip, &c->peer_src_ip, HostAddrSz);
    memcpy(&p->peer_dst_ip, &c->peer_dst_ip, HostAddrSz);
    if (c->std_comms) memcpy(p->std_comms, c->std_comms, MAX_BGP_STD_COMMS);
    if (c->ext_comms) memcpy(p->ext_comms, c->ext_comms, MAX_BGP_EXT_COMMS);
    if (c->as_path) memcpy(p->as_path, c->as_path, MAX_BGP_ASPATH);
    p->local_pref = c->local_pref;
    p->med = c->med;
    if (c->src_std_comms) memcpy(p->src_std_comms, c->src_std_comms, MAX_BGP_STD_COMMS);
    if (c->src_ext_comms) memcpy(p->src_ext_comms, c->src_ext_comms, MAX_BGP_EXT_COMMS);
    if (c->src_as_path) memcpy(p->src_as_path, c->src_as_path, MAX_BGP_ASPATH);
    p->src_local_pref = c->src_local_pref;
    p->src_med = c->src_med;
    memcpy(&p->mpls_vpn_rd, &c->mpls_vpn_rd, sizeof(rd_t));
  }
}

void free_cache_bgp_primitives(struct cache_bgp_primitives **c)
{
  struct cache_bgp_primitives *cbgp = *c;

  if (c && *c) {
    if (cbgp->std_comms) free(cbgp->std_comms);
    if (cbgp->ext_comms) free(cbgp->ext_comms);
    if (cbgp->as_path) free(cbgp->as_path);
    if (cbgp->src_std_comms) free(cbgp->src_std_comms);
    if (cbgp->src_ext_comms) free(cbgp->src_ext_comms);
    if (cbgp->src_as_path) free(cbgp->src_as_path);

    memset(cbgp, 0, sizeof(struct cache_bgp_primitives));
    free(*c);
    *c = NULL;
  }
}

void bgp_config_checks(struct configuration *c)
{
  if (c->what_to_count & (COUNT_STD_COMM|COUNT_EXT_COMM|COUNT_LOCAL_PREF|COUNT_MED|COUNT_AS_PATH|
			  COUNT_PEER_SRC_AS|COUNT_PEER_DST_AS|COUNT_PEER_SRC_IP|COUNT_PEER_DST_IP|
			  COUNT_SRC_STD_COMM|COUNT_SRC_EXT_COMM|COUNT_SRC_AS_PATH|COUNT_SRC_MED|
			  COUNT_SRC_LOCAL_PREF|COUNT_MPLS_VPN_RD)) {
    /* Sanitizing the aggregation method */
    if ( ((c->what_to_count & COUNT_STD_COMM) && (c->what_to_count & COUNT_EXT_COMM)) ||
         ((c->what_to_count & COUNT_SRC_STD_COMM) && (c->what_to_count & COUNT_SRC_EXT_COMM)) ) {
      printf("ERROR: The use of STANDARD and EXTENDED BGP communitities is mutual exclusive.\n");
      exit(1);
    }
    if ( (c->what_to_count & COUNT_SRC_STD_COMM && !c->nfacctd_bgp_src_std_comm_type) ||
	 (c->what_to_count & COUNT_SRC_EXT_COMM && !c->nfacctd_bgp_src_ext_comm_type) ||
	 (c->what_to_count & COUNT_SRC_AS_PATH && !c->nfacctd_bgp_src_as_path_type ) ||
	 (c->what_to_count & COUNT_SRC_LOCAL_PREF && !c->nfacctd_bgp_src_local_pref_type ) ||
	 (c->what_to_count & COUNT_SRC_MED && !c->nfacctd_bgp_src_med_type ) ||
	 (c->what_to_count & COUNT_PEER_SRC_AS && !c->nfacctd_bgp_peer_as_src_type &&
	  (config.acct_type != ACCT_SF && config.acct_type != ACCT_NF)) ) {
      printf("ERROR: At least one of the following primitives is in use but its source type is not specified:\n");
      printf("       peer_src_as     =>  bgp_peer_src_as_type\n");
      printf("       src_as_path     =>  bgp_src_as_path_type\n");
      printf("       src_std_comm    =>  bgp_src_std_comm_type\n");
      printf("       src_ext_comm    =>  bgp_src_ext_comm_type\n");
      printf("       src_local_pref  =>  bgp_src_local_pref_type\n");
      printf("       src_med         =>  bgp_src_med_type\n");
      exit(1);
    }
    c->data_type |= PIPE_TYPE_BGP;
  }
}

void process_bgp_md5_file(int sock, struct bgp_md5_table *bgp_md5)
{
  struct my_tcp_md5sig md5sig;
  struct sockaddr_storage ss_md5sig;
  int rc, keylen, idx = 0, ss_md5sig_len;

  while (idx < bgp_md5->num) {
    memset(&md5sig, 0, sizeof(md5sig));
    memset(&ss_md5sig, 0, sizeof(ss_md5sig));

    ss_md5sig_len = addr_to_sa((struct sockaddr *)&ss_md5sig, &bgp_md5->table[idx].addr, 0);
    memcpy(&md5sig.tcpm_addr, &ss_md5sig, ss_md5sig_len);

    keylen = strlen(bgp_md5->table[idx].key);
    if (keylen) {
      md5sig.tcpm_keylen = keylen;
      memcpy(md5sig.tcpm_key, &bgp_md5->table[idx].key, keylen);
    }

    rc = setsockopt(sock, IPPROTO_TCP, TCP_MD5SIG, &md5sig, sizeof(md5sig));
    if (rc < 0) Log(LOG_ERR, "WARN ( %s/core/BGP ): setsockopt() failed for TCP_MD5SIG (errno: %d).\n", config.name, errno);

    idx++;
  }
}

u_int32_t bgp_route_info_modulo_pathid(struct bgp_peer *peer, path_id_t *path_id)
{
  path_id_t local_path_id = 1;

  if (path_id && *path_id) local_path_id = *path_id;

  return (((peer->fd * config.bgp_table_per_peer_buckets) +
	  ((local_path_id - 1) % config.bgp_table_per_peer_buckets)) %
	  (config.bgp_table_peer_buckets * config.bgp_table_per_peer_buckets));
}
