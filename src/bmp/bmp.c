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
#define __BMP_C

/* includes */
#include "pmacct.h"
#include "../bgp/bgp.h"
#include "bmp.h"
#include "thread_pool.h"

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
  int slen, clen, ret, rc, peers_idx, allowed, yes=1;
  char bmp_packet[BMP_MAX_PACKET_SIZE], *bmp_packet_ptr;
  struct timeval dump_refresh_timeout, *drt_ptr;
  time_t now;
  afi_t afi;
  safi_t safi;

  struct bgp_peer *peer; /* XXX: bgp_peer ? */

#if defined ENABLE_IPV6
  struct sockaddr_storage server, client;
  struct ipv6_mreq multi_req6;
#else
  struct sockaddr server, client;
#endif
  struct hosts_table allow;
  struct host_addr addr;

  /* BMP peer batching vars */
  int bmp_current_batch_elem = 0;
  time_t bmp_current_batch_stamp_base = 0;

  /* select() stuff */
  fd_set read_descs, bkp_read_descs;
  int select_fd, select_num;

  /* initial cleanups */
  memset(&server, 0, sizeof(server));
  memset(&client, 0, sizeof(client));
  memset(bmp_packet, 0, BMP_MAX_PACKET_SIZE);
  memset(&allow, 0, sizeof(struct hosts_table));
  clen = sizeof(client);

  /* socket creation for BMP server: IPv4 only */
#if (defined ENABLE_IPV6 && defined V4_MAPPED)
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

  /* XXX: BMP peers sructure allocation */

  /* XXX: init logging structures, including AMQP */

  if (!config.bmp_table_attr_hash_buckets) config.bmp_table_attr_hash_buckets = HASHTABSIZE;
  bmp_attr_init();

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
#if (defined ENABLE_IPV6 && defined V4_MAPPED)
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

  if (config.nfacctd_bmp_pipe_size) {
    int l = sizeof(config.nfacctd_bmp_pipe_size);
    u_int64_t saved = 0, obtained = 0;

    getsockopt(config.bmp_sock, SOL_SOCKET, SO_RCVBUF, &saved, &l);
    Setsocksize(config.bmp_sock, SOL_SOCKET, SO_RCVBUF, &config.nfacctd_bmp_pipe_size, sizeof(config.nfacctd_bmp_pipe_size));
    getsockopt(config.bmp_sock, SOL_SOCKET, SO_RCVBUF, &obtained, &l);

    Setsocksize(config.bmp_sock, SOL_SOCKET, SO_RCVBUF, &saved, l);
    getsockopt(config.bmp_sock, SOL_SOCKET, SO_RCVBUF, &obtained, &l);
    Log(LOG_INFO, "INFO ( %s/core/BMP ): bmp_daemon_pipe_size: obtained=%u target=%u.\n", config.name, obtained, config.nfacctd_bmp_pipe_size);
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
      bmp_rib[afi][safi] = bgp_table_init(afi, safi);
    }
  }

  /* BMP peers batching checks */
  if ((config.nfacctd_bmp_batch && !config.nfacctd_bmp_batch_interval) ||
      (config.nfacctd_bmp_batch_interval && !config.nfacctd_bmp_batch)) {
    Log(LOG_WARNING, "WARN ( %s/core/BMP ): 'bmp_daemon_batch_interval' and 'bmp_daemon_batch' both set to zero.\n", config.name);
    config.nfacctd_bmp_batch = 0;
    config.nfacctd_bmp_batch_interval = 0;
  }

  /* XXX: more init logging structures, including AMQP */

  for (;;) {
    select_again:

    select_fd = config.bmp_sock;
    for (peers_idx = 0; peers_idx < config.nfacctd_bmp_max_peers; peers_idx++)
      if (select_fd < peers[peers_idx].fd) select_fd = peers[peers_idx].fd;
    select_fd++;
    memcpy(&read_descs, &bkp_read_descs, sizeof(bkp_read_descs));

    /* XXX: logging & refresh timeout handling */
    drt_ptr = NULL;

    select_num = select(select_fd, &read_descs, NULL, NULL, drt_ptr);
    if (select_num < 0) goto select_again;

    /* XXX: signals handling, if any */

    /* XXX: if (reload_log_bmp_thread) */

    /* XXX: bgp_handle_dump_event() && bgp_daemon_msglog_init_amqp_host() */

    /* 
       If select_num == 0 then we got out of select() due to a timeout rather
       than because we had a message from a peeer to handle. By now we did all
       routine checks and can happily return to selet() again.
    */
    if (!select_num) goto select_again;

    /* New connection is coming in */
    if (FD_ISSET(config.bmp_sock, &read_descs)) {
      int peers_check_idx, peers_num;

      for (peer = NULL, peers_idx = 0; peers_idx < config.nfacctd_bmp_max_peers; peers_idx++) {
        if (peers[peers_idx].fd == 0) {
          now = time(NULL);

          if (bmp_current_batch_elem > 0 || now > (bmp_current_batch_stamp_base + config.nfacctd_bmp_batch_interval)) {
            peer = &peers[peers_idx];
            if (bgp_peer_init(peer)) peer = NULL;

            // XXX: log_notification_unset(&log_notifications.bmp_peers_throttling);

            if (config.nfacctd_bmp_batch && peer) {
              if (now > (bmp_current_batch_stamp_base + config.nfacctd_bmp_batch_interval)) {
                bmp_current_batch_elem = config.nfacctd_bmp_batch;
                bmp_current_batch_stamp_base = now;
              }

              if (bmp_current_batch_elem > 0) bmp_current_batch_elem--;
            }

            break;
          }
          else { /* throttle */
            int fd = 0;

            /* We briefly accept the new connection to be able to drop it */
/* 	    XXX:
            if (!log_notification_isset(log_notifications.bmp_peers_throttling)) {
              Log(LOG_INFO, "INFO ( %s/core/BMP ): throttling at BMP peer #%u\n", config.name, peers_idx);
              log_notification_set(&log_notifications.bmp_peers_throttling);
            }
*/
            fd = accept(config.bmp_sock, (struct sockaddr *) &client, &clen);
            close(fd);
            goto select_again;
          }
        }
        /* XXX: replenish sessions with expired keepalives */
      }

      if (!peer) {
        int fd;

        /* We briefly accept the new connection to be able to drop it */
        Log(LOG_ERR, "ERROR ( %s/core/BMP ): Insufficient number of BMP peers has been configured by 'bmp_daemon_max_peers' (%d).\n",
                        config.name, config.nfacctd_bmp_max_peers);
        fd = accept(config.bmp_sock, (struct sockaddr *) &client, &clen);
        close(fd);
        goto select_again;
      }
      peer->fd = accept(config.bmp_sock, (struct sockaddr *) &client, &clen);

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

      /* Check: only one TCP connection is allowed per peer */
      for (peers_check_idx = 0, peers_num = 0; peers_check_idx < config.nfacctd_bmp_max_peers; peers_check_idx++) {
        if (peers_idx != peers_check_idx && !memcmp(&peers[peers_check_idx].addr, &peer->addr, sizeof(peers[peers_check_idx].addr))) {
          now = time(NULL);
          if ((now - peers[peers_check_idx].last_keepalive) > peers[peers_check_idx].ht) {
            Log(LOG_INFO, "INFO ( %s/core/BMP ): [Id: %s] Replenishing stale connection by peer.\n",
                                config.name, inet_ntoa(peers[peers_check_idx].id.address.ipv4));
            FD_CLR(peers[peers_check_idx].fd, &bkp_read_descs);
            bgp_peer_close(&peers[peers_check_idx]);
          }
          else {
            Log(LOG_ERR, "ERROR ( %s/core/BMP ): [Id: %s] Refusing new connection from existing peer (residual holdtime: %u).\n",
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

      Log(LOG_INFO, "INFO ( %s/core/BMP ): BMP peers usage: %u/%u\n", config.name, peers_num, config.nfacctd_bmp_max_peers);

      if (config.nfacctd_bmp_neighbors_file)
        write_neighbors_file(config.nfacctd_bmp_neighbors_file);

      goto select_again;
    }

    /* We have something coming in: let's lookup which peer is that; XXX: to be optimized */
    for (peer = NULL, peers_idx = 0; peers_idx < config.nfacctd_bmp_max_peers; peers_idx++) {
      if (peers[peers_idx].fd && FD_ISSET(peers[peers_idx].fd, &read_descs)) {
        peer = &peers[peers_idx];
        break;
      }
    }

    if (!peer) {
      Log(LOG_ERR, "ERROR ( %s/core/BMP ): message delivered to an unknown peer (FD bits: %d; FD max: %d)\n", config.name, select_num, select_fd);
      goto select_again;
    }

    peer->msglen = ret = recv(peer->fd, bmp_packet, BMP_MAX_PACKET_SIZE, 0);

    if (ret <= 0) {
      Log(LOG_INFO, "INFO ( %s/core/BMP ): [Id: %s] Existing BMP connection was reset (%d).\n", config.name, inet_ntoa(peer->id.address.ipv4), errno);
      FD_CLR(peer->fd, &bkp_read_descs);
      bgp_peer_close(peer);
      goto select_again;
    }
    else {
      /* XXX: BMP packet parsing & processing */
    }
  }
}

void bmp_attr_init()
{
  aspath_init(bmp_ashash);
  attrhash_init(bmp_attrhash);
  community_init(bmp_comhash);
  ecommunity_init(bmp_ecomhash);
}
