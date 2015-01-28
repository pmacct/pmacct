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

  struct bgp_peer *peer;

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

  bmp_peers = malloc(config.nfacctd_bmp_max_peers*sizeof(struct bgp_peer));
  if (!bmp_peers) {
    Log(LOG_ERR, "ERROR ( %s/core/BMP ): Unable to malloc() BMP peers structure. Terminating thread.\n", config.name);
    exit_all(1);
  }
  memset(bmp_peers, 0, config.nfacctd_bmp_max_peers*sizeof(struct bgp_peer));

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
      if (select_fd < bmp_peers[peers_idx].fd) select_fd = bmp_peers[peers_idx].fd;
    select_fd++;
    memcpy(&read_descs, &bkp_read_descs, sizeof(bkp_read_descs));

    /* XXX: logging & refresh timeout handling */
    drt_ptr = NULL;

    select_num = select(select_fd, &read_descs, NULL, NULL, drt_ptr);
    if (select_num < 0) goto select_again;

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
        if (bmp_peers[peers_idx].fd == 0) {
          now = time(NULL);

          if (bmp_current_batch_elem > 0 || now > (bmp_current_batch_stamp_base + config.nfacctd_bmp_batch_interval)) {
            peer = &bmp_peers[peers_idx];
            if (bgp_peer_init(peer)) peer = NULL;

            log_notification_unset(&log_notifications.bmp_peers_throttling);

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
            if (!log_notification_isset(log_notifications.bmp_peers_throttling)) {
              Log(LOG_INFO, "INFO ( %s/core/BMP ): throttling at BMP peer #%u\n", config.name, peers_idx);
              log_notification_set(&log_notifications.bmp_peers_throttling);
            }
            fd = accept(config.bmp_sock, (struct sockaddr *) &client, &clen);
            close(fd);
            goto select_again;
          }
        }
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
      addr_to_str(peer->addr_str, &peer->addr);
      memcpy(&peer->id, &peer->addr, sizeof(struct host_addr)); /* XXX: some inet_ntoa()'s could be around against peer->id */

      /* Check: only one TCP connection is allowed per peer */
      for (peers_check_idx = 0, peers_num = 0; peers_check_idx < config.nfacctd_bmp_max_peers; peers_check_idx++) {
        if (peers_idx != peers_check_idx && !memcmp(&bmp_peers[peers_check_idx].addr, &peer->addr, sizeof(bmp_peers[peers_check_idx].addr))) {
          Log(LOG_ERR, "ERROR ( %s/core/BMP ): [Id: %s] Refusing new connection from existing peer.\n",
                                config.name, bmp_peers[peers_check_idx].addr_str);
          FD_CLR(peer->fd, &bkp_read_descs);
          bgp_peer_close(peer);
          goto select_again;
        }
        else {
          if (bmp_peers[peers_check_idx].fd) peers_num++;
        }
      }

      Log(LOG_INFO, "INFO ( %s/core/BMP ): BMP peers usage: %u/%u\n", config.name, peers_num, config.nfacctd_bmp_max_peers);

      if (config.nfacctd_bmp_neighbors_file)
        write_neighbors_file(config.nfacctd_bmp_neighbors_file);

      goto select_again;
    }

    /* We have something coming in: let's lookup which peer is that; XXX old: to be optimized */
    for (peer = NULL, peers_idx = 0; peers_idx < config.nfacctd_bmp_max_peers; peers_idx++) {
      if (bmp_peers[peers_idx].fd && FD_ISSET(bmp_peers[peers_idx].fd, &read_descs)) {
        peer = &bmp_peers[peers_idx];
        break;
      }
    }

    if (!peer) {
      Log(LOG_ERR, "ERROR ( %s/core/BMP ): message delivered to an unknown peer (FD bits: %d; FD max: %d)\n", config.name, select_num, select_fd);
      goto select_again;
    }

    peer->msglen = ret = recv(peer->fd, bmp_packet, BMP_MAX_PACKET_SIZE, 0);

    if (ret <= 0) {
      Log(LOG_INFO, "INFO ( %s/core/BMP ): [Id: %s] Existing BMP connection was reset (%d).\n", config.name, peer->addr_str, errno);
      FD_CLR(peer->fd, &bkp_read_descs);
      bgp_peer_close(peer);
      goto select_again;
    }
    else bmp_process_packet(bmp_packet, peer->msglen, peer);
  }
}

void bmp_process_packet(char *bmp_packet, u_int32_t len, struct bgp_peer *peer)
{
  char *bmp_packet_ptr = bmp_packet;
  u_int32_t remaining_len, bmp_len;

  struct bmp_common_hdr *bch = NULL;

  remaining_len = len;
  if (!(bch = (struct bmp_common_hdr *) bmp_get_and_check_length(&bmp_packet_ptr, &remaining_len, sizeof(struct bmp_common_hdr)))) {
    Log(LOG_INFO, "INFO ( %s/core/BMP ): [Id: %s] packet discarded: failed bmp_get_and_check_length() BMP common hdr\n", config.name, peer->addr_str);
    return;
  }

  if (bch->version != BMP_V3) {
    Log(LOG_INFO, "INFO ( %s/core/BMP ): [Id: %s] packet discarded: BMP version != %u\n", config.name, peer->addr_str, BMP_V3);
    return;
  } 

  bmp_common_hdr_get_len(bch, &bmp_len);

/*
  if (bmp_len != len) {
    // Option 1: log only
    Log(LOG_DEBUG, "DEBUG ( %s/core/BMP ): [Id: %s] BMP common hdr len (%u) != recv() len (%u)\n",
	config.name, peer->addr_str, bmp_len, len);

    // Option 2: log and return
    Log(LOG_INFO, "INFO ( %s/core/BMP ): [Id: %s] packet discarded: BMP len (%u) != recv() len (%u)\n",
	config.name, peer->addr_str, bmp_len, len);
    return;
  }
*/

  if (bch->type <= BMP_MSG_TYPE_MAX) {
    Log(LOG_DEBUG, "DEBUG ( %s/core/BMP ): [Id: %s] [common] type: %s (%u)\n",
	config.name, peer->addr_str, bmp_msg_types[bch->type], bch->type);
  }

  switch (bch->type) {
  case BMP_MSG_ROUTE:
    bmp_process_msg_route(&bmp_packet_ptr, &remaining_len, peer);
    break;
  case BMP_MSG_STATS:
    bmp_process_msg_stats(&bmp_packet_ptr, &remaining_len, peer);
    break;
  case BMP_MSG_PEER_DOWN:
    bmp_process_msg_peer_down(&bmp_packet_ptr, &remaining_len, peer);
    break;
  case BMP_MSG_PEER_UP:
    bmp_process_msg_peer_up(&bmp_packet_ptr, &remaining_len, peer); 
    break;
  case BMP_MSG_INIT:
    bmp_process_msg_init(&bmp_packet_ptr, &remaining_len, peer); 
    break;
  case BMP_MSG_TERM:
    bmp_process_msg_term(&bmp_packet_ptr, &remaining_len, peer); 
    break;
  default:
    Log(LOG_INFO, "INFO ( %s/core/BMP ): [Id: %s] packet discarded: unknown message type (%u)\n", config.name, peer->addr_str, bch->type);
    return;
  }
}

void bmp_process_msg_init(char **bmp_packet, u_int32_t *len, struct bgp_peer *peer)
{
  struct bmp_init_hdr *bih;
  u_int16_t bmp_len;
  char *bmp_init_info;

  while (*len) {
    if (!(bih = (struct bmp_init_hdr *) bmp_get_and_check_length(bmp_packet, len, sizeof(struct bmp_init_hdr)))) {
      Log(LOG_INFO, "INFO ( %s/core/BMP ): [Id: %s] [init] packet discarded: failed bmp_get_and_check_length() BMP init hdr\n",
		config.name, peer->addr_str);
      return;
    }

    bmp_init_hdr_get_len(bih, &bmp_len);

    if (!(bmp_init_info = bmp_get_and_check_length(bmp_packet, len, bmp_len))) {
      Log(LOG_INFO, "INFO ( %s/core/BMP ): [Id: %s] [init] packet discarded: failed bmp_get_and_check_length() BMP init info\n",
		config.name, peer->addr_str);
      return;
    }

    if (bih->type == BMP_INIT_INFO_STRING || bih->type == BMP_INIT_INFO_SYSDESCR || bih->type == BMP_INIT_INFO_SYSNAME) 
      Log(LOG_DEBUG, "DEBUG ( %s/core/BMP ): [Id: %s] [init] T: %u L: %u V: %s\n",
		config.name, peer->addr_str, bih->type, bmp_len, bmp_init_info);
    else
      Log(LOG_DEBUG, "DEBUG ( %s/core/BMP ): [Id: %s] [init] T: %u L: %u\n",
		config.name, peer->addr_str, bih->type, bmp_len);
  }
}

void bmp_process_msg_term(char **bmp_packet, u_int32_t *len, struct bgp_peer *peer)
{
  struct bmp_term_hdr *bth;
  u_int16_t bmp_len;
  char *bmp_term_info;

  while (*len) {
    if (!(bth = (struct bmp_term_hdr *) bmp_get_and_check_length(bmp_packet, len, sizeof(struct bmp_term_hdr)))) {
      Log(LOG_INFO, "INFO ( %s/core/BMP ): [Id: %s] [term] packet discarded: failed bmp_get_and_check_length() BMP term hdr\n",
		config.name, peer->addr_str);
       return;
    }

    bmp_term_hdr_get_len(bth, &bmp_len);

    if (!(bmp_term_info = bmp_get_and_check_length(bmp_packet, len, bmp_len))) {
      Log(LOG_INFO, "INFO ( %s/core/BMP ): [Id: %s] [term] packet discarded: failed bmp_get_and_check_length() BMP term info\n",
		config.name, peer->addr_str);
      return;
    }

    if (bth->type == BMP_TERM_INFO_STRING) 
      Log(LOG_DEBUG, "DEBUG ( %s/core/BMP ): [Id: %s] [term] T: %u L: %u V: %s\n",
		config.name, peer->addr_str, bth->type, bmp_len, bmp_term_info);
    else if (bth->type == BMP_TERM_INFO_REASON) {
      u_int16_t reason_type;
      char *reason_type_str = NULL;

      if (bmp_len == 2) {
	bmp_term_hdr_get_reason_type(bmp_packet, len, &reason_type);

	if (reason_type <= BMP_TERM_REASON_MAX) reason_type_str = (char *) bmp_term_reason_types[reason_type];

	Log(LOG_DEBUG, "DEBUG ( %s/core/BMP ): [Id: %s] [term] T: %u L: %u V: %s (%u)\n",
		config.name, peer->addr_str, bth->type, bmp_len, reason_type_str, reason_type);
      }
    }
    else
      Log(LOG_DEBUG, "DEBUG ( %s/core/BMP ): [Id: %s] [term] T: %u L: %u\n",
		config.name, peer->addr_str, bth->type, bmp_len);
  }
}

void bmp_process_msg_peer_up(char **bmp_packet, u_int32_t *len, struct bgp_peer *peer)
{
  struct bmp_data bdata;
  struct bmp_peer_hdr *bph;
  struct bmp_peer_up_hdr *bpuh;

  memset(&bdata, 0, sizeof(bdata));

  if (!(bph = (struct bmp_peer_hdr *) bmp_get_and_check_length(bmp_packet, len, sizeof(struct bmp_peer_hdr)))) {
    Log(LOG_INFO, "INFO ( %s/core/BMP ): [Id: %s] [peer up] packet discarded: failed bmp_get_and_check_length() BMP peer hdr\n",
	config.name, peer->addr_str);
    return;
  }

  if (!(bpuh = (struct bmp_peer_up_hdr *) bmp_get_and_check_length(bmp_packet, len, sizeof(struct bmp_peer_up_hdr)))) {
    Log(LOG_INFO, "INFO ( %s/core/BMP ): [Id: %s] [peer up] packet discarded: failed bmp_get_and_check_length() BMP peer up hdr\n",
	config.name), peer->addr_str;
    return;
  }

  bmp_peer_hdr_get_family(bph, &bdata.family);
  bmp_peer_hdr_get_peer_ip(bph, &bdata.peer_ip, bdata.family);
  bmp_peer_hdr_get_bgp_id(bph, &bdata.bgp_id);
  bmp_peer_hdr_get_tstamp(bph, &bdata.tstamp);
  bmp_peer_up_hdr_get_local_ip(bpuh, &bdata.local_ip, bdata.family);

  /* If no timestamp in BMP then let's generate one */
  if (!bdata.tstamp.tv_sec) gettimeofday(&bdata.tstamp, NULL);

  {
    char tstamp_str[SRVBUFLEN], peer_ip[INET6_ADDRSTRLEN], local_ip[INET6_ADDRSTRLEN];
    u_int32_t asn = 0;
    u_int16_t loc_port = 0, rem_port = 0;

    compose_timestamp(tstamp_str, SRVBUFLEN, &bdata.tstamp, TRUE);
    addr_to_str(peer_ip, &bdata.peer_ip);
    addr_to_str(local_ip, &bdata.local_ip);
    bmp_peer_hdr_get_asn(bph, &asn);
    bmp_peer_up_hdr_get_loc_port(bpuh, &loc_port);
    bmp_peer_up_hdr_get_rem_port(bpuh, &rem_port);

    Log(LOG_DEBUG, "DEBUG ( %s/core/BMP ): [Id: %s] [peer up] [tstamp: %s] [peer_ip: %s] type: %u bgp_id: %s, peer ASN: %u\n",
	config.name, peer->addr_str, tstamp_str, peer_ip, bph->type, inet_ntoa(bdata.bgp_id.address.ipv4), asn);

    Log(LOG_DEBUG, "DEBUG ( %s/core/BMP ): [Id: %s] [peer up] [tstamp: %s] [peer_ip: %s] local_ip: %s local port: %u remote port: %u\n",
	config.name, peer->addr_str, tstamp_str, peer_ip, local_ip, loc_port, rem_port);
  }
}

void bmp_process_msg_peer_down(char **bmp_packet, u_int32_t *len, struct bgp_peer *peer)
{
  struct bmp_data bdata;
  struct bmp_peer_hdr *bph;
  struct bmp_peer_down_hdr *bpdh;

  memset(&bdata, 0, sizeof(bdata));

  if (!(bph = (struct bmp_peer_hdr *) bmp_get_and_check_length(bmp_packet, len, sizeof(struct bmp_peer_hdr)))) {
    Log(LOG_INFO, "INFO ( %s/core/BMP ): [Id: %s] [peer down] packet discarded: failed bmp_get_and_check_length() BMP peer hdr\n",
        config.name, peer->addr_str);
    return;
  }

  if (!(bpdh = (struct bmp_peer_down_hdr *) bmp_get_and_check_length(bmp_packet, len, sizeof(struct bmp_peer_down_hdr)))) {
    Log(LOG_INFO, "INFO ( %s/core/BMP ): [Id: %s] [peer down] packet discarded: failed bmp_get_and_check_length() BMP peer down hdr\n",
        config.name, peer->addr_str);
    return;
  }

  bmp_peer_hdr_get_family(bph, &bdata.family);
  bmp_peer_hdr_get_peer_ip(bph, &bdata.peer_ip, bdata.family);
  bmp_peer_hdr_get_bgp_id(bph, &bdata.bgp_id);
  bmp_peer_hdr_get_tstamp(bph, &bdata.tstamp);

  /* If no timestamp in BMP then let's generate one */
  if (!bdata.tstamp.tv_sec) gettimeofday(&bdata.tstamp, NULL);

  {
    char tstamp_str[SRVBUFLEN], peer_ip[INET6_ADDRSTRLEN];
    u_int32_t asn = 0;
    u_int16_t code = 0;

    compose_timestamp(tstamp_str, SRVBUFLEN, &bdata.tstamp, TRUE);
    addr_to_str(peer_ip, &bdata.peer_ip);
    bmp_peer_hdr_get_asn(bph, &asn);

    Log(LOG_DEBUG, "DEBUG ( %s/core/BMP ): [Id: %s] [peer down] [tstamp: %s] [peer_ip: %s] type: %u bgp_id: %s, peer ASN: %u\n",
        config.name, peer->addr_str, tstamp_str, peer_ip, bph->type, inet_ntoa(bdata.bgp_id.address.ipv4), asn);

    switch (bpdh->reason) {
    case BMP_PEER_DOWN_LOC_CODE:
      bmp_peer_down_hdr_get_loc_code(bmp_packet, len, &code);
      Log(LOG_DEBUG, "DEBUG ( %s/core/BMP ): [Id: %s] [peer down] [tstamp: %s] [peer_ip: %s] reason type: %u code: %u\n",
		config.name, peer->addr_str, tstamp_str, peer_ip, bpdh->reason, code);
      break;
    case BMP_PEER_DOWN_LOC_NOT_MSG:
      // XXX: to be worked out
    case BMP_PEER_DOWN_REM_NOT_MSG:
      // XXX: to be worked out
    case BMP_PEER_DOWN_REM_CODE: 
    default:
      Log(LOG_DEBUG, "DEBUG ( %s/core/BMP ): [Id: %s] [peer down] [tstamp: %s] [peer_ip: %s] reason type: %u\n",
		config.name, peer->addr_str, tstamp_str, peer_ip, bpdh->reason);
      break;
    }
  }

  // XXX: withdraw routes from peer
}

void bmp_process_msg_route(char **bmp_packet, u_int32_t *len, struct bgp_peer *peer)
{
  struct bmp_data bdata;
  struct bmp_peer_hdr *bph;
  char tstamp_str[SRVBUFLEN], peer_ip[INET6_ADDRSTRLEN];

  if (!(bph = (struct bmp_peer_hdr *) bmp_get_and_check_length(bmp_packet, len, sizeof(struct bmp_peer_hdr)))) {
    Log(LOG_INFO, "INFO ( %s/core/BMP ): [Id: %s] [stats] packet discarded: failed bmp_get_and_check_length() BMP peer hdr\n",
        config.name, peer->addr_str);
    return;
  }

  bmp_peer_hdr_get_family(bph, &bdata.family);
  bmp_peer_hdr_get_peer_ip(bph, &bdata.peer_ip, bdata.family);
  bmp_peer_hdr_get_bgp_id(bph, &bdata.bgp_id);
  bmp_peer_hdr_get_tstamp(bph, &bdata.tstamp);

  /* If no timestamp in BMP then let's generate one */
  if (!bdata.tstamp.tv_sec) gettimeofday(&bdata.tstamp, NULL);

  compose_timestamp(tstamp_str, SRVBUFLEN, &bdata.tstamp, TRUE);
  addr_to_str(peer_ip, &bdata.peer_ip);

  // XXX: parse BGP UPDATE(s)
}

void bmp_process_msg_stats(char **bmp_packet, u_int32_t *len, struct bgp_peer *peer)
{
  struct bmp_data bdata;
  struct bmp_peer_hdr *bph;
  struct bmp_stats_hdr *bsh;
  struct bmp_stats_cnt_hdr *bsch;
  u_int64_t cnt_data64;
  u_int32_t index, count = 0, cnt_data32;
  u_int16_t cnt_type, cnt_len;
  u_int8_t got_data;
  char tstamp_str[SRVBUFLEN], peer_ip[INET6_ADDRSTRLEN];

  memset(&bdata, 0, sizeof(bdata));

  if (!(bph = (struct bmp_peer_hdr *) bmp_get_and_check_length(bmp_packet, len, sizeof(struct bmp_peer_hdr)))) {
    Log(LOG_INFO, "INFO ( %s/core/BMP ): [Id: %s] [stats] packet discarded: failed bmp_get_and_check_length() BMP peer hdr\n",
        config.name, peer->addr_str);
    return;
  }

  if (!(bsh = (struct bmp_stats_hdr *) bmp_get_and_check_length(bmp_packet, len, sizeof(struct bmp_stats_hdr)))) {
    Log(LOG_INFO, "INFO ( %s/core/BMP ): [Id: %s] [stats] packet discarded: failed bmp_get_and_check_length() BMP stats hdr\n",
        config.name, peer->addr_str);
    return;
  }

  bmp_peer_hdr_get_family(bph, &bdata.family);
  bmp_peer_hdr_get_peer_ip(bph, &bdata.peer_ip, bdata.family);
  bmp_peer_hdr_get_bgp_id(bph, &bdata.bgp_id);
  bmp_peer_hdr_get_tstamp(bph, &bdata.tstamp);
  bmp_stats_hdr_get_count(bsh, &count);

  /* If no timestamp in BMP then let's generate one */
  if (!bdata.tstamp.tv_sec) gettimeofday(&bdata.tstamp, NULL);

  compose_timestamp(tstamp_str, SRVBUFLEN, &bdata.tstamp, TRUE);
  addr_to_str(peer_ip, &bdata.peer_ip);

  for (index = 0; index < count; index++) {
    if (!(bsch = (struct bmp_stats_cnt_hdr *) bmp_get_and_check_length(bmp_packet, len, sizeof(struct bmp_stats_cnt_hdr)))) {
      Log(LOG_INFO, "INFO ( %s/core/BMP ): [Id: %s] [stats] packet discarded: failed bmp_get_and_check_length() BMP stats cnt hdr #%u\n",
          config.name, peer->addr_str, index);
      return;
    }

    bmp_stats_cnt_hdr_get_type(bsch, &cnt_type);
    bmp_stats_cnt_hdr_get_len(bsch, &cnt_len);
    cnt_data32 = 0; cnt_data64 = 0, got_data = FALSE;

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
      if (cnt_len == 4) {
	bmp_stats_cnt_get_data32(bmp_packet, len, &cnt_data32);
	got_data = TRUE;
      }
      else if (cnt_len == 8) {
	bmp_stats_cnt_get_data64(bmp_packet, len, &cnt_data64);
	got_data = TRUE;
      }
      else bmp_get_and_check_length(bmp_packet, len, cnt_len);
      break;
    }

    if (cnt_data32 && !cnt_data64) cnt_data64 = cnt_data32; 
    if (cnt_type <= BMP_STATS_MAX) {
      Log(LOG_DEBUG, "DEBUG ( %s/core/BMP ): [Id: %s] [stats] [tstamp: %s] [peer_ip: %s] %s (%u): %llu\n",
		config.name, peer->addr_str, tstamp_str, peer_ip, bmp_stats_cnt_types[cnt_type], cnt_type, cnt_data64);
    }
    else {
      if (got_data) {
        Log(LOG_DEBUG, "DEBUG ( %s/core/BMP ): [Id: %s] [stats] [tstamp: %s] [peer_ip: %s] %s (%u): %llu\n",
                config.name, peer->addr_str, tstamp_str, peer_ip, "Unknown", cnt_type, cnt_data64);
      }
      else {
        Log(LOG_DEBUG, "DEBUG ( %s/core/BMP ): [Id: %s] [stats] [tstamp: %s] [peer_ip: %s] unknown stats counter: %u\n",
                config.name, peer->addr_str, tstamp_str, peer_ip, cnt_type);
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

    if (version == 0) (*family) = AF_INET;
#if defined ENABLE_IPV6
    else if (version == 1) (*family) = AF_INET6;
#endif
  }
}

void bmp_peer_hdr_get_peer_ip(struct bmp_peer_hdr *bph, struct host_addr *a, u_int8_t family)
{
  if (bph && a && family) {
    a->family = family;

    if (family == AF_INET) a->address.ipv4.s_addr = bph->addr[3]; 
#if defined ENABLE_IPV6
    else if (family == AF_INET6) memcpy(&a->address.ipv6, &bph->addr, 16); 
#endif
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

void bmp_peer_hdr_get_asn(struct bmp_peer_hdr *bph, u_int32_t *asn)
{
  if (bph && asn) (*asn) = ntohl(bph->asn);
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
  
  if ((*pkt_size) >= len) {
    current_ptr = (*bmp_packet_ptr);
    (*pkt_size) -= len;
    (*bmp_packet_ptr) += len;
  }

  return current_ptr;
}

void bmp_attr_init()
{
  aspath_init(&bmp_ashash);
  attrhash_init(&bmp_attrhash);
  community_init(&bmp_comhash);
  ecommunity_init(&bmp_ecomhash);
}
