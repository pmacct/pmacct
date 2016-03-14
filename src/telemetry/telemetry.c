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
#define __TELEMETRY_C

/* includes */
#include "pmacct.h"
#include "thread_pool.h"
#include "telemetry.h"
#if defined WITH_RABBITMQ
#include "amqp_common.h"
#endif
#ifdef WITH_KAFKA
#include "kafka_common.h"
#endif

/* variables to be exported away */
thread_pool_t *telemetry_pool;

/* Functions */
#if defined ENABLE_THREADS
void telemetry_wrapper()
{
  struct telemetry_data t_data;

  /* initialize variables */
  if (!config.telemetry_port) config.telemetry_port = TELEMETRY_TCP_PORT;

  /* initialize threads pool */
  telemetry_pool = allocate_thread_pool(1);
  assert(telemetry_pool);
  Log(LOG_DEBUG, "DEBUG ( %s/core/TELE ): %d thread(s) initialized\n", config.name, 1);
  telemetry_prepare_thread(&t_data);

  /* giving a kick to the BMP thread */
  send_to_pool(telemetry_pool, telemetry_daemon, &t_data);
}
#endif

void telemetry_daemon(void *t_data_void)
{
  struct telemetry_data *t_data = t_data_void;
  int slen, clen, ret, rc, peers_idx, allowed, yes=1, no=0;
  int peers_idx_rr = 0, max_peers_idx = 0;
  char *telemetry_packet_ptr;
  u_int32_t pkt_remaining_len=0;
  time_t now;

  struct telemetry_peer *peer = NULL;

  if (!t_data) {
    Log(LOG_ERR, "ERROR ( %s/%s ): telemetry_daemon(): missing telemetry data. Terminating.\n", config.name, t_data->log_str);
    exit_all(1);
  }

#if defined ENABLE_IPV6
  struct sockaddr_storage server, client;
#else
  struct sockaddr server, client;
#endif
  struct hosts_table allow;
  struct host_addr addr;

  /* select() stuff */
  fd_set read_descs, bkp_read_descs;
  int fd, select_fd, bkp_select_fd, recalc_fds, select_num;

  /* logdump time management */
  time_t dump_refresh_deadline;
  struct timeval dump_refresh_timeout, *drt_ptr;

  /* initial cleanups */
  reload_log_telemetry_thread = FALSE;
  memset(&server, 0, sizeof(server));
  memset(&client, 0, sizeof(client));
  memset(&allow, 0, sizeof(struct hosts_table));
  clen = sizeof(client);

  /* socket creation for telemetry server: IPv4 only */
#if (defined ENABLE_IPV6)
  if (!config.telemetry_ip) {
    struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&server;

    sa6->sin6_family = AF_INET6;
    sa6->sin6_port = htons(config.telemetry_port);
    slen = sizeof(struct sockaddr_in6);
  }
#else
  if (!config.telemetry_ip) {
    struct sockaddr_in *sa4 = (struct sockaddr_in *)&server;

    sa4->sin_family = AF_INET;
    sa4->sin_addr.s_addr = htonl(0);
    sa4->sin_port = htons(config.telemetry_port);
    slen = sizeof(struct sockaddr_in);
  }
#endif
  else {
    trim_spaces(config.telemetry_ip);
    ret = str_to_addr(config.telemetry_ip, &addr);
    if (!ret) {
      Log(LOG_ERR, "ERROR ( %s/%s ): 'telemetry_ip' value is not a valid IPv4/IPv6 address. Terminating.\n", config.name, t_data->log_str);
      exit_all(1);
    }
    slen = addr_to_sa((struct sockaddr *)&server, &addr, config.telemetry_port);
  }

  if (!config.telemetry_max_peers) config.telemetry_max_peers = TELEMETRY_MAX_PEERS_DEFAULT;
  Log(LOG_INFO, "INFO ( %s/%s ): maximum telemetry peers allowed: %d\n", config.name, t_data->log_str, config.telemetry_max_peers);

  telemetry_peers = malloc(config.telemetry_max_peers*sizeof(struct telemetry_peer));
  if (!telemetry_peers) {
    Log(LOG_ERR, "ERROR ( %s/%s ): Unable to malloc() telemetry peers structure. Terminating.\n", config.name, t_data->log_str);
    exit_all(1);
  }
  memset(telemetry_peers, 0, config.telemetry_max_peers*sizeof(struct telemetry_peer));

  // XXX: msglog + dump init

  config.telemetry_sock = socket(((struct sockaddr *)&server)->sa_family, SOCK_STREAM, 0);
  if (config.telemetry_sock < 0) {
#if (defined ENABLE_IPV6)
    /* retry with IPv4 */
    if (!config.telemetry_ip) {
      struct sockaddr_in *sa4 = (struct sockaddr_in *)&server;

      sa4->sin_family = AF_INET;
      sa4->sin_addr.s_addr = htonl(0);
      sa4->sin_port = htons(config.telemetry_port);
      slen = sizeof(struct sockaddr_in);

      config.telemetry_sock = socket(((struct sockaddr *)&server)->sa_family, SOCK_STREAM, 0);
    }
#endif

    if (config.telemetry_sock < 0) {
      Log(LOG_ERR, "ERROR ( %s/%s ): socket() failed. Terminating.\n", config.name, t_data->log_str);
      exit_all(1);
    }
  }

  if (config.telemetry_ipprec) {
    int opt = config.telemetry_ipprec << 5;

    rc = setsockopt(config.telemetry_sock, IPPROTO_IP, IP_TOS, &opt, sizeof(opt));
    if (rc < 0) Log(LOG_ERR, "WARN ( %s/%s ): setsockopt() failed for IP_TOS (errno: %d).\n", config.name, t_data->log_str, errno);
  }

  rc = setsockopt(config.telemetry_sock, SOL_SOCKET, SO_REUSEADDR, (char *)&yes, sizeof(yes));
  if (rc < 0) Log(LOG_ERR, "WARN ( %s/%s ): setsockopt() failed for SO_REUSEADDR (errno: %d).\n", config.name, t_data->log_str, errno);

#if (defined ENABLE_IPV6) && (defined IPV6_BINDV6ONLY)
  rc = setsockopt(config.telemetry_sock, IPPROTO_IPV6, IPV6_BINDV6ONLY, (char *) &no, (socklen_t) sizeof(no));
  if (rc < 0) Log(LOG_ERR, "WARN ( %s/%s ): setsockopt() failed for IPV6_BINDV6ONLY (errno: %d).\n", config.name, t_data->log_str, errno);
#endif

  if (config.telemetry_pipe_size) {
    int l = sizeof(config.telemetry_pipe_size);
    int saved = 0, obtained = 0;

    getsockopt(config.telemetry_sock, SOL_SOCKET, SO_RCVBUF, &saved, &l);
    Setsocksize(config.telemetry_sock, SOL_SOCKET, SO_RCVBUF, &config.telemetry_pipe_size, sizeof(config.telemetry_pipe_size));
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
    Log(LOG_ERR, "ERROR ( %s/%s ): bind() to ip=%s port=%d/tcp failed (errno: %d).\n",
	config.name, t_data->log_str, ip_address, config.telemetry_port, errno);
    exit_all(1);
  }

  rc = listen(config.telemetry_sock, 1);
  if (rc < 0) {
    Log(LOG_ERR, "ERROR ( %s/%s ): listen() failed (errno: %d).\n", config.name, t_data->log_str, errno);
    exit_all(1);
  }

  /* Preparing for syncronous I/O multiplexing */
  select_fd = 0;
  FD_ZERO(&bkp_read_descs);
  FD_SET(config.telemetry_sock, &bkp_read_descs);

  {
    char srv_string[INET6_ADDRSTRLEN];
    struct host_addr srv_addr;
    u_int16_t srv_port;

    sa_to_addr(&server, &srv_addr, &srv_port);
    addr_to_str(srv_string, &srv_addr);
    Log(LOG_INFO, "INFO ( %s/%s ): waiting for telemetry data on %s:%u\n", config.name, t_data->log_str, srv_string, srv_port);
  }

  /* Preparing ACL, if any */
  if (config.telemetry_allow_file) load_allow_file(config.telemetry_allow_file, &allow);

  select_fd = bkp_select_fd = (config.telemetry_sock + 1);
  recalc_fds = FALSE;

  // XXX: for (;;) loop
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
