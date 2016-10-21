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

#define __TEE_PLUGIN_C

#include "pmacct.h"
#include "addr.h"
#include "tee_plugin.h"
#include "pmacct-data.h"
#include "plugin_hooks.h"

void tee_plugin(int pipe_fd, struct configuration *cfgptr, void *ptr)
{
  struct pkt_msg *msg;
  unsigned char *pipebuf;
  struct pollfd pfd;
  int timeout, refresh_timeout, amqp_timeout, kafka_timeout, err, ret, num;
  int fd, pool_idx, recv_idx;
  struct ring *rg = &((struct channels_list_entry *)ptr)->rg;
  struct ch_status *status = ((struct channels_list_entry *)ptr)->status;
  struct plugins_list_entry *plugin_data = ((struct channels_list_entry *)ptr)->plugin;
  u_int32_t bufsz = ((struct channels_list_entry *)ptr)->bufsize;
  pid_t core_pid = ((struct channels_list_entry *)ptr)->core_pid;
  char *dataptr, dest_addr[256], dest_serv[256];
  struct tee_receiver *target = NULL;
  struct plugin_requests req;

  unsigned char *rgptr;
  int pollagain = TRUE;
  u_int32_t seq = 1, rg_err_count = 0;
  time_t now;
  void *kafka_msg;

#ifdef WITH_RABBITMQ
  struct p_amqp_host *amqp_host = &((struct channels_list_entry *)ptr)->amqp_host;
#endif

#ifdef WITH_KAFKA
  struct p_kafka_host *kafka_host = &((struct channels_list_entry *)ptr)->kafka_host;
#endif

  memcpy(&config, cfgptr, sizeof(struct configuration));
  recollect_pipe_memory(ptr);
  pm_setproctitle("%s [%s]", "Tee Plugin", config.name);
  if (config.pidfile) write_pid_file_plugin(config.pidfile, config.type, config.name);
  if (config.logfile) {
    fclose(config.logfile_fd);
    config.logfile_fd = open_output_file(config.logfile, "a", FALSE);
  }

  if (config.proc_priority) {
    int ret;

    ret = setpriority(PRIO_PROCESS, 0, config.proc_priority);
    if (ret) Log(LOG_WARNING, "WARN ( %s/%s ): proc_priority failed (errno: %d)\n", config.name, config.type, errno);
    else Log(LOG_INFO, "INFO ( %s/%s ): proc_priority set to %d\n", config.name, config.type, getpriority(PRIO_PROCESS, 0));
  }

  /* signal handling */
  signal(SIGINT, Tee_exit_now);
  signal(SIGUSR1, SIG_IGN);
  signal(SIGUSR2, reload_maps); /* sets to true the reload_maps flag */
  signal(SIGPIPE, SIG_IGN);
  signal(SIGCHLD, SIG_IGN);

  if (config.tee_transparent && getuid() != 0) {
    Log(LOG_ERR, "ERROR ( %s/%s ): Transparent mode requires super-user permissions. Exiting ...\n", config.name, config.type);
    exit_plugin(1);
  }

  if (config.nfprobe_receiver && config.tee_receivers) {
    Log(LOG_ERR, "ERROR ( %s/%s ): tee_receiver and tee_receivers are mutually exclusive. Exiting ...\n", config.name, config.type);
    exit_plugin(1);
  }
  else if (!config.nfprobe_receiver && !config.tee_receivers) {
    Log(LOG_ERR, "ERROR ( %s/%s ): No receivers specified: tee_receiver or tee_receivers is required. Exiting ...\n", config.name, config.type);
    exit_plugin(1);
  }

  memset(&receivers, 0, sizeof(receivers));
  memset(&req, 0, sizeof(req));
  reload_map = FALSE;

  /* Setting up pools */
  if (!config.tee_max_receiver_pools) config.tee_max_receiver_pools = MAX_TEE_POOLS;

  receivers.pools = malloc((config.tee_max_receiver_pools+1)*sizeof(struct tee_receivers_pool));
  if (!receivers.pools) {
    Log(LOG_ERR, "ERROR ( %s/%s ): unable to allocate receiver pools. Exiting ...\n", config.name, config.type);
    exit_plugin(1);
  }
  else memset(receivers.pools, 0, (config.tee_max_receiver_pools+1)*sizeof(struct tee_receivers_pool));

  /* Setting up receivers per pool */
  if (!config.tee_max_receivers) config.tee_max_receivers = MAX_TEE_RECEIVERS;

  for (pool_idx = 0; pool_idx < config.tee_max_receiver_pools; pool_idx++) { 
    receivers.pools[pool_idx].receivers = malloc(config.tee_max_receivers*sizeof(struct tee_receivers));
    if (!receivers.pools[pool_idx].receivers) {
      Log(LOG_ERR, "ERROR ( %s/%s ): unable to allocate receivers for pool #%u. Exiting ...\n", config.name, config.type, pool_idx);
      exit_plugin(1);
    }
    else memset(receivers.pools[pool_idx].receivers, 0, config.tee_max_receivers*sizeof(struct tee_receivers));
  }

  if (config.nfprobe_receiver) {
    pool_idx = 0; recv_idx = 0;

    target = &receivers.pools[pool_idx].receivers[recv_idx];
    target->dest_len = sizeof(target->dest);
    if (Tee_parse_hostport(config.nfprobe_receiver, (struct sockaddr *) &target->dest, &target->dest_len)) {
      Log(LOG_ERR, "ERROR ( %s/%s ): Invalid receiver %s . ", config.name, config.type, config.nfprobe_receiver);
      exit_plugin(1);
    }
    else {
      recv_idx++; receivers.pools[pool_idx].num = recv_idx;
      pool_idx++; receivers.num = pool_idx;
    }
  }
  else if (config.tee_receivers) {
    int recvs_allocated = FALSE;

    req.key_value_table = (void *) &receivers;
    load_id_file(MAP_TEE_RECVS, config.tee_receivers, NULL, &req, &recvs_allocated);
  }

  config.sql_refresh_time = DEFAULT_TEE_REFRESH_TIME;
  refresh_timeout = config.sql_refresh_time*1000;

  pipebuf = (unsigned char *) pm_malloc(config.buffer_size);

  if (config.pipe_amqp) {
    plugin_pipe_amqp_compile_check();
#ifdef WITH_RABBITMQ
    pipe_fd = plugin_pipe_amqp_connect_to_consume(amqp_host, plugin_data);
    amqp_timeout = plugin_pipe_set_retry_timeout(&amqp_host->btimers, pipe_fd);
#endif
  }
  else if (config.pipe_kafka) {
    plugin_pipe_kafka_compile_check();
#ifdef WITH_KAFKA
    pipe_fd = plugin_pipe_kafka_connect_to_consume(kafka_host, plugin_data);
    kafka_timeout = plugin_pipe_set_retry_timeout(&kafka_host->btimers, pipe_fd);
#endif
  }
  else setnonblocking(pipe_fd);

  now = time(NULL);

  memset(pipebuf, 0, config.buffer_size);
  err_cant_bridge_af = 0;

  /* Arrange send socket */
  Tee_init_socks();

  /* plugin main loop */
  for (;;) {
    poll_again:
    status->wakeup = TRUE;

    pfd.fd = pipe_fd;
    pfd.events = POLLIN;

    if (config.pipe_homegrown || config.pipe_amqp) {
      timeout = MIN(refresh_timeout, (amqp_timeout ? amqp_timeout : INT_MAX));
      ret = poll(&pfd, (pfd.fd == ERR ? 0 : 1), timeout);
    }
#ifdef WITH_KAFKA
    else if (config.pipe_kafka) {
      timeout = MIN(refresh_timeout, (kafka_timeout ? kafka_timeout : INT_MAX));
      ret = p_kafka_consume_poller(kafka_host, &kafka_msg, timeout);
    }
#endif

    if (ret < 0) goto poll_again;

    if (reload_map) {
      if (config.tee_receivers) {
        int recvs_allocated = FALSE;

        Tee_destroy_recvs();
        load_id_file(MAP_TEE_RECVS, config.tee_receivers, NULL, &req, &recvs_allocated);

        Tee_init_socks();
      }

      reload_map = FALSE;
    }

    now = time(NULL);

#ifdef WITH_RABBITMQ
    if (config.pipe_amqp && pipe_fd == ERR) {
      if (timeout == amqp_timeout) {
        pipe_fd = plugin_pipe_amqp_connect_to_consume(amqp_host, plugin_data);
        amqp_timeout = plugin_pipe_set_retry_timeout(&amqp_host->btimers, pipe_fd);
      }
      else amqp_timeout = plugin_pipe_calc_retry_timeout_diff(&amqp_host->btimers, now);
    }
#endif

#ifdef WITH_KAFKA
    if (config.pipe_kafka && pipe_fd == ERR) {
      if (timeout == kafka_timeout) {
        pipe_fd = plugin_pipe_kafka_connect_to_consume(kafka_host, plugin_data);
        kafka_timeout = plugin_pipe_set_retry_timeout(&kafka_host->btimers, pipe_fd);
      }
      else kafka_timeout = plugin_pipe_calc_retry_timeout_diff(&kafka_host->btimers, now);
    }
#endif

    switch (ret) {
    case 0: /* timeout */
      /* reserved for future since we don't currently cache/batch/etc */
      break;
    default: /* we received data */
      read_data:
      if (config.pipe_homegrown) {
        if (!pollagain) {
          seq++;
          seq %= MAX_SEQNUM;
          if (seq == 0) rg_err_count = FALSE;
        }
        else {
          if ((ret = read(pipe_fd, &rgptr, sizeof(rgptr))) == 0)
            exit_plugin(1); /* we exit silently; something happened at the write end */
        }
  
        if ((rg->ptr + bufsz) > rg->end) rg->ptr = rg->base;
  
        if (((struct ch_buf_hdr *)rg->ptr)->seq != seq) {
          if (!pollagain) {
            pollagain = TRUE;
            goto poll_again;
          }
          else {
            rg_err_count++;
            if (config.debug || (rg_err_count > MAX_RG_COUNT_ERR)) {
              Log(LOG_WARNING, "WARN ( %s/%s ): Missing data detected (plugin_buffer_size=%llu plugin_pipe_size=%llu).\n",
                        config.name, config.type, config.buffer_size, config.pipe_size);
              Log(LOG_WARNING, "WARN ( %s/%s ): Increase values or look for plugin_buffer_size, plugin_pipe_size in CONFIG-KEYS document.\n\n",
                        config.name, config.type);
            }

	    rg->ptr = (rg->base + status->last_buf_off);
            seq = ((struct ch_buf_hdr *)rg->ptr)->seq;
          }
        }
  
        pollagain = FALSE;
        memcpy(pipebuf, rg->ptr, bufsz);
        rg->ptr += bufsz;
      }
#ifdef WITH_RABBITMQ
      else if (config.pipe_amqp) {
        ret = p_amqp_consume_binary(amqp_host, pipebuf, config.buffer_size);
        if (ret) pipe_fd = ERR;

        seq = ((struct ch_buf_hdr *)pipebuf)->seq;
        amqp_timeout = plugin_pipe_set_retry_timeout(&amqp_host->btimers, pipe_fd);
      }
#endif
#ifdef WITH_KAFKA
      else if (config.pipe_kafka) {
        ret = p_kafka_consume_data(kafka_host, kafka_msg, pipebuf, config.buffer_size);
        if (ret) pipe_fd = ERR;

        seq = ((struct ch_buf_hdr *)pipebuf)->seq;
        kafka_timeout = plugin_pipe_set_retry_timeout(&kafka_host->btimers, pipe_fd);
      }
#endif

      msg = (struct pkt_msg *) (pipebuf+sizeof(struct ch_buf_hdr));
      msg->payload = (pipebuf+sizeof(struct ch_buf_hdr)+PmsgSz);

      if (config.debug_internal_msg) 
        Log(LOG_DEBUG, "DEBUG ( %s/%s ): buffer received cpid=%u len=%llu seq=%u num_entries=%u\n",
                config.name, config.type, core_pid, ((struct ch_buf_hdr *)pipebuf)->len,
                seq, ((struct ch_buf_hdr *)pipebuf)->num);

      if (!config.pipe_check_core_pid || ((struct ch_buf_hdr *)pipebuf)->core_pid == core_pid) {
      while (((struct ch_buf_hdr *)pipebuf)->num > 0) {
	for (pool_idx = 0; pool_idx < receivers.num; pool_idx++) {
	  if (!evaluate_tags(&receivers.pools[pool_idx].tag_filter, msg->tag)) {
	    if (!receivers.pools[pool_idx].balance.func) {
	      for (recv_idx = 0; recv_idx < receivers.pools[pool_idx].num; recv_idx++) {
	        target = &receivers.pools[pool_idx].receivers[recv_idx];
	        Tee_send(msg, (struct sockaddr *) &target->dest, target->fd);
	      }
	    }
	    else {
	      target = receivers.pools[pool_idx].balance.func(&receivers.pools[pool_idx], msg);
	      Tee_send(msg, (struct sockaddr *) &target->dest, target->fd);
	    }
	  }
	}

        ((struct ch_buf_hdr *)pipebuf)->num--;
        if (((struct ch_buf_hdr *)pipebuf)->num) {
	  dataptr = (unsigned char *) msg;
          dataptr += (PmsgSz + msg->len);
	  msg = (struct pkt_msg *) dataptr;
	  msg->payload = (dataptr + PmsgSz);
	}
      }
      }

      if (config.pipe_homegrown) goto read_data;
    }
  }  
}

void Tee_exit_now(int signum)
{
  wait(NULL);
  exit_plugin(0);
}

void Tee_send(struct pkt_msg *msg, struct sockaddr *target, int fd)
{
  struct host_addr r;
  u_char recv_addr[50];
  u_int16_t recv_port;

  if (config.debug) {
    char *flow = NULL, netflow[] = "NetFlow/IPFIX", sflow[] = "sFlow";
    struct host_addr a;
    u_char agent_addr[50];
    u_int16_t agent_port;

    sa_to_addr((struct sockaddr *)msg, &a, &agent_port);
    addr_to_str(agent_addr, &a);

    sa_to_addr((struct sockaddr *)target, &r, &recv_port);
    addr_to_str(recv_addr, &r);

    if (config.acct_type == ACCT_NF) flow = netflow;
    else if (config.acct_type == ACCT_SF) flow = sflow;

    Log(LOG_DEBUG, "DEBUG ( %s/%s ): Sending %s packet from [%s:%u] seqno [%u] to [%s:%u]\n",
                        config.name, config.type, flow, agent_addr, agent_port, msg->seqno,
			recv_addr, recv_port);
  }

  if (!config.tee_transparent) {
    if (send(fd, msg->payload, msg->len, 0) == -1) {
      struct host_addr a;
      u_char agent_addr[50];
      u_int16_t agent_port;

      sa_to_addr((struct sockaddr *)msg, &a, &agent_port);
      addr_to_str(agent_addr, &a);

      sa_to_addr((struct sockaddr *)target, &r, &recv_port);
      addr_to_str(recv_addr, &r);

      Log(LOG_ERR, "ERROR ( %s/%s ): send() from [%s:%u] seqno [%u] to [%s:%u] failed (%s)\n",
			config.name, config.type, agent_addr, agent_port, msg->seqno, recv_addr,
			recv_port, strerror(errno));
    }
  }
  else {
    char *buf_ptr = tee_send_buf;
    struct sockaddr_in *sa = (struct sockaddr_in *) &msg->agent;
    struct my_iphdr *i4h = (struct my_iphdr *) buf_ptr;
#if defined ENABLE_IPV6
    struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *) &msg->agent;
    struct ip6_hdr *i6h = (struct ip6_hdr *) buf_ptr;
#endif
    struct my_udphdr *uh;

    if (msg->agent.sa_family == target->sa_family) {
      /* UDP header first */
      if (target->sa_family == AF_INET) {
        buf_ptr += IP4HdrSz;
        uh = (struct my_udphdr *) buf_ptr;
        uh->uh_sport = sa->sin_port;
        uh->uh_dport = ((struct sockaddr_in *)target)->sin_port;
      }
#if defined ENABLE_IPV6
      else if (target->sa_family == AF_INET6) {
        buf_ptr += IP6HdrSz;
        uh = (struct my_udphdr *) buf_ptr;
        uh->uh_sport = sa6->sin6_port;
        uh->uh_dport = ((struct sockaddr_in6 *)target)->sin6_port;
      }
#endif

      uh->uh_ulen = htons(msg->len+UDPHdrSz);
      uh->uh_sum = 0;

      /* IP header then */
      if (target->sa_family == AF_INET) {
        i4h->ip_vhl = 4;
        i4h->ip_vhl <<= 4;
        i4h->ip_vhl |= (IP4HdrSz/4);

	if (config.nfprobe_ipprec) {
	  int opt = config.nfprobe_ipprec << 5;
          i4h->ip_tos = opt;
	}
	else i4h->ip_tos = 0;

#if !defined BSD
        i4h->ip_len = htons(IP4HdrSz+UDPHdrSz+msg->len);
#else
        i4h->ip_len = IP4HdrSz+UDPHdrSz+msg->len;
#endif
        i4h->ip_id = 0;
        i4h->ip_off = 0;
        i4h->ip_ttl = 255;
        i4h->ip_p = IPPROTO_UDP;
        i4h->ip_sum = 0;
        i4h->ip_src.s_addr = sa->sin_addr.s_addr;
        i4h->ip_dst.s_addr = ((struct sockaddr_in *)target)->sin_addr.s_addr;
      }
#if defined ENABLE_IPV6
      else if (target->sa_family == AF_INET6) {
        i6h->ip6_vfc = 6;
        i6h->ip6_vfc <<= 4;
        i6h->ip6_plen = htons(UDPHdrSz+msg->len);
        i6h->ip6_nxt = IPPROTO_UDP;
        i6h->ip6_hlim = 255;
        memcpy(&i6h->ip6_src, &sa6->sin6_addr, IP6AddrSz);
        memcpy(&i6h->ip6_dst, &((struct sockaddr_in6 *)target)->sin6_addr, IP6AddrSz);
      }
#endif

      /* Put everything together and send */
      buf_ptr += UDPHdrSz;
      memcpy(buf_ptr, msg->payload, msg->len);

      if (send(fd, tee_send_buf, IP4HdrSz+UDPHdrSz+msg->len, 0) == -1) {
        struct host_addr a;
        u_char agent_addr[50];
        u_int16_t agent_port;

        sa_to_addr((struct sockaddr *)msg, &a, &agent_port);
        addr_to_str(agent_addr, &a);

	sa_to_addr((struct sockaddr *)target, &r, &recv_port);
	addr_to_str(recv_addr, &r);

        Log(LOG_ERR, "ERROR ( %s/%s ): raw send() from [%s:%u] seqno [%u] to [%s:%u] failed (%s)\n",
			config.name, config.type, agent_addr, agent_port, msg->seqno, recv_addr,
			recv_port, strerror(errno));
      }
    }
    else {
      time_t now = time(NULL);

      if (now > err_cant_bridge_af + 60) {
        Log(LOG_ERR, "ERROR ( %s/%s ): Can't bridge Address Families when in transparent mode\n", config.name, config.type);
	err_cant_bridge_af = now;
      }
    }
  }
}

void Tee_destroy_recvs()
{
  struct tee_receiver *target = NULL;
  int pool_idx, recv_idx;

  for (pool_idx = 0; pool_idx < receivers.num; pool_idx++) {
    for (recv_idx = 0; recv_idx < receivers.pools[pool_idx].num; recv_idx++) {
      target = &receivers.pools[pool_idx].receivers[recv_idx];
      if (target->fd) close(target->fd);
    }

    memset(receivers.pools[pool_idx].receivers, 0, config.tee_max_receivers*sizeof(struct tee_receivers));
    memset(&receivers.pools[pool_idx].tag_filter, 0, sizeof(struct pretag_filter));
    memset(&receivers.pools[pool_idx].balance, 0, sizeof(struct tee_balance));
    receivers.pools[pool_idx].id = 0;
    receivers.pools[pool_idx].num = 0;
  }

  receivers.num = 0;
}

void Tee_init_socks()
{
  struct tee_receiver *target = NULL;
  struct sockaddr *sa;
  int pool_idx, recv_idx, err;
  char dest_addr[256], dest_serv[256];

  for (pool_idx = 0; pool_idx < receivers.num; pool_idx++) {
    for (recv_idx = 0; recv_idx < receivers.pools[pool_idx].num; recv_idx++) {
      target = &receivers.pools[pool_idx].receivers[recv_idx];
      sa = (struct sockaddr *) &target->dest;
      target->dest_len = sizeof(target->dest);

      if (sa->sa_family != 0) {
        if ((err = getnameinfo(sa, target->dest_len, dest_addr, sizeof(dest_addr),
            dest_serv, sizeof(dest_serv), NI_NUMERICHOST)) == -1) {
          Log(LOG_ERR, "ERROR ( %s/%s ): getnameinfo: %d\n", config.name, config.type, err);
          exit_plugin(1);
        }
      }

      target->fd = Tee_prepare_sock((struct sockaddr *) &target->dest, target->dest_len);

      if (config.debug) {
	struct host_addr recv_addr;
        u_char recv_addr_str[INET6_ADDRSTRLEN];
	u_int16_t recv_port;

	sa_to_addr((struct sockaddr *)&target->dest, &recv_addr, &recv_port); 
        addr_to_str(recv_addr_str, &recv_addr);
        Log(LOG_DEBUG, "DEBUG ( %s/%s ): pool ID: %u :: receiver: %s :: fd: %d.\n",
                config.name, config.type, receivers.pools[pool_idx].id, recv_addr_str, target->fd);
      }
    }
  }
}

int Tee_prepare_sock(struct sockaddr *addr, socklen_t len)
{
  int s, ret = 0;

  if (!config.tee_transparent) {
    struct host_addr source_ip;
#if defined ENABLE_IPV6
    struct sockaddr_storage ssource_ip;
#else
    struct sockaddr ssource_ip;
#endif

    if (config.nfprobe_source_ip) {
      ret = str_to_addr(config.nfprobe_source_ip, &source_ip);
      addr_to_sa((struct sockaddr *) &ssource_ip, &source_ip, 0);
    }

    if ((s = socket(addr->sa_family, SOCK_DGRAM, 0)) == -1) {
      Log(LOG_ERR, "ERROR ( %s/%s ): socket() error: %s\n", config.name, config.type, strerror(errno));
      exit_plugin(1);
    }

    if (config.nfprobe_ipprec) {
      int opt = config.nfprobe_ipprec << 5;
      int rc;

      rc = setsockopt(s, IPPROTO_IP, IP_TOS, &opt, sizeof(opt));
      if (rc < 0) Log(LOG_WARNING, "WARN ( %s/%s ): setsockopt() failed for IP_TOS: %s\n", config.name, config.type, strerror(errno));
    }

    if (ret && bind(s, (struct sockaddr *) &ssource_ip, sizeof(ssource_ip)) == -1)
      Log(LOG_ERR, "ERROR ( %s/%s ): bind() error: %s\n", config.name, config.type, strerror(errno));
  }
  else {
    int hincl = 1;                  /* 1 = on, 0 = off */

    if ((s = socket(addr->sa_family, SOCK_RAW, IPPROTO_RAW)) == -1) {
      Log(LOG_ERR, "ERROR ( %s/%s ): socket() error: %s\n", config.name, config.type, strerror(errno));
      exit_plugin(1);
    }


#if defined BSD
    setsockopt(s, IPPROTO_IP, IP_HDRINCL, &hincl, sizeof(hincl));
#endif
  }

  if (config.tee_pipe_size) {
    int l = sizeof(config.tee_pipe_size);
    int saved = 0, obtained = 0;
    
    getsockopt(s, SOL_SOCKET, SO_SNDBUF, &saved, &l);
    Setsocksize(s, SOL_SOCKET, SO_SNDBUF, &config.tee_pipe_size, sizeof(config.tee_pipe_size));
    getsockopt(s, SOL_SOCKET, SO_SNDBUF, &obtained, &l);
  
    if (obtained < saved) {
      Setsocksize(s, SOL_SOCKET, SO_SNDBUF, &saved, l);
      getsockopt(s, SOL_SOCKET, SO_SNDBUF, &obtained, &l);
    }
    Log(LOG_INFO, "INFO ( %s/%s ): tee_pipe_size: obtained=%d target=%d.\n", config.name, config.type, obtained, config.tee_pipe_size);
  }

  if (connect(s, (struct sockaddr *)addr, len) == -1) {
    Log(LOG_ERR, "ERROR ( %s/%s ): connect() error: %s\n", config.name, config.type, strerror(errno));
    exit_plugin(1);
  }

  return(s);
}

int Tee_parse_hostport(const char *s, struct sockaddr *addr, socklen_t *len)
{
  char *orig, *host, *port;
  struct addrinfo hints, *res;
  int herr;

  memset(&hints, '\0', sizeof(hints));

  if ((host = orig = strdup(s)) == NULL) {
    Log(LOG_ERR, "ERROR ( %s/%s ): Tee_parse_hostport() out of memory. Exiting ..\n", config.name, config.type);
    exit_plugin(1);
  }

  trim_spaces(host);
  trim_spaces(orig);

  if ((port = strrchr(host, ':')) == NULL || *(++port) == '\0' || *host == '\0') return TRUE;

  *(port - 1) = '\0';

  /* Accept [host]:port for numeric IPv6 addresses */
  if (*host == '[' && *(port - 2) == ']') {
    host++;
    *(port - 2) = '\0';
    hints.ai_family = AF_INET6;
  }

  hints.ai_socktype = SOCK_DGRAM;

  /* Validations */
  if ((herr = getaddrinfo(host, port, &hints, &res)) == -1) return TRUE;
  if (res == NULL || res->ai_addr == NULL) return TRUE;
  if (res->ai_addrlen > *len) return TRUE;

  memcpy(addr, res->ai_addr, res->ai_addrlen);
  free(orig);
  *len = res->ai_addrlen;

  return FALSE;
}

struct tee_receiver *Tee_rr_balance(void *pool, struct pkt_msg *msg)
{
  struct tee_receivers_pool *p = pool;
  struct tee_receiver *target = NULL;

  if (p) {
    target = &p->receivers[p->balance.next % p->num];
    p->balance.next++;
    p->balance.next %= p->num;
  }

  return target;
}

struct tee_receiver *Tee_hash_agent_balance(void *pool, struct pkt_msg *msg)
{
  struct tee_receivers_pool *p = pool;
  struct tee_receiver *target = NULL;
  struct sockaddr_in *sa4 = (struct sockaddr_in *) &msg->agent;

  if (p) {
    if (msg->agent.sa_family == AF_INET) target = &p->receivers[sa4->sin_addr.s_addr & p->num];
    /* XXX: hashing against IPv6 agents is not supported (yet) */
  }

  return target;
}

struct tee_receiver *Tee_hash_tag_balance(void *pool, struct pkt_msg *msg)
{
  struct tee_receivers_pool *p = pool;
  struct tee_receiver *target = NULL;

  if (p) target = &p->receivers[msg->tag % p->num];

  return target;
}
