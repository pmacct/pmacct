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

#include "pmacct.h"
#include "addr.h"
#ifdef WITH_KAFKA
#include "kafka_common.h"
#endif
#include "pmacct-data.h"
#include "plugin_hooks.h"
#include "plugin_common.h"
#include "tee_plugin.h"
#include "nfacctd.h"
#include "crc32.h"

/* Global variables */
char tee_send_buf[65535];
struct tee_receivers receivers; 

void tee_plugin(int pipe_fd, struct configuration *cfgptr, void *ptr)
{
  struct pkt_msg *msg;
  unsigned char *pipebuf;
  struct pollfd pfd;
  int refresh_timeout, ret, pool_idx, recv_idx, recv_budget, poll_bypass;
  struct ring *rg = &((struct channels_list_entry *)ptr)->rg;
  struct ch_status *status = ((struct channels_list_entry *)ptr)->status;
  u_int32_t bufsz = ((struct channels_list_entry *)ptr)->bufsize;
  unsigned char *dataptr;
  struct tee_receiver *target = NULL;
  struct plugin_requests req;

  unsigned char *rgptr;
  int pollagain = TRUE;
  u_int32_t seq = 1, rg_err_count = 0;

#ifdef WITH_ZMQ
  struct p_zmq_host *zmq_host = &((struct channels_list_entry *)ptr)->zmq_host;
#else
  void *zmq_host = NULL;
#endif

#ifdef WITH_REDIS
  struct p_redis_host redis_host;
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
    exit_gracefully(1);
  }

  if (!config.tee_receivers) {
    Log(LOG_ERR, "ERROR ( %s/%s ): No receivers specified: tee_receivers is required. Exiting ...\n", config.name, config.type);
    exit_gracefully(1);
  }

  memset(empty_mem_area_256b, 0, sizeof(empty_mem_area_256b));
  memset(&receivers, 0, sizeof(receivers));
  memset(&req, 0, sizeof(req));
  reload_map = FALSE;

  /* Setting up pools */
  if (!config.tee_max_receiver_pools) config.tee_max_receiver_pools = MAX_TEE_POOLS;

  receivers.pools = malloc((config.tee_max_receiver_pools+1)*sizeof(struct tee_receivers_pool));
  if (!receivers.pools) {
    Log(LOG_ERR, "ERROR ( %s/%s ): unable to allocate receiver pools. Exiting ...\n", config.name, config.type);
    exit_gracefully(1);
  }
  else memset(receivers.pools, 0, (config.tee_max_receiver_pools+1)*sizeof(struct tee_receivers_pool));

  /* Setting up receivers per pool */
  if (!config.tee_max_receivers) config.tee_max_receivers = MAX_TEE_RECEIVERS;

  for (pool_idx = 0; pool_idx < config.tee_max_receiver_pools; pool_idx++) { 
    receivers.pools[pool_idx].receivers = malloc(config.tee_max_receivers*sizeof(struct tee_receiver));
    if (!receivers.pools[pool_idx].receivers) {
      Log(LOG_ERR, "ERROR ( %s/%s ): unable to allocate receivers for pool #%u. Exiting ...\n", config.name, config.type, pool_idx);
      exit_gracefully(1);
    }
    else memset(receivers.pools[pool_idx].receivers, 0, config.tee_max_receivers*sizeof(struct tee_receiver));
  }

  if (config.tee_receivers) {
    int recvs_allocated = FALSE;

    req.key_value_table = (void *) &receivers;
    load_id_file(MAP_TEE_RECVS, config.tee_receivers, NULL, &req, &recvs_allocated);
  }

  config.sql_refresh_time = DEFAULT_TEE_REFRESH_TIME;
  refresh_timeout = config.sql_refresh_time*1000;

  pipebuf = (unsigned char *) pm_malloc(config.buffer_size);

  if (config.pipe_zmq) P_zmq_pipe_init(zmq_host, &pipe_fd, &seq);
  else setnonblocking(pipe_fd);

  memset(pipebuf, 0, config.buffer_size);

  /* Arrange send socket */
  Tee_init_socks();

#ifdef WITH_REDIS
  if (config.redis_host) {
    char log_id[SHORTBUFLEN];

    snprintf(log_id, sizeof(log_id), "%s/%s", config.name, config.type);
    p_redis_init(&redis_host, log_id, p_redis_thread_produce_common_plugin_handler);
  }
#endif

  /* plugin main loop */
  for (;;) {
    poll_again:
    status->wakeup = TRUE;
    poll_bypass = FALSE;

    pfd.fd = pipe_fd;
    pfd.events = POLLIN;

    ret = poll(&pfd, (pfd.fd == ERR ? 0 : 1), refresh_timeout);

    if (ret < 0) goto poll_again;

    poll_ops:
    if (reload_map) {
      if (config.tee_receivers) {
        int recvs_allocated = FALSE;

        Tee_destroy_recvs();
        load_id_file(MAP_TEE_RECVS, config.tee_receivers, NULL, &req, &recvs_allocated);

        Tee_init_socks();
      }

      reload_map = FALSE;
    }

    if (reload_log) {
      reload_logs();
      reload_log = FALSE;
    }

    recv_budget = 0;
    if (poll_bypass) {
      poll_bypass = FALSE;
      goto read_data;
    }

    switch (ret) {
    case 0: /* timeout */
      /* reserved for future since we don't currently cache/batch/etc */
      break;
    default: /* we received data */
      read_data:
      if (recv_budget == DEFAULT_PLUGIN_COMMON_RECV_BUDGET) {
	poll_bypass = TRUE;
	goto poll_ops;
      }

      if (config.pipe_homegrown) {
        if (!pollagain) {
          seq++;
          seq %= MAX_SEQNUM;
          if (seq == 0) rg_err_count = FALSE;
        }
        else {
          if ((ret = read(pipe_fd, &rgptr, sizeof(rgptr))) == 0)
            exit_gracefully(1); /* we exit silently; something happened at the write end */
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
              Log(LOG_WARNING, "WARN ( %s/%s ): Missing data detected (plugin_buffer_size=%" PRIu64 " plugin_pipe_size=%" PRIu64 ").\n",
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
#ifdef WITH_ZMQ
      else if (config.pipe_zmq) {
	ret = p_zmq_topic_recv(zmq_host, pipebuf, config.buffer_size);
	if (ret > 0) {
	  if (seq && (((struct ch_buf_hdr *)pipebuf)->seq != ((seq + 1) % MAX_SEQNUM))) {
	    Log(LOG_WARNING, "WARN ( %s/%s ): Missing data detected. Sequence received=%u expected=%u\n",
		config.name, config.type, ((struct ch_buf_hdr *)pipebuf)->seq, ((seq + 1) % MAX_SEQNUM));
	  }

	  seq = ((struct ch_buf_hdr *)pipebuf)->seq;
	}
	else goto poll_again;
      }
#endif

      msg = (struct pkt_msg *) (pipebuf+sizeof(struct ch_buf_hdr));
      msg->payload = (pipebuf+sizeof(struct ch_buf_hdr)+PmsgSz);

      if (config.debug_internal_msg) 
        Log(LOG_DEBUG, "DEBUG ( %s/%s ): buffer received len=%" PRIu64 " seq=%u num_entries=%u\n",
                config.name, config.type, ((struct ch_buf_hdr *)pipebuf)->len, seq,
                ((struct ch_buf_hdr *)pipebuf)->num);

      while (((struct ch_buf_hdr *)pipebuf)->num > 0) {
	for (pool_idx = 0; pool_idx < receivers.num; pool_idx++) {
	  if (msg->bcast || !evaluate_tags(&receivers.pools[pool_idx].tag_filter, msg->tag)) {
	    if (!receivers.pools[pool_idx].balance.func) {
	      for (recv_idx = 0; recv_idx < receivers.pools[pool_idx].num; recv_idx++) {
	        target = &receivers.pools[pool_idx].receivers[recv_idx];
	        Tee_send(msg, (struct sockaddr *) &target->dest, target->fd, config.tee_transparent);
	      }

#ifdef WITH_KAFKA
	      /* Checking the handler is the most light weight op we can perform
		 in order to ensure we are in business with the Kafka broker */
	      if (p_kafka_get_handler(&receivers.pools[pool_idx].kafka_host)) {
		Tee_kafka_send(msg, &receivers.pools[pool_idx]);
	      }
#endif

#ifdef WITH_ZMQ
	      if (p_zmq_get_sock(&receivers.pools[pool_idx].zmq_host)) {
		Tee_zmq_send(msg, &receivers.pools[pool_idx]);
	      }
#endif
	    }
	    else {
	      target = receivers.pools[pool_idx].balance.func(&receivers.pools[pool_idx], msg);
	      Tee_send(msg, (struct sockaddr *) &target->dest, target->fd, config.tee_transparent);
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

      recv_budget++;
      goto read_data;
    }
  }  
}

void Tee_exit_now(int signum)
{
  wait(NULL);
  exit_gracefully(0);
}

size_t Tee_craft_transparent_msg(struct pkt_msg *msg, struct sockaddr *target)
{
  char *buf_ptr = tee_send_buf;
  struct sockaddr *sa = (struct sockaddr *) &msg->agent;
  struct sockaddr_in *sa4 = (struct sockaddr_in *) &msg->agent;
  struct pm_iphdr *i4h = (struct pm_iphdr *) buf_ptr;
  struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *) &msg->agent;
  struct ip6_hdr *i6h = (struct ip6_hdr *) buf_ptr;
  struct pm_udphdr *uh;
  size_t msglen = 0;

  if (sa->sa_family == target->sa_family) {
    /* UDP header first */
    if (target->sa_family == AF_INET) {
      buf_ptr += IP4HdrSz;
      uh = (struct pm_udphdr *) buf_ptr;
      uh->uh_sport = sa4->sin_port;
      uh->uh_dport = ((struct sockaddr_in *)target)->sin_port;
    }
    else if (target->sa_family == AF_INET6) {
      buf_ptr += IP6HdrSz;
      uh = (struct pm_udphdr *) buf_ptr;
      uh->uh_sport = sa6->sin6_port;
      uh->uh_dport = ((struct sockaddr_in6 *)target)->sin6_port;
    }
    else {
      assert(0);
      return msglen;
    }

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
      i4h->ip_src.s_addr = sa4->sin_addr.s_addr;
      i4h->ip_dst.s_addr = ((struct sockaddr_in *)target)->sin_addr.s_addr;

      msglen = (IP4HdrSz + UDPHdrSz + msg->len);
    }
    else if (target->sa_family == AF_INET6) {
      i6h->ip6_vfc = 6;
      i6h->ip6_vfc <<= 4;
      i6h->ip6_plen = htons(UDPHdrSz+msg->len);
      i6h->ip6_nxt = IPPROTO_UDP;
      i6h->ip6_hlim = 255;
      memcpy(&i6h->ip6_src, &sa6->sin6_addr, IP6AddrSz);
      memcpy(&i6h->ip6_dst, &((struct sockaddr_in6 *)target)->sin6_addr, IP6AddrSz);

      msglen = (IP6HdrSz + UDPHdrSz + msg->len);
    }

    /* Put everything together and send */
    buf_ptr += UDPHdrSz;
    memcpy(buf_ptr, msg->payload, msg->len);

    /* If IPv6: last thing last compute the checksum */
    if (target->sa_family == AF_INET6) {
      uh->uh_sum = pm_udp6_checksum(i6h, uh, msg->payload, msg->len);
    }
  }
  else {
    time_t now = time(NULL);

    if (!log_notification_isset(&log_notifications.tee_plugin_cant_bridge_af, now)) {
      Log(LOG_ERR, "ERROR ( %s/%s ): Can't bridge Address Families when in transparent mode\n", config.name, config.type);
      log_notification_set(&log_notifications.tee_plugin_cant_bridge_af, now, 60);
    }
  }

  return msglen;
}

void Tee_send(struct pkt_msg *msg, struct sockaddr *target, int fd, int transparent)
{
  struct host_addr r;
  char recv_addr[50];
  u_int16_t recv_port;

  if (config.debug) {
    char *flow = NULL, netflow[] = "NetFlow/IPFIX", sflow[] = "sFlow";
    struct host_addr a;
    char agent_addr[50];
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

  if (!transparent) {
    if (send(fd, msg->payload, msg->len, 0) == -1) {
      struct host_addr a;
      char agent_addr[50];
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
    size_t msglen;

    msglen = Tee_craft_transparent_msg(msg, target);

    if (msglen && send(fd, tee_send_buf, msglen, 0) == -1) {
      struct host_addr a;
      char agent_addr[50];
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
}

#ifdef WITH_KAFKA
void Tee_kafka_send(struct pkt_msg *msg, struct tee_receivers_pool *pool)
{
  struct p_kafka_host *kafka_host = &pool->kafka_host; 
  struct sockaddr *sa, target;
  time_t last_fail, now;
  size_t msglen = 0;

  memset(&target, 0, sizeof(target));
  sa = (struct sockaddr *) &msg->agent;

  target.sa_family = sa->sa_family;

  if (config.debug) {
    char *flow = NULL, netflow[] = "NetFlow/IPFIX", sflow[] = "sFlow";
    char *broker, *topic;
    struct host_addr a;
    char agent_addr[50];
    u_int16_t agent_port;

    sa_to_addr((struct sockaddr *)msg, &a, &agent_port);
    addr_to_str(agent_addr, &a);

    broker = p_kafka_get_broker(kafka_host);
    topic = p_kafka_get_topic(kafka_host);

    if (config.acct_type == ACCT_NF) flow = netflow;
    else if (config.acct_type == ACCT_SF) flow = sflow;

    Log(LOG_DEBUG, "DEBUG ( %s/%s ): Sending %s packet from [%s:%u] seqno [%u] to Kafka [%s-%s]\n",
                        config.name, config.type, flow, agent_addr, agent_port, msg->seqno,
                        broker, topic);
  }

  last_fail = P_broker_timers_get_last_fail(&kafka_host->btimers);
  if (last_fail) {
    now = time(NULL);

    if ((last_fail + P_broker_timers_get_retry_interval(&kafka_host->btimers)) <= now) {
      Tee_init_kafka_host(kafka_host, pool->kafka_broker, pool->kafka_topic, pool->id);
    }
  }

  if (config.tee_transparent) {
    msglen = Tee_craft_transparent_msg(msg, &target);

    if (msglen) p_kafka_produce_data(kafka_host, tee_send_buf, msglen);
  }
}
#endif

#ifdef WITH_ZMQ
void Tee_zmq_send(struct pkt_msg *msg, struct tee_receivers_pool *pool)
{
  struct p_zmq_host *zmq_host = &pool->zmq_host; 
  struct sockaddr *sa, target;
  size_t msglen = 0;
  int ret;

  memset(&target, 0, sizeof(target));
  sa = (struct sockaddr *) &msg->agent;

  target.sa_family = sa->sa_family;

  if (config.debug) {
    char *flow = NULL, netflow[] = "NetFlow/IPFIX", sflow[] = "sFlow";
    char *address;
    struct host_addr a;
    char agent_addr[50];
    u_int16_t agent_port;

    sa_to_addr((struct sockaddr *)msg, &a, &agent_port);
    addr_to_str(agent_addr, &a);

    address = p_zmq_get_address(zmq_host);

    if (config.acct_type == ACCT_NF) flow = netflow;
    else if (config.acct_type == ACCT_SF) flow = sflow;

    Log(LOG_DEBUG, "DEBUG ( %s/%s ): Sending %s packet from [%s:%u] seqno [%u] via ZeroMQ [%s]\n",
	config.name, config.type, flow, agent_addr, agent_port, msg->seqno, address);
  }

  if (config.tee_transparent) {
    msglen = Tee_craft_transparent_msg(msg, &target);

    if (msglen) {
      ret = p_zmq_send_bin(&zmq_host->sock, tee_send_buf, msglen, TRUE);
      if (ret == ERR && errno == EAGAIN) {
	char *address;

	address = p_zmq_get_address(zmq_host);
	Log(LOG_WARNING, "WARN ( %s/%s ): Queue full: ZeroMQ [%s]\n", config.name, config.type, address);
      }
    }
  }
}
#endif

void Tee_destroy_recvs()
{
  struct tee_receiver *target = NULL;
  int pool_idx, recv_idx;

  for (pool_idx = 0; pool_idx < receivers.num; pool_idx++) {
    for (recv_idx = 0; recv_idx < receivers.pools[pool_idx].num; recv_idx++) {
      target = &receivers.pools[pool_idx].receivers[recv_idx];
      if (target->fd) close(target->fd);
    }

    memset(receivers.pools[pool_idx].receivers, 0, config.tee_max_receivers*sizeof(struct tee_receiver));
    memset(&receivers.pools[pool_idx].tag_filter, 0, sizeof(struct pretag_filter));
    memset(&receivers.pools[pool_idx].balance, 0, sizeof(struct tee_balance));
    receivers.pools[pool_idx].id = 0;
    receivers.pools[pool_idx].num = 0;

#ifdef WITH_KAFKA
    if (strlen(receivers.pools[pool_idx].kafka_broker)) {
      p_kafka_close(&receivers.pools[pool_idx].kafka_host, FALSE);
      memset(receivers.pools[pool_idx].kafka_broker, 0, sizeof(receivers.pools[pool_idx].kafka_broker));
      memset(receivers.pools[pool_idx].kafka_topic, 0, sizeof(receivers.pools[pool_idx].kafka_topic));
    }
#endif

#ifdef WITH_ZMQ
    if (strlen(receivers.pools[pool_idx].zmq_address)) {
      p_zmq_close(&receivers.pools[pool_idx].zmq_host);
      memset(receivers.pools[pool_idx].zmq_address, 0, sizeof(receivers.pools[pool_idx].zmq_address));
    }
#endif
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

      if (sa->sa_family != 0) {
        if ((err = getnameinfo(sa, target->dest_len, dest_addr, sizeof(dest_addr),
            dest_serv, sizeof(dest_serv), NI_NUMERICHOST)) == -1) {
          Log(LOG_ERR, "ERROR ( %s/%s ): getnameinfo: %d\n", config.name, config.type, err);
          exit_gracefully(1);
        }
      }

      target->fd = Tee_prepare_sock((struct sockaddr *) &target->dest, target->dest_len, receivers.pools[pool_idx].src_port,
				    config.tee_transparent, config.tee_pipe_size);

      if (config.debug) {
	struct host_addr recv_addr;
        char recv_addr_str[INET6_ADDRSTRLEN];
	u_int16_t recv_port;

	sa_to_addr((struct sockaddr *)&target->dest, &recv_addr, &recv_port); 
        addr_to_str(recv_addr_str, &recv_addr);
        Log(LOG_DEBUG, "DEBUG ( %s/%s ): PoolID=%u receiver=%s fd=%d\n",
	    config.name, config.type, receivers.pools[pool_idx].id, recv_addr_str, target->fd);
      }
    }

#ifdef WITH_KAFKA
    if (strlen(receivers.pools[pool_idx].kafka_broker)) {
      Tee_init_kafka_host(&receivers.pools[pool_idx].kafka_host, receivers.pools[pool_idx].kafka_broker,
			  receivers.pools[pool_idx].kafka_topic, receivers.pools[pool_idx].id);
    }
#endif

#ifdef WITH_ZMQ
    if (strlen(receivers.pools[pool_idx].zmq_address)) {
      Tee_init_zmq_host(&receivers.pools[pool_idx].zmq_host, receivers.pools[pool_idx].zmq_address,
			receivers.pools[pool_idx].id);
    }
#endif
  }
}

#ifdef WITH_KAFKA
void Tee_init_kafka_host(struct p_kafka_host *kafka_host, char *kafka_broker, char *kafka_topic, u_int32_t pool_id)
{
  p_kafka_init_host(kafka_host, config.tee_kafka_config_file);
  p_kafka_connect_to_produce(kafka_host);
  p_kafka_set_broker(kafka_host, kafka_broker, FALSE);
  p_kafka_set_topic(kafka_host, kafka_topic);
  p_kafka_set_content_type(kafka_host, PM_KAFKA_CNT_TYPE_BIN);
  P_broker_timers_set_retry_interval(&kafka_host->btimers, PM_KAFKA_DEFAULT_RETRY);

  if (config.debug) {
    char *broker, *topic;

    broker = p_kafka_get_broker(kafka_host);
    topic = p_kafka_get_topic(kafka_host);
    Log(LOG_DEBUG, "DEBUG ( %s/%s ): PoolID=%u KafkaBroker=%s KafkaTopic=%s\n",
	config.name, config.type, pool_id, broker, topic);
  }
}
#endif

#ifdef WITH_ZMQ
void Tee_init_zmq_host(struct p_zmq_host *zmq_host, char *zmq_address, u_int32_t pool_id)
{
  char log_id[SHORTBUFLEN];

  p_zmq_init_push(zmq_host, zmq_address);
  snprintf(log_id, sizeof(log_id), "%s/%s", config.name, config.type);
  p_zmq_set_log_id(zmq_host, log_id);
  p_zmq_set_hwm(zmq_host, PM_ZMQ_DEFAULT_FLOW_HWM); 
  p_zmq_push_setup(zmq_host);

  if (config.debug) {
    char *broker;

    broker = p_zmq_get_address(zmq_host);
    Log(LOG_DEBUG, "DEBUG ( %s/%s ): PoolID=%u ZmqAddress=%s\n", config.name, config.type, pool_id, broker);
  }
}
#endif

int Tee_prepare_sock(struct sockaddr *addr, socklen_t len, u_int16_t src_port, int transparent, int pipe_size)
{
  int s, ret = 0;

  if (!transparent) {
    struct host_addr source_ip;
    struct sockaddr_storage ssource_ip;

    memset(&source_ip, 0, sizeof(source_ip));
    memset(&ssource_ip, 0, sizeof(ssource_ip));

    if (src_port) { 
      source_ip.family = addr->sa_family; 
      ret = addr_to_sa((struct sockaddr *) &ssource_ip, &source_ip, src_port);
    }

    if ((s = socket(addr->sa_family, SOCK_DGRAM, 0)) == -1) {
      Log(LOG_ERR, "ERROR ( %s/%s ): socket() error: %s\n", config.name, config.type, strerror(errno));
      exit_gracefully(1);
    }

    if (ret && bind(s, (struct sockaddr *) &ssource_ip, sizeof(ssource_ip)) == -1)
      Log(LOG_WARNING, "WARN ( %s/%s ): bind() error: %s\n", config.name, config.type, strerror(errno));
  }
  else {
    if ((s = socket(addr->sa_family, SOCK_RAW, IPPROTO_RAW)) == -1) {
      Log(LOG_ERR, "ERROR ( %s/%s ): socket() error: %s\n", config.name, config.type, strerror(errno));
      exit_gracefully(1);
    }


#if defined BSD
    setsockopt(s, IPPROTO_IP, IP_HDRINCL, &hincl, (socklen_t) sizeof(hincl));
#endif
  }

  if (pipe_size) {
    socklen_t l = sizeof(pipe_size);
    int saved = 0, obtained = 0;
    
    getsockopt(s, SOL_SOCKET, SO_SNDBUF, &saved, &l);
    Setsocksize(s, SOL_SOCKET, SO_SNDBUF, &pipe_size, (socklen_t) sizeof(pipe_size));
    getsockopt(s, SOL_SOCKET, SO_SNDBUF, &obtained, &l);
  
    if (obtained < saved) {
      Setsocksize(s, SOL_SOCKET, SO_SNDBUF, &saved, l);
      getsockopt(s, SOL_SOCKET, SO_SNDBUF, &obtained, &l);
    }
    Log(LOG_INFO, "INFO ( %s/%s ): tee_pipe_size: obtained=%d target=%d.\n", config.name, config.type, obtained, pipe_size);
  }

  if (connect(s, (struct sockaddr *)addr, len) == -1) {
    Log(LOG_ERR, "ERROR ( %s/%s ): connect() error: %s\n", config.name, config.type, strerror(errno));
    exit_gracefully(1);
  }

  return(s);
}

int Tee_parse_hostport(const char *s, struct sockaddr *addr, socklen_t *len, int dont_check_port)
{
  char *orig, *host, *port, zero_port[] = "]:0";
  struct addrinfo hints, *res;
  int herr;

  memset(&hints, '\0', sizeof(hints));

  if ((host = orig = strdup(s)) == NULL) {
    Log(LOG_ERR, "ERROR ( %s/%s ): Tee_parse_hostport() out of memory. Exiting ..\n", config.name, config.type);
    exit_gracefully(1);
  }

  trim_spaces(host);
  trim_spaces(orig);

  if ((port = strrchr(host, ':')) == NULL || *(++port) == '\0') {
    if (dont_check_port) {
      port = zero_port;
      ++port; ++port;
    }
    else return TRUE;
  }

  if (*host == '\0') return TRUE;

  *(port - 1) = '\0';

  /* Accept [host]:port for numeric IPv6 addresses;
     XXX: if dont_check_port is set to true, check for ']' will be inaccurate */
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

struct tee_receiver *Tee_hash_agent_crc32(void *pool, struct pkt_msg *msg)
{
  struct tee_receivers_pool *p = pool;
  struct tee_receiver *target = NULL;
  struct sockaddr *sa = (struct sockaddr *) &msg->agent;
  struct sockaddr_in *sa4 = (struct sockaddr_in *) &msg->agent;
  unsigned int bucket = 0;

  if (p) {
    if (sa->sa_family == AF_INET) {
      bucket = cache_crc32((const unsigned char*)&sa4->sin_addr.s_addr, 4);
      bucket %= p->num;
      target = &p->receivers[bucket];
    }
    else if (sa->sa_family == AF_INET6) {
      bucket = sa_hash(sa, p->num);
      target = &p->receivers[bucket];
    }
  }

  return target;
}

struct tee_receiver *Tee_hash_agent_balance(void *pool, struct pkt_msg *msg)
{
  struct tee_receivers_pool *p = pool;
  struct tee_receiver *target = NULL;
  struct sockaddr *sa = (struct sockaddr *) &msg->agent;
  struct sockaddr_in *sa4 = (struct sockaddr_in *) &msg->agent;

  if (p) {
    if (sa->sa_family == AF_INET) target = &p->receivers[sa4->sin_addr.s_addr & p->num];
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

void Tee_select_templates(unsigned char *pkt, int pkt_len, int nfv, unsigned char *tpl_pkt, int *tpl_pkt_len)
{
  struct struct_header_v9 *hdr_v9 = NULL;
  struct struct_header_ipfix *hdr_v10 = NULL;
  struct data_hdr_v9 *hdr_flowset = NULL;

  unsigned char *src_ptr = pkt, *dst_ptr = tpl_pkt;
  u_int16_t flowsetNo = 0, flowsetCount = 0, flowsetTplCount = 0;
  int tmp_len = 0, hdr_len = 0, term1 = 0, term2 = 0;

  if (!pkt || !pkt_len || !tpl_pkt || !tpl_pkt_len) return;
  if (nfv != 9 && nfv != 10) return;
  if (pkt_len > NETFLOW_MSG_SIZE) return;

  (*tpl_pkt_len) = 0;

  /* NetFlow v9 */
  if (nfv == 9) {
    hdr_v9 = (struct struct_header_v9 *) tpl_pkt;
    hdr_len = sizeof(struct struct_header_v9);
  }
  else if (nfv == 10) { 
    hdr_v10 = (struct struct_header_ipfix *) tpl_pkt;
    hdr_len = sizeof(struct struct_header_ipfix);
  }

  if (pkt_len < hdr_len) return;
    
  memcpy(dst_ptr, src_ptr, hdr_len);
  src_ptr += hdr_len; 
  dst_ptr += hdr_len;
  pkt_len -= hdr_len;
  tmp_len += hdr_len;

  if (nfv == 9) {
    flowsetNo = htons(hdr_v9->count);
    term1 = (flowsetNo + 1); /* trick to use > operator */
    term2 = flowsetCount;
  }
  else if (nfv == 10) {
    term1 = pkt_len;
    term2 = 0;
  }

  hdr_flowset = (struct data_hdr_v9 *) src_ptr;

  while (term1 > term2) {
    int fset_id = ntohs(hdr_flowset->flow_id);
    int fset_len = ntohs(hdr_flowset->flow_len);
    int fset_hdr_len = sizeof(struct data_hdr_v9);

    if (!fset_len || (fset_hdr_len + fset_len) > pkt_len) break;

    /* if template, copy over */
    if (((nfv == 9) && (fset_id == 0 || fset_id == 1)) ||
       ((nfv == 10) && (fset_id == 2 || fset_id == 3))) {
      memcpy(dst_ptr, src_ptr, fset_len);

      src_ptr += fset_len;
      dst_ptr += fset_len;

      pkt_len -= fset_len;
      tmp_len += fset_len;

      flowsetTplCount++;
    }
    /* if data, skip */
    else {
      src_ptr += fset_len;
      pkt_len -= fset_len;
    }

    if (nfv == 9) {
      flowsetCount++;
      term2 = flowsetCount;
    }
    else if (nfv == 10) {
      term1 = pkt_len;
    }

    hdr_flowset = (struct data_hdr_v9 *) src_ptr;
  }

  /* if we have at least one template, let's update the template packet */
  if (flowsetTplCount) {
    if (nfv == 9) {
      hdr_v9->count = htons(flowsetTplCount);
    }
    else if (nfv == 10) {
      hdr_v10->len = htons(tmp_len);
    }

    (*tpl_pkt_len) = tmp_len;
  }
}
