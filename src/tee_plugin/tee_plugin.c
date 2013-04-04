/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2013 by Paolo Lucente
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

#include "../pmacct.h"
#include "tee_plugin.h"
#include "pmacct-data.h"
#include "plugin_hooks.h"

void tee_plugin(int pipe_fd, struct configuration *cfgptr, void *ptr)
{
  struct pkt_msg *msg;
  unsigned char *pipebuf;
  struct pollfd pfd;
  int timeout, err;
  int ret, num, fd, pool_idx, recv_idx;
  struct ring *rg = &((struct channels_list_entry *)ptr)->rg;
  struct ch_status *status = ((struct channels_list_entry *)ptr)->status;
  u_int32_t bufsz = ((struct channels_list_entry *)ptr)->bufsize;
  char *dataptr, dest_addr[256], dest_serv[256];
  struct tee_receiver *target = NULL;
  struct plugin_requests req;

  unsigned char *rgptr;
  int pollagain = TRUE;
  u_int32_t seq = 1, rg_err_count = 0;

  memcpy(&config, cfgptr, sizeof(struct configuration));
  recollect_pipe_memory(ptr);
  pm_setproctitle("%s [%s]", "Tee Plugin", config.name);
  if (config.pidfile) write_pid_file_plugin(config.pidfile, config.type, config.name);

  /* signal handling */
  signal(SIGINT, Tee_exit_now);
  signal(SIGUSR1, SIG_IGN);
  signal(SIGUSR2, reload_maps); /* sets to true the reload_maps flag */
  signal(SIGPIPE, SIG_IGN);
#if !defined FBSD4
  signal(SIGCHLD, SIG_IGN);
#else
  signal(SIGCHLD, ignore_falling_child);
#endif

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

  for (pool_idx = 0; pool_idx < MAX_TEE_POOLS; pool_idx++) { 
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
  timeout = config.sql_refresh_time*1000;

  pipebuf = (unsigned char *) Malloc(config.buffer_size);

  pfd.fd = pipe_fd;
  pfd.events = POLLIN;
  setnonblocking(pipe_fd);

  memset(pipebuf, 0, config.buffer_size);
  err_cant_bridge_af = 0;

  /* Arrange send socket */
  Tee_init_socks();

  /* plugin main loop */
  for (;;) {
    poll_again:
    status->wakeup = TRUE;
    ret = poll(&pfd, 1, timeout);
    if (ret < 0) goto poll_again;

    if (reload_map) {
      int recvs_allocated = FALSE;

      Tee_destroy_recvs();
      load_id_file(MAP_TEE_RECVS, config.tee_receivers, NULL, &req, &recvs_allocated);

      Tee_init_socks();
      reload_map = FALSE;
    }

    switch (ret) {
    case 0: /* timeout */
      /* reserved for future since we don't currently cache/batch/etc */
      break;
    default: /* we received data */
      read_data:
      if (!pollagain) {
        seq++;
        seq %= MAX_SEQNUM;
        if (seq == 0) rg_err_count = FALSE;
      }
      else {
        if ((ret = read(pipe_fd, &rgptr, sizeof(rgptr))) == 0)
          exit_plugin(1); /* we exit silently; something happened at the write end */
      }

      if (((struct ch_buf_hdr *)rg->ptr)->seq != seq) {
        if (!pollagain) {
          pollagain = TRUE;
          goto poll_again;
        }
        else {
          rg_err_count++;
          if (config.debug || (rg_err_count > MAX_RG_COUNT_ERR)) {
            Log(LOG_ERR, "ERROR ( %s/%s ): We are missing data.\n", config.name, config.type);
            Log(LOG_ERR, "If you see this message once in a while, discard it. Otherwise some solutions follow:\n");
            Log(LOG_ERR, "- increase shared memory size, 'plugin_pipe_size'; now: '%u'.\n", config.pipe_size);
            Log(LOG_ERR, "- increase buffer size, 'plugin_buffer_size'; now: '%u'.\n", config.buffer_size);
            Log(LOG_ERR, "- increase system maximum socket size.\n\n");
          }
          seq = ((struct ch_buf_hdr *)rg->ptr)->seq;
        }
      }

      pollagain = FALSE;
      memcpy(pipebuf, rg->ptr, bufsz);
      if ((rg->ptr+bufsz) >= rg->end) rg->ptr = rg->base;
      else rg->ptr += bufsz;

      msg = (struct pkt_msg *) (pipebuf+sizeof(struct ch_buf_hdr));

      while (((struct ch_buf_hdr *)pipebuf)->num) {
	for (pool_idx = 0; pool_idx < receivers.num; pool_idx++) {
	  if (!evaluate_tags(&receivers.pools[pool_idx].tag_filter, msg->id)) {
	    if (!receivers.pools[pool_idx].balance.func) {
	      for (recv_idx = 0; recv_idx < receivers.pools[pool_idx].num; recv_idx++) {
	        target = &receivers.pools[pool_idx].receivers[recv_idx];
	        Tee_send(msg, &target->dest, target->fd);
	      }
	    }
	    else {
	      target = receivers.pools[pool_idx].balance.func(&receivers.pools[pool_idx], msg);
	      Tee_send(msg, &target->dest, target->fd);
	    }
	  }
	}

        ((struct ch_buf_hdr *)pipebuf)->num--;
        if (((struct ch_buf_hdr *)pipebuf)->num) {
	  dataptr = (unsigned char *) msg;
          dataptr += PmsgSz;
	  msg = (struct pkt_msg *) dataptr;
	}
      }
      goto read_data;
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
    struct host_addr a;
    u_char agent_addr[50];
    u_int16_t agent_port;

    sa_to_addr((struct sockaddr *)msg, &a, &agent_port);
    addr_to_str(agent_addr, &a);

    sa_to_addr((struct sockaddr *)target, &r, &recv_port);
    addr_to_str(recv_addr, &r);

    Log(LOG_DEBUG, "DEBUG ( %s/%s ): Sending NetFlow packet from [%s:%u] seqno [%u] to [%s]\n",
                        config.name, config.type, agent_addr, agent_port, msg->seqno, recv_addr);
  }

  if (!config.tee_transparent) {
    if (send(fd, msg->payload, msg->len, 0) == -1) {
      sa_to_addr((struct sockaddr *)target, &r, &recv_port);
      addr_to_str(recv_addr, &r);

      Log(LOG_ERR, "ERROR ( %s/%s ): send() to [%s] failed (%s)\n", config.name, config.type, recv_addr, strerror(errno));
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
        i4h->ip_tos = 0;
        i4h->ip_len = htons(IP4HdrSz+UDPHdrSz+msg->len);
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
	sa_to_addr((struct sockaddr *)target, &r, &recv_port);
	addr_to_str(recv_addr, &r);

        Log(LOG_ERR, "ERROR ( %s/%s ): raw send() to [%s] failed (%s)\n", config.name, config.type, recv_addr, strerror(errno));
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
  int pool_idx, recv_idx, err;
  char dest_addr[256], dest_serv[256];

  for (pool_idx = 0; pool_idx < receivers.num; pool_idx++) {
    for (recv_idx = 0; recv_idx < receivers.pools[pool_idx].num; recv_idx++) {
      target = &receivers.pools[pool_idx].receivers[recv_idx];

      if (target->dest.sa_family != 0) {
        if ((err = getnameinfo((struct sockaddr *) &target->dest,
            target->dest_len, dest_addr, sizeof(dest_addr),
            dest_serv, sizeof(dest_serv), NI_NUMERICHOST)) == -1) {
          Log(LOG_ERR, "ERROR ( %s/%s ): getnameinfo: %d\n", config.name, config.type, err);
          exit_plugin(1);
        }
      }

      target->fd = Tee_prepare_sock(&target->dest, target->dest_len);

      if (config.debug) {
        u_char recv_addr[50];

        addr_to_str(recv_addr, &target->dest);
        Log(LOG_DEBUG, "DEBUG ( %s/%s ): pool ID: %u :: receiver: %s :: fd: %d.\n",
                config.name, config.type, receivers.pools[pool_idx].id, recv_addr, target->fd);
      }
    }
  }
}

int Tee_prepare_sock(struct sockaddr *addr, socklen_t len)
{
  int s, ret = 0;

  if (!config.tee_transparent) {
    struct host_addr source_ip;
    struct sockaddr ssource_ip;

    if (config.nfprobe_source_ip) {
      ret = str_to_addr(config.nfprobe_source_ip, &source_ip);
      addr_to_sa(&ssource_ip, &source_ip, 0);
    }

    if ((s = socket(addr->sa_family, SOCK_DGRAM, 0)) == -1) {
      Log(LOG_ERR, "ERROR ( %s/%s ): socket() error: %s\n", config.name, config.type, strerror(errno));
      exit_plugin(1);
    }

    if (ret && bind(s, (struct sockaddr *) &ssource_ip, sizeof(ssource_ip)) == -1)
      Log(LOG_ERR, "ERROR ( %s/%s ): bind() error: %s\n", config.name, config.type, strerror(errno));
  }
  else {
    if ((s = socket(addr->sa_family, SOCK_RAW, IPPROTO_RAW)) == -1) {
      Log(LOG_ERR, "ERROR ( %s/%s ): socket() error: %s\n", config.name, config.type, strerror(errno));
      exit_plugin(1);
    }
  }

  /* XXX: SNDBUF tuning? */

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
  }

  memset(&hints, '\0', sizeof(hints));
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

  if (p) target = &p->receivers[msg->id % p->num];

  return target;
}
