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

#define __IMT_PLUGIN_C

/* includes */
#include "pmacct.h"
#include "plugin_hooks.h"
#include "imt_plugin.h"
#include "net_aggr.h"
#include "ports_aggr.h"
#include "bgp/bgp.h"

/* Functions */
void imt_plugin(int pipe_fd, struct configuration *cfgptr, void *ptr) 
{
  int maxqsize = (MAX_QUERIES*sizeof(struct pkt_primitives))+sizeof(struct query_header)+2;
  struct sockaddr cAddr;
  struct pkt_data *data;
  struct ports_table pt;
  unsigned char srvbuf[maxqsize];
  unsigned char *srvbufptr;
  struct query_header *qh;
  unsigned char *pipebuf;
  char path[] = "/tmp/collect.pipe";
  short int go_to_clear = FALSE;
  u_int32_t request, sz;
  struct ch_status *status = ((struct channels_list_entry *)ptr)->status;
  int datasize = ((struct channels_list_entry *)ptr)->datasize;
  pid_t core_pid = ((struct channels_list_entry *)ptr)->core_pid;
  struct extra_primitives extras;
  unsigned char *rgptr;
  int pollagain = 0;
  u_int32_t seq = 0;
  int rg_err_count = 0;
  int amqp_timeout = INT_MAX, ret;
  struct pkt_bgp_primitives *pbgp, empty_pbgp;
  struct pkt_legacy_bgp_primitives *plbgp, empty_plbgp;
  struct pkt_nat_primitives *pnat, empty_pnat;
  struct pkt_mpls_primitives *pmpls, empty_pmpls;
  char *pcust, empty_pcust[] = "";
  struct pkt_vlen_hdr_primitives *pvlen, empty_pvlen;
  struct networks_file_data nfd;
  struct timeval select_timeout;
  struct primitives_ptrs prim_ptrs;
  struct plugins_list_entry *plugin_data = ((struct channels_list_entry *)ptr)->plugin;

  fd_set read_descs, bkp_read_descs; /* select() stuff */
  int select_fd, lock = FALSE;
  int cLen, num, sd, sd2;
  char *dataptr;

#ifdef WITH_RABBITMQ
  struct p_amqp_host *amqp_host = &((struct channels_list_entry *)ptr)->amqp_host;
#endif

  memcpy(&config, cfgptr, sizeof(struct configuration));
  memcpy(&extras, &((struct channels_list_entry *)ptr)->extras, sizeof(struct extra_primitives));
  recollect_pipe_memory(ptr);
  pm_setproctitle("%s [%s]", "IMT Plugin", config.name);

  if (config.proc_priority) {
    int ret;

    ret = setpriority(PRIO_PROCESS, 0, config.proc_priority);
    if (ret) Log(LOG_WARNING, "WARN ( %s/%s ): proc_priority failed (errno: %d)\n", config.name, config.type, errno);
    else Log(LOG_INFO, "INFO ( %s/%s ): proc_priority set to %d\n", config.name, config.type, getpriority(PRIO_PROCESS, 0));
  }

  if (config.pidfile) write_pid_file_plugin(config.pidfile, config.type, config.name);
  if (config.logfile) {
    fclose(config.logfile_fd);
    config.logfile_fd = open_output_file(config.logfile, "a", FALSE);
  }

  if (extras.off_pkt_vlen_hdr_primitives) {
    Log(LOG_ERR, "ERROR ( %s/%s ): variable-length primitives, ie. label, are not supported in IMT plugin. Exiting ..\n", config.name, config.type);
    exit_plugin(1);
  }

  reload_map = FALSE;
  status->wakeup = TRUE;

  /* a bunch of default definitions and post-checks */
  pipebuf = (unsigned char *) malloc(config.buffer_size);
  if (!pipebuf) {
    Log(LOG_ERR, "ERROR ( %s/%s ): malloc() failed (pipebuf). Exiting ..\n", config.name, config.type);
    exit_plugin(1);
  }

  if (config.pipe_amqp) {
    plugin_pipe_amqp_compile_check();
#ifdef WITH_RABBITMQ
    pipe_fd = plugin_pipe_amqp_connect_to_consume(amqp_host, plugin_data);
#endif
  }
  else setnonblocking(pipe_fd);

  memset(pipebuf, 0, config.buffer_size);
  no_more_space = FALSE;

  if (config.what_to_count & (COUNT_SUM_HOST|COUNT_SUM_NET))
    imt_insert_func = sum_host_insert;
  else if (config.what_to_count & COUNT_SUM_PORT) imt_insert_func = sum_port_insert;
  else if (config.what_to_count & COUNT_SUM_AS) imt_insert_func = sum_as_insert;
#if defined (HAVE_L2)
  else if (config.what_to_count & COUNT_SUM_MAC) imt_insert_func = sum_mac_insert;
#endif
  else imt_insert_func = insert_accounting_structure;

  memset(&nt, 0, sizeof(nt));
  memset(&nc, 0, sizeof(nc));
  memset(&pt, 0, sizeof(pt));

  load_networks(config.networks_file, &nt, &nc);
  set_net_funcs(&nt);

  if (config.ports_file) load_ports(config.ports_file, &pt);
  if (config.pkt_len_distrib_bins_str) load_pkt_len_distrib_bins();
  else {
    if (config.what_to_count_2 & COUNT_PKT_LEN_DISTRIB) {
      Log(LOG_ERR, "ERROR ( %s/%s ): 'aggregate' contains pkt_len_distrib but no 'pkt_len_distrib_bins' defined. Exiting.\n", config.name, config.type);
      exit_plugin(1); 
    }
  }

  if (!config.num_memory_pools) config.num_memory_pools = NUM_MEMORY_POOLS;
  if (!config.memory_pool_size) config.memory_pool_size = MEMORY_POOL_SIZE;  
  else {
    if (config.memory_pool_size < sizeof(struct acc)) {
      Log(LOG_WARNING, "WARN ( %s/%s ): enforcing memory pool's minimum size, %d bytes.\n", config.name, config.type, sizeof(struct acc));
      config.memory_pool_size = MEMORY_POOL_SIZE;
    }
  }

  if (!config.imt_plugin_path) config.imt_plugin_path = path; 
  if (!config.buckets) config.buckets = MAX_HOSTS;

  init_memory_pool_table(config);
  if (mpd == NULL) {
    Log(LOG_ERR, "ERROR ( %s/%s ): unable to allocate memory pools table\n", config.name, config.type);
    exit_plugin(1);
  }

  current_pool = request_memory_pool(config.buckets*sizeof(struct acc));
  if (current_pool == NULL) {
    Log(LOG_ERR, "ERROR ( %s/%s ): unable to allocate first memory pool, try with larger value.\n", config.name, config.type);
    exit_plugin(1);
  }
  a = current_pool->base_ptr;

  lru_elem_ptr = malloc(config.buckets*sizeof(struct acc *));
  if (lru_elem_ptr == NULL) {
    Log(LOG_ERR, "ERROR ( %s/%s ): unable to allocate LRU element pointers.\n", config.name, config.type);
    exit_plugin(1);
  }
  else memset(lru_elem_ptr, 0, config.buckets*sizeof(struct acc *));

  current_pool = request_memory_pool(config.memory_pool_size);
  if (current_pool == NULL) {
    Log(LOG_ERR, "ERROR ( %s/%s ): unable to allocate more memory pools, try with larger value.\n", config.name, config.type);
    exit_plugin(1);
  }

  signal(SIGHUP, reload); /* handles reopening of syslog channel */
  signal(SIGINT, exit_now); /* exit lane */
  signal(SIGUSR1, SIG_IGN);
  signal(SIGUSR2, reload_maps);
  signal(SIGPIPE, SIG_IGN);
  signal(SIGCHLD, SIG_IGN); 

  memset(&empty_pbgp, 0, sizeof(empty_pbgp));
  memset(&empty_plbgp, 0, sizeof(empty_plbgp));
  memset(&empty_pnat, 0, sizeof(empty_pnat));
  memset(&empty_pmpls, 0, sizeof(empty_pmpls));
  memset(&empty_pvlen, 0, sizeof(empty_pvlen));

  memset(&table_reset_stamp, 0, sizeof(table_reset_stamp));

  /* building a server for interrogations by clients */
  sd = build_query_server(config.imt_plugin_path);
  cLen = sizeof(cAddr);

  /* preparing for synchronous I/O multiplexing */
  select_fd = 0;

  FD_ZERO(&read_descs);
  FD_SET(sd, &read_descs);

  if (sd > select_fd) select_fd = sd;
  if (pipe_fd != ERR) {
    FD_SET(pipe_fd, &read_descs);
    if (pipe_fd > select_fd) select_fd = pipe_fd;
  }

  select_fd++;
  memcpy(&bkp_read_descs, &read_descs, sizeof(read_descs));

  qh = (struct query_header *) srvbuf;

  /* plugin main loop */
  for(;;) {
    select_again:
    select_timeout.tv_sec = MIN(DEFAULT_IMT_PLUGIN_SELECT_TIMEOUT, amqp_timeout);
    select_timeout.tv_usec = 0;

    memcpy(&read_descs, &bkp_read_descs, sizeof(bkp_read_descs));
    num = select(select_fd, &read_descs, NULL, NULL, &select_timeout);

    gettimeofday(&cycle_stamp, NULL);

#ifdef WITH_RABBITMQ
    if (config.pipe_amqp && pipe_fd == ERR) {
      if (select_timeout.tv_sec == amqp_timeout) {
        pipe_fd = plugin_pipe_amqp_connect_to_consume(amqp_host, plugin_data);

        if (pipe_fd != ERR) {
          FD_SET(pipe_fd, &bkp_read_descs);
          if (pipe_fd > select_fd) select_fd = pipe_fd;
          select_fd++;
	  amqp_timeout = LONGLONG_RETRY;
        }
	else amqp_timeout = P_broker_timers_get_retry_interval(&amqp_host->btimers);
      }
      else {
        amqp_timeout = ((P_broker_timers_get_last_fail(&amqp_host->btimers) + P_broker_timers_get_retry_interval(&amqp_host->btimers)) - cycle_stamp.tv_sec);
        assert(amqp_timeout >= 0);
      }
    }
#endif

    if (num <= 0) {
      if (getppid() == 1) {
	Log(LOG_ERR, "ERROR ( %s/%s ): Core process *seems* gone. Exiting.\n", config.name, config.type);
	exit_plugin(1);
      } 

      goto select_again;  
    }

    /* doing server tasks */
    if (FD_ISSET(sd, &read_descs)) {
      struct pollfd pfd;
      int ret;

      sd2 = accept(sd, &cAddr, &cLen);
      setblocking(sd2);
      srvbufptr = srvbuf;
      sz = maxqsize;

      pfd.fd = sd2;
      pfd.events = POLLIN;

      recv_again:
      ret = poll(&pfd, 1, 1000);
      if (ret == 0) {
        Log(LOG_WARNING, "WARN ( %s/%s ): Timed out while processing fragmented query.\n", config.name, config.type); 
        close(sd2);
	goto select_again;
      }
      else {
        num = recv(sd2, srvbufptr, sz, 0);
        if (srvbufptr[num-1] != '\x4') {
	  srvbufptr += num;
	  sz -= num;
	  goto recv_again; /* fragmented query */
        }
      }

      num = num+(maxqsize-sz);

      if (qh->num > MAX_QUERIES) {
	Log(LOG_DEBUG, "DEBUG ( %s/%s ): request discarded. Too much queries.\n", config.name, config.type);
	close(sd2);
	continue;
      }

      request = qh->type;
      if (request & WANT_RESET) request ^= WANT_RESET;
      if (request & WANT_LOCK_OP) {
	lock = TRUE;
	request ^= WANT_LOCK_OP;
      }

      /* 
	 - if explicitely required, we do not fork: query obtains exclusive
	   control - lock - over the memory table; 
	 - operations that may cause inconsistencies (full erasure, counter
	   reset for individual entries, etc.) are entitled of an exclusive
	   lock.
	 - if query is matter of just a single short-lived walk through the
	   table, we avoid fork(): the plugin will serve the request;
         - in all other cases, we fork; the newly created child will serve
	   queries asyncronously.
      */

      if (request & WANT_ERASE) {
	request ^= WANT_ERASE;
	if (request) {
	  if (num > 0) process_query_data(sd2, srvbuf, num, &extras, datasize, FALSE);
	  else Log(LOG_DEBUG, "DEBUG ( %s/%s ): %d incoming bytes. Errno: %d\n", config.name, config.type, num, errno);
	}
	Log(LOG_DEBUG, "DEBUG ( %s/%s ): Closing connection with client ...\n", config.name, config.type);
	go_to_clear = TRUE;  
      }
      else if (((request == WANT_COUNTER) || (request == WANT_MATCH)) &&
	(qh->num == 1) && (qh->what_to_count == config.what_to_count)) {
	if (num > 0) process_query_data(sd2, srvbuf, num, &extras, datasize, FALSE);
        else Log(LOG_DEBUG, "DEBUG ( %s/%s ): %d incoming bytes. ERRNO: %d\n", config.name, config.type, num, errno);
        Log(LOG_DEBUG, "DEBUG ( %s/%s ): Closing connection with client ...\n", config.name, config.type);
      } 
      else if (request == WANT_CLASS_TABLE) {
	if (num > 0) process_query_data(sd2, srvbuf, num, &extras, datasize, FALSE);
        else Log(LOG_DEBUG, "DEBUG ( %s/%s ): %d incoming bytes. ERRNO: %d\n", config.name, config.type, num, errno);
        Log(LOG_DEBUG, "DEBUG ( %s/%s ): Closing connection with client ...\n", config.name, config.type);
      }
      else if (request == WANT_PKT_LEN_DISTRIB_TABLE) {
        if (num > 0) process_query_data(sd2, srvbuf, num, &extras, datasize, FALSE);
        else Log(LOG_DEBUG, "DEBUG ( %s/%s ): %d incoming bytes. ERRNO: %d\n", config.name, config.type, num, errno);
        Log(LOG_DEBUG, "DEBUG ( %s/%s ): Closing connection with client ...\n", config.name, config.type);
      }
      else {
	if (lock) {
	  if (num > 0) process_query_data(sd2, srvbuf, num, &extras, datasize, FALSE);
          else Log(LOG_DEBUG, "DEBUG ( %s/%s ): %d incoming bytes. Errno: %d\n", config.name, config.type, num, errno);
          Log(LOG_DEBUG, "DEBUG ( %s/%s ): Closing connection with client ...\n", config.name, config.type);
	}
	else { 
          switch (fork()) {
	  case -1: /* Something went wrong */
	    Log(LOG_WARNING, "WARN ( %s/%s ): Unable to serve client query: %s\n", config.name, config.type, strerror(errno));
	    break;
          case 0: /* Child */
            close(sd);
	    pm_setproctitle("%s [%s]", "IMT Plugin -- serving client", config.name);
            if (num > 0) process_query_data(sd2, srvbuf, num, &extras, datasize, TRUE);
	    else Log(LOG_DEBUG, "DEBUG ( %s/%s ): %d incoming bytes. Errno: %d\n", config.name, config.type, num, errno);
            Log(LOG_DEBUG, "DEBUG ( %s/%s ): Closing connection with client ...\n", config.name, config.type);
            close(sd2);
            exit(0);
          default: /* Parent */
            break;
          } 
	}
      }
      close(sd2);
    }

    /* clearing stats if requested */
    if (go_to_clear) {
      /* When using extended BGP features we need to
	 free() up memory allocations before erasing */ 
      /* XXX: given the current use of empty_* vars we have always to
         free_extra_allocs() in order to prevent memory leaks */
      /*
      if (extras.off_pkt_bgp_primitives || extras.off_pkt_nat_primitives ||
	  extras.off_pkt_mpls_primitives || extras.off_custom_primitives)
      */
	free_extra_allocs(); 
      clear_memory_pool_table();
      current_pool = request_memory_pool(config.buckets*sizeof(struct acc));
      if (current_pool == NULL) {
        Log(LOG_ERR, "ERROR ( %s/%s ): Cannot allocate my first memory pool, try with larger value.\n", config.name, config.type);
        exit_plugin(1);
      }
      a = current_pool->base_ptr;

      current_pool = request_memory_pool(config.memory_pool_size);
      if (current_pool == NULL) {
        Log(LOG_ERR, "ERROR ( %s/%s ): Cannot allocate more memory pools, try with larger value.\n", config.name, config.type);
        exit_plugin(1);
      }
      go_to_clear = FALSE;
      no_more_space = FALSE;
      memcpy(&table_reset_stamp, &cycle_stamp, sizeof(struct timeval));
    }

    if (FD_ISSET(pipe_fd, &read_descs)) {
      if (!config.pipe_amqp) {
        if (!pollagain) {
          seq++;
          seq %= MAX_SEQNUM;
        }

        pollagain = FALSE;
        if ((num = read(pipe_fd, &rgptr, sizeof(rgptr))) == 0)
          exit_plugin(1); /* we exit silently; something happened at the write end */

        if (num < 0) {
          pollagain = TRUE;
          goto select_again;
        }

        memcpy(pipebuf, rgptr, config.buffer_size);
        status->last_plugin_off = (rgptr - (unsigned char *)((struct channels_list_entry *)ptr)->rg.base);
        if (((struct ch_buf_hdr *)pipebuf)->seq != seq) {
          rg_err_count++;
          if (config.debug || (rg_err_count > MAX_RG_COUNT_ERR)) {
	    Log(LOG_WARNING, "WARN ( %s/%s ): Missing data detected (plugin_buffer_size=%llu plugin_pipe_size=%llu).\n",
		config.name, config.type, config.buffer_size, config.pipe_size);
	    Log(LOG_WARNING, "WARN ( %s/%s ): Increase values or look for plugin_buffer_size, plugin_pipe_size in CONFIG-KEYS document.\n\n",
		config.name, config.type);
	  }

          seq = ((struct ch_buf_hdr *)pipebuf)->seq;
	}
      }
#ifdef WITH_RABBITMQ
      else {
        ret = p_amqp_consume_binary(amqp_host, pipebuf, config.buffer_size);
        if (!ret) {
          seq = ((struct ch_buf_hdr *)pipebuf)->seq;
	  amqp_timeout = LONGLONG_RETRY;
	  num = TRUE;
	}
	else {
          if (pipe_fd != ERR) {
            FD_CLR(pipe_fd, &bkp_read_descs);
	    pipe_fd = ERR;
          }
	  amqp_timeout = P_broker_timers_get_retry_interval(&amqp_host->btimers);
	}
      }
#endif

      if (num > 0) {
	data = (struct pkt_data *) (pipebuf+sizeof(struct ch_buf_hdr));

	if (config.debug_internal_msg) 
	  Log(LOG_DEBUG, "DEBUG ( %s/%s ): buffer received cpid=%u len=%llu seq=%u num_entries=%u\n",
		config.name, config.type, core_pid, ((struct ch_buf_hdr *)pipebuf)->len,
		seq, ((struct ch_buf_hdr *)pipebuf)->num);

	if (!config.pipe_check_core_pid || ((struct ch_buf_hdr *)pipebuf)->core_pid == core_pid) {
	while (((struct ch_buf_hdr *)pipebuf)->num > 0) {

          if (extras.off_pkt_bgp_primitives)
	    pbgp = (struct pkt_bgp_primitives *) ((u_char *)data + extras.off_pkt_bgp_primitives);
	  else pbgp = &empty_pbgp;
          if (extras.off_pkt_lbgp_primitives)
            plbgp = (struct pkt_legacy_bgp_primitives *) ((u_char *)data + extras.off_pkt_lbgp_primitives);
          else plbgp = &empty_plbgp;
          if (extras.off_pkt_nat_primitives) 
            pnat = (struct pkt_nat_primitives *) ((u_char *)data + extras.off_pkt_nat_primitives);
          else pnat = &empty_pnat;
          if (extras.off_pkt_mpls_primitives) 
            pmpls = (struct pkt_mpls_primitives *) ((u_char *)data + extras.off_pkt_mpls_primitives);
          else pmpls = &empty_pmpls;
          if (extras.off_custom_primitives)
	    pcust = ((u_char *)data + extras.off_custom_primitives);
          else pcust = empty_pcust;
	  if (extras.off_pkt_vlen_hdr_primitives)
	    pvlen = (struct pkt_vlen_hdr_primitives *) ((u_char *)data + extras.off_pkt_vlen_hdr_primitives); 
	  else pvlen = &empty_pvlen;

	  for (num = 0; net_funcs[num]; num++)
	    (*net_funcs[num])(&nt, &nc, &data->primitives, pbgp, &nfd);

	  if (config.ports_file) {
	    if (!pt.table[data->primitives.src_port]) data->primitives.src_port = 0;
	    if (!pt.table[data->primitives.dst_port]) data->primitives.dst_port = 0;
	  }

	  if (config.pkt_len_distrib_bins_str &&
	      config.what_to_count_2 & COUNT_PKT_LEN_DISTRIB)
	    evaluate_pkt_len_distrib(data);

	  prim_ptrs.data = data; 
	  prim_ptrs.pbgp = pbgp; 
	  prim_ptrs.plbgp = plbgp; 
	  prim_ptrs.pnat = pnat;
	  prim_ptrs.pmpls = pmpls;
	  prim_ptrs.pcust = pcust;
	  prim_ptrs.pvlen = pvlen;
	  
          (*imt_insert_func)(&prim_ptrs);

	  ((struct ch_buf_hdr *)pipebuf)->num--;
	  if (((struct ch_buf_hdr *)pipebuf)->num) {
            dataptr = (unsigned char *) data;
            dataptr += datasize;
            data = (struct pkt_data *) dataptr;
	  }
        }
	}
      }
    } 

    if (reload_map) {
      load_networks(config.networks_file, &nt, &nc);
      load_ports(config.ports_file, &pt);
      reload_map = FALSE;
    }
  }
}

void exit_now(int signum)
{
  if (config.imt_plugin_path) unlink(config.imt_plugin_path);
  exit_plugin(0);
}

void sum_host_insert(struct primitives_ptrs *prim_ptrs)
{
  struct pkt_data *data = prim_ptrs->data;
  struct host_addr tmp;

  memcpy(&tmp, &data->primitives.dst_ip, HostAddrSz);
  memset(&data->primitives.dst_ip, 0, HostAddrSz);
  insert_accounting_structure(prim_ptrs);
  memcpy(&data->primitives.src_ip, &tmp, HostAddrSz);
  insert_accounting_structure(prim_ptrs);
}

void sum_port_insert(struct primitives_ptrs *prim_ptrs)
{
  struct pkt_data *data = prim_ptrs->data;
  u_int16_t port;

  port = data->primitives.dst_port;
  data->primitives.dst_port = 0;
  insert_accounting_structure(prim_ptrs);
  data->primitives.src_port = port;
  insert_accounting_structure(prim_ptrs);
}

void sum_as_insert(struct primitives_ptrs *prim_ptrs)
{
  struct pkt_data *data = prim_ptrs->data;
  as_t asn;

  asn = data->primitives.dst_as;
  data->primitives.dst_as = 0;
  insert_accounting_structure(prim_ptrs);
  data->primitives.src_as = asn;
  insert_accounting_structure(prim_ptrs);
}

#if defined (HAVE_L2)
void sum_mac_insert(struct primitives_ptrs *prim_ptrs)
{
  struct pkt_data *data = prim_ptrs->data;
  u_char macaddr[ETH_ADDR_LEN];

  memcpy(macaddr, &data->primitives.eth_dhost, ETH_ADDR_LEN);
  memset(data->primitives.eth_dhost, 0, ETH_ADDR_LEN);
  insert_accounting_structure(prim_ptrs);
  memcpy(&data->primitives.eth_shost, macaddr, ETH_ADDR_LEN);
  insert_accounting_structure(prim_ptrs);
}
#endif

void free_extra_allocs()
{
  struct acc *acc_elem = NULL;
  unsigned char *elem;
  int following_chain = FALSE;
  unsigned int idx;

  elem = (unsigned char *) a;

  for (idx = 0; idx < config.buckets; idx++) {
    if (!following_chain) acc_elem = (struct acc *) elem;
    if (acc_elem->pbgp) {
      free(acc_elem->pbgp);
      acc_elem->pbgp = NULL;
    }
    if (acc_elem->clbgp) free_cache_legacy_bgp_primitives(&acc_elem->clbgp);
    if (acc_elem->pnat) {
      free(acc_elem->pnat);
      acc_elem->pnat = NULL;
    }
    if (acc_elem->pmpls) {
      free(acc_elem->pmpls);
      acc_elem->pmpls = NULL;
    }
    if (acc_elem->pcust) {
      free(acc_elem->pcust);
      acc_elem->pcust = NULL;
    }
    if (acc_elem->pvlen) {
      free(acc_elem->pvlen);
      acc_elem->pvlen= NULL;
    }
    if (acc_elem->next) {
      acc_elem = acc_elem->next;
      following_chain++;
      idx--;
    }
    else {
      elem += sizeof(struct acc);
      following_chain = FALSE;
    }
  }
}
