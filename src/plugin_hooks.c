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
    along with this program; if no, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#define __PLUGIN_HOOKS_C

/* includes */
#include "pmacct.h"
#include "pmacct-data.h"
#include "thread_pool.h"
#include "plugin_hooks.h"
#include "pkt_handlers.h"

/* functions */

/* load_plugins() starts plugin processes; creates pipes
   and handles them inserting in channels_list structure */

/* no AMQP: when not using map_shared, 'pipe_size' is the size of the pipe
   created with socketpair(); when map_shared is enabled, it refers to the
   size of the shared memory area */
void load_plugins(struct plugin_requests *req)
{
  u_int64_t buf_pipe_ratio_sz = 0, pipe_idx = 0;
  int snd_buflen = 0, rcv_buflen = 0, socklen = 0, target_buflen = 0, ret;

  int nfprobe_id = 0, min_sz = 0;
  struct plugins_list_entry *list = plugins_list;
  int l = sizeof(list->cfg.pipe_size), offset = 0;
  struct channels_list_entry *chptr = NULL;

  init_random_seed(); 
  init_pipe_channels();

  while (list) {
    if ((*list->type.func)) {
      if (list->cfg.data_type & (PIPE_TYPE_METADATA|PIPE_TYPE_PAYLOAD|PIPE_TYPE_MSG));
      else {
	Log(LOG_ERR, "ERROR ( %s/%s ): Data type not supported: %d\n", list->name, list->type.string, list->cfg.data_type);
	exit(1);
      }

      min_sz = ChBufHdrSz;
      if (list->cfg.data_type & PIPE_TYPE_METADATA) min_sz += PdataSz; 
      if (list->cfg.data_type & PIPE_TYPE_PAYLOAD) {
	if (list->cfg.acct_type == ACCT_PM && list->cfg.snaplen) min_sz += (PpayloadSz+list->cfg.snaplen); 
	else min_sz += (PpayloadSz+DEFAULT_PLOAD_SIZE); 
      }
      if (list->cfg.data_type & PIPE_TYPE_EXTRAS) min_sz += PextrasSz; 
      if (list->cfg.data_type & PIPE_TYPE_MSG) min_sz += PmsgSz; 
      if (list->cfg.data_type & PIPE_TYPE_BGP) min_sz += sizeof(struct pkt_bgp_primitives);
      if (list->cfg.data_type & PIPE_TYPE_NAT) min_sz += sizeof(struct pkt_nat_primitives);
      if (list->cfg.data_type & PIPE_TYPE_MPLS) min_sz += sizeof(struct pkt_mpls_primitives);
      if (list->cfg.cpptrs.len) min_sz += list->cfg.cpptrs.len;
      if (list->cfg.data_type & PIPE_TYPE_VLEN) min_sz += sizeof(struct pkt_vlen_hdr_primitives);

      /* If nothing is supplied, let's hint some working default values */
      if (!list->cfg.pipe_size || !list->cfg.buffer_size) {
        if (!list->cfg.pipe_size) list->cfg.pipe_size = 4096000; /* 4Mb */
        if (!list->cfg.buffer_size) {
	  if (list->cfg.pcap_savefile) list->cfg.buffer_size = 10240; /* 10Kb */
	  else list->cfg.buffer_size = MIN(min_sz, 10240);
	}
      }

      /* some validations */
      if (list->cfg.pipe_size < min_sz) list->cfg.pipe_size = min_sz;
      if (list->cfg.buffer_size < min_sz) list->cfg.buffer_size = min_sz;
      if (list->cfg.buffer_size > list->cfg.pipe_size) list->cfg.buffer_size = list->cfg.pipe_size;

      /*  if required let's align plugin_buffer_size to  4 bytes boundary */
#if NEED_ALIGN
      while (list->cfg.buffer_size % 4 != 0) list->cfg.buffer_size--;
#endif

      if (!list->cfg.pipe_amqp) {
        /* creating communication channel */
        socketpair(AF_UNIX, SOCK_DGRAM, 0, list->pipe);

        /* checking SO_RCVBUF and SO_SNDBUF values; if different we take the smaller one */
        getsockopt(list->pipe[0], SOL_SOCKET, SO_RCVBUF, &rcv_buflen, &l);
        getsockopt(list->pipe[1], SOL_SOCKET, SO_SNDBUF, &snd_buflen, &l);
        socklen = (rcv_buflen < snd_buflen) ? rcv_buflen : snd_buflen;

        buf_pipe_ratio_sz = (list->cfg.pipe_size/list->cfg.buffer_size)*sizeof(char *);
        if (buf_pipe_ratio_sz > INT_MAX) {
	  Log(LOG_ERR, "ERROR ( %s/%s ): Current plugin_buffer_size elems per plugin_pipe_size: %d. Max: %d.\nExiting.\n",
		list->name, list->type.string, (list->cfg.pipe_size/list->cfg.buffer_size), (INT_MAX/sizeof(char *)));
          exit_all(1);
        }
        else target_buflen = buf_pipe_ratio_sz;

        if (target_buflen > socklen) {
	  Setsocksize(list->pipe[0], SOL_SOCKET, SO_RCVBUF, &target_buflen, l);
	  Setsocksize(list->pipe[1], SOL_SOCKET, SO_SNDBUF, &target_buflen, l);
        }

        getsockopt(list->pipe[0], SOL_SOCKET, SO_RCVBUF, &rcv_buflen, &l);
        getsockopt(list->pipe[1], SOL_SOCKET, SO_SNDBUF, &snd_buflen, &l);
        if (rcv_buflen < snd_buflen) snd_buflen = rcv_buflen;

        if (snd_buflen < socklen) {
	  Setsocksize(list->pipe[0], SOL_SOCKET, SO_RCVBUF, &socklen, l);
	  Setsocksize(list->pipe[1], SOL_SOCKET, SO_SNDBUF, &socklen, l);

          getsockopt(list->pipe[0], SOL_SOCKET, SO_RCVBUF, &rcv_buflen, &l);
          getsockopt(list->pipe[1], SOL_SOCKET, SO_SNDBUF, &snd_buflen, &l);
          if (rcv_buflen < snd_buflen) snd_buflen = rcv_buflen;
        }

        if (list->cfg.debug || (list->cfg.pipe_size > WARNING_PIPE_SIZE)) {
	  Log(LOG_INFO, "INFO ( %s/%s ): plugin_pipe_size=%llu bytes plugin_buffer_size=%llu bytes\n", 
		list->name, list->type.string, list->cfg.pipe_size, list->cfg.buffer_size);
	  if (target_buflen <= snd_buflen) 
            Log(LOG_INFO, "INFO ( %s/%s ): ctrl channel: obtained=%d bytes target=%d bytes\n",
		list->name, list->type.string, snd_buflen, target_buflen);
	  else
	    /* This should return an error and exit but we fallback to a
	       warning in order to be backward compatible */
            Log(LOG_WARNING, "WARN ( %s/%s ): ctrl channel: obtained=%d bytes target=%d bytes\n",
		list->name, list->type.string, snd_buflen, target_buflen);
        }
      }
      else {
	pipe_idx++;
        list->pipe[0] = list->pipe[1] = pipe_idx;
      }

      list->cfg.name = list->name;
      list->cfg.type = list->type.string;
      list->cfg.type_id = list->type.id;
      chptr = insert_pipe_channel(list->type.id, &list->cfg, list->pipe[1]);
      if (!chptr) {
	Log(LOG_ERR, "ERROR ( %s/%s ): Unable to setup a new Core Process <-> Plugin channel.\nExiting.\n", list->name, list->type.string);
	exit_all(1);
      }
      else chptr->plugin = list;

      /* sets new value to be assigned to 'wakeup'; 'TRUE' disables on-request wakeup */ 
      if (list->type.id == PLUGIN_ID_MEMORY) chptr->request = TRUE; 

      /* sets fixed/vlen offsets and cleaner routine; XXX: we should refine the cleaner
	 part: 1) ie. extras assumes it's automagically piled with metadata; 2) what if
	 multiple vlen components are stacked up? */
      if (list->cfg.data_type & PIPE_TYPE_METADATA) {
	chptr->clean_func = pkt_data_clean;
	offset = sizeof(struct pkt_data);
      }
      if (list->cfg.data_type & PIPE_TYPE_PAYLOAD) chptr->clean_func = pkt_payload_clean;
      if (list->cfg.data_type & PIPE_TYPE_EXTRAS) {
	chptr->extras.off_pkt_extras = offset;
	offset += sizeof(struct pkt_extras);
      }
      if (list->cfg.data_type & PIPE_TYPE_MSG) chptr->clean_func = pkt_msg_clean;
      if (list->cfg.data_type & PIPE_TYPE_BGP) {
        chptr->extras.off_pkt_bgp_primitives = offset;
	offset += sizeof(struct pkt_bgp_primitives);
      }
      else chptr->extras.off_pkt_bgp_primitives = 0; 
      if (list->cfg.data_type & PIPE_TYPE_NAT) {
        chptr->extras.off_pkt_nat_primitives = offset;
        offset += sizeof(struct pkt_nat_primitives);
      }
      else chptr->extras.off_pkt_nat_primitives = 0; 
      if (list->cfg.data_type & PIPE_TYPE_MPLS) {
        chptr->extras.off_pkt_mpls_primitives = offset;
        offset += sizeof(struct pkt_mpls_primitives);
      }
      else chptr->extras.off_pkt_mpls_primitives = 0;
      if (list->cfg.cpptrs.len) {
	chptr->extras.off_custom_primitives = offset;
	offset += list->cfg.cpptrs.len;
      }
      /* PIPE_TYPE_VLEN at the end of the stack so to not make
	 vlen other structures (although possible it would not
	 make much sense) */
      if (list->cfg.data_type & PIPE_TYPE_VLEN) {
        chptr->extras.off_pkt_vlen_hdr_primitives = offset;
        offset += sizeof(struct pkt_vlen_hdr_primitives);
      }
      else chptr->extras.off_pkt_vlen_hdr_primitives = 0;
      /* any further offset beyond this point must be set to
         PM_VARIABLE_LENGTH so to indicate plugins to resolve
         value at runtime. */

      chptr->datasize = min_sz-ChBufHdrSz;

      /* sets nfprobe ID */
      if (list->type.id == PLUGIN_ID_NFPROBE) {
	list->cfg.nfprobe_id = nfprobe_id;
	nfprobe_id++;
      }
      
      switch (list->pid = fork()) {  
      case -1: /* Something went wrong */
	Log(LOG_WARNING, "WARN ( %s/%s ): Unable to initialize plugin: %s\n", list->name, list->type.string, strerror(errno));
	delete_pipe_channel(list->pipe[1]);
	break;
      case 0: /* Child */
	/* SIGCHLD handling issue: SysV avoids zombies by ignoring SIGCHLD; to emulate
	   such semantics on BSD systems, we need an handler like handle_falling_child() */
#if defined (IRIX) || (SOLARIS)
	signal(SIGCHLD, SIG_IGN);
#else
	signal(SIGCHLD, ignore_falling_child);
#endif

#if defined HAVE_MALLOPT
        mallopt(M_CHECK_ACTION, 0);
#endif

	close(config.sock);
	close(config.bgp_sock);
	if (!list->cfg.pipe_amqp) close(list->pipe[1]);
	(*list->type.func)(list->pipe[0], &list->cfg, chptr);
	exit(0);
      default: /* Parent */
	if (!list->cfg.pipe_amqp) {
	  close(list->pipe[0]);
	  setnonblocking(list->pipe[1]);
	}
	break;
      }

      /* some residual check */
      if (chptr && list->cfg.a_filter) req->bpf_filter = TRUE;
    }
    list = list->next;
  }

  sort_pipe_channels();

  /* define pre_tag_map(s) now so that they don't finish unnecessarily in plugin memory space */
  {
    int ptm_index = 0, ptm_global = FALSE;
    char *ptm_ptr = NULL;

    list = plugins_list;

    while (list) {
      if (list->cfg.pre_tag_map) {
        if (!ptm_index) {
          ptm_ptr = list->cfg.pre_tag_map;
          ptm_global = TRUE;
        }
        else {
          if (!ptm_ptr || strcmp(ptm_ptr, list->cfg.pre_tag_map))
            ptm_global = FALSE;
        }

        load_pre_tag_map(config.acct_type, list->cfg.pre_tag_map, &list->cfg.ptm, req, &list->cfg.ptm_alloc,
                         list->cfg.maps_entries, list->cfg.maps_row_len);
      }

      list = list->next;
      ptm_index++;
    }

    /* enforcing global flag */
    list = plugins_list;

    while (list) {
      list->cfg.ptm_global = ptm_global;
      list = list->next;
    }
  }

  /* AMQP handling, if required */
#ifdef WITH_RABBITMQ
  {
    int ret, index, index2;

    for (index = 0; channels_list[index].aggregation || channels_list[index].aggregation_2; index++) {
      chptr = &channels_list[index];
      list = chptr->plugin;

      if (list->cfg.pipe_amqp) {
        plugin_pipe_amqp_init_host(&chptr->amqp_host, list);
        ret = p_amqp_connect_to_publish(&chptr->amqp_host);
        if (ret) plugin_pipe_amqp_sleeper_start(chptr);
      }

      /* reset core process pipe AMQP routing key */
      if (list->type.id == PLUGIN_ID_CORE) list->cfg.pipe_amqp_routing_key = NULL;
    }

    for (index = 0; channels_list[index].aggregation || channels_list[index].aggregation_2; index++) {
      struct plugins_list_entry *list2 = plugins_list;
      struct channels_list_entry *chptr2 = NULL;

      chptr = &channels_list[index];
      list = chptr->plugin;

      for (index2 = index; channels_list[index2].aggregation || channels_list[index2].aggregation_2; index2++) {
        chptr2 = &channels_list[index2];
        list2 = chptr2->plugin;

	if (index2 > index && list->cfg.pipe_amqp_exchange && list->cfg.pipe_amqp_routing_key) {
	  if (!strcmp(list->cfg.pipe_amqp_exchange, list2->cfg.pipe_amqp_exchange) &&
	      !strcmp(list->cfg.pipe_amqp_routing_key, list2->cfg.pipe_amqp_routing_key)) {
	    Log(LOG_ERR, "ERROR ( %s/%s ): Duplicated plugin_pipe_amqp_exchange, plugin_pipe_amqp_routing_key: %s, %s\nExiting.\n",
		list->name, list->type.string, list->cfg.pipe_amqp_exchange, list->cfg.pipe_amqp_routing_key);
	    exit(1);
	  }
        }
      }
    }
  }
#endif

  /* Kafka handling, if required */
#ifdef WITH_KAFKA
  {
    int ret, index, index2;

    for (index = 0; channels_list[index].aggregation || channels_list[index].aggregation_2; index++) {
      chptr = &channels_list[index];
      list = chptr->plugin;

      /* XXX: no sleeper thread, trusting librdkafka */
      if (list->cfg.pipe_kafka) ret = plugin_pipe_kafka_init_host(&chptr->kafka_host, list, TRUE);

      /* reset core process pipe Kafka topic */
      if (list->type.id == PLUGIN_ID_CORE) list->cfg.pipe_kafka_topic = NULL;
    }

    for (index = 0; channels_list[index].aggregation || channels_list[index].aggregation_2; index++) {
      struct plugins_list_entry *list2 = plugins_list;
      struct channels_list_entry *chptr2 = NULL;

      chptr = &channels_list[index];
      list = chptr->plugin;

      for (index2 = index; channels_list[index2].aggregation || channels_list[index2].aggregation_2; index2++) {
        chptr2 = &channels_list[index2];
        list2 = chptr2->plugin;

        if (index2 > index && list->cfg.pipe_kafka_broker_host && list->cfg.pipe_kafka_topic) {
          if (!strcmp(list->cfg.pipe_kafka_broker_host, list2->cfg.pipe_kafka_broker_host) &&
              list->cfg.pipe_kafka_broker_port == list2->cfg.pipe_kafka_broker_port &&
              !strcmp(list->cfg.pipe_kafka_topic, list2->cfg.pipe_kafka_topic) /* && XXX: topic partition too? */ ) {
            Log(LOG_ERR, "ERROR ( %s/%s ): Duplicated plugin_pipe_kafka_broker_*, plugin_pipe_kafka_topic: %s, %s, %s\nExiting.\n",
                list->name, list->type.string, list->cfg.pipe_kafka_broker_host, list->cfg.pipe_kafka_broker_port,
		list->cfg.pipe_kafka_topic);
            exit(1);
          }
        }
      }
    }
  }
#endif
}

void exec_plugins(struct packet_ptrs *pptrs, struct plugin_requests *req) 
{
  int saved_have_tag = FALSE, saved_have_tag2 = FALSE, saved_have_label = FALSE;
  pm_id_t saved_tag = 0, saved_tag2 = 0;
  pt_label_t saved_label;

  int num, ret, fixed_size, already_reprocessed = 0;
  u_int32_t savedptr;
  char *bptr;
  int index, got_tags = FALSE;

  pretag_init_label(&saved_label);

#if defined WITH_GEOIPV2
  if (reload_geoipv2_file && config.geoipv2_file) {
    pm_geoipv2_close();
    pm_geoipv2_init();

    reload_geoipv2_file = FALSE;
  }
#endif

  for (index = 0; channels_list[index].aggregation || channels_list[index].aggregation_2; index++) {
    struct plugins_list_entry *p = channels_list[index].plugin;

    if (p->cfg.pre_tag_map && find_id_func) {
      if (p->cfg.ptm_global && got_tags) {
        pptrs->tag = saved_tag;
        pptrs->tag2 = saved_tag2;
	pretag_copy_label(&pptrs->label, &saved_label);

        pptrs->have_tag = saved_have_tag;
        pptrs->have_tag2 = saved_have_tag2;
        pptrs->have_label = saved_have_label;
      }
      else {
        find_id_func(&p->cfg.ptm, pptrs, &pptrs->tag, &pptrs->tag2);

	if (p->cfg.ptm_global) {
	  saved_tag = pptrs->tag;
	  saved_tag2 = pptrs->tag2;
	  pretag_copy_label(&saved_label, &pptrs->label);

	  saved_have_tag = pptrs->have_tag;
	  saved_have_tag2 = pptrs->have_tag2;
	  saved_have_label = pptrs->have_label;

          got_tags = TRUE;
        }
      }
    }

    if (evaluate_filters(&channels_list[index].agg_filter, pptrs->packet_ptr, pptrs->pkthdr) &&
        !evaluate_tags(&channels_list[index].tag_filter, pptrs->tag) && 
        !evaluate_tags(&channels_list[index].tag2_filter, pptrs->tag2) && 
        !evaluate_labels(&channels_list[index].label_filter, &pptrs->label) && 
	!check_shadow_status(pptrs, &channels_list[index])) {
      /* arranging buffer: supported primitives + packet total length */
reprocess:
      channels_list[index].reprocess = FALSE;
      num = 0;

      /* rg.ptr points to slot's base address into the ring (shared memory); bufptr works
	 as a displacement into the slot to place sequentially packets */
      bptr = channels_list[index].rg.ptr+ChBufHdrSz+channels_list[index].bufptr; 
      fixed_size = (*channels_list[index].clean_func)(bptr, channels_list[index].datasize);
      channels_list[index].var_size = 0; 
      savedptr = channels_list[index].bufptr;
      reset_fallback_status(pptrs);
      
      while (channels_list[index].phandler[num]) {
        (*channels_list[index].phandler[num])(&channels_list[index], pptrs, &bptr);
        num++;
      }

      if (channels_list[index].s.rate && !channels_list[index].s.sampled_pkts) {
	channels_list[index].reprocess = FALSE;
	channels_list[index].bufptr = savedptr;
	channels_list[index].hdr.num--; /* let's cheat this value as it will get increased later */
	fixed_size = 0;
	channels_list[index].var_size = 0;
      }

      if (channels_list[index].reprocess) {
        /* Let's check if we have an issue with the buffer size */
        if (already_reprocessed) {
          struct plugins_list_entry *list = channels_list[index].plugin;

          Log(LOG_ERR, "ERROR ( %s/%s ): plugin_buffer_size is too short.\n", list->name, list->type.string);
          exit_all(1);
        }
        already_reprocessed = TRUE;

	/* Let's cheat the size in order to send out the current buffer */
	fixed_size = channels_list[index].plugin->cfg.pipe_size;
      }
      else {
        channels_list[index].hdr.num++;
        channels_list[index].bufptr += (fixed_size + channels_list[index].var_size);
      }

      if ((channels_list[index].bufptr+fixed_size) > channels_list[index].bufend ||
	  channels_list[index].hdr.num == INT_MAX) {
	channels_list[index].hdr.seq++;
	channels_list[index].hdr.seq %= MAX_SEQNUM;

	/* let's commit the buffer we just finished writing */
	((struct ch_buf_hdr *)channels_list[index].rg.ptr)->seq = channels_list[index].hdr.seq;
	((struct ch_buf_hdr *)channels_list[index].rg.ptr)->num = channels_list[index].hdr.num;
	((struct ch_buf_hdr *)channels_list[index].rg.ptr)->core_pid = channels_list[index].core_pid;

        if (config.debug_internal_msg) {
	  struct plugins_list_entry *list = channels_list[index].plugin;
	  Log(LOG_DEBUG, "DEBUG ( %s/%s ): buffer released cpid=%u seq=%u num_entries=%u\n", list->name, list->type.string,
		channels_list[index].core_pid, channels_list[index].hdr.seq, channels_list[index].hdr.num);
	}

	/* sending the buffer to the AMQP broker */
	if (channels_list[index].plugin->cfg.pipe_amqp) {
#ifdef WITH_RABBITMQ
          struct channels_list_entry *chptr = &channels_list[index];

          plugin_pipe_amqp_sleeper_stop(chptr);
	  if (!chptr->amqp_host_sleep) ret = p_amqp_publish_binary(&chptr->amqp_host, chptr->rg.ptr, chptr->bufsize);
	  else ret = FALSE;
          if (ret) plugin_pipe_amqp_sleeper_start(chptr);
#endif
	}
	/* sending the buffer to the Kafka broker */
	else if (channels_list[index].plugin->cfg.pipe_kafka) {
#ifdef WITH_KAFKA
          struct channels_list_entry *chptr = &channels_list[index];

	  /* XXX: no sleeper thread, trusting librdkafka */
	  ret = p_kafka_produce_data(&chptr->kafka_host, chptr->rg.ptr, chptr->bufsize);
#endif
	}
	else {
	  if (channels_list[index].status->wakeup) {
	    channels_list[index].status->backlog++;
	  
	    if (channels_list[index].status->backlog >
		((channels_list[index].plugin->cfg.pipe_size/channels_list[index].plugin->cfg.buffer_size)
		*channels_list[index].plugin->cfg.pipe_backlog)/100) {
	      channels_list[index].status->wakeup = channels_list[index].request;
              if (write(channels_list[index].pipe, &channels_list[index].rg.ptr, CharPtrSz) != CharPtrSz) {
	        struct plugins_list_entry *list = channels_list[index].plugin;
	        Log(LOG_WARNING, "WARN ( %s/%s ): Failed during write: %s\n", list->name, list->type.string, strerror(errno));
	      }
	      channels_list[index].status->backlog = 0;
	    }
	  }
	}

	channels_list[index].rg.ptr += channels_list[index].bufsize;

	if ((channels_list[index].rg.ptr+channels_list[index].bufsize) > channels_list[index].rg.end)
	  channels_list[index].rg.ptr = channels_list[index].rg.base;

	/* let's protect the buffer we are going to write */
        ((struct ch_buf_hdr *)channels_list[index].rg.ptr)->seq = -1;
        ((struct ch_buf_hdr *)channels_list[index].rg.ptr)->num = 0;
        ((struct ch_buf_hdr *)channels_list[index].rg.ptr)->core_pid = 0;

        /* rewind pointer */
        channels_list[index].bufptr = channels_list[index].buf;
        channels_list[index].hdr.num = 0;

	if (channels_list[index].reprocess) goto reprocess;

	/* if reading from a savefile, let's sleep a bit after
	   having sent over a buffer worth of data */
	if (channels_list[index].plugin->cfg.pcap_savefile) usleep(1000); /* 1 msec */ 
      }
    }

    pptrs->tag = 0;
    pptrs->tag2 = 0;
    pretag_free_label(&pptrs->label);
  }

  /* check if we have to reload the map: new loop is to
     ensure we reload it for all plugins and prevent any
     timing issues with pointers to labels */
  if (reload_map_exec_plugins) {
    for (index = 0; channels_list[index].aggregation || channels_list[index].aggregation_2; index++) {
      struct plugins_list_entry *p = channels_list[index].plugin;

      if (p->cfg.pre_tag_map && find_id_func) {
        load_pre_tag_map(config.acct_type, p->cfg.pre_tag_map, &p->cfg.ptm, req, &p->cfg.ptm_alloc,
                         p->cfg.maps_entries, p->cfg.maps_row_len);
      }
    }
  }

  /* cleanups */
  reload_map_exec_plugins = FALSE;
  pretag_free_label(&saved_label);
}

struct channels_list_entry *insert_pipe_channel(int plugin_type, struct configuration *cfg, int pipe)
{
  struct channels_list_entry *chptr; 
  int index = 0, x;  

  while (index < MAX_N_PLUGINS) {
    chptr = &channels_list[index]; 
    if (!chptr->aggregation && !chptr->aggregation_2) { /* found room */
      chptr->aggregation = cfg->what_to_count;
      chptr->aggregation_2 = cfg->what_to_count_2;
      chptr->pipe = pipe; 
      chptr->agg_filter.table = cfg->bpfp_a_table;
      chptr->agg_filter.num = (int *) &cfg->bpfp_a_num; 
      chptr->bufsize = cfg->buffer_size;
      chptr->core_pid = getpid();
      chptr->tag = cfg->post_tag;
      chptr->tag2 = cfg->post_tag2;
      if (cfg->sampling_rate && plugin_type != PLUGIN_ID_SFPROBE) { /* sfprobe cares for itself */
	chptr->s.rate = cfg->sampling_rate;

	if (cfg->acct_type == ACCT_NF) chptr->s.sf = &take_simple_systematic_skip;
	else chptr->s.sf = &take_simple_random_skip;
      } 
      memcpy(&chptr->tag_filter, &cfg->ptf, sizeof(struct pretag_filter));
      memcpy(&chptr->tag2_filter, &cfg->pt2f, sizeof(struct pretag_filter));
      memcpy(&chptr->label_filter, &cfg->ptlf, sizeof(struct pretag_label_filter));
      chptr->buf = 0;
      chptr->bufptr = chptr->buf;
      chptr->bufend = cfg->buffer_size-sizeof(struct ch_buf_hdr);

      // XXX: no need to map_shared() if using AMQP
      /* +PKT_MSG_SIZE has been introduced as a margin as a
         countermeasure against the reception of malicious NetFlow v9
	 templates */
      chptr->rg.base = map_shared(0, cfg->pipe_size+PKT_MSG_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
      if (chptr->rg.base == MAP_FAILED) {
        Log(LOG_ERR, "ERROR ( %s/%s ): unable to allocate pipe buffer. Exiting ...\n", cfg->name, cfg->type); 
	exit_all(1);
      }
      memset(chptr->rg.base, 0, cfg->pipe_size);
      chptr->rg.ptr = chptr->rg.base;
      chptr->rg.end = chptr->rg.base+cfg->pipe_size;

      chptr->status = map_shared(0, sizeof(struct ch_status), PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
      if (chptr->status == MAP_FAILED) {
        Log(LOG_ERR, "ERROR ( %s/%s ): unable to allocate status buffer. Exiting ...\n", cfg->name, cfg->type);
        exit_all(1);
      }
      memset(chptr->status, 0, sizeof(struct ch_status));

      break;
    }
    else chptr = NULL; 

    index++;
  }

  return chptr;
}

void delete_pipe_channel(int pipe)
{
  struct channels_list_entry *chptr;
  int index = 0, index2;

  while (index < MAX_N_PLUGINS) {
    chptr = &channels_list[index];

    if (chptr->pipe == pipe) {
      chptr->aggregation = FALSE;
      chptr->aggregation_2 = FALSE;
	
      /* we ensure that any plugin is depending on the one
	 being removed via the 'same_aggregate' flag */
      if (!chptr->same_aggregate) {
	index2 = index;
	for (index2++; index2 < MAX_N_PLUGINS; index2++) {
	  chptr = &channels_list[index2];

	  if (!chptr->aggregation && !chptr->aggregation_2) break; /* we finished channels */
	  if (chptr->same_aggregate) {
	    chptr->same_aggregate = FALSE;
	    break; 
	  }
	  else break; /* we have nothing to do */
	}
      }

      index2 = index;
      for (index2++; index2 < MAX_N_PLUGINS; index2++) {
	chptr = &channels_list[index2];
	if (chptr->aggregation || chptr->aggregation_2) {
	  memcpy(&channels_list[index], chptr, sizeof(struct channels_list_entry)); 
	  memset(chptr, 0, sizeof(struct channels_list_entry)); 
	  index++;
	}
	else break; /* we finished channels */
      }
       
      break;
    }

    index++;
  }
}

/* trivial sorting(tm) :-) */
void sort_pipe_channels()
{
  struct channels_list_entry ctmp;
  int x = 0, y = 0; 

  while (x < MAX_N_PLUGINS) {
    if (!channels_list[x].aggregation && !channels_list[x].aggregation_2) break;
    y = x+1; 
    while (y < MAX_N_PLUGINS) {
      if (!channels_list[y].aggregation && !channels_list[y].aggregation_2) break;
      if (channels_list[x].aggregation == channels_list[y].aggregation &&
          channels_list[x].aggregation_2 == channels_list[y].aggregation_2) {
	channels_list[y].same_aggregate = TRUE;
	if (y == x+1) x++;
	else {
	  memcpy(&ctmp, &channels_list[x+1], sizeof(struct channels_list_entry));
	  memcpy(&channels_list[x+1], &channels_list[y], sizeof(struct channels_list_entry));
	  memcpy(&channels_list[y], &ctmp, sizeof(struct channels_list_entry));
	  x++;
	}
      }
      y++;
    }
    x++;
  }
}

void init_pipe_channels()
{
  memset(&channels_list, 0, MAX_N_PLUGINS*sizeof(struct channels_list_entry)); 
}

void evaluate_sampling(struct sampling *smp, pm_counter_t *pkt_len, pm_counter_t *pkt_num, pm_counter_t *sample_pool)
{
  pm_counter_t delta, pkts = *pkt_num;

  if (!smp->rate) { /* sampling is disabled */
    smp->sample_pool = pkts;
    smp->sampled_pkts = pkts;
    return;
  }

  smp->sampled_pkts = 0;

run_again: 
  if (!smp->counter) smp->counter = (smp->sf)(smp->rate);

  delta = MIN(smp->counter, pkts);
  smp->counter -= delta;
  pkts -= delta; 
  smp->sample_pool += delta;

  if (!smp->counter) {
    smp->sampled_pkts++;
    *sample_pool = smp->sample_pool;
    smp->sample_pool = 0;
    if (pkts > 0) goto run_again;
  }

  /* Let's handle flows meaningfully */
  if (smp->sampled_pkts && *pkt_num > 1) {
    *pkt_len = ( *pkt_len / *pkt_num ) * smp->sampled_pkts;
    *pkt_num = smp->sampled_pkts;
  }
}

/* simple random algorithm */
pm_counter_t take_simple_random_skip(pm_counter_t mean)
{
  pm_counter_t skip;

  if (mean > 1) {
    skip = ((random() % ((2 * mean) - 1)) + 1);
    srandom(random());
  }
  else skip = 1; /* smp->rate == 1 */

  return skip;
}

/* simple systematic algorithm */
pm_counter_t take_simple_systematic_skip(pm_counter_t mean)
{
  pm_counter_t skip = mean;

  return skip;
}

/* return value:
   TRUE: We want it!
   FALSE: Discard it!
*/
int evaluate_filters(struct aggregate_filter *filter, char *pkt, struct pcap_pkthdr *pkthdr)
{
  int index;

  if (*filter->num == 0) return TRUE;  /* no entries in the filter array: aggregate filtering disabled */

  for (index = 0; index < *filter->num; index++) {
    if (bpf_filter(filter->table[index]->bf_insns, pkt, pkthdr->len, pkthdr->caplen)) return TRUE; 
  }

  return FALSE;
}

void recollect_pipe_memory(struct channels_list_entry *mychptr)
{
  struct channels_list_entry *chptr;
  int index = 0;

  while (index < MAX_N_PLUGINS) {
    chptr = &channels_list[index];
    if (mychptr->rg.base != chptr->rg.base) {
      munmap(chptr->rg.base, (chptr->rg.end-chptr->rg.base)+PKT_MSG_SIZE);
      munmap(chptr->status, sizeof(struct ch_status));
    }
    index++;
  }
}

void init_random_seed()
{
  struct timeval tv;

  gettimeofday(&tv, NULL);
  srandom((unsigned int)tv.tv_usec);
}

void fill_pipe_buffer()
{
  struct channels_list_entry *chptr;
  int index;

  for (index = 0; channels_list[index].aggregation || channels_list[index].aggregation_2; index++) {
    chptr = &channels_list[index];

    chptr->hdr.seq++;
    chptr->hdr.seq %= MAX_SEQNUM;

    ((struct ch_buf_hdr *)chptr->rg.ptr)->seq = chptr->hdr.seq;
    ((struct ch_buf_hdr *)chptr->rg.ptr)->num = chptr->hdr.num;
    ((struct ch_buf_hdr *)chptr->rg.ptr)->core_pid = chptr->core_pid;

    if (chptr->plugin->cfg.pipe_amqp) {
#ifdef WITH_RABBITMQ
      p_amqp_publish_binary(&chptr->amqp_host, chptr->rg.ptr, chptr->bufsize);
#endif
    }
    else if (chptr->plugin->cfg.pipe_kafka) {
#ifdef WITH_KAFKA
      p_kafka_produce_data(&chptr->kafka_host, chptr->rg.ptr, chptr->bufsize);
#endif
    }
    else {
      if (chptr->status->wakeup) {
        chptr->status->wakeup = chptr->request;
        if (write(chptr->pipe, &chptr->rg.ptr, CharPtrSz) != CharPtrSz)
	  Log(LOG_WARNING, "WARN ( %s/%s ): Failed during write: %s\n", chptr->plugin->cfg.name, chptr->plugin->cfg.type, strerror(errno));
      }
    }
  }
}

int check_pipe_buffer_space(struct channels_list_entry *mychptr, struct pkt_vlen_hdr_primitives *pvlen, int len)
{
  int buf_space = 0;

  if (!mychptr || !pvlen) return ERR;

  /* init to base of current element */
  buf_space = mychptr->bufend - mychptr->bufptr;

  /* subtract fixed part, current variable part and new var part (len) */
  buf_space -= mychptr->datasize;
  buf_space -= pvlen->tot_len;
  buf_space -= len;

  /* return virdict. if positive fix sizes. if negative take care of triggering a reprocess */
  if (buf_space >= 0) {
    mychptr->var_size += len;
    return FALSE;
  }
  else {
    mychptr->bufptr += (mychptr->bufend - mychptr->bufptr);
    mychptr->reprocess = TRUE;
    mychptr->var_size = 0;

    return TRUE;
  }
}

void return_pipe_buffer_space(struct channels_list_entry *mychptr, int len)
{
  if (!mychptr || !len) return;

  if (mychptr->var_size < len) return;

  mychptr->var_size -= len;
}

int check_shadow_status(struct packet_ptrs *pptrs, struct channels_list_entry *mychptr)
{
  if (pptrs->shadow) {
    if (pptrs->tag && mychptr->aggregation & COUNT_TAG) return FALSE;
    else if (pptrs->tag2 && mychptr->aggregation & COUNT_TAG2) return FALSE;
    else return TRUE;
  } 
  else return FALSE;
}

void load_plugin_filters(int link_type)
{
  struct plugins_list_entry *list = plugins_list;

  while (list) {
    if ((*list->type.func)) {

      /* compiling aggregation filter if needed */
      if (list->cfg.a_filter) {
	pcap_t *dev_desc;
	bpf_u_int32 localnet, netmask = 0;  /* pcap library stuff */
	char errbuf[PCAP_ERRBUF_SIZE], *count_token;
	int idx = 0;

	dev_desc = pcap_open_dead(link_type, 128); /* 128 bytes should be long enough */

	if (config.dev) pcap_lookupnet(config.dev, &localnet, &netmask, errbuf);

	list->cfg.bpfp_a_table[idx] = malloc(sizeof(struct bpf_program));
	while ( (count_token = extract_token(&list->cfg.a_filter, ',')) && idx < AGG_FILTER_ENTRIES ) {
	  if (pcap_compile(dev_desc, list->cfg.bpfp_a_table[idx], count_token, 0, netmask) < 0) {
	    Log(LOG_WARNING, "WARN: %s\nWARN ( %s/%s ): aggregation filter disabled.\n",
	    				pcap_geterr(dev_desc), list->cfg.name, list->cfg.type);
	  }
	  else {
	    idx++;
	    list->cfg.bpfp_a_table[idx] = malloc(sizeof(struct bpf_program));
	  }
	}

	list->cfg.bpfp_a_num = idx;
      }
    }
    list = list->next;
  }
}

int pkt_data_clean(void *pdata, int len)
{
  memset(pdata, 0, len);

  return len;
}

int pkt_payload_clean(void *ppayload, int len)
{
  memset(ppayload, 0, PpayloadSz);

  return PpayloadSz;
}

int pkt_msg_clean(void *ppayload, int len)
{
  memset(ppayload, 0, PmsgSz);

  return PmsgSz;
}

int pkt_extras_clean(void *pextras, int len)
{
  memset(pextras, 0, PdataSz+PextrasSz);

  return PdataSz+PextrasSz;
}

void handle_plugin_pipe_dyn_strings(char *new, int newlen, char *old, struct plugins_list_entry *list)
{
  int oldlen, ptr_len;
  char core_proc_name[] = "$core_proc_name", plugin_name[] = "$plugin_name";
  char plugin_type[] = "$plugin_type";
  char *ptr_start, *ptr_end;

  if (!new || !old || !list) return;

  oldlen = strlen(old);
  if (oldlen <= newlen) strcpy(new, old);
  else {
    strncpy(new, old, newlen);
    return;
  }

  replace_string(new, newlen, core_proc_name, list->cfg.proc_name);
  replace_string(new, newlen, plugin_name, list->cfg.name);
  replace_string(new, newlen, plugin_type, list->cfg.type);
}

char *plugin_pipe_compose_default_string(struct plugins_list_entry *list, char *default_rk)
{
  char *rk = NULL;

  if (!list || !default_rk) return rk;

  rk = malloc(SRVBUFLEN);
  memset(rk, 0, SRVBUFLEN);

  handle_plugin_pipe_dyn_strings(rk, SRVBUFLEN, default_rk, list);

  return rk;
}

#ifdef WITH_RABBITMQ
void plugin_pipe_amqp_init_host(struct p_amqp_host *amqp_host, struct plugins_list_entry *list)
{
  int ret;

  if (amqp_host) {
    char *amqp_rk = plugin_pipe_compose_default_string(list, "$core_proc_name-$plugin_name-$plugin_type");

    p_amqp_init_host(amqp_host);

    if (!list->cfg.pipe_amqp_user) list->cfg.pipe_amqp_user = rabbitmq_user;
    if (!list->cfg.pipe_amqp_passwd) list->cfg.pipe_amqp_passwd = rabbitmq_pwd;
    if (!list->cfg.pipe_amqp_exchange) list->cfg.pipe_amqp_exchange = default_amqp_exchange;
    if (!list->cfg.pipe_amqp_host) list->cfg.pipe_amqp_host = default_amqp_host;
    if (!list->cfg.pipe_amqp_vhost) list->cfg.pipe_amqp_vhost = default_amqp_vhost;
    if (!list->cfg.pipe_amqp_routing_key) list->cfg.pipe_amqp_routing_key = amqp_rk;
    if (!list->cfg.pipe_amqp_retry) list->cfg.pipe_amqp_retry = AMQP_DEFAULT_RETRY;

    p_amqp_set_user(amqp_host, list->cfg.pipe_amqp_user);
    p_amqp_set_passwd(amqp_host, list->cfg.pipe_amqp_passwd);
    p_amqp_set_exchange(amqp_host, list->cfg.pipe_amqp_exchange);
    p_amqp_set_host(amqp_host, list->cfg.pipe_amqp_host);
    p_amqp_set_vhost(amqp_host, list->cfg.pipe_amqp_vhost);
    p_amqp_set_routing_key(amqp_host, list->cfg.pipe_amqp_routing_key);
    P_broker_timers_set_retry_interval(&amqp_host->btimers, list->cfg.pipe_amqp_retry);

    p_amqp_set_frame_max(amqp_host, list->cfg.buffer_size);
    p_amqp_set_exchange_type(amqp_host, default_amqp_exchange_type);
    p_amqp_set_content_type_binary(amqp_host);
  }
}

struct plugin_pipe_amqp_sleeper *plugin_pipe_amqp_sleeper_define(struct p_amqp_host *amqp_host, int *flag, struct plugins_list_entry *plugin)
{
  struct plugin_pipe_amqp_sleeper *pas;
  int size = sizeof(struct plugin_pipe_amqp_sleeper);

  if (!amqp_host || !flag) return NULL;

  pas = malloc(size);

  if (pas) {
    memset(pas, 0, size);
    pas->amqp_host = amqp_host;
    pas->plugin = plugin;
    pas->do_reconnect = flag;
  }
  else {
    Log(LOG_ERR, "ERROR ( %s/%s ): plugin_pipe_amqp_sleeper_define(): malloc() failed\n", plugin->cfg.name, plugin->cfg.type);
    return NULL;
  }

  return pas;
}

void plugin_pipe_amqp_sleeper_free(struct plugin_pipe_amqp_sleeper **pas)
{
  if (!pas || !(*pas)) return;

  free((*pas));
  (*pas) = NULL;
}

void plugin_pipe_amqp_sleeper_publish_func(struct plugin_pipe_amqp_sleeper *pas)
{
  int ret;

  if (!pas || !pas->amqp_host || !pas->plugin || !pas->do_reconnect) return;

sleep_again:
  sleep(P_broker_timers_get_retry_interval(&pas->amqp_host->btimers));

  plugin_pipe_amqp_init_host(pas->amqp_host, pas->plugin);
  ret = p_amqp_connect_to_publish(pas->amqp_host);

  if (ret) goto sleep_again;

  (*pas->do_reconnect) = TRUE;

  plugin_pipe_amqp_sleeper_free(&pas);
}

void plugin_pipe_amqp_sleeper_start(struct channels_list_entry *chptr)
{
#if defined ENABLE_THREADS
  if (chptr && !chptr->amqp_host_sleep) {
    struct plugin_pipe_amqp_sleeper *pas;

    chptr->amqp_host_sleep = allocate_thread_pool(1);
    assert(chptr->amqp_host_sleep);

    pas = plugin_pipe_amqp_sleeper_define(&chptr->amqp_host, &chptr->amqp_host_reconnect, chptr->plugin);
    if (pas) send_to_pool((thread_pool_t *) chptr->amqp_host_sleep, plugin_pipe_amqp_sleeper_publish_func, pas);
    else Log(LOG_ERR, "ERROR ( %s/%s ): plugin_pipe_amqp_sleeper_start(): sleeper define failed\n", chptr->plugin->cfg.name, chptr->plugin->cfg.type);
  }
#endif
}

void plugin_pipe_amqp_sleeper_stop(struct channels_list_entry *chptr)
{
#if defined ENABLE_THREADS
  if (chptr && chptr->amqp_host_reconnect) {
    deallocate_thread_pool((thread_pool_t **) &chptr->amqp_host_sleep);
    chptr->amqp_host_sleep = NULL;
    chptr->amqp_host_reconnect = FALSE;
  }
#endif
}

int plugin_pipe_amqp_connect_to_consume(struct p_amqp_host *amqp_host, struct plugins_list_entry *plugin_data)
{
  plugin_pipe_amqp_init_host(amqp_host, plugin_data);
  p_amqp_connect_to_consume(amqp_host);
  return p_amqp_get_sockfd(amqp_host);
}
#endif

#if defined WITH_KAFKA
int plugin_pipe_kafka_init_host(struct p_kafka_host *kafka_host, struct plugins_list_entry *list, int is_prod)
{
  int ret = SUCCESS;

  if (kafka_host && list && !validate_truefalse(is_prod)) {
    char *topic = plugin_pipe_compose_default_string(list, "pmacct.$core_proc_name-$plugin_name-$plugin_type");

    p_kafka_init_host(kafka_host);

    if (is_prod) ret = p_kafka_connect_to_produce(kafka_host);
    else ret = p_kafka_connect_to_consume(kafka_host);

    if (!list->cfg.pipe_kafka_broker_host) list->cfg.pipe_kafka_broker_host = default_kafka_broker_host;
    if (!list->cfg.pipe_kafka_broker_port) list->cfg.pipe_kafka_broker_port = default_kafka_broker_port;
    if (!list->cfg.pipe_kafka_topic) list->cfg.pipe_kafka_topic = topic;
    if (!list->cfg.pipe_kafka_retry) list->cfg.pipe_kafka_retry = PM_KAFKA_DEFAULT_RETRY;

    p_kafka_set_broker(kafka_host, list->cfg.pipe_kafka_broker_host, list->cfg.pipe_kafka_broker_port);
    p_kafka_set_topic(kafka_host, list->cfg.pipe_kafka_topic);
    p_kafka_set_partition(kafka_host, list->cfg.pipe_kafka_partition);
    p_kafka_set_key(kafka_host, list->cfg.pipe_kafka_partition_key, list->cfg.pipe_kafka_partition_keylen);
    p_kafka_set_content_type(kafka_host, PM_KAFKA_CNT_TYPE_BIN);
    P_broker_timers_set_retry_interval(&kafka_host->btimers, list->cfg.pipe_kafka_retry);
  }
  else return ERR;

  return ret;
}

int plugin_pipe_kafka_connect_to_consume(struct p_kafka_host *kafka_host, struct plugins_list_entry *plugin_data)
{
  int ret = SUCCESS;

  if (kafka_host && plugin_data) {
    ret = plugin_pipe_kafka_init_host(kafka_host, plugin_data, FALSE);
    if (!ret) ret = p_kafka_manage_consumer(kafka_host, TRUE);
  }
  else return ERR;

  return ret;
}
#endif 

int plugin_pipe_set_retry_timeout(struct p_broker_timers *btimers, int pipe_fd)
{
  if (pipe_fd == ERR) return (P_broker_timers_get_retry_interval(btimers) * 1000);
  else return LONGLONG_RETRY;
}

int plugin_pipe_calc_retry_timeout_diff(struct p_broker_timers *btimers, time_t now)
{
  int timeout;

  timeout = (((P_broker_timers_get_last_fail(btimers) + P_broker_timers_get_retry_interval(btimers)) - now) * 1000);
  assert(timeout >= 0);

  return timeout;
}

void plugin_pipe_amqp_compile_check()
{
#ifndef WITH_RABBITMQ
  Log(LOG_ERR, "ERROR ( %s/%s ): 'plugin_pipe_amqp' requires compiling with --enable-rabbitmq. Exiting ..\n", config.name, config.type);
  exit_plugin(1);
#endif
}

void plugin_pipe_kafka_compile_check()
{
#ifndef WITH_KAFKA
  Log(LOG_ERR, "ERROR ( %s/%s ): 'plugin_pipe_kafka' requires compiling with --enable-kafka. Exiting ..\n", config.name, config.type);
  exit_plugin(1);
#endif
}

void plugin_pipe_check(struct configuration *cfg)
{
  if (!cfg->pipe_amqp && !cfg->pipe_kafka) cfg->pipe_homegrown = TRUE;

  if (cfg->pipe_amqp && cfg->pipe_kafka) {
    Log(LOG_WARNING, "WARN ( %s/%s ): 'plugin_pipe_amqp' and 'plugin_pipe_kafka' are mutual exclusive: disabling both.\n", cfg->name, cfg->type);

    cfg->pipe_amqp = FALSE;
    cfg->pipe_kafka = FALSE;
    cfg->pipe_homegrown = TRUE;
  }
}
