/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2019 by Paolo Lucente
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

/* includes */
#include "pmacct.h"
#include "pmacct-data.h"
#include "thread_pool.h"
#include "plugin_hooks.h"
#include "plugin_common.h"
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
  int snd_buflen = 0, rcv_buflen = 0, socklen = 0, target_buflen = 0;

  int nfprobe_id = 0, min_sz = 0, extra_sz = 0, offset = 0;
  struct plugins_list_entry *list = plugins_list;
  socklen_t l = sizeof(list->cfg.pipe_size);
  struct channels_list_entry *chptr = NULL;

 
  init_random_seed(); 
  init_pipe_channels();
 
#ifdef WITH_ZMQ
  char username[SHORTBUFLEN], password[SHORTBUFLEN];
  memset(username, 0, sizeof(username));
  memset(password, 0, sizeof(password));

  generate_random_string(username, (sizeof(username) - 1));
  generate_random_string(password, (sizeof(password) - 1));
#endif

  while (list) {
    if ((*list->type.func)) {
      if (list->cfg.data_type & (PIPE_TYPE_METADATA|PIPE_TYPE_PAYLOAD|PIPE_TYPE_MSG));
      else {
	Log(LOG_ERR, "ERROR ( %s/%s ): Data type not supported: %d\n", list->name, list->type.string, list->cfg.data_type);
	exit_gracefully(1);
      }

      min_sz = ChBufHdrSz;
      list->cfg.buffer_immediate = FALSE;
      if (list->cfg.data_type & PIPE_TYPE_METADATA) min_sz += PdataSz; 
      if (list->cfg.data_type & PIPE_TYPE_PAYLOAD) {
	if (list->cfg.acct_type == ACCT_PM && list->cfg.snaplen) min_sz += (PpayloadSz+list->cfg.snaplen); 
	else min_sz += (PpayloadSz+DEFAULT_PLOAD_SIZE); 
      }
      if (list->cfg.data_type & PIPE_TYPE_EXTRAS) min_sz += PextrasSz; 
      if (list->cfg.data_type & PIPE_TYPE_MSG) {
	min_sz += PmsgSz; 
        if (!list->cfg.buffer_size) {
          extra_sz = PKT_MSG_SIZE; 
          list->cfg.buffer_immediate = TRUE;
        }
      }
      if (list->cfg.data_type & PIPE_TYPE_BGP) min_sz += sizeof(struct pkt_bgp_primitives);
      if (list->cfg.data_type & PIPE_TYPE_LBGP) min_sz += sizeof(struct pkt_legacy_bgp_primitives);
      if (list->cfg.data_type & PIPE_TYPE_NAT) min_sz += sizeof(struct pkt_nat_primitives);
      if (list->cfg.data_type & PIPE_TYPE_TUN) min_sz += sizeof(struct pkt_tunnel_primitives);
      if (list->cfg.data_type & PIPE_TYPE_MPLS) min_sz += sizeof(struct pkt_mpls_primitives);
      if (list->cfg.cpptrs.len) min_sz += list->cfg.cpptrs.len;
      if (list->cfg.data_type & PIPE_TYPE_VLEN) {
	min_sz += sizeof(struct pkt_vlen_hdr_primitives);
	if (!list->cfg.buffer_size) {
	  extra_sz = 1024; /* wild shot: 1Kb added for the actual variable-length data */
	  list->cfg.buffer_immediate = TRUE;
	}
      }

      /* If nothing is supplied, let's hint some working default values */
      if (!list->cfg.pipe_size || !list->cfg.buffer_size) {
        if (!list->cfg.pipe_size) list->cfg.pipe_size = 4096000; /* 4Mb */
        if (!list->cfg.buffer_size) {
	  if (list->cfg.pcap_savefile) list->cfg.buffer_size = 10240; /* 10Kb */
	  else list->cfg.buffer_size = MIN((min_sz + extra_sz), 10240);
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

      if (!list->cfg.pipe_zmq) {
        /* creating communication channel */
        socketpair(AF_UNIX, SOCK_DGRAM, 0, list->pipe);

        /* checking SO_RCVBUF and SO_SNDBUF values; if different we take the smaller one */
        getsockopt(list->pipe[0], SOL_SOCKET, SO_RCVBUF, &rcv_buflen, &l);
        getsockopt(list->pipe[1], SOL_SOCKET, SO_SNDBUF, &snd_buflen, &l);
        socklen = (rcv_buflen < snd_buflen) ? rcv_buflen : snd_buflen;

        buf_pipe_ratio_sz = (list->cfg.pipe_size/list->cfg.buffer_size)*sizeof(char *);
        if (buf_pipe_ratio_sz > INT_MAX) {
	  Log(LOG_ERR, "ERROR ( %s/%s ): Current plugin_buffer_size elems per plugin_pipe_size: %llu. Max: %d.\nExiting.\n",
		list->name, list->type.string, (unsigned long long)(list->cfg.pipe_size/list->cfg.buffer_size),
		(INT_MAX/(int)sizeof(char *)));
          exit_gracefully(1);
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
	  Log(LOG_INFO, "INFO ( %s/%s ): plugin_pipe_size=%" PRIu64 " bytes plugin_buffer_size=%" PRIu64 " bytes\n", 
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
	exit_gracefully(1);
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

      if (list->cfg.data_type & PIPE_TYPE_LBGP) {
        chptr->extras.off_pkt_lbgp_primitives = offset;
        offset += sizeof(struct pkt_legacy_bgp_primitives);
      }
      else chptr->extras.off_pkt_lbgp_primitives = 0;

      if (list->cfg.data_type & PIPE_TYPE_NAT) {
        chptr->extras.off_pkt_nat_primitives = offset;
        offset += sizeof(struct pkt_nat_primitives);
      }
      else chptr->extras.off_pkt_nat_primitives = 0; 

      if (list->cfg.data_type & PIPE_TYPE_TUN) {
        chptr->extras.off_pkt_tun_primitives = offset;
        offset += sizeof(struct pkt_tunnel_primitives);
      }
      else chptr->extras.off_pkt_tun_primitives = 0;

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

      /* ZMQ inits, if required */
#ifdef WITH_ZMQ
      if (list->cfg.pipe_zmq) {
	char log_id[LARGEBUFLEN];

	p_zmq_plugin_pipe_init_core(&chptr->zmq_host, list->id, username, password);
	snprintf(log_id, sizeof(log_id), "%s/%s", list->name, list->type.string);
	p_zmq_set_log_id(&chptr->zmq_host, log_id);
	p_zmq_pub_setup(&chptr->zmq_host);
      }
#endif
      
      switch (list->pid = fork()) {  
      case -1: /* Something went wrong */
	Log(LOG_WARNING, "WARN ( %s/%s ): Unable to initialize plugin: %s\n", list->name, list->type.string, strerror(errno));
	delete_pipe_channel(list->pipe[1]);
	break;
      case 0: /* Child */
	/* SIGCHLD handling issue: SysV avoids zombies by ignoring SIGCHLD; to emulate
	   such semantics on BSD systems, we need an handler like handle_falling_child() */
#if defined (SOLARIS)
	signal(SIGCHLD, SIG_IGN);
#else
	signal(SIGCHLD, ignore_falling_child);
#endif

#if defined HAVE_MALLOPT
        mallopt(M_CHECK_ACTION, 0);
#endif

	if (device.dev_desc) pcap_close(device.dev_desc);
	close(config.sock);
	close(config.bgp_sock);
	if (!list->cfg.pipe_zmq) close(list->pipe[1]);
	(*list->type.func)(list->pipe[0], &list->cfg, chptr);
	exit_gracefully(0);
      default: /* Parent */
	if (!list->cfg.pipe_zmq) {
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

	if (list->cfg.type_id == PLUGIN_ID_TEE) {
	  req->ptm_c.load_ptm_plugin = list->cfg.type_id;
	  req->ptm_c.load_ptm_res = FALSE;
	}

        load_pre_tag_map(config.acct_type, list->cfg.pre_tag_map, &list->cfg.ptm, req, &list->cfg.ptm_alloc,
                         list->cfg.maps_entries, list->cfg.maps_row_len);

	if (list->cfg.type_id == PLUGIN_ID_TEE) {
	  list->cfg.ptm_complex = req->ptm_c.load_ptm_res;
	  if (req->ptm_c.load_ptm_res) req->ptm_c.exec_ptm_dissect = TRUE;
	}
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
}

void exec_plugins(struct packet_ptrs *pptrs, struct plugin_requests *req) 
{
  int saved_have_tag = FALSE, saved_have_tag2 = FALSE, saved_have_label = FALSE;
  pm_id_t saved_tag = 0, saved_tag2 = 0;
  pt_label_t *saved_label = malloc(sizeof(pt_label_t));

  int num, fixed_size;
  u_int32_t savedptr;
  char *bptr;
  int index, got_tags = FALSE;

  pretag_init_label(saved_label);

#if defined WITH_GEOIPV2
  if (reload_geoipv2_file && config.geoipv2_file) {
    pm_geoipv2_close();
    pm_geoipv2_init();

    reload_geoipv2_file = FALSE;
  }
#endif

  for (index = 0; channels_list[index].aggregation || channels_list[index].aggregation_2; index++) {
    struct plugins_list_entry *p = channels_list[index].plugin;

    channels_list[index].already_reprocessed = FALSE;

    if (p->cfg.pre_tag_map && find_id_func) {
      if (p->cfg.type_id == PLUGIN_ID_TEE) {
	/*
	   replicate and compute tagging if:
	   - a dissected flow hits a complex pre_tag_map or
	   - a non-dissected (full) packet hits a simple pre_tag_map
	*/
	if ((req->ptm_c.exec_ptm_res && !p->cfg.ptm_complex) || (!req->ptm_c.exec_ptm_res && p->cfg.ptm_complex))
	  continue;
      }

      if (p->cfg.ptm_global && got_tags) {
        pptrs->tag = saved_tag;
        pptrs->tag2 = saved_tag2;
	pretag_copy_label(&pptrs->label, saved_label);

        pptrs->have_tag = saved_have_tag;
        pptrs->have_tag2 = saved_have_tag2;
        pptrs->have_label = saved_have_label;
      }
      else {
	if (p->cfg.type_id == PLUGIN_ID_TEE && req->ptm_c.exec_ptm_res && pptrs->tee_dissect_bcast) /* noop */;
        else {
	  find_id_func(&p->cfg.ptm, pptrs, &pptrs->tag, &pptrs->tag2);

	  if (p->cfg.ptm_global) {
	    saved_tag = pptrs->tag;
	    saved_tag2 = pptrs->tag2;
	    pretag_copy_label(saved_label, &pptrs->label);

	    saved_have_tag = pptrs->have_tag;
	    saved_have_tag2 = pptrs->have_tag2;
	    saved_have_label = pptrs->have_label;

            got_tags = TRUE;
	  }
        }
      }
    }
    else {
      if (p->cfg.type_id == PLUGIN_ID_TEE) {
        /* stop dissected flows from being replicated in case of no pre_tag_map */
        if (req->ptm_c.exec_ptm_res) continue;
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
        if (channels_list[index].already_reprocessed) {
          struct plugins_list_entry *list = channels_list[index].plugin;

          Log(LOG_ERR, "ERROR ( %s/%s ): plugin_buffer_size is too short.\n", list->name, list->type.string);
          exit_gracefully(1);
        }

        channels_list[index].already_reprocessed = TRUE;

	/* Let's cheat the size in order to send out the current buffer */
	fixed_size = channels_list[index].plugin->cfg.pipe_size;
      }
      else {
        channels_list[index].hdr.num++;
        channels_list[index].bufptr += (fixed_size + channels_list[index].var_size);
      }

      if (((channels_list[index].bufptr + fixed_size) > channels_list[index].bufend) ||
	  (channels_list[index].hdr.num == INT_MAX) || channels_list[index].buffer_immediate) {
	channels_list[index].hdr.seq++;
	channels_list[index].hdr.seq %= MAX_SEQNUM;

	/* let's commit the buffer we just finished writing */
	((struct ch_buf_hdr *)channels_list[index].rg.ptr)->len = channels_list[index].bufptr;
	((struct ch_buf_hdr *)channels_list[index].rg.ptr)->seq = channels_list[index].hdr.seq;
	((struct ch_buf_hdr *)channels_list[index].rg.ptr)->num = channels_list[index].hdr.num;

	channels_list[index].status->last_buf_off = (u_int64_t)(channels_list[index].rg.ptr - channels_list[index].rg.base);

        if (config.debug_internal_msg) {
	  struct plugins_list_entry *list = channels_list[index].plugin;
	  Log(LOG_DEBUG, "DEBUG ( %s/%s ): buffer released len=%" PRIu64 " seq=%u num_entries=%u off=%" PRIu64 "\n",
		list->name, list->type.string, channels_list[index].bufptr, channels_list[index].hdr.seq,
		channels_list[index].hdr.num, channels_list[index].status->last_buf_off);
	}

	/* sending buffer to connected ZMQ subscriber(s) */
	if (channels_list[index].plugin->cfg.pipe_zmq) {
#ifdef WITH_ZMQ
          struct channels_list_entry *chptr = &channels_list[index];

	  int ret = p_zmq_topic_send(&chptr->zmq_host, chptr->rg.ptr, chptr->bufsize);
          (void)ret; //Check error?
#endif
	}
	else {
	  if (channels_list[index].status->wakeup) {
	    channels_list[index].status->wakeup = channels_list[index].request;
	    if (write(channels_list[index].pipe, &channels_list[index].rg.ptr, CharPtrSz) != CharPtrSz) {
	      struct plugins_list_entry *list = channels_list[index].plugin;
	      Log(LOG_WARNING, "WARN ( %s/%s ): Failed during write: %s\n", list->name, list->type.string, strerror(errno));
	    }
	  }
	}

	channels_list[index].rg.ptr += channels_list[index].bufsize;

	if ((channels_list[index].rg.ptr+channels_list[index].bufsize) > channels_list[index].rg.end)
	  channels_list[index].rg.ptr = channels_list[index].rg.base;

	/* let's protect the buffer we are going to write */
        ((struct ch_buf_hdr *)channels_list[index].rg.ptr)->seq = -1;
        ((struct ch_buf_hdr *)channels_list[index].rg.ptr)->num = 0;

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
    memset(&req->ptm_c, 0, sizeof(struct ptm_complex)); 

    for (index = 0; channels_list[index].aggregation || channels_list[index].aggregation_2; index++) {
      struct plugins_list_entry *p = channels_list[index].plugin;

      if (p->cfg.pre_tag_map && find_id_func) {
        if (p->cfg.type_id == PLUGIN_ID_TEE) {
          req->ptm_c.load_ptm_plugin = p->cfg.type_id;
          req->ptm_c.load_ptm_res = FALSE;
        }

        load_pre_tag_map(config.acct_type, p->cfg.pre_tag_map, &p->cfg.ptm, req, &p->cfg.ptm_alloc,
                         p->cfg.maps_entries, p->cfg.maps_row_len);

        if (p->cfg.type_id == PLUGIN_ID_TEE) {
          p->cfg.ptm_complex = req->ptm_c.load_ptm_res;
          if (req->ptm_c.load_ptm_res) req->ptm_c.exec_ptm_dissect = TRUE;
        }
      }
    }
  }

  /* cleanups */
  reload_map_exec_plugins = FALSE;
  pretag_free_label(saved_label);
  if (saved_label) free(saved_label);
}

struct channels_list_entry *insert_pipe_channel(int plugin_type, struct configuration *cfg, int pipe)
{
  struct channels_list_entry *chptr; 
  int index = 0;  

  while (index < MAX_N_PLUGINS) {
    chptr = &channels_list[index]; 
    if (!chptr->aggregation && !chptr->aggregation_2) { /* found room */
      chptr->aggregation = cfg->what_to_count;
      chptr->aggregation_2 = cfg->what_to_count_2;
      chptr->pipe = pipe; 
      chptr->agg_filter.table = cfg->bpfp_a_table;
      chptr->agg_filter.num = (int *) &cfg->bpfp_a_num; 
      chptr->bufsize = cfg->buffer_size;
      chptr->buffer_immediate = cfg->buffer_immediate;
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
	exit_gracefully(1);
      }
      memset(chptr->rg.base, 0, cfg->pipe_size);
      chptr->rg.ptr = chptr->rg.base;
      chptr->rg.end = chptr->rg.base+cfg->pipe_size;

      chptr->status = map_shared(0, sizeof(struct ch_status), PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
      if (chptr->status == MAP_FAILED) {
        Log(LOG_ERR, "ERROR ( %s/%s ): unable to allocate status buffer. Exiting ...\n", cfg->name, cfg->type);
        exit_gracefully(1);
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
int evaluate_filters(struct aggregate_filter *filter, u_char *pkt, struct pcap_pkthdr *pkthdr)
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

    if (chptr->plugin->cfg.pipe_zmq) {
#ifdef WITH_ZMQ
      p_zmq_topic_send(&chptr->zmq_host, chptr->rg.ptr, chptr->bufsize);
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

  if (!mychptr) return ERR;

  /* init to base of current element */
  buf_space = mychptr->bufend - mychptr->bufptr;

  /* subtract fixed part, current variable part and new var part (len) */
  buf_space -= mychptr->datasize;
  if (pvlen) buf_space -= pvlen->tot_len;
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

	if (config.pcap_if) pcap_lookupnet(config.pcap_if, &localnet, &netmask, errbuf);

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

void plugin_pipe_zmq_compile_check()
{
#ifndef WITH_ZMQ
  Log(LOG_ERR, "ERROR ( %s/%s ): 'plugin_pipe_zmq' requires compiling with --enable-zmq. Exiting ..\n", config.name, config.type);
  exit_gracefully(1);
#endif
}

void plugin_pipe_check(struct configuration *cfg)
{
  if (!cfg->pipe_zmq) cfg->pipe_homegrown = TRUE;
}

void P_zmq_pipe_init(void *zh, int *pipe_fd, u_int32_t *seq)
{
  plugin_pipe_zmq_compile_check();

#ifdef WITH_ZMQ
  if (zh) {
    struct p_zmq_host *zmq_host = zh;
    char log_id[LARGEBUFLEN];

    p_zmq_plugin_pipe_init_plugin(zmq_host);

    snprintf(log_id, sizeof(log_id), "%s/%s", config.name, config.type);
    p_zmq_set_log_id(zmq_host, log_id);

    p_zmq_set_hwm(zmq_host, config.pipe_zmq_hwm);
    p_zmq_sub_setup(zmq_host);
    p_zmq_set_retry_timeout(zmq_host, config.pipe_zmq_retry);

    if (pipe_fd) (*pipe_fd) = p_zmq_get_fd(zmq_host);
    if (seq) (*seq) = 0;
  }
#endif
}
