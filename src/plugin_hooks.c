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

/* when not using map_shared, 'pipe_size' is the size of
   the pipe created with socketpair(); when map_shared is
   enabled, it refers to the size of the shared memory
   area */
void load_plugins(struct plugin_requests *req)
{
  int x, v, socklen, nfprobe_id = 0, min_sz = 0;
  struct plugins_list_entry *list = plugins_list;
  int l = sizeof(list->cfg.pipe_size), offset;
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

      /* If nothing is supplied, let's hint some working default values */
      if (list->cfg.pcap_savefile && !list->cfg.pipe_size && !list->cfg.buffer_size) {
        list->cfg.pipe_size = 4096000; /* 4Mb */
        list->cfg.buffer_size = 10240; /* 10Kb */
      }
      /* creating communication channel */
      socketpair(AF_UNIX, SOCK_DGRAM, 0, list->pipe);
      if (list->cfg.pipe_size) {
	if (list->cfg.pipe_size < min_sz) list->cfg.pipe_size = min_sz;
      }
      else {
        x = DEFAULT_PIPE_SIZE;
	Setsocksize(list->pipe[0], SOL_SOCKET, SO_RCVBUF, &x, l);
        Setsocksize(list->pipe[1], SOL_SOCKET, SO_SNDBUF, &x, l);
      }

      /* checking SO_RCVBUF and SO_SNDBUF values; if different we take the smaller one */
      getsockopt(list->pipe[0], SOL_SOCKET, SO_RCVBUF, &v, &l);
      x = v;
      getsockopt(list->pipe[1], SOL_SOCKET, SO_SNDBUF, &v, &l);
      socklen = (v < x) ? v : x;

      /* checking Core <-> Plugins buffer size; then, if required let's align it on
         4 bytes boundary -- on the assumption that data strucures are aligned aswell. */
      if (list->cfg.buffer_size < min_sz) list->cfg.buffer_size = min_sz;
#if NEED_ALIGN
      while (list->cfg.buffer_size % 4 != 0) list->cfg.buffer_size--;
#endif

      if (list->cfg.data_type == PIPE_TYPE_PAYLOAD) {
	/* Let's tweak plugin_pipe_size if we don't have an explicit size */
	if (!list->cfg.pipe_size) list->cfg.pipe_size = 4096000; /* 4Mb */
      }

      /* if we are not supplied a 'plugin_pipe_size', then we calculate it using
         buffer size and given socket size; if 'plugin_pipe_size' is known, we
	 reverse the method: we try to obtain needed socket size to accomodate
	 given pipe and buffer size */
      if (!list->cfg.pipe_size) { 
        list->cfg.pipe_size = (socklen/sizeof(char *))*list->cfg.buffer_size;
	if ((list->cfg.debug) || (list->cfg.pipe_size > WARNING_PIPE_SIZE))  {
          Log(LOG_INFO, "INFO ( %s/%s ): %d bytes are available to address shared memory segment; buffer size is %d bytes.\n",
			list->name, list->type.string, socklen, list->cfg.buffer_size);
	  Log(LOG_INFO, "INFO ( %s/%s ): Trying to allocate a shared memory segment of %d bytes.\n",
			list->name, list->type.string, list->cfg.pipe_size);
	}
      }
      else {
        if (list->cfg.buffer_size > list->cfg.pipe_size)
	  list->cfg.buffer_size = list->cfg.pipe_size;

        x = (list->cfg.pipe_size/list->cfg.buffer_size)*sizeof(char *);
        if (x > socklen) {
	  Setsocksize(list->pipe[0], SOL_SOCKET, SO_RCVBUF, &x, l);
	  Setsocksize(list->pipe[1], SOL_SOCKET, SO_SNDBUF, &x, l);
        }

        socklen = x;
        getsockopt(list->pipe[0], SOL_SOCKET, SO_RCVBUF, &v, &l);
        x = v;
        getsockopt(list->pipe[1], SOL_SOCKET, SO_SNDBUF, &v, &l);
        if (x > v) x = v;

        if ((x < socklen) || (list->cfg.debug))
          Log(LOG_INFO, "INFO ( %s/%s ): Pipe size obtained: %d / %d.\n", list->name, list->type.string, x, socklen);
      }

      list->cfg.name = list->name;
      list->cfg.type = list->type.string;
      chptr = insert_pipe_channel(list->type.id, &list->cfg, list->pipe[1]);
      if (!chptr) {
	Log(LOG_ERR, "ERROR ( %s/%s ): Unable to setup a new Core Process <-> Plugin channel.\nExiting.\n", list->name, list->type.string);
	exit_all(1);
      }
      else chptr->plugin = list;

      /* sets new value to be assigned to 'wakeup'; 'TRUE' disables on-request wakeup */ 
      if (list->type.id == PLUGIN_ID_MEMORY) chptr->request = TRUE; 

      /* sets cleaner routine; XXX: we should definitely refine the way it works, maybe
         by looking at stacking more of them, ie. extras assumes it's automagically piled
	 with metadata */
      if (list->cfg.data_type & PIPE_TYPE_METADATA) {
	chptr->clean_func = pkt_data_clean;
	offset = sizeof(struct pkt_data);
      }
      if (list->cfg.data_type & PIPE_TYPE_PAYLOAD) chptr->clean_func = pkt_payload_clean;
      if (list->cfg.data_type & PIPE_TYPE_EXTRAS) chptr->clean_func = pkt_extras_clean;
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
	close(config.sock);
	close(list->pipe[1]);
	(*list->type.func)(list->pipe[0], &list->cfg, chptr);
	exit(0);
      default: /* Parent */
	close(list->pipe[0]);
	setnonblocking(list->pipe[1]);
	break;
      }

      /* some residual check */
      if (chptr && list->cfg.a_filter) req->bpf_filter = TRUE;
    }
    list = list->next;
  }

  sort_pipe_channels();
}

void exec_plugins(struct packet_ptrs *pptrs) 
{
  int num, size, already_reprocessed = 0;
  u_int32_t savedptr;
  char *bptr;
  int index;

  for (index = 0; channels_list[index].aggregation || channels_list[index].aggregation_2; index++) {
    if (evaluate_filters(&channels_list[index].agg_filter, pptrs->packet_ptr, pptrs->pkthdr) &&
        !evaluate_tags(&channels_list[index].tag_filter, pptrs->tag) && 
        !evaluate_tags(&channels_list[index].tag2_filter, pptrs->tag2) && 
	!check_shadow_status(pptrs, &channels_list[index])) {
      /* arranging buffer: supported primitives + packet total length */
reprocess:
      channels_list[index].reprocess = FALSE;
      num = 0;

      /* rg.ptr points to slot's base address into the ring (shared memory); bufptr works
	 as a displacement into the slot to place sequentially packets */
      bptr = channels_list[index].rg.ptr+ChBufHdrSz+channels_list[index].bufptr; 
      size = (*channels_list[index].clean_func)(bptr, channels_list[index].datasize);
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
	size = 0;
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
	size = channels_list[index].plugin->cfg.pipe_size;
      }
      else {
        channels_list[index].hdr.num++;
        channels_list[index].bufptr += size;
      }

      if ((channels_list[index].bufptr+size) > channels_list[index].bufend) {
	channels_list[index].hdr.seq++;
	channels_list[index].hdr.seq %= MAX_SEQNUM;

	((struct ch_buf_hdr *)channels_list[index].rg.ptr)->seq = channels_list[index].hdr.seq;
	((struct ch_buf_hdr *)channels_list[index].rg.ptr)->num = channels_list[index].hdr.num;

	if (channels_list[index].status->wakeup) {
	  channels_list[index].status->backlog++;
	  
	  if (channels_list[index].status->backlog > ((channels_list[index].plugin->cfg.pipe_size/channels_list[index].plugin->cfg.buffer_size)*channels_list[index].plugin->cfg.pipe_backlog)/100) {
	    channels_list[index].status->wakeup = channels_list[index].request;
            if (write(channels_list[index].pipe, &channels_list[index].rg.ptr, CharPtrSz) != CharPtrSz)
	      Log(LOG_WARNING, "WARN: Failed during write: %s\n", strerror(errno));
	    channels_list[index].status->backlog = 0;
	  }
	}
	channels_list[index].rg.ptr += channels_list[index].bufsize;

	if ((channels_list[index].rg.ptr+channels_list[index].bufsize) > channels_list[index].rg.end)
	  channels_list[index].rg.ptr = channels_list[index].rg.base;

        /* rewind pointer */
        channels_list[index].bufptr = channels_list[index].buf;
        channels_list[index].hdr.num = 0;

	if (channels_list[index].reprocess) goto reprocess;
      }
    }
  }
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
      chptr->id = cfg->post_tag;
      if (cfg->sampling_rate && plugin_type != PLUGIN_ID_SFPROBE) { /* sfprobe cares for itself */
	chptr->s.rate = cfg->sampling_rate;

	if (cfg->acct_type == ACCT_NF) chptr->s.sf = &take_simple_systematic_skip;
	else chptr->s.sf = &take_simple_random_skip;
      } 
      memcpy(&chptr->tag_filter, &cfg->ptf, sizeof(struct pretag_filter));
      memcpy(&chptr->tag2_filter, &cfg->pt2f, sizeof(struct pretag_filter));
      chptr->buf = 0;
      chptr->bufptr = chptr->buf;
      chptr->bufend = cfg->buffer_size-sizeof(struct ch_buf_hdr);

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
  int index;

  for (index = 0; channels_list[index].aggregation || channels_list[index].aggregation_2; index++) {
    channels_list[index].hdr.seq++;
    channels_list[index].hdr.seq %= MAX_SEQNUM;

    ((struct ch_buf_hdr *)channels_list[index].rg.ptr)->seq = channels_list[index].hdr.seq;
    ((struct ch_buf_hdr *)channels_list[index].rg.ptr)->num = channels_list[index].hdr.num;

    if (channels_list[index].status->wakeup) {
      channels_list[index].status->wakeup = channels_list[index].request;
      if (write(channels_list[index].pipe, &channels_list[index].rg.ptr, CharPtrSz) != CharPtrSz)
	Log(LOG_WARNING, "WARN: Failed during write: %s\n", strerror(errno));
    }
  }
}

int check_shadow_status(struct packet_ptrs *pptrs, struct channels_list_entry *mychptr)
{
  if (pptrs->shadow) {
    if (pptrs->tag && mychptr->aggregation & COUNT_ID) return FALSE;
    else if (pptrs->tag2 && mychptr->aggregation & COUNT_ID2) return FALSE;
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
