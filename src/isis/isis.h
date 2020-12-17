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

#ifndef _ISIS_H_
#define _ISIS_H_

/* includes */
#include "isis_ll.h"
#include "prefix.h"
#include "isis_constants.h"

/* defines */
#define MAX_IGP_MAP_ELEM 64
#define MAX_IGP_MAP_NODES 4096

/* Flag manipulation macros. */
#define CHECK_FLAG(V,F)      ((V) & (F))
#define SET_FLAG(V,F)        (V) |= (F)
#define UNSET_FLAG(V,F)      (V) &= ~(F)

/* Does the I/O error indicate that the operation should be retried later? */
#define ERRNO_IO_RETRY(EN) (((EN) == EAGAIN) || ((EN) == EWOULDBLOCK) || ((EN) == EINTR))

/* structures */
static struct _devices_struct __attribute__((unused))  _isis_devices[] = {
#if defined DLT_LINUX_SLL
  {isis_sll_handler, DLT_LINUX_SLL},
#endif
  {NULL, -1},
};

struct pm_pcap_isis_callback_data {
  struct pm_pcap_device *device;
  struct isis_circuit *circuit;
};

struct igp_map_metric {
  struct isis_prefix prefix;
  u_int32_t metric;
};

struct igp_map_entry {
  struct host_addr node;
  u_int16_t area_id;
  struct igp_map_metric adj_metric[MAX_IGP_MAP_ELEM];
  struct igp_map_metric reach_metric[MAX_IGP_MAP_ELEM];
  struct igp_map_metric reach6_metric[MAX_IGP_MAP_ELEM];
  u_int8_t adj_metric_num;
  u_int8_t reach_metric_num;
  u_int8_t reach6_metric_num;
};

struct sysid_fragment {
  u_char sysid[ISIS_SYS_ID_LEN];
  u_char frag_num;
  u_char valid;
};

/* prototypes */
extern void nfacctd_isis_wrapper();
extern int skinny_isis_daemon();
extern void isis_pdu_runner(u_char *, const struct pcap_pkthdr *, const u_char *);
extern int iso_handler(register struct packet_ptrs *);

extern int igp_daemon_map_node_handler(char *, struct id_entry *, char *, struct plugin_requests *, int);
extern int igp_daemon_map_area_id_handler(char *, struct id_entry *, char *, struct plugin_requests *, int);
extern int igp_daemon_map_adj_metric_handler(char *, struct id_entry *, char *, struct plugin_requests *, int);
extern int igp_daemon_map_reach_metric_handler(char *, struct id_entry *, char *, struct plugin_requests *, int);
extern int igp_daemon_map_reach6_metric_handler(char *, struct id_entry *, char *, struct plugin_requests *, int);
extern void igp_daemon_map_validate(char *, struct plugin_requests *);
extern void igp_daemon_map_initialize(char *, struct plugin_requests *);
extern void igp_daemon_map_finalize(char *, struct plugin_requests *);
extern int igp_daemon_map_handle_len(int *, int, struct plugin_requests *, char *);
extern int igp_daemon_map_handle_lsp_id(u_char *, struct host_addr *);
extern void isis_srcdst_lookup(struct packet_ptrs *);

/* global variables */
extern struct thread_master *master;
extern struct isis *isis;
extern struct in_addr router_id_zebra; /* XXX: do something with this eventually */
extern struct timeval isis_now, isis_spf_deadline, isis_psnp_deadline;
extern struct igp_map_entry ime;
extern pcap_dumper_t *idmm_fd; /* igp_daemon_map : file descriptor for igp_daemon_map_msglog */
extern u_int32_t glob_isis_seq_num; 
extern struct sysid_fragment sysid_fragment_table[MAX_IGP_MAP_NODES];

#endif
