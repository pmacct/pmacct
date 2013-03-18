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

#ifndef _PMACCT_H_
#define _PMACCT_H_

/* includes */
#ifdef HAVE_PCAP_PCAP_H
#include <pcap/pcap.h>
#endif
#ifdef HAVE_PCAP_H
#include <pcap.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#ifdef HAVE_GETOPT_H
#include <getopt.h> 
#endif

#include <ctype.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <signal.h>
#include <syslog.h>

#include <sys/mman.h>
#if !defined (MAP_ANONYMOUS)
#if defined (MAP_ANON)
#define MAP_ANONYMOUS MAP_ANON
#else
#define MAP_ANONYMOUS 0
#define USE_DEVZERO 1
#endif
#endif

#if defined (WITH_GEOIP)
#include <GeoIP.h>
#endif

#include "pmacct-build.h"

#if !defined INET_ADDRSTRLEN 
#define INET_ADDRSTRLEN 16
#endif
#if !defined INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif

#if (defined SOLARIS) && (defined CPU_sparc)
#define htons(x) (x)
#define htonl(x) (x)
#endif

#if (!defined HAVE_U_INT8_T) && (defined HAVE_UINT8_T) 
#define u_int8_t uint8_t
#endif
#if (!defined HAVE_U_INT16_T) && (defined HAVE_UINT16_T)
#define u_int16_t uint16_t
#endif
#if (!defined HAVE_U_INT32_T) && (defined HAVE_UINT32_T)
#define u_int32_t uint32_t
#endif
#if (!defined HAVE_U_INT64_T) && (defined HAVE_UINT64_T)
#define u_int64_t uint64_t
#endif

#if defined HAVE_64BIT_COUNTERS
#define MOREBUFSZ 32
#else
#define MOREBUFSZ 0
#endif

#ifndef LOCK_UN
#define LOCK_UN 8
#endif

#ifndef LOCK_EX
#define LOCK_EX 2
#endif

#ifdef NOINLINE
#define Inline
#else
#define Inline static inline
#endif

/* Let work the unaligned copy macros the hard way: byte-per byte copy via
   u_char pointers. We discard the packed attribute way because it fits just
   to GNU compiler */
#if !defined NEED_ALIGN
#define Assign8(a, b) a = b
#else
#define Assign8(a, b)		\
{             			\
  u_char *ptr = (u_char *)&a;	\
  *ptr = b;			\
}
#endif

#if !defined NEED_ALIGN
#define Assign16(a, b) a = b
#else
#define Assign16(a, b)		\
{      				\
  u_int16_t c = b;		\
  u_char *dst = (u_char *)&a;	\
  u_char *src = (u_char *)&c;	\
  *(dst + 0) = *(src + 0);	\
  *(dst + 1) = *(src + 1);	\
}
#endif

#if !defined NEED_ALIGN
#define Assign32(a, b) a = b
#else
#define Assign32(a, b)		\
{             			\
  u_int32_t c = b;		\
  u_char *dst = (u_char *)&a;	\
  u_char *src = (u_char *)&c;	\
  *(dst + 0) = *(src + 0);	\
  *(dst + 1) = *(src + 1);	\
  *(dst + 2) = *(src + 2);	\
  *(dst + 3) = *(src + 3);	\
}
#endif

struct plugin_requests {
  u_int8_t bpf_filter;		/* On-request packet copy for BPF purposes */
  void *key_value_table;	/* load_id_file() : table to be filled in from key-value files */
  int line_num;			/* load_id_file() : line number being processed */
};

#include "pmacct-defines.h"
#include "network.h"
#include "pretag.h"
#include "cfg.h"
#include "util.h"
#include "xflow_status.h"
#include "log.h"
#include "once.h"
#include "mpls.h"

/*
 * htonvl(): host to network (byte ordering) variable length
 * ntohvl(): network to host (byer ordering) variable length
 *
 * This is in order to handle meaningfully both 32bit and 64bit
 * counters avoiding a bunch of #if-#else statements.
 */
#if defined HAVE_64BIT_COUNTERS
#define htonvl(x) pm_htonll(x)
#define ntohvl(x) pm_ntohll(x)
#define CACHE_THRESHOLD UINT64T_THRESHOLD
#else
#define htonvl(x) htonl(x)
#define ntohvl(x) ntohl(x)
#define CACHE_THRESHOLD UINT32T_THRESHOLD
#endif

/* structures */
struct pcap_device {
  pcap_t *dev_desc;
  int link_type;
  int active;
  struct _devices_struct *data; 
};

struct pcap_callback_data {
  u_char * f_agent; 
  u_char * idt; 
  u_char * bta_table;
  u_char * bpas_table; 
  u_char * blp_table; 
  u_char * bmed_table; 
  u_char * biss_table; 
  struct pcap_device *device;
  u_int16_t ifindex_in;
  u_int16_t ifindex_out;
};

struct _protocols_struct {
  char name[PROTO_LEN];
  int number;
};

struct _devices_struct {
  void (*handler)(const struct pcap_pkthdr *, register struct packet_ptrs *);
  int link_type;
};

struct smallbuf {
  u_char base[SRVBUFLEN];
  u_char *end;
  u_char *ptr;
};	

struct largebuf {
  u_char base[LARGEBUFLEN];
  u_char *end;
  u_char *ptr;
};

struct child_ctl {
  u_int16_t active;
  u_int16_t retired;
  u_int32_t flags;
};

#define INIT_BUF(x) \
	memset(x.base, 0, sizeof(x.base)); \
	x.end = x.base+sizeof(x.base); \
	x.ptr = x.base;

/* prototypes */
void startup_handle_falling_child();
void handle_falling_child();
void ignore_falling_child();
void my_sigint_handler();
void reload();
void push_stats();
void reload_maps();

#if (!defined __LL_C)
#define EXT extern
#else
#define EXT
#endif
EXT char sll_mac[2][ETH_ADDR_LEN];

EXT void null_handler(const struct pcap_pkthdr *, register struct packet_ptrs *);
EXT void eth_handler(const struct pcap_pkthdr *, register struct packet_ptrs *);
EXT void fddi_handler(const struct pcap_pkthdr *, register struct packet_ptrs *);
EXT void tr_handler(const struct pcap_pkthdr *, register struct packet_ptrs *);
EXT u_int16_t mpls_handler(u_char *, u_int16_t *, u_int16_t *, register struct packet_ptrs *);
EXT void ppp_handler(const struct pcap_pkthdr *, register struct packet_ptrs *);
EXT void ieee_802_11_handler(const struct pcap_pkthdr *, register struct packet_ptrs *);
EXT void sll_handler(const struct pcap_pkthdr *, register struct packet_ptrs *);
EXT void raw_handler(const struct pcap_pkthdr *, register struct packet_ptrs *);
EXT u_char *llc_handler(const struct pcap_pkthdr *, u_int, register u_char *, register struct packet_ptrs *);
EXT void chdlc_handler(const struct pcap_pkthdr *, register struct packet_ptrs *);
#undef EXT

#if (!defined __NL_C)
#define EXT extern
#else
#define EXT
#endif
EXT int ip_handler(register struct packet_ptrs *);
EXT int ip6_handler(register struct packet_ptrs *);
EXT int gtp_tunnel_func(register struct packet_ptrs *);
EXT int gtp_tunnel_configurator(struct tunnel_handler *, char *);
EXT void tunnel_registry_init();
EXT void pcap_cb(u_char *, const struct pcap_pkthdr *, const u_char *);
EXT int PM_find_id(struct id_table *, struct packet_ptrs *, pm_id_t *, pm_id_t *);
EXT void compute_once();
#undef EXT

#if (!defined __PMACCTD_C) && (!defined __NFACCTD_C) && (!defined __SFACCTD_C) && (!defined __UACCTD_C)
#define EXT extern
#else
#define EXT
#endif
EXT struct host_addr mcast_groups[MAX_MCAST_GROUPS];
EXT int reload_map, reload_map_bgp_thread, data_plugins, tee_plugins;
EXT struct timeval reload_map_tstamp;
EXT struct child_ctl sql_writers;
#undef EXT

size_t strlcpy(char *, const char *, size_t);

/* global variables */
pcap_t *glob_pcapt;
struct pcap_stat ps;

#if (!defined __PMACCTD_C) && (!defined __NFACCTD_C) && (!defined __SFACCTD_C) && (!defined __UACCTD_C)
extern int debug;
extern int have_num_memory_pools; /* global getopt() stuff */
extern struct configuration config; /* global configuration structure */ 
extern struct plugins_list_entry *plugins_list; /* linked list of each plugin configuration */
extern pid_t failed_plugins[MAX_N_PLUGINS]; /* plugins failed during startup phase */
extern u_char dummy_tlhdr[16];
#endif

#endif /* _PMACCT_H_ */
