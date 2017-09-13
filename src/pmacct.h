/*  
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2017 by Paolo Lucente
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

#if defined HAVE_MALLOPT
#include <malloc.h>
#endif

#if defined (HAVE_ZLIB)
#include <zlib.h>
#endif

#include <ctype.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <signal.h>
#include <syslog.h>
#include <sys/resource.h>
#include <dirent.h>
#include <limits.h>
#include "pmsearch.h"

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
#if defined (WITH_GEOIPV2)
#error "--enable-geoip and --enable-geoipv2 are mutually exclusive"
#endif
#endif
#if defined (WITH_GEOIPV2)
#include <maxminddb.h>
#endif

#if defined (WITH_NDPI)
#include <ndpi_main.h>
#endif

#if defined (WITH_ZMQ)
#include <zmq.h>
#endif

#include "pmacct-build.h"

#if !defined ETHER_ADDRSTRLEN
#define ETHER_ADDRSTRLEN 18
#endif
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

/* structure to pass requests: probably plugin_requests
   name outdated at this point .. */

struct ptm_complex {
  int load_ptm_plugin;		/* load_pre_tag_map(): input plugin type ID */
  int load_ptm_res;		/* load_pre_tag_map(): result */
  int exec_ptm_dissect;		/* exec_plugins(): TRUE if at least one plugin returned load_ptm_res == TRUE */
  int exec_ptm_res;		/* exec_plugins(): input to be matched against list->cfg.ptm_complex */ 
};

struct plugin_requests {
  u_int8_t bpf_filter;		/* On-request packet copy for BPF purposes */

  /* load_id_file() stuff */
  void *key_value_table;	/* table to be filled in from key-value files */
  int line_num;			/* line number being processed */
  int map_entries;		/* number of map entries: wins over global setting */
  int map_row_len;		/* map row length: wins over global setting */
  struct ptm_complex ptm_c;	/* flags a map that requires parsing of the records (ie. tee plugin) */
};

typedef struct {
  char *val;
  u_int16_t len;
} pm_hash_key_t;

typedef struct {
  pm_hash_key_t key;
  u_int16_t off;
} pm_hash_serial_t;

#if (defined WITH_JANSSON)
#include <jansson.h>
#endif

#if (defined WITH_AVRO)
#include <avro.h>
#endif

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
  int errors; /* error count when reading from a savefile */
  struct _devices_struct *data; 
};

struct pcap_callback_data {
  u_char * f_agent; 
  u_char * bta_table;
  u_char * bpas_table; 
  u_char * blp_table; 
  u_char * bmed_table; 
  u_char * biss_table; 
  struct pcap_device *device;
  u_int32_t ifindex_in;
  u_int32_t ifindex_out;
};

struct _protocols_struct {
  char name[PROTO_LEN];
  int number;
};

struct _devices_struct {
  void (*handler)(const struct pcap_pkthdr *, register struct packet_ptrs *);
  int link_type;
};

struct _primitives_matrix_struct {
  char name[PRIMITIVE_LEN];
  u_int8_t pmacctd;
  u_int8_t uacctd;
  u_int8_t nfacctd;
  u_int8_t sfacctd;
  u_int8_t pmtelemetryd;
  u_int8_t pmbgpd;
  u_int8_t pmbmpd;
  char desc[PRIMITIVE_DESC_LEN];
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

struct child_ctl2 {
  pid_t *list;
  u_int16_t active;
  u_int16_t max;
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
EXT void set_index_pkt_ptrs(struct packet_ptrs *);
EXT ssize_t recvfrom_savefile(struct pcap_device *, void **, struct sockaddr *, struct timeval **);
#undef EXT

#ifndef HAVE_STRLCPY
size_t strlcpy(char *, const char *, size_t);
#endif

#if (defined WITH_JANSSON)
#if (!defined HAVE_JSON_OBJECT_UPDATE_MISSING)
int json_object_update_missing(json_t *, json_t *);
#endif
#endif

void
#ifdef __STDC__
pm_setproctitle(const char *fmt, ...);
#else /* __STDC__ */
#error
pm_setproctitle(fmt, va_alist);
#endif /* __STDC__ */

void
initsetproctitle(int, char**, char**);

/* global variables */
#if (!defined __PMACCTD_C) && (!defined __NFACCTD_C) && (!defined __SFACCTD_C) && (!defined __UACCTD_C) && (!defined __PMTELEMETRYD_C) && (!defined __PMBGPD_C) && (!defined __PMBMPD_C)
#define EXT extern
#else
#define EXT
#endif
EXT struct host_addr mcast_groups[MAX_MCAST_GROUPS];
EXT int reload_map, reload_map_exec_plugins, reload_geoipv2_file;
EXT int reload_map_bgp_thread, reload_log_bgp_thread, reload_log_bmp_thread;
EXT int reload_log_sf_cnt, reload_log_telemetry_thread;
EXT int data_plugins, tee_plugins;
EXT struct timeval reload_map_tstamp;
EXT struct child_ctl2 dump_writers;
EXT int debug;
EXT struct configuration config; /* global configuration structure */
EXT struct plugins_list_entry *plugins_list; /* linked list of each plugin configuration */
EXT pid_t failed_plugins[MAX_N_PLUGINS]; /* plugins failed during startup phase */
EXT u_char dummy_tlhdr[16];
EXT pcap_t *glob_pcapt;
EXT struct pcap_stat ps;
#undef EXT
#endif /* _PMACCT_H_ */
