/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2008 by Paolo Lucente
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

/* defines */
#define IPFT_HASHSZ 256 
#define IPF_TIMEOUT 60 
#define PRUNE_INTERVAL 7200
#define EMER_PRUNE_INTERVAL 60
#define PRUNE_OFFSET 1800 
#define DEFAULT_FRAG_BUFFER_SIZE 4096000 /* 4 Mb */

/* structures */
struct ip_fragment {
  unsigned char tlhdr[8];	/* upper level info */ 
  u_int8_t got_first;		/* got first packet ? */
  u_int16_t a;			/* bytes accumulator */
  u_int16_t pa;			/* packets accumulator */
  time_t deadline;		/* timeout timestamp */
  u_int16_t ip_id;
  u_int8_t ip_p;
  u_int32_t ip_src;
  u_int32_t ip_dst;
  u_int16_t bucket;
  struct ip_fragment *lru_next;
  struct ip_fragment *lru_prev;
  struct ip_fragment *next;
  struct ip_fragment *prev;
};

struct lru_l {
  struct ip_fragment *root;
  struct ip_fragment *last;
};

#if defined ENABLE_IPV6
struct ip6_fragment {
  unsigned char tlhdr[8];       /* upper level info */
  u_int8_t got_first;           /* got first packet ? */
  u_int16_t a;                  /* bytes accumulator */
  u_int16_t pa;			/* packets accumulator */
  time_t deadline;		/* timeout timestamp */
  u_int32_t id;
  u_int32_t src[4];
  u_int32_t dst[4];
  u_int16_t bucket;
  struct ip6_fragment *lru_next;
  struct ip6_fragment *lru_prev;
  struct ip6_fragment *next;
  struct ip6_fragment *prev;
};

struct lru_l6 {
  struct ip6_fragment *root;
  struct ip6_fragment *last;
};
#endif

/* global vars */
struct ip_fragment *ipft[IPFT_HASHSZ];
struct lru_l lru_list;

#if defined ENABLE_IPV6
struct ip6_fragment *ipft6[IPFT_HASHSZ];
struct lru_l6 lru_list6;
#endif

/* prototypes */
#if (!defined __IP_FRAG_C)
#define EXT extern
#else
#define EXT
#endif
EXT void init_ip_fragment_handler(); /* wrapper */ 
EXT void init_ip4_fragment_handler(); 
EXT int ip_fragment_handler(struct packet_ptrs *); 
EXT int find_fragment(u_int32_t, struct packet_ptrs *); 
EXT int create_fragment(u_int32_t, struct ip_fragment *, u_int8_t, unsigned int, struct packet_ptrs *); 
EXT unsigned int hash_fragment(u_int16_t, u_int32_t, u_int32_t, u_int8_t);
EXT void prune_old_fragments(u_int32_t, u_int32_t); 
EXT void notify_orphan_fragment(struct ip_fragment *);

#if defined ENABLE_IPV6
EXT void init_ip6_fragment_handler();
EXT int ip6_fragment_handler6(struct packet_ptrs *, struct ip6_frag *);
EXT unsigned int hash_fragment6(u_int32_t, struct in6_addr *, struct in6_addr *);
EXT int find_fragment6(u_int32_t, struct packet_ptrs *, struct ip6_frag *);
EXT int create_fragment6(u_int32_t, struct ip6_fragment *, u_int8_t, unsigned int, struct packet_ptrs *, struct ip6_frag *);
EXT void prune_old_fragments6(u_int32_t, u_int32_t); 
EXT void notify_orphan_fragment6(struct ip6_fragment *);
#endif
#undef EXT
