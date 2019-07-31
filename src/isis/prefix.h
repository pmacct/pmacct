/*
 * Prefix structure.
 * Copyright (C) 1998 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.  
 */

#ifndef _PREFIX_H_
#define _PREFIX_H_

#include "sockunion.h"

/*
 * A struct prefix contains an address family, a prefix length, and an
 * address.  This can represent either a 'network prefix' as defined
 * by CIDR, where the 'host bits' of the prefix are 0
 * (e.g. AF_INET:10.0.0.0/8), or an address and netmask
 * (e.g. AF_INET:10.0.0.9/8), such as might be configured on an
 * interface.
 */

/* IPv4 and IPv6 unified prefix structure. */
struct isis_prefix
{
  u_char family;
  u_char prefixlen;
  union 
  {
    u_char prefix;
    struct in_addr prefix4;
    struct in6_addr prefix6;
    u_char val[8];
  } u __attribute__ ((aligned (8)));
  struct in_addr adv_router;
};

#ifndef INET_ADDRSTRLEN
#define INET_ADDRSTRLEN 16
#endif /* INET_ADDRSTRLEN */

#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif /* INET6_ADDRSTRLEN */

#ifndef INET6_BUFSIZ
#define INET6_BUFSIZ 51
#endif /* INET6_BUFSIZ */

/* Max bit/byte length of IPv4 address. */
#define IPV4_MAX_BYTELEN    4
#define IPV4_MAX_BITLEN    32
#define IPV4_MAX_PREFIXLEN 32
#define IPV4_ADDR_CMP(D,S)   memcmp ((D), (S), IPV4_MAX_BYTELEN)
#define IPV4_ADDR_SAME(D,S)  (memcmp ((D), (S), IPV4_MAX_BYTELEN) == 0)
#define IPV4_ADDR_COPY(D,S)  memcpy ((D), (S), IPV4_MAX_BYTELEN)

#define IPV4_NET0(a)    ((((u_int32_t) (a)) & 0xff000000) == 0x00000000)
#define IPV4_NET127(a)  ((((u_int32_t) (a)) & 0xff000000) == 0x7f000000)
#define IPV4_LINKLOCAL(a) ((((u_int32_t) (a)) & 0xffff0000) == 0xa9fe0000)

/* Max bit/byte length of IPv6 address. */
#define IPV6_MAX_BYTELEN    16
#define IPV6_MAX_BITLEN    128
#define IPV6_MAX_PREFIXLEN 128
#define IPV6_ADDR_CMP(D,S)   memcmp ((D), (S), IPV6_MAX_BYTELEN)
#define IPV6_ADDR_SAME(D,S)  (memcmp ((D), (S), IPV6_MAX_BYTELEN) == 0)
#define IPV6_ADDR_COPY(D,S)  memcpy ((D), (S), IPV6_MAX_BYTELEN)

/* Count prefix size from mask length */
#define PSIZE(a) (((a) + 7) / (8))

/* Prefix's family member. */
#define PREFIX_FAMILY(p)  ((p)->family)

/* Check bit of the prefix. */
static inline unsigned int
prefix_bit (const u_char *prefix, const u_char prefixlen)
{
  unsigned int offset = prefixlen / 8;
  unsigned int shift  = 7 - (prefixlen % 8);

  return (prefix[offset] >> shift) & 1;
}

static inline unsigned int
prefix6_bit (const struct in6_addr *prefix, const u_char prefixlen)
{
  return prefix_bit((const u_char *) &prefix->s6_addr, prefixlen);
}

#define PREFIX_COPY_IPV4(DST, SRC)	\
	*((struct prefix_ipv4 *)(DST)) = *((const struct prefix_ipv4 *)(SRC));


#define PREFIX_COPY_IPV6(DST, SRC)	\
	*((struct prefix_ipv6 *)(DST)) = *((const struct prefix_ipv6 *)(SRC));

/* Prototypes. */
extern struct isis_prefix *isis_prefix_new (void);
extern void isis_prefix_free (struct isis_prefix *);
extern const char *isis_prefix_family_str (const struct isis_prefix *);
extern int isis_prefix_blen (const struct isis_prefix *);
extern int isis_str2prefix (const char *, struct isis_prefix *);
extern int isis_prefix2str (const struct isis_prefix *, char *, int);
extern int isis_prefix_match (const struct isis_prefix *, const struct isis_prefix *);
extern int isis_prefix_same (const struct isis_prefix *, const struct isis_prefix *);
extern int isis_prefix_cmp (const struct isis_prefix *, const struct isis_prefix *);
extern void isis_prefix_copy (struct isis_prefix *, const struct isis_prefix *);
extern void isis_apply_mask (struct isis_prefix *);
extern struct isis_prefix *sockunion2prefix (const union sockunion *, const union sockunion *);
extern struct isis_prefix *sockunion2hostprefix (const union sockunion *);
extern struct prefix_ipv4 *isis_prefix_ipv4_new (void);
extern int isis_str2prefix_ipv4 (const char *, struct prefix_ipv4 *);
extern void isis_apply_mask_ipv4 (struct prefix_ipv4 *);
extern u_char isis_ip_masklen (struct in_addr);
extern void isis_masklen2ip (int, struct in_addr *);
extern int netmask_isis_str2prefix_str (const char *, const char *, char *);
extern struct prefix_ipv6 *prefix_ipv6_new (void);
extern void isis_prefix_ipv6_free (struct prefix_ipv6 *);
extern int isis_str2prefix_ipv6 (const char *, struct prefix_ipv6 *);
extern void isis_apply_mask_ipv6 (struct prefix_ipv6 *);
extern int isis_ip6_masklen (struct in6_addr);
extern void isis_masklen2ip6 (int, struct in6_addr *);
extern void isis_str2in6_addr (const char *, struct in6_addr *);
extern const char *isis_inet6_ntoa (struct in6_addr);

#endif /* _PREFIX_H_ */
