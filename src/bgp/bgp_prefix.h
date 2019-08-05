/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2019 by Paolo Lucente
*/

/*
 * Originally based on Quagga prefix structure which is:
 *
 * Copyright (C) 1998 Kunihiro Ishiguro
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

#ifndef _BGP_PREFIX_H_
#define _BGP_PREFIX_H_

#define PREFIX_MASKSTRLEN	4
#define PREFIX_STRLEN		(INET6_ADDRSTRLEN + PREFIX_MASKSTRLEN)

/*
 * A struct prefix contains an address family, a prefix length, and an
 * address.  This can represent either a 'network prefix' as defined
 * by CIDR, where the 'host bits' of the prefix are 0
 * (e.g. AF_INET:10.0.0.0/8), or an address and netmask
 * (e.g. AF_INET:10.0.0.9/8), such as might be configured on an
 * interface.
 */

/* IPv4 and IPv6 unified prefix structure. */
struct prefix
{
  u_char family;
  u_char prefixlen;
  union 
  {
    u_char prefix;
    struct in_addr prefix4;
    struct in6_addr prefix6;
  } u __attribute__ ((aligned (8)));
};

/* IPv4 prefix structure. */
struct prefix_ipv4
{
  u_char family;
  u_char prefixlen;
  struct in_addr prefix __attribute__ ((aligned (8)));
};

/* IPv6 prefix structure. */
struct prefix_ipv6
{
  u_char family;
  u_char prefixlen;
  struct in6_addr prefix __attribute__ ((aligned (8)));
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

/* Prototypes. */
extern int afi2family (int);
extern int family2afi (int);

extern struct prefix *prefix_new (void);
extern void prefix_free (struct prefix *);
extern const char *prefix_family_str (const struct prefix *);
extern int prefix_blen (const struct prefix *);
extern int str2prefix (const char *, struct prefix *);
extern int prefix2str (const struct prefix *, char *, int);
extern int prefix_match (const struct prefix *, const struct prefix *);
extern int prefix_same (const struct prefix *, const struct prefix *);
extern int prefix_cmp (const struct prefix *, const struct prefix *);
extern void prefix_copy (struct prefix *dest, const struct prefix *src);
extern void apply_mask (struct prefix *);

extern struct prefix_ipv4 *prefix_ipv4_new (void);
extern void prefix_ipv4_free (struct prefix_ipv4 *);
extern int str2prefix_ipv4 (const char *, struct prefix_ipv4 *);
extern void apply_mask_ipv4 (struct prefix_ipv4 *);

#define PREFIX_COPY_IPV4(DST, SRC)	\
	*((struct prefix_ipv4 *)(DST)) = *((const struct prefix_ipv4 *)(SRC));

extern int prefix_ipv4_any (const struct prefix_ipv4 *);
extern void apply_classful_mask_ipv4 (struct prefix_ipv4 *);

extern u_char ip_masklen (struct in_addr);
extern void masklen2ip (int, struct in_addr *);
/* returns the network portion of the host address */
extern in_addr_t ipv4_network_addr (in_addr_t hostaddr, int masklen);
/* given the address of a host on a network and the network mask length,
 * calculate the broadcast address for that network;
 * special treatment for /31: returns the address of the other host
 * on the network by flipping the host bit */
extern in_addr_t ipv4_broadcast_addr (in_addr_t hostaddr, int masklen);

extern int netmask_str2prefix_str (const char *, const char *, char *);

extern struct prefix_ipv6 *prefix_ipv6_new (void);
extern void prefix_ipv6_free (struct prefix_ipv6 *);
extern int str2prefix_ipv6 (const char *, struct prefix_ipv6 *);
extern void apply_mask_ipv6 (struct prefix_ipv6 *);

#define PREFIX_COPY_IPV6(DST, SRC)	\
	*((struct prefix_ipv6 *)(DST)) = *((const struct prefix_ipv6 *)(SRC));

extern int ip6_masklen (struct in6_addr);
extern void masklen2ip6 (int, struct in6_addr *);

extern void str2in6_addr (const char *, struct in6_addr *);
extern const char *inet6_ntoa (struct in6_addr);

extern int all_digit (const char *);

#endif
