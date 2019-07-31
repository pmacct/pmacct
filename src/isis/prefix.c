/*
 * Prefix related functions.
 * Copyright (C) 1997, 98, 99 Kunihiro Ishiguro
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

#include "pmacct.h"
#include "isis.h"

#include "prefix.h"
#include "sockunion.h"

/* Maskbit. */
static const u_char maskbit[] = {0x00, 0x80, 0xc0, 0xe0, 0xf0,
			         0xf8, 0xfc, 0xfe, 0xff};

/* Number of bits in prefix type. */
#ifndef PNBBY
#define PNBBY 8
#endif /* PNBBY */

#define MASKBIT(offset)  ((0xff << (PNBBY - (offset))) & 0xff)

/* If n includes p prefix then return 1 else return 0. */
int
isis_prefix_match (const struct isis_prefix *n, const struct isis_prefix *p)
{
  int offset;
  int shift;
  const u_char *np, *pp;

  /* If n's prefix is longer than p's one return 0. */
  if (n->prefixlen > p->prefixlen)
    return 0;

  /* Set both prefix's head pointer. */
  np = (const u_char *)&n->u.prefix;
  pp = (const u_char *)&p->u.prefix;
  
  offset = n->prefixlen / PNBBY;
  shift =  n->prefixlen % PNBBY;

  if (shift)
    if (maskbit[shift] & (np[offset] ^ pp[offset]))
      return 0;
  
  while (offset--)
    if (np[offset] != pp[offset])
      return 0;
  return 1;
}

/* Copy prefix from src to dest. */
void
isis_prefix_copy (struct isis_prefix *dest, const struct isis_prefix *src)
{
  dest->family = src->family;
  dest->prefixlen = src->prefixlen;

  if (src->family == AF_INET)
    dest->u.prefix4 = src->u.prefix4;
  else if (src->family == AF_INET6)
    dest->u.prefix6 = src->u.prefix6;
  else
    {
      Log(LOG_ERR, "ERROR ( %s/core/ISIS ): isis_prefix_copy(): Unknown address family %d\n", config.name, src->family);
      assert (0);
    }

  dest->adv_router = src->adv_router;
}

/* 
 * Return 1 if the address/netmask contained in the prefix structure
 * is the same, and else return 0.  For this routine, 'same' requires
 * that not only the prefix length and the network part be the same,
 * but also the host part.  Thus, 10.0.0.1/8 and 10.0.0.2/8 are not
 * the same.  Note that this routine has the same return value sense
 * as '==' (which is different from isis_prefix_cmp).
 */
int
isis_prefix_same (const struct isis_prefix *p1, const struct isis_prefix *p2)
{
  if (p1->family == p2->family && p1->prefixlen == p2->prefixlen)
    {
      if (p1->family == AF_INET)
	if (IPV4_ADDR_SAME (&p1->u.prefix, &p2->u.prefix))
	  return 1;
      if (p1->family == AF_INET6 )
	if (IPV6_ADDR_SAME (&p1->u.prefix, &p2->u.prefix))
	  return 1;
    }
  return 0;
}

/*
 * Return 0 if the network prefixes represented by the struct prefix
 * arguments are the same prefix, and 1 otherwise.  Network prefixes
 * are considered the same if the prefix lengths are equal and the
 * network parts are the same.  Host bits (which are considered masked
 * by the prefix length) are not significant.  Thus, 10.0.0.1/8 and
 * 10.0.0.2/8 are considered equivalent by this routine.  Note that
 * this routine has the same return sense as strcmp (which is different
 * from isis_prefix_same).
 */
int
isis_prefix_cmp (const struct isis_prefix *p1, const struct isis_prefix *p2)
{
  int offset;
  int shift;

  /* Set both prefix's head pointer. */
  const u_char *pp1 = (const u_char *)&p1->u.prefix;
  const u_char *pp2 = (const u_char *)&p2->u.prefix;

  if (p1->family != p2->family || p1->prefixlen != p2->prefixlen)
    return 1;

  offset = p1->prefixlen / 8;
  shift = p1->prefixlen % 8;

  if (shift)
    if (maskbit[shift] & (pp1[offset] ^ pp2[offset]))
      return 1;

  while (offset--)
    if (pp1[offset] != pp2[offset])
      return 1;

  return 0;
}

/* Return prefix family type string. */
const char *
isis_prefix_family_str (const struct isis_prefix *p)
{
  if (p->family == AF_INET)
    return "inet";
  if (p->family == AF_INET6)
    return "inet6";
  return "unspec";
}

/* Allocate new prefix_ipv4 structure. */
struct prefix_ipv4 *
isis_prefix_ipv4_new ()
{
  struct prefix_ipv4 *p;

  /* Call isis_prefix_new to allocate a full-size struct isis_prefix to avoid problems
     where the struct prefix_ipv4 is cast to struct isis_prefix and unallocated
     bytes were being referenced (e.g. in structure assignments). */
  p = (struct prefix_ipv4 *)isis_prefix_new();
  p->family = AF_INET;
  return p;
}

/* When string format is invalid return 0. */
int
isis_str2prefix_ipv4 (const char *str, struct prefix_ipv4 *p)
{
  int ret;
  int plen;
  char *pnt;
  char *cp;

  /* Find slash inside string. */
  pnt = strchr (str, '/');

  /* String doesn't contail slash. */
  if (pnt == NULL) 
    {
      /* Convert string to prefix. */
      ret = inet_aton (str, &p->prefix);
      if (ret == 0)
	return 0;

      /* If address doesn't contain slash we assume it host address. */
      p->family = AF_INET;
      p->prefixlen = IPV4_MAX_BITLEN;

      return ret;
    }
  else
    {
      cp = calloc(1, (pnt - str) + 1);
      strncpy (cp, str, pnt - str);
      *(cp + (pnt - str)) = '\0';
      ret = inet_aton (cp, &p->prefix);
      free(cp);

      /* Get prefix length. */
      plen = (u_char) atoi (++pnt);
      if (plen > IPV4_MAX_PREFIXLEN)
	return 0;

      p->family = AF_INET;
      p->prefixlen = plen;
    }

  return ret;
}

/* Convert masklen into IP address's netmask. */
void
isis_masklen2ip (int masklen, struct in_addr *netmask)
{
  u_char *pnt;
  int bit;
  int offset;

  memset (netmask, 0, sizeof (struct in_addr));
  pnt = (unsigned char *) netmask;

  offset = masklen / 8;
  bit = masklen % 8;
  
  while (offset--)
    *pnt++ = 0xff;

  if (bit)
    *pnt = maskbit[bit];
}

/* Convert IP address's netmask into integer. We assume netmask is
   sequential one. Argument netmask should be network byte order. */
u_char
isis_ip_masklen (struct in_addr netmask)
{
  u_char len;
  u_char *pnt;
  u_char *end;
  u_char val;

  len = 0;
  pnt = (u_char *) &netmask;
  end = pnt + 4;

  while ((pnt < end) && (*pnt == 0xff))
    {
      len+= 8;
      pnt++;
    } 

  if (pnt < end)
    {
      val = *pnt;
      while (val)
	{
	  len++;
	  val <<= 1;
	}
    }
  return len;
}

/* Apply mask to IPv4 prefix. */
void
isis_apply_mask_ipv4 (struct prefix_ipv4 *p)
{
  u_char *pnt;
  int index;
  int offset;

  index = p->prefixlen / 8;

  if (index < 4)
    {
      pnt = (u_char *) &p->prefix;
      offset = p->prefixlen % 8;

      pnt[index] &= maskbit[offset];
      index++;

      while (index < 4)
	pnt[index++] = 0;
    }
}

/* Allocate a new ip version 6 route */
struct prefix_ipv6 *
isis_prefix_ipv6_new (void)
{
  struct prefix_ipv6 *p;

  /* Allocate a full-size struct isis_prefix to avoid problems with structure
     size mismatches. */
  p = (struct prefix_ipv6 *)isis_prefix_new();
  p->family = AF_INET6;
  return p;
}

/* Free prefix for IPv6. */
void
isis_prefix_ipv6_free (struct prefix_ipv6 *p)
{
  isis_prefix_free((struct isis_prefix *)p);
}

/* If given string is valid return pin6 else return NULL */
int
isis_str2prefix_ipv6 (const char *str, struct prefix_ipv6 *p)
{
  char *pnt;
  char *cp;
  int ret;

  pnt = strchr (str, '/');

  /* If string doesn't contain `/' treat it as host route. */
  if (pnt == NULL) 
    {
      ret = inet_pton (AF_INET6, str, &p->prefix);
      if (ret == 0)
	return 0;
      p->prefixlen = IPV6_MAX_BITLEN;
    }
  else 
    {
      int plen;

      cp = calloc(0, (pnt - str) + 1);
      strncpy (cp, str, pnt - str);
      *(cp + (pnt - str)) = '\0';
      ret = inet_pton (AF_INET6, cp, &p->prefix);
      free (cp);
      if (ret == 0)
	return 0;
      plen = (u_char) atoi (++pnt);
      if (plen > 128)
	return 0;
      p->prefixlen = plen;
    }
  p->family = AF_INET6;

  return ret;
}

/* Convert struct in6_addr netmask into integer.
 * FIXME return u_char as isis_ip_maskleni() does. */
int
isis_ip6_masklen (struct in6_addr netmask)
{
  int len = 0;
  unsigned char val;
  unsigned char *pnt;
  
  pnt = (unsigned char *) & netmask;

  while ((*pnt == 0xff) && len < 128) 
    {
      len += 8;
      pnt++;
    } 
  
  if (len < 128) 
    {
      val = *pnt;
      while (val) 
	{
	  len++;
	  val <<= 1;
	}
    }
  return len;
}

void
isis_masklen2ip6 (int masklen, struct in6_addr *netmask)
{
  unsigned char *pnt;
  int bit;
  int offset;

  memset (netmask, 0, sizeof (struct in6_addr));
  pnt = (unsigned char *) netmask;

  offset = masklen / 8;
  bit = masklen % 8;

  while (offset--)
    *pnt++ = 0xff;

  if (bit)
    *pnt = maskbit[bit];
}

void
isis_apply_mask_ipv6 (struct prefix_ipv6 *p)
{
  u_char *pnt;
  int index;
  int offset;

  index = p->prefixlen / 8;

  if (index < 16)
    {
      pnt = (u_char *) &p->prefix;
      offset = p->prefixlen % 8;

      pnt[index] &= maskbit[offset];
      index++;

      while (index < 16)
	pnt[index++] = 0;
    }
}

void
isis_str2in6_addr (const char *str, struct in6_addr *addr)
{
  int i;
  unsigned int x;

  /* %x must point to unsinged int */
  for (i = 0; i < 16; i++)
    {
      sscanf (str + (i * 2), "%02x", &x);
      addr->s6_addr[i] = x & 0xff;
    }
}

void
isis_apply_mask (struct isis_prefix *p)
{
  switch (p->family)
    {
      case AF_INET:
        isis_apply_mask_ipv4 ((struct prefix_ipv4 *)p);
        break;
      case AF_INET6:
        isis_apply_mask_ipv6 ((struct prefix_ipv6 *)p);
        break;
      default:
        break;
    }
  return;
}

/* Utility function of convert between struct isis_prefix <=> union sockunion.
 * FIXME This function isn't used anywhere. */
struct isis_prefix *
sockunion2prefix (const union sockunion *dest,
		  const union sockunion *mask)
{
  if (dest->sa.sa_family == AF_INET)
    {
      struct prefix_ipv4 *p;

      p = isis_prefix_ipv4_new ();
      p->family = AF_INET;
      p->prefix = dest->sin.sin_addr;
      p->prefixlen = isis_ip_masklen (mask->sin.sin_addr);
      return (struct isis_prefix *) p;
    }
  if (dest->sa.sa_family == AF_INET6)
    {
      struct prefix_ipv6 *p;

      p = isis_prefix_ipv6_new ();
      p->family = AF_INET6;
      p->prefixlen = isis_ip6_masklen (mask->sin6.sin6_addr);
      memcpy (&p->prefix, &dest->sin6.sin6_addr, sizeof (struct in6_addr));
      return (struct isis_prefix *) p;
    }
  return NULL;
}

/* Utility function of convert between struct isis_prefix <=> union sockunion. */
struct isis_prefix *
sockunion2hostprefix (const union sockunion *su)
{
  if (su->sa.sa_family == AF_INET)
    {
      struct prefix_ipv4 *p;

      p = isis_prefix_ipv4_new ();
      p->family = AF_INET;
      p->prefix = su->sin.sin_addr;
      p->prefixlen = IPV4_MAX_BITLEN;
      return (struct isis_prefix *) p;
    }
  if (su->sa.sa_family == AF_INET6)
    {
      struct prefix_ipv6 *p;

      p = isis_prefix_ipv6_new ();
      p->family = AF_INET6;
      p->prefixlen = IPV6_MAX_BITLEN;
      memcpy (&p->prefix, &su->sin6.sin6_addr, sizeof (struct in6_addr));
      return (struct isis_prefix *) p;
    }
  return NULL;
}

int
isis_prefix_blen (const struct isis_prefix *p)
{
  switch (p->family) 
    {
    case AF_INET:
      return IPV4_MAX_BYTELEN;
      break;
    case AF_INET6:
      return IPV6_MAX_BYTELEN;
      break;
    }
  return 0;
}

/* Generic function for conversion string to struct prefix. */
int
isis_str2prefix (const char *str, struct isis_prefix *p)
{
  int ret;

  /* First we try to convert string to struct prefix_ipv4. */
  ret = isis_str2prefix_ipv4 (str, (struct prefix_ipv4 *) p);
  if (ret)
    return ret;

  /* Next we try to convert string to struct prefix_ipv6. */
  ret = isis_str2prefix_ipv6 (str, (struct prefix_ipv6 *) p);
  if (ret)
    return ret;

  return 0;
}

int
isis_prefix2str (const struct isis_prefix *p, char *str, int size)
{
  char buf[BUFSIZ];

  inet_ntop (p->family, &p->u.prefix, buf, BUFSIZ);
  snprintf (str, size, "%s/%d", buf, p->prefixlen);
  return 0;
}

struct isis_prefix *
isis_prefix_new ()
{
  struct isis_prefix *p;

  p = calloc(1, sizeof *p);
  return p;
}

/* Free prefix structure. */
void
isis_prefix_free (struct isis_prefix *p)
{
  free(p);
}

/* Utility function to convert ipv4 netmask to prefixes 
   ex.) "1.1.0.0" "255.255.0.0" => "1.1.0.0/16"
   ex.) "1.0.0.0" NULL => "1.0.0.0/8"                   */
int
netmask_isis_str2prefix_str (const char *net_str, const char *mask_str,
			char *prefix_str)
{
  struct in_addr network;
  struct in_addr mask;
  u_char prefixlen;
  u_int32_t destination;
  int ret;

  ret = inet_aton (net_str, &network);
  if (! ret)
    return 0;

  if (mask_str)
    {
      ret = inet_aton (mask_str, &mask);
      if (! ret)
        return 0;

      prefixlen = isis_ip_masklen (mask);
    }
  else 
    {
      destination = ntohl (network.s_addr);

      if (network.s_addr == 0)
	prefixlen = 0;
      else if (IN_CLASSC (destination))
	prefixlen = 24;
      else if (IN_CLASSB (destination))
	prefixlen = 16;
      else if (IN_CLASSA (destination))
	prefixlen = 8;
      else
	return 0;
    }

  sprintf (prefix_str, "%s/%d", net_str, prefixlen);

  return 1;
}
