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

#define __ADDR_C

#include "pmacct.h"
#include "addr.h"

static const char hex[] = "0123456789abcdef";

/*
 * str_to_addr() converts a string into a supported family address
 */
unsigned int str_to_addr(const char *str, struct host_addr *a)
{
  if (inet_aton(str, &a->address.ipv4)) {
    a->family = AF_INET;
    return a->family;
  }
#if defined ENABLE_IPV6
  if (inet_pton(AF_INET6, str, &a->address.ipv6) > 0) {
    a->family = AF_INET6;
    return a->family;
  }
#endif

  return 0;
}

/*
 * addr_to_str() converts a supported family addres into a string
 * 'str' length is not checked and assumed to be INET6_ADDRSTRLEN 
 */
unsigned int addr_to_str(char *str, const struct host_addr *a)
{
  if (a->family == AF_INET) {
    inet_ntop(AF_INET, &a->address.ipv4, str, INET6_ADDRSTRLEN); 
    return a->family;
  }
#if defined ENABLE_IPV6
  if (a->family == AF_INET6) {
    inet_ntop(AF_INET6, &a->address.ipv6, str, INET6_ADDRSTRLEN); 
    return a->family;
  }
#endif
#if defined ENABLE_PLABEL
  if (a->family == AF_PLABEL) {
    strlcpy(str, a->address.plabel, INET6_ADDRSTRLEN);
    return a->family;
  }
#endif

  memset(str, 0, INET6_ADDRSTRLEN);

  return 0;
}

/*
 * str_to_addr_mask() converts a string into a supported family address
 */
unsigned int str_to_addr_mask(const char *str, struct host_addr *a, struct host_mask *m)
{
  char *delim = NULL, *net = NULL, *mask = NULL;
  unsigned int family = 0, index = 0, j;

  if (!str || !a || !m) return family;

  net = (char *) str;

  delim = strchr(str, '/');
  if (delim) {
    *delim = '\0';
    mask = delim+1;
  }
  
  family = str_to_addr(str, a);
  if (delim) *delim = '/'; 

  if (family) {
    if (mask) {
      index = atoi(mask);
      if (family == AF_INET) {
        if (index > 32) goto error;
        else {
	  m->mask.m4 = htonl((index == 32) ? 0xffffffffUL : ~(0xffffffffUL >> index));
	  a->address.ipv4.s_addr &= m->mask.m4;
        }
      }
#if defined ENABLE_IPV6
      else if (family == AF_INET6) {
        if (index > 128) goto error;

        for (j = 0; j < 4 && index >= 32; j++, index -= 32) m->mask.m6[j] = 0xffffffffU;
	if (j < 4 && index) m->mask.m6[j] = htonl(~(0xffffffffU >> index));

        for (j = 0; j < 4; j++) a->address.ipv6.s6_addr[j] &= m->mask.m6[j];
      }
#endif
      else goto error;
    }
    /* if no mask: set ipv4 mask to /32 and ipv6 mask to /128 */
    else {
      if (family == AF_INET) m->mask.m4 = 0xffffffffUL;
#if defined ENABLE_IPV6
      else if (family == AF_INET6) for (j = 0; j < 4; j++) m->mask.m6[j] = 0xffffffffU;
#endif
      else goto error;
    }

    m->family = family;
  }

  return family;

  error:
  a->family = 0;
  m->family = 0;
  return 0;
}

/*
 * addr_to_sa() converts a supported family address into a sockaddr 
 * structure 
 */
unsigned int addr_to_sa(struct sockaddr *sa, struct host_addr *a, u_int16_t port)
{
  struct sockaddr_in *sa4 = (struct sockaddr_in *)sa;
#if defined ENABLE_IPV6
  struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)sa;
#endif

  if (a->family == AF_INET) {
    sa->sa_family = AF_INET;
    sa4->sin_addr.s_addr = a->address.ipv4.s_addr;
    sa4->sin_port = htons(port);
    return sizeof(struct sockaddr_in);
  }
#if defined ENABLE_IPV6
  if (a->family == AF_INET6) {
    sa->sa_family = AF_INET6;
    ip6_addr_cpy(&sa6->sin6_addr, &a->address.ipv6);
    sa6->sin6_port = htons(port);
    return sizeof(struct sockaddr_in6); 
  }
#endif

  memset(sa, 0, sizeof(struct sockaddr));
  return 0;
}

/*
 * sa_to_addr() converts a sockaddr structure into a supported family
 * address 
 */
unsigned int sa_to_addr(struct sockaddr *sa, struct host_addr *a, u_int16_t *port)
{
  struct sockaddr_in *sa4 = (struct sockaddr_in *)sa;
#if defined ENABLE_IPV6
  struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)sa;
#endif
  
  if (sa->sa_family == AF_INET) {
    a->family = AF_INET;
    a->address.ipv4.s_addr = sa4->sin_addr.s_addr;
    *port = ntohs(sa4->sin_port);
    return sizeof(struct sockaddr_in);
  }
#if defined ENABLE_IPV6
  if (sa->sa_family == AF_INET6) {
    a->family = AF_INET6;
    ip6_addr_cpy(&a->address.ipv6, &sa6->sin6_addr);
    *port = ntohs(sa6->sin6_port);
    return sizeof(struct sockaddr_in6);
  }
#endif

  memset(a, 0, sizeof(struct host_addr));
  return 0;
}

/*
 * sa_addr_cmp(): compare two IP addresses: the first encapsulated into a
 * 'struct sockaddr' and the second into a 'struct host_addr'.
 * returns 0 if they match; 1 if they don't match; -1 to signal a generic
 * error (e.g. unsupported family mismatch).
 */
int sa_addr_cmp(struct sockaddr *sa, struct host_addr *a)
{
  struct sockaddr_in *sa4 = (struct sockaddr_in *)sa;
#if defined ENABLE_IPV6
  struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)sa;
  struct sockaddr_in6 sa6_local;
#endif

  if (a->family == AF_INET && sa->sa_family == AF_INET) {
    if (sa4->sin_addr.s_addr == a->address.ipv4.s_addr) return FALSE;
    else return TRUE; 
  }
#if defined ENABLE_IPV6
  if (a->family == AF_INET6 && sa->sa_family == AF_INET6) {
    if (!ip6_addr_cmp(&sa6->sin6_addr, &a->address.ipv6)) return FALSE;
    else return TRUE;
  }
  else if (a->family == AF_INET && sa->sa_family == AF_INET6) {
    memset(&sa6_local, 0, sizeof(sa6_local));
    memset((u_int8_t *)&sa6_local.sin6_addr+10, 0xff, 2);
    memcpy((u_int8_t *)&sa6_local.sin6_addr+12, &a->address.ipv4.s_addr, 4);
    if (!ip6_addr_cmp(&sa6->sin6_addr, &sa6_local.sin6_addr)) return FALSE;
    else return TRUE;
  }
  else if (a->family == AF_INET6 && sa->sa_family == AF_INET) {
    memset(&sa6_local, 0, sizeof(sa6_local));
    memset((u_int8_t *)&sa6_local.sin6_addr+10, 0xff, 2);
    memcpy((u_int8_t *)&sa6_local.sin6_addr+12, &sa4->sin_addr, 4);
    if (!ip6_addr_cmp(&sa6_local.sin6_addr, &a->address.ipv6)) return FALSE;
    else return TRUE;
  }
#endif

  return -1;
}

/*
 * sa_port_cmp(): compare two TCP/UDP ports: the first encapsulated in a
 * 'struct sockaddr' and the second as a u_int16_t
 * returns 0 if they match; 1 if they don't match; -1 to signal a generic
 * error (e.g. unsupported family).
 */
int sa_port_cmp(struct sockaddr *sa, u_int16_t port)
{
  struct sockaddr_in *sa4 = (struct sockaddr_in *)sa;
#if defined ENABLE_IPV6
  struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)sa;
  struct sockaddr_in6 sa6_local;
#endif

  if (sa->sa_family == AF_INET) {
    if (sa4->sin_port == port) return FALSE;
    else return TRUE;
  }
#if defined ENABLE_IPV6
  if (sa->sa_family == AF_INET6) {
    if (sa6->sin6_port == port) return FALSE;
    else return TRUE;
  }
#endif

  return -1;
}

/*
 * host_addr_mask_cmp() checks whether s1 falls in a1/m1
 * returns 0 if positive; 1 if negative; -1 to signal a generic error
 * (e.g. unsupported family).
 */
int host_addr_mask_sa_cmp(struct host_addr *a1, struct host_mask *m1, struct sockaddr *s1)
{
  struct sockaddr_in *sa4 = (struct sockaddr_in *)s1;
#if defined ENABLE_IPV6
  struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)s1;
  struct sockaddr_in6 sa6_local;
  int ret, j;
#endif

  if (!a1 || !m1 || !s1) return -1;
  if (a1->family != s1->sa_family || a1->family != m1->family) return -1;

  if (a1->family == AF_INET) {
    if ((sa4->sin_addr.s_addr & m1->mask.m4) == a1->address.ipv4.s_addr) return 0;
    else return 1;
  }
#if defined ENABLE_IPV6
  else if (a1->family == AF_INET6) {
    memcpy(&sa6_local, s1, sizeof(struct sockaddr));
    for (j = 0; j < 4; j++) sa6_local.sin6_addr.s6_addr[j] &= m1->mask.m6[j];
    ret = ip6_addr_cmp(a1, &sa6_local.sin6_addr);
    if (!ret) return 0;
    else return 1;
  }
#endif

  return -1;
}

/*
 * raw_to_sa() converts a supported family address into a sockaddr 
 * structure 
 */
unsigned int raw_to_sa(struct sockaddr *sa, char *src, u_int16_t port, u_int8_t v4v6)
{
  struct sockaddr_in *sa4 = (struct sockaddr_in *)sa;
#if defined ENABLE_IPV6
  struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)sa;
#endif

  if (v4v6 == AF_INET) {
    sa->sa_family = AF_INET;
    memcpy(&sa4->sin_addr.s_addr, src, 4);
    sa4->sin_port = port;
    return sizeof(struct sockaddr_in);
  }
#if defined ENABLE_IPV6
  if (v4v6 == AF_INET6) {
    sa->sa_family = AF_INET6;
    ip6_addr_cpy(&sa6->sin6_addr, src);
    sa6->sin6_port = port;
    return sizeof(struct sockaddr_in6);
  }
#endif

  memset(sa, 0, sizeof(struct sockaddr));
  return 0;
}

/*
 * sa_to_str() converts a supported family addres into a string
 * 'str' length is not checked and assumed to be INET6_ADDRSTRLEN 
 */
unsigned int sa_to_str(char *str, const struct sockaddr *sa)
{
  struct sockaddr_in *sa4 = (struct sockaddr_in *)sa;
#if defined ENABLE_IPV6
  struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)sa;
#endif

  if (sa->sa_family == AF_INET) {
    inet_ntop(AF_INET, &sa4->sin_addr.s_addr, str, INET6_ADDRSTRLEN);
    return sa->sa_family;
  }
#if defined ENABLE_IPV6
  if (sa->sa_family == AF_INET6) {
    inet_ntop(AF_INET6, &sa6->sin6_addr, str, INET6_ADDRSTRLEN);
    return sa->sa_family;
  }
#endif

  memset(str, 0, INET6_ADDRSTRLEN);

  return 0;
}

/*
 * pm_htonl6(): same as htonl() for IPv6 addresses; no checks are done
 * on the length of the buffer.
 */
void *pm_htonl6(void *addr)
{
  register u_int32_t *ptr = addr;
  static u_int32_t buf[4];
  u_int8_t chunk;

  for (chunk = 0; chunk < 4; chunk++) buf[chunk] = htonl(ptr[chunk]);

  return buf;
}

/*
 * pm_ntohl6(): same as ntohl() for IPv6 addresses; no checks are done
 * on the length of the buffer.
 */
void *pm_ntohl6(void *addr)
{
  register u_int32_t *ptr = addr;
  static u_int32_t buf[4];
  u_int8_t chunk;

  for (chunk = 0; chunk < 4; chunk++) buf[chunk] = ntohl(ptr[chunk]);

  return buf;
}

/*
 * ip6_addr_cmp(): compare two IPv6 addresses; returns 0 if they match,
 * 1 if the first not matching chunk of addr1 is found to be greater than
 * addr2; -1 on the contrary. 
 */
int ip6_addr_cmp(void *addr1, void *addr2)
{
  register u_int32_t *ptr1 = addr1, *ptr2 = addr2; 
  int chunk;
  
  for (chunk = 0; chunk < 4; chunk++) {
    if (ptr1[chunk] == ptr2[chunk]) continue;
    else {
      if (ptr1[chunk] > ptr2[chunk]) return TRUE;
      else return -1; 
    }
  }

  return FALSE;
}

/*
 * ip6_addr_cpy(): copy of a *src IPv6 address into a *dst buffer.
 */
void ip6_addr_cpy(void *dst, void *src)
{
  register u_int32_t *ptrs = src, *ptrd = dst;
  int chunk;

  for (chunk = 0; chunk < 4; chunk++) 
    ptrd[chunk] = ptrs[chunk];
}

/*
 * ip6_addr_32bit_cpy(): copy of arbitrary 32bit IPv6 address chunks
 */
void ip6_addr_32bit_cpy(void *dst, void *src, int dstart, int sstart, int send)
{
  register u_int32_t *ptrs = src, *ptrd = dst;
  int schunk, dchunk;

  for (schunk = sstart, dchunk = dstart; schunk <= send; schunk++, dchunk++)
    ptrd[dchunk] = ptrs[schunk];
}

void etheraddr_string(const u_char *ep, char *buf)
{
  u_int i, j;
  char *cp;

  cp = buf;
  if ((j = *ep >> 4) != 0)
    *cp++ = hex[j];
  else
    *cp++ = '0';

  *cp++ = hex[*ep++ & 0xf];

  for (i = 5; (int)--i >= 0;) {
    *cp++ = ':';
    if ((j = *ep >> 4) != 0)
      *cp++ = hex[j];
    else
      *cp++ = '0';

    *cp++ = hex[*ep++ & 0xf];
  }

  *cp = '\0';
}

/*
 * string_etheraddr() writes the content of *asc in *addr (which has
 * to be ETH_ADDR_LEN long). TRUE is returned if any failure occurs;
 * TRUE if the routine completes the job successfully 
 */
int string_etheraddr(const u_char *asc, char *addr)
{
  int cnt;

  for (cnt = 0; cnt < 6; ++cnt) {
    unsigned int number;
    char ch;

    ch = tolower (*asc++);
    if ((ch < '0' || ch > '9') && (ch < 'a' || ch > 'f'))
      return 1;
    number = isdigit (ch) ? (ch - '0') : (ch - 'a' + 10);

    ch = tolower(*asc);
    if ((cnt < 5 && ch != ':') || (cnt == 5 && ch != '\0' && !isspace (ch))) {
      ++asc;
      if ((ch < '0' || ch > '9') && (ch < 'a' || ch > 'f'))
        return 1;
      number <<= 4;
      number += isdigit (ch) ? (ch - '0') : (ch - 'a' + 10);
      ch = *asc;
      if (cnt < 5 && ch != ':')
        return 1;
    }

    /* Store result.  */
    addr[cnt] = (unsigned char) number;

    /* Skip ':'.  */
    ++asc;
  }

  return FALSE;
}

/*
 * pm_htonll(): similar to htonl() for 64 bits integers; no checks are done
 * on the length of the buffer.
 */
u_int64_t pm_htonll(u_int64_t addr)
{
#if defined IM_LITTLE_ENDIAN
  u_int64_t buf;

  u_int32_t *x = (u_int32_t *)(void *) &addr;
  u_int32_t *y = (u_int32_t *)(void *) &buf;

  y[0] = htonl(x[1]);
  y[1] = htonl(x[0]);

  return buf;
#else
  return addr;
#endif
}

/*
 * pm_ntohll(): similar to ntohl() for 64 bits integers; no checks are done
 * on the length of the buffer.
 */
u_int64_t pm_ntohll(u_int64_t addr)
{
#if defined IM_LITTLE_ENDIAN
  static u_int64_t buf;

  buf = ((u_int64_t) ntohl(addr & 0xFFFFFFFFLLU)) << 32;
  buf |= ntohl((addr & 0xFFFFFFFF00000000LLU) >> 32);

  return buf;
#else
  return addr;
#endif
}

/*
 * is_multicast(): determines whether the supplied IPv4/IPv6 address is a
 * multicast address or not. 
 */
int is_multicast(struct host_addr *a)
{
  if (!a) return FALSE;

  if (a->family == AF_INET) {
    if (IS_IPV4_MULTICAST(a->address.ipv4.s_addr)) return a->family;
    else return FALSE;
  }
#if defined ENABLE_IPV6
  if (a->family == AF_INET6) {
    if (IS_IPV6_MULTICAST(&a->address.ipv6)) return a->family;
    else return FALSE;
  }
#endif

  return FALSE;
}

/*
 * is_any(): determines whether the supplied IPv4/IPv6 address is a
 * 0.0.0.0 IPv4 or :: IPv6 address or not. 
 */
int is_any(struct host_addr *a)
{
  struct host_addr empty_host_addr;

  if (!a) return FALSE;

  memset(&empty_host_addr, 0, sizeof(empty_host_addr));

  if (a->family == AF_INET) {
    if (!memcmp(&empty_host_addr.address.ipv4, &a->address.ipv4, 4)) return a->family;
    else return FALSE;
  }
#if defined ENABLE_IPV6
  if (a->family == AF_INET6) {
    if (!memcmp(&empty_host_addr.address.ipv6, &a->address.ipv6, 16)) return a->family;
    else return FALSE;
  }
#endif

  return FALSE;
}

/*
 * clean_sin_addr(): cleans the IP address from the pointed sockaddr structure
 */
void clean_sin_addr(struct sockaddr *sa)
{
  struct sockaddr_in *sa4 = (struct sockaddr_in *)sa;
#if defined ENABLE_IPV6
  struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)sa;
#endif

  if (sa->sa_family == AF_INET) sa4->sin_addr.s_addr = 0;
#if defined ENABLE_IPV6
  if (sa->sa_family == AF_INET6) memset(&sa6->sin6_addr, 0, 16);
#endif
}

#if defined ENABLE_PLABEL
/*
 * label_to_addr() converts a label into a supported family address
 */
unsigned int label_to_addr(const char *label, struct host_addr *a, int len)
{
  strlcpy(a->address.plabel, label, len);
  a->family = AF_PLABEL;

  return 0;
}
#endif

/*
 * ipv4_mapped_to_ipv4() converts a label into a supported family address
 */
#if defined ENABLE_IPV6
void ipv4_mapped_to_ipv4(struct sockaddr_storage *sas)
{
  struct sockaddr_storage sas_local;
  struct sockaddr *sa = (struct sockaddr *) sas;
  struct sockaddr_in *sa4 = (struct sockaddr_in *) sas;
  struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *) sas;

  if (sa->sa_family != AF_INET6 || !IN6_IS_ADDR_V4MAPPED(&sa6->sin6_addr)) return;

  memcpy(&sas_local, sas, sizeof(struct sockaddr_storage));
  memset(sas, 0, sizeof(struct sockaddr_storage));
  sa6 = (struct sockaddr_in6 *) &sas_local;
  sa->sa_family = AF_INET;
  memcpy(&sa4->sin_addr, (u_int8_t *) &sa6->sin6_addr+12, 4);
  sa4->sin_port = sa6->sin6_port;
}

void ipv4_to_ipv4_mapped(struct sockaddr_storage *sas)
{
  struct sockaddr_storage sas_local;
  struct sockaddr *sa = (struct sockaddr *) sas;
  struct sockaddr_in *sa4 = (struct sockaddr_in *) sas;
  struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *) sas;
  static u_int16_t ffff = 0xFFFF;

  if (sa->sa_family != AF_INET) return;

  memcpy(&sas_local, sas, sizeof(struct sockaddr_storage));
  memset(sas, 0, sizeof(struct sockaddr_storage));
  sa4 = (struct sockaddr_in *) &sas_local;
  sa->sa_family = AF_INET6;
  memcpy((u_int8_t *) &sa6->sin6_addr+10, &ffff, 2);
  memcpy((u_int8_t *) &sa6->sin6_addr+12, &sa4->sin_addr, 4);
  sa6->sin6_port = sa4->sin_port;
}
#endif

u_int8_t etype_to_af(u_int16_t etype)
{
  if (etype == ETHERTYPE_IP) return AF_INET;
#if defined ENABLE_IPV6
  else if (etype == ETHERTYPE_IPV6) return AF_INET6;
#endif

  return FALSE;
}

u_int16_t af_to_etype(u_int8_t af)
{
  if (af == AF_INET) return ETHERTYPE_IP;
#if defined ENABLE_IPV6
  else if (af == AF_INET6) return ETHERTYPE_IPV6;
#endif

  return FALSE;
}
