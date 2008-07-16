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
 * NOTE: 'str' length is not checked ! 
 */
unsigned int addr_to_str(char *str, const struct host_addr *a)
{
  char *ptr;

  if (a->family == AF_INET) {
    ptr = inet_ntoa(a->address.ipv4);
    strcpy(str, ptr);
    return a->family;
  }
#if defined ENABLE_IPV6
  if (a->family == AF_INET6) {
    inet_ntop(AF_INET6, &a->address.ipv6, str, INET6_ADDRSTRLEN); 
    return a->family;
  }
#endif

  memset(str, 0, INET6_ADDRSTRLEN);
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
 * error (e.g. family mismatch).
 */
unsigned int sa_addr_cmp(struct sockaddr *sa, struct host_addr *a)
{
  struct sockaddr_in *sa4 = (struct sockaddr_in *)sa;
#if defined ENABLE_IPV6
  struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)sa;
#endif

  if (sa->sa_family != a->family) return -1;

  if (a->family == AF_INET) {
    if (sa4->sin_addr.s_addr == a->address.ipv4.s_addr) return FALSE;
    else return TRUE; 
  }
#if defined ENABLE_IPV6
  if (a->family == AF_INET6) {
    if (!ip6_addr_cmp(&sa6->sin6_addr, &a->address.ipv6)) return FALSE;
    else return TRUE;
  }
#endif

  return -1;
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
unsigned int ip6_addr_cmp(void *addr1, void *addr2)
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
  static u_int64_t buf;
  register u_int32_t *x = (u_int32_t *)(void *) &addr;
  register u_int32_t *y = (u_int32_t *)(void *) &buf;

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
  register u_int32_t *x = (u_int32_t *)(void *) &addr;
  register u_int32_t *y = (u_int32_t *)(void *) &buf;

  y[0] = ntohl(x[1]);
  y[1] = ntohl(x[0]);

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
