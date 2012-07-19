/* Socket union related function.
 * Copyright (c) 1997, 98 Kunihiro Ishiguro
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

#define __SOCKUNION_C

#include "pmacct.h"
#include "isis.h"

#include "prefix.h"
#include "sockunion.h"

const char *
inet_sutop (union sockunion *su, char *str)
{
  switch (su->sa.sa_family)
    {
    case AF_INET:
      inet_ntop (AF_INET, &su->sin.sin_addr, str, INET_ADDRSTRLEN);
      break;
#ifdef ENABLE_IPV6
    case AF_INET6:
      inet_ntop (AF_INET6, &su->sin6.sin6_addr, str, INET6_ADDRSTRLEN);
      break;
#endif /* ENABLE_IPV6 */
    }
  return str;
}

int
str2sockunion (const char *str, union sockunion *su)
{
  int ret;

  memset (su, 0, sizeof (union sockunion));

  ret = inet_pton (AF_INET, str, &su->sin.sin_addr);
  if (ret > 0)			/* Valid IPv4 address format. */
    {
      su->sin.sin_family = AF_INET;
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
      su->sin.sin_len = sizeof(struct sockaddr_in);
#endif /* HAVE_STRUCT_SOCKADDR_IN_SIN_LEN */
      return 0;
    }
#ifdef ENABLE_IPV6
  ret = inet_pton (AF_INET6, str, &su->sin6.sin6_addr);
  if (ret > 0)			/* Valid IPv6 address format. */
    {
      su->sin6.sin6_family = AF_INET6;
#ifdef SIN6_LEN
      su->sin6.sin6_len = sizeof(struct sockaddr_in6);
#endif /* SIN6_LEN */
      return 0;
    }
#endif /* ENABLE_IPV6 */
  return -1;
}

const char *
sockunion2str (union sockunion *su, char *buf, size_t len)
{
  if  (su->sa.sa_family == AF_INET)
    return inet_ntop (AF_INET, &su->sin.sin_addr, buf, len);
#ifdef ENABLE_IPV6
  else if (su->sa.sa_family == AF_INET6)
    return inet_ntop (AF_INET6, &su->sin6.sin6_addr, buf, len);
#endif /* ENABLE_IPV6 */
  return NULL;
}

union sockunion *
sockunion_str2su (const char *str)
{
  int ret;
  union sockunion *su;

  su = calloc(1, sizeof (union sockunion));

  ret = inet_pton (AF_INET, str, &su->sin.sin_addr);
  if (ret > 0)			/* Valid IPv4 address format. */
    {
      su->sin.sin_family = AF_INET;
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
      su->sin.sin_len = sizeof(struct sockaddr_in);
#endif /* HAVE_STRUCT_SOCKADDR_IN_SIN_LEN */
      return su;
    }
#ifdef ENABLE_IPV6
  ret = inet_pton (AF_INET6, str, &su->sin6.sin6_addr);
  if (ret > 0)			/* Valid IPv6 address format. */
    {
      su->sin6.sin6_family = AF_INET6;
#ifdef SIN6_LEN
      su->sin6.sin6_len = sizeof(struct sockaddr_in6);
#endif /* SIN6_LEN */
      return su;
    }
#endif /* ENABLE_IPV6 */

  free(su);
  return NULL;
}

char *
sockunion_su2str (union sockunion *su)
{
  char str[SU_ADDRSTRLEN];

  switch (su->sa.sa_family)
    {
    case AF_INET:
      inet_ntop (AF_INET, &su->sin.sin_addr, str, sizeof (str));
      break;
#ifdef ENABLE_IPV6
    case AF_INET6:
      inet_ntop (AF_INET6, &su->sin6.sin6_addr, str, sizeof (str));
      break;
#endif /* ENABLE_IPV6 */
    }
  return strdup(str);
}

/* Convert IPv4 compatible IPv6 address to IPv4 address. */
static void
sockunion_normalise_mapped (union sockunion *su)
{
  struct sockaddr_in sin;
  
#ifdef ENABLE_IPV6
  if (su->sa.sa_family == AF_INET6 
      && IN6_IS_ADDR_V4MAPPED (&su->sin6.sin6_addr))
    {
      memset (&sin, 0, sizeof (struct sockaddr_in));
      sin.sin_family = AF_INET;
      sin.sin_port = su->sin6.sin6_port;
      memcpy (&sin.sin_addr, ((char *)&su->sin6.sin6_addr) + 12, 4);
      memcpy (su, &sin, sizeof (struct sockaddr_in));
    }
#endif /* ENABLE_IPV6 */
}

/* Return socket of sockunion. */
int
sockunion_socket (union sockunion *su)
{
  int sock;

  sock = socket (su->sa.sa_family, SOCK_STREAM, 0);
  if (sock < 0)
    {
      Log(LOG_WARNING, "WARN ( default/core/ISIS ): Can't make socket : %s\n", strerror (errno));
      return -1;
    }

  return sock;
}

/* Return accepted new socket file descriptor. */
int
sockunion_accept (int sock, union sockunion *su)
{
  socklen_t len;
  int client_sock;

  len = sizeof (union sockunion);
  client_sock = accept (sock, (struct sockaddr *) su, &len);
  
  sockunion_normalise_mapped (su);
  return client_sock;
}

/* Return sizeof union sockunion.  */
static int
sockunion_sizeof (union sockunion *su)
{
  int ret;

  ret = 0;
  switch (su->sa.sa_family)
    {
    case AF_INET:
      ret = sizeof (struct sockaddr_in);
      break;
#ifdef ENABLE_IPV6
    case AF_INET6:
      ret = sizeof (struct sockaddr_in6);
      break;
#endif /* AF_INET6 */
    }
  return ret;
}

/* return sockunion structure : this function should be revised. */
static char *
sockunion_log (union sockunion *su)
{
  static char buf[SU_ADDRSTRLEN];

  switch (su->sa.sa_family) 
    {
    case AF_INET:
      snprintf (buf, SU_ADDRSTRLEN, "%s", inet_ntoa (su->sin.sin_addr));
      break;
#ifdef ENABLE_IPV6
    case AF_INET6:
      snprintf (buf, SU_ADDRSTRLEN, "%s",
		inet_ntop (AF_INET6, &(su->sin6.sin6_addr), buf, SU_ADDRSTRLEN));
      break;
#endif /* ENABLE_IPV6 */
    default:
      snprintf (buf, SU_ADDRSTRLEN, "af_unknown %d ", su->sa.sa_family);
      break;
    }
  return (strdup(buf));
}

/* sockunion_connect returns
   -1 : error occured
   0 : connect success
   1 : connect is in progress */
enum connect_result
sockunion_connect (int fd, union sockunion *peersu, unsigned short port,
		   unsigned int ifindex)
{
  int ret;
  int val;
  union sockunion su;

  memcpy (&su, peersu, sizeof (union sockunion));

  switch (su.sa.sa_family)
    {
    case AF_INET:
      su.sin.sin_port = port;
      break;
#ifdef ENABLE_IPV6
    case AF_INET6:
      su.sin6.sin6_port  = port;
#ifdef KAME
      if (IN6_IS_ADDR_LINKLOCAL(&su.sin6.sin6_addr) && ifindex)
	{
#ifdef HAVE_STRUCT_SOCKADDR_IN6_SIN6_SCOPE_ID
	  /* su.sin6.sin6_scope_id = ifindex; */
#ifdef MUSICA
	  su.sin6.sin6_scope_id = ifindex; 
#endif
#endif /* HAVE_STRUCT_SOCKADDR_IN6_SIN6_SCOPE_ID */
#ifndef MUSICA
	  SET_IN6_LINKLOCAL_IFINDEX (su.sin6.sin6_addr, ifindex);
#endif
	}
#endif /* KAME */
      break;
#endif /* ENABLE_IPV6 */
    }      

  /* Make socket non-block. */
  val = fcntl (fd, F_GETFL, 0);
  fcntl (fd, F_SETFL, val|O_NONBLOCK);

  /* Call connect function. */
  ret = connect (fd, (struct sockaddr *) &su, sockunion_sizeof (&su));

  /* Immediate success */
  if (ret == 0)
    {
      fcntl (fd, F_SETFL, val);
      return connect_success;
    }

  /* If connect is in progress then return 1 else it's real error. */
  if (ret < 0)
    {
      if (errno != EINPROGRESS)
	{
	  Log(LOG_INFO, "INFO ( default/core/ISIS ): can't connect to %s fd %d : %s\n",
		     sockunion_log (&su), fd, strerror (errno));
	  return connect_error;
	}
    }

  fcntl (fd, F_SETFL, val);

  return connect_in_progress;
}

/* Make socket from sockunion union. */
int
sockunion_stream_socket (union sockunion *su)
{
  int sock;

  if (su->sa.sa_family == 0)
    su->sa.sa_family = AF_INET_UNION;

  sock = socket (su->sa.sa_family, SOCK_STREAM, 0);

  if (sock < 0)
    Log(LOG_WARNING, "WARN ( default/core/ISIS ): can't make socket sockunion_stream_socket\n");

  return sock;
}

/* Bind socket to specified address. */
int
sockunion_bind (int sock, union sockunion *su, unsigned short port, 
		union sockunion *su_addr)
{
  int size = 0;
  int ret;

  if (su->sa.sa_family == AF_INET)
    {
      size = sizeof (struct sockaddr_in);
      su->sin.sin_port = htons (port);
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
      su->sin.sin_len = size;
#endif /* HAVE_STRUCT_SOCKADDR_IN_SIN_LEN */
      if (su_addr == NULL)
	su->sin.sin_addr.s_addr = htonl (INADDR_ANY);
    }
#ifdef ENABLE_IPV6
  else if (su->sa.sa_family == AF_INET6)
    {
      size = sizeof (struct sockaddr_in6);
      su->sin6.sin6_port = htons (port);
#ifdef SIN6_LEN
      su->sin6.sin6_len = size;
#endif /* SIN6_LEN */
      if (su_addr == NULL)
	{
#if defined(LINUX_IPV6) || defined(NRL)
	  memset (&su->sin6.sin6_addr, 0, sizeof (struct in6_addr));
#else
	  su->sin6.sin6_addr = in6addr_any;
#endif /* LINUX_IPV6 */
	}
    }
#endif /* ENABLE_IPV6 */
  

  ret = bind (sock, (struct sockaddr *)su, size);
  if (ret < 0)
    Log(LOG_WARNING, "WARN ( default/core/ISIS ): can't bind socket : %s\n", strerror (errno));

  return ret;
}

int
sockopt_reuseaddr (int sock)
{
  int ret;
  int on = 1;

  ret = setsockopt (sock, SOL_SOCKET, SO_REUSEADDR, 
		    (void *) &on, sizeof (on));
  if (ret < 0)
    {
      Log(LOG_WARNING, "WARN ( default/core/ISIS ): can't set sockopt SO_REUSEADDR to socket %d\n", sock);
      return -1;
    }
  return 0;
}

#ifdef SO_REUSEPORT
int
sockopt_reuseport (int sock)
{
  int ret;
  int on = 1;

  ret = setsockopt (sock, SOL_SOCKET, SO_REUSEPORT, 
		    (void *) &on, sizeof (on));
  if (ret < 0)
    {
      Log(LOG_WARNING, "WARN ( default/core/ISIS ): can't set sockopt SO_REUSEPORT to socket %d\n", sock);
      return -1;
    }
  return 0;
}
#else
int
sockopt_reuseport (int sock)
{
  return 0;
}
#endif /* 0 */

int
sockopt_ttl (int family, int sock, int ttl)
{
  int ret;

#ifdef IP_TTL
  if (family == AF_INET)
    {
      ret = setsockopt (sock, IPPROTO_IP, IP_TTL, 
			(void *) &ttl, sizeof (int));
      if (ret < 0)
	{
	  Log(LOG_WARNING, "WARN ( default/core/ISIS ): can't set sockopt IP_TTL %d to socket %d\n", ttl, sock);
	  return -1;
	}
      return 0;
    }
#endif /* IP_TTL */
#ifdef ENABLE_IPV6
  if (family == AF_INET6)
    {
      ret = setsockopt (sock, IPPROTO_IPV6, IPV6_UNICAST_HOPS, 
			(void *) &ttl, sizeof (int));
      if (ret < 0)
	{
	  Log(LOG_WARNING, "WARN ( default/core/ISIS ): can't set sockopt IPV6_UNICAST_HOPS %d to socket %d\n",
		    ttl, sock);
	  return -1;
	}
      return 0;
    }
#endif /* ENABLE_IPV6 */
  return 0;
}

int
sockopt_cork (int sock, int onoff)
{
#ifdef TCP_CORK
  return setsockopt (sock, IPPROTO_TCP, TCP_CORK, &onoff, sizeof(onoff));
#else
  return 0;
#endif
}

int
sockopt_minttl (int family, int sock, int minttl)
{
#ifdef IP_MINTTL
  if (family == AF_INET)
    {
      int ret = setsockopt (sock, IPPROTO_IP, IP_MINTTL, &minttl, sizeof(minttl));
      if (ret < 0)
	  Log(LOG_WARNING, "WARN ( default/core/ISIS ): can't set sockopt IP_MINTTL to %d on socket %d: %s\n",
		minttl, sock, strerror (errno));
      return ret;
    }
#endif /* IP_MINTTL */
#ifdef IPV6_MINHOPCNT
  if (family == AF_INET6)
    {
      int ret = setsockopt (sock, IPPROTO_IPV6, IPV6_MINHOPCNT, &minttl, sizeof(minttl));
      if (ret < 0)
	  Log(LOG_WARNING, "WARN ( default/core/ISIS ): can't set sockopt IPV6_MINHOPCNT to %d on socket %d: %s\n",
		minttl, sock, strerror (errno));
      return ret;
    }
#endif

  errno = EOPNOTSUPP;
  return -1;
}

/* If same family and same prefix return 1. */
int
sockunion_same (union sockunion *su1, union sockunion *su2)
{
  int ret = 0;

  if (su1->sa.sa_family != su2->sa.sa_family)
    return 0;

  switch (su1->sa.sa_family)
    {
    case AF_INET:
      ret = memcmp (&su1->sin.sin_addr, &su2->sin.sin_addr,
		    sizeof (struct in_addr));
      break;
#ifdef ENABLE_IPV6
    case AF_INET6:
      ret = memcmp (&su1->sin6.sin6_addr, &su2->sin6.sin6_addr,
		    sizeof (struct in6_addr));
      break;
#endif /* ENABLE_IPV6 */
    }
  if (ret == 0)
    return 1;
  else
    return 0;
}

/* After TCP connection is established.  Get local address and port. */
union sockunion *
sockunion_getsockname (int fd)
{
  int ret;
  socklen_t len;
  union
  {
    struct sockaddr sa;
    struct sockaddr_in sin;
#ifdef ENABLE_IPV6
    struct sockaddr_in6 sin6;
#endif /* ENABLE_IPV6 */
    char tmp_buffer[128];
  } name;
  union sockunion *su;

  memset (&name, 0, sizeof name);
  len = sizeof name;

  ret = getsockname (fd, (struct sockaddr *)&name, &len);
  if (ret < 0)
    {
      Log(LOG_WARNING, "WARN ( default/core/ISIS ): Can't get local address and port by getsockname: %s\n",
		 strerror (errno));
      return NULL;
    }

  if (name.sa.sa_family == AF_INET)
    {
      su = calloc(1, sizeof (union sockunion));
      memcpy (su, &name, sizeof (struct sockaddr_in));
      return su;
    }
#ifdef ENABLE_IPV6
  if (name.sa.sa_family == AF_INET6)
    {
      su = calloc(1, sizeof (union sockunion));
      memcpy (su, &name, sizeof (struct sockaddr_in6));
      sockunion_normalise_mapped (su);
      return su;
    }
#endif /* ENABLE_IPV6 */
  return NULL;
}

/* After TCP connection is established.  Get remote address and port. */
union sockunion *
sockunion_getpeername (int fd)
{
  int ret;
  socklen_t len;
  union
  {
    struct sockaddr sa;
    struct sockaddr_in sin;
#ifdef ENABLE_IPV6
    struct sockaddr_in6 sin6;
#endif /* ENABLE_IPV6 */
    char tmp_buffer[128];
  } name;
  union sockunion *su;

  memset (&name, 0, sizeof name);
  len = sizeof name;
  ret = getpeername (fd, (struct sockaddr *)&name, &len);
  if (ret < 0)
    {
      Log(LOG_WARNING, "WARN ( default/core/ISIS ): Can't get remote address and port: %s\n",
	    strerror (errno));
      return NULL;
    }

  if (name.sa.sa_family == AF_INET)
    {
      su = calloc(1, sizeof (union sockunion));
      memcpy (su, &name, sizeof (struct sockaddr_in));
      return su;
    }
#ifdef ENABLE_IPV6
  if (name.sa.sa_family == AF_INET6)
    {
      su = calloc(1, sizeof (union sockunion));
      memcpy (su, &name, sizeof (struct sockaddr_in6));
      sockunion_normalise_mapped (su);
      return su;
    }
#endif /* ENABLE_IPV6 */
  return NULL;
}

#ifdef ENABLE_IPV6
static int
in6addr_cmp (struct in6_addr *addr1, struct in6_addr *addr2)
{
  unsigned int i;
  u_char *p1, *p2;

  p1 = (u_char *)addr1;
  p2 = (u_char *)addr2;

  for (i = 0; i < sizeof (struct in6_addr); i++)
    {
      if (p1[i] > p2[i])
	return 1;
      else if (p1[i] < p2[i])
	return -1;
    }
  return 0;
}
#endif /* ENABLE_IPV6 */

int
sockunion_cmp (union sockunion *su1, union sockunion *su2)
{
  if (su1->sa.sa_family > su2->sa.sa_family)
    return 1;
  if (su1->sa.sa_family < su2->sa.sa_family)
    return -1;

  if (su1->sa.sa_family == AF_INET)
    {
      if (ntohl (su1->sin.sin_addr.s_addr) == ntohl (su2->sin.sin_addr.s_addr))
	return 0;
      if (ntohl (su1->sin.sin_addr.s_addr) > ntohl (su2->sin.sin_addr.s_addr))
	return 1;
      else
	return -1;
    }
#ifdef ENABLE_IPV6
  if (su1->sa.sa_family == AF_INET6)
    return in6addr_cmp (&su1->sin6.sin6_addr, &su2->sin6.sin6_addr);
#endif /* ENABLE_IPV6 */
  return 0;
}

/* Duplicate sockunion. */
union sockunion *
sockunion_dup (union sockunion *su)
{
  union sockunion *dup = calloc(1, sizeof (union sockunion));
  memcpy (dup, su, sizeof (union sockunion));
  return dup;
}

void
sockunion_free (union sockunion *su)
{
  free(su);
}
