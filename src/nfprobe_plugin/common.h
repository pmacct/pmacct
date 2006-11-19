/*
 * Copyright (c) 2002 Damien Miller.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _SFD_COMMON_H
#define _SFD_COMMON_H

#define _BSD_SOURCE /* Needed for BSD-style struct ip,tcp,udp on Linux */

#include "pmacct.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#if defined ENABLE_IPV6
#include "../../include/ip6.h"
#include "../../include/ah.h"
#endif
#include <netinet/udp.h>
#include <arpa/inet.h>

#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <netdb.h>
#include <limits.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

#if defined(HAVE_NET_BPF_H)
#include <net/bpf.h>
#elif defined(HAVE_PCAP_BPF_H)
#include <pcap-bpf.h>
#endif
#if defined(HAVE_INTTYPES_H)
#include <inttypes.h>
#endif

/* The name of the program */
// #define PROGNAME		"softflowd"

/* The name of the program */
#define PROGVER			"0.9.7"

/* Default pidfile */
#define DEFAULT_PIDFILE		"/var/run/" PROGNAME ".pid"

/* Default control socket */
#define DEFAULT_CTLSOCK		"/var/run/" PROGNAME ".ctl"

#define RCSID(msg) \
	static /**/const char *const flowd_rcsid[] =		\
	    { (const char *)flowd_rcsid, "\100(#)" msg }	\

/*
#ifndef IP_OFFMASK
# define IP_OFFMASK		0x1fff	
#endif
#ifndef IPV6_VERSION
#define IPV6_VERSION		0x60
#endif
#ifndef IPV6_VERSION_MASK
#define IPV6_VERSION_MASK	0xf0
#endif
#ifndef IPV6_FLOWINFO_MASK
#define IPV6_FLOWINFO_MASK	ntohl(0x0fffffff)
#endif
#ifndef IPV6_FLOWLABEL_MASK
#define IPV6_FLOWLABEL_MASK	ntohl(0x000fffff)
#endif
*/

#ifndef _PATH_DEVNULL
# define _PATH_DEVNULL		"/dev/null"
#endif

#ifndef MIN
# define MIN(a,b) (((a)<(b))?(a):(b))
#endif
#ifndef MAX
# define MAX(a,b) (((a)>(b))?(a):(b))
#endif
#ifndef offsetof
# define offsetof(type, member) ((size_t) &((type *)0)->member)
#endif

#if defined(__GNUC__)
# ifndef __dead
#  define __dead                __attribute__((__noreturn__))
# endif
# ifndef __packed
#  define __packed              __attribute__((__packed__))
# endif
#endif

#if !defined(HAVE_INT8_T) && defined(OUR_CFG_INT8_T)
typedef OUR_CFG_INT8_T int8_t;
#endif
#if !defined(HAVE_INT16_T) && defined(OUR_CFG_INT16_T)
typedef OUR_CFG_INT16_T int16_t;
#endif
#if !defined(HAVE_INT32_T) && defined(OUR_CFG_INT32_T)
typedef OUR_CFG_INT32_T int32_t;
#endif
#if !defined(HAVE_INT64_T) && defined(OUR_CFG_INT64_T)
typedef OUR_CFG_INT64_T int64_t;
#endif
#if !defined(HAVE_U_INT8_T) && defined(OUR_CFG_U_INT8_T)
typedef OUR_CFG_U_INT8_T u_int8_t;
#endif
#if !defined(HAVE_U_INT16_T) && defined(OUR_CFG_U_INT16_T)
typedef OUR_CFG_U_INT16_T u_int16_t;
#endif
#if !defined(HAVE_U_INT32_T) && defined(OUR_CFG_U_INT32_T)
typedef OUR_CFG_U_INT32_T u_int32_t;
#endif
#if !defined(HAVE_U_INT64_T) && defined(OUR_CFG_U_INT64_T)
typedef OUR_CFG_U_INT64_T u_int64_t;
#endif

#ifndef HAVE_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t siz);
#endif
#ifndef HAVE_STRLCAT
size_t strlcat(char *dst, const char *src, size_t siz);
#endif

#endif /* _SFD_COMMON_H */
