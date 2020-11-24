/*
 * Copyright (c) 1998-2005 Sendmail, Inc. and its suppliers.
 *      All rights reserved.
 * Copyright (c) 1983, 1995-1997 Eric P. Allman.  All rights reserved.
 * Copyright (c) 1988, 1993
 *      The Regents of the University of California.  All rights reserved.
 *
 * By using this file, you agree to the terms and conditions set
 * forth in the LICENSE file which can be found at the top level of
 * the sendmail distribution.
 *
 *
 *      $Id$
 */

#ifdef __hpux
#  undef SPT_TYPE
// #  define SPT_TYPE      SPT_PSTAT
#endif

#ifdef _AIX3
#  define SPT_PADCHAR   '\0'
#endif

#ifdef AIX
#  define SPT_PADCHAR   '\0'
#endif

#if defined (__bsdi__) || defined(__DragonFly__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#  undef SPT_TYPE
#  define SPT_TYPE	SPT_BUILTIN
#endif

#if defined(__linux__)
#  undef SPT_TYPE
#  define SPT_TYPE	SPT_REUSEARGV
#  define SPT_PADCHAR	'\0'
#endif

#if !defined(__hpux) && (defined(_H3050R) || defined(_HIUX_SOURCE))
#  define SPT_TYPE	SPT_PSTAT
#endif

#if defined(HAVE_SETPROCTITLE)
#  undef SPT_TYPE
#  define SPT_TYPE      SPT_BUILTIN
#endif

char pmacctd_globstr[] = "pmacctd\0";
char nfacctd_globstr[] = "nfacctd\0";
char sfacctd_globstr[] = "sfacctd\0";
char uacctd_globstr[] = "uacctd\0";
char pmtele_globstr[] = "pmtelemetryd\0";
char pmbgpd_globstr[] = "pmbgpd\0";
char pmbmpd_globstr[] = "pmbmpd\0";
