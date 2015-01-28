/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2015 by Paolo Lucente
*/

/* 
 Originally based on Quagga AS path related definitions which is:
 
 Copyright (C) 1997, 98, 99 Kunihiro Ishiguro

GNU Zebra is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2, or (at your option) any
later version.

GNU Zebra is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with GNU Zebra; see the file COPYING.  If not, write to the Free
Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
02111-1307, USA.  */

#ifndef _BGP_ASPATH_H_
#define _BGP_ASPATH_H_

/* AS path segment type.  */
#define AS_SET                       1
#define AS_SEQUENCE                  2
#define AS_CONFED_SEQUENCE           3
#define AS_CONFED_SET                4

/* Private AS range defined in RFC2270.  */
#define BGP_PRIVATE_AS_MIN       64512U
#define BGP_PRIVATE_AS_MAX       65535U

/* we leave BGP_AS_MAX as the 16bit AS MAX number.  */
#define BGP_AS_MAX		     65535U
#define BGP_AS4_MAX		4294967295U
/* Transition 16Bit AS as defined by IANA */
#define BGP_AS_TRANS		 23456U

/* AS_PATH segment data in abstracted form, no limit is placed on length */
struct assegment
{
  struct assegment *next;
  as_t *as;
  u_short length;
  u_char type;
};

/* AS path may be include some AsSegments.  */
struct aspath 
{
  /* Reference count to this aspath.  */
  unsigned long refcnt;

  /* segment data */
  struct assegment *segments;
  as_t last_as;

  char *str;
};

#define ASPATH_STR_DEFAULT_LEN 32

/* Prototypes. */
#if (!defined __BGP_ASPATH_C)
#define EXT extern
#else
#define EXT
#endif
EXT void aspath_init (struct hash **);
EXT void aspath_finish (void);
EXT struct aspath *aspath_parse (char *, size_t, int);
EXT struct aspath *aspath_dup (struct aspath *);
EXT struct aspath *aspath_aggregate (struct aspath *, struct aspath *);
EXT struct aspath *aspath_prepend (struct aspath *, struct aspath *);
EXT struct aspath *aspath_filter_exclude (struct aspath *, struct aspath *);
EXT struct aspath *aspath_add_seq (struct aspath *, as_t);
EXT struct aspath *aspath_add_confed_seq (struct aspath *, as_t);
EXT int aspath_cmp_left (const struct aspath *, const struct aspath *);
EXT int aspath_cmp_left_confed (const struct aspath *, const struct aspath *);
EXT struct aspath *aspath_delete_confed_seq (struct aspath *);
EXT struct aspath *aspath_empty (void);
EXT struct aspath *aspath_empty_get (void);
EXT struct aspath *aspath_str2aspath (const char *);
EXT void aspath_free (struct aspath *);
EXT struct aspath *aspath_intern (struct aspath *);
EXT void aspath_unintern (struct aspath *);
EXT const char *aspath_print (struct aspath *);
EXT unsigned int aspath_key_make (void *);
EXT int aspath_loop_check (struct aspath *, as_t);
EXT int aspath_private_as_check (struct aspath *);
EXT int aspath_firstas_check (struct aspath *, as_t);
EXT unsigned long aspath_count (void);
EXT unsigned int aspath_count_hops (struct aspath *);
EXT unsigned int aspath_count_confeds (struct aspath *);
EXT unsigned int aspath_size (struct aspath *);
EXT as_t aspath_highest (struct aspath *);

EXT struct aspath *aspath_reconcile_as4 (struct aspath *, struct aspath *);
EXT unsigned int aspath_has_as4 (struct aspath *);
EXT unsigned int aspath_count_numas (struct aspath *);

#undef EXT
#endif
