/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2019 by Paolo Lucente
*/

/*
 Originally based on Quagga BGP community attribute related functions
 which is:

 Copyright (C) 1998, 2001 Kunihiro Ishiguro

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

#ifndef _BGP_COMMUNITY_H_
#define _BGP_COMMUNITY_H_

/* Communities attribute.  */
struct community 
{
  /* Reference count of communities value.  */
  unsigned long refcnt;

  /* Communities value size.  */
  int size;

  /* Communities value.  */
  u_int32_t *val;

  /* String of community attribute.  This sring is used by vty output
     and expanded community-list for regular expression match.  */
  char *str;
};

/* Well-known communities value.  */
#define COMMUNITY_INTERNET              0x0
#define COMMUNITY_NO_EXPORT             0xFFFFFF01
#define COMMUNITY_NO_ADVERTISE          0xFFFFFF02
#define COMMUNITY_NO_EXPORT_SUBCONFED   0xFFFFFF03
#define COMMUNITY_LOCAL_AS              0xFFFFFF03

/* Macros of community attribute.  */
#define com_length(X)    ((X)->size * 4)
#define com_lastval(X)   ((X)->val + (X)->size - 1)
#define com_nthval(X,n)  ((X)->val + (n))

/* Prototypes of communities attribute functions.  */
extern struct community *community_new (struct bgp_peer *);
extern void community_init (int, struct hash **);
extern void community_free (struct community *);
extern struct community *community_uniq_sort (struct bgp_peer *, struct community *);
extern struct community *community_intern (struct bgp_peer *, struct community *);
extern void community_unintern (struct bgp_peer *, struct community *);
extern unsigned int community_hash_make (struct community *);
extern int community_cmp (const struct community *, const struct community *);
extern struct community *community_delete (struct community *, struct community *);
extern struct community *community_parse (struct bgp_peer *, u_int32_t *, u_short);
extern int community_include (struct community *, u_int32_t);
extern void community_del_val (struct community *, u_int32_t *);
extern int community_str2com_simple(const char *, u_int32_t *);
extern void community_add_val(struct bgp_peer *, struct community *, u_int32_t);
extern u_int32_t community_val_get(struct community *, int);
extern int community_compare(const void *, const void *);
extern struct community *community_dup(struct community *);
#endif
