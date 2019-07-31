/*  
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2019 by Paolo Lucente
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

#ifndef _BGP_LCOMMUNITY_H_
#define _BGP_LCOMMUNITY_H_

#define LCOMMUNITY_SIZE			12
#define LCOMMUNITY_PART_SIZE 		4
#define LCOMMUNITY_STR_DEFAULT_LEN	32

/* Large Communities attribute */
struct lcommunity
{
  /* Reference counter */
  unsigned long refcnt;

  /* Size of Large Communities attribute.  */
  int size;

  /* Large Communities value.  */
  u_int8_t *val;

  /* Human readable format string.  */
  char *str;
};

/* Extended community value is eight octet.  */
struct lcommunity_val
{
  char val[LCOMMUNITY_SIZE];
};

#define lcom_length(X)    ((X)->size * LCOMMUNITY_SIZE)

extern void lcommunity_init (int, struct hash **);
extern void lcommunity_free (struct lcommunity *);
extern struct lcommunity *lcommunity_new (struct bgp_peer *);
extern struct lcommunity *lcommunity_parse (struct bgp_peer *, u_int8_t *, u_short);
extern struct lcommunity *lcommunity_intern (struct bgp_peer *, struct lcommunity *);
extern int lcommunity_cmp (const void *, const void *);
extern void lcommunity_unintern (struct bgp_peer *, struct lcommunity *);
extern unsigned int lcommunity_hash_make (void *);
extern char *lcommunity_lcom2str (struct bgp_peer *, struct lcommunity *);
extern struct lcommunity *lcommunity_dup(struct lcommunity *);

#endif
