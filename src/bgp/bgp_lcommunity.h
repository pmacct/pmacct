/*  
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2016 by Paolo Lucente
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

#define LCOMMUNITY_SIZE	12

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

#if (!defined __BGP_LCOMMUNITY_C)
#define EXT extern
#else
#define EXT
#endif

/* XXX */

#undef EXT
#endif
