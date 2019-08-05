/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2019 by Paolo Lucente
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
#define AS_SET			1
#define AS_SEQUENCE		2
#define AS_CONFED_SEQUENCE	3
#define AS_CONFED_SET		4

/* Private AS range defined in RFC2270.  */
#define BGP_PRIVATE_AS_MIN	64512U
#define BGP_PRIVATE_AS_MAX	65535U

/* we leave BGP_AS_MAX as the 16bit AS MAX number.  */
#define BGP_AS_MAX		65535U
#define BGP_AS4_MAX		4294967295U
/* Transition 16Bit AS as defined by IANA */
#define BGP_AS_TRANS		23456U

/* Attr. Flags and Attr. Type Code. */
#define AS_HEADER_SIZE		2  

/* Now FOUR octets are used for AS value. */
#define AS_VALUE_SIZE		sizeof (as_t)
/* This is the old one */
#define AS16_VALUE_SIZE		sizeof (as16_t)

/* Maximum protocol segment length value */
#define AS_SEGMENT_MAX		255

/* Calculated size in bytes of ASN segment data to hold N ASN's */
#define ASSEGMENT_DATA_SIZE(N,S) \
	((N) * ( (S) ? AS_VALUE_SIZE : AS16_VALUE_SIZE) )

/* Calculated size of segment struct to hold N ASN's */
#define ASSEGMENT_SIZE(N,S)  (AS_HEADER_SIZE + ASSEGMENT_DATA_SIZE (N,S))

/* AS segment octet length. */
#define ASSEGMENT_LEN(X,S) ASSEGMENT_SIZE((X)->length,S)

/* AS_SEQUENCE segments can be packed together */
/* Can the types of X and Y be considered for packing? */
#define ASSEGMENT_TYPES_PACKABLE(X,Y) \
	( ((X)->type == (Y)->type) \
	&& ((X)->type == AS_SEQUENCE))
/* Types and length of X,Y suitable for packing? */
#define ASSEGMENTS_PACKABLE(X,Y) \
	( ASSEGMENT_TYPES_PACKABLE( (X), (Y)) \
	&& ( ((X)->length + (Y)->length) <= AS_SEGMENT_MAX ) )

#define ASPATH_STR_DEFAULT_LEN 32

/* AS path string lexical token enum. */
enum as_token
{
  as_token_asval,
  as_token_set_start,
  as_token_set_end,
  as_token_confed_seq_start,
  as_token_confed_seq_end,
  as_token_confed_set_start,
  as_token_confed_set_end,
  as_token_unknown
};

/* As segment header - the on-wire representation NOT the internal representation! */
struct assegment_header
{
  u_char type;
  u_char length;
};

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

/* Prototypes. */
extern void aspath_init (int, struct hash **);
extern struct aspath *aspath_parse (struct bgp_peer *, char *, size_t, int);
extern struct aspath *aspath_dup (struct aspath *);
extern int aspath_cmp_left (const struct aspath *, const struct aspath *);
extern int aspath_cmp_left_confed (const struct aspath *, const struct aspath *);
extern void aspath_free (struct aspath *);
extern struct aspath *aspath_intern (struct bgp_peer *, struct aspath *);
extern void aspath_unintern (struct bgp_peer *, struct aspath *);
extern const char *aspath_print (struct aspath *);
extern const char *aspath_gettoken (const char *, enum as_token *, as_t *);
extern struct aspath *aspath_str2aspath (const char *);
extern struct aspath *aspath_ast2aspath (as_t);
extern struct aspath *aspath_parse_ast(struct bgp_peer *, as_t);
extern unsigned int aspath_key_make (void *);
extern int aspath_loop_check (struct aspath *, as_t);
extern int aspath_private_as_check (struct aspath *);
extern int aspath_firstas_check (struct aspath *, as_t);
extern unsigned int aspath_count_hops (struct aspath *);
extern unsigned int aspath_count_confeds (struct aspath *);
extern unsigned int aspath_size (struct aspath *);
extern as_t aspath_highest (struct aspath *);
extern char *aspath_make_empty(); 

extern struct aspath *aspath_reconcile_as4 (struct aspath *, struct aspath *);
extern unsigned int aspath_has_as4 (struct aspath *);
extern unsigned int aspath_count_numas (struct aspath *);

#endif
