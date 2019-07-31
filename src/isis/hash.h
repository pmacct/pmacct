/* Hash routine.
   Copyright (C) 1998 Kunihiro Ishiguro

This file is part of GNU Zebra.

GNU Zebra is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published
by the Free Software Foundation; either version 2, or (at your
option) any later version.

GNU Zebra is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with GNU Zebra; see the file COPYING.  If not, write to the
Free Software Foundation, Inc., 59 Temple Place - Suite 330,
Boston, MA 02111-1307, USA.  */

#ifndef _HASH_H_
#define _HASH_H_

/* Default hash table size.  */ 
#define HASHTABSIZE     1024

struct hash_backet
{
  /* Linked list.  */
  struct hash_backet *next;

  /* Hash key. */
  unsigned int key;

  /* Data.  */
  void *data;
};

struct hash
{
  /* Hash backet. */
  struct hash_backet **index;

  /* Hash table size. */
  unsigned int size;

  /* Key make function. */
  unsigned int (*hash_key) (void *);

  /* Data compare function. */
  int (*hash_cmp) (const void *, const void *);

  /* Backet alloc. */
  unsigned long count;
};

extern struct hash *isis_hash_create (unsigned int (*) (void *), int (*) (const void *, const void *));
extern struct hash *isis_hash_create_size (unsigned int, unsigned int (*) (void *),  int (*) (const void *, const void *));
extern void *isis_hash_get (struct hash *, void *, void * (*) (void *));
extern void *isis_hash_alloc_intern (void *);
extern void *isis_hash_lookup (struct hash *, void *);
extern void *isis_hash_release (struct hash *, void *);
extern void isis_hash_iterate (struct hash *, void (*) (struct hash_backet *, void *), void *);
extern void isis_hash_clean (struct hash *, void (*) (void *));
extern void isis_hash_free (struct hash *);
extern unsigned int string_hash_make (const char *);

#endif /* _HASH_H_ */
