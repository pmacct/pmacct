/* Hash routine.
 * Copyright (C) 1998 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2, or (at your
 * option) any later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include "pmacct.h"
#include "isis.h"

#include "hash.h"

/* Allocate a new hash.  */
struct hash *
isis_hash_create_size (unsigned int size, unsigned int (*hash_key) (void *),
                                     int (*hash_cmp) (const void *, const void *))
{
  struct hash *hash;

  hash = calloc(1, sizeof (struct hash));
  hash->index = calloc(1, sizeof (struct hash_backet *) * size);
  hash->size = size;
  hash->hash_key = hash_key;
  hash->hash_cmp = hash_cmp;
  hash->count = 0;

  return hash;
}

/* Allocate a new hash with default hash size.  */
struct hash *
isis_hash_create (unsigned int (*hash_key) (void *), 
             int (*hash_cmp) (const void *, const void *))
{
  return isis_hash_create_size (HASHTABSIZE, hash_key, hash_cmp);
}

/* Utility function for hash_get().  When this function is specified
   as alloc_func, return arugment as it is.  This function is used for
   intern already allocated value.  */
void *
isis_hash_alloc_intern (void *arg)
{
  return arg;
}

/* Lookup and return hash backet in hash.  If there is no
   corresponding hash backet and alloc_func is specified, create new
   hash backet.  */
void *
isis_hash_get (struct hash *hash, void *data, void * (*alloc_func) (void *))
{
  unsigned int key;
  unsigned int index;
  void *newdata;
  struct hash_backet *backet;

  key = (*hash->hash_key) (data);
  index = key % hash->size;

  for (backet = hash->index[index]; backet != NULL; backet = backet->next) 
    if (backet->key == key && (*hash->hash_cmp) (backet->data, data))
      return backet->data;

  if (alloc_func)
    {
      newdata = (*alloc_func) (data);
      if (newdata == NULL)
	return NULL;

      backet = calloc(1, sizeof (struct hash_backet));
      backet->data = newdata;
      backet->key = key;
      backet->next = hash->index[index];
      hash->index[index] = backet;
      hash->count++;
      return backet->data;
    }
  return NULL;
}

/* Hash lookup.  */
void *
isis_hash_lookup (struct hash *hash, void *data)
{
  return isis_hash_get (hash, data, NULL);
}

/* Simple Bernstein hash which is simple and fast for common case */
unsigned int string_hash_make (const char *str)
{
  unsigned int hash = 0;

  while (*str)
    hash = (hash * 33) ^ (unsigned int) *str++;

  return hash;
}

/* This function release registered value from specified hash.  When
   release is successfully finished, return the data pointer in the
   hash backet.  */
void *
isis_hash_release (struct hash *hash, void *data)
{
  void *ret;
  unsigned int key;
  unsigned int index;
  struct hash_backet *backet;
  struct hash_backet *pp;

  key = (*hash->hash_key) (data);
  index = key % hash->size;

  for (backet = pp = hash->index[index]; backet; backet = backet->next)
    {
      if (backet->key == key && (*hash->hash_cmp) (backet->data, data)) 
	{
	  if (backet == pp) 
	    hash->index[index] = backet->next;
	  else 
	    pp->next = backet->next;

	  ret = backet->data;
	  free(backet);
	  hash->count--;
	  return ret;
	}
      pp = backet;
    }
  return NULL;
}

/* Iterator function for hash.  */
void
isis_hash_iterate (struct hash *hash, 
	      void (*func) (struct hash_backet *, void *), void *arg)
{
  unsigned int i;
  struct hash_backet *hb;
  struct hash_backet *hbnext;

  for (i = 0; i < hash->size; i++)
    for (hb = hash->index[i]; hb; hb = hbnext)
      {
	/* get pointer to next hash backet here, in case (*func)
	 * decides to delete hb by calling hash_release
	 */
	hbnext = hb->next;
	(*func) (hb, arg);
      }
}

/* Clean up hash.  */
void
isis_hash_clean (struct hash *hash, void (*free_func) (void *))
{
  unsigned int i;
  struct hash_backet *hb;
  struct hash_backet *next;

  for (i = 0; i < hash->size; i++)
    {
      for (hb = hash->index[i]; hb; hb = next)
	{
	  next = hb->next;
	      
	  if (free_func)
	    (*free_func) (hb->data);

	  free(hb);
	  hash->count--;
	}
      hash->index[i] = NULL;
    }
}

/* Free hash memory.  You may call hash_clean before call this
   function.  */
void
isis_hash_free (struct hash *hash)
{
  free(hash->index);
  free(hash);
}
