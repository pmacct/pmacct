/*
   Copyright (C) 1993-2018 Free Software Foundation, Inc.
   This file is based on the GNU C Library and contains:

   * Declarations for System V style searching functions
   * Declarations for hash hash table management functions

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.
*/
#ifndef PMSEARCH_H
#define PMSEARCH_H

/* includes */
#include <stddef.h>
#include <stdint.h>

/* definitions */
typedef struct pm_node_t
{
  /* Callers expect this to be the first element in the structure - do not
     move!  */
  const void *key;
  uintptr_t left_node; /* Includes whether the node is red in low-bit. */
  uintptr_t right_node;
} *pm_node;

#define RED(N) (pm_node)((N)->left_node & ((uintptr_t) 0x1))
#define SETRED(N) (N)->left_node |= ((uintptr_t) 0x1)
#define SETBLACK(N) (N)->left_node &= ~((uintptr_t) 0x1)
#define SETNODEPTR(NP,P) (*NP) = (pm_node)((((uintptr_t)(*NP)) \
                                         & (uintptr_t) 0x1) | (uintptr_t)(P))
#define LEFT(N) (pm_node)((N)->left_node & ~((uintptr_t) 0x1))
#define LEFTPTR(N) (pm_node *)(&(N)->left_node)
#define SETLEFT(N,L) (N)->left_node = (((N)->left_node & (uintptr_t) 0x1) \
                                       | (uintptr_t)(L))
#define RIGHT(N) (pm_node)((N)->right_node)
#define RIGHTPTR(N) (pm_node *)(&(N)->right_node)
#define SETRIGHT(N,R) (N)->right_node = (uintptr_t)(R)
#define DEREFNODEPTR(NP) (pm_node)((uintptr_t)(*(NP)) & ~((uintptr_t) 0x1))

typedef const struct pm_node_t *pm_const_node;

/* The tsearch routines are very interesting. They make many
   assumptions about the compiler.  It assumes that the first field
   in node must be the "key" field, which points to the datum.
   Everything depends on that.  */
typedef enum
{
  preorder,
  postorder,
  endorder,
  leaf
} pm_VISIT;

typedef int (*pm_compar_fn_t) (const void *, const void *);
typedef int (*pm_action_fn_t) (const void *, pm_VISIT, int, void *);
typedef void (*pm_free_fn_t) (void *);

typedef enum {
  FIND,
  INSERT,
  DELETE
} pm_ACTION;

typedef struct pm_hentry_t {
  void *key;
  unsigned int keylen;
  void *data;
} pm_HENTRY;

typedef struct _pm_hentry_t {
  unsigned int used;
  pm_HENTRY entry;
} _pm_HENTRY;

struct pm_htable {
  _pm_HENTRY *table;
  unsigned int size;
  unsigned int filled;
};

/* prototypes */
/* Search for an entry matching the given KEY in the tree pointed to
   by *ROOTP and insert a new element if not found.  */
extern void *__pm_tsearch (const void *, void **, pm_compar_fn_t);

/* Search for an entry matching the given KEY in the tree pointed to
   by *ROOTP.  If no matching entry is available return NULL.  */
extern void *pm_tfind (const void *, void **, pm_compar_fn_t);

/* Remove the element matching KEY from the tree pointed to by *ROOTP.  */
extern void *pm_tdelete (const void *, void **, pm_compar_fn_t);

/* Walk through the whole tree and call the ACTION callback for every node or leaf.  */
extern void pm_twalk (const void *, pm_action_fn_t, void *);

/* Destroy the whole tree, call FREEFCT for each node or leaf.  */
extern void __pm_tdestroy (void *, pm_free_fn_t);

extern int pm_hcreate(size_t, struct pm_htable *);
extern void pm_hdestroy(struct pm_htable *);
extern int pm_hsearch(pm_HENTRY, pm_ACTION, pm_HENTRY **, struct pm_htable *);
extern void pm_hmove(struct pm_htable *, struct pm_htable *, struct pm_htable *);
extern void __pm_hdelete(_pm_HENTRY *);

#endif //PMSEARCH_H
