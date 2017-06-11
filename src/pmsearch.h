/* Declarations for System V style searching functions.
   Copyright (C) 1995-2017 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

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
   <http://www.gnu.org/licenses/>.  */

#if defined LINUX

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
}
__pm_VISIT;

typedef int (*pm_compar_fn_t) (const void *, const void *);
typedef int (*pm_action_fn_t) (const void *__nodep, __pm_VISIT __value, int __level);
typedef void (*pm_free_fn_t) (void *__nodep);

/* prototypes */
#if (!defined __PMSEARCH_C)
#define EXT extern
#else
#define EXT
#endif
/* Search for an entry matching the given KEY in the tree pointed to
   by *ROOTP and insert a new element if not found.  */
EXT void *__pm_tsearch (const void *__key, void **__rootp, pm_compar_fn_t __compar);

/* Search for an entry matching the given KEY in the tree pointed to
   by *ROOTP.  If no matching entry is available return NULL.  */
EXT void *__pm_tfind (const void *__key, void *const *__rootp, pm_compar_fn_t __compar);

/* Remove the element matching KEY from the tree pointed to by *ROOTP.  */
EXT void *__pm_tdelete (const void *__restrict __key, void **__restrict __rootp, pm_compar_fn_t __compar);

/* Walk through the whole tree and call the ACTION callback for every node or leaf.  */
EXT void __pm_twalk (const void *__root, pm_action_fn_t __action);

/* Destroy the whole tree, call FREEFCT for each node or leaf.  */
EXT void __pm_tdestroy (void *__root, pm_free_fn_t __freefct);
#undef EXT
#endif
