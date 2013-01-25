/* Generic linked list
 * Copyright (C) 1997, 2000 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.  
 */

#ifndef _LINKLIST_H_
#define _LINKLIST_H_

/* listnodes must always contain data to be valid. Adding an empty node
 * to a list is invalid
 */
struct listnode 
{
  struct listnode *next;
  struct listnode *prev;
  
  /* private member, use getdata() to retrieve, do not access directly */
  void *data;
};

struct list 
{
  struct listnode *head;
  struct listnode *tail;

  /* invariant: count is the number of listnodes in the list */
  unsigned int count;

  /*
   * Returns -1 if val1 < val2, 0 if equal?, 1 if val1 > val2.
   * Used as definition of sorted for isis_listnode_add_sort
   */
  int (*cmp) (void *val1, void *val2);

  /* callback to free user-owned data when listnode is deleted. supplying
   * this callback is very much encouraged!
   */
  void (*del) (void *val);
};

#define listnextnode(X) ((X)->next)
#define listhead(X) ((X)->head)
#define listtail(X) ((X)->tail)
#define listcount(X) ((X)->count)
#define isis_list_isempty(X) ((X)->head == NULL && (X)->tail == NULL)
#define listgetdata(X) (assert((X)->data != NULL), (X)->data)

/* Prototypes. */
#if (!defined __LINKLIST_C)
#define EXT extern
#else
#define EXT
#endif
EXT struct list *isis_list_new(void); /* encouraged: set list.del callback on new lists */
EXT void isis_list_free (struct list *);
EXT void isis_listnode_add (struct list *, void *);
EXT void isis_listnode_add_sort (struct list *, void *);
EXT void isis_listnode_add_after (struct list *, struct listnode *, void *);
EXT void isis_listnode_delete (struct list *, void *);
EXT struct listnode *isis_listnode_lookup (struct list *, void *);
EXT void *isis_listnode_head (struct list *);
EXT void isis_list_delete (struct list *);
EXT void isis_list_delete_all_node (struct list *);
#undef EXT

/* List iteration macro. 
 * Usage: for (ALL_LIST_ELEMENTS (...) { ... }
 * It is safe to delete the listnode using this macro.
 */
#define ALL_LIST_ELEMENTS(list,node,nextnode,data) \
  (node) = listhead(list); \
  (node) != NULL && \
    ((data) = listgetdata(node),(nextnode) = listnextnode(node), 1); \
  (node) = (nextnode)

/* read-only list iteration macro.
 * Usage: as per ALL_LIST_ELEMENTS, but not safe to delete the listnode Only
 * use this macro when it is *immediately obvious* the listnode is not
 * deleted in the body of the loop. Does not have forward-reference overhead
 * of previous macro.
 */
#define ALL_LIST_ELEMENTS_RO(list,node,data) \
  (node) = listhead(list); \
  (node) != NULL && ((data) = listgetdata(node), 1); \
  (node) = listnextnode(node)

/* these *do not* cleanup list nodes and referenced data, as the functions
 * do - these macros simply {de,at}tach a listnode from/to a list.
 */
 
/* List node attach macro.  */
#define LISTNODE_ATTACH(L,N) \
  do { \
    (N)->prev = (L)->tail; \
    if ((L)->head == NULL) \
      (L)->head = (N); \
    else \
      (L)->tail->next = (N); \
    (L)->tail = (N); \
    (L)->count++; \
  } while (0)

/* List node detach macro.  */
#define LISTNODE_DETACH(L,N) \
  do { \
    if ((N)->prev) \
      (N)->prev->next = (N)->next; \
    else \
      (L)->head = (N)->next; \
    if ((N)->next) \
      (N)->next->prev = (N)->prev; \
    else \
      (L)->tail = (N)->prev; \
    (L)->count--; \
  } while (0)

#endif /* _LINKLIST_H_ */
