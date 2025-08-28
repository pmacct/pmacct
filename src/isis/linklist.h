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
struct pm_listnode 
{
  struct pm_listnode *next;
  struct pm_listnode *prev;
  
  /* private member, use getdata() to retrieve, do not access directly */
  void *data;
};

struct pm_list 
{
  struct pm_listnode *head;
  struct pm_listnode *tail;

  /* invariant: count is the number of listnodes in the list */
  unsigned int count;

  /*
   * Returns -1 if val1 < val2, 0 if equal?, 1 if val1 > val2.
   * Used as definition of sorted for pm_listnode_add_sort
   */
  int (*cmp) (void *val1, void *val2);

  /* callback to free user-owned data when listnode is deleted. supplying
   * this callback is very much encouraged!
   */
  void (*del) (void *val);
};

#define pm_listnextnode(X) ((X)->next)
#define pm_listhead(X) ((X)->head)
#define pm_listtail(X) ((X)->tail)
#define pm_listcount(X) ((X)->count)
#define pm_list_isempty(X) ((X)->head == NULL && (X)->tail == NULL)
#define pm_listgetdata(X) (assert((X)->data != NULL), (X)->data)

/* Prototypes. */
extern struct pm_list *pm_list_new(void); /* encouraged: set list.del callback on new lists */
extern void pm_list_free (struct pm_list *);
extern void pm_listnode_add (struct pm_list *, void *);
extern void pm_listnode_add_sort (struct pm_list *, void *);
extern void pm_listnode_add_after (struct pm_list *, struct pm_listnode *, void *);
extern void pm_listnode_delete (struct pm_list *, void *);
extern struct pm_listnode *pm_listnode_lookup (struct pm_list *, void *);
extern void *pm_listnode_head (struct pm_list *);
extern void pm_list_delete (struct pm_list *);
extern void pm_list_delete_all_node (struct pm_list *);
extern void pm_list_delete_node (struct pm_list *, struct pm_listnode *);
extern void pm_list_add_node_prev (struct pm_list *, struct pm_listnode *, void *);
extern void pm_list_add_node_next (struct pm_list *, struct pm_listnode *, void *);
extern void pm_list_add_list (struct pm_list *, struct pm_list *);

/* List iteration macro. 
 * Usage: for (ALL_LIST_ELEMENTS (...) { ... }
 * It is safe to delete the listnode using this macro.
 */
#define PM_ALL_LIST_ELEMENTS(list,node,nextnode,data) \
  (node) = pm_listhead(list); \
  (node) != NULL && \
    ((data) = pm_listgetdata(node),(nextnode) = pm_listnextnode(node), 1); \
  (node) = (nextnode)

/* read-only list iteration macro.
 * Usage: as per ALL_LIST_ELEMENTS, but not safe to delete the listnode Only
 * use this macro when it is *immediately obvious* the listnode is not
 * deleted in the body of the loop. Does not have forward-reference overhead
 * of previous macro.
 */
#define PM_ALL_LIST_ELEMENTS_RO(list,node,data) \
  (node) = pm_listhead(list); \
  (node) != NULL && ((data) = pm_listgetdata(node), 1); \
  (node) = pm_listnextnode(node)

/* these *do not* cleanup list nodes and referenced data, as the functions
 * do - these macros simply {de,at}tach a listnode from/to a list.
 */
 
/* List node attach macro.  */
#define PM_LISTNODE_ATTACH(L,N) \
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
#define PM_LISTNODE_DETACH(L,N) \
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
