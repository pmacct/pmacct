/*
   Copyright (C) 1993-2018 Free Software Foundation, Inc.
   This file is largely based on the GNU C Library and contains:

   * System V style searching functions
     - Contributed by Bernd Schmidt <crux@Pool.Informatik.RWTH-Aachen.DE>, 1997.
   * Hash table management functions
     - Contributed by Ulrich Drepper <drepper@gnu.ai.mit.edu>, 1993.

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

/* Tree search for red/black trees.
   The algorithm for adding nodes is taken from one of the many "Algorithms"
   books by Robert Sedgewick, although the implementation differs.
   The algorithm for deleting nodes can probably be found in a book named
   "Introduction to Algorithms" by Cormen/Leiserson/Rivest.  At least that's
   the book that my professor took most algorithms from during the "Data
   Structures" course... Totally public domain.  */

/* Red/black trees are binary trees in which the edges are colored either red
   or black.  They have the following properties:
   1. The number of black edges on every path from the root to a leaf is
      constant.
   2. No two red edges are adjacent.
   Therefore there is an upper bound on the length of every path, it's
   O(log n) where n is the number of nodes in the tree.  No path can be longer
   than 1+2*P where P is the length of the shortest path in the tree.
   Useful for the implementation:
   3. If one of the children of a node is NULL, then the other one is red
      (if it exists).

   In the implementation, not the edges are colored, but the nodes.  The color
   interpreted as the color of the edge leading to this node.  The color is
   meaningless for the root node, but we color the root node black for
   convenience.  All added nodes are red initially.

   Adding to a red/black tree is rather easy.  The right place is searched
   with a usual binary tree search.  Additionally, whenever a node N is
   reached that has two red successors, the successors are colored black and
   the node itself colored red.  This moves red edges up the tree where they
   pose less of a problem once we get to really insert the new node.  Changing
   N's color to red may violate rule 2, however, so rotations may become
   necessary to restore the invariants.  Adding a new red leaf may violate
   the same rule, so afterwards an additional check is run and the tree
   possibly rotated.

   Deleting is hairy.  There are mainly two nodes involved: the node to be
   deleted (n1), and another node that is to be unchained from the tree (n2).
   If n1 has a successor (the node with a smallest key that is larger than
   n1), then the successor becomes n2 and its contents are copied into n1,
   otherwise n1 becomes n2.
   Unchaining a node may violate rule 1: if n2 is black, one subtree is
   missing one black edge afterwards.  The algorithm must try to move this
   error upwards towards the root, so that the subtree that does not have
   enough black edges becomes the whole tree.  Once that happens, the error
   has disappeared.  It may not be necessary to go all the way up, since it
   is possible that rotations and recoloring can fix the error before that.

   Although the deletion algorithm must walk upwards through the tree, we
   do not store parent pointers in the nodes.  Instead, delete allocates a
   small array of parent pointers and fills it while descending the tree.
   Since we know that the length of a path is O(log n), where n is the number
   of nodes, this is likely to use less memory.  */

/* Tree rotations look like this:
      A                C
     / \              / \
    B   C            A   G
   / \ / \  -->     / \
   D E F G         B   F
                  / \
                 D   E

   In this case, A has been rotated left.  This preserves the ordering of the
   binary tree.  */

/* includes */
#include "pmacct.h"
#include "crc32.h"

/* Possibly "split" a node with two red successors, and/or fix up two red
   edges in a row.  ROOTP is a pointer to the lowest node we visited, PARENTP
   and GPARENTP pointers to its parent/grandparent.  P_R and GP_R contain the
   comparison values that determined which way was taken in the tree to reach
   ROOTP.  MODE is 1 if we need not do the split, but must check for two red
   edges between GPARENTP and ROOTP.  */
static void
pm_maybe_split_for_insert (pm_node *rootp, pm_node *parentp, pm_node *gparentp,
			int p_r, int gp_r, int mode)
{
  pm_node root = DEREFNODEPTR(rootp);
  pm_node *rp, *lp;
  pm_node rpn, lpn;
  rp = RIGHTPTR(root);
  rpn = RIGHT(root);
  lp = LEFTPTR(root);
  lpn = LEFT(root);

  /* See if we have to split this node (both successors red).  */
  if (mode == 1
      || ((rpn) != NULL && (lpn) != NULL && RED(rpn) && RED(lpn)))
    {
      /* This node becomes red, its successors black.  */
      SETRED(root);
      if (rpn)
	SETBLACK(rpn);
      if (lpn)
	SETBLACK(lpn);

      /* If the parent of this node is also red, we have to do
	 rotations.  */
      if (parentp != NULL && RED(DEREFNODEPTR(parentp)))
	{
	  pm_node gp = DEREFNODEPTR(gparentp);
	  pm_node p = DEREFNODEPTR(parentp);
	  /* There are two main cases:
	     1. The edge types (left or right) of the two red edges differ.
	     2. Both red edges are of the same type.
	     There exist two symmetries of each case, so there is a total of
	     4 cases.  */
	  if ((p_r > 0) != (gp_r > 0))
	    {
	      /* Put the child at the top of the tree, with its parent
		 and grandparent as successors.  */
	      SETRED(p);
	      SETRED(gp);
	      SETBLACK(root);
	      if (p_r < 0)
		{
		  /* Child is left of parent.  */
		  SETLEFT(p,rpn);
		  SETNODEPTR(rp,p);
		  SETRIGHT(gp,lpn);
		  SETNODEPTR(lp,gp);
		}
	      else
		{
		  /* Child is right of parent.  */
		  SETRIGHT(p,lpn);
		  SETNODEPTR(lp,p);
		  SETLEFT(gp,rpn);
		  SETNODEPTR(rp,gp);
		}
	      SETNODEPTR(gparentp,root);
	    }
	  else
	    {
	      SETNODEPTR(gparentp,p);
	      /* Parent becomes the top of the tree, grandparent and
		 child are its successors.  */
	      SETBLACK(p);
	      SETRED(gp);
	      if (p_r < 0)
		{
		  /* Left edges.  */
		  SETLEFT(gp,RIGHT(p));
		  SETRIGHT(p,gp);
		}
	      else
		{
		  /* Right edges.  */
		  SETRIGHT(gp,LEFT(p));
		  SETLEFT(p,gp);
		}
	    }
	}
    }
}

/* Find or insert datum into search tree.
   KEY is the key to be located, ROOTP is the address of tree root,
   COMPAR the ordering function.  */
void * __pm_tsearch (const void *key, void **vrootp, pm_compar_fn_t compar)
{
  pm_node q, root;
  pm_node *parentp = NULL, *gparentp = NULL;
  pm_node *rootp = (pm_node *) vrootp;
  pm_node *nextp;
  int r = 0, p_r = 0, gp_r = 0; /* No they might not, Mr Compiler.  */

  // static_assert (alignof (max_align_t) > 1, "malloc must return aligned ptrs");

  if (rootp == NULL)
    return NULL;

  /* This saves some additional tests below.  */
  root = DEREFNODEPTR(rootp);
  if (root != NULL)
    SETBLACK(root);

  nextp = rootp;
  while (DEREFNODEPTR(nextp) != NULL)
    {
      root = DEREFNODEPTR(rootp);
      r = (*compar) (key, root->key);
      if (r == 0)
	return root;

      pm_maybe_split_for_insert (rootp, parentp, gparentp, p_r, gp_r, 0);
      /* If that did any rotations, parentp and gparentp are now garbage.
	 That doesn't matter, because the values they contain are never
	 used again in that case.  */

      nextp = r < 0 ? LEFTPTR(root) : RIGHTPTR(root);
      if (DEREFNODEPTR(nextp) == NULL)
	break;

      gparentp = parentp;
      parentp = rootp;
      rootp = nextp;

      gp_r = p_r;
      p_r = r;
    }

  q = (struct pm_node_t *) malloc (sizeof (struct pm_node_t));
  if (q != NULL)
    {
      /* Make sure the malloc implementation returns naturally aligned
	 memory blocks when expected.  Or at least even pointers, so we
	 can use the low bit as red/black flag.  Even though we have a
	 static_assert to make sure alignof (max_align_t) > 1 there could
	 be an interposed malloc implementation that might cause havoc by
	 not obeying the malloc contract.  */
      assert (((uintptr_t) q & (uintptr_t) 0x1) == 0);
      SETNODEPTR(nextp,q);		/* link new node to old */
      q->key = key;			/* initialize new node */
      SETRED(q);
      SETLEFT(q,NULL);
      SETRIGHT(q,NULL);

      if (nextp != rootp)
	/* There may be two red edges in a row now, which we must avoid by
	   rotating the tree.  */
	pm_maybe_split_for_insert (nextp, rootp, parentp, r, p_r, 1);
    }

  return q;
}

/* Find datum in search tree.
   KEY is the key to be located, ROOTP is the address of tree root,
   COMPAR the ordering function.  */
void *pm_tfind (const void *key, void **vrootp, pm_compar_fn_t compar)
{
  pm_node root;
  pm_node *rootp = (pm_node *) vrootp;

  if (rootp == NULL)
    return NULL;

  root = DEREFNODEPTR(rootp);

  while (DEREFNODEPTR(rootp) != NULL)
    {
      root = DEREFNODEPTR(rootp);
      int r;

      r = (*compar) (key, root->key);
      if (r == 0)
	return root;

      rootp = r < 0 ? LEFTPTR(root) : RIGHTPTR(root);
    }
  return NULL;
}

/* Delete node with given key.
   KEY is the key to be deleted, ROOTP is the address of the root of tree,
   COMPAR the comparison function.  */
void *pm_tdelete (const void *key, void **vrootp, pm_compar_fn_t compar)
{
  pm_node p, q, r, retval;
  int cmp;
  pm_node *rootp = (pm_node *) vrootp;
  pm_node root, unchained;
  /* Stack of nodes so we remember the parents without recursion.  It's
     _very_ unlikely that there are paths longer than 40 nodes.  The tree
     would need to have around 250.000 nodes.  */
  int stacksize = 40;
  int sp = 0;
  pm_node **nodestack = alloca (sizeof (pm_node *) * stacksize);

  if (rootp == NULL)
    return NULL;
  p = DEREFNODEPTR(rootp);
  if (p == NULL)
    return NULL;

  root = DEREFNODEPTR(rootp);
  while ((cmp = (*compar) (key, root->key)) != 0)
    {
      if (sp == stacksize)
	{
	  pm_node **newstack;
	  stacksize += 20;
	  newstack = alloca (sizeof (pm_node *) * stacksize);
	  nodestack = memcpy (newstack, nodestack, sp * sizeof (pm_node *));
	}

      nodestack[sp++] = rootp;
      p = DEREFNODEPTR(rootp);
      if (cmp < 0)
	{
	  rootp = LEFTPTR(p);
	  root = LEFT(p);
	}
      else
	{
	  rootp = RIGHTPTR(p);
	  root = RIGHT(p);
	}
      if (root == NULL)
	return NULL;
    }

  /* This is bogus if the node to be deleted is the root... this routine
     really should return an integer with 0 for success, -1 for failure */
  retval = p;

  /* We don't unchain the node we want to delete. Instead, we overwrite
     it with its successor and unchain the successor.  If there is no
     successor, we really unchain the node to be deleted.  */

  root = DEREFNODEPTR(rootp);

  r = RIGHT(root);
  q = LEFT(root);

  if (q == NULL || r == NULL)
    unchained = root;
  else
    {
      pm_node *parentp = rootp, *up = RIGHTPTR(root);
      pm_node upn;
      for (;;)
	{
	  if (sp == stacksize)
	    {
	      pm_node **newstack;
	      stacksize += 20;
	      newstack = alloca (sizeof (pm_node *) * stacksize);
	      nodestack = memcpy (newstack, nodestack, sp * sizeof (pm_node *));
	    }
	  nodestack[sp++] = parentp;
	  parentp = up;
	  upn = DEREFNODEPTR(up);
	  if (LEFT(upn) == NULL)
	    break;
	  up = LEFTPTR(upn);
	}
      unchained = DEREFNODEPTR(up);
    }

  /* We know that either the left or right successor of UNCHAINED is NULL.
     R becomes the other one, it is chained into the parent of UNCHAINED.  */
  r = LEFT(unchained);
  if (r == NULL)
    r = RIGHT(unchained);
  if (sp == 0)
    SETNODEPTR(rootp,r);
  else
    {
      q = DEREFNODEPTR(nodestack[sp-1]);
      if (unchained == RIGHT(q))
	SETRIGHT(q,r);
      else
	SETLEFT(q,r);
    }

  if (unchained != root)
    root->key = unchained->key;
  if (!RED(unchained))
    {
      /* Now we lost a black edge, which means that the number of black
	 edges on every path is no longer constant.  We must balance the
	 tree.  */
      /* NODESTACK now contains all parents of R.  R is likely to be NULL
	 in the first iteration.  */
      /* NULL nodes are considered black throughout - this is necessary for
	 correctness.  */
      while (sp > 0 && (r == NULL || !RED(r)))
	{
	  pm_node *pp = nodestack[sp - 1];
	  p = DEREFNODEPTR(pp);
	  /* Two symmetric cases.  */
	  if (r == LEFT(p))
	    {
	      /* Q is R's brother, P is R's parent.  The subtree with root
		 R has one black edge less than the subtree with root Q.  */
	      q = RIGHT(p);
	      if (RED(q))
		{
		  /* If Q is red, we know that P is black. We rotate P left
		     so that Q becomes the top node in the tree, with P below
		     it.  P is colored red, Q is colored black.
		     This action does not change the black edge count for any
		     leaf in the tree, but we will be able to recognize one
		     of the following situations, which all require that Q
		     is black.  */
		  SETBLACK(q);
		  SETRED(p);
		  /* Left rotate p.  */
		  SETRIGHT(p,LEFT(q));
		  SETLEFT(q,p);
		  SETNODEPTR(pp,q);
		  /* Make sure pp is right if the case below tries to use
		     it.  */
		  nodestack[sp++] = pp = LEFTPTR(q);
		  q = RIGHT(p);
		}
	      /* We know that Q can't be NULL here.  We also know that Q is
		 black.  */
	      if ((LEFT(q) == NULL || !RED(LEFT(q)))
		  && (RIGHT(q) == NULL || !RED(RIGHT(q))))
		{
		  /* Q has two black successors.  We can simply color Q red.
		     The whole subtree with root P is now missing one black
		     edge.  Note that this action can temporarily make the
		     tree invalid (if P is red).  But we will exit the loop
		     in that case and set P black, which both makes the tree
		     valid and also makes the black edge count come out
		     right.  If P is black, we are at least one step closer
		     to the root and we'll try again the next iteration.  */
		  SETRED(q);
		  r = p;
		}
	      else
		{
		  /* Q is black, one of Q's successors is red.  We can
		     repair the tree with one operation and will exit the
		     loop afterwards.  */
		  if (RIGHT(q) == NULL || !RED(RIGHT(q)))
		    {
		      /* The left one is red.  We perform the same action as
			 in maybe_split_for_insert where two red edges are
			 adjacent but point in different directions:
			 Q's left successor (let's call it Q2) becomes the
			 top of the subtree we are looking at, its parent (Q)
			 and grandparent (P) become its successors. The former
			 successors of Q2 are placed below P and Q.
			 P becomes black, and Q2 gets the color that P had.
			 This changes the black edge count only for node R and
			 its successors.  */
		      pm_node q2 = LEFT(q);
		      if (RED(p))
			SETRED(q2);
		      else
			SETBLACK(q2);
		      SETRIGHT(p,LEFT(q2));
		      SETLEFT(q,RIGHT(q2));
		      SETRIGHT(q2,q);
		      SETLEFT(q2,p);
		      SETNODEPTR(pp,q2);
		      SETBLACK(p);
		    }
		  else
		    {
		      /* It's the right one.  Rotate P left. P becomes black,
			 and Q gets the color that P had.  Q's right successor
			 also becomes black.  This changes the black edge
			 count only for node R and its successors.  */
		      if (RED(p))
			SETRED(q);
		      else
			SETBLACK(q);
		      SETBLACK(p);

		      SETBLACK(RIGHT(q));

		      /* left rotate p */
		      SETRIGHT(p,LEFT(q));
		      SETLEFT(q,p);
		      SETNODEPTR(pp,q);
		    }

		  /* We're done.  */
		  sp = 1;
		  r = NULL;
		}
	    }
	  else
	    {
	      /* Comments: see above.  */
	      q = LEFT(p);
	      if (RED(q))
		{
		  SETBLACK(q);
		  SETRED(p);
		  SETLEFT(p,RIGHT(q));
		  SETRIGHT(q,p);
		  SETNODEPTR(pp,q);
		  nodestack[sp++] = pp = RIGHTPTR(q);
		  q = LEFT(p);
		}
	      if ((RIGHT(q) == NULL || !RED(RIGHT(q)))
		  && (LEFT(q) == NULL || !RED(LEFT(q))))
		{
		  SETRED(q);
		  r = p;
		}
	      else
		{
		  if (LEFT(q) == NULL || !RED(LEFT(q)))
		    {
		      pm_node q2 = RIGHT(q);
		      if (RED(p))
			SETRED(q2);
		      else
			SETBLACK(q2);
		      SETLEFT(p,RIGHT(q2));
		      SETRIGHT(q,LEFT(q2));
		      SETLEFT(q2,q);
		      SETRIGHT(q2,p);
		      SETNODEPTR(pp,q2);
		      SETBLACK(p);
		    }
		  else
		    {
		      if (RED(p))
			SETRED(q);
		      else
			SETBLACK(q);
		      SETBLACK(p);
		      SETBLACK(LEFT(q));
		      SETLEFT(p,RIGHT(q));
		      SETRIGHT(q,p);
		      SETNODEPTR(pp,q);
		    }
		  sp = 1;
		  r = NULL;
		}
	    }
	  --sp;
	}
      if (r != NULL)
	SETBLACK(r);
    }

  free (unchained);
  return retval;
}

/* Walk the nodes of a tree.
   ROOT is the root of the tree to be walked, ACTION the function to be
   called at each node.  LEVEL is the level of ROOT in the whole tree.
   RET, the return level from ACTION, says if continue (TRUE) or break
   (FALSE), ie. due to budgeted traversal */
static void pm_trecurse (const void *vroot, pm_action_fn_t action, int level, void *extra)
{
  int ret = TRUE;
  pm_const_node root = (pm_const_node) vroot;

  if (LEFT(root) == NULL && RIGHT(root) == NULL) {
    ret = (*action) (root, leaf, level, extra);
  }
  else {
    ret = (*action) (root, preorder, level, extra);
    if (!ret) goto exit_lane;

    if (LEFT(root) != NULL)
      pm_trecurse (LEFT(root), action, level + 1, extra);

    ret = (*action) (root, postorder, level, extra);
    if (!ret) goto exit_lane;

    if (RIGHT(root) != NULL)
      pm_trecurse (RIGHT(root), action, level + 1, extra);

    ret = (*action) (root, endorder, level, extra);
    if (!ret) goto exit_lane;
  }

  exit_lane:

  return;
}

/* Walk the nodes of a tree.
   ROOT is the root of the tree to be walked, ACTION the function to be
   called at each node.  */
void pm_twalk (const void *vroot, pm_action_fn_t action, void *extra)
{
  pm_const_node root = (pm_const_node) vroot;

  if (root != NULL && action != NULL)
    pm_trecurse (root, action, 0, extra);
}

/* The standardized functions miss an important functionality: the
   tree cannot be removed easily.  We provide a function to do this.  */
static void pm_tdestroy_recurse (pm_node root, pm_free_fn_t freefct)
{
  if (LEFT(root) != NULL)
    pm_tdestroy_recurse (LEFT(root), freefct);
  if (RIGHT(root) != NULL)
    pm_tdestroy_recurse (RIGHT(root), freefct);
  (*freefct) ((void *) root->key);
  /* Free the node itself.  */
  free (root);
}

void __pm_tdestroy (void *vroot, pm_free_fn_t freefct)
{
  pm_node root = (pm_node) vroot;

  if (root != NULL)
    pm_tdestroy_recurse (root, freefct);
}

/* For the used double hash method the table size has to be a prime. To
   correct the user given table size we need a prime test.  This trivial
   algorithm is adequate because
   a)  the code is (most probably) called a few times per program run and
   b)  the number is small because the table must fit in the core  */
static int pm_isprime(unsigned int number)
{
  unsigned int div;

  /* no even number will be passed */
  for (div = 3; div <= number / div; div += 2) {
    if (number % div == 0) return 0;
  }

  return 1;
}

/* Before using the hash table we must allocate memory for it.
   Test for an existing table are done. We allocate one element
   more as the found prime number says. This is done for more effective
   indexing as explained in the comment for the hsearch function.
   The contents of the table is zeroed, especially the field used
   becomes zero.  */
int pm_hcreate(size_t nel, struct pm_htable *htab)
{
  /* Test for correct arguments.  */
  if (htab == NULL) return 0;

  /* There is still another table active. Return with error. */
  if (htab->table != NULL) return 0;

  /* We need a size of at least 3.  Otherwise the hash functions we
     use will not work.  */
  if (nel < 3) nel = 3;

  /* Change nel to the first prime number in the range [nel, UINT_MAX - 2],
     The '- 2' means 'nel += 2' cannot overflow.  */
  for (nel |= 1; ; nel += 2) {
    if (UINT_MAX - 2 < nel) return 0;

    if (pm_isprime (nel)) break;
  }

  htab->size = nel;
  htab->filled = 0;

  /* allocate memory and zero out */
  htab->table = (_pm_HENTRY *) calloc (htab->size + 1, sizeof (_pm_HENTRY));
  if (htab->table == NULL) return 0;

  /* everything went alright */
  return 1;
}

/* After using the hash table it has to be destroyed. The used memory can
   be freed and the local static variable can be marked as not used.  */
void pm_hdestroy(struct pm_htable *htab)
{
  size_t idx;

  /* Test for correct arguments.  */
  if (htab == NULL) return;

  for (idx = 0; idx < htab->size; idx++) __pm_hdelete(&htab->table[idx]);

  /* Free used memory.  */
  free (htab->table);

  /* the sign for an existing table is an value != NULL in htable */
  htab->table = NULL;
}

/* This is the search function. It uses double hashing with open addressing.
   The argument item.key has to be a pointer to an zero terminated, most
   probably strings of chars. The function for generating a number of the
   strings is simple but fast. It can be replaced by a more complex function
   like ajw (see [Aho,Sethi,Ullman]) if the needs are shown.
   We use an trick to speed up the lookup. The table is created by hcreate
   with one more element available. This enables us to use the index zero
   special. This index will never be used because we store the first hash
   index in the field used where zero means not used. Every other value
   means used. The used field can be used as a first fast comparison for
   equality of the stored and the parameter value. This helps to prevent
   unnecessary more expensive calls of memcmp.  */
int pm_hsearch(pm_HENTRY item, pm_ACTION action, pm_HENTRY **retval, struct pm_htable *htab)
{
  unsigned int hval;
  unsigned int idx;

  /* Compute an value for the given string. Perhaps use a better method. */
  hval = cache_crc32(item.key, item.keylen);

  /* First hash function: simply take the modul but prevent zero. */
  idx = hval % htab->size + 1;
  if (htab->table[idx].used) {
    /* Further action might be required according to the action value. */
    if (htab->table[idx].used == hval && item.keylen == htab->table[idx].entry.keylen
        && (!memcmp(item.key, htab->table[idx].entry.key, item.keylen))) {
      if (action == DELETE) {
	__pm_hdelete(&htab->table[idx]);
	(*retval) = NULL;
      }
      else {
        (*retval) = &htab->table[idx].entry;
      }

      return 1;
    }

    /* Second hash function, as suggested in [Knuth] */
    unsigned int hval2 = 1 + hval % (htab->size - 2);
    unsigned int first_idx = idx;
    do {
      /* Because SIZE is prime this guarantees to step through all available indeces */
      if (idx <= hval2) idx = htab->size + idx - hval2;
      else idx -= hval2;

      /* If we visited all entries leave the loop unsuccessfully.  */
      if (idx == first_idx) break;

      /* If entry is found use it. */
      if (htab->table[idx].used == hval && item.keylen == htab->table[idx].entry.keylen
	  && (!memcmp(item.key, htab->table[idx].entry.key, item.keylen))) {
	if (action == DELETE) {
	  __pm_hdelete(&htab->table[idx]);
	  (*retval) = NULL;
	}
	else {
	  (*retval) = &htab->table[idx].entry;
	}

	return 1;
      }
    }
    while (htab->table[idx].used);
  }

  /* An empty bucket has been found. */
  if (action == INSERT) {
    /* If table is full and another entry should be entered return with error.  */
    if (htab->filled == htab->size) {
      *retval = NULL;
      return ERR;
    }

    htab->table[idx].used  = hval;
    htab->table[idx].entry = item;
    ++htab->filled;
    *retval = &htab->table[idx].entry;

    return 1;
  }

  *retval = NULL;
  return 0;
}

void pm_hmove(struct pm_htable *new_htab, struct pm_htable *old_htab, struct pm_htable *saved_htab)
{
  memcpy(saved_htab, old_htab, sizeof(struct pm_htable));
  memcpy(old_htab, new_htab, sizeof(struct pm_htable));
}

void __pm_hdelete(_pm_HENTRY *item)
{
  item->used = 0;

  item->entry.keylen = 0;
  free(item->entry.key);
  item->entry.key = NULL;

  if (item->entry.data) {
    free(item->entry.data);
    item->entry.data = NULL;
  }
}
